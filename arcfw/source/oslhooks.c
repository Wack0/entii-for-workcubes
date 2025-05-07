#include <stddef.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "arc.h"
#include "arcmem.h"
#include "arcio.h"
#include "arcload.h"
#include "coff.h"
#include "ppcinst.h"
#include "ppchook.h"
#include "oslhooks.h"
#include "timer.h"
#include "pxi.h"
#include "runtime.h"

static PVOID ScratchAddress = NULL;

static inline ARC_FORCEINLINE ULONG ScratchEnd() {
    return (ULONG)ScratchAddress + ARCFW_MEM2_SIZE;
}

static inline ARC_FORCEINLINE bool is_offset_in_branch_range(long offset)
{
    return (offset >= -0x2000000 && offset <= 0x1fffffc && !(offset & 0x3));
}

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

static inline ARC_FORCEINLINE ULONG min(ULONG val1, ULONG val2) {
    if (val1 <= val2) return val1;
    return val2;
}

static inline ARC_FORCEINLINE ULONG max(ULONG val1, ULONG val2) {
    if (val1 >= val2) return val1;
    return val2;
}

enum {
    BLOCKED_AREA_COUNT = 32
};

enum {
    NEWBASE_KERNEL32 = 0x73000000,
    NEWBASE_USER32 = NEWBASE_KERNEL32 + 0x200000, // 2MB for kernel32
    NEWBASE_OLE32 = NEWBASE_USER32 + 0x200000, // 2MB for user32
};

typedef enum {
    AREA_NOT_BLOCKED, // Not a blocked area. AOT is handled as usual.
    AREA_BLOCKED_EMULATION, // Blocked for AOT. Any instructions requiring AOT must be handled separately.
} BLOCKED_AREA_DEFINITION;

typedef enum {
    AOT_NONE,
    AOT_STWCX,
} INSTRUCTION_AOT_TYPE;

// Define ARC boot library structures used here.

enum {
    BL_FILE_TABLE_SIZE = 32
};

typedef ARC_STATUS(*PRENAME_ROUTINE)(IN ULONG FileId, IN PCHAR NewName);
typedef ARC_STATUS(*PBL_OPEN_ROUTINE)(ULONG DeviceId, PCHAR OpenPath, OPEN_MODE OpenMode, PU32LE FileId);
typedef ARC_STATUS(*tfpBlSetupForNt)(PVOID LoaderParameterBlock);

typedef struct ARC_LE {
    size_t Function;
    size_t Toc;
} AIXCALL_FPTR, *PAIXCALL_FPTR;

typedef struct ARC_LE _BOOTFS_INFO {
    ULONG DriverName; // WCHAR*
} BOOTFS_INFO, *PBOOTFS_INFO;

typedef struct ARC_LE _BL_FILE_FLAGS {
    ULONG Open : 1;
    ULONG Read : 1;
    ULONG Write : 1;
    ULONG DoubleSpace : 1;
} BL_FILE_FLAGS, *PBL_FILE_FLAGS;

typedef struct ARC_LE _BL_FILE_TABLE {
    BL_FILE_FLAGS Flags;
    ULONG DeviceId;
    LARGE_INTEGER Position;
    ULONG StructureContext;
    ULONG DeviceEntryTable; // PBL_DEVICE_ENTRY_TABLE
    UCHAR FileNameLength;
    CHAR FileName[MAXIMUM_FILE_NAME_LENGTH];
    CHAR Body[0x28];
} BL_FILE_TABLE, *PBL_FILE_TABLE;

_Static_assert(sizeof(BL_FILE_TABLE) == 0x68);
_Static_assert(offsetof(BL_FILE_TABLE, DeviceEntryTable) == 0x14);

typedef struct ARC_LE _BL_DEVICE_ENTRY_TABLE {
    PARC_CLOSE_ROUTINE Close;
    PARC_MOUNT_ROUTINE Mount;
    PARC_OPEN_ROUTINE Open;
    PARC_READ_ROUTINE Read;
    PARC_READ_STATUS_ROUTINE GetReadStatus;
    PARC_SEEK_ROUTINE Seek;
    PARC_WRITE_ROUTINE Write;
    PARC_GET_FILE_INFO_ROUTINE GetFileInformation;
    PARC_SET_FILE_INFO_ROUTINE SetFileInformation;
    PRENAME_ROUTINE Rename;
    PARC_GET_DIRECTORY_ENTRY_ROUTINE GetDirectoryEntry;
    PBOOTFS_INFO BootFsInfo;
} BL_DEVICE_ENTRY_TABLE, *PBL_DEVICE_ENTRY_TABLE;

// Structures for PE patching operation
typedef enum {
    STATE_OPENED, // BlOpen called, nothing is known about this.
    STATE_READING_HEADER, // In the process of reading headers.
    STATE_READING_SECTIONS, // In the process of reading sections.
    STATE_READING_SECTION_INJECTED, // Reading the injected section.
    STATE_READING_SECTIONS_AFTER_INJECTED, // Reading sections after the injected section was read.
    STATE_NOP, // PE patcher has either failed, was not needed, or succeeded.
} PE_PATCH_STATE;

typedef struct _PE_PATCH_ENTRY {
    PE_PATCH_STATE State; // State of the PE patcher
    PBYTE PeHeaderInitial; // Initial copy of the PE headers (0x400 bytes) read to the stack
    PUCHAR PointerInjectedSection; // When not NULL, used as the base of the injected section. Also used to denote a not-mapped PE (ie, on-disk format)
    size_t BaseAddress; // Actual base address of the PE, reads OptionalHeader->SizeOfHeaders bytes here
    ULONG SizeOfInjectedSection; // Size of injected section, to hold original instructions that were patched, and hook trampolines
    ULONG ImagePositionOfInjectedSection; // Offset of injected section
    ULONG IndexOfInjectedSection; // Index of injected section
    ULONG RealImageBase; // Real ImageBase, for system dlls that must always be located in same place across all processes (user32, ole32, kernel32)
    CHAR FileName[MAXIMUM_FILE_NAME_LENGTH + 1]; // Filename of PE being loaded, null terminated.
    bool InjectedSectionIsFinal;
} PE_PATCH_ENTRY, *PPE_PATCH_ENTRY;

typedef struct _PE_PATCH_SECTION_ENTRY {
    ULONG PointerToRawData; // Offset into original file where this part of the file is.
    ULONG OurOffset; // Offset into section memory where this part of the file is.
    ULONG SizeOfRawData; // Size of section on disk (that is expected to be read)
} PE_PATCH_SECTION_ENTRY, *PPE_PATCH_SECTION_ENTRY;

typedef struct _BLOCKED_AREA {
    ULONG Start, End;
} BLOCKED_AREA, * PBLOCKED_AREA;

static PBL_DEVICE_ENTRY_TABLE orig_DeviceEntryTable[BL_FILE_TABLE_SIZE];
static BL_DEVICE_ENTRY_TABLE hook_DeviceEntryTable[BL_FILE_TABLE_SIZE];
static PE_PATCH_ENTRY s_PatchTable[BL_FILE_TABLE_SIZE];
static PBL_OPEN_ROUTINE orig_BlOpen;
static tfpBlSetupForNt orig_BlSetupForNt;
static PBL_FILE_TABLE s_BlFileTable;

// Blocked areas:
// s_BlockedAreas => these areas will not have instructions patched in a generic way.
static BLOCKED_AREA s_BlockedAreas[BLOCKED_AREA_COUNT];
static ULONG s_BlockedAreaCount = 0;
static bool s_IsLoadingNtKernel = false;
static bool s_KernelIsUniProcessor = false;
static bool s_KernelIsNotUniProcessor = false;
static PVOID s_NtKernelReal0 = NULL;
static PVOID s_NtKernelReal0End = NULL;
static PVOID s_NtKernelPteStart = NULL;
static PVOID s_NtKernelPteEnd = NULL;

#define DEVICE_ENTRY_TYPE_ORIG(Element) __typeof__( ((PBL_DEVICE_ENTRY_TABLE)NULL)-> Element )

#define DEVICE_ENTRY_GET(Element, DeviceId) *( (PAIXCALL_FPTR) orig_DeviceEntryTable[DeviceId] -> Element )

#define DEVICE_ENTRY_HOOK(Element, DeviceId, Aixfptr) ( hook_DeviceEntryTable[DeviceId] . Element ) = (PVOID)& Aixfptr

#define DEVICE_ENTRY_CALL_ORIG(Element, DeviceId, ...) \
    ( ( DEVICE_ENTRY_TYPE_ORIG(Element) ) ( ( (PAIXCALL_FPTR) orig_DeviceEntryTable[DeviceId] -> Element ) ->Function ) ) (DeviceId, ## __VA_ARGS__ )

static inline ARC_FORCEINLINE bool IsBufferInsideArea(ULONG Start, ULONG End, ULONG AreaStart, ULONG AreaEnd) {
    if (Start >= AreaStart && Start < AreaEnd) return true;
    if (AreaStart >= Start && AreaStart < End) return true;
    return false;
}

static BLOCKED_AREA_DEFINITION CheckBlockedArea(ULONG Pointer, ULONG Length, PULONG BlockedLength) {
    ULONG End = Pointer + Length;
    for (ULONG i = 0; i < s_BlockedAreaCount; i++) {
        PBLOCKED_AREA Area = &s_BlockedAreas[i];
        if (IsBufferInsideArea(Pointer, End, Area->Start, Area->End)) {
            *BlockedLength = Area->End - Pointer;
            return AREA_BLOCKED_EMULATION;
        }
    }

    return AREA_NOT_BLOCKED;
}

// Boyer-Moore Horspool algorithm adapted from http://www-igm.univ-mlv.fr/~lecroq/string/node18.html#SECTION00180
PBYTE mem_mem(PBYTE startPos, const void* pattern, size_t size, size_t patternSize)
{
    const BYTE* patternc = (const BYTE*)pattern;
    size_t table[256];

    // Preprocessing
    for (ULONG i = 0; i < 256; i++)
        table[i] = patternSize;
    for (size_t i = 0; i < patternSize - 1; i++)
        table[patternc[i]] = patternSize - i - 1;

    // Searching
    size_t j = 0;
    while (j <= size - patternSize)
    {
        BYTE c = startPos[j + patternSize - 1];
        if (patternc[patternSize - 1] == c && memcmp(pattern, startPos + j, patternSize - 1) == 0)
            return startPos + j;
        j += table[c];
    }

    return NULL;
}

static BYTE to_lower(BYTE chr) {
    if (chr >= 'A' && chr <= 'Z') return chr | 0x20;
    return chr;
}

static int stricmp(const char* str1, const char* str2) {
    while (to_lower(*str1) == to_lower(*str2)) {
        if (*str1 == 0) return 0;
        str1++;
        str2++;
    }

    return (int)to_lower(*str1) - (int)to_lower(*str2);
}

static PVOID FindSymbolEnd(ULONG ImageBase, PRUNTIME_FUNCTION_ENTRY ExceptionDir, ULONG ExceptionSize, PVOID SymbolStart) {
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
    ULONG OldImageBase = NtHeaders->OptionalHeader.ImageBase;
    ULONG ExceptionCount = ExceptionSize / sizeof(RUNTIME_FUNCTION_ENTRY);
    for (ULONG i = 0; i < ExceptionCount; i++) {
        ULONG BeginAddress = ExceptionDir[i].BeginAddress - OldImageBase + ImageBase;
        if (BeginAddress == (ULONG)SymbolStart) return (PVOID)(ExceptionDir[i].EndAddress - OldImageBase + ImageBase);
        if (BeginAddress < (ULONG)SymbolStart) return (PVOID)BeginAddress;
    }
    return NULL;
}

static PVOID FindSymbolSpecifiedEnd(ULONG ImageBase, PRUNTIME_FUNCTION_ENTRY ExceptionDir, ULONG ExceptionSize, PVOID SymbolAddr) {
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
    ULONG OldImageBase = NtHeaders->OptionalHeader.ImageBase;
    ULONG ExceptionCount = ExceptionSize / sizeof(RUNTIME_FUNCTION_ENTRY);
    for (ULONG i = 0; i < ExceptionCount; i++) {
        ULONG BeginAddress = ExceptionDir[i].BeginAddress - OldImageBase + ImageBase;
        ULONG EndAddress = ExceptionDir[i].EndAddress - OldImageBase + ImageBase;
        if ((ULONG)SymbolAddr >= BeginAddress && (ULONG)SymbolAddr < EndAddress) return (PVOID)EndAddress;
    }
    return NULL;
}

static PVOID FindSymbolNextStart(ULONG ImageBase, PRUNTIME_FUNCTION_ENTRY ExceptionDir, ULONG ExceptionSize, PVOID SymbolAddr) {
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
    ULONG OldImageBase = NtHeaders->OptionalHeader.ImageBase;
    ULONG ExceptionCount = ExceptionSize / sizeof(RUNTIME_FUNCTION_ENTRY);
    for (ULONG i = 0; i < ExceptionCount; i++) {
        ULONG BeginAddress = ExceptionDir[i].BeginAddress - OldImageBase + ImageBase;
        ULONG EndAddress = ExceptionDir[i].EndAddress - OldImageBase + ImageBase;
        if ((ULONG)SymbolAddr >= BeginAddress && (ULONG)SymbolAddr < EndAddress) return (PVOID)(ExceptionDir[i + 1].BeginAddress - OldImageBase + ImageBase);
    }
    return NULL;
}

static PVOID FindSymbolStart(ULONG ImageBase, PRUNTIME_FUNCTION_ENTRY ExceptionDir, ULONG ExceptionSize, PVOID SymbolAddr) {
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
    ULONG OldImageBase = NtHeaders->OptionalHeader.ImageBase;
    ULONG ExceptionCount = ExceptionSize / sizeof(RUNTIME_FUNCTION_ENTRY);
    for (ULONG i = 0; i < ExceptionCount; i++) {
        ULONG BeginAddress = ExceptionDir[i].BeginAddress - OldImageBase + ImageBase;
        ULONG EndAddress = ExceptionDir[i].EndAddress - OldImageBase + ImageBase;
        if ((ULONG)SymbolAddr >= BeginAddress && (ULONG)SymbolAddr < EndAddress) return (PVOID)BeginAddress;
    }
    return NULL;
}

static PVOID FindSymbolPrevious(ULONG ImageBase, PRUNTIME_FUNCTION_ENTRY ExceptionDir, ULONG ExceptionSize, PVOID SymbolAddr, PVOID* EndAddress) {
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
    ULONG OldImageBase = NtHeaders->OptionalHeader.ImageBase;
    ULONG ExceptionCount = ExceptionSize / sizeof(RUNTIME_FUNCTION_ENTRY);
    for (ULONG i = 1; i < ExceptionCount; i++) {
        ULONG BeginAddress = ExceptionDir[i].BeginAddress - OldImageBase + ImageBase;
        ULONG exEndAddress = ExceptionDir[i].EndAddress - OldImageBase + ImageBase;
        if ((ULONG)SymbolAddr >= BeginAddress && (ULONG)SymbolAddr < exEndAddress) {
            if (EndAddress != NULL) *EndAddress = (PVOID)(ExceptionDir[i - 1].EndAddress - OldImageBase + ImageBase);
            return (PVOID)(ExceptionDir[i - 1].BeginAddress - OldImageBase + ImageBase);
        }
    }
    return NULL;
}

static PVOID PeGetExport(ULONG ImageBase, PIMAGE_EXPORT_DIRECTORY Export, const char* ExportName) {
    bool LookUpName = true;
    USHORT Ordinal = 0;
    if (((ULONG)ExportName & 0xffff0000) == 0) {
        LookUpName = false;
        Ordinal = (USHORT)(ULONG)ExportName;
    }

    if (LookUpName) {
        PU32LE AddressOfNames = (PU32LE)(ImageBase + Export->AddressOfNames);
        PU16LE AddressOfNameOrdinals = (PU16LE)(ImageBase + Export->AddressOfNameOrdinals);
        for (ULONG i = 0; i < Export->NumberOfNames; i++) {
            const char* Name = (const char*)(ImageBase + AddressOfNames[i].v);
            if (!strcmp(Name, ExportName)) {
                // found it
                Ordinal = AddressOfNameOrdinals[i].v;
                LookUpName = false;
                break;
            }
        }

        if (LookUpName) return NULL;
    }

    PU32LE AddressOfFunctions = (PU32LE)(ImageBase + Export->AddressOfFunctions);
    return (PVOID)(ImageBase + AddressOfFunctions[Ordinal].v);
}

static PVOID PeGetProcAddress(ULONG ImageBase, PIMAGE_EXPORT_DIRECTORY Export, const char* ExportName) {
    PAIXCALL_FPTR Fptr = (PAIXCALL_FPTR)PeGetExport(ImageBase, Export, ExportName);
    if (Fptr == NULL) return NULL;
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
    return (PVOID)(Fptr->Function - NtHeaders->OptionalHeader.ImageBase + ImageBase);
}

static PVOID PeGetEntryPoint(ULONG ImageBase, PIMAGE_OPTIONAL_HEADER OptionalHeader) {
    if (OptionalHeader->AddressOfEntryPoint == 0) return NULL;
    PAIXCALL_FPTR Fptr = (PAIXCALL_FPTR)(ImageBase + OptionalHeader->AddressOfEntryPoint);
    return (PVOID)(Fptr->Function - OptionalHeader->ImageBase + ImageBase);
}

static void InitialiseBlockedAreaByProcAddress(ULONG ImageBase, PIMAGE_EXPORT_DIRECTORY Export, PRUNTIME_FUNCTION_ENTRY Exception, ULONG ExceptionSize, const char* ExportName) {
    PVOID Function = PeGetProcAddress(ImageBase, Export, ExportName);
    if (Function == NULL) return;
    PVOID FunctionEnd = FindSymbolNextStart(ImageBase, Exception, ExceptionSize, Function);
    if (FunctionEnd == NULL) return;

    s_BlockedAreas[s_BlockedAreaCount].Start = (ULONG)Function;
    s_BlockedAreas[s_BlockedAreaCount].End = (ULONG)FunctionEnd;
    s_BlockedAreaCount++;
}

static inline ARC_FORCEINLINE LONG HookSignExtBranch(LONG x) {
    return x & 0x2000000 ? (LONG)(x | 0xFC000000) : (LONG)(x);
}

static inline ARC_FORCEINLINE LONG HookSignExt16(SHORT x) {
    return (LONG)x;
}

static PCHAR PeGetExportImageName(ULONG ImageBase, PIMAGE_DATA_DIRECTORY ExportDir) {
    if (ExportDir->VirtualAddress == 0 || ExportDir->Size == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY Export = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + ExportDir->VirtualAddress);
    PCHAR ImageName = (PCHAR)(ImageBase + Export->Name);
    return ImageName;
}

static ARC_NOINLINE ARC_STATUS InitialiseBlockedAreas(ULONG ImageBase, PIMAGE_NT_HEADERS NtHeaders) {
    memset(s_BlockedAreas, 0, sizeof(s_BlockedAreas));
    s_BlockedAreaCount = 0;
    s_IsLoadingNtKernel = false;
    PIMAGE_FILE_HEADER FileHeader = &NtHeaders->FileHeader;

    USHORT NumberOfSections = FileHeader->NumberOfSections;
    if (NumberOfSections == 0) return _EBADF; // ???
    PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&FileHeader[1];
    PIMAGE_SECTION_HEADER Sections = (PIMAGE_SECTION_HEADER)((size_t)OptionalHeader + FileHeader->SizeOfOptionalHeader);

    // Get export directory
    PIMAGE_DATA_DIRECTORY ExportDir = &OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    // if nothing is there then nothing needs to be done
    if (ExportDir->VirtualAddress == 0 || ExportDir->Size == 0) return _ESUCCESS;

    // Get exception directory
    PIMAGE_DATA_DIRECTORY ExceptionDir = &OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    PRUNTIME_FUNCTION_ENTRY Exceptions = (PRUNTIME_FUNCTION_ENTRY)(ImageBase + ExceptionDir->VirtualAddress);

    PIMAGE_EXPORT_DIRECTORY Export = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + ExportDir->VirtualAddress);
    PCHAR ImageName = (PCHAR)(ImageBase + Export->Name);
    s_IsLoadingNtKernel = !strcmp(ImageName, "ntoskrnl.exe");

    if (s_IsLoadingNtKernel) {
        // Loading the kernel. Find real0 and blacklist it.
        static const char s_Real0StartPattern[] = "PowerPC";
        // real0 is either in .text (NT 3.5x) or in INIT (NT 4.0) section
        PIMAGE_SECTION_HEADER InitSection = (PIMAGE_SECTION_HEADER)(ULONG)NULL;
        // .text is always first section in an nt kernel PE
        PIMAGE_SECTION_HEADER TextSection = &Sections[0];
        if (OptionalHeader->MajorOperatingSystemVersion == 4) {
            for (ULONG i = 0; i < NumberOfSections; i++) {
                if (!strcmp((char*)Sections[i].Name, "INIT")) {
                    InitSection = &Sections[i];
                    break;
                }
            }
        }

        PBYTE Real0 = NULL;
        PVOID InitOrTextAddr = (PVOID)(ImageBase + (InitSection == NULL ? TextSection : InitSection)->VirtualAddress);
        ULONG InitOrTextLength = (InitSection == NULL ? TextSection : InitSection)->Misc.VirtualSize;
        PVOID KernelText = (PVOID)(ImageBase + TextSection->VirtualAddress);
        if (InitSection != NULL) {
            PVOID KernelInitText = (PVOID)(ImageBase + InitSection->VirtualAddress);
            Real0 = mem_mem((PBYTE)KernelInitText, s_Real0StartPattern, InitSection->Misc.VirtualSize, sizeof(s_Real0StartPattern));
        }
        if (Real0 == NULL) {
            Real0 = mem_mem((PBYTE)KernelText, s_Real0StartPattern, TextSection->Misc.VirtualSize, sizeof(s_Real0StartPattern));
        }
        if (Real0 == NULL) {
            return _EBADF;
        }

        s_NtKernelReal0 = Real0;
        // Find the end of real0, that'll be whatever pdata says.
        // (in NT 3.x anyway. In NT4, end of real0 is +0x4000.)
        PVOID Real0End = &Real0[0x4000];
        if (OptionalHeader->MajorOperatingSystemVersion < 4)
            Real0End = FindSymbolNextStart(ImageBase, Exceptions, ExceptionDir->Size, Real0);
        if (Real0End == NULL) {
            return _EBADF; // can't find the end of real0?!
        }

        s_NtKernelReal0End = Real0End;

        s_BlockedAreas[s_BlockedAreaCount].Start = (ULONG)Real0;
        s_BlockedAreas[s_BlockedAreaCount].End = (ULONG)Real0End;
        s_BlockedAreaCount++;


        // In NT4, this is part of code that gets copied from INIT section to somewhere else :(
        // We don't know where it will end up...
        PBYTE PageTableFuncsStart = (PVOID)((ULONG)Real0 + 0x4000);
        if (*(PULONG)PageTableFuncsStart != 0x607F0000) { // mr r31, r3
            static const ULONG s_PageTableUpdatePattern[] = { 0x7ca02526 }; // { 0x2625a07c }; // mfsrin r5, r4 - never changed, although its location did (.text in NT3.x, INIT in NT4 copied elsewhere later)
            PageTableFuncsStart = mem_mem(InitOrTextAddr, s_PageTableUpdatePattern, InitOrTextLength, sizeof(s_PageTableUpdatePattern));
            if (PageTableFuncsStart == NULL) {
                return _EBADF;
            }
        }
        // For the end: we look for "sync;blr" after "mfsdr1 r5"
        static const ULONG s_EndReturnPattern[] = { 0x7c0004ac, 0x4e800020 };// { 0xAC04007C, 0x2000804E };
        static const ULONG s_LastFuncStartPattern[] = { 0x7cb902a6 }; // 0xa602b97c

        ULONG RemainingLength = InitOrTextLength - ((ULONG)PageTableFuncsStart - (ULONG)InitOrTextAddr);
        PBYTE PageTableFuncsEnd = mem_mem(PageTableFuncsStart, s_LastFuncStartPattern, RemainingLength, sizeof(s_LastFuncStartPattern));
        if (PageTableFuncsEnd == NULL) {
            return _EBADF;
        }
        RemainingLength -= ((ULONG)PageTableFuncsEnd - (ULONG)InitOrTextAddr);
        PageTableFuncsEnd = mem_mem(PageTableFuncsEnd, s_EndReturnPattern, RemainingLength, sizeof(s_EndReturnPattern));
        if (PageTableFuncsEnd == NULL) {
            return _EBADF;
        }

        if (PageTableFuncsStart == (PVOID)((ULONG)Real0 + 0x4000)) {
            // This area gets relocated in early kernel init in NT4.
            // So we must deal with stwcx in this area seperately.
            s_BlockedAreas[s_BlockedAreaCount].Start = (ULONG)PageTableFuncsStart;
            s_BlockedAreas[s_BlockedAreaCount].End = (ULONG)PageTableFuncsEnd + sizeof(s_EndReturnPattern);
            s_BlockedAreaCount++;
            s_NtKernelPteStart = PageTableFuncsStart;
            s_NtKernelPteEnd = PageTableFuncsEnd; // not exactly true but there's nothing to patch in "sync;blr"
        }
        else {
            s_NtKernelPteStart = NULL;
            s_NtKernelPteEnd = NULL;
        }

        // Found all blocked areas for kernel specifically.
    }

    return _ESUCCESS;
}

static ULONG InstructionNeedsAot(ULONG i, INSTRUCTION_AOT_TYPE* AotType) {
    PPC_INSTRUCTION Insn;
    Insn.Long = i;
    *AotType = AOT_NONE;

    if (Insn.Primary_Op != X31_OP) return 0;
    // stwcx patch:
    // dcbst ra,rb
    // stwcx rt,ra,rb
    // b next_insn

    if (Insn.Xform_XO == STWCX_RC_OP) {
        *AotType = AOT_STWCX;
        return 3 * sizeof(ULONG);
    }

    return 0;
}

static ARC_STATUS FindLengthOfCodeTable(ULONG FileId, PIMAGE_SECTION_HEADER Sections, USHORT NumberOfSections, PULONG TableLength) {
    if (TableLength == NULL) {
        return _EFAULT;
    }
    if (ScratchAddress == NULL) {
        return _ENOMEM;
    }
    ARC_STATUS Status;
    ULONG CalculatedTableLength = 0;

    // For all code sections, read to scratch chunk
    INSTRUCTION_AOT_TYPE AotType;
    ULONG CodeScratch = (ULONG)ScratchAddress;

    // If this PE has one section with IMAGE_SCN_CNT_CODE flag, then look for those.
    // Otherwise, look for sections marked executable.
    bool HasAtLeastOneCodeSection = false;
    for (int Section = 0; Section < NumberOfSections; Section++) {
        if ((Sections[Section].Characteristics & IMAGE_SCN_CNT_CODE) != 0) {
            HasAtLeastOneCodeSection = true;
            break;
        }
    }

    ULONG SectionFlags = (HasAtLeastOneCodeSection ? IMAGE_SCN_CNT_CODE : IMAGE_SCN_MEM_EXECUTE);
    for (int Section = 0; Section < NumberOfSections; Section++) {
        if ((Sections[Section].Characteristics & SectionFlags) == 0) continue;

        LARGE_INTEGER SeekPosition = Int64ToLargeInteger(Sections[Section].PointerToRawData);
        {
            U32LE Count;
            Status = DEVICE_ENTRY_CALL_ORIG(Seek, FileId, &SeekPosition, SeekAbsolute);
            if (ARC_FAIL(Status)) return Status;
            // Ensure that the read isn't past our allocated scratch area of MEM2.
            if ((CodeScratch + Sections[Section].SizeOfRawData) >= ScratchEnd()) return _E2BIG;
            Status = DEVICE_ENTRY_CALL_ORIG(Read, FileId, (PVOID)CodeScratch, Sections[Section].SizeOfRawData, &Count);
            if (ARC_FAIL(Status)) return Status;
            if (Count.v != Sections[Section].SizeOfRawData) {
                return _EFAULT;
            }
        }

        // Walk through all instructions, looking for stwcx instructions.
        PU32LE Instruction = (PU32LE)CodeScratch;
        for (ULONG i = 0; i < Sections[Section].SizeOfRawData / sizeof(ULONG); i++) {
            ULONG RealIndex = i;
            ULONG AotLength = InstructionNeedsAot(Instruction[RealIndex].v, &AotType);
            if (AotLength != 0) {
                CalculatedTableLength += AotLength;
            }
        }
    }

    *TableLength = CalculatedTableLength;
    return _ESUCCESS;
}

#define mfpvr() ({u32 _rval; \
		__asm__ __volatile__ ("mfpvr %0" : "=r"(_rval)); _rval;})

static ARC_STATUS InstructionPatchAot(
    PULONG SectionBase,
    PULONG* TablePointer,
    ULONG Offset,
    ULONG TableSectionStart,
    ULONG TableSectionLength,
    //ULONG TableOffsetFromInstruction,
    BLOCKED_AREA_DEFINITION BlockedArea
) {
    if (BlockedArea == AREA_BLOCKED_EMULATION) return _ESUCCESS;
    ULONG instruction = SectionBase[Offset];
    INSTRUCTION_AOT_TYPE AotType;
    ULONG AotLength = InstructionNeedsAot(instruction, &AotType);

    if (AotLength == 0) return _ESUCCESS;

    PPC_INSTRUCTION OriginalInsn;
    OriginalInsn.Long = instruction;
    PPC_INSTRUCTION AotInsn = { 0 };
    ULONG TableOffset = (ULONG)*TablePointer - TableSectionStart;
    if (TableOffset + AotLength >= TableSectionLength) {
        return 10201;
    }
    ULONG TablePointerStart = (ULONG)*TablePointer;
    ULONG FixupStart = (ULONG)TablePointer[1];
    LONG JumpOffset;

    switch (AotType) {
    case AOT_STWCX:
        // dcbst ra,rb
        AotInsn.Long = 0;
        AotInsn.Primary_Op = X31_OP;
        AotInsn.Xform_XO = DCBST_OP;
        AotInsn.Xform_RA = OriginalInsn.Xform_RA;
        AotInsn.Xform_RB = OriginalInsn.Xform_RB;
        (*TablePointer)[0] = AotInsn.Long;
        (*TablePointer)++;
        // stwcx rt,ra,rb
        AotInsn.Long = OriginalInsn.Long;
        (*TablePointer)[0] = AotInsn.Long;
        (*TablePointer)++;
        // b next_insn
        AotInsn.Long = 0;
        AotInsn.Primary_Op = B_OP;
        AotInsn.Iform_LK = 0;
        AotInsn.Iform_AA = 0;
        JumpOffset = ((ULONG)&SectionBase[Offset + 1] - ((ULONG)TablePointer[1] + ((ULONG)*TablePointer - TablePointerStart)));
        if (!is_offset_in_branch_range(JumpOffset)) {
            //DEBUG_PANIC("branch out of range 3\n");
            return 10204;
        }
        AotInsn.Iform_LI = JumpOffset >> 2;
        (*TablePointer)[0] = AotInsn.Long;
        (*TablePointer)++;
        break;
    default:
        // should never happen???
        return 10205;
    }

    ULONG NewTableSectionPointer = (ULONG)TablePointer[1] + ((ULONG)*TablePointer - TablePointerStart);
    TablePointer[1] = (PULONG)NewTableSectionPointer;
    AotInsn.Long = 0;
    AotInsn.Primary_Op = B_OP;
    AotInsn.Iform_LK = 0;
    AotInsn.Iform_AA = 0;
    JumpOffset = (FixupStart - (ULONG)&SectionBase[Offset]);
    if (!is_offset_in_branch_range(JumpOffset)) {
        //DEBUG_PANIC("branch out of range 8\n");
        return 10209;
    }
    AotInsn.Iform_LI = JumpOffset >> 2;
    SectionBase[Offset] = AotInsn.Long;
    return _ESUCCESS;
}

static ARC_STATUS PePatch_Relocate(PPE_PATCH_ENTRY Patch) {
    PBYTE PeHeader = (PBYTE)Patch->BaseAddress;
    ULONG ImageBase = (ULONG)PeHeader;
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)PeHeader;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 11000; // no DOS header

    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(PeHeader + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) return 11001; // no PE header
    PIMAGE_FILE_HEADER FileHeader = &NtHeaders->FileHeader;

    USHORT NumberOfSections = FileHeader->NumberOfSections;
    PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&FileHeader[1];
    PIMAGE_SECTION_HEADER Sections = (PIMAGE_SECTION_HEADER)((size_t)OptionalHeader + FileHeader->SizeOfOptionalHeader);

    ARC_STATUS Status = _ESUCCESS;

    ULONG OldBase = OptionalHeader->ImageBase;
    if (Patch->RealImageBase != 0) OldBase = Patch->RealImageBase;

    s_IsLoadingNtKernel = 0;

    PIMAGE_SECTION_HEADER TableSection = &Sections[Patch->IndexOfInjectedSection];
    ULONG TableSectionLength = TableSection->Misc.VirtualSize;
    ULONG TableSectionVa = TableSection->VirtualAddress;
    ULONG TableSectionStart = ImageBase + TableSectionVa;
    ULONG pTableSectionStart = TableSectionStart;
    PULONG TablePointer[] = { (PULONG)TableSectionStart, (PULONG)TableSectionStart };
    {
        if (Patch->IndexOfInjectedSection == 0) {
            // This should never occur, and if so means that this hasn't been called correctly.
            return 10104;
        }
        // Need to patch instructions.
        // We need to blocklist some areas.

        PIMAGE_DATA_DIRECTORY ExceptionDir = &OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        bool HasExceptions = ExceptionDir->VirtualAddress != 0 && ExceptionDir->Size != 0;

        if (!HasExceptions) {
            // For a PE, exception directory is required, due to NT 3.51/NT 4.0 having rodata sections merged into .text
            return 10002;// _EFAULT;
        }

        if (ARC_FAIL(InitialiseBlockedAreas(ImageBase, NtHeaders))) return 10003;// _EFAULT;

        // parse the exception data to get all known function bounds, swap endianness of each instruction
        PRUNTIME_FUNCTION_ENTRY ExceptionTable = (PRUNTIME_FUNCTION_ENTRY)(ImageBase + ExceptionDir->VirtualAddress);
        ULONG ExceptionCount = ExceptionDir->Size / sizeof(RUNTIME_FUNCTION_ENTRY);
        for (ULONG i = 0; i < ExceptionCount; i++) {
            ULONG ptrStart = (ExceptionTable[i].BeginAddress - OldBase + ImageBase);
            //ULONG ptrEnd = ExceptionTable[i].EndAddress;
            ULONG lastEnd = 0;
            if (i != 0) lastEnd = (ExceptionTable[i - 1].EndAddress - OldBase + ImageBase);
            ULONG funcLen = (ExceptionTable[i].EndAddress - OldBase + ImageBase) - ptrStart;
            PULONG BaseLittle = (PULONG)ptrStart;
            ULONG TableOffsetFromInstruction = TableSectionStart - ptrStart;
            BLOCKED_AREA_DEFINITION BlockedArea;
            ULONG BlockedLength;

            //extern ULONG PeekWithStackFrame(PULONG Address);

            if (i != 0 && ptrStart != lastEnd) {
                // Not all functions have an entry in pdata;
                // specifically, some asm functions don't;
                // so if this function start does not equal previous function end, deal with it.

                // NT4 does merge non-code sections with .text;
                // however the code is always at end of .text;
                // first pdata entry will always point to first instruction.

                // also: do NOT do this if it spans sections.
                // there may be data sections in between code sections.
                ULONG rvaStart = lastEnd - ImageBase;
                ULONG rvaEnd = ptrStart - ImageBase;
                // find section of rvaStart
                PIMAGE_SECTION_HEADER sectStart = (PIMAGE_SECTION_HEADER)(ULONG)NULL;
                bool doAdditional = false;
                for (ULONG s = 0; s < NumberOfSections; s++) {
                    if (rvaStart >= Sections[s].VirtualAddress && rvaStart <= Sections[s].VirtualAddress + Sections[s].Misc.VirtualSize) {
                        sectStart = &Sections[s];
                        break;
                    }
                }
                if (sectStart != NULL) {
                    doAdditional = rvaEnd < sectStart->VirtualAddress + sectStart->Misc.VirtualSize;
                }

                if (doAdditional) {
                    ULONG additionalStart = lastEnd;
                    ULONG additionalLen = ptrStart - additionalStart;
                    PULONG additionalLittle = (PULONG)additionalStart;
                    ULONG additionalOffset = TableSectionStart - additionalStart;

                    for (ULONG off = 0; off < additionalLen / sizeof(ULONG); off++, additionalOffset -= sizeof(ULONG)) {
                        if (additionalOffset > INT32_MAX) {
                            // ???
                            return 10100;
                        }
                        if ((ULONG)&additionalLittle[off] >= ImageBase + OptionalHeader->SizeOfImage || (ULONG)&additionalLittle[off] < ImageBase) {
                            return 10101;
                        }
                        BlockedArea = CheckBlockedArea((ULONG)&additionalLittle[off], sizeof(ULONG), &BlockedLength);

                        //PeekWithStackFrame((PULONG)&additionalBig[off]);


                        Status = InstructionPatchAot(
                            additionalLittle,
                            TablePointer,
                            off,
                            pTableSectionStart,
                            TableSectionLength,
                            //additionalOffset,
                            BlockedArea
                        );
                        if (ARC_FAIL(Status)) return Status;
                    }
                }
            }

            for (ULONG off = 0; off < funcLen / sizeof(ULONG); off++, TableOffsetFromInstruction -= sizeof(ULONG)) {
                if (TableOffsetFromInstruction > INT32_MAX) {
                    // ???
                    return 10102;
                }
                if ((ULONG)&BaseLittle[off] >= ImageBase + OptionalHeader->SizeOfImage || (ULONG)&BaseLittle[off] < ImageBase) {
                    return 10103;
                }
                BlockedArea = CheckBlockedArea((ULONG)&BaseLittle[off], sizeof(ULONG), &BlockedLength);

                //PeekWithStackFrame((PULONG)&BaseBig[off]);

                Status = InstructionPatchAot(
                    BaseLittle,
                    TablePointer,
                    off,
                    pTableSectionStart,
                    TableSectionLength,
                    //TableOffsetFromInstruction,
                    BlockedArea
                );
                if (ARC_FAIL(Status)) return Status;
            }
        }


        if (s_IsLoadingNtKernel) {
            // Deal with stwcx instructions in real0
            for (ULONG addr = (ULONG)s_NtKernelReal0; addr < (ULONG)s_NtKernelReal0End; addr += 4) {
                PPPC_INSTRUCTION insn = (PPPC_INSTRUCTION)addr;
                if (insn->Primary_Op != X31_OP || insn->Xform_XO != STWCX_RC_OP) continue;
                // start from the start of real0, as NT4 SP2 (for example) has zero space after the stwcx insn.
                PULONG cave = (PULONG)s_NtKernelReal0;
                for (; cave < (PULONG)s_NtKernelReal0End; cave++) {
                    // we need three zeroed out entries in this cave in a row.
                    if (cave[0] == 0 && cave[1] == 0 && cave[2] == 0) break;
                }
                if (cave >= (PULONG)s_NtKernelReal0End) return 11100; // can't find a cave

                PPPC_INSTRUCTION insn_cave = (PPPC_INSTRUCTION)cave;
                // dcbst ra,rb
                PPC_INSTRUCTION AotInsn;
                AotInsn.Long = 0;
                AotInsn.Primary_Op = X31_OP;
                AotInsn.Xform_XO = DCBST_OP;
                AotInsn.Xform_RA = insn->Xform_RA;
                AotInsn.Xform_RB = insn->Xform_RB;
                insn_cave[0].Long = AotInsn.Long;
                // stwcx rt,ra,rb
                insn_cave[1].Long = insn->Long;
                // b next_insn
                AotInsn.Long = 0;
                AotInsn.Primary_Op = B_OP;
                AotInsn.Iform_LK = 0;
                AotInsn.Iform_AA = 0;
                LONG JumpOffset = (ULONG)&insn[1] - (ULONG)&insn_cave[2];
                if (!is_offset_in_branch_range(JumpOffset)) {
                    return _E2BIG;
                }
                AotInsn.Iform_LI = JumpOffset >> 2;
                insn_cave[2].Long = AotInsn.Long;

                AotInsn.Long = 0;
                AotInsn.Primary_Op = B_OP;
                AotInsn.Iform_LK = 0;
                AotInsn.Iform_AA = 0;
                JumpOffset = (ULONG)&insn_cave[0] - (ULONG)&insn[0];
                if (!is_offset_in_branch_range(JumpOffset)) {
                    return _E2BIG;
                }
                AotInsn.Iform_LI = JumpOffset >> 2;
                insn->Long = AotInsn.Long;
            }

            // Deal with stwcx instructions in PTE functions
            for (ULONG addr = (ULONG)s_NtKernelPteStart; addr < (ULONG)s_NtKernelPteEnd; addr += 4) {
                PPPC_INSTRUCTION insn = (PPPC_INSTRUCTION)addr;
                if (insn->Primary_Op != X31_OP || insn->Xform_XO != STWCX_RC_OP) continue;
                // start from the start of pte start, to ensure space can be found.
                PULONG cave = (PULONG)s_NtKernelPteStart;
                for (; cave < (PULONG)s_NtKernelPteEnd; cave++) {
                    // we need three zeroed out entries in this cave in a row.
                    if (cave[0] == 0 && cave[1] == 0 && cave[2] == 0) break;
                }
                if (cave >= (PULONG)s_NtKernelPteEnd) return 11100; // can't find a cave

                PPPC_INSTRUCTION insn_cave = (PPPC_INSTRUCTION)cave;
                // dcbst ra,rb
                PPC_INSTRUCTION AotInsn;
                AotInsn.Long = 0;
                AotInsn.Primary_Op = X31_OP;
                AotInsn.Xform_XO = DCBST_OP;
                AotInsn.Xform_RA = insn->Xform_RA;
                AotInsn.Xform_RB = insn->Xform_RB;
                insn_cave[0].Long = AotInsn.Long;
                // stwcx rt,ra,rb
                insn_cave[1].Long = insn->Long;
                // b next_insn
                AotInsn.Long = 0;
                AotInsn.Primary_Op = B_OP;
                AotInsn.Iform_LK = 0;
                AotInsn.Iform_AA = 0;
                LONG JumpOffset = (ULONG)&insn[1] - (ULONG)&insn_cave[2];
                if (!is_offset_in_branch_range(JumpOffset)) {
                    return _E2BIG;
                }
                AotInsn.Iform_LI = JumpOffset >> 2;
                insn_cave[2].Long = AotInsn.Long;

                AotInsn.Long = 0;
                AotInsn.Primary_Op = B_OP;
                AotInsn.Iform_LK = 0;
                AotInsn.Iform_AA = 0;
                JumpOffset = (ULONG)&insn_cave[0] - (ULONG)&insn[0];
                if (!is_offset_in_branch_range(JumpOffset)) {
                    return _E2BIG;
                }
                AotInsn.Iform_LI = JumpOffset >> 2;
                insn->Long = AotInsn.Long;
            }
        }
    }

    return _ESUCCESS;
}

static ARC_STATUS PePatch_Header(ULONG FileId, PPE_PATCH_ENTRY Patch) {
    (void)FileId;
    PBYTE PeHeader = (PBYTE)Patch->BaseAddress;
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)PeHeader;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return _EBADF; // no DOS header

    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(PeHeader + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) return _EBADF; // no PE header
    PIMAGE_FILE_HEADER FileHeader = &NtHeaders->FileHeader;

    USHORT NumberOfSections = FileHeader->NumberOfSections;
    PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&FileHeader[1];
    PIMAGE_SECTION_HEADER Sections = (PIMAGE_SECTION_HEADER)((size_t)OptionalHeader + FileHeader->SizeOfOptionalHeader);

    bool HasRelocations = false;
    {
        PIMAGE_DATA_DIRECTORY RelocDir = &OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        HasRelocations = RelocDir->VirtualAddress != 0 && RelocDir->Size != 0;
    }

    // If last section is ".debug" it won't be loaded.
    ULONG SizeOfImage = OptionalHeader->SizeOfImage;
    if (!strcmp((char*)Sections[NumberOfSections - 1].Name, ".debug")) {
        NumberOfSections--;
        SizeOfImage -= Sections[NumberOfSections].SizeOfRawData;
        OptionalHeader->SizeOfImage = SizeOfImage;
        FileHeader->NumberOfSections = NumberOfSections;
    }

    // Add the additional section.
    ULONG SizeOfUsedHeaders = sizeof(IMAGE_FILE_HEADER) + FileHeader->SizeOfOptionalHeader + (sizeof(IMAGE_SECTION_HEADER) * NumberOfSections) + DosHeader->e_lfanew;
    ULONG SizeOfAllHeaders = SizeOfUsedHeaders + sizeof(IMAGE_SECTION_HEADER);
    if (SizeOfAllHeaders > OptionalHeader->SizeOfHeaders) {
        // try to sacrifice the DOS stub to gain more space
        // it's not like that part of the file is actually needed anyways
        if ((ULONG)DosHeader->e_lfanew <= sizeof(IMAGE_DOS_HEADER)) {
            return _EBADF;
        }
        ULONG SizeOfDosStub = DosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER);
        SizeOfAllHeaders -= SizeOfDosStub;
        if (SizeOfAllHeaders > OptionalHeader->SizeOfHeaders) {
            // nope, still not enough space
            return _EBADF;
        }

        // pull the headers down
        memcpy(&DosHeader[1], NtHeaders, OptionalHeader->SizeOfHeaders - SizeOfDosStub);
        DosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER);
        // fix the pointers
        NtHeaders = (PIMAGE_NT_HEADERS)&DosHeader[1];
        FileHeader = (PIMAGE_FILE_HEADER)&NtHeaders->FileHeader;
        OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&FileHeader[1];
        Sections = (PIMAGE_SECTION_HEADER)((size_t)OptionalHeader + FileHeader->SizeOfOptionalHeader);
    }

    ULONG SectionIndexToAdd = NumberOfSections;
    ULONG LastSection = NumberOfSections - 1;

    if (HasRelocations) {
        // a PE with relocations means based relocations, .reloc section must be last
        memcpy(&Sections[NumberOfSections], &Sections[NumberOfSections - 1], sizeof(IMAGE_SECTION_HEADER));
        SectionIndexToAdd--;
        LastSection++;
    }

    ULONG TableLength = Patch->SizeOfInjectedSection;

    memset(&Sections[SectionIndexToAdd], 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy((char*)Sections[SectionIndexToAdd].Name, "haustorc", sizeof(Sections[SectionIndexToAdd].Name));
    ULONG NewSectionSize = TableLength;
    NewSectionSize = ARC_ALIGNUP(NewSectionSize, OptionalHeader->SectionAlignment);
    Sections[SectionIndexToAdd].SizeOfRawData = NewSectionSize;
    Sections[SectionIndexToAdd].Misc.VirtualSize = NewSectionSize;
    ULONG NewRva = Sections[SectionIndexToAdd - 1].VirtualAddress + Sections[SectionIndexToAdd - 1].Misc.VirtualSize;
    NewRva = ARC_ALIGNUP(NewRva, OptionalHeader->SectionAlignment);
    Sections[SectionIndexToAdd].VirtualAddress = NewRva;
    Sections[SectionIndexToAdd].PointerToRawData = Sections[LastSection].PointerToRawData + Sections[LastSection].SizeOfRawData;
    Sections[SectionIndexToAdd].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_NOT_PAGED | IMAGE_SCN_CNT_CODE;
    NumberOfSections++;
    FileHeader->NumberOfSections++;
    OptionalHeader->SizeOfCode += NewSectionSize;
    OptionalHeader->SizeOfImage += NewSectionSize;
    SizeOfImage += NewSectionSize;

    if (HasRelocations) {
        // move the relocation section up
        ULONG NewRelocVA = NewRva + NewSectionSize;
        PIMAGE_DATA_DIRECTORY RelocDir = &OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        RelocDir->VirtualAddress += (NewRelocVA - Sections[LastSection].VirtualAddress);
        Sections[LastSection].VirtualAddress = NewRelocVA;
    }
    Patch->ImagePositionOfInjectedSection = Sections[SectionIndexToAdd].PointerToRawData;
    Patch->InjectedSectionIsFinal = (SectionIndexToAdd == (ULONG)(NumberOfSections - 1));
    Patch->IndexOfInjectedSection = SectionIndexToAdd;

    PIMAGE_SECTION_HEADER LastSectionHeader = &Sections[(NumberOfSections - 1)];
    // do what osloader does to calculate last section size
    ULONG LastSectionSize = LastSectionHeader->SizeOfRawData;
    ULONG LastSectionVSize = LastSectionHeader->Misc.VirtualSize;
    if ((LastSectionSize & 1) == 1) LastSectionSize++; // load in WORDs for the checksum we won't be calculating
    if (LastSectionHeader->PointerToRawData == 0) LastSectionSize = 0;
    else if (LastSectionVSize != 0 && LastSectionSize > LastSectionVSize) LastSectionSize = LastSectionVSize;

    // make sure osloader won't calculate the image checksum, this flag bit is only checked there and nowhere else
    FileHeader->Characteristics &= ~IMAGE_FILE_DEBUG_STRIPPED;

    return _ESUCCESS;
}

static ARC_STATUS PePatch_HeaderInitial(ULONG FileId, PPE_PATCH_ENTRY Patch, ULONG Count) {
    // We have PeHeaderInitial only.
    PBYTE PeHeader = Patch->PeHeaderInitial;
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)PeHeader;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return _EBADF; // no DOS header
    if ((DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) > Count) {
        // PE header offset past the number of bytes read
        return _EBADF;
    }

    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(PeHeader + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) return _EBADF; // no PE header
    PIMAGE_FILE_HEADER FileHeader = &NtHeaders->FileHeader;

    if (
        // Don't accept any COFF that isn't for PPC(LE).
        (FileHeader->Machine != IMAGE_FILE_MACHINE_POWERPC) ||
        // Don't accept a COFF that isn't executable.
        (FileHeader->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0 ||
        // Don't accept a COFF with an optional header that's too small. (PE optional header required here!)
        FileHeader->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER)
        ) {
        return _EBADF;
    }

    USHORT NumberOfSections = FileHeader->NumberOfSections;
    PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&FileHeader[1];
    PIMAGE_SECTION_HEADER Sections = (PIMAGE_SECTION_HEADER)((size_t)OptionalHeader + FileHeader->SizeOfOptionalHeader);

    // Optional header magic must be PE32
    if (OptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return _EBADF;

    // All we need to do here is increase SizeOfImage.
    // Don't need to fix section headers yet.

    // osloader does seek back to position zero, so we can do what we want with file APIs here (other than close of course)

    ULONG TableLength = 0;
    ARC_STATUS Status = FindLengthOfCodeTable(FileId, Sections, NumberOfSections, &TableLength);
    if (ARC_FAIL(Status)) return Status;
    if (TableLength == 0) return _ESUCCESS;
    // Add an additional page for hook trampolines
    //TableLength += PAGE_SIZE;
    // Align to page size
    TableLength = (TableLength + PAGE_SIZE - 1) & ~PAGE_SIZE;
    Patch->SizeOfInjectedSection = TableLength;
    OptionalHeader->SizeOfImage += TableLength;

    // If last section is .debug, fix the offsets / etc, so the "last" section is still loaded
    if (!strcmp((char*)Sections[NumberOfSections - 1].Name, ".debug")) {
        Sections[NumberOfSections - 1].Name[5] = 'f';
        // this is usually done by osloader
        OptionalHeader->SizeOfImage -= Sections[NumberOfSections - 1].SizeOfRawData;
    }
    else {
        // Otherwise, add another section to load
        FileHeader->NumberOfSections++;
    }
    return _ESUCCESS;
}

static ARC_STATUS fhook_BlSeek(ULONG FileId, PLARGE_INTEGER Offset, SEEK_MODE SeekMode) {
    // Get the patch entry
    PPE_PATCH_ENTRY Patch = &s_PatchTable[FileId];
    if (Patch->State == STATE_READING_SECTIONS) {
        if (Offset->QuadPart == Patch->ImagePositionOfInjectedSection && SeekMode == SeekAbsolute) {
            // Seeking to injected section.
            Patch->State = STATE_READING_SECTION_INJECTED;
            return _ESUCCESS;
        }
    }
    return DEVICE_ENTRY_CALL_ORIG(Seek, FileId, Offset, SeekMode);
}

static ARC_STATUS fhook_BlRead(ULONG FileId, PVOID Buffer, ULONG Length, PU32LE Count) {
    // Get the patch entry
    PPE_PATCH_ENTRY Patch = &s_PatchTable[FileId];
    if (Patch->State == STATE_READING_SECTION_INJECTED) {
        // Memset the entire section to zero for now, data will be written out later
        memset(Buffer, 0, Length);
        Patch->State = STATE_READING_SECTIONS_AFTER_INJECTED;

        if (Patch->InjectedSectionIsFinal) {
            // this was the last section to load, so perform relocation now!
            Patch->State = STATE_NOP;
            return PePatch_Relocate(Patch);
        }
        return _ESUCCESS;
    }
    // Call original read function
    ARC_STATUS Status = DEVICE_ENTRY_CALL_ORIG(Read, FileId, Buffer, Length, Count);
    // which must succeed if we are to do anything here
    if (ARC_FAIL(Status)) {
        Patch->State = STATE_NOP;
        return Status;
    }

    switch (Patch->State) {
    case STATE_OPENED:
        // must be reading 0x400 bytes
        if (Length != 0x400) {
            Patch->State = STATE_NOP;
            return Status;
        }

        // fill in the pointer
        Patch->PeHeaderInitial = (PBYTE)Buffer;

        // attempt to patch the SizeOfImage
        if (ARC_FAIL(PePatch_HeaderInitial(FileId, Patch, Count->v))) {
            Patch->State = STATE_NOP;
        }
        else {
            Patch->State = STATE_READING_HEADER;
        }
        return Status;
    case STATE_READING_HEADER:
        // fill in the pointer
        Patch->BaseAddress = (size_t)Buffer;

        // attempt to patch the header now we have the entire thing
        // if the size of injected section is zero, don't bother.
        if (Patch->SizeOfInjectedSection == 0 || ARC_FAIL(PePatch_Header(FileId, Patch))) {
            Patch->State = STATE_NOP;
        }
        else {
            Patch->State = STATE_READING_SECTIONS;
        }
        return Status;

    case STATE_READING_SECTIONS_AFTER_INJECTED:
        // The injected section is either the last or second to last section.
        // Which means there's no need for any length check here, if we got here we're reading the last section.
        // Loaded the final section, perform relocation.
        Patch->State = STATE_NOP;
        return PePatch_Relocate(Patch);

    default:
        break;
    }

    return Status;
}

static AIXCALL_FPTR hook_BlSeek = { 0 };
static AIXCALL_FPTR hook_BlRead = { 0 };

static ARC_STATUS GetImageBase(ULONG DeviceId, PCHAR Dir, PCHAR FileName, PULONG ImageBase) {
    CHAR FullPath[260];
    UCHAR HeaderPage[PAGE_SIZE + 0x40];
    PBYTE LocalPointer = (PVOID)(((ULONG)(&HeaderPage[DCACHE_LINE_SIZE - 1])) & ~(DCACHE_LINE_SIZE - 1));
    snprintf(FullPath, sizeof(FullPath), "%s%s", Dir, FileName);
    U32LE FileId;
    ARC_STATUS Status = orig_BlOpen(DeviceId, FullPath, ArcOpenReadOnly, &FileId);
    if (ARC_FAIL(Status)) return Status;

    ULONG Id = FileId.v;
    PBL_DEVICE_ENTRY_TABLE DeviceEntryTable = (PBL_DEVICE_ENTRY_TABLE)s_BlFileTable[Id].DeviceEntryTable;
    orig_DeviceEntryTable[Id] = DeviceEntryTable;
    U32LE Count;
    Status = DEVICE_ENTRY_CALL_ORIG(Read, Id, LocalPointer, PAGE_SIZE, &Count);
    DEVICE_ENTRY_CALL_ORIG(Close, Id);
    if (ARC_FAIL(Status)) {
        return Status;
    }

    PIMAGE_DOS_HEADER Mz = (PIMAGE_DOS_HEADER)LocalPointer;
    if (Mz->e_magic != IMAGE_DOS_SIGNATURE) return _EBADF;
    if ((ULONG)Mz->e_lfanew > (PAGE_SIZE - sizeof(IMAGE_NT_HEADERS))) return _EBADF;
    PIMAGE_NT_HEADERS Pe = (PIMAGE_NT_HEADERS)&LocalPointer[Mz->e_lfanew];
    if (Pe->Signature != IMAGE_NT_SIGNATURE) return _EBADF;
    if (Pe->FileHeader.Machine != IMAGE_FILE_MACHINE_POWERPC) return _EBADF;
    *ImageBase = Pe->OptionalHeader.ImageBase;
    return _ESUCCESS;
}

typedef enum {
    FILE_NOT_PE,
    FILE_KERNEL_UNIPROCESSOR,
    FILE_KERNEL_MULTIPROCESSOR
} KERNEL_FILE_TYPE;

static ARC_STATUS GetKernelType(ULONG FileId, KERNEL_FILE_TYPE* KernelFileType) {
    UCHAR HeaderPage[PAGE_SIZE + 0x40];
    PBYTE LocalPointer = (PVOID)(((ULONG)(&HeaderPage[DCACHE_LINE_SIZE - 1])) & ~(DCACHE_LINE_SIZE - 1));

    *KernelFileType = FILE_NOT_PE;

    PBL_DEVICE_ENTRY_TABLE DeviceEntryTable = (PBL_DEVICE_ENTRY_TABLE)s_BlFileTable[FileId].DeviceEntryTable;
    orig_DeviceEntryTable[FileId] = DeviceEntryTable;
    U32LE Count;
    ARC_STATUS Status = DEVICE_ENTRY_CALL_ORIG(Read, FileId, LocalPointer, PAGE_SIZE, &Count);
    if (ARC_FAIL(Status)) return Status;
    LARGE_INTEGER SeekOffset = INT32_TO_LARGE_INTEGER(0);
    Status = DEVICE_ENTRY_CALL_ORIG(Seek, FileId, &SeekOffset, SeekAbsolute);
    if (ARC_FAIL(Status)) return Status;

    // for initial header size checks, return success.
    // only return error if the file seems to be a PE. (that is, valid MZ header pointing to PE header)
    // size check against MZ header only
    if (Count.v < sizeof(IMAGE_DOS_HEADER)) return _ESUCCESS;
    PIMAGE_DOS_HEADER Mz = (PIMAGE_DOS_HEADER)LocalPointer;
    if (Mz->e_magic != IMAGE_DOS_SIGNATURE) return _ESUCCESS;
    if ((ULONG)Mz->e_lfanew > (PAGE_SIZE - sizeof(IMAGE_NT_HEADERS))) return _ESUCCESS;
    PIMAGE_NT_HEADERS Pe = (PIMAGE_NT_HEADERS)&LocalPointer[Mz->e_lfanew];
    PIMAGE_FILE_HEADER FileHeader = &Pe->FileHeader;
    // size check against MZ + PE file header
    if (Count.v < (Mz->e_lfanew + sizeof(*Pe))) return _ESUCCESS;
    if (Pe->Signature != IMAGE_NT_SIGNATURE) return _ESUCCESS;
    if (FileHeader->Machine != IMAGE_FILE_MACHINE_POWERPC) return _EBADF;

    // Read the entire file.
    ULONG FileLength = Pe->OptionalHeader.SizeOfHeaders;
    USHORT NumberOfSections = FileHeader->NumberOfSections;
    PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&FileHeader[1];
    PIMAGE_SECTION_HEADER Sections = (PIMAGE_SECTION_HEADER)((size_t)OptionalHeader + FileHeader->SizeOfOptionalHeader);
    // size check against entire PE headers.
    if (Count.v < (Mz->e_lfanew + sizeof(*Pe) + FileHeader->SizeOfOptionalHeader + (NumberOfSections * sizeof(*Sections)))) return _EBADF;
    for (int i = 0; i < NumberOfSections; i++) {
        ULONG SizeAfterSection = Sections[i].PointerToRawData + Sections[i].SizeOfRawData;
        if (SizeAfterSection > FileLength) FileLength = SizeAfterSection;
    }

    if ((ULONG)ScratchAddress + FileLength > ScratchEnd()) return _E2BIG;

    Status = DEVICE_ENTRY_CALL_ORIG(Read, FileId, ScratchAddress, FileLength, &Count);
    if (ARC_FAIL(Status)) return Status;
    Status = DEVICE_ENTRY_CALL_ORIG(Seek, FileId, &SeekOffset, SeekAbsolute);
    if (ARC_FAIL(Status)) return Status;
    
    // Multiprocessor kernel imports hal!HalStartNextProcessor - uniprocessor kernel does not
    static const char s_MpKrnlPattern[] = "HalStartNextProcessor";
    if (mem_mem((PBYTE)ScratchAddress, s_MpKrnlPattern, Count.v, sizeof(s_MpKrnlPattern)) == NULL) {
        *KernelFileType = FILE_KERNEL_UNIPROCESSOR;
    }
    else {
        *KernelFileType = FILE_KERNEL_MULTIPROCESSOR;
    }
    return _ESUCCESS;
}

static ARC_STATUS hook_BlOpen(ULONG DeviceId, PCHAR OpenPath, OPEN_MODE OpenMode, PU32LE FileId) {
    //printf("hook_BlOpen: %s\r\n", OpenPath);
    ARC_STATUS Status;
#if 0 // todo: probably need to still do this, but pass them to hal exports???
    // Get the base addresses of kernel32, user32, ole32 if needed.
    if (s_Kernel32Base == 0) {
        PCHAR System32 = strstr(OpenPath, "\\system32\\");
        if (System32 != NULL) {
            CHAR System32Dir[260];
            System32[0] = 0;
            snprintf(System32Dir, sizeof(System32Dir), "%s\\system32\\", OpenPath);
            System32[0] = '\\';
            Status = GetImageBase(DeviceId, System32Dir, "kernel32.dll", &s_Kernel32Base);
            if (ARC_FAIL(Status)) return Status;
            Status = GetImageBase(DeviceId, System32Dir, "user32.dll", &s_User32Base);
            if (ARC_FAIL(Status)) return Status;
            Status = GetImageBase(DeviceId, System32Dir, "ole32.dll", &s_Ole32Base);
            if (ARC_FAIL(Status)) return Status;
        }
    }
#endif
    // Call the original file open function.
    Status = orig_BlOpen(DeviceId, OpenPath, OpenMode, FileId);
    if (ARC_FAIL(Status)) return Status;

    // If the uniprocessor kernel was loaded, do nothing.
    if (s_KernelIsUniProcessor) return Status;

    // File has been opened.
    ULONG Id = FileId->v;

    // osloader and setupldr will always load the kernel as the first PE loaded.
    // check here as we don't want to hook the PE loader at all if the uniprocessor kernel was loaded
    // also specify whether the kernel is currently being loaded so additional patches can be applied.
    if (!s_KernelIsUniProcessor && !s_KernelIsNotUniProcessor) {

        KERNEL_FILE_TYPE KernelType = FILE_NOT_PE;
        // If this is a PE, it must be the kernel, see above.
        Status = GetKernelType(Id, &KernelType);
        if (ARC_FAIL(Status)) return Status;

        if (KernelType == FILE_KERNEL_UNIPROCESSOR) {
            s_KernelIsUniProcessor = true;
            return Status;
        }
        else if (KernelType == FILE_KERNEL_MULTIPROCESSOR) {
            s_KernelIsNotUniProcessor = true;
            s_IsLoadingNtKernel = true;
        }
        else { // KernelType == FILE_NOT_PE
            s_IsLoadingNtKernel = false;
            // This is not a PE file, so don't bother hooking here.
            return Status;
        }
    }
    else {
        // s_KernelIsNotUniProcessor == true
        // has already loaded multiprocessor kernel
        // thus, this must not be loading the kernel
        s_IsLoadingNtKernel = false;
    }

    
    PBL_DEVICE_ENTRY_TABLE DeviceEntryTable = (PBL_DEVICE_ENTRY_TABLE)s_BlFileTable[Id].DeviceEntryTable;
    // Make a copy of the original device entry table pointer.
    orig_DeviceEntryTable[Id] = DeviceEntryTable;
    // Make a copy of the contents so the function pointers within can be hooked.
    hook_DeviceEntryTable[Id] = *DeviceEntryTable;
    s_BlFileTable[Id].DeviceEntryTable = (ULONG)&hook_DeviceEntryTable[Id];
    // Hook the various functions within it.
    // For the PE patcher, it's required to hook seek() and read().

    if (hook_BlSeek.Function == 0) {
        hook_BlSeek = DEVICE_ENTRY_GET(Seek, Id);
        hook_BlRead = DEVICE_ENTRY_GET(Read, Id);
        hook_BlSeek.Function = (size_t)fhook_BlSeek;
        hook_BlRead.Function = (size_t)fhook_BlRead;
    }
    DEVICE_ENTRY_HOOK(Seek, Id, hook_BlSeek);
    DEVICE_ENTRY_HOOK(Read, Id, hook_BlRead);

    // Set up the PE patch entry structure for this file ID
    PPE_PATCH_ENTRY Patch = &s_PatchTable[Id];
    memset(Patch, 0, sizeof(*Patch));
    Patch->State = STATE_OPENED;

    memcpy(Patch->FileName, s_BlFileTable[Id].FileName, s_BlFileTable[Id].FileNameLength);
    // All done
    return Status;
}

static ARC_STATUS hook_BlSetupForNt(PVOID LoaderParameterBlock) {
    // Do final changes to allow NT kernel init to work
    
    // Call the original function, if it failed, return that failure.
    ARC_STATUS Status = orig_BlSetupForNt(LoaderParameterBlock);
    if (ARC_FAIL(Status)) return Status;

    // On Flipper? nothing needs to be done
    if (s_RuntimePointers[RUNTIME_SYSTEM_TYPE].v == ARTX_SYSTEM_FLIPPER) return Status;

    // Shutdown USB subsystem.
    void UlmsFinalise(void);
    UlmsFinalise();
    void UlkShutdown(void);
    UlkShutdown();
    void UlShutdown(void);
    UlShutdown();

    // Shutdown SDMC driver.
    bool SdmcFinalise(void);
    SdmcFinalise();


    // dolphin is broken and *requires* an IOS restart here
    if (s_RuntimePointers[RUNTIME_IN_EMULATOR].v) {
        // Restart IOS.

        ULONG IosVersion = NativeReadBase32((PVOID)0x60000000, 0x3140);
        if (IosVersion < 3 || IosVersion >= 255) IosVersion = 58;

        IOS_HANDLE hEs;
        LONG Result = PxiIopOpen("/dev/es", IOSOPEN_NONE, &hEs);
        if (Result < 0) return _EFAULT;

        static ULONG xTitleId[2] ARC_ALIGNED(32);
        static ULONG cntviews[2] ARC_ALIGNED(32);
        static UCHAR tikviews[0xd8 * 4] ARC_ALIGNED(32);
        static IOS_IOCTL_VECTOR vectors[3] ARC_ALIGNED(32);

        enum {
            IOCTL_ES_LAUNCH = 0x08,
            IOCTL_ES_GETVIEWCNT = 0x12,
            IOCTL_ES_GETVIEWS = 0x13
        };

        xTitleId[0] = IosVersion;
        xTitleId[1] = 1;
        vectors[0].Pointer = xTitleId;
        vectors[0].Length = sizeof(xTitleId);
        vectors[1].Pointer = cntviews;
        vectors[1].Length = sizeof(ULONG);
        Result = PxiIopIoctlv(hEs, IOCTL_ES_GETVIEWCNT, 1, 1, vectors, 0, 0);
        if (Result < 0) return _EFAULT;
        if (cntviews[1] > 4) return _EFAULT;


        vectors[0].Pointer = xTitleId;
        vectors[0].Length = sizeof(xTitleId);
        vectors[1].Pointer = cntviews;
        vectors[1].Length = sizeof(ULONG);
        vectors[2].Pointer = tikviews;
        vectors[2].Length = 0xd8 * cntviews[1];
        Result = PxiIopIoctlv(hEs, IOCTL_ES_GETVIEWS, 2, 1, vectors, 0, 0);
        if (Result < 0) return _EFAULT;
        NativeWriteBase32((PVOID)0x60000000, 0x3140, 0);
        vectors[0].Pointer = xTitleId;
        vectors[0].Length = sizeof(xTitleId);
        vectors[1].Pointer = tikviews;
        vectors[1].Length = 0xd8;
        Result = PxiIopIoctlvReboot(hEs, IOCTL_ES_LAUNCH, 2, 0, vectors, 0, 0);
        if (Result < 0) return _EFAULT;

        while ((LoadToRegister32(NativeReadBase32((PVOID)0x60000000, 0x3140)) >> 16) == 0) udelay(1000);

        for (ULONG counter = 0; counter <= 400; counter++) {
            udelay(1000);

            if ((MmioReadBase32((PVOID)0x6D000000, 4) & 6) != 0)
                break;
        }
#if 0
        // try opening ES again
        if (s_RuntimePointers[RUNTIME_IN_EMULATOR].v == 0) {
            Result = PxiIopOpen("/dev/es", IOSOPEN_NONE, &hEs);
            if (Result < 0) return _EFAULT;
            PxiIopClose(hEs);

            // delay a bit
            mdelay(1000);
        }
#endif

        data_cache_invalidate((void*)0x80000000, 0x4000);
    }

    return Status;
}


void OslHookInit(PVOID BlOpen, PVOID BlFileTable, PVOID BlSetupForNt, PVOID BlReadSignature) {
    (void)BlReadSignature;

    // On Espresso, hook BlOpen and get BlFileTable, to hook the PE loader in osloader/setupldr
    // This is so all boot-time loaded PEs get patched:
    // stwcx rS,rA,rB to dcbst rA,rB ; stwcx rS,rA,rB - patching in a branch to a code cave (one created by extra PE section) as required.
    // This is to work around a hardware erratum on multiprocessor Espresso.
    // When NT is booted, the HAL can hook the kernel's PE loader to do the same thing.
    ULONG Pvr;
    __asm__ __volatile__("mfpvr %0" : "=r"(Pvr));
    Pvr >>= 16;
    if (Pvr == 0x7001) {
        orig_BlOpen = (PBL_OPEN_ROUTINE)BlOpen;
        s_BlFileTable = (PBL_FILE_TABLE)BlFileTable;
        if (ScratchAddress == NULL) ScratchAddress = ArcLoadGetScratchAddress();
        PPCHook_Hook((PVOID*)&orig_BlOpen, hook_BlOpen);
    }

    orig_BlSetupForNt = (tfpBlSetupForNt)BlSetupForNt;
    PPCHook_Hook((PVOID*)&orig_BlSetupForNt, hook_BlSetupForNt);
}
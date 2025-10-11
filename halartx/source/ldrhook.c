// Hooks the NT kernel's PE loader to work around the multiprocessor stwcx erratum in Espresso

#define DEVL 1
#include <ntddk.h>
#include <arc.h>
#include <stdio.h>
#include "runtime.h"
#include "ppcinst.h"
#include "peimage.h"
#include "backport.h"

#define ARC_BIT(x) (1 << (x))
#define ARC_ALIGNDOWN(x, align) ((x) & -(align))
#define ARC_ALIGNUP(x, align) (-(-(x) & -(align)))
#define INT32_TO_LARGE_INTEGER(i32) (LARGE_INTEGER){ .LowPart = (i32), .HighPart = 0 }

enum {
    SEC_IMAGE = 0x1000000,
    SEC_COMMIT = 0x08000000,
};

// https://github.com/fail0verflow/hbc/blob/a8e5f6c0f7e484c7f7112967eee6eee47b27d9ac/wiipax/stub/sync.c#L29
static void sync_before_exec(const void* p, ULONG len)
{

	ULONG a, b;

	a = (ULONG)p & ~0x1f;
	b = ((ULONG)p + len + 0x1f) & ~0x1f;

	for (; a < b; a += 32)
		asm("dcbst 0,%0 ; sync ; icbi 0,%0" : : "b"(a));

	asm("sync ; isync");
}

// PE patcher.

#define INT32_MAX MAXLONG

typedef enum {
    AOT_NONE,
    AOT_STWCX,
} INSTRUCTION_AOT_TYPE;

typedef struct _PE_PATCH_ENTRY {
    PUCHAR PointerInjectedSection; // Base of the injected section.
    ULONG BaseAddress; // Actual base address of the PE, reads OptionalHeader->SizeOfHeaders bytes here
    ULONG SizeOfInjectedSection; // Size of injected section, to hold original instructions that were patched, and hook trampolines
    ULONG IndexOfInjectedSection; // Index of injected section
    ULONG RealImageBase; // Real ImageBase, where needed.
} PE_PATCH_ENTRY, *PPE_PATCH_ENTRY;

typedef struct _PE_PATCH_SECTION_ENTRY {
    ULONG PointerToRawData; // Offset into original file where this part of the file is.
    ULONG OurOffset; // Offset into section memory where this part of the file is.
    ULONG SizeOfRawData; // Size of section on disk (that is expected to be read)
} PE_PATCH_SECTION_ENTRY, * PPE_PATCH_SECTION_ENTRY;

typedef struct _PE_PATCH_ENTRY_FILE_NT {
    struct _PE_PATCH_ENTRY_FILE_NT* Next; // Single linked list
    PVOID FileObject; // Underlying file object
    PVOID BaseSectionObject; // Section object containing manually mapped patched PE
    PVOID InjectedSectionObject; // Section object containing data of patch-data.
    ULONG InjectedSectionStart; // "File offset" of injected section start.
    ULONG InjectedSectionEnd; // "File offset" of injected section end.
    ULONG RealImageBase; // Real ImageBase, stored here then placed in section patch entry later.
    ULONG SizeOfHeaders; // Size of headers after patch.
    PPE_PATCH_SECTION_ENTRY PatchedSections; // Description of PE sections that were patched
    ULONG PatchedSectionsCount; // Count of PE sections that were patched.
    PE_PATCH_ENTRY PatchEntry; // ARC patch entry structure.
} PE_PATCH_ENTRY_FILE_NT, * PPE_PATCH_ENTRY_FILE_NT;

typedef struct _PE_PATCH_ENTRY_NT {
    struct _PE_PATCH_ENTRY_NT * Next; // Single linked list
    struct _PE_PATCH_ENTRY_FILE_NT * PatchFile; // Patch entry for the underlying file object
    PVOID SectionObject; // Section object of the image section being loaded.
    PVOID FileObject; // Underlying file object for the created section. Must match PatchFile->FileObject.
    ULONG SizeOfMap; // Mapped image size for when patching is deferred.
} PE_PATCH_ENTRY_NT, *PPE_PATCH_ENTRY_NT;

static inline BOOLEAN is_offset_in_branch_range(long offset)
{
	return (offset >= -0x2000000 && offset <= 0x1fffffc && !(offset & 0x3));
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

static BOOLEAN FindLengthOfCodeTable(ULONG ImageBase, PIMAGE_SECTION_HEADER Sections, USHORT NumberOfSections, PULONG TableLength, PULONG TextCaveRva, PULONG TextCaveLength) {
    if (TableLength == NULL) {
        return FALSE;
    }
    ARC_STATUS Status;
    ULONG CalculatedTableLength = 0;

    // For all code sections, read to scratch chunk
    INSTRUCTION_AOT_TYPE AotType;

    // If this PE has one section with IMAGE_SCN_CNT_CODE flag, then look for those.
    // Otherwise, look for sections marked executable.
    BOOLEAN HasAtLeastOneCodeSection = FALSE;
    for (int Section = 0; Section < NumberOfSections; Section++) {
        if ((Sections[Section].Characteristics & IMAGE_SCN_CNT_CODE) != 0) {
            HasAtLeastOneCodeSection = TRUE;
            break;
        }
    }

	ULONG FirstCodeSection = NumberOfSections;
    ULONG SectionFlags = (HasAtLeastOneCodeSection ? IMAGE_SCN_CNT_CODE : IMAGE_SCN_MEM_EXECUTE);
    for (int Section = 0; Section < NumberOfSections; Section++) {
        if ((Sections[Section].Characteristics & SectionFlags) == 0) continue;
		if (FirstCodeSection == NumberOfSections) FirstCodeSection = Section;

        // Walk through all instructions, looking for stwcx instructions.
        PULONG Instruction = 0;
        for (ULONG i = 0; i < Sections[Section].SizeOfRawData / sizeof(ULONG); i++) {
            ULONG RealIndex = i;
			Instruction = (PULONG)(ULONG)(ImageBase + Sections[Section].VirtualAddress);
            ULONG AotLength = InstructionNeedsAot(Instruction[RealIndex], &AotType);
            if (AotLength != 0) {
                CalculatedTableLength += AotLength;
            }
        }
    }
	
	*TextCaveRva = 0;
	*TextCaveLength = 0;
	if (FirstCodeSection != NumberOfSections) {
		PULONG SectionStart = (PULONG)(ULONG)(ImageBase + Sections[FirstCodeSection].VirtualAddress);
		PULONG SectionPtr = (PULONG)(ULONG)(ImageBase + Sections[FirstCodeSection].VirtualAddress + Sections[FirstCodeSection].SizeOfRawData - sizeof(ULONG));
		ULONG SizeOfCave = 0;
		while (SectionPtr > SectionStart) {
			if (*SectionPtr != 0) break;
			// If the byte before this 32-bit value isn't zero, then stop here to prevent overwriting any null terminator.
			if (SectionPtr[-1] != 0) {
				PUCHAR SectionPtr8 = (PUCHAR)SectionPtr;
				if (SectionPtr8[-1] != 0) {
					break;
				}
			}
			SizeOfCave += sizeof(*SectionPtr);
			SectionPtr--;
		}
		*TextCaveLength = SizeOfCave;
		*TextCaveRva = Sections[FirstCodeSection].VirtualAddress + Sections[FirstCodeSection].SizeOfRawData - SizeOfCave;
	}
	
    *TableLength = CalculatedTableLength;
    return TRUE;
}

static ULONG InstructionPatchAot(
    PULONG SectionBase,
    PULONG* TablePointer,
    ULONG Offset,
    ULONG TableSectionStart,
    ULONG TableSectionLength,
	PBOOLEAN InstructionReplaced
) {
	*InstructionReplaced = FALSE;
    ULONG instruction = SectionBase[Offset];
    INSTRUCTION_AOT_TYPE AotType;
    ULONG AotLength = InstructionNeedsAot(instruction, &AotType);

    if (AotLength == 0) return 0;

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
	*InstructionReplaced = TRUE;
    return 0;
}

static ULONG PePatch_Relocate(PPE_PATCH_ENTRY Patch, PRTL_BITMAP PatchedPages) {
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

    ULONG Status = 0;

    ULONG OldBase = OptionalHeader->ImageBase;
    if (Patch->RealImageBase != 0) OldBase = Patch->RealImageBase;

    PIMAGE_SECTION_HEADER TableSection = &Sections[Patch->IndexOfInjectedSection];
    ULONG TableSectionLength = TableSection->Misc.VirtualSize;
    ULONG TableSectionVa = TableSection->VirtualAddress;
    ULONG TableSectionStart = ImageBase + TableSectionVa;
    ULONG pTableSectionStart = (ULONG)Patch->PointerInjectedSection;
	if (Patch->IndexOfInjectedSection == 0) {
		// No section was injected, PointerInjectedSection is to code cave in .text:
		TableSectionLength = Patch->SizeOfInjectedSection;
		TableSectionVa = (ULONG)Patch->PointerInjectedSection - ImageBase;
		TableSectionStart = (ULONG)Patch->PointerInjectedSection;
	}
    PULONG TablePointer[] = { (PULONG)Patch->PointerInjectedSection, (PULONG)TableSectionStart };
    {
        // Need to patch instructions.
        // We need to blocklist some areas.

        PIMAGE_DATA_DIRECTORY ExceptionDir = &OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        BOOLEAN HasExceptions = ExceptionDir->VirtualAddress != 0 && ExceptionDir->Size != 0;

        if (!HasExceptions) {
            // For a PE, exception directory is required, due to NT 3.51/NT 4.0 having rodata sections merged into .text
            return 10002;// _EFAULT;
        }

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
                BOOLEAN doAdditional = FALSE;
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

                        //PeekWithStackFrame((PULONG)&additionalBig[off]);

						BOOLEAN InstructionReplaced;
                        Status = InstructionPatchAot(
                            additionalLittle,
                            TablePointer,
                            off,
                            pTableSectionStart,
                            TableSectionLength,
							&InstructionReplaced
                        );
                        if (Status != 0) return Status;
						if (InstructionReplaced) {
							ULONG currRva = (ULONG)&additionalLittle[off] - ImageBase;
							ULONG currPage = currRva / PAGE_SIZE;
							RtlSetBits(PatchedPages, currPage, 1);
						}
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

                //PeekWithStackFrame((PULONG)&BaseBig[off]);

				BOOLEAN InstructionReplaced;
                Status = InstructionPatchAot(
                    BaseLittle,
                    TablePointer,
                    off,
                    pTableSectionStart,
                    TableSectionLength,
					&InstructionReplaced
                );
                if (Status != 0) return Status;
				if (InstructionReplaced) {
					ULONG currRva = (ULONG)&BaseLittle[off] - ImageBase;
					ULONG currPage = currRva / PAGE_SIZE;
					RtlSetBits(PatchedPages, currPage, 1);
				}
            }
        }
    }

    return 0;
}

// Hook implementations.

typedef NTSTATUS
(*tfpObCreateObject)(
	IN KPROCESSOR_MODE AttributesMode,
	IN POBJECT_TYPE ObjectType,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN KPROCESSOR_MODE AccessMode,
	IN PVOID Reserved,
	IN ULONG ObjectSize,
	IN ULONG PagedPoolCharge,
	IN ULONG NonPagedPoolCharge,
	OUT PVOID* Object
);

typedef NTSTATUS
(*tfpObReferenceObjectByPointer)(
	PVOID Object,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode
);

typedef NTSTATUS
(*tfpMmCreateSection)(
	OUT PVOID *SectionObject,
	IN ULONG DesiredAccess,
	IN PVOID ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN PVOID FileHandle OPTIONAL,
	IN PVOID FileObject OPTIONAL
);

typedef NTSTATUS
(*tfpMmMapViewInSystemSpace)(
	IN PVOID Section,
	OUT PVOID* MappedBase,
	IN OUT PULONG ViewSize
);

typedef void (*tfpMiSectionDelete)(PVOID Object);
typedef void (*tfpIopDeleteFile)(PVOID Object);

typedef NTSTATUS
(*tfpIoPageRead)(
	IN PVOID FileObject,
	IN PMDL MemoryDescriptorList,
	IN PLARGE_INTEGER StartingOffset,
	IN PKEVENT Event,
	OUT PIO_STATUS_BLOCK IoStatusBlock
);

typedef NTSTATUS (*tfpFsRtlGetFileSize)(PVOID FileObject, PLARGE_INTEGER FileSize);

typedef PVOID (*tfpMmPageEntireDriver)(PVOID AddrInSection);

typedef ULONG (*tfpRtlVirtualUnwind)(
	ULONG ControlPc,
	PRUNTIME_FUNCTION_ENTRY FunctionEntry,
	PCONTEXT ContextRecord,
	PBOOLEAN InFunction,
	PULONG EstablisherFrame,
	PVOID ContextPointers,
	ULONG LowStackLimit,
	ULONG HighStackLimit
);

typedef PVOID (*tfpRtlPcToFileHeader)(ULONG Address, PVOID BaseAddress);

#define DEFINE_ORIG(name) static AIXCALL_FPTR fporig_##name; static tfp##name orig_##name = (tfp##name)&fporig_##name
DEFINE_ORIG(ObCreateObject);
//DEFINE_ORIG(ObReferenceObjectByPointer);
DEFINE_ORIG(MmCreateSection);
DEFINE_ORIG(MmMapViewInSystemSpace);
DEFINE_ORIG(MiSectionDelete);
DEFINE_ORIG(IopDeleteFile);
DEFINE_ORIG(IoPageRead);
DEFINE_ORIG(FsRtlGetFileSize);
DEFINE_ORIG(MmPageEntireDriver);
DEFINE_ORIG(RtlVirtualUnwind);

static AIXCALL_FPTR fp_RtlPcToFileHeader;
static tfpRtlPcToFileHeader RtlPcToFileHeader = (tfpRtlPcToFileHeader)&fp_RtlPcToFileHeader;

enum {
	// file_object has a size element, but the structure size never changed until NT6x
	FILE_OFFSET_OF_ADDED = 0x70,
	// section object doesn't store size
	// but SECTION struct has always been 0x28 for 32-bit architectures
	// and this is the same for powerpc
	SECTION_OFFSET_OF_ADDED = 0x28,
};

#define PATCH_ENTRY_FILE(FileObject) *(PPE_PATCH_ENTRY_FILE_NT*)((ULONG)(FileObject) + FILE_OFFSET_OF_ADDED)
#define PATCH_ENTRY_SECTION(SectionObject) *(PPE_PATCH_ENTRY_NT*)((ULONG)(SectionObject) + SECTION_OFFSET_OF_ADDED)


static void NtPe_DeletePatchEntry(PPE_PATCH_ENTRY_NT PatchEntry) {
	PVOID SectionObject = PatchEntry->SectionObject;
	if (SectionObject != NULL) PATCH_ENTRY_SECTION(SectionObject) = NULL;
	
    // Free the patch entry.
    ExFreePool(PatchEntry);
}

static void NtPe_DeleteFilePatchEntry(PPE_PATCH_ENTRY_FILE_NT PatchEntry) {
	PVOID FileObject = PatchEntry->FileObject;
	if (FileObject != NULL) PATCH_ENTRY_FILE(FileObject) = NULL;

    // Free the patched sections memory if it's allocated.
    if (PatchEntry->PatchedSections != NULL) {
        ExFreePool(PatchEntry->PatchedSections);
    }

    // If a section object is in the patch entry, dereference it, thus deleting it.
    if (PatchEntry->BaseSectionObject != NULL) {
        ObDereferenceObject(PatchEntry->BaseSectionObject);
    }
    if (PatchEntry->InjectedSectionObject != NULL) {
        ObDereferenceObject(PatchEntry->InjectedSectionObject);
    }

    // Free the patch entry.
    ExFreePool(PatchEntry);
}

static ULONG PageAlign(ULONG Val) {
    return Val & ~(PAGE_SIZE - 1);
}

static ULONG PageOffset(ULONG Val) {
    return Val & (PAGE_SIZE - 1);
}

static PMDL MdlTryAllocate(PVOID Base, ULONG Length) {
    PMDL Mdl = (PMDL)ExAllocatePool(PagedPool, MmSizeOfMdl(Base, Length));
    if (Mdl == NULL) {
        return NULL;
    }
    MmCreateMdl(Mdl, Base, Length);
    Mdl->MdlFlags |= MDL_ALLOCATED_MUST_SUCCEED; // so IoFreeMdl frees the MDL correctly
    if (Base != NULL) MmBuildMdlForNonPagedPool(Mdl); // if we passed a base, then it's nonpaged pool, so don't try to map it again
    return Mdl;
}

extern POBJECT_TYPE *MmSectionObjectType;

NTSTATUS
hook_ObCreateObject(
	IN KPROCESSOR_MODE AttributesMode,
	IN POBJECT_TYPE ObjectType,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN KPROCESSOR_MODE AccessMode,
	IN PVOID Reserved,
	IN ULONG ObjectSize,
	IN ULONG PagedPoolCharge,
	IN ULONG NonPagedPoolCharge
) {
	// Hook code can only deal with up to 8 args, and buys stack space. So args past the eighth need to be grabbed from the hook caller's frame.
	// Arg 9 is at offset 0x38, and so on.
	PVOID* Object = *(PVOID**)((ULONG)__builtin_frame_address(2) + 0x38);
	if (*IoFileObjectType != NULL && ObjectType == *IoFileObjectType) {
		if (ObjectSize != FILE_OFFSET_OF_ADDED) return STATUS_UNSUCCESSFUL;
		ObjectSize += 4;
		if (PagedPoolCharge == FILE_OFFSET_OF_ADDED) PagedPoolCharge += 4;
		if (NonPagedPoolCharge == FILE_OFFSET_OF_ADDED) NonPagedPoolCharge += 4;
		NTSTATUS Status = orig_ObCreateObject(AttributesMode, ObjectType, ObjectAttributes, AccessMode, Reserved, ObjectSize, PagedPoolCharge, NonPagedPoolCharge, Object);
		if (!NT_SUCCESS(Status)) return Status;
		ULONG FileObject = (ULONG)*Object;
		PATCH_ENTRY_FILE(FileObject) = NULL;
		return Status;
	}
	
	if (*MmSectionObjectType != NULL && ObjectType == *MmSectionObjectType) {
		if (ObjectSize != SECTION_OFFSET_OF_ADDED) return STATUS_UNSUCCESSFUL;
		ObjectSize += 4;
		PagedPoolCharge += 4;
		NTSTATUS Status = orig_ObCreateObject(AttributesMode, ObjectType, ObjectAttributes, AccessMode, Reserved, ObjectSize, PagedPoolCharge, NonPagedPoolCharge, Object);
		if (!NT_SUCCESS(Status)) return Status;
		ULONG SectionObject = (ULONG)*Object;
		PATCH_ENTRY_SECTION(SectionObject) = NULL;
		return Status;
	}
	
	return orig_ObCreateObject(AttributesMode, ObjectType, ObjectAttributes, AccessMode, Reserved, ObjectSize, PagedPoolCharge, NonPagedPoolCharge, Object);
}

NTSTATUS
hook_MmCreateSection(
	OUT PVOID *SectionObject,
	IN ULONG DesiredAccess,
	IN PVOID ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN PVOID FileHandle OPTIONAL,
	IN PVOID FileObject OPTIONAL
) {
	BOOLEAN NotImage = (AllocationAttributes & SEC_IMAGE) == 0;
	BOOLEAN InvalidArguments = FileHandle == NULL && FileObject == NULL;
	if (NotImage || InvalidArguments) {
		return orig_MmCreateSection(SectionObject, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle, FileObject);
	}

	ULONG Status = 0;

	// Caller requested an image mapping.
	PVOID File = FileObject;
	if (FileObject == NULL) {
		// Caller didn't pass FileObject.
		// Therefore, caller passed FileHandle.
		// Get a pointer to the file object.
		Status = ObReferenceObjectByHandle(FileHandle, 0x20, NULL, 0, &File, NULL);
		if (!NT_SUCCESS(Status)) return Status;
		// Dereference the file object, we know it'll hang around for the lifetime of the section.
		ObDereferenceObject(File);
	}

	// Check for an existing file list entry.
	BOOLEAN CreatedNewFile = FALSE;
	PPE_PATCH_ENTRY_FILE_NT FileEntry = PATCH_ENTRY_FILE(File);

	if (FileEntry == NULL) {
		// No file list entry exists, so create one.
		FileEntry = (PPE_PATCH_ENTRY_FILE_NT)ExAllocatePool(NonPagedPool, sizeof(*FileEntry));
		if (FileEntry == NULL) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		CreatedNewFile = TRUE;

		// Initialise the entry object, zero out everything and set the file object pointer.
		memset(FileEntry, 0, sizeof(*FileEntry));
		FileEntry->FileObject = File;

		PATCH_ENTRY_FILE(File) = FileEntry;
	}

	// Allocate memory for a patch list entry.
	PPE_PATCH_ENTRY_NT PatchEntry = (PPE_PATCH_ENTRY_NT)ExAllocatePool(NonPagedPool, sizeof(PE_PATCH_ENTRY_NT));
	if (PatchEntry == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	// Prepare it.
	memset(PatchEntry, 0, sizeof(*PatchEntry));
	PatchEntry->FileObject = File;
	PatchEntry->PatchFile = FileEntry;

	do {
		// The patch entry has been added to the list.
		// Call the original MmCreateSection.
		// IoReadFile hook will deal with the PE header.
		// FsRtlGetFileSize hook will deal with the remaining patches.

		PVOID Section = NULL;

		Status = orig_MmCreateSection(&Section, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle, FileObject);
		if (!NT_SUCCESS(Status)) {
			break;
		}

		// At this point, section object has been created, and the PE header has been modified.
		// Set up the section object in the patch entry.
		PatchEntry->SectionObject = Section;
		PATCH_ENTRY_SECTION(Section) = PatchEntry;
		// And write it to the caller's pointer.
		*SectionObject = Section;

		// Can't do anything more until something maps it.
		// Return success.
		return Status;
	} while (0);

	// Remove and free the patch entry.
	NtPe_DeletePatchEntry(PatchEntry);
	// If the file patch entry was created by us, it's useless, so get rid of it.
	if (CreatedNewFile) NtPe_DeleteFilePatchEntry(FileEntry);
	// Return status.
	return Status;
}

void hook_MiSectionDelete(PVOID Object) {
	//USE_NT_VOLATILE_REGISTERS();
	// Deleting a section object.
	
	// Get the patch entry object
	PPE_PATCH_ENTRY_NT PatchEntry = PATCH_ENTRY_SECTION(Object);
	
	if (PatchEntry != NULL) {
		// Remove and free the patch entry.
		NtPe_DeletePatchEntry(PatchEntry);
	}
	
	// Call the original function.
	orig_MiSectionDelete(Object);
}

void hook_IopDeleteFile(PVOID Object) {
	// Deleting a file object.
	
	// Get the patch entry object.
	PPE_PATCH_ENTRY_FILE_NT PatchEntry = PATCH_ENTRY_FILE(Object);
	
	if (PatchEntry != NULL) {
		// Remove and free the file patch entry.
		NtPe_DeleteFilePatchEntry(PatchEntry);
	}
	
	// Call the original function.
	orig_IopDeleteFile(Object);
}

NTSTATUS
hook_MmMapViewInSystemSpace(
	IN PVOID Section,
	OUT PVOID* MappedBase,
	IN OUT PULONG ViewSize
) { 
	// Get the patch entry.
	PPE_PATCH_ENTRY_NT PatchEntry = PATCH_ENTRY_SECTION(Section);

	if (PatchEntry == NULL) {
		// Could not find the entry in the list. Just call the original function.
		return orig_MmMapViewInSystemSpace(Section, MappedBase, ViewSize);
	}

	// Trying to map a PE. This means it must be a driver.
	// Mapping a driver like this causes it to be paged, we don't want that.
	// Returning an error here will cause a fallback to the other codepath.
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS
hook_IoPageRead(
	IN PVOID FileObject,
	IN PMDL MemoryDescriptorList,
	IN PLARGE_INTEGER StartingOffset,
	IN PKEVENT Event,
	OUT PIO_STATUS_BLOCK IoStatusBlock
) {
	// Reading some pages from the file.
	
	// Get the patch entry.
	PPE_PATCH_ENTRY_FILE_NT PatchEntry = PATCH_ENTRY_FILE(FileObject);

	// If a patch entry was not present, call the original function.
	// Do the same if there is to be no added section, that is, no patches whatsoever.
	if (PatchEntry == NULL || PatchEntry->BaseSectionObject == NULL) {
		return orig_IoPageRead(FileObject, MemoryDescriptorList, StartingOffset, Event, IoStatusBlock);
	}
	ULONG OffsetStart = StartingOffset->LowPart;
	ULONG Length = MemoryDescriptorList->ByteCount;
	ULONG OffsetEnd = OffsetStart + Length;
	ULONG MemOffset = 0;

	NTSTATUS Status = STATUS_SUCCESS;
	PVOID MappedBase = NULL;
	ULONG ViewSize = 0;
	
#ifdef PE_LDR_HOOK_DEBUG
	char Buffer[1024];
#endif
	
#ifdef PE_LDR_HOOK_DEBUG
	_snprintf(Buffer, sizeof(Buffer), "PE: (%08x) PageRead 0x%x bytes from offset 0x%08x\n", PatchEntry->RealImageBase, Length, OffsetStart);
	HalDisplayString(Buffer);
#endif

	if (OffsetEnd <= PatchEntry->SizeOfHeaders) {
		// Reading headers.
		
		// Get the kernel VA of the MDL
		PVOID Mapped = MmGetSystemAddressForMdl(MemoryDescriptorList);
		
		// Map in the section
		ViewSize = OffsetEnd;
		Status = orig_MmMapViewInSystemSpace(PatchEntry->BaseSectionObject, &MappedBase, &ViewSize);
		if (!NT_SUCCESS(Status)) {
			//s_IoPageReadFailingStatus = Status;
			return Status;
		}
		PUCHAR Section = (PUCHAR)MappedBase;

		// Copy to MDL
		memcpy(Mapped, &Section[OffsetStart], Length);
		sync_before_exec(Mapped, Length);
		
		// Fill in the IoStatusBlock
		IoStatusBlock->Status = STATUS_SUCCESS;
		IoStatusBlock->Information = Length;

		// Unmap the section
		MmUnmapViewInSystemSpace(Section);

		// Set the event we were passed in
		KeSetEvent(Event, 0, FALSE);

		// Success
		return STATUS_SUCCESS;
	}

	if (PatchEntry->InjectedSectionStart != 0 && OffsetStart >= PatchEntry->InjectedSectionStart) {
		// Reading the injected section.

		// Get the kernel VA of the MDL
		PVOID Mapped = MmGetSystemAddressForMdl(MemoryDescriptorList);

		ULONG InjectedLength = PatchEntry->InjectedSectionEnd - PatchEntry->InjectedSectionStart;
		ULONG CopyLength = Length;
		if (CopyLength > InjectedLength) CopyLength = InjectedLength;

		ULONG InjectedOffset = OffsetStart - PatchEntry->InjectedSectionStart;

		// Map in the section
		ViewSize = 0;
		Status = orig_MmMapViewInSystemSpace(PatchEntry->InjectedSectionObject, &MappedBase, &ViewSize);
		if (!NT_SUCCESS(Status)) {
			//s_IoPageReadFailingStatus = Status;
			return Status;
		}
		PUCHAR Section = (PUCHAR)MappedBase;

		// Copy to MDL
		memcpy(Mapped, &Section[InjectedOffset], CopyLength);
		sync_before_exec(Mapped, Length);
		// Fill in the IoStatusBlock
		IoStatusBlock->Status = STATUS_SUCCESS;
		IoStatusBlock->Information = CopyLength;

		// Unmap the section
		MmUnmapViewInSystemSpace(Section);

		// Set the event we were passed in
		KeSetEvent(Event, 0, FALSE);

		// Success
		return STATUS_SUCCESS;
	}

	if (OffsetStart < PatchEntry->SizeOfHeaders) {
		// Reading headers partially.

		// Get the kernel VA of the MDL
		PVOID Mapped = MmGetSystemAddressForMdl(MemoryDescriptorList);

		// Map in the section
		ViewSize = PatchEntry->SizeOfHeaders;
		Status = orig_MmMapViewInSystemSpace(PatchEntry->BaseSectionObject, &MappedBase, &ViewSize);
		if (!NT_SUCCESS(Status)) {
			//s_IoPageReadFailingStatus = Status;
			return Status;
		}
		PUCHAR Section = (PUCHAR)MappedBase;

		// Copy to MDL
		ULONG CopyLength = PatchEntry->SizeOfHeaders - OffsetStart;
		if (CopyLength > Length) CopyLength = Length;
		memcpy(Mapped, &Section[OffsetStart], CopyLength);
		sync_before_exec(Mapped, CopyLength);
		// Fill in the IoStatusBlock
		IoStatusBlock->Status = STATUS_SUCCESS;
		IoStatusBlock->Information = CopyLength;

		// Unmap the section
		MmUnmapViewInSystemSpace(Section);

		// Update the offsets
		MemOffset += CopyLength;
		Length -= CopyLength;
		OffsetStart = PatchEntry->SizeOfHeaders;
		OffsetEnd = (OffsetStart + Length);
	} else {
		IoStatusBlock->Information = 0;
	}

	// Offset is at least inside a section.
	// Loop through our array of modified sections (sorted by PointerToRawData aka original file offset)
	// For anything inside our sections, copy.
	// Otherwise, read from original file.

	// Ensure the MDL is mapped into kernel memory space so it can be copied to
	PUCHAR Mapped = (PUCHAR)MmGetSystemAddressForMdl(MemoryDescriptorList);
	// Allocate a single page for a read buffer, plus a kernel event.
	PKEVENT Kevent = ExAllocatePool(NonPagedPool, sizeof(KEVENT) + PAGE_SIZE);
	if (Kevent == NULL) {
		//s_IoPageReadFailingStatus = STATUS_UNSUCCESSFUL;
		return STATUS_UNSUCCESSFUL;
	}
	PVOID ReadBuffer = (PVOID)((ULONG)Kevent + sizeof(KEVENT));
	// Allocate MDL for read buffer.
	PMDL MdlReadBuffer = MdlTryAllocate(ReadBuffer, PAGE_SIZE);
	if (MdlReadBuffer == NULL) {
		ExFreePool(ReadBuffer);
		//s_IoPageReadFailingStatus = STATUS_UNSUCCESSFUL;
		return STATUS_UNSUCCESSFUL;
	}

	IO_STATUS_BLOCK Iosb;
	PUCHAR Section = NULL;
	for (ULONG i = 0; i < PatchEntry->PatchedSectionsCount && Length != 0; i++) {
		PPE_PATCH_SECTION_ENTRY PatchSection = &PatchEntry->PatchedSections[i];

		if (OffsetStart < PatchSection->PointerToRawData || PatchSection->OurOffset == 0) {
			// Reading from file up to the start of this section
			ULONG ReadLength32 = PatchSection->PointerToRawData - OffsetStart;
			if (ReadLength32 > Length) ReadLength32 = Length;
#ifdef PE_LDR_HOOK_DEBUG
			_snprintf(Buffer, sizeof(Buffer), "PE: (%08x) pre-sec 0x%x bytes from offset 0x%08x\n", PatchEntry->RealImageBase, ReadLength32, OffsetStart);
			HalDisplayString(Buffer);
#endif
			while (ReadLength32 != 0) {
				LARGE_INTEGER ReadOffset = INT32_TO_LARGE_INTEGER(OffsetStart);
				KeInitializeEvent(Kevent, NotificationEvent, FALSE);
				Status = orig_IoPageRead(FileObject, MdlReadBuffer, &ReadOffset, Kevent, &Iosb);
				if (Status == STATUS_PENDING) {
					KeWaitForSingleObject(Kevent, WrPageIn, KernelMode, FALSE, NULL);
					Status = STATUS_SUCCESS;
				}

				if (!NT_SUCCESS(Status) || !NT_SUCCESS(Iosb.Status)) {
					if (!NT_SUCCESS(Iosb.Status)) Status = Iosb.Status;
					break;
				}

				// Copy to output buffer from read buffer
				ULONG IosbLength = Iosb.Information;
				if (IosbLength > ReadLength32) IosbLength = ReadLength32;
				memcpy(&Mapped[MemOffset], ReadBuffer, IosbLength);
				sync_before_exec(&Mapped[MemOffset], IosbLength);
				ReadLength32 -= IosbLength;

				MemOffset += IosbLength;
				Length -= IosbLength;
				OffsetStart += IosbLength;
				OffsetEnd = (OffsetStart + Length);
				IoStatusBlock->Information += IosbLength;
			}

			if (!NT_SUCCESS(Status)) break;
		}

		// OffsetStart guaranteed to be >= this section
		// Is OffsetStart > this section end?
		// If so, move on to next section
		if (OffsetStart >= (PatchSection->PointerToRawData + PatchSection->SizeOfRawData)) continue;
		// Same if this section is purely coming from the original file
		if (PatchSection->OurOffset == 0) continue;

		// OffsetStart is within this section, so copy to this section
		if (Length == 0) break; // Nothing to copy.
		

		// Map in the section, offset + length
		if (Section == NULL) {
			ViewSize = 0; // Map the entire section :(
			Status = orig_MmMapViewInSystemSpace(PatchEntry->BaseSectionObject, &MappedBase, &ViewSize);
			if (!NT_SUCCESS(Status)) break;
			Section = (PUCHAR)MappedBase;
		}


		ULONG LengthToCopy = PatchSection->SizeOfRawData;
		if (LengthToCopy > Length) LengthToCopy = Length;
		ULONG SectionOffset = OffsetStart - PatchSection->PointerToRawData;

		ULONG LengthToZero = 0;
		if (ViewSize < (PatchSection->OurOffset + SectionOffset + LengthToCopy)) {
			// Not enough space, zero out the remainder:
			LengthToZero = (PatchSection->OurOffset + SectionOffset + LengthToCopy) - ViewSize;
			LengthToCopy = ViewSize;
		}
		
#ifdef PE_LDR_HOOK_DEBUG
		_snprintf(Buffer, sizeof(Buffer), "PE: (%08x) sec 0x%x bytes (and 0x%x bytes zeroed) from offset 0x%08x(0x%08x)\n",
			PatchEntry->RealImageBase,
			LengthToCopy,
			LengthToZero,
			OffsetStart,
			PatchSection->OurOffset + SectionOffset
		);
		HalDisplayString(Buffer);
#endif

		// Copy to MDL
		memcpy(&Mapped[MemOffset], &Section[PatchSection->OurOffset + SectionOffset], LengthToCopy);
		sync_before_exec(&Mapped[MemOffset], LengthToCopy);
		// Fill in the IoStatusBlock
		IoStatusBlock->Information += LengthToCopy;

		// Fix up the offsets
		MemOffset += LengthToCopy;
		Length -= LengthToCopy;
		OffsetStart += LengthToCopy;

		// Zero out the part requiring that
		if (LengthToZero != 0) {
			memset(&Mapped[MemOffset], 0, LengthToZero);
			sync_before_exec(&Mapped[MemOffset], LengthToZero);

			// Fix up the offsets
			MemOffset += LengthToZero;
			Length -= LengthToZero;
			OffsetStart += LengthToZero;
		}

		OffsetEnd = (OffsetStart + Length);

		// All done for this iteration
	}

	if (Section != NULL) {
		// Unmap the section
		MmUnmapViewInSystemSpace(Section);
	}

	if (Length > 0 && NT_SUCCESS(Status)) {
		// Still looking to read data.
		// Do the same thing as the previous, but for the injected section instead
		do {
			if (PatchEntry->InjectedSectionStart == 0 || OffsetStart < PatchEntry->InjectedSectionStart) {
				// Reading from file up to the start of the injected section
				// or, if there is no injected section, just from the file.

				ULONG ReadLength32 = PatchEntry->InjectedSectionStart - OffsetStart;
				if (PatchEntry->InjectedSectionStart == 0 || ReadLength32 > Length) ReadLength32 = Length;
				
#ifdef PE_LDR_HOOK_DEBUG
				_snprintf(Buffer, sizeof(Buffer), "PE: (%08x) pre-injected 0x%x bytes from offset 0x%08x\n", PatchEntry->RealImageBase, ReadLength32, OffsetStart);
				HalDisplayString(Buffer);
#endif
				
				while (ReadLength32 != 0) {
					LARGE_INTEGER ReadOffset = INT32_TO_LARGE_INTEGER(OffsetStart);
					KeInitializeEvent(Kevent, NotificationEvent, FALSE);
					Status = orig_IoPageRead(FileObject, MdlReadBuffer, &ReadOffset, Kevent, &Iosb);
					if (Status == STATUS_PENDING) {
						KeWaitForSingleObject(Kevent, WrPageIn, KernelMode, FALSE, NULL);
						Status = STATUS_SUCCESS;
					}

					if (!NT_SUCCESS(Status) || !NT_SUCCESS(Iosb.Status)) {
						if (!NT_SUCCESS(Iosb.Status)) Status = Iosb.Status;
						break;
					}

					// Copy to output buffer from read buffer
					ULONG IosbLength = Iosb.Information;
					if (IosbLength > ReadLength32) IosbLength = ReadLength32;
					memcpy(&Mapped[MemOffset], ReadBuffer, IosbLength);
					sync_before_exec(&Mapped[MemOffset], IosbLength);
					ReadLength32 -= IosbLength;

					MemOffset += IosbLength;
					Length -= IosbLength;
					OffsetStart += IosbLength;
					OffsetEnd = (OffsetStart + Length);
					IoStatusBlock->Information += IosbLength;
				}

				if (!NT_SUCCESS(Status)) break;
			}

			// If OffsetStart is >= injected section end, nothing to copy.
			if (PatchEntry->InjectedSectionStart == 0) break;
			if (OffsetStart >= PatchEntry->InjectedSectionEnd) break;
			if (Length == 0) break;

			// Map in the section, offset + length
			ULONG LengthToCopy = PatchEntry->InjectedSectionEnd - PatchEntry->InjectedSectionStart;
			if (LengthToCopy > Length) LengthToCopy = Length;
			ULONG SectionOffset = OffsetStart - PatchEntry->InjectedSectionStart;
			
#ifdef PE_LDR_HOOK_DEBUG
			_snprintf(Buffer, sizeof(Buffer), "PE: (%08x) injected 0x%x bytes from offset 0x%08x(0x%08x)\n", PatchEntry->RealImageBase, LengthToCopy, OffsetStart, SectionOffset);
			HalDisplayString(Buffer);
#endif
			
			ViewSize = 0;
			Status = orig_MmMapViewInSystemSpace(PatchEntry->InjectedSectionObject, &MappedBase, &ViewSize);
			if (!NT_SUCCESS(Status)) break;
			PUCHAR Section = (PUCHAR)MappedBase;

			// Copy to MDL
			memcpy(&Mapped[MemOffset], &Section[SectionOffset], LengthToCopy);
			sync_before_exec(&Mapped[MemOffset], LengthToCopy);
			// Fill in the IoStatusBlock
			IoStatusBlock->Information += LengthToCopy;

			// Unmap the section
			MmUnmapViewInSystemSpace(Section);

			// Fix up the offsets
			MemOffset += LengthToCopy;
			Length -= LengthToCopy;
			OffsetStart += LengthToCopy;
			OffsetEnd = (OffsetStart + Length);
		} while (FALSE);
	}


	// Free MDL
	IoFreeMdl(MdlReadBuffer);
	// Free read buffer
	ExFreePool(Kevent);

	// Set the event we were passed in on success
	if (NT_SUCCESS(Status)) KeSetEvent(Event, 0, FALSE);

	if (!NT_SUCCESS(Status)) {
		// store this status code off somewhere. if we are trying to read a kernel mode page this is a bugcheck anyway!
		//s_IoPageReadFailingStatus = Status;
	}

	return Status;
}

static BOOLEAN SectionContainsRva(PIMAGE_SECTION_HEADER Section, ULONG Rva) {
	if (Section == NULL) return FALSE;
	if (Rva < Section->VirtualAddress) return FALSE;
	if (Rva >= Section->VirtualAddress + Section->Misc.VirtualSize) return FALSE;
	return TRUE;
}

static PIMAGE_SECTION_HEADER SectionContainingRva(PIMAGE_SECTION_HEADER Sections, ULONG NumberOfSections, ULONG Rva) {
	for (int i = 0; i < NumberOfSections; i++) {
		if (Rva < Sections[i].VirtualAddress) continue;
		if (Rva >= Sections[i].VirtualAddress + Sections[i].SizeOfRawData) continue;
		return &Sections[i];
	}
	return NULL;
}

NTSTATUS hook_FsRtlGetFileSize(PVOID FileObject, PLARGE_INTEGER FileSize) {
	// Getting the file size. Need to increase the file size for MiCreateImageFileMap.
	// Also save off various file offsets to be used later.

	// Get the patch entry.
	PPE_PATCH_ENTRY_FILE_NT PatchEntry = PATCH_ENTRY_FILE(FileObject);
	if (PatchEntry != NULL) {
		// File object exists.
		// If there's already a created section object, then we've already performed the operation.
		if (PatchEntry->BaseSectionObject != NULL) {
			PatchEntry = NULL;
		}
	}

	// Call the original function.
	ULONG Status = orig_FsRtlGetFileSize(FileObject, FileSize);

	// If a patch entry was not present or this function already ran once, return.
	if (PatchEntry == NULL) return Status;

	// If original function failed, return.
	if (!NT_SUCCESS(Status)) return Status;
	
	// If original file size would not be permitted, return.
	if (FileSize->HighPart != 0) return Status;

	// We need to read the header ourselves.
	
	// Allocate 8KB + kevent.
	PKEVENT Kevent = ExAllocatePool(NonPagedPool, sizeof(KEVENT) + (PAGE_SIZE * 2));
	if (Kevent == NULL) return 0xC0324000UL;
	PVOID Base = (PVOID)((ULONG)Kevent + sizeof(KEVENT));
	// Read 8KB.
	PMDL Mdl = MdlTryAllocate(Base, PAGE_SIZE * 2);
	if (Mdl == NULL) {
		ExFreePool(Kevent);
		return 0xC0324001UL;
	}

	ULONG SizeOfImage = 0;
	ULONG SectionAlignment = 0;
	ULONG FileAlignment = 0;
	ULONG RealFileLength = 0;
	BOOLEAN SacrificeDosStub = FALSE;

	do {

		LARGE_INTEGER Offset;
		Offset.QuadPart = 0;
		// Read.
		IO_STATUS_BLOCK Iosb;
		KeInitializeEvent(Kevent, NotificationEvent, FALSE);
		Status = orig_IoPageRead(FileObject, Mdl, &Offset, Kevent, &Iosb);
		if (Status == STATUS_PENDING) {
			KeWaitForSingleObject(Kevent, WrPageIn, KernelMode, FALSE, NULL);
			Status = STATUS_SUCCESS;
		}

		if (!NT_SUCCESS(Status) || !NT_SUCCESS(Iosb.Status)) {
			Status = 0xC0324002UL;
			break;
		}

		PIMAGE_DOS_HEADER Mz = (PIMAGE_DOS_HEADER)Base;

		if (Mz->e_magic != IMAGE_DOS_SIGNATURE) {
			Status = STATUS_SUCCESS; // caller will detect this
			break;
		}

		ULONG PeOffset = Mz->e_lfanew;
		if ((PeOffset & (sizeof(ULONG) - 1)) != 0) {
			// PE header must be 32-bit aligned on non-x86 architectures
			Status = STATUS_SUCCESS; // caller will detect this
			break;
		}
		ULONG OptionalHeaderOffset = __builtin_offsetof(IMAGE_NT_HEADERS, OptionalHeader);
		ULONG SectionsOffset = PeOffset + sizeof(IMAGE_NT_HEADERS);

		ULONG SectionsLength = 0;
		PIMAGE_NT_HEADERS Pe = (PIMAGE_NT_HEADERS) ((ULONG)Base + PeOffset);
		PIMAGE_SECTION_HEADER Sections = (PIMAGE_SECTION_HEADER)(ULONG)NULL;
		ULONG NumberOfSections = 0;
		ULONG SizeOfHeaders = 0;
		BOOLEAN ReadMore = (PeOffset + OptionalHeaderOffset) > Iosb.Information;
		if (!ReadMore) {
			if (Pe->Signature != IMAGE_NT_SIGNATURE || Pe->FileHeader.Machine != IMAGE_FILE_MACHINE_POWERPC) {
				Status = STATUS_SUCCESS; // caller will check itself
				break;
			}
			SectionsOffset = PeOffset + OptionalHeaderOffset + Pe->FileHeader.SizeOfOptionalHeader;
			SectionsLength = Pe->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
			NumberOfSections = Pe->FileHeader.NumberOfSections;
			Sections = (PIMAGE_SECTION_HEADER)((ULONG)Base + SectionsOffset);
			ReadMore = (SectionsOffset + SectionsLength) > Iosb.Information;
			if (!ReadMore) {
				SizeOfHeaders = Pe->OptionalHeader.SizeOfHeaders;
				SizeOfImage = Pe->OptionalHeader.SizeOfImage;
				PIMAGE_DATA_DIRECTORY RelocDir = &Pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
				SectionAlignment = Pe->OptionalHeader.SectionAlignment;
				FileAlignment = Pe->OptionalHeader.FileAlignment;
				PatchEntry->RealImageBase = Pe->OptionalHeader.ImageBase;

				// If the PE has bound imports, the DOS stub must be sacrificed.
				PIMAGE_DATA_DIRECTORY BoundImports = &Pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
				if (BoundImports->VirtualAddress != 0 && BoundImports->Size != 0) {
					SacrificeDosStub = TRUE;
				}
			}
		}
		if (ReadMore) {
			// The entire PE headers is not part of the 8KB read.
			// Read 8KB starting from PE header.
			Offset.QuadPart = PageAlign(PeOffset);
			KeInitializeEvent(Kevent, NotificationEvent, FALSE);
			Status = orig_IoPageRead(FileObject, Mdl, &Offset, Kevent, &Iosb);

			if (Status == STATUS_PENDING) {
				KeWaitForSingleObject(Kevent, WrPageIn, KernelMode, FALSE, NULL);
				Status = STATUS_SUCCESS;
			}

			if (!NT_SUCCESS(Status) || !NT_SUCCESS(Iosb.Status)) {
				Status = 0xC0324003UL;
				break;
			}
			Pe = (PIMAGE_NT_HEADERS)((ULONG)Base + PageOffset(PeOffset));

			if (Pe->Signature != IMAGE_NT_SIGNATURE || Pe->FileHeader.Machine != IMAGE_FILE_MACHINE_POWERPC) {
				Status = STATUS_SUCCESS; // caller will check itself
				break;
			}

			if (OptionalHeaderOffset > Iosb.Information) {
				// what?
				Status = 0xC0324004UL;
				break;
			}

			SectionsOffset = OptionalHeaderOffset + Pe->FileHeader.SizeOfOptionalHeader;
			SectionsLength = Pe->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
			Sections = (PIMAGE_SECTION_HEADER)((ULONG)Base + SectionsOffset);
			SectionsOffset += PeOffset;


			if (SectionsLength > (8 * 1024)) {
				// Section headers are too large to fit in 8KB?
				// In this case, the NT loader should fail on this PE anyway!
				Status = 0xC0324005UL;
				break;
			}

			NumberOfSections = Pe->FileHeader.NumberOfSections;
			SizeOfHeaders = Pe->OptionalHeader.SizeOfHeaders;
			SizeOfImage = Pe->OptionalHeader.SizeOfImage;
			PIMAGE_DATA_DIRECTORY RelocDir = &Pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			SectionAlignment = Pe->OptionalHeader.SectionAlignment;
			FileAlignment = Pe->OptionalHeader.FileAlignment;
			PatchEntry->RealImageBase = Pe->OptionalHeader.ImageBase;
			
			// If the PE has bound imports, the DOS stub must be sacrificed.
			PIMAGE_DATA_DIRECTORY BoundImports = &Pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
			if (BoundImports->VirtualAddress != 0 && BoundImports->Size != 0) {
				SacrificeDosStub = TRUE;
			}

			if ((SectionsOffset + SectionsLength) > Iosb.Information) {
				// We need the section headers, and for some reason 8KB didn't hit them.
				Offset.QuadPart = PageAlign(SectionsOffset);

				KeInitializeEvent(Kevent, NotificationEvent, FALSE);
				Status = orig_IoPageRead(FileObject, Mdl, &Offset, Kevent, &Iosb);

				if (Status == STATUS_PENDING) {
					KeWaitForSingleObject(Kevent, WrPageIn, KernelMode, FALSE, NULL);
					Status = STATUS_SUCCESS;
				}

				if (!NT_SUCCESS(Status) || !NT_SUCCESS(Iosb.Status)) {
					Status = 0xC0324006UL;
					break;
				}

				if (SectionsLength > Iosb.Information) {
					// Couldn't load the section headers...
					Status = 0xC0324006UL;
					break;
				}

				Sections = (PIMAGE_SECTION_HEADER)((ULONG)Base + PageOffset(SectionsOffset));
			}
		}

		ULONG FileSize32 = FileSize->LowPart;

		// Check all sections. If any section is outside of the file then just return, the caller will also detect this and error.
		BOOLEAN SectionsInsideFile = TRUE;
		for (int i = 0; i < NumberOfSections; i++) {
			ULONG SectionEnd = Sections[i].PointerToRawData + Sections[i].SizeOfRawData;
			if (SectionEnd > FileSize32) {
				SectionsInsideFile = FALSE;
				break;
			}
		}
		if (!SectionsInsideFile) {
			break;
		}

		ULONG SectionsEnd = SectionsOffset + SectionsLength;

		// Calculate the code table length.
		ULONG TableLength = 0;
		for (ULONG Section = 0; Section < NumberOfSections; Section++) {
			if ((Sections[Section].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
			TableLength += Sections[Section].SizeOfRawData;
		}

		// We now need to map the actual PE into a section object.
		// Create the section object, backed by pagefile, and map it into system space.
		PVOID BaseSectionObject = NULL;
		ULONG SectionSize32 = SectionAlignment < PAGE_SIZE ? FileSize32 : SizeOfImage;
		LARGE_INTEGER SectionSize = INT32_TO_LARGE_INTEGER(SectionSize32);
		Status = orig_MmCreateSection(
			&BaseSectionObject,
			0,
			NULL,
			&SectionSize,
			PAGE_READWRITE,
			SEC_COMMIT,
			NULL,
			NULL
		);
		if (!NT_SUCCESS(Status)) {
			break;
		}

		// Map the section into system space.
		PVOID MappedSection;
		ULONG MappedSize = 0;

		Status = orig_MmMapViewInSystemSpace(BaseSectionObject, &MappedSection, &MappedSize);
		if (!NT_SUCCESS(Status)) {
			ObDereferenceObject(BaseSectionObject);
			break;
		}

		PUCHAR pBaseSection = (PUCHAR)MappedSection;

		// Read entire PE into section.
		// Do it two pages at a time into our scratch buffer, then copy to section.
		// Allocate the seperate MDL for the final read first.
		PMDL MdlFinal = MdlTryAllocate(Base, PAGE_SIZE * 2);
		if (MdlFinal == NULL) {
			// Unmap view of section.
			MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
			ObDereferenceObject(BaseSectionObject);
			Status = 0xC0324007UL;
			break;
		}
		

		// For section alignment at least PAGE_SIZE, read headers only here.
		// Ensure offset looks good.
		if (SizeOfHeaders < SectionsEnd) SizeOfHeaders = SectionsEnd;
		ULONG LengthToRead32 = SectionAlignment < PAGE_SIZE ? FileSize32 : SizeOfHeaders;
		for (Offset.QuadPart = 0; Offset.LowPart < LengthToRead32; Offset.LowPart += (PAGE_SIZE * 2)) {
			ULONG Remaining = FileSize32 - Offset.LowPart;
			ULONG ReadSize = PAGE_SIZE * 2;
			PMDL MdlToUse = Mdl;
			if (Remaining < (PAGE_SIZE * 2)) {
				MdlFinal->ByteCount = Remaining;
				MdlToUse = MdlFinal;
				ReadSize = Remaining;
			}

			KeInitializeEvent(Kevent, NotificationEvent, FALSE);
			Status = orig_IoPageRead(FileObject, MdlToUse, &Offset, Kevent, &Iosb);
			if (Status == STATUS_PENDING) {
				KeWaitForSingleObject(Kevent, WrPageIn, KernelMode, FALSE, NULL);
				Status = STATUS_SUCCESS;
			}

			if (!NT_SUCCESS(Status) || !NT_SUCCESS(Iosb.Status)) {
				Status = 0xC0324008UL;
				break;
			}

			memcpy(&pBaseSection[Offset.LowPart], Base, ReadSize);
		}

		if (!NT_SUCCESS(Status)) {
			IoFreeMdl(MdlFinal);
			// Unmap view of section.
			MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
			ObDereferenceObject(BaseSectionObject);
			break;
		}

		// For section alignment at least PAGE_SIZE, read the rest of the file.
		// Fix up the header pointers.
		Mz = (PIMAGE_DOS_HEADER)pBaseSection;
		PeOffset = Mz->e_lfanew;
		if ((PeOffset + OptionalHeaderOffset) > LengthToRead32) {
			// someone's trying a toctou? lol
			// Unmap view of section.
			MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
			ObDereferenceObject(BaseSectionObject);
			Status = 0xC0324009ULL;
			break;
		}
		Pe = (PIMAGE_NT_HEADERS)((ULONG)pBaseSection + Mz->e_lfanew);
		SectionsOffset = PeOffset + OptionalHeaderOffset + Pe->FileHeader.SizeOfOptionalHeader;
		SectionsLength = Pe->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
		NumberOfSections = Pe->FileHeader.NumberOfSections;
		if ((SectionsOffset + SectionsLength) > LengthToRead32) {
			// someone's trying a toctou? lol
			// Unmap view of section.
			MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
			ObDereferenceObject(BaseSectionObject);
			Status = 0xC032400AULL;
			break;
		}
		Sections = (PIMAGE_SECTION_HEADER)((ULONG)pBaseSection + SectionsOffset);

		if (SectionAlignment >= PAGE_SIZE) {
			// Need to read the rest of the file.
			// For each section:
			for (ULONG Section = 0; Section < NumberOfSections; Section++) {
				ULONG VirtualSize = Sections[Section].Misc.VirtualSize;
				ULONG SizeOfRawData = Sections[Section].SizeOfRawData;
				if (VirtualSize == 0) VirtualSize = SizeOfRawData;

				if (Sections[Section].PointerToRawData == 0) SizeOfRawData = 0;
				else if (SizeOfRawData > VirtualSize) SizeOfRawData = VirtualSize;

				// Read SizeOfRawData bytes from file at offset PointerToRawData to offset VirtualAddress
				ULONG PointerToRawData = Sections[Section].PointerToRawData;
				ULONG VirtualAddress = Sections[Section].VirtualAddress;
				for (ULONG Offset32 = 0; Offset32 < SizeOfRawData; Offset32 += PAGE_SIZE) {
					ULONG Remaining = SizeOfRawData - Offset32;
					ULONG ReadSize = PAGE_SIZE;
					PMDL MdlToUse = Mdl;
					if (Remaining < (PAGE_SIZE)) {
						MdlFinal->ByteCount = Remaining;
						MdlToUse = MdlFinal;
						ReadSize = Remaining;
					}

					Offset.HighPart = 0;
					Offset.LowPart = Offset32 + PointerToRawData;

					KeInitializeEvent(Kevent, NotificationEvent, FALSE);
					Status = orig_IoPageRead(FileObject, MdlToUse, &Offset, Kevent, &Iosb);
					if (Status == STATUS_PENDING) {
						KeWaitForSingleObject(Kevent, WrPageIn, KernelMode, FALSE, NULL);
						Status = STATUS_SUCCESS;
					}

					if (!NT_SUCCESS(Status) || !NT_SUCCESS(Iosb.Status)) {
						Status = 0xC032400BUL;
						break;
					}

					memcpy(&pBaseSection[VirtualAddress + Offset32], Base, ReadSize);
				}

				if (SizeOfRawData < VirtualSize) {
					memset(&pBaseSection[Sections[Section].VirtualAddress + SizeOfRawData], 0, VirtualSize - SizeOfRawData);
				}
			}
		}

		IoFreeMdl(MdlFinal);

		if (!NT_SUCCESS(Status)) {
			// Unmap view of section.
			MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
			ObDereferenceObject(BaseSectionObject);
			break;
		}
		

		// Entire PE is in memory, so we don't need to wait for any more I/O there.
		ULONG TextCaveRva = 0;
		ULONG TextCaveLength = 0;
		BOOLEAN Success = FindLengthOfCodeTable((ULONG)pBaseSection, Sections, NumberOfSections, &TableLength, &TextCaveRva, &TextCaveLength);
		if (!Success) {
			Status = 0xC0324007UL;
			// Unmap view of section.
			MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
			ObDereferenceObject(BaseSectionObject);
			break;
		}
		
		Status = STATUS_SUCCESS;
		
		if (TableLength == 0) {
			// No additional space required.
			// Free the memory we allocated, no patches are needed.
			// Unmap view of section.
			MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
			// Dereference the section offset.
			ObDereferenceObject(BaseSectionObject);
			break;
		}
		
		// If patched in data can fit at end of .text, handle this without injecting an additional section
		PVOID pInjectedSection = NULL;
		if (TableLength <= TextCaveLength) {
			SacrificeDosStub = FALSE;
			
			PatchEntry->PatchEntry.PointerInjectedSection = (PUCHAR)pBaseSection + TextCaveRva;
			PatchEntry->PatchEntry.SizeOfInjectedSection  = TextCaveLength;
			
			// Ensure the VirtualSize is not less than SizeOfRawData for the text section, otherwise the text cave will be cut off.
			PIMAGE_SECTION_HEADER TextSection = SectionContainingRva(Sections, NumberOfSections, TextCaveRva & ~PAGE_SIZE);
			if (TextSection == NULL) {
				// what?
				Status = 0xC032400CUL;
				// Unmap view of sections.
				MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
				ObDereferenceObject(BaseSectionObject);
				break;
			}
			if (TextSection->Misc.VirtualSize < TextSection->SizeOfRawData) TextSection->Misc.VirtualSize = TextSection->SizeOfRawData;
		} else {
			TextCaveRva = 0;
			// Align to page size
			TableLength = (TableLength + PAGE_SIZE - 1) & ~PAGE_SIZE;
			PatchEntry->PatchEntry.SizeOfInjectedSection = TableLength;


			ULONG NewSize = SectionsEnd + sizeof(IMAGE_SECTION_HEADER);
			// Ensure the DOS stub is sacrificed if required or if it's bigger than the default one
			if (NewSize > SizeOfHeaders || PeOffset > 0x80) {
				SacrificeDosStub = TRUE;
			}

			// Add the table length to the file size.
			// If section alignment is at least a page, add another page to ensure length checks pass with the additional section being added after .reloc.
			RealFileLength = FileSize->LowPart;
			FileSize->QuadPart = ARC_ALIGNUP(RealFileLength, FileAlignment) + ARC_ALIGNUP(TableLength, FileAlignment);
			if (SectionAlignment >= PAGE_SIZE) FileSize->QuadPart += PAGE_SIZE;

			// Now perform the PE patch.
			// First patch the headers.
			ULONG NewSectionSize = PatchEntry->PatchEntry.SizeOfInjectedSection;
			NewSectionSize = ARC_ALIGNUP(NewSectionSize, SectionAlignment);

			// Sacrifice the DOS stub to gain more space if needed. This should gain ~0x40 bytes which is more than enough for another section.
			if (SacrificeDosStub) {
				ULONG SpaceSaved = Mz->e_lfanew - sizeof(IMAGE_DOS_HEADER);
				ULONG LengthToCopy = Pe->OptionalHeader.SizeOfHeaders - SpaceSaved;
				Pe->OptionalHeader.SizeOfHeaders -= SpaceSaved;
				Pe->OptionalHeader.SizeOfHeaders = ARC_ALIGNUP(Pe->OptionalHeader.SizeOfHeaders, Pe->OptionalHeader.FileAlignment);
				Mz->e_lfanew = sizeof(IMAGE_DOS_HEADER);
				memcpy((PVOID)((ULONG)pBaseSection + sizeof(IMAGE_DOS_HEADER)), Pe, LengthToCopy);
				Pe = (PIMAGE_NT_HEADERS)((ULONG)pBaseSection + sizeof(IMAGE_DOS_HEADER));
				Sections = (PIMAGE_SECTION_HEADER)((ULONG)&Pe->OptionalHeader + Pe->FileHeader.SizeOfOptionalHeader);
			}

			Pe->FileHeader.NumberOfSections++;
			Pe->OptionalHeader.SizeOfCode += NewSectionSize;
			Pe->OptionalHeader.SizeOfImage += NewSectionSize;
			//Pe->FileHeader.Characteristics &= ~(IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP | IMAGE_FILE_NET_RUN_FROM_SWAP);

			// Fix up the bound import descriptor directory if needed.
			PIMAGE_DATA_DIRECTORY BoundImports = &Pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
			BoundImports->VirtualAddress = BoundImports->Size = 0;

			// Add the new section
			ULONG SectionIndexToAdd = NumberOfSections;
			ULONG LastSection = NumberOfSections - 1;

			memset(&Sections[SectionIndexToAdd], 0, sizeof(IMAGE_SECTION_HEADER));
			memcpy((char*)Sections[SectionIndexToAdd].Name, "haustorc", sizeof(Sections[SectionIndexToAdd].Name));
			Sections[SectionIndexToAdd].SizeOfRawData = NewSectionSize;
			Sections[SectionIndexToAdd].Misc.VirtualSize = NewSectionSize;
			ULONG PreviousSectionSize = Sections[SectionIndexToAdd - 1].Misc.VirtualSize;
			if (PreviousSectionSize == 0) PreviousSectionSize = Sections[SectionIndexToAdd - 1].SizeOfRawData;
			ULONG NewRva = Sections[SectionIndexToAdd - 1].VirtualAddress + ARC_ALIGNUP(PreviousSectionSize, SectionAlignment);
			if (SectionAlignment < PAGE_SIZE) {
				// In this case VirtualAddress must equal PointerToRawData.
				NewRva = RealFileLength;
			}
			Sections[SectionIndexToAdd].VirtualAddress = NewRva;
			// Read from file starting from the "original end" rounded up to file alignment.
			Sections[SectionIndexToAdd].PointerToRawData = RealFileLength;
			if (SectionAlignment >= PAGE_SIZE) {
				Sections[SectionIndexToAdd].PointerToRawData = ARC_ALIGNUP(RealFileLength, FileAlignment);
			}
			//Sections[SectionIndexToAdd].PointerToRawData = Sections[LastSection].PointerToRawData + Sections[LastSection].SizeOfRawData;
			PatchEntry->InjectedSectionStart = Sections[SectionIndexToAdd].PointerToRawData;
			PatchEntry->InjectedSectionEnd = PatchEntry->InjectedSectionStart + NewSectionSize;
			Sections[SectionIndexToAdd].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
			NumberOfSections++;

			//PatchEntry->PatchEntry.InjectedSectionIsFinal = (SectionIndexToAdd == (NumberOfSections - 1));
			PatchEntry->PatchEntry.IndexOfInjectedSection = SectionIndexToAdd;

			// Create the section to store injected section contents.
			PVOID InjectedSectionObject = NULL;
			SectionSize.HighPart = 0;
			SectionSize.LowPart = NewSectionSize;
			Status = orig_MmCreateSection(
				&InjectedSectionObject,
				0,
				NULL,
				&SectionSize,
				PAGE_READWRITE,
				SEC_COMMIT,
				NULL,
				NULL
			);
			if (!NT_SUCCESS(Status)) {
				// Unmap view of section.
				MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
				ObDereferenceObject(BaseSectionObject);
				break;
			}
			PatchEntry->InjectedSectionObject = InjectedSectionObject;

			// Map the section into system space.
			MappedSize = 0;

			Status = orig_MmMapViewInSystemSpace(PatchEntry->InjectedSectionObject, &MappedSection, &MappedSize);
			if (!NT_SUCCESS(Status)) {
				// Unmap view of section.
				MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
				ObDereferenceObject(BaseSectionObject);
				break;
			}

			pInjectedSection = MappedSection;
			PatchEntry->PatchEntry.PointerInjectedSection = pInjectedSection;
		}

		// Initialise bitmap for patched pages.
		// Allocate buffer SizeOfImage / PAGE_SIZE bits.
		// Maximum possible size 512Kbit = 64KB.
		ULONG BitCount = Pe->OptionalHeader.SizeOfImage / PAGE_SIZE;
		if ((Pe->OptionalHeader.SizeOfImage & (PAGE_SIZE - 1)) != 0) {
			BitCount++;
		}
		ULONG PageCount = BitCount;
		// Align to 32 bits.
		BitCount = ARC_ALIGNUP(BitCount, 32);
		// This can go into the paged pool as it's only used here where paging is allowed.
		PULONG BitmapBuffer = ExAllocatePool(PagedPool, BitCount / 8);
		if (BitmapBuffer == NULL) {
			Status = 0xC032400EUL;
			// Unmap view of sections.
			if (pInjectedSection != NULL) MmUnmapViewInSystemSpace(pInjectedSection);
			MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
			ObDereferenceObject(BaseSectionObject);
			break;
		}
		
		// Initialise the buffer to zero.
		memset(BitmapBuffer, 0, BitCount / 8);
		// Initialise the bitmap structure.
		RTL_BITMAP PatchedPages;
		RtlInitializeBitMap(&PatchedPages, BitmapBuffer, BitCount);
		
		if (TextCaveRva != 0) {
			for (ULONG TextCavePage = TextCaveRva / PAGE_SIZE; TextCavePage <= (TextCaveRva + TextCaveLength) / PAGE_SIZE; TextCavePage++) {
				RtlSetBits(&PatchedPages, TextCavePage, 1);
			}
		}
		
		// Patch the PE.
		PatchEntry->PatchEntry.BaseAddress = (ULONG)pBaseSection;
		PatchEntry->PatchEntry.RealImageBase = PatchEntry->RealImageBase;
		ULONG PatchError = PePatch_Relocate(&PatchEntry->PatchEntry, &PatchedPages);

		// Done with the injected section for now, unmap it.
		if (pInjectedSection != NULL) MmUnmapViewInSystemSpace(pInjectedSection);

		if (PatchError != 0) {
			Status = 0xC0330000UL | PatchError;
			ExFreePool(BitmapBuffer);
			// Unmap view of sections.
			MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
			ObDereferenceObject(BaseSectionObject);
			break;
		}
		
		// If section alignment is less than a page, can't do anything but to keep the entire PE.
		if (SectionAlignment < PAGE_SIZE) {
			ExFreePool(BitmapBuffer);
			PatchEntry->BaseSectionObject = BaseSectionObject;
			PatchEntry->SizeOfHeaders = FileSize32;
			PatchEntry->PatchedSectionsCount = 0;
			MmUnmapViewInSystemSpace(pBaseSection);
			break;
		}
		
		// We only want to keep the patched header, plus any section pages that were patched.
		// The injected PE section, if any, is stored in its own section object.
		ULONG NumberOfPatchedPages = RtlNumberOfSetBits(&PatchedPages);

		ULONG FinalSectionLength = Pe->OptionalHeader.SizeOfHeaders + (NumberOfPatchedPages * PAGE_SIZE);

		// Allocate memory for patched sections.
		PatchEntry->PatchedSections = ExAllocatePool(NonPagedPool, NumberOfPatchedPages * sizeof(PatchEntry->PatchedSections[0]));
		if (PatchEntry->PatchedSections == NULL) {
			// Free bitmap buffer.
			ExFreePool(BitmapBuffer);
			// Unmap view of section.
			MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
			ObDereferenceObject(BaseSectionObject);
			// Cleanup code later will free the section object.
			Status = 0xC0324010UL;
			break;
		}

		PatchEntry->PatchedSectionsCount = NumberOfPatchedPages;

		// Calculated the final section length, so create the section for that:
		PVOID FinalSectionObject = NULL;
		SectionSize.HighPart = 0;
		SectionSize.LowPart = FinalSectionLength;
		Status = orig_MmCreateSection(
			&FinalSectionObject,
			0,
			NULL,
			&SectionSize,
			PAGE_READWRITE,
			SEC_COMMIT,
			NULL,
			NULL
		);
		if (!NT_SUCCESS(Status)) {
			// Unmap view of section.
			MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
			ObDereferenceObject(BaseSectionObject);
			break;
		}

		// Map the section into system space.
		MappedSize = 0;

		Status = orig_MmMapViewInSystemSpace(FinalSectionObject, &MappedSection, &MappedSize);
		if (!NT_SUCCESS(Status)) {
			// Free bitmap buffer.
			ExFreePool(BitmapBuffer);
			// Unmap view of section.
			MmUnmapViewInSystemSpace(pBaseSection); // (returns an NTSTATUS sure, but guaranteed to succeed)
			ObDereferenceObject(BaseSectionObject);
			ObDereferenceObject(FinalSectionObject);
			break;
		}

		PUCHAR pFinalSection = (PUCHAR)MappedSection;

		// Copy headers
		PatchEntry->SizeOfHeaders = Pe->OptionalHeader.SizeOfHeaders;
		memcpy(pFinalSection, pBaseSection, Pe->OptionalHeader.SizeOfHeaders);

		// Copy patched pages
		ULONG FinalOffset = PatchEntry->SizeOfHeaders;
		ULONG PatchedSectionIndex = 0;
		PIMAGE_SECTION_HEADER CurrentSection = NULL;
		for (ULONG Page = 0; Page < PageCount; Page++) {
			if (!RtlCheckBit(&PatchedPages, Page)) continue;
			if (PatchEntry->InjectedSectionStart != 0 && (Page * PAGE_SIZE) >= PatchEntry->InjectedSectionStart) continue;
			
			// Find the section containing this page.
			ULONG PageOffset = Page * PAGE_SIZE;
			if (!SectionContainsRva(CurrentSection, PageOffset)) CurrentSection = SectionContainingRva(Sections, NumberOfSections, PageOffset);
			if (CurrentSection == NULL) continue; // ???
			
			ULONG SectionPageOffset = PageOffset - CurrentSection->VirtualAddress;
			ULONG VirtualSize = PAGE_SIZE;
			ULONG SectionVirtualSize = CurrentSection->Misc.VirtualSize - SectionPageOffset;
			if (SectionVirtualSize < PAGE_SIZE) VirtualSize = SectionVirtualSize;
			ULONG SizeOfRawData = CurrentSection->SizeOfRawData - SectionPageOffset;

			if (CurrentSection->PointerToRawData == 0) SizeOfRawData = 0;
			else if (SizeOfRawData > VirtualSize) SizeOfRawData = VirtualSize;
			
			if (SizeOfRawData == 0) continue;

			PatchEntry->PatchedSections[PatchedSectionIndex].PointerToRawData = CurrentSection->PointerToRawData + SectionPageOffset;
			PatchEntry->PatchedSections[PatchedSectionIndex].OurOffset = FinalOffset;
			PatchEntry->PatchedSections[PatchedSectionIndex].SizeOfRawData = SizeOfRawData;
			
			PatchedSectionIndex++;
			memcpy(&pFinalSection[FinalOffset], &pBaseSection[PageOffset], SizeOfRawData);
			FinalOffset += SizeOfRawData;
		}

		// Free the bitmap buffer.
		ExFreePool(BitmapBuffer);
		// All done with the final section and the base section.
		MmUnmapViewInSystemSpace(pFinalSection);
		MmUnmapViewInSystemSpace(pBaseSection);

		// Free the base section object, we're completely done with it
		ObDereferenceObject(BaseSectionObject);
		// And insert the final section object
		PatchEntry->BaseSectionObject = FinalSectionObject;

		// Sort the sections by PointerToRawData. A well behaved linker should have done this already but that's not a guarantee.
		for (ULONG First = 1; First < NumberOfPatchedPages; First++) {
			PE_PATCH_SECTION_ENTRY Temp = PatchEntry->PatchedSections[First];
			ULONG Second = First - 1;

			while (Second >= 0 && PatchEntry->PatchedSections[Second].PointerToRawData > Temp.PointerToRawData) {
				PatchEntry->PatchedSections[Second + 1] = PatchEntry->PatchedSections[Second];
				Second--;
			}

			PatchEntry->PatchedSections[Second + 1] = Temp;
		}
	} while (0);


	IoFreeMdl(Mdl);
	ExFreePool(Kevent);
	return Status;
}

static PVOID hook_MmPageEntireDriver(PVOID AddrInSection) {
    // In kernel mode, injected section cannot be paged out.
    // Therefore, disable paging out the entire driver as if it were disabled in the registry.
	
	// We need to return the image base.
	PVOID ImageBase = NULL;
	if (RtlPcToFileHeader != NULL) {
		PVOID ImageBase = NULL;
		RtlPcToFileHeader(AddrInSection, &ImageBase);
	}
	
	if (ImageBase == NULL) {
		// Fall back to the slow option.
		PVOID ImageBase = orig_MmPageEntireDriver(AddrInSection);
		MmResetDriverPaging(AddrInSection);
	}
	
	return ImageBase;
}

static ULONG hook_RtlVirtualUnwind(
	ULONG ControlPc,
	PRUNTIME_FUNCTION_ENTRY FunctionEntry,
	PCONTEXT ContextRecord,
	PBOOLEAN InFunction,
	PULONG EstablisherFrame,
	PVOID ContextPointers,
	ULONG LowStackLimit,
	ULONG HighStackLimit
) {
	// Called at kernel exception time.
	
	// The function we are trying to look at may be compiled with correctly formed prologue+epilogue, or not.
	// If it is not, RtlVirtualUnwind may hang or return ControlPc.
	
	ULONG Caller = orig_RtlVirtualUnwind(ControlPc, FunctionEntry, ContextRecord, InFunction, EstablisherFrame, ContextPointers, LowStackLimit, HighStackLimit);
	
	// The function we are trying to look at may be compiled with correctly formed prologue+epilogue, or not.
	// If it is not, RtlVirtualUnwind may hang or return ControlPc or zero.
	if (Caller == 0 || Caller == ControlPc) {
		Caller = EstablisherFrame[2]; // gcc saves lr to sp+8
	}
	
	return Caller;
}

// Hook engine.
// Based on https://gist.github.com/TheRouletteBoi/e1e9925699ee8d708881e167e397058b
// Assumptions:
// - r0 is always safe to use in function prologue (it's only ever used as a scratch register)

enum {
	BRANCH_OPTION_ALWAYS = 20, // 0b10100
	SPR_CTR = 288, // 0b01001_00000
};

static ULONG PPCHook_EmitAbsoluteBranchImpl(PPPC_INSTRUCTION Destination, const PPPC_INSTRUCTION Target, BOOLEAN Call, ULONG BranchOptions, ULONG ConditionRegister) {
	LONG JumpOffset = ((ULONG)Target - (ULONG)Destination);
	if (BranchOptions == BRANCH_OPTION_ALWAYS && is_offset_in_branch_range(JumpOffset)) {
		if (Destination != NULL) {
			PPC_INSTRUCTION Branch;
			Branch.Long = 0;
			Branch.Primary_Op = B_OP;
			Branch.Iform_LK = Call;
			Branch.Iform_LI = JumpOffset >> 2;
			Destination[0] = Branch;
		}
		return 1;
	}
	PPC_INSTRUCTION Instructions[4] = { 0 };
	// addis r0, 0, Target@hi ; load address (upper half)
	Instructions[0].Primary_Op = ADDIS_OP;
	Instructions[0].Dform_RT = 0;
	Instructions[0].Dform_RA = 0;
	Instructions[0].Dform_D = (USHORT)((ULONG)Target >> 16);
	// ori r0, r0, Target@lo ; load address (lower half)
	Instructions[1].Primary_Op = ORI_OP;
	Instructions[1].Dform_RT = 0;
	Instructions[1].Dform_RA = 0;
	Instructions[1].Dform_D = ((USHORT)(ULONG)Target);
	// mtctr r0 ; move to ctr
	Instructions[2].Primary_Op = X31_OP;
	Instructions[2].XFXform_XO = MTSPR_OP;
	Instructions[2].XFXform_RS = 0;
	Instructions[2].XFXform_spr = SPR_CTR;
	// bcctr(l) ; branch through ctr
	Instructions[3].Primary_Op = X19_OP;
	Instructions[3].XLform_XO = BCCTR_OP;
	Instructions[3].XLform_BO = BranchOptions;
	Instructions[3].XLform_BI = ConditionRegister;
	Instructions[3].XLform_LK = Call;

	if (Destination != NULL) {
		for (size_t i = 0; i < sizeof(Instructions) / sizeof(Instructions[0]); i++) Destination[i] = Instructions[i];
	}
	return sizeof(Instructions) / sizeof(Instructions[0]);
}

static ULONG PPCHook_EmitAbsoluteBranch(PPPC_INSTRUCTION Destination, const PPPC_INSTRUCTION Target) {
	return PPCHook_EmitAbsoluteBranchImpl(Destination, Target, FALSE, BRANCH_OPTION_ALWAYS, 0);
}

static ULONG PPCHook_EmitAbsoluteBranchCall(PPPC_INSTRUCTION Destination, const PPPC_INSTRUCTION Target) {
	return PPCHook_EmitAbsoluteBranchImpl(Destination, Target, TRUE, BRANCH_OPTION_ALWAYS, 0);
}

static ULONG PPCHook_EmitTocPrologue(PPPC_INSTRUCTION Destination, ULONG TocRegister) {
	PPC_INSTRUCTION Instructions[6] = { 0 };
	// mflr r0 ; get lr
	Instructions[0].Long = 0x7C0802A6;
	// stw r0, 8(r1) ; save lr
	Instructions[1].Primary_Op = STW_OP;
	Instructions[1].Dform_RS = 0;
	Instructions[1].Dform_RA = 1;
	Instructions[1].Dform_D = 8;
	// stw r2, 0xC(r1) ; save toc - must NOT touch 4(r1) as caller might have saved their toc there
	Instructions[2].Primary_Op = STW_OP;
	Instructions[2].Dform_RS = 2;
	Instructions[2].Dform_RA = 1;
	Instructions[2].Dform_D = 0xC;
	// stwu r1, -0x38(r1) ; buy stack frame
	Instructions[3].Primary_Op = STWU_OP;
	Instructions[3].Dform_RT = 1;
	Instructions[3].Dform_RA = 1;
	Instructions[3].Dform_D = -0x38;
	// addis r2, 0, TocRegister@hi ; load toc (upper half)
	Instructions[4].Primary_Op = ADDIS_OP;
	Instructions[4].Dform_RT = 2;
	Instructions[4].Dform_RA = 0;
	Instructions[4].Dform_D = (USHORT)((ULONG)TocRegister >> 16);
	// ori r2, r2, TocRegister@lo ; load toc (lower half)
	Instructions[5].Primary_Op = ORI_OP;
	Instructions[5].Dform_RT = 2;
	Instructions[5].Dform_RA = 2;
	Instructions[5].Dform_D = ((USHORT)(ULONG)TocRegister);

	if (Destination != NULL) {
		for (size_t i = 0; i < sizeof(Instructions) / sizeof(Instructions[0]); i++) Destination[i] = Instructions[i];
	}
	return sizeof(Instructions) / sizeof(Instructions[0]);
}

static ULONG PPCHook_GetAbsoluteBranchSize(ULONG Destination, ULONG Target) {
	if (Target != 0) {
		LONG JumpOffset = Target - Destination;
		if (is_offset_in_branch_range(JumpOffset)) return 1; // can be done in 1 instruction!
	}
	return PPCHook_EmitAbsoluteBranch(NULL, NULL);
}

static inline LONG HookSignExtBranch(LONG x) {
	return x & 0x2000000 ? (LONG)(x | 0xFC000000) : (LONG)(x);
}

static inline LONG HookSignExt16(SHORT x) {
	return (LONG)x;
}

static ULONG PPCHook_RelocateBranch(PPPC_INSTRUCTION Destination, PPPC_INSTRUCTION Source) {
	if (Source->Iform_AA) {
		// Branch is absolute, so no special handling needs doing
		if (Destination != NULL) *Destination = *Source;
		return 1;
	}

	LONG BranchOffset;
	ULONG BranchOptions, ConditionRegister;
	switch (Source->Primary_Op) {
	case B_OP:
		BranchOffset = HookSignExtBranch(Source->Iform_LI << 2);
		BranchOptions = BRANCH_OPTION_ALWAYS;
		ConditionRegister = 0;
		break;
	case BC_OP:
		BranchOffset = HookSignExt16(Source->Bform_BD << 2);
		BranchOptions = Source->Bform_BO;
		ConditionRegister = Source->Bform_BI;
		break;
	}

	PPPC_INSTRUCTION BranchAddress = (PPPC_INSTRUCTION)((ULONG)Source + BranchOffset);
	return PPCHook_EmitAbsoluteBranchImpl(Destination, BranchAddress, Source->Iform_LK, BranchOptions, ConditionRegister);
}

static size_t PPCHook_RelocateInstruction(PPPC_INSTRUCTION Destination, PPPC_INSTRUCTION Source) {
	switch (Source->Primary_Op) {
	case B_OP:
	case BC_OP:
		return PPCHook_RelocateBranch(Destination, Source);
	default:
		if (Destination != NULL) *Destination = *Source;
		return 1;
	}
}

/// <summary>
/// Hooks a powerpc function, using the specified code-cave to store the trampoline.
/// </summary>
/// <param name="FunctionPointer">Pointer to function pointer to hook, will get overwritten by orig_function trampoline address.</param>
/// <param name="HookLocation">Pointer to hooked implementation.</param>
/// <param name="TrampolineCave">Code cave to use as trampoline.</param>
/// <param name="TrampolineReturn">Pointer to TOC restore epilogue instructions.</param>
/// <returns>Number of instructions written to TrampolineCave.</returns>
static ULONG PPCHook_HookWithCave(PVOID* FunctionPointer, PVOID HookLocation, PPPC_INSTRUCTION TrampolineCave, PPPC_INSTRUCTION TrampolineReturn) {
	// In this ABI, the function pointers are really pointers to AIXCALL_FPTR
	PVOID HookToc = (PVOID)((PAIXCALL_FPTR)HookLocation)->Toc;
	//PVOID OrigToc = (PVOID)((PAIXCALL_FPTR)*FunctionPointer)->Toc;
	HookLocation = (PVOID)((PAIXCALL_FPTR)HookLocation)->Function;
	// Get the length of the hook (in instructions)
	PPPC_INSTRUCTION Function = (PPPC_INSTRUCTION)((PAIXCALL_FPTR)*FunctionPointer)->Function;
	ULONG InsnCount = PPCHook_GetAbsoluteBranchSize((ULONG)Function, (ULONG)TrampolineCave);

	ULONG HookSize = 0;
	ULONG RelocationStart = 0;
	// Write out the toc setter prologue.
	HookSize = PPCHook_EmitTocPrologue(TrampolineCave, (ULONG)HookToc);
	// Write out a call from trampoline to the hook location.
	HookSize += PPCHook_EmitAbsoluteBranchCall(&TrampolineCave[HookSize], (PPPC_INSTRUCTION)HookLocation);
	// Write out a branch from trampoline to the trampoline return
	HookSize += PPCHook_EmitAbsoluteBranch(&TrampolineCave[HookSize], TrampolineReturn);
	RelocationStart = HookSize;

	// Relocate the instructions to the provided cave.
	for (size_t i = 0; i < InsnCount; i++) {
		HookSize += PPCHook_RelocateInstruction(&TrampolineCave[HookSize], &Function[i]);
	}

	// Write out the branch to original function.
	// Don't preserve r0, as it's expected to be clobbered across function calls anyway
	PPPC_INSTRUCTION OriginalBranch = &Function[InsnCount];
	HookSize += PPCHook_EmitAbsoluteBranch(&TrampolineCave[HookSize], OriginalBranch);

	// All instructions have been written.
	((PAIXCALL_FPTR)*FunctionPointer)->Function = (ULONG)&TrampolineCave[RelocationStart];
	// Write out the branch to the trampoline.
	PPCHook_EmitAbsoluteBranch(Function, TrampolineCave);
	sync_before_exec(Function, 0x20);

	return HookSize;
}

// Hooking stuff below.

PVOID PeGetExportWithDirectory(PVOID ImageBase, PIMAGE_EXPORT_DIRECTORY Export, const char* ExportName);

static PVOID PeGetProcAddress(PVOID ImageBase, PIMAGE_EXPORT_DIRECTORY Export, const char* ExportName) {
	PAIXCALL_FPTR Fptr = (PAIXCALL_FPTR)PeGetExportWithDirectory(ImageBase, Export, ExportName);
	if (Fptr == NULL) return NULL;
	return (PVOID)Fptr->Function;
}

static PVOID FindSymbolEnd(ULONG ImageBase, PRUNTIME_FUNCTION_ENTRY ExceptionDir, ULONG ExceptionSize, PVOID SymbolStart) {
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
	//ULONG OldImageBase = NtHeaders->OptionalHeader.ImageBase;
	ULONG ExceptionCount = ExceptionSize / sizeof(RUNTIME_FUNCTION_ENTRY);
	for (ULONG i = 0; i < ExceptionCount; i++) {
		ULONG BeginAddress = ExceptionDir[i].BeginAddress;
		if (BeginAddress == (ULONG)SymbolStart) return (PVOID)(ExceptionDir[i].EndAddress);
		if (BeginAddress < (ULONG)SymbolStart) return (PVOID)BeginAddress;
	}
	return NULL;
}

static PVOID FindSymbolSpecifiedEnd(ULONG ImageBase, PRUNTIME_FUNCTION_ENTRY ExceptionDir, ULONG ExceptionSize, PVOID SymbolAddr) {
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
	//ULONG OldImageBase = NtHeaders->OptionalHeader.ImageBase;
	ULONG ExceptionCount = ExceptionSize / sizeof(RUNTIME_FUNCTION_ENTRY);
	for (ULONG i = 0; i < ExceptionCount; i++) {
		ULONG BeginAddress = ExceptionDir[i].BeginAddress;
		ULONG EndAddress = ExceptionDir[i].EndAddress;
		if ((ULONG)SymbolAddr >= BeginAddress && (ULONG)SymbolAddr < EndAddress) return (PVOID)EndAddress;
	}
	return NULL;
}

static PVOID FindSymbolNextStart(ULONG ImageBase, PRUNTIME_FUNCTION_ENTRY ExceptionDir, ULONG ExceptionSize, PVOID SymbolAddr) {
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
	//ULONG OldImageBase = NtHeaders->OptionalHeader.ImageBase;
	ULONG ExceptionCount = ExceptionSize / sizeof(RUNTIME_FUNCTION_ENTRY);
	for (ULONG i = 0; i < ExceptionCount; i++) {
		ULONG BeginAddress = ExceptionDir[i].BeginAddress;
		ULONG EndAddress = ExceptionDir[i].EndAddress;
		if ((ULONG)SymbolAddr >= BeginAddress && (ULONG)SymbolAddr < EndAddress) return (PVOID)(ExceptionDir[i + 1].BeginAddress);
	}
	return NULL;
}

static PVOID FindSymbolStart(ULONG ImageBase, PRUNTIME_FUNCTION_ENTRY ExceptionDir, ULONG ExceptionSize, PVOID SymbolAddr) {
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
	//ULONG OldImageBase = NtHeaders->OptionalHeader.ImageBase;
	ULONG ExceptionCount = ExceptionSize / sizeof(RUNTIME_FUNCTION_ENTRY);
	for (ULONG i = 0; i < ExceptionCount; i++) {
		ULONG BeginAddress = ExceptionDir[i].BeginAddress;
		ULONG EndAddress = ExceptionDir[i].EndAddress;
		if ((ULONG)SymbolAddr >= BeginAddress && (ULONG)SymbolAddr < EndAddress) return (PVOID)BeginAddress;
	}
	return NULL;
}

static PVOID FindSymbolPrevious(ULONG ImageBase, PRUNTIME_FUNCTION_ENTRY ExceptionDir, ULONG ExceptionSize, PVOID SymbolAddr, PVOID* EndAddress) {
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
	//ULONG OldImageBase = NtHeaders->OptionalHeader.ImageBase;
	ULONG ExceptionCount = ExceptionSize / sizeof(RUNTIME_FUNCTION_ENTRY);
	for (ULONG i = 1; i < ExceptionCount; i++) {
		ULONG BeginAddress = ExceptionDir[i].BeginAddress;
		ULONG exEndAddress = ExceptionDir[i].EndAddress;
		if ((ULONG)SymbolAddr >= BeginAddress && (ULONG)SymbolAddr < exEndAddress) {
			if (EndAddress != NULL) *EndAddress = (PVOID)(ExceptionDir[i - 1].EndAddress);
			return (PVOID)(ExceptionDir[i - 1].BeginAddress);
		}
	}
	return NULL;
}

BOOLEAN HalpHookKernelPeLoader(PVOID ImageBase) {
	// get the PE headers.
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE; // no DOS header
	
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + DosHeader->e_lfanew);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE; // no PE header
	PIMAGE_FILE_HEADER FileHeader = &NtHeaders->FileHeader;

	USHORT NumberOfSections = FileHeader->NumberOfSections;
	PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&FileHeader[1];
	PIMAGE_SECTION_HEADER Sections = (PIMAGE_SECTION_HEADER)((size_t)OptionalHeader + FileHeader->SizeOfOptionalHeader);
	
	// get the index of the section injected by the boot time loader hooks
	ULONG IndexOfInjectedSection = NumberOfSections;
	for (int i = NumberOfSections - 1; i >= 0; i--) {
		if (Sections[i].Name[0] == '.') continue;
		IndexOfInjectedSection = i;
		break;
	}
	
	if (IndexOfInjectedSection == NumberOfSections) return FALSE;
	
	ULONG SectionLength = Sections[IndexOfInjectedSection].Misc.VirtualSize;
	ULONG SectionVa = Sections[IndexOfInjectedSection].VirtualAddress;
	
	// Get unused part of injected section
	PULONG InjectedSection = (PULONG)((ULONG)ImageBase + SectionVa);
	while (SectionLength > 0 && *InjectedSection != 0) {
		InjectedSection++;
		SectionLength -= sizeof(*InjectedSection);
	}
	
	if (SectionLength == 0) return FALSE;
	
	// Write the TOC restore epilogue instructions.
	if (SectionLength <= 0x14) return FALSE;
	SectionLength -= 0x14;
	PVOID TocRestoreEpilogue = InjectedSection;
	InjectedSection[0] = 0x38210038; // addi r1, r1, 0x38 ; let go of stack frame
	InjectedSection[1] = 0x80010008; // lwz r0, 8(r1) ; get lr
	InjectedSection[2] = 0x7C0803a6; // mtlr r0 ; restore lr
	InjectedSection[3] = 0x8041000C; // lwz r2, 0xC(r1) ; restore toc
	InjectedSection[4] = 0x4E800020; // blr ; return
	InjectedSection += 5;
	
	// Get export directory
	PIMAGE_EXPORT_DIRECTORY Export = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	
	// Get exception directory
	PIMAGE_DATA_DIRECTORY ExceptionDir = &OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	PRUNTIME_FUNCTION_ENTRY Exceptions = (PRUNTIME_FUNCTION_ENTRY)(ImageBase + ExceptionDir->VirtualAddress);
	
	// Get the kernel TOC
	PVOID KernelToc = (PVOID) ((PAIXCALL_FPTR)((ULONG)ImageBase + OptionalHeader->AddressOfEntryPoint))->Toc;
	
	// MiSectionDelete is not exported, but is guaranteed to be before MmForceSectionClosed:
	PVOID MmForceSectionClosed = PeGetProcAddress(ImageBase, Export, "MmForceSectionClosed");
	if (MmForceSectionClosed == NULL) return FALSE;
	
	fporig_MiSectionDelete.Function = 0;
	fporig_MiSectionDelete.Toc = (ULONG)KernelToc;
	PVOID FuncStart = MmForceSectionClosed, FuncEnd = NULL;
	
	

#define PPC_HOOK_DO(FunctionPointer, HookLocation) do { \
	if (SectionLength == 0) return FALSE; \
	else { \
		ULONG Length = PPCHook_HookWithCave((FunctionPointer), (HookLocation), (PPPC_INSTRUCTION)InjectedSection, TocRestoreEpilogue); \
		SectionLength -= Length * sizeof(*InjectedSection); \
		InjectedSection += Length; \
	} \
} while (0)
	
	while (TRUE) {
		// Get the previous function.
		FuncStart = FindSymbolPrevious((ULONG)ImageBase, Exceptions, ExceptionDir->Size, FuncStart, &FuncEnd);
		if (FuncStart == NULL) break;

        BOOLEAN InsnFound = FALSE;
        for (PPPC_INSTRUCTION Insn = (PPPC_INSTRUCTION)FuncStart; Insn < (PPPC_INSTRUCTION)FuncEnd; Insn++) {
            PPC_INSTRUCTION Insn2;
            Insn2.Long = Insn->Long;
            if (Insn2.Primary_Op != RLWINM_OP) continue;
            if (Insn2.Mform_RC != 0) continue;
            if (Insn2.Mform_SH != 16) continue;
            if (Insn2.Mform_MB != 31) continue;
            if (Insn2.Mform_ME != 31) continue;

            InsnFound = TRUE;
            break;
        }

        if (!InsnFound) continue;

        fporig_MiSectionDelete.Function = (ULONG)FuncStart;
        PPC_HOOK_DO((PVOID*)&orig_MiSectionDelete, hook_MiSectionDelete);
        break;
    }
	
	if (fporig_MiSectionDelete.Function == 0) return FALSE;
	
	// IopDeleteFile is not exported, but is guaranteed to be after IoVerifyVolume and before kernel entrypoint
    PVOID IoVerifyVolume = PeGetProcAddress(ImageBase, Export, "IoVerifyVolume");
    PVOID KiSystemStartup = (PVOID)((PAIXCALL_FPTR)((ULONG)ImageBase + OptionalHeader->AddressOfEntryPoint))->Function;
    if (IoVerifyVolume == NULL) return FALSE;

    fporig_IopDeleteFile.Function = 0;
	fporig_IopDeleteFile.Toc = (ULONG)KernelToc;
    FuncStart = IoVerifyVolume;
    FuncEnd = FindSymbolNextStart((ULONG)ImageBase, Exceptions, ExceptionDir->Size, FuncStart);

    while (TRUE) {
        // Get the next function
        FuncStart = FuncEnd;
        FuncEnd = FindSymbolNextStart((ULONG)ImageBase, Exceptions, ExceptionDir->Size, FuncStart);
        if (FuncEnd == NULL) break;
        if (FuncEnd >= KiSystemStartup) break;

        BOOLEAN InsnFound = FALSE;
        for (PPPC_INSTRUCTION_BIG Insn = (PPPC_INSTRUCTION_BIG)FuncStart; Insn < (PPPC_INSTRUCTION_BIG)FuncEnd; Insn++) {
            PPC_INSTRUCTION_BIG Insn2;
            Insn2.Long = Insn->Long;
            // rlwinm. rx, rx, 0, 13, 13
            if (Insn2.Primary_Op != RLWINM_OP) continue;
            if (Insn2.Mform_RC == 0) continue;
            if (Insn2.Mform_SH != 0) continue;
            if (Insn2.Mform_MB != 13) continue;
            if (Insn2.Mform_ME != 13) continue;

            InsnFound = TRUE;
            break;
        }

        if (!InsnFound) continue;

        fporig_MiSectionDelete.Function = (ULONG)FuncStart;
        PPC_HOOK_DO((PVOID*)&orig_IopDeleteFile, hook_IopDeleteFile);
        break;
    }

    if (fporig_MiSectionDelete.Function == 0) return FALSE;

#if 0
	// MiLoadImageSection is not exported, but is guaranteed to be after MmFreeNonCachedMemory
	PVOID MmFreeNonCachedMemory = PeGetProcAddress(ImageBase, Export, "MmFreeNonCachedMemory");
	if (MmFreeNonCachedMemory == NULL) return FALSE;

	fporig_MiLoadImageSection.Function = 0;
	fporig_MiLoadImageSection.Toc = (ULONG)KernelToc;
	FuncStart = MmFreeNonCachedMemory;
	FuncEnd = FindSymbolNextStart((ULONG)ImageBase, Exceptions, ExceptionDir->Size, FuncStart);

	while (TRUE) {
		// Get the next function
		FuncStart = FuncEnd;
		FuncEnd = FindSymbolNextStart((ULONG)ImageBase, Exceptions, ExceptionDir->Size, FuncStart);
		if (FuncEnd == NULL) break;

		BOOLEAN InsnFound = FALSE;
		PUCHAR FuncNext = FuncStart;
		while (TRUE) {
			// search for constant 0x4000000E
			static BYTE s_Pattern1[] = { 0x40, 0x00 };
			if ((ULONG)FuncNext >= (ULONG)FuncEnd) break;

			PUCHAR Pattern1 = (PUCHAR)mem_mem(FuncNext, s_Pattern1, (ULONG)FuncNext - (ULONG)FuncStart, sizeof(s_Pattern1));
			if (Pattern1 == NULL) break;
			FuncNext = &Pattern1[1];

			if (Pattern1[4] != 0x00) continue;
			if (Pattern1[5] != 0x0E) continue;
			// if following instruction is unconditional branch, this is MiMapViewOfImageSection
			PPPC_INSTRUCTION_BIG Insn = (PPPC_INSTRUCTION_BIG)(ULONG)&Pattern1[6];
			if (Insn->Primary_Op == B_OP) continue;

			// found
			InsnFound = TRUE;
			break;
		}
		if (!InsnFound) continue;

		fporig_MiLoadImageSection.Function = (ULONG)FuncStart;
		PPC_HOOK_DO((PVOID*)&orig_MiLoadImageSection, hook_MiLoadImageSection);
		break;
	}

	if (fporig_MiLoadImageSection.Function == 0) return FALSE;
#endif
	
	
	// Dynamically import the needed functions, and hook those that need hooking.
#define GET_PROC_ADDRESS_ORIG_AND_HOOK(Name) do { \
	fporig_##Name .Function = (ULONG) PeGetProcAddress(ImageBase, Export, #Name ); \
	if (fporig_##Name .Function == 0) { \
		return FALSE; \
	} \
	fporig_##Name .Toc = (ULONG)KernelToc; \
    PPC_HOOK_DO((PVOID*)&orig_##Name , hook_##Name); \
} while (0)

	GET_PROC_ADDRESS_ORIG_AND_HOOK(ObCreateObject);
	//GET_PROC_ADDRESS_ORIG_AND_HOOK(ObReferenceObjectByPointer);
	GET_PROC_ADDRESS_ORIG_AND_HOOK(MmCreateSection);
	//GET_PROC_ADDRESS_ORIG_AND_HOOK(MmMapViewOfSection);
	GET_PROC_ADDRESS_ORIG_AND_HOOK(MmMapViewInSystemSpace);
	GET_PROC_ADDRESS_ORIG_AND_HOOK(IoPageRead);
	GET_PROC_ADDRESS_ORIG_AND_HOOK(FsRtlGetFileSize);
	//GET_PROC_ADDRESS_ORIG_AND_HOOK(IofCallDriver);
	GET_PROC_ADDRESS_ORIG_AND_HOOK(MmPageEntireDriver);
	GET_PROC_ADDRESS_ORIG_AND_HOOK(RtlVirtualUnwind);
	
#if 0
	// for debug: set PAGE_FAULT_IN_NONPAGED_AREA arg2 to faulting address
	ULONG insn = 0x80a1022c; // lwz r5, 0x22c(r1)
	// these addresses are for NT4 SP1 ntkrnlmp
	*(PULONG)(0x8069b4a8 - 0x80648000 + ImageBase) = insn;
	*(PULONG)(0x8069b4d8 - 0x80648000 + ImageBase) = insn;
	*(PULONG)(0x8069b5a4 - 0x80648000 + ImageBase) = insn;
#endif
	
	// Get RtlPcToFileHeader. This is the first bl instruction in RtlLookupFunctionEntry (exported)
	
	extern __declspec(dllimport) PVOID RtlLookupFunctionEntry (ULONG ControlPc);
	PAIXCALL_FPTR AfLookupFunctionEntry = *(PAIXCALL_FPTR*)RtlLookupFunctionEntry;
	PPPC_INSTRUCTION Insn = (PPPC_INSTRUCTION)AfLookupFunctionEntry->Function;
	ULONG Count = 0;
	for (; Count < 10; Insn++, Count++) {
		if (Insn->Primary_Op != B_OP) continue;
		if (!Insn->Iform_LK) continue;
		break;
	}
	if (Count >= 10) {
		RtlPcToFileHeader = NULL;
	} else {
		fp_RtlPcToFileHeader.Function = (ULONG)Insn + HookSignExtBranch(Insn->Iform_LI << 2);
		fp_RtlPcToFileHeader.Toc = (ULONG)KernelToc;
	}
	
	sync_before_exec((PULONG)((ULONG)ImageBase + SectionVa), SectionLength);
	
	return TRUE;
}
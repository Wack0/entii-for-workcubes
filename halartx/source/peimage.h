#pragma once


typedef UCHAR BYTE;
typedef PUCHAR PBYTE;

// Bring in NT types we need:
// LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    ULONG   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// PE header structures:
#include "pshpack4.h"                   // 4 byte packing is the default

#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#define IMAGE_OS2_SIGNATURE                 0x454E      // NE
#define IMAGE_OS2_SIGNATURE_LE              0x454C      // LE
#define IMAGE_VXD_SIGNATURE                 0x454C      // LE
#define IMAGE_NT_SIGNATURE                  0x00004550  // PE00

#include "pshpack2.h"                   // 16 bit headers are 2 byte packed

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    USHORT e_magic;                     // Magic number
    USHORT e_cblp;                      // Bytes on last page of file
    USHORT e_cp;                        // Pages in file
    USHORT e_crlc;                      // Relocations
    USHORT e_cparhdr;                   // Size of header in paragraphs
    USHORT e_minalloc;                  // Minimum extra paragraphs needed
    USHORT e_maxalloc;                  // Maximum extra paragraphs needed
    USHORT e_ss;                        // Initial (relative) SS value
    USHORT e_sp;                        // Initial SP value
    USHORT e_csum;                      // Checksum
    USHORT e_ip;                        // Initial IP value
    USHORT e_cs;                        // Initial (relative) CS value
    USHORT e_lfarlc;                    // File address of relocation table
    USHORT e_ovno;                      // Overlay number
    USHORT e_res[4];                    // Reserved words
    USHORT e_oemid;                     // OEM identifier (for e_oeminfo)
    USHORT e_oeminfo;                   // OEM information; e_oemid specific
    USHORT e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_OS2_HEADER {      // OS/2 .EXE header
    USHORT ne_magic;                    // Magic number
    CHAR   ne_ver;                      // Version number
    CHAR   ne_rev;                      // Revision number
    USHORT ne_enttab;                   // Offset of Entry Table
    USHORT ne_cbenttab;                 // Number of bytes in Entry Table
    LONG   ne_crc;                      // Checksum of whole file
    USHORT ne_flags;                    // Flag word
    USHORT ne_autodata;                 // Automatic data segment number
    USHORT ne_heap;                     // Initial heap allocation
    USHORT ne_stack;                    // Initial stack allocation
    LONG   ne_csip;                     // Initial CS:IP setting
    LONG   ne_sssp;                     // Initial SS:SP setting
    USHORT ne_cseg;                     // Count of file segments
    USHORT ne_cmod;                     // Entries in Module Reference Table
    USHORT ne_cbnrestab;                // Size of non-resident name table
    USHORT ne_segtab;                   // Offset of Segment Table
    USHORT ne_rsrctab;                  // Offset of Resource Table
    USHORT ne_restab;                   // Offset of resident name table
    USHORT ne_modtab;                   // Offset of Module Reference Table
    USHORT ne_imptab;                   // Offset of Imported Names Table
    LONG   ne_nrestab;                  // Offset of Non-resident Names Table
    USHORT ne_cmovent;                  // Count of movable entries
    USHORT ne_align;                    // Segment alignment shift count
    USHORT ne_cres;                     // Count of resource segments
    UCHAR  ne_exetyp;                   // Target Operating system
    UCHAR  ne_flagsothers;              // Other .EXE flags
    USHORT ne_pretthunks;               // offset to return thunks
    USHORT ne_psegrefbytes;             // offset to segment ref. bytes
    USHORT ne_swaparea;                 // Minimum code swap area size
    USHORT ne_expver;                   // Expected Windows version number
  } IMAGE_OS2_HEADER, *PIMAGE_OS2_HEADER;

typedef struct _IMAGE_VXD_HEADER {      // Windows VXD header
    USHORT e32_magic;                   // Magic number
    UCHAR  e32_border;                  // The byte ordering for the VXD
    UCHAR  e32_worder;                  // The word ordering for the VXD
    ULONG  e32_level;                   // The EXE format level for now = 0
    USHORT e32_cpu;                     // The CPU type
    USHORT e32_os;                      // The OS type
    ULONG  e32_ver;                     // Module version
    ULONG  e32_mflags;                  // Module flags
    ULONG  e32_mpages;                  // Module # pages
    ULONG  e32_startobj;                // Object # for instruction pointer
    ULONG  e32_eip;                     // Extended instruction pointer
    ULONG  e32_stackobj;                // Object # for stack pointer
    ULONG  e32_esp;                     // Extended stack pointer
    ULONG  e32_pagesize;                // VXD page size
    ULONG  e32_lastpagesize;            // Last page size in VXD
    ULONG  e32_fixupsize;               // Fixup section size
    ULONG  e32_fixupsum;                // Fixup section checksum
    ULONG  e32_ldrsize;                 // Loader section size
    ULONG  e32_ldrsum;                  // Loader section checksum
    ULONG  e32_objtab;                  // Object table offset
    ULONG  e32_objcnt;                  // Number of objects in module
    ULONG  e32_objmap;                  // Object page map offset
    ULONG  e32_itermap;                 // Object iterated data map offset
    ULONG  e32_rsrctab;                 // Offset of Resource Table
    ULONG  e32_rsrccnt;                 // Number of resource entries
    ULONG  e32_restab;                  // Offset of resident name table
    ULONG  e32_enttab;                  // Offset of Entry Table
    ULONG  e32_dirtab;                  // Offset of Module Directive Table
    ULONG  e32_dircnt;                  // Number of module directives
    ULONG  e32_fpagetab;                // Offset of Fixup Page Table
    ULONG  e32_frectab;                 // Offset of Fixup Record Table
    ULONG  e32_impmod;                  // Offset of Import Module Name Table
    ULONG  e32_impmodcnt;               // Number of entries in Import Module Name Table
    ULONG  e32_impproc;                 // Offset of Import Procedure Name Table
    ULONG  e32_pagesum;                 // Offset of Per-Page Checksum Table
    ULONG  e32_datapage;                // Offset of Enumerated Data Pages
    ULONG  e32_preload;                 // Number of preload pages
    ULONG  e32_nrestab;                 // Offset of Non-resident Names Table
    ULONG  e32_cbnrestab;               // Size of Non-resident Name Table
    ULONG  e32_nressum;                 // Non-resident Name Table Checksum
    ULONG  e32_autodata;                // Object # for automatic data object
    ULONG  e32_debuginfo;               // Offset of the debugging information
    ULONG  e32_debuglen;                // The length of the debugging info. in bytes
    ULONG  e32_instpreload;             // Number of instance pages in preload section of VXD file
    ULONG  e32_instdemand;              // Number of instance pages in demand load section of VXD file
    ULONG  e32_heapsize;                // Size of heap - for 16-bit apps
    UCHAR  e32_res3[12];                // Reserved words
    ULONG  e32_winresoff;
    ULONG  e32_winreslen;
    USHORT e32_devid;                   // Device ID for VxD
    USHORT e32_ddkver;                  // DDK version for VxD
  } IMAGE_VXD_HEADER, *PIMAGE_VXD_HEADER;

#include "poppack.h"                    // Back to 4 byte packing

//
// File header format.
//

typedef struct _IMAGE_FILE_HEADER {
    USHORT  Machine;
    USHORT  NumberOfSections;
    ULONG   TimeDateStamp;
    ULONG   PointerToSymbolTable;
    ULONG   NumberOfSymbols;
    USHORT  SizeOfOptionalHeader;
    USHORT  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

#define IMAGE_SIZEOF_FILE_HEADER             20

#define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file.
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // File is executable  (i.e. no unresolved externel references).
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // Line nunbers stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // Local symbols stripped from file.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // Agressively trim working set
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  // Bytes of machine word are reversed.
#define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32 bit word machine.
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // Debugging info stripped from file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // If Image is on removable media, copy and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // If Image is on Net, copy and run from the swap file.
#define IMAGE_FILE_SYSTEM                    0x1000  // System File.
#define IMAGE_FILE_DLL                       0x2000  // File is a DLL.
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // File should only be run on a UP machine
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000  // Bytes of machine word are reversed.

#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_I386              0x14c   // Intel 386.
#define IMAGE_FILE_MACHINE_R3000             0x162   // MIPS little-endian, 0x160 big-endian
#define IMAGE_FILE_MACHINE_R4000             0x166   // MIPS little-endian
#define IMAGE_FILE_MACHINE_R10000            0x168   // MIPS little-endian
#define IMAGE_FILE_MACHINE_ALPHA             0x184   // Alpha_AXP
#define IMAGE_FILE_MACHINE_POWERPC           0x1F0   // IBM PowerPC Little-Endian

//
// Directory format.
//

typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG   VirtualAddress;
    ULONG   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

//
// Optional header format.
//

typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    USHORT  Magic;
    UCHAR   MajorLinkerVersion;
    UCHAR   MinorLinkerVersion;
    ULONG   SizeOfCode;
    ULONG   SizeOfInitializedData;
    ULONG   SizeOfUninitializedData;
    ULONG   AddressOfEntryPoint;
    ULONG   BaseOfCode;
    ULONG   BaseOfData;

    //
    // NT additional fields.
    //

    ULONG   ImageBase;
    ULONG   SectionAlignment;
    ULONG   FileAlignment;
    USHORT  MajorOperatingSystemVersion;
    USHORT  MinorOperatingSystemVersion;
    USHORT  MajorImageVersion;
    USHORT  MinorImageVersion;
    USHORT  MajorSubsystemVersion;
    USHORT  MinorSubsystemVersion;
    ULONG   Win32VersionValue;
    ULONG   SizeOfImage;
    ULONG   SizeOfHeaders;
    ULONG   CheckSum;
    USHORT  Subsystem;
    USHORT  DllCharacteristics;
    ULONG   SizeOfStackReserve;
    ULONG   SizeOfStackCommit;
    ULONG   SizeOfHeapReserve;
    ULONG   SizeOfHeapCommit;
    ULONG   LoaderFlags;
    ULONG   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
    USHORT Magic;
    UCHAR  MajorLinkerVersion;
    UCHAR  MinorLinkerVersion;
    ULONG  SizeOfCode;
    ULONG  SizeOfInitializedData;
    ULONG  SizeOfUninitializedData;
    ULONG  AddressOfEntryPoint;
    ULONG  BaseOfCode;
    ULONG  BaseOfData;
    ULONG  BaseOfBss;
    ULONG  GprMask;
    ULONG  CprMask[4];
    ULONG  GpValue;
} IMAGE_ROM_OPTIONAL_HEADER, *PIMAGE_ROM_OPTIONAL_HEADER;

#define IMAGE_SIZEOF_ROM_OPTIONAL_HEADER      56
#define IMAGE_SIZEOF_STD_OPTIONAL_HEADER      28
#define IMAGE_SIZEOF_NT_OPTIONAL_HEADER      224

#define IMAGE_NT_OPTIONAL_HDR_MAGIC        0x10b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x107

typedef struct _IMAGE_NT_HEADERS {
    ULONG Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_ROM_HEADERS {
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
} IMAGE_ROM_HEADERS, *PIMAGE_ROM_HEADERS;

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG)ntheader +                                                  \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))


// Subsystem Values

#define IMAGE_SUBSYSTEM_UNKNOWN              0   // Unknown subsystem.
#define IMAGE_SUBSYSTEM_NATIVE               1   // Image doesn't require a subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_GUI          2   // Image runs in the Windows GUI subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_CUI          3   // Image runs in the Windows character subsystem.
#define IMAGE_SUBSYSTEM_OS2_CUI              5   // image runs in the OS/2 character subsystem.
#define IMAGE_SUBSYSTEM_POSIX_CUI            7   // image run  in the Posix character subsystem.
#define IMAGE_SUBSYSTEM_RESERVED8            8   // image run  in the 8 subsystem.

// end_winnt

#define IMAGE_DLLCHARACTERISTICS_X86_THUNK   0x0001 // Image is a Wx86 Thunk DLL

// begin_winnt

// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT         0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT         1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE       2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION      3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY       4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC      5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG          6   // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT      7   // Description String
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR      8   // Machine Value (MIPS GP)
#define IMAGE_DIRECTORY_ENTRY_TLS            9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG   10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT  11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT           12   // Import Address Table

//
// Section header format.
//

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    UCHAR   Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            ULONG   PhysicalAddress;
            ULONG   VirtualSize;
    } Misc;
    ULONG   VirtualAddress;
    ULONG   SizeOfRawData;
    ULONG   PointerToRawData;
    ULONG   PointerToRelocations;
    ULONG   PointerToLinenumbers;
    USHORT  NumberOfRelocations;
    USHORT  NumberOfLinenumbers;
    ULONG   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER          40

//
// Section characteristics.
//

//      IMAGE_SCN_TYPE_REG                   0x00000000  // Reserved.
//      IMAGE_SCN_TYPE_DSECT                 0x00000001  // Reserved.
//      IMAGE_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
//      IMAGE_SCN_TYPE_GROUP                 0x00000004  // Reserved.
#define IMAGE_SCN_TYPE_NO_PAD                0x00000008  // Reserved.
//      IMAGE_SCN_TYPE_COPY                  0x00000010  // Reserved.

#define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.

#define IMAGE_SCN_LNK_OTHER                  0x00000100  // Reserved.
#define IMAGE_SCN_LNK_INFO                   0x00000200  // Section contains comments or some other type of information.
//      IMAGE_SCN_TYPE_OVER                  0x00000400  // Reserved.
#define IMAGE_SCN_LNK_REMOVE                 0x00000800  // Section contents will not become part of image.
#define IMAGE_SCN_LNK_COMDAT                 0x00001000  // Section contents comdat.
//                                           0x00002000  // Reserved.

//      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000
#define IMAGE_SCN_MEM_FARDATA                0x00008000
//      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000
#define IMAGE_SCN_MEM_16BIT                  0x00020000
#define IMAGE_SCN_MEM_LOCKED                 0x00040000
#define IMAGE_SCN_MEM_PRELOAD                0x00080000

#define IMAGE_SCN_ALIGN_1BYTES               0x00100000  //
#define IMAGE_SCN_ALIGN_2BYTES               0x00200000  //
#define IMAGE_SCN_ALIGN_4BYTES               0x00300000  //
#define IMAGE_SCN_ALIGN_8BYTES               0x00400000  //
#define IMAGE_SCN_ALIGN_16BYTES              0x00500000  // Default alignment if no others are specified.
#define IMAGE_SCN_ALIGN_32BYTES              0x00600000  //
#define IMAGE_SCN_ALIGN_64BYTES              0x00700000  //
// Unused                                    0x00800000

#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  // Section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  // Section can be discarded.
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  // Section is not cachable.
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // Section is not pageable.
#define IMAGE_SCN_MEM_SHARED                 0x10000000  // Section is shareable.
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.
#define IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.
#define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.


//
// TLS Chaacteristic Flags
//
#define IMAGE_SCN_SCALE_INDEX                0x00000001  // Tls index is scaled

#include "pshpack2.h"                       // Symbols, relocs, and linenumbers are 2 byte packed

//
// Symbol format.
//

typedef struct _IMAGE_SYMBOL {
    union {
        UCHAR   ShortName[8];
        struct {
            ULONG   Short;     // if 0, use LongName
            ULONG   Long;      // offset into string table
        } Name;
        PUCHAR  LongName[2];
    } N;
    ULONG   Value;
    SHORT   SectionNumber;
    USHORT  Type;
    UCHAR   StorageClass;
    UCHAR   NumberOfAuxSymbols;
} IMAGE_SYMBOL;
typedef IMAGE_SYMBOL UNALIGNED *PIMAGE_SYMBOL;


#define IMAGE_SIZEOF_SYMBOL                  18

//
// Section values.
//
// Symbols have a section number of the section in which they are
// defined. Otherwise, section numbers have the following meanings:
//

#define IMAGE_SYM_UNDEFINED           (SHORT)0          // Symbol is undefined or is common.
#define IMAGE_SYM_ABSOLUTE            (SHORT)-1         // Symbol is an absolute value.
#define IMAGE_SYM_DEBUG               (SHORT)-2         // Symbol is a special debug item.

//
// Type (fundamental) values.
//

#define IMAGE_SYM_TYPE_NULL                 0x0000  // no type.
#define IMAGE_SYM_TYPE_VOID                 0x0001  //
#define IMAGE_SYM_TYPE_CHAR                 0x0002  // type character.
#define IMAGE_SYM_TYPE_SHORT                0x0003  // type short integer.
#define IMAGE_SYM_TYPE_INT                  0x0004  //
#define IMAGE_SYM_TYPE_LONG                 0x0005  //
#define IMAGE_SYM_TYPE_FLOAT                0x0006  //
#define IMAGE_SYM_TYPE_DOUBLE               0x0007  //
#define IMAGE_SYM_TYPE_STRUCT               0x0008  //
#define IMAGE_SYM_TYPE_UNION                0x0009  //
#define IMAGE_SYM_TYPE_ENUM                 0x000A  // enumeration.
#define IMAGE_SYM_TYPE_MOE                  0x000B  // member of enumeration.
#define IMAGE_SYM_TYPE_UCHAR                0x000C  //
#define IMAGE_SYM_TYPE_USHORT               0x000D  //
#define IMAGE_SYM_TYPE_UINT                 0x000E  //
#define IMAGE_SYM_TYPE_ULONG                0x000F  //
#define IMAGE_SYM_TYPE_PCODE                0x8000  //

//
// Type (derived) values.
//

#define IMAGE_SYM_DTYPE_NULL                0       // no derived type.
#define IMAGE_SYM_DTYPE_POINTER             1       // pointer.
#define IMAGE_SYM_DTYPE_FUNCTION            2       // function.
#define IMAGE_SYM_DTYPE_ARRAY               3       // array.

//
// Storage classes.
//

#define IMAGE_SYM_CLASS_END_OF_FUNCTION     (UCHAR)-1
#define IMAGE_SYM_CLASS_NULL                0x0000
#define IMAGE_SYM_CLASS_AUTOMATIC           0x0001
#define IMAGE_SYM_CLASS_EXTERNAL            0x0002
#define IMAGE_SYM_CLASS_STATIC              0x0003
#define IMAGE_SYM_CLASS_REGISTER            0x0004
#define IMAGE_SYM_CLASS_EXTERNAL_DEF        0x0005
#define IMAGE_SYM_CLASS_LABEL               0x0006
#define IMAGE_SYM_CLASS_UNDEFINED_LABEL     0x0007
#define IMAGE_SYM_CLASS_MEMBER_OF_STRUCT    0x0008
#define IMAGE_SYM_CLASS_ARGUMENT            0x0009
#define IMAGE_SYM_CLASS_STRUCT_TAG          0x000A
#define IMAGE_SYM_CLASS_MEMBER_OF_UNION     0x000B
#define IMAGE_SYM_CLASS_UNION_TAG           0x000C
#define IMAGE_SYM_CLASS_TYPE_DEFINITION     0x000D
#define IMAGE_SYM_CLASS_UNDEFINED_STATIC    0x000E
#define IMAGE_SYM_CLASS_ENUM_TAG            0x000F
#define IMAGE_SYM_CLASS_MEMBER_OF_ENUM      0x0010
#define IMAGE_SYM_CLASS_REGISTER_PARAM      0x0011
#define IMAGE_SYM_CLASS_BIT_FIELD           0x0012

#define IMAGE_SYM_CLASS_FAR_EXTERNAL        0x0044  //

#define IMAGE_SYM_CLASS_BLOCK               0x0064
#define IMAGE_SYM_CLASS_FUNCTION            0x0065
#define IMAGE_SYM_CLASS_END_OF_STRUCT       0x0066
#define IMAGE_SYM_CLASS_FILE                0x0067
// new
#define IMAGE_SYM_CLASS_SECTION             0x0068
#define IMAGE_SYM_CLASS_WEAK_EXTERNAL       0x0069

// type packing constants

#define N_BTMASK                            0x000F
#define N_TMASK                             0x0030
#define N_TMASK1                            0x00C0
#define N_TMASK2                            0x00F0
#define N_BTSHFT                            4
#define N_TSHIFT                            2

// MACROS

// Basic Type of  x
#define BTYPE(x) ((x) & N_BTMASK)

// Is x a pointer?
#ifndef ISPTR
#define ISPTR(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_POINTER << N_BTSHFT))
#endif

// Is x a function?
#ifndef ISFCN
#define ISFCN(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT))
#endif

// Is x an array?

#ifndef ISARY
#define ISARY(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_ARRAY << N_BTSHFT))
#endif

// Is x a structure, union, or enumeration TAG?
#ifndef ISTAG
#define ISTAG(x) ((x)==IMAGE_SYM_CLASS_STRUCT_TAG || (x)==IMAGE_SYM_CLASS_UNION_TAG || (x)==IMAGE_SYM_CLASS_ENUM_TAG)
#endif

#ifndef INCREF
#define INCREF(x) ((((x)&~N_BTMASK)<<N_TSHIFT)|(IMAGE_SYM_DTYPE_POINTER<<N_BTSHFT)|((x)&N_BTMASK))
#endif
#ifndef DECREF
#define DECREF(x) ((((x)>>N_TSHIFT)&~N_BTMASK)|((x)&N_BTMASK))
#endif

//
// Auxiliary entry format.
//

typedef union _IMAGE_AUX_SYMBOL {
    struct {
        ULONG    TagIndex;                      // struct, union, or enum tag index
        union {
            struct {
                USHORT  Linenumber;             // declaration line number
                USHORT  Size;                   // size of struct, union, or enum
            } LnSz;
           ULONG    TotalSize;
        } Misc;
        union {
            struct {                            // if ISFCN, tag, or .bb
                ULONG    PointerToLinenumber;
                ULONG    PointerToNextFunction;
            } Function;
            struct {                            // if ISARY, up to 4 dimen.
                USHORT   Dimension[4];
            } Array;
        } FcnAry;
        USHORT  TvIndex;                        // tv index
    } Sym;
    struct {
        UCHAR   Name[IMAGE_SIZEOF_SYMBOL];
    } File;
    struct {
        ULONG   Length;                         // section length
        USHORT  NumberOfRelocations;            // number of relocation entries
        USHORT  NumberOfLinenumbers;            // number of line numbers
        ULONG   CheckSum;                       // checksum for communal
        SHORT   Number;                         // section number to associate with
        UCHAR   Selection;                      // communal selection type
    } Section;
} IMAGE_AUX_SYMBOL;
typedef IMAGE_AUX_SYMBOL UNALIGNED *PIMAGE_AUX_SYMBOL;

#define IMAGE_SIZEOF_AUX_SYMBOL             18

//
// Communal selection types.
//

#define IMAGE_COMDAT_SELECT_NODUPLICATES    1
#define IMAGE_COMDAT_SELECT_ANY             2
#define IMAGE_COMDAT_SELECT_SAME_SIZE       3
#define IMAGE_COMDAT_SELECT_EXACT_MATCH     4
#define IMAGE_COMDAT_SELECT_ASSOCIATIVE     5
#define IMAGE_COMDAT_SELECT_LARGEST         6
#define IMAGE_COMDAT_SELECT_NEWEST          7

#define IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY  1
#define IMAGE_WEAK_EXTERN_SEARCH_LIBRARY    2
#define IMAGE_WEAK_EXTERN_SEARCH_ALIAS      3

//
// Relocation format.
//

typedef struct _IMAGE_RELOCATION {
    union {
        ULONG   VirtualAddress;
        ULONG   RelocCount;             // Set to the real count when IMAGE_SCN_LNK_NRELOC_OVFL is set
    };
    ULONG   SymbolTableIndex;
    USHORT  Type;
} IMAGE_RELOCATION;
typedef IMAGE_RELOCATION UNALIGNED *PIMAGE_RELOCATION;

#define IMAGE_SIZEOF_RELOCATION         10

//
// I386 relocation types.
//

#define IMAGE_REL_I386_ABSOLUTE         0x0000  // Reference is absolute, no relocation is necessary
#define IMAGE_REL_I386_DIR16            0x0001  // Direct 16-bit reference to the symbols virtual address
#define IMAGE_REL_I386_REL16            0x0002  // PC-relative 16-bit reference to the symbols virtual address
#define IMAGE_REL_I386_DIR32            0x0006  // Direct 32-bit reference to the symbols virtual address
#define IMAGE_REL_I386_DIR32NB          0x0007  // Direct 32-bit reference to the symbols virtual address, base not included
#define IMAGE_REL_I386_SEG12            0x0009  // Direct 16-bit reference to the segment-selector bits of a 32-bit virtual address
#define IMAGE_REL_I386_SECTION          0x000A
#define IMAGE_REL_I386_SECREL           0x000B
#define IMAGE_REL_I386_REL32            0x0014  // PC-relative 32-bit reference to the symbols virtual address

//
// MIPS relocation types.
//

#define IMAGE_REL_MIPS_ABSOLUTE         0x0000  // Reference is absolute, no relocation is necessary
#define IMAGE_REL_MIPS_REFHALF          0x0001
#define IMAGE_REL_MIPS_REFWORD          0x0002
#define IMAGE_REL_MIPS_JMPADDR          0x0003
#define IMAGE_REL_MIPS_REFHI            0x0004
#define IMAGE_REL_MIPS_REFLO            0x0005
#define IMAGE_REL_MIPS_GPREL            0x0006
#define IMAGE_REL_MIPS_LITERAL          0x0007
#define IMAGE_REL_MIPS_SECTION          0x000A
#define IMAGE_REL_MIPS_SECREL           0x000B
#define IMAGE_REL_MIPS_SECRELLO         0x000C  // Low 16-bit section relative referemce (used for >32k TLS)
#define IMAGE_REL_MIPS_SECRELHI         0x000D  // High 16-bit section relative reference (used for >32k TLS)
#define IMAGE_REL_MIPS_REFWORDNB        0x0022
#define IMAGE_REL_MIPS_PAIR             0x0025

//
// Alpha Relocation types.
//

#define IMAGE_REL_ALPHA_ABSOLUTE        0x0000
#define IMAGE_REL_ALPHA_REFLONG         0x0001
#define IMAGE_REL_ALPHA_REFQUAD         0x0002
#define IMAGE_REL_ALPHA_GPREL32         0x0003
#define IMAGE_REL_ALPHA_LITERAL         0x0004
#define IMAGE_REL_ALPHA_LITUSE          0x0005
#define IMAGE_REL_ALPHA_GPDISP          0x0006
#define IMAGE_REL_ALPHA_BRADDR          0x0007
#define IMAGE_REL_ALPHA_HINT            0x0008
#define IMAGE_REL_ALPHA_INLINE_REFLONG  0x0009
#define IMAGE_REL_ALPHA_REFHI           0x000A
#define IMAGE_REL_ALPHA_REFLO           0x000B
#define IMAGE_REL_ALPHA_PAIR            0x000C
#define IMAGE_REL_ALPHA_MATCH           0x000D
#define IMAGE_REL_ALPHA_SECTION         0x000E
#define IMAGE_REL_ALPHA_SECREL          0x000F
#define IMAGE_REL_ALPHA_REFLONGNB       0x0010
#define IMAGE_REL_ALPHA_SECRELLO        0x0011  // Low 16-bit section relative reference
#define IMAGE_REL_ALPHA_SECRELHI        0x0012  // High 16-bit section relative reference

//
// IBM PowerPC relocation types.
//

#define IMAGE_REL_PPC_ABSOLUTE          0x0000  // NOP
#define IMAGE_REL_PPC_ADDR64            0x0001  // 64-bit address
#define IMAGE_REL_PPC_ADDR32            0x0002  // 32-bit address
#define IMAGE_REL_PPC_ADDR24            0x0003  // 26-bit address, shifted left 2 (branch absolute)
#define IMAGE_REL_PPC_ADDR16            0x0004  // 16-bit address
#define IMAGE_REL_PPC_ADDR14            0x0005  // 16-bit address, shifted left 2 (load doubleword)
#define IMAGE_REL_PPC_REL24             0x0006  // 26-bit PC-relative offset, shifted left 2 (branch relative)
#define IMAGE_REL_PPC_REL14             0x0007  // 16-bit PC-relative offset, shifted left 2 (br cond relative)
#define IMAGE_REL_PPC_TOCREL16          0x0008  // 16-bit offset from TOC base
#define IMAGE_REL_PPC_TOCREL14          0x0009  // 16-bit offset from TOC base, shifted left 2 (load doubleword)

#define IMAGE_REL_PPC_ADDR32NB          0x000A  // 32-bit addr w/o image base
#define IMAGE_REL_PPC_SECREL            0x000B  // va of containing section (as in an image sectionhdr)
#define IMAGE_REL_PPC_SECTION           0x000C  // sectionheader number
#define IMAGE_REL_PPC_IFGLUE            0x000D  // substitute TOC restore instruction iff symbol is glue code
#define IMAGE_REL_PPC_IMGLUE            0x000E  // symbol is glue code; virtual address is TOC restore instruction
#define IMAGE_REL_PPC_SECREL16          0x000F  // va of containing section (limited to 16 bits)
#define IMAGE_REL_PPC_REFHI             0x0010
#define IMAGE_REL_PPC_REFLO             0x0011
#define IMAGE_REL_PPC_PAIR              0x0012
#define IMAGE_REL_PPC_SECRELLO          0x0013  // Low 16-bit section relative reference (used for >32k TLS)
#define IMAGE_REL_PPC_SECRELHI          0x0014  // High 16-bit section relative reference (used for >32k TLS)

#define IMAGE_REL_PPC_TYPEMASK          0x00FF  // mask to isolate above values in IMAGE_RELOCATION.Type

// Flag bits in IMAGE_RELOCATION.TYPE

#define IMAGE_REL_PPC_NEG               0x0100  // subtract reloc value rather than adding it
#define IMAGE_REL_PPC_BRTAKEN           0x0200  // fix branch prediction bit to predict branch taken
#define IMAGE_REL_PPC_BRNTAKEN          0x0400  // fix branch prediction bit to predict branch not taken
#define IMAGE_REL_PPC_TOCDEFN           0x0800  // toc slot defined in file (or, data in toc)

//
// Line number format.
//

typedef struct _IMAGE_LINENUMBER {
    union {
        ULONG   SymbolTableIndex;               // Symbol table index of function name if Linenumber is 0.
        ULONG   VirtualAddress;                 // Virtual address of line number.
    } Type;
    USHORT  Linenumber;                         // Line number.
} IMAGE_LINENUMBER;
typedef IMAGE_LINENUMBER UNALIGNED *PIMAGE_LINENUMBER;

#define IMAGE_SIZEOF_LINENUMBER              6

#include "poppack.h"                        // Back to 4 byte packing

//
// Based relocation format.
//

typedef struct _IMAGE_BASE_RELOCATION {
    ULONG   VirtualAddress;
    ULONG   SizeOfBlock;
//  USHORT  TypeOffset[1];
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;

#define IMAGE_SIZEOF_BASE_RELOCATION         8

//
// Based relocation types.
//

#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MIPS_JMPADDR          5
#define IMAGE_REL_BASED_SECTION               6
#define IMAGE_REL_BASED_REL32                 7

//
// Archive format.
//

#define IMAGE_ARCHIVE_START_SIZE             8
#define IMAGE_ARCHIVE_START                  "!<arch>\n"
#define IMAGE_ARCHIVE_END                    "`\n"
#define IMAGE_ARCHIVE_PAD                    "\n"
#define IMAGE_ARCHIVE_LINKER_MEMBER          "/               "
#define IMAGE_ARCHIVE_LONGNAMES_MEMBER       "//              "

typedef struct _IMAGE_ARCHIVE_MEMBER_HEADER {
    UCHAR    Name[16];                          // File member name - `/' terminated.
    UCHAR    Date[12];                          // File member date - decimal.
    UCHAR    UserID[6];                         // File member user id - decimal.
    UCHAR    GroupID[6];                        // File member group id - decimal.
    UCHAR    Mode[8];                           // File member mode - octal.
    UCHAR    Size[10];                          // File member size - decimal.
    UCHAR    EndHeader[2];                      // String to end header.
} IMAGE_ARCHIVE_MEMBER_HEADER, *PIMAGE_ARCHIVE_MEMBER_HEADER;

#define IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR      60

//
// DLL support.
//

//
// Export Format
//

typedef struct _IMAGE_EXPORT_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   Name;
    ULONG   Base;
    ULONG   NumberOfFunctions;
    ULONG   NumberOfNames;
    PULONG  *AddressOfFunctions;
    PULONG  *AddressOfNames;
    PUSHORT *AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

//
// Import Format
//

typedef struct _IMAGE_IMPORT_BY_NAME {
    USHORT  Hint;
    UCHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA {
    union {
        PUCHAR ForwarderString;
        PULONG Function;
        ULONG Ordinal;
        PIMAGE_IMPORT_BY_NAME AddressOfData;
    } u1;
} IMAGE_THUNK_DATA;
typedef IMAGE_THUNK_DATA * PIMAGE_THUNK_DATA;

#define IMAGE_ORDINAL_FLAG 0x80000000
#define IMAGE_SNAP_BY_ORDINAL(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG) != 0)
#define IMAGE_ORDINAL(Ordinal) (Ordinal & 0xffff)

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        ULONG   Characteristics;                // 0 for terminating null import descriptor
        PIMAGE_THUNK_DATA OriginalFirstThunk;   // RVA to original unbound IAT
    };
    ULONG   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    ULONG   ForwarderChain;                 // -1 if no forwarders
    ULONG   Name;
    PIMAGE_THUNK_DATA FirstThunk;           // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

//
// New format import descriptors pointed to by DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ]
//

typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    ULONG   TimeDateStamp;
    USHORT  OffsetModuleName;
    USHORT  NumberOfModuleForwarderRefs;
// Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
} IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_BOUND_FORWARDER_REF {
    ULONG   TimeDateStamp;
    USHORT  OffsetModuleName;
    USHORT  Reserved;
} IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;


//
// Thread Local Storage
//

typedef VOID
(NTAPI *PIMAGE_TLS_CALLBACK) (
    PVOID DllHandle,
    ULONG Reason,
    PVOID Reserved
    );

typedef struct _IMAGE_TLS_DIRECTORY {
    ULONG   StartAddressOfRawData;
    ULONG   EndAddressOfRawData;
    PULONG  AddressOfIndex;
    PIMAGE_TLS_CALLBACK *AddressOfCallBacks;
    ULONG   SizeOfZeroFill;
    ULONG   Characteristics;
} IMAGE_TLS_DIRECTORY, *PIMAGE_TLS_DIRECTORY;


//
// Resource Format.
//

//
// Resource directory consists of two counts, following by a variable length
// array of directory entries.  The first count is the number of entries at
// beginning of the array that have actual names associated with each entry.
// The entries are in ascending order, case insensitive strings.  The second
// count is the number of entries that immediately follow the named entries.
// This second count identifies the number of entries that have 16-bit integer
// Ids as their name.  These entries are also sorted in ascending order.
//
// This structure allows fast lookup by either name or number, but for any
// given resource entry only one form of lookup is supported, not both.
// This is consistant with the syntax of the .RC file and the .RES file.
//

typedef struct _IMAGE_RESOURCE_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    USHORT  NumberOfNamedEntries;
    USHORT  NumberOfIdEntries;
//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

#define IMAGE_RESOURCE_NAME_IS_STRING        0x80000000
#define IMAGE_RESOURCE_DATA_IS_DIRECTORY     0x80000000

//
// Each directory contains the 32-bit Name of the entry and an offset,
// relative to the beginning of the resource directory of the data associated
// with this directory entry.  If the name of the entry is an actual text
// string instead of an integer Id, then the high order bit of the name field
// is set to one and the low order 31-bits are an offset, relative to the
// beginning of the resource directory of the string, which is of type
// IMAGE_RESOURCE_DIRECTORY_STRING.  Otherwise the high bit is clear and the
// low-order 16-bits are the integer Id that identify this resource directory
// entry. If the directory entry is yet another resource directory (i.e. a
// subdirectory), then the high order bit of the offset field will be
// set to indicate this.  Otherwise the high bit is clear and the offset
// field points to a resource data entry.
//

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            ULONG NameOffset:31;
            ULONG NameIsString:1;
        };
        ULONG   Name;
        USHORT  Id;
    };
    union {
        ULONG   OffsetToData;
        struct {
            ULONG   OffsetToDirectory:31;
            ULONG   DataIsDirectory:1;
        };
    };
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

//
// For resource directory entries that have actual string names, the Name
// field of the directory entry points to an object of the following type.
// All of these string objects are stored together after the last resource
// directory entry and before the first resource data object.  This minimizes
// the impact of these variable length objects on the alignment of the fixed
// size directory entry objects.
//

typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING {
    USHORT  Length;
    CHAR    NameString[ 1 ];
} IMAGE_RESOURCE_DIRECTORY_STRING, *PIMAGE_RESOURCE_DIRECTORY_STRING;


typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
    USHORT  Length;
    WCHAR   NameString[ 1 ];
} IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;


//
// Each resource data entry describes a leaf node in the resource directory
// tree.  It contains an offset, relative to the beginning of the resource
// directory of the data for the resource, a size field that gives the number
// of bytes of data at that offset, a CodePage that should be used when
// decoding code point values within the resource data.  Typically for new
// applications the code page would be the unicode code page.
//

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
    ULONG   OffsetToData;
    ULONG   Size;
    ULONG   CodePage;
    ULONG   Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

//
// Load Configuration Directory Entry
//

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   GlobalFlagsClear;
    ULONG   GlobalFlagsSet;
    ULONG   CriticalSectionDefaultTimeout;
    ULONG   DeCommitFreeBlockThreshold;
    ULONG   DeCommitTotalFreeThreshold;
    PVOID   LockPrefixTable;
    ULONG   MaximumAllocationSize;
    ULONG   VirtualMemoryThreshold;
    ULONG   ProcessHeapFlags;
    ULONG   ProcessAffinityMask;
    ULONG   Reserved[ 3 ];
} IMAGE_LOAD_CONFIG_DIRECTORY, *PIMAGE_LOAD_CONFIG_DIRECTORY;


//
// Function table entry format for MIPS/ALPHA images.  Function table is
// pointed to by the IMAGE_DIRECTORY_ENTRY_EXCEPTION directory entry.
// This definition duplicates ones in ntmips.h and ntalpha.h for use
// by portable image file mungers.
//

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ULONG BeginAddress;
    ULONG EndAddress;
    PVOID ExceptionHandler;
    PVOID HandlerData;
    ULONG PrologEndAddress;
} IMAGE_RUNTIME_FUNCTION_ENTRY, *PIMAGE_RUNTIME_FUNCTION_ENTRY;

//
// Debug Format
//

typedef struct _IMAGE_DEBUG_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   Type;
    ULONG   SizeOfData;
    ULONG   AddressOfRawData;
    ULONG   PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

#define IMAGE_DEBUG_TYPE_UNKNOWN          0
#define IMAGE_DEBUG_TYPE_COFF             1
#define IMAGE_DEBUG_TYPE_CODEVIEW         2
#define IMAGE_DEBUG_TYPE_FPO              3
#define IMAGE_DEBUG_TYPE_MISC             4
#define IMAGE_DEBUG_TYPE_EXCEPTION        5
#define IMAGE_DEBUG_TYPE_FIXUP            6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC      7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    8

// end_winnt

// IMAGE_DEBUG_TYPE values > 0x7FFFFFFF are reserved for Lego

// begin_winnt

typedef struct _IMAGE_COFF_SYMBOLS_HEADER {
    ULONG   NumberOfSymbols;
    ULONG   LvaToFirstSymbol;
    ULONG   NumberOfLinenumbers;
    ULONG   LvaToFirstLinenumber;
    ULONG   RvaToFirstByteOfCode;
    ULONG   RvaToLastByteOfCode;
    ULONG   RvaToFirstByteOfData;
    ULONG   RvaToLastByteOfData;
} IMAGE_COFF_SYMBOLS_HEADER, *PIMAGE_COFF_SYMBOLS_HEADER;

#define FRAME_FPO       0
#define FRAME_TRAP      1
#define FRAME_TSS       2
#define FRAME_NONFPO    3

typedef struct _FPO_DATA {
    ULONG       ulOffStart;             // offset 1st byte of function code
    ULONG       cbProcSize;             // # bytes in function
    ULONG       cdwLocals;              // # bytes in locals/4
    USHORT      cdwParams;              // # bytes in params/4
    USHORT      cbProlog : 8;           // # bytes in prolog
    USHORT      cbRegs   : 3;           // # regs saved
    USHORT      fHasSEH  : 1;           // TRUE if SEH in func
    USHORT      fUseBP   : 1;           // TRUE if EBP has been allocated
    USHORT      reserved : 1;           // reserved for future use
    USHORT      cbFrame  : 2;           // frame type
} FPO_DATA, *PFPO_DATA;
#define SIZEOF_RFPO_DATA 16


#define IMAGE_DEBUG_MISC_EXENAME    1

typedef struct _IMAGE_DEBUG_MISC {
    ULONG       DataType;               // type of misc data, see defines
    ULONG       Length;                 // total length of record, rounded to four
                                        // byte multiple.
    BOOLEAN     Unicode;                // TRUE if data is unicode string
    UCHAR       Reserved[ 3 ];
    UCHAR       Data[ 1 ];              // Actual data
} IMAGE_DEBUG_MISC, *PIMAGE_DEBUG_MISC;


//
// Function table extracted from MIPS/ALPHA images.  Does not contain
// information needed only for runtime support.  Just those fields for
// each entry needed by a debugger.
//

typedef struct _IMAGE_FUNCTION_ENTRY {
    ULONG   StartingAddress;
    ULONG   EndingAddress;
    ULONG   EndOfPrologue;
} IMAGE_FUNCTION_ENTRY, *PIMAGE_FUNCTION_ENTRY;

//
// Debugging information can be stripped from an image file and placed
// in a separate .DBG file, whose file name part is the same as the
// image file name part (e.g. symbols for CMD.EXE could be stripped
// and placed in CMD.DBG).  This is indicated by the IMAGE_FILE_DEBUG_STRIPPED
// flag in the Characteristics field of the file header.  The beginning of
// the .DBG file contains the following structure which captures certain
// information from the image file.  This allows a debug to proceed even if
// the original image file is not accessable.  This header is followed by
// zero of more IMAGE_SECTION_HEADER structures, followed by zero or more
// IMAGE_DEBUG_DIRECTORY structures.  The latter structures and those in
// the image file contain file offsets relative to the beginning of the
// .DBG file.
//
// If symbols have been stripped from an image, the IMAGE_DEBUG_MISC structure
// is left in the image file, but not mapped.  This allows a debugger to
// compute the name of the .DBG file, from the name of the image in the
// IMAGE_DEBUG_MISC structure.
//

typedef struct _IMAGE_SEPARATE_DEBUG_HEADER {
    USHORT      Signature;
    USHORT      Flags;
    USHORT      Machine;
    USHORT      Characteristics;
    ULONG       TimeDateStamp;
    ULONG       CheckSum;
    ULONG       ImageBase;
    ULONG       SizeOfImage;
    ULONG       NumberOfSections;
    ULONG       ExportedNamesSize;
    ULONG       DebugDirectorySize;
    ULONG       SectionAlignment;
    ULONG       Reserved[2];
} IMAGE_SEPARATE_DEBUG_HEADER, *PIMAGE_SEPARATE_DEBUG_HEADER;

#define IMAGE_SEPARATE_DEBUG_SIGNATURE  0x4944

#define IMAGE_SEPARATE_DEBUG_FLAGS_MASK 0x8000
#define IMAGE_SEPARATE_DEBUG_MISMATCH   0x8000  // when DBG was updated, the
                                                // old checksum didn't match.

#include "poppack.h"                        // Return to the default

typedef struct {
    ULONG Function;
    ULONG Toc;
} AIXCALL_FPTR, *PAIXCALL_FPTR;

typedef IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION_ENTRY, *PRUNTIME_FUNCTION_ENTRY;

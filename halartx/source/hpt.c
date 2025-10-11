#include "halp.h"

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	// ...
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

PVOID PeGetExport(PVOID ImageBase, const char* ExportName);

typedef void (*tfpMmAllocateHPT)(ULONG Size, PLOADER_PARAMETER_BLOCK LoaderBlock);
static volatile ULONG s_HashPageTables = 0;

#define __mtspr(spr, value)     \
  __asm__ volatile ("mtspr %0, %1" : : "n" (spr), "r" (value))

// NT 3.51 init calls this function to initialise hashed page tables.
// NT 4 does this in the kernel itself.
NTHALAPI VOID HalInitializeHPT(IN ULONG ProcessorNumber, IN PLOADER_PARAMETER_BLOCK LoaderBlock) {
	// We need to import some functions.
	// Those functions are gone in NT4, so we can't just link with the implib.
	// We have LOADER_PARAMETER_BLOCK so we can walk through loaded binaries.
	// first one in load order should well be kernel.
	
	if (ProcessorNumber == 0) {
	
		PLDR_DATA_TABLE_ENTRY Entry = (PLDR_DATA_TABLE_ENTRY)
			LoaderBlock->LoadOrderListHead.Flink;
		PVOID ImageBase = Entry->DllBase;
		
		tfpMmAllocateHPT MmAllocateHPT = (tfpMmAllocateHPT)
			PeGetExport(ImageBase, "MmAllocateHPT");
		
		if (MmAllocateHPT == NULL) KeBugCheck(MISMATCHED_HAL);
		// Work around compiler bug
		asm volatile("");
		
		MmAllocateHPT(0x10000, LoaderBlock);
		LoaderBlock->u.Ppc.NumberCongruenceClasses = 64;
		
		// This is NT 3.51. Put some stuff in the PCR(?).
		ULONG PcrMaybe;
		asm volatile("mfsprg %0, 1\n" : "=r" (PcrMaybe));
		*(PULONG)(PcrMaybe + 0x484) = 0x8000;
		*(PULONG)(PcrMaybe + 0x48c) = 0x8000;
		*(PULONG)(PcrMaybe + 0x4AC) = 31;
		*(PULONG)(PcrMaybe + 0x4B4) = 31;
		
		s_HashPageTables = LoaderBlock->u.Ppc.HashedPageTable;
	} else {
		// Spin until first processor allocates the HPTs.
		while (s_HashPageTables == 0) { }
	}
	
	// set SDR1
	__mtspr(25, s_HashPageTables);
}
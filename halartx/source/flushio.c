// Cache flushing/etc functions.
#include "halp.h"

ULONG HalGetDmaAlignmentRequirement(void) {
	return 1;
}


void HalpSweepPhysicalRange(ULONG Page, ULONG Offset, ULONG Length, BOOLEAN AlsoFlushDcache);

// Flush the IO buffer from dcache.
void HalFlushIoBuffers(PMDL Mdl, BOOLEAN ReadOperation, BOOLEAN DmaOperation) {
	// If it's not a read, then do nothing.
	if (ReadOperation == FALSE || (Mdl->MdlFlags & MDL_IO_PAGE_READ) == 0) {
		return;
	}
	
	ULONG Length = Mdl->ByteCount;
	if (!Length) return;

	BOOLEAN AlsoFlushDcache = DmaOperation == FALSE;
	
	ULONG Offset = Mdl->ByteOffset;
	ULONG PartialLength = PAGE_SIZE - Offset;
	if (PartialLength > Length) PartialLength = Length;

	PULONG Page = (PULONG) &Mdl[1];
	
	// Sweep the first page.
	HalpSweepPhysicalRange(*Page, Offset, PartialLength, AlsoFlushDcache);
	Page++;
	Length -= PartialLength;
	if (Length == 0) return;

	// Additional pages are done without any byte offset.
	PartialLength = PAGE_SIZE;
	do {
		if (PartialLength > Length) PartialLength = Length;
		HalpSweepPhysicalRange(*Page, 0, PartialLength, AlsoFlushDcache);
		Page++;
		Length -= PartialLength;
	} while (Length != 0);
}

// https://github.com/fail0verflow/hbc/blob/a8e5f6c0f7e484c7f7112967eee6eee47b27d9ac/wiipax/stub/sync.c#L29
void HalSyncBeforeExecution(PVOID BaseAddress, ULONG Length) {
	ULONG a, b;

	a = (ULONG)BaseAddress & ~0x1f;
	b = ((ULONG)BaseAddress + Length + 0x1f) & ~0x1f;

	for (; a < b; a += 32)
		asm("dcbst 0,%0 ; sync ; icbi 0,%0" : : "b"(a));

	asm("sync ; isync");
}
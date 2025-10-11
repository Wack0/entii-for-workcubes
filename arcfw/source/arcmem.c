#include <stddef.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include "arc.h"
#include "arcmem.h"
#include "processor.h"
#include "runtime.h"

enum {
	MEM_CHUNK_COUNT = 20
};

static ARC_MEMORY_CHUNK s_Descriptors[MEM_CHUNK_COUNT] = { 0 };

// https://github.com/fail0verflow/hbc/blob/a8e5f6c0f7e484c7f7112967eee6eee47b27d9ac/wiipax/stub/sync.c#L29
void sync_before_exec(const void* p, ULONG len)
{

	u32 a, b;

	a = (u32)p & ~0x1f;
	b = ((u32)p + len + 0x1f) & ~0x1f;

	// should only be calling this with uncached addresses.
	if (a > 0xA0000000) return;
	if (a < 0x80000000) return;

	for (; a < b; a += 32)
		asm("dcbst 0,%0 ; sync ; icbi 0,%0" : : "b"(a));

	asm("sync ; isync");
}

void data_cache_invalidate(const void* p, ULONG len) {
	u32 a, b;

	a = (u32)p & ~0x1f;
	b = ((u32)p + len + 0x1f) & ~0x1f;

	// should only be calling this with uncached addresses.
	if (a > 0xA0000000) return;
	if (a < 0x80000000) return;

	for (; a < b; a += 32)
		asm("dcbi 0,%0 ; sync" : : "b"(a));

	asm("sync ; isync");
}

void data_cache_flush(const void* p, ULONG len) {
	u32 a, b;

	a = (u32)p & ~0x1f;
	b = ((u32)p + len + 0x1f) & ~0x1f;

	// should only be calling this with uncached addresses.
	if (a > 0xA0000000) return;
	if (a < 0x80000000) return;

	for (; a < b; a += 32)
		asm("dcbf 0,%0 ; sync" : : "b"(a));

	asm("sync ; isync");
}

static ULONG s_BootMemPages = 0;

static void ArcFlushAllCaches(void) {
	// Flush only the first 8MB.
	ULONG Start = 0x80000000;
	ULONG Length = 0x800000;
	sync_before_exec((PVOID)Start, Length);
}

static inline ARC_FORCEINLINE void LinkDescriptors(ULONG Chunk) {
	if ((Chunk + 1) >= MEM_CHUNK_COUNT) return;
	s_Descriptors[Chunk].Next = &s_Descriptors[Chunk + 1];
	s_Descriptors[Chunk + 1].Prev = &s_Descriptors[Chunk];
}

static inline ARC_FORCEINLINE void InitDescriptor(ULONG Chunk, ULONG BasePage, ULONG PageCount, MEMORY_TYPE MemoryType) {
	if ((Chunk + 1) >= MEM_CHUNK_COUNT) return;
	s_Descriptors[Chunk].Descriptor.BasePage = BasePage;
	s_Descriptors[Chunk].Descriptor.PageCount = PageCount;
	s_Descriptors[Chunk].Descriptor.MemoryType = MemoryType;
}

#define INIT_DESCRIPTOR(Chunk, BasePage, PageCount, MemoryType) do { \
	if (Chunk != 0) LinkDescriptors(Chunk - 1); \
	InitDescriptor(Chunk, BasePage, PageCount, MemoryType); \
	BasePage += (PageCount); \
} while (0)

static PMEMORY_DESCRIPTOR ArcMemory(PMEMORY_DESCRIPTOR MemoryDescriptor) {
	if (MemoryDescriptor == NULL) {
		return &s_Descriptors[0].Descriptor;
	}

	PARC_MEMORY_CHUNK Chunk = (PARC_MEMORY_CHUNK)MemoryDescriptor;
	if (Chunk->Next == NULL) return NULL;
	return &Chunk->Next->Descriptor;
}

static ARC_NOINLINE PMEMORY_DESCRIPTOR ArcMemFindChunkImpl(ULONG BasePage, ULONG LengthPages, MEMORY_TYPE Type) {
	PMEMORY_DESCRIPTOR Chunk = ArcMemory(NULL);
	for (; Chunk != NULL; Chunk = ArcMemory(Chunk)) {
		if (Chunk->MemoryType != Type) continue;
		if (BasePage < Chunk->BasePage) continue;
		if ((BasePage + LengthPages) > (Chunk->BasePage + Chunk->PageCount)) continue;
		break;
	}
	return Chunk;
}

static ARC_NOINLINE PMEMORY_DESCRIPTOR ArcMemFindChunkAny(ULONG BasePage, ULONG LengthPages) {
	PMEMORY_DESCRIPTOR Chunk = ArcMemory(NULL);
	for (; Chunk != NULL; Chunk = ArcMemory(Chunk)) {
		if (BasePage < Chunk->BasePage) continue;
		if ((BasePage + LengthPages) > (Chunk->BasePage + Chunk->PageCount)) continue;
		break;
	}
	return Chunk;
}

static ARC_NOINLINE PMEMORY_DESCRIPTOR ArcMemFindChunkWithoutLength(ULONG BasePage, MEMORY_TYPE Type) {
	PMEMORY_DESCRIPTOR Chunk = ArcMemory(NULL);
	for (; Chunk != NULL; Chunk = ArcMemory(Chunk)) {
		if (Chunk->MemoryType != Type) continue;
		if (Chunk->BasePage >= BasePage) break;
		if ((Chunk->BasePage + Chunk->PageCount) <= BasePage) continue;
		break;
	}
	return Chunk;
}

static ARC_NOINLINE PMEMORY_DESCRIPTOR ArcMemFindAnyChunkWithoutLength(ULONG BasePage) {
	PMEMORY_DESCRIPTOR Chunk = ArcMemory(NULL);
	for (; Chunk != NULL; Chunk = ArcMemory(Chunk)) {
		if (Chunk->BasePage > BasePage) continue;
		if (Chunk->BasePage < BasePage) {
			if ((Chunk->BasePage + Chunk->PageCount) <= BasePage) continue;
		}
		break;
	}
	return Chunk;
}

/// <summary>
/// Obtains the free chunk including a set of pages.
/// </summary>
/// <param name="BasePage">Base page to search for.</param>
/// <param name="LengthPages">Number of pages of the allocation.</param>
/// <returns>Free memory chunk suitable for ArcMemAllocateFromFreeChunk, or NULL if not found.</returns>
PMEMORY_DESCRIPTOR ArcMemFindChunk(ULONG BasePage, ULONG LengthPages) {
	return ArcMemFindChunkImpl(BasePage, LengthPages, MemoryFree);
}

/// <summary>
/// Finds a free (unused) memory chunk, not inside the linked list.
/// </summary>
/// <returns>Unused memory chunk, or NULL if not found.</returns>
static PARC_MEMORY_CHUNK ArcMemFindFreeChunk(void) {
	for (int i = 0; i < MEM_CHUNK_COUNT; i++) {
		if (s_Descriptors[i].Next == NULL && s_Descriptors[i].Prev == NULL) return &s_Descriptors[i];
	}
	return NULL;
}

static ARC_STATUS ArcMemAllocateFromChunk(PMEMORY_DESCRIPTOR Desc, ULONG BasePage, ULONG PageCount, MEMORY_TYPE MemoryType) {
	ULONG DescBase = Desc->BasePage;
	ULONG DescCount = Desc->PageCount;

	// Is the entire free memchunk being allocated?
	if (DescBase == BasePage && DescCount == PageCount) {
		// yes.
		Desc->MemoryType = MemoryType;
		return _ESUCCESS;
	}

	// Ensure the allocated chunk is entirely part of this one.
	if (BasePage < DescBase) return _EINVAL;
	ULONG OffsetFromDesc = BasePage - DescBase;
	if (OffsetFromDesc + PageCount > DescCount) return _EINVAL;

	// Additional chunks need to be allocated to describe the free memory around this descriptor.
	PARC_MEMORY_CHUNK Chunk = (PARC_MEMORY_CHUNK)Desc;
	if (DescBase == BasePage) {
		// Allocation is from the start of the chunk. Additional chunk needs to be allocated to describe the rest of the region.
		PARC_MEMORY_CHUNK FreeChunk = ArcMemFindFreeChunk();
		if (FreeChunk == NULL) return _ENOMEM;
		FreeChunk->Prev = Chunk;
		FreeChunk->Next = Chunk->Next;
		FreeChunk->Next->Prev = FreeChunk;
		FreeChunk->Descriptor = Chunk->Descriptor;
		FreeChunk->Descriptor.BasePage += PageCount;
		FreeChunk->Descriptor.PageCount -= PageCount;

		Desc->MemoryType = MemoryType;
		Desc->PageCount = PageCount;
		Chunk->Next = FreeChunk;
		return _ESUCCESS;
	}

	if (DescCount == OffsetFromDesc + PageCount) {
		// Allocation is from the end of the chunk. Additional chunk needs to be allocated to describe the rest of the region.
		PARC_MEMORY_CHUNK FreeChunk = ArcMemFindFreeChunk();
		if (FreeChunk == NULL) return _ENOMEM;
		FreeChunk->Next = Chunk;
		FreeChunk->Prev = Chunk->Prev;
		FreeChunk->Prev->Next = FreeChunk;
		FreeChunk->Descriptor = Chunk->Descriptor;
		FreeChunk->Descriptor.PageCount -= PageCount;

		Desc->BasePage = BasePage;
		Desc->PageCount = PageCount;
		Desc->MemoryType = MemoryType;
		Chunk->Prev = FreeChunk;
		return _ESUCCESS;
	}

	// Allocation is in the middle of the chunk. Additional TWO chunks need to be allocated to describe the other regions.
	PARC_MEMORY_CHUNK FreeChunkPrev = ArcMemFindFreeChunk();
	if (FreeChunkPrev == NULL) return _ENOMEM;
	// Start to set up the linked list so that this chunk is no longer considered free
	FreeChunkPrev->Next = Chunk;
	PARC_MEMORY_CHUNK FreeChunkNext = ArcMemFindFreeChunk();
	if (FreeChunkNext == NULL) {
		FreeChunkPrev->Next = NULL;
		return _ENOMEM;
	}

	FreeChunkPrev->Prev = Chunk->Prev;
	FreeChunkPrev->Prev->Next = FreeChunkPrev;
	FreeChunkNext->Prev = Chunk;
	FreeChunkNext->Next = Chunk->Next;
	FreeChunkNext->Next->Prev = FreeChunkPrev;

	FreeChunkPrev->Descriptor = FreeChunkNext->Descriptor = Chunk->Descriptor;
	FreeChunkPrev->Descriptor.PageCount = OffsetFromDesc;
	FreeChunkNext->Descriptor.BasePage = BasePage + PageCount;
	FreeChunkNext->Descriptor.PageCount = DescCount - OffsetFromDesc - PageCount;

	Desc->BasePage = BasePage;
	Desc->PageCount = PageCount;
	Desc->MemoryType = MemoryType;
	Chunk->Next = FreeChunkNext;
	Chunk->Prev = FreeChunkPrev;
	return _ESUCCESS;
}

/// <summary>
/// Given a free memory chunk, allocate an area of memory from it.
/// </summary>
/// <param name="Desc">Chunk to allocate from</param>
/// <param name="BasePage">Base page</param>
/// <param name="PageCount">Page count</param>
/// <param name="MemoryType">Memory type</param>
/// <remarks>Sub-chunks are carved out around the passed in descriptor, which will be the allocated sub-chunk on function success.</remarks>
/// <returns>ARC status code.</returns>
ARC_STATUS ArcMemAllocateFromFreeChunk(PMEMORY_DESCRIPTOR Desc, ULONG BasePage, ULONG PageCount, MEMORY_TYPE MemoryType) {
	if (Desc->MemoryType != MemoryFree) return _EINVAL;

	return ArcMemAllocateFromChunk(Desc, BasePage, PageCount, MemoryType);
}

static PVOID ArcMemAllocImpl(size_t length, MEMORY_TYPE MemoryType, size_t startAddr, size_t endAddr) {
	// Align length to page size.
	ULONG LengthPages = (length + (PAGE_SIZE - 1)) / PAGE_SIZE;
	length = LengthPages * PAGE_SIZE;

	// Find the first chunk marked free above startAddr. // 0x800000
	// We can't use any memory above endAddr either. // 0x10000000

	// Note that we are only performing a 1:1 mapping here.
	PMEMORY_DESCRIPTOR Desc = ArcMemFindChunkWithoutLength(startAddr / PAGE_SIZE, MemoryFree);
	if (Desc == NULL || Desc->BasePage >= (endAddr / PAGE_SIZE)) {
		return NULL;
	}

	// Allocate from the end of this memchunk.

	// Get the start and end of the memchunk.
	ULONG Arena1Hi = ((ULONG)(Desc->BasePage + Desc->PageCount) * PAGE_SIZE);
	ULONG Arena1Lo = ((ULONG)(Desc->BasePage) * PAGE_SIZE);
	// If it's not aligned to a page, do that now.
	// Just mask off the relevant bits.
	ULONG Arena1HiOld = Arena1Hi;
	Arena1Hi &= ~(PAGE_SIZE - 1);
	if (Arena1Hi != Arena1HiOld) {
		// Additional page being used.
		LengthPages++;
	}

	PVOID ret = (PVOID)(Arena1Hi - length);
	if ((ULONG)ret < Arena1Lo) {
		return NULL;
	}

	// Carve this chunk out of the memory descriptors.
	ULONG BasePage = ((ULONG)ret) / PAGE_SIZE;
	if (ARC_FAIL(ArcMemAllocateFromChunk(Desc, BasePage, LengthPages, MemoryType))) return NULL;

	// physical to virtual
	ret = (PVOID)((ULONG)ret | 0x80000000);
	return ret;
}

static PVOID ArcMemAllocChunk(size_t length, MEMORY_TYPE MemoryType, bool InDDR) {
	size_t startAddr = InDDR ? 0x10000000 : 0x800000;
	size_t endAddr = InDDR ? 0x20000000 : 0x10000000;
	return ArcMemAllocImpl(length, MemoryType, startAddr, endAddr);
}

/// <summary>
/// Allocates a chunk of memory to use during boot. The chunk is configured as FirmwareTemporary.
/// </summary>
/// <param name="length">Length to allocate in bytes.</param>
/// <param name="InDDR">If false, memory will be allocated from Splash/Napa/MEM1. If true, memory will be allocated from DDR/MEM2.</param>
/// <returns>Pointer to allocated memory.</returns>
PVOID ArcMemAllocTemp(size_t length, bool InDDR) {
	return ArcMemAllocChunk(length, MemoryFirmwareTemporary, InDDR);
}

/// <summary>
/// Allocates a chunk of memory to use for hardware purposes. The chunk is configured as FirmwarePermanent so NT doesn't clobber it.
/// </summary>
/// <param name="length">Length to allocate in bytes.</param>
/// <param name="InDDR">If false, memory will be allocated from Splash/Napa/MEM1. If true, memory will be allocated from DDR/MEM2.</param>
/// <returns>Pointer to allocated memory.</returns>
PVOID ArcMemAllocDirect(size_t length, bool InDDR) {
	return ArcMemAllocChunk(length, MemoryFirmwarePermanent, InDDR);
}

static inline ARC_FORCEINLINE ULONG MegabytesInPages(ULONG Size) {
	return Size * ((1024 * 1024) / PAGE_SIZE);
}

/// <summary>
/// Initialise the default memory descriptors so ArcMemAllocDirect can work.
/// </summary>
int ArcMemInitDescriptors(PHW_DESCRIPTION HwDesc) {

	// The loader allocated XFB at end of MEM1, and 64KB GX FIFO before that.
	// So use GX FIFO base as "MEM1 size".

	ULONG PageCount = HwDesc->GxFifoBase / PAGE_SIZE;
	ULONG BasePage = 0;
	// First chunk: exception block
	INIT_DESCRIPTOR(0, BasePage, 4, MemoryExceptionBlock);
	PageCount -= 4;
	// Second chunk: ARC system table (4 pages)
	INIT_DESCRIPTOR(1, BasePage, 4, MemoryFirmwarePermanent);
	PageCount -= 4;
	// Third chunk: up to 8MB as free, as NT prior to (somewhere between 1234 and 1314) only maps that much by a BAT.
	if ((BasePage + PageCount) < MegabytesInPages(8)) {
		return -1;
	}
	else {
		ULONG PagesFree = MegabytesInPages(8) - BasePage;
		INIT_DESCRIPTOR(2, BasePage, PagesFree, MemoryFree);
		PageCount -= PagesFree;
	}

	// Fourth chunk: ARC firmware stack, up to wherever we start at
	extern BYTE __executable_start[], _end[];
	ULONG ExeBase = ((ULONG)&__executable_start[0]) - 0x80000000;
	ULONG ExeLength = ((ULONG)&_end[0]) - 0x80000000 - ExeBase;
	ExeBase /= PAGE_SIZE;
	if ((ExeLength & (PAGE_SIZE - 1)) != 0) ExeLength += PAGE_SIZE;
	ExeLength /= PAGE_SIZE;
	PageCount -= (ExeBase - BasePage);
	INIT_DESCRIPTOR(3, BasePage, ExeBase - BasePage, MemoryFirmwareTemporary);

	// Fifth chunk: ARC firmware itself.
	// This implementation does not hook the kernel (only slight patching to fix MSR stuff in bootloader/kernel)
	// Thus, mark as firmware temporary as, for example, Motorola's implementation does.
	INIT_DESCRIPTOR(4, BasePage, ExeLength, MemoryFirmwareTemporary);
	PageCount -= ExeLength;

	// Sixth chunk: the rest of MEM1
	s_BootMemPages = BasePage + PageCount;
	INIT_DESCRIPTOR(5, BasePage, PageCount, MemoryFree);

	// Seventh chunk: GX FIFO
	PageCount = (HwDesc->FrameBufferBase - HwDesc->GxFifoBase) / PAGE_SIZE;
	INIT_DESCRIPTOR(6, BasePage, PageCount, MemoryFirmwarePermanent);

	// Eighth chunk: XFB
	PageCount = (HwDesc->MemoryLength[0] - HwDesc->FrameBufferBase) / PAGE_SIZE;
	INIT_DESCRIPTOR(7, BasePage, PageCount, MemoryFirmwarePermanent);

	// If this is DOL there's no more memory
	if (HwDesc->MemoryLength[1] == 0) return 0;

	// Ninth chunk: MEM2 (DDR).
	// First 1MB marked as firmware permanent, this is used by SDMC and USB drivers which require addresses inside DDR.
	BasePage = 0x10000000 / PAGE_SIZE;
	PageCount = (0x100000 / PAGE_SIZE);
	INIT_DESCRIPTOR(8, BasePage, PageCount, MemoryFirmwarePermanent);
	// Tenth chunk: DDR memory as far as the IOS IPC buffer marked as free (for now)
	PageCount = (HwDesc->DdrIpcBase - 0x10100000) / PAGE_SIZE;
	INIT_DESCRIPTOR(9, BasePage, PageCount, MemoryFree);

	// Eleventh chunk: IOS IPC buffer (firmware permanent)
	PageCount = (HwDesc->DdrIpcLength) / PAGE_SIZE;
	INIT_DESCRIPTOR(10, BasePage, PageCount, MemoryFirmwarePermanent);

	// If this is RVL there's no more memory
	ULONG DdrIpcEndOff = (HwDesc->DdrIpcBase + HwDesc->DdrIpcLength) - 0x10000000;
	if (DdrIpcEndOff == HwDesc->MemoryLength[1]) return 0;
	
	// Twelfth chunk: up to 64MB-aligned value as firmware permanent (IOS might use this memory)
	ULONG IosEndOff = (DdrIpcEndOff / 0x4000000);
	if ((DdrIpcEndOff % 0x4000000) != 0) IosEndOff++;
	IosEndOff *= 0x4000000;
	PageCount = ((0x10000000 + IosEndOff) / PAGE_SIZE) - BasePage;
	INIT_DESCRIPTOR(11, BasePage, PageCount, MemoryFirmwarePermanent);

	// Twelfth chunk: rest of RAM as firmware temporary
	PageCount = ((0x10000000 + HwDesc->MemoryLength[1]) / PAGE_SIZE) - BasePage;
	INIT_DESCRIPTOR(12, BasePage, PageCount, MemoryFirmwareTemporary);

	// All done.
	return 0;
}

void ArcMemInit(void) {
	// Initialise the functions implemented here.
	PVENDOR_VECTOR_TABLE Api = ARC_VENDOR_VECTORS();
	Api->MemoryRoutine = ArcMemory;
	Api->FlushAllCachesRoutine = ArcFlushAllCaches;
}
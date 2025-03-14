#include <stdlib.h>
#include "types.h"
#include "arc.h"
#include "pxiheap.h"

#include <stdio.h>

typedef struct _PXI_HEAP_CHUNK {
	ULONG Status;
	ULONG Size;
	struct _PXI_HEAP_CHUNK
		*Previous, *Next;
} PXI_HEAP_CHUNK, *PPXI_HEAP_CHUNK;

typedef struct _PXI_HEAP {
	PVOID Base;
	ULONG Size;
	PPXI_HEAP_CHUNK FreeList;
} PXI_HEAP, * PPXI_HEAP;

typedef enum {
	CHUNK_FREE,
	CHUNK_USED,
	CHUNK_ALIGNED
} PXI_HEAP_CHUNK_STATUS;

enum {
	CACHE_ALIGN_SIZE = 32,
	CACHE_ALIGN_MASK = CACHE_ALIGN_SIZE - 1
};

static bool PhCreate(PPXI_HEAP Heap, PVOID Ptr, ULONG Size);
static void PhDelete(PPXI_HEAP Heap);
static PVOID PhAlloc(PPXI_HEAP Heap, ULONG Size);
static PVOID PhAllocAligned(PPXI_HEAP Heap, ULONG Size, ULONG Alignment);
static void PhFree(PPXI_HEAP Heap, PVOID Ptr);

static inline bool PhpChunkInHeap(PPXI_HEAP Heap, PPXI_HEAP_CHUNK Chunk) {
	return (Chunk >= Heap->Base && (ULONG)Chunk < ((ULONG)Heap->Base + Heap->Size));
}

static void PhpCombineChunks(PPXI_HEAP_CHUNK Chunk) {
	if (Chunk == NULL) return;
	ULONG NextFree = (ULONG)Chunk->Next;
	if (NextFree != ((ULONG)Chunk + Chunk->Size + sizeof(*Chunk))) return;

	PPXI_HEAP_CHUNK Next = Chunk->Next;
	Chunk->Next = Next->Next;
	if (Chunk->Next != NULL) {
		Chunk->Next->Previous = Chunk;
	}
	Chunk->Size += Next->Size + sizeof(*Next);
}

static bool PhCreate(PPXI_HEAP Heap, PVOID Ptr, ULONG Size) {
	if (((ULONG)Ptr & CACHE_ALIGN_MASK) != 0) return false;

	Heap->Base = Ptr;
	Heap->Size = Size;
	Heap->FreeList = (PPXI_HEAP_CHUNK)Ptr;
	Heap->FreeList->Status = CHUNK_FREE;
	Heap->FreeList->Size = Size - sizeof(PXI_HEAP_CHUNK);
	Heap->FreeList->Previous = Heap->FreeList->Next = NULL;

	return true;
}

static void PhDelete(PPXI_HEAP Heap) {
	if (Heap == NULL) return;

	Heap->Base = NULL;
	Heap->Size = 0;
	Heap->FreeList = NULL;

}

static inline PPXI_HEAP_CHUNK PhpGetChunk(PVOID Ptr) {
	return (PPXI_HEAP_CHUNK)(
		(ULONG)Ptr - sizeof(PXI_HEAP_CHUNK)
		);
}

static inline void PhpEnsureChunkLinkInHeap(PPXI_HEAP Heap, PPXI_HEAP_CHUNK Chunk, PPXI_HEAP_CHUNK Link) {
	if (!PhpChunkInHeap(Heap, Link)) {
		while (1);
	}
}

static PVOID PhpAllocLocked(PPXI_HEAP Heap, ULONG Size, ULONG Alignment) {
	if (Size == 0) Size = 1;
	if (Alignment == 0) return NULL;
	if (Alignment < CACHE_ALIGN_SIZE) Alignment = CACHE_ALIGN_SIZE;
	ULONG AlignMask = Alignment - 1;
	if ((Alignment & AlignMask) != 0) {
		Alignment = 1 << (32 - __builtin_clz(Alignment - 1));
		AlignMask = Alignment - 1;
	}

	// Align Size to a cache line.
	Size = (Size + CACHE_ALIGN_MASK) & ~CACHE_ALIGN_MASK;

	// Search the free list.
	PPXI_HEAP_CHUNK BestFit = NULL;
	for (PPXI_HEAP_CHUNK Chunk = Heap->FreeList; Chunk != NULL; Chunk = Chunk->Next) {
		ULONG Body = (ULONG)Chunk + sizeof(*Chunk);
		ULONG Extra = (Alignment - (Body & AlignMask)) & AlignMask;
		if (Extra == 0 && Chunk->Size == Size) {
			BestFit = Chunk;
			break;
		}
		ULONG Total = Size + Extra;
		if (Chunk->Size >= Total) {
			if (BestFit == NULL || Chunk->Size < BestFit->Size) {
				BestFit = Chunk;
				continue;
			}
		}
	}

	if (BestFit == NULL) {
		return NULL;
	}

	// Found a chunk
	ULONG ChunkBody = (ULONG)BestFit + sizeof(*BestFit);
	ULONG Extra = (Alignment - (ChunkBody & AlignMask)) & AlignMask;

	// Split the chunk if size is larger than what is wanted
	ULONG WantedSize = Size + Extra + sizeof(*BestFit);
	if (BestFit->Size > WantedSize) {
		PPXI_HEAP_CHUNK New = (PPXI_HEAP_CHUNK)(
			(PUCHAR)BestFit + WantedSize
			);
		New->Status = CHUNK_FREE;
		New->Size = BestFit->Size - WantedSize;
		New->Next = BestFit->Next;
		if (New->Next != NULL) {
			New->Next->Previous = New;
		}
		BestFit->Next = New;
		BestFit->Size = Size + Extra;
	}

	BestFit->Status = CHUNK_USED;
	if (BestFit->Previous != NULL) {
		PhpEnsureChunkLinkInHeap(Heap, BestFit, BestFit->Previous);
		BestFit->Previous->Next = BestFit->Next;
	}
	else {
		Heap->FreeList = BestFit->Next;
	}

	if (BestFit->Next != NULL) {
		PhpEnsureChunkLinkInHeap(Heap, BestFit, BestFit->Next);
		BestFit->Next->Previous = BestFit->Previous;
	}
	BestFit->Previous = BestFit->Next = NULL;

	PVOID Body = (PUCHAR)BestFit + Extra + sizeof(*BestFit);

	if (Extra != 0) {
		PPXI_HEAP_CHUNK ExtraChunk = PhpGetChunk(Body);
		ExtraChunk->Status = CHUNK_ALIGNED;
		ExtraChunk->Previous = BestFit;
	}

	return Body;
}

static PVOID PhpAlloc(PPXI_HEAP Heap, ULONG Size, ULONG Alignment) {
	// Allocate the memory
	PVOID Buffer = PhpAllocLocked(Heap, Size, Alignment);

	// Return.
	return Buffer;
}

static void PhpFreeLocked(PPXI_HEAP Heap, PVOID Ptr) {
	// Check pointer is within heap bounds
	ULONG HeapStart = (ULONG)Heap->Base + sizeof(PXI_HEAP_CHUNK);
	ULONG HeapEnd = (ULONG)Heap->Base + Heap->Size;
	if ((ULONG)Ptr < HeapStart || (ULONG)Ptr > HeapEnd) return;

	// Grab the memchunk header
	PPXI_HEAP_CHUNK Chunk = PhpGetChunk(Ptr);

	// Ensure it's actually in use.
	if (Chunk->Status == CHUNK_ALIGNED) {
		Chunk = Chunk->Previous;
	}
	if (Chunk->Status != CHUNK_USED) return;

	Chunk->Status = CHUNK_FREE;

	// Find previous free chunk.
	PPXI_HEAP_CHUNK PreviousChunk = Heap->FreeList;
	for (; PreviousChunk != NULL; PreviousChunk = PreviousChunk->Next) {
		if (PreviousChunk->Next == NULL) break;
		if (PreviousChunk->Next > Chunk) break;
	}

	if (PreviousChunk != NULL && Chunk > PreviousChunk) {
		// Add chunk to free list
		Chunk->Previous = PreviousChunk;
		Chunk->Next = PreviousChunk->Next;
		PreviousChunk->Next = Chunk;
	}
	else {
		// Set Chunk as the first entry in the free list
		Chunk->Next = Heap->FreeList;
		Heap->FreeList = Chunk;
		Chunk->Previous = NULL;
	}

	if (Chunk->Next != NULL) {
		PhpEnsureChunkLinkInHeap(Heap, Chunk, Chunk->Next);
		Chunk->Next->Previous = Chunk;
	}

	// Combine any chunks that can be combined.
	PhpCombineChunks(Chunk);
	PhpCombineChunks(Chunk->Previous);
}

static PVOID PhAlloc(PPXI_HEAP Heap, ULONG Size) {
	return PhpAlloc(Heap, Size, CACHE_ALIGN_SIZE);
}

static PVOID PhAllocAligned(PPXI_HEAP Heap, ULONG Size, ULONG Alignment) {
	return PhpAlloc(Heap, Size, Alignment);
}

static void PhFree(PPXI_HEAP Heap, PVOID Ptr) {
	// Free the memory
	PhpFreeLocked(Heap, Ptr);
}


static PXI_HEAP s_PxiHeap;

bool PxiHeapInit(ULONG PhysAddr, ULONG Size) {
	return PhCreate(&s_PxiHeap, MEM_PHYSICAL_TO_K1(PhysAddr), Size);
}

PVOID PxiIopAlloc(ULONG Size) {
	return PhAlloc(&s_PxiHeap, Size);
}

PVOID PxiIopAllocAligned(ULONG Size, ULONG Alignment) {
	return PhAllocAligned(&s_PxiHeap, Size, Alignment);
}

void PxiIopFree(PVOID Ptr) {
	return PhFree(&s_PxiHeap, Ptr);
}
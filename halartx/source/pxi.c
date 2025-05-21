// PXI stuff.
#include "halp.h"
#include "pxi_regs.h"
#include "ios.h"
#include "ints.h"
#include "pxiheap.h"

#include <stdio.h>

PPXI_REGISTERS HalpPxiRegisters = NULL;
ULONG HalpPxiBufferPhys = 0;
PVOID HalpPxiBuffer = NULL;
PVOID HalpPxiBufferEnd = NULL;
ULONG HalpPxiLength = 0;

static KINTERRUPT s_PxiInterrupt;
static PXI_HEAP s_HalpPxiHeap;
static KEVENT s_IpcSendReadyEvent;
static KEVENT s_IpcSendPrepareEvent;

enum {
	IPC_REQUEST_COUNT = 16
};

typedef struct _IOS_IPC_REQUEST_ENTRY
	IOS_IPC_REQUEST_ENTRY, *PIOS_IPC_REQUEST_ENTRY;

struct _IOS_IPC_REQUEST_ENTRY {
	LIST_ENTRY ListEntry;
	PIOS_IPC_REQUEST Request;
	IOS_IPC_SYNC IpcSync;
};

static LIST_ENTRY s_IpcRequestPendingList;
static KSPIN_LOCK s_IpcRequestPendingSpinLock;
static KSPIN_LOCK s_IpcMemorySpinLock;

//static ULONG s_CurrentRequest = 0;
static LONG s_NumberOfRequestsToAck = 0;

static KDPC
	s_DpcRequestAck[IPC_REQUEST_COUNT],
	s_DpcResponseSent[IPC_REQUEST_COUNT];
	
static KIRQL PxipAcquireSpinLock(PKSPIN_LOCK SpinLock) {
	KIRQL CurrentIrql = KeGetCurrentIrql();
	if (CurrentIrql < DISPATCH_LEVEL) KeRaiseIrql(DISPATCH_LEVEL, &CurrentIrql);
	KiAcquireSpinLock(SpinLock);
	return CurrentIrql;
}

static void PxipReleaseSpinLock(PKSPIN_LOCK SpinLock, KIRQL OldIrql) {
	KiReleaseSpinLock(SpinLock);
	if (OldIrql < DISPATCH_LEVEL) KeLowerIrql(OldIrql);
}

static void HalpPxiAddRequest(PIOS_IPC_REQUEST_ENTRY Entry) {
	KIRQL OldIrql = PxipAcquireSpinLock(&s_IpcRequestPendingSpinLock);
	InsertHeadList(&s_IpcRequestPendingList, &Entry->ListEntry);
	PxipReleaseSpinLock(&s_IpcRequestPendingSpinLock, OldIrql);
}

static void HalpPxiRemoveRequest(PIOS_IPC_REQUEST_ENTRY Entry) {
	RemoveEntryList(&Entry->ListEntry);
}

static PVOID HalpPxiPhysToVirt(ULONG PhysAddr) {
	if (PhysAddr < HalpPxiBufferPhys) return NULL;
	if (PhysAddr >= HalpPxiBufferPhys + HalpPxiLength) return NULL;
	return (PVOID)(PhysAddr - HalpPxiBufferPhys + (ULONG)HalpPxiBuffer);
}

static ULONG HalpPxiVirtToPhys(PVOID VirtAddr) {
	if (VirtAddr < HalpPxiBuffer) return 0;
	if (VirtAddr >= HalpPxiBufferEnd) return 0;
	return (ULONG)VirtAddr - (ULONG)HalpPxiBuffer + HalpPxiBufferPhys;
}

static BOOLEAN HalpPxiInterrupt(PKINTERRUPT InterruptRoutine, PVOID ServiceContext, PVOID TrapFrame) {
	BOOLEAN IntAcked = FALSE;
	PXI_CONTROL Control = PXI_CONTROL_READ();
	if ((Control & PXI_REQ_ACK) != 0) {
		// IOP acked our request.
		// Clear the ack.
		PXI_CONTROL_SET(PXI_REQ_ACK);
		// Clear the Vegas interrupt.
		VEGAS_INTERRUPT_CLEAR( VEGAS_INTERRUPT_PXI );
		IntAcked = TRUE;
		
		// Fire off the DPC, to raise the event to allow another request to be sent off.
		// BUGBUG: Dolphin doesn't allow reads to PXI request register.
		// (this is incorrect behaviour but of course I'm the first to rely on that...)
		// Request ack DPC doesn't use the provided ptr anyway...
		/*
		PVOID Request = HalpPxiPhysToVirt(PXI_REQUEST_READ());
		if (Request != NULL) {
			KeInsertQueueDpc(&s_DpcRequestAck, Request, NULL);
		}
		*/
		
		// Queue the first unused DPC.
		BOOLEAN AlreadyQueued = FALSE;
		for (ULONG i = 0; i < IPC_REQUEST_COUNT; i++) {
			AlreadyQueued = KeInsertQueueDpc(&s_DpcRequestAck[i], NULL, NULL);
			if (AlreadyQueued) break;
		}
		if (!AlreadyQueued) {
			// Missed a PXI interrupt!
			KeBugCheckEx(NO_MORE_IRP_STACK_LOCATIONS, 0, 0, 0, 'HWD');
		}
	}
	if ((Control & PXI_RES_SENT) != 0) {
		// IOP responded.
		PVOID Response = HalpPxiPhysToVirt(PXI_RESPONSE_READ());
		if (Response != NULL) {
			// Queue the first unused DPC.
			BOOLEAN AlreadyQueued = FALSE;
			for (ULONG i = 0; i < IPC_REQUEST_COUNT; i++) {
				AlreadyQueued = KeInsertQueueDpc(&s_DpcResponseSent[i], Response, NULL);
				if (AlreadyQueued) break;
			}
			if (!AlreadyQueued) {
				// Missed a PXI interrupt!
				KeBugCheckEx(NO_MORE_IRP_STACK_LOCATIONS, 1, 0, 0, 'HWD');
			}
		}
		// Acknowledge the response and clear the interrupt.
		PXI_CONTROL_SET(PXI_RES_SENT);
		
		// Clear the Vegas interrupt.
		if (!IntAcked) VEGAS_INTERRUPT_CLEAR( VEGAS_INTERRUPT_PXI );
		IntAcked = TRUE;
		
		// Tell IOP we're done with the response pointer.
		PXI_CONTROL_SET(PXI_RES_ACK);
	}
	
	// Ensure the Vegas interrupt is cleared
	if (!IntAcked) VEGAS_INTERRUPT_CLEAR( VEGAS_INTERRUPT_PXI );
	return TRUE;
}

static NTSTATUS HalpIosErrorToNtStatus(int err) {
	// TODO: iosc / FS / ES errors?
	if (err == 0) return STATUS_SUCCESS;
	if (err > 0) {
		// If collision with existing status code would occur,
		// then just return STATUS_SUCCESS.
		if (err >= (0x40000000 - 0x1000)) return STATUS_SUCCESS;
		// Avoid collision with existing status code.
		// But this still counts as NT_SUCCESS.
		ULONG Status = 0x1000;
		Status += err;
		return (NTSTATUS)Status;
	}
	
	err = -err;
#define IOSERROR_DEFINE(ios,nt) if (err == (ios)) return (nt) ;
#include "ioserr.inc"
#undef IOSERROR_DEFINE
	// return STATUS_UNSUCCESSFUL;
	// instead of just returning unsuccessful;
	// return unused NTSTATUS (for this NT version),
	// with the IOS error encoded within
	ULONG Status = 0xC0100000UL;
	Status += err;
	return (NTSTATUS)Status;
}

static void HalpIpcSendOneRequestFromDpcLevel(PLIST_ENTRY SendList);

static void HalpPxiRequestAck(PKDPC Dpc, PVOID Unused, PVOID Request, PVOID Unused2) {
	KeAcquireSpinLockAtDpcLevel(&s_IpcRequestPendingSpinLock);
	// If there's pending async requests that were sent at DISPATCH_LEVEL,
	// send one of them now.
	if (!IsListEmpty(&s_IpcRequestPendingList)) {
		HalpIpcSendOneRequestFromDpcLevel(&s_IpcRequestPendingList);
	} else {
		KeReleaseSpinLockFromDpcLevel(&s_IpcRequestPendingSpinLock);
		// Raise the event, to allow another IPC request to be sent off.
		KeSetEvent(&s_IpcSendReadyEvent, (KPRIORITY)0, FALSE);
	}
	// Raise the event to try and get a thread to allocate memory again.
	KeSetEvent(&s_IpcSendPrepareEvent, (KPRIORITY)0, FALSE);
}

// Allocate a request.
static PIOS_IPC_REQUEST HalpIpcAlloc(void) {
	KIRQL OldIrql = PxipAcquireSpinLock(&s_IpcMemorySpinLock);
	PIOS_IPC_REQUEST Request = PhAlloc( &s_HalpPxiHeap, sizeof(IOS_IPC_REQUEST) );
	PxipReleaseSpinLock(&s_IpcMemorySpinLock, OldIrql);
	if (Request == NULL) {
		return NULL;
	}
	RtlZeroMemory(Request, sizeof(*Request));
	return Request;
}

// Free a request.
static void HalpIpcFree(PIOS_IPC_REQUEST Request) {
	KIRQL OldIrql = PxipAcquireSpinLock(&s_IpcMemorySpinLock);
	PhFree( &s_HalpPxiHeap, Request);
	PxipReleaseSpinLock(&s_IpcMemorySpinLock, OldIrql);
}

// Allocate some buffers.
static PIOS_IPC_BUFFER HalpIpcBufferAlloc(PIOS_IPC_REQUEST Request, ULONG Count) {
	if (Request->Flags & IPC_FLAG_STATIC) {
		if (Count > 8) return NULL;
		PIOS_IPC_REQUEST_STATIC RequestStatic = (PIOS_IPC_REQUEST_STATIC) Request;
		return RequestStatic->Ioctlv;
	}
	ULONG Size = Count * sizeof(IOS_IPC_BUFFER);
	KIRQL OldIrql = PxipAcquireSpinLock(&s_IpcMemorySpinLock);
	PIOS_IPC_BUFFER Buffers = PhAlloc( &s_HalpPxiHeap, Size );
	PxipReleaseSpinLock(&s_IpcMemorySpinLock, OldIrql);
	if (Buffers == NULL) {
		return NULL;
	}
	// Don't zero the memory, the entire size will be written to.
	return Buffers;
}

// Free some buffers.
static void HalpIpcBufferFreeVirt(PIOS_IPC_REQUEST Request, PVOID Addr) {
	if (Request->Flags & IPC_FLAG_STATIC) return;
	KIRQL OldIrql = PxipAcquireSpinLock(&s_IpcMemorySpinLock);
	PhFree( &s_HalpPxiHeap, Addr );
	PxipReleaseSpinLock(&s_IpcMemorySpinLock, OldIrql);
}

static void HalpIpcBufferFree(PIOS_IPC_REQUEST Request, ULONG PhysAddr) {
	if (Request->Flags & IPC_FLAG_STATIC) return;
	PVOID Addr = HalpPxiPhysToVirt(PhysAddr);
	if (Addr == NULL) return; // leaks some memory but what else can be done here?
	KIRQL OldIrql = PxipAcquireSpinLock(&s_IpcMemorySpinLock);
	PhFree( &s_HalpPxiHeap, Addr );
	PxipReleaseSpinLock(&s_IpcMemorySpinLock, OldIrql);
}

void HalpInvalidateDcacheRange(PVOID Start, ULONG Length);

// Endianness swapping functionality.
// Swap64 where length is 64 bits aligned, and dest+src are 32 bits aligned
static void HalpEndianSwap64(void* dest, const void* src, ULONG len) {
	const ULONG* src32 = (const ULONG*)src;
	ULONG* dest32 = (ULONG*)dest;
	for (ULONG i = 0; i < len; i += sizeof(ULONG) * 2) {
		ULONG idx = i / sizeof(ULONG);
		ULONG buf0 = __builtin_bswap32(src32[idx + 0]);
		dest32[idx + 0] = __builtin_bswap32(src32[idx + 1]);
		dest32[idx + 1] = buf0;
	}
}

static void HalpEndianSwapInPlace64(void* buffer, ULONG len) {
	HalpEndianSwap64(buffer, buffer, len);
}

static void HalpPxiResponseSent(PKDPC Dpc, PVOID Unused, PVOID Response, PVOID Unused2) {
	if (Response == NULL) {
		return;
	}
	// got an IPC response.
	// Response should point to a msg that we sent.
	
	// Invalidate the dcache of all buffers that were passed in the request.
	// IPC buffer is mapped uncached, otherwise weird cache things happen and flushing dcache in the "correct" places isn't fixing them.
	
	PIOS_IPC_REQUEST Req = (PIOS_IPC_REQUEST)Response;
	//HalpInvalidateDcacheRange( &Req->Ipc, sizeof(Req->Ipc) );
	
	ULONG Count;
	PIOS_IOCTL_VECTOR Buffers;
	
	switch (Req->Ipc.ReqOp) {
		case IOS_OPEN:
			// Set the returned IOS handle.
			if (Req->Handle != NULL && Req->Status != NULL) {
				if (Req->Ipc.Result >= 0) Req->Handle[0] = (IOS_HANDLE) Req->Ipc.Result;
				else Req->Handle[0] = 0xFFFFFFFF;
			}
			break;
		case IOS_WRITE:
			// Set the returned number of bytes transferred.
			if (Req->NumberOfBytesTransferred != NULL && Req->Status != NULL) {
				if (Req->Ipc.Result >= 0) Req->NumberOfBytesTransferred[0] = (ULONG)Req->Ipc.Result;
				else Req->NumberOfBytesTransferred[0] = 0;
			}
			if ((Req->SwapModeOutput & RW_SWAP_OUTPUT) != 0) {
				// Invalidate dcache for the buffer and swap it in place.
				HalpInvalidateDcacheRange((PVOID)Req->IpcVirt.Args.Write.Pointer, Req->IpcVirt.Args.Write.Length);
				HalpEndianSwapInPlace64((PVOID)Req->IpcVirt.Args.Write.Pointer, Req->IpcVirt.Args.Write.Length);
			}
			break;
		case IOS_READ:
			// Set the returned number of bytes transferred.
			if (Req->NumberOfBytesTransferred != NULL && Req->Status != NULL) {
				if (Req->Ipc.Result >= 0) Req->NumberOfBytesTransferred[0] = (ULONG)Req->Ipc.Result;
				else Req->NumberOfBytesTransferred[0] = 0;
			}
			HalpInvalidateDcacheRange((PVOID)Req->IpcVirt.Args.Read.Pointer, Req->IpcVirt.Args.Read.Length);
			if ((Req->SwapModeOutput & RW_SWAP_OUTPUT) != 0) {
				// Swap the buffer in place.
				HalpEndianSwapInPlace64((PVOID)Req->IpcVirt.Args.Write.Pointer, Req->IpcVirt.Args.Write.Length);
			}
			break;
		case IOS_SEEK:
			// Set the returned file offset.
			if (Req->FileOffset != NULL && Req->Status != NULL) {
				if (Req->Ipc.Result >= 0) Req->FileOffset[0] = (ULONG)Req->Ipc.Result;
				else Req->FileOffset[0] = 0xFFFFFFFF;
			}
			break;
		case IOS_IOCTL:
			if (Req->IpcVirt.Args.Ioctl.Input.Pointer != 0) {
				HalpInvalidateDcacheRange((PVOID)Req->IpcVirt.Args.Ioctl.Input.Pointer, Req->IpcVirt.Args.Ioctl.Input.Length);
				if ((Req->SwapModeOutput & IOCTL_SWAP_INPUT) != 0) {
					HalpEndianSwapInPlace64((PVOID)Req->IpcVirt.Args.Ioctl.Input.Pointer, Req->IpcVirt.Args.Ioctl.Input.Length);
				}
			}
			if (Req->IpcVirt.Args.Ioctl.Output.Pointer != 0) {
				HalpInvalidateDcacheRange((PVOID)Req->IpcVirt.Args.Ioctl.Output.Pointer, Req->IpcVirt.Args.Ioctl.Output.Length);
				if ((Req->SwapModeOutput & IOCTL_SWAP_OUTPUT) != 0) {
					HalpEndianSwapInPlace64((PVOID)Req->IpcVirt.Args.Ioctl.Output.Pointer, Req->IpcVirt.Args.Ioctl.Output.Length);
				}
			}
			break;
		case IOS_IOCTLV:
			Count = Req->Ipc.Args.Ioctlv.NumRead + Req->Ipc.Args.Ioctlv.NumWritten;
			Buffers = (PIOS_IOCTL_VECTOR) Req->IpcVirt.Args.Ioctlv.Buffers;
			HalpInvalidateDcacheRange(Buffers, sizeof(IOS_IOCTL_VECTOR) * Count);
			for (ULONG i = 0; i < Count; i++) {
				if (Buffers[i].Pointer != NULL) {
					HalpInvalidateDcacheRange(Buffers[i].Pointer, Buffers[i].Length);
					if ((Req->SwapModeOutput & BIT(i)) != 0) {
						HalpEndianSwapInPlace64(Buffers[i].Pointer, Buffers[i].Length);
					}
				}
			}
			// Free the buffer used to provide vector physical addresses.
			HalpIpcBufferFree( Req, Req->Ipc.Args.Ioctlv.Buffers );
			break;
	}
	
	if ((Req->Flags & IPC_FLAG_CALLBACK) == 0) {
		// This is a sync or non-DPC async request.
		// Set the status code.
		Req->Status[0] = HalpIosErrorToNtStatus(Req->Ipc.Result);
		// Raise the event.
		KeSetEvent(Req->Event, (KPRIORITY) 0, FALSE);
		// Free the request.
		HalpIpcFree(Req);
	} else {
		// This is a DPC async request.
		// Get the callback.
		IOP_CALLBACK Callback = Req->Callback;
		// Get the result.
		ULONG Result = Req->Ipc.Result;
		// Get the context.
		PVOID Context = Req->Context;
		// Free the request.
		// The callback will probably try to make another IPC request,
		// so guarantee that there's enough space for it.
		HalpIpcFree(Req);
		// Call the callback.
		Callback( HalpIosErrorToNtStatus(Result), Result, Context);
	}
}

// Initialises a request to send.
static NTSTATUS HalpIpcPrepareSendRequest(PIOS_IPC_REQUEST Request, PIOS_IPC_REQUEST_ENTRY* PendingRequest, PIOS_IPC_SYNC* SynchronousOperation) {
	// Ensure the request is within the correct bounds.
	if ((PVOID)Request < HalpPxiBuffer) return STATUS_INVALID_PARAMETER;
	if ((PVOID)Request >= HalpPxiBufferEnd) return STATUS_INVALID_PARAMETER;
	// Ensure the non-IPC params look good.
	if (PendingRequest == NULL) return STATUS_INVALID_PARAMETER;
	// don't check Status, it can be NULL for a DPC async request.
	//if (SynchronousOperation == NULL && Request->Status == NULL) return STATUS_INVALID_PARAMETER;
	if (SynchronousOperation == NULL && Request->Event == NULL) return STATUS_INVALID_PARAMETER;
	// Allocate the request list entry
	PIOS_IPC_REQUEST_ENTRY RequestEntry = ExAllocatePool(NonPagedPool, sizeof(IOS_IPC_REQUEST_ENTRY));
	if (RequestEntry == NULL) {
		KIRQL CurrentIrql = KeGetCurrentIrql();
		// For DISPATCH_LEVEL, return error, caller should wait and try again
		// Also return error for above DISPATCH_LEVEL although we should not be called there.
		if (CurrentIrql >= DISPATCH_LEVEL) return STATUS_INSUFFICIENT_RESOURCES;
		// For APC_LEVEL and above, wait for event and keep trying
		do {
			KeWaitForSingleObject( &s_IpcSendPrepareEvent, Executive, KernelMode, FALSE, NULL);
			RequestEntry = ExAllocatePool(NonPagedPool, sizeof(IOS_IPC_REQUEST_ENTRY));
		} while (RequestEntry == NULL);
	}
	// For a synchronous operation, initialise the kevent
	if (SynchronousOperation != NULL) {
		KeInitializeEvent(&RequestEntry->IpcSync.Event, NotificationEvent, FALSE);
		*SynchronousOperation = &RequestEntry->IpcSync;
		Request->Event = &RequestEntry->IpcSync.Event;
		Request->Status = &RequestEntry->IpcSync.Status;
		Request->Flags |= IPC_FLAG_SYNC;
	}
	// Flush the data out of the cache.
	HalSweepDcacheRange( &Request->Ipc, sizeof(Request->Ipc) );
	// Add it
	RequestEntry->Request = Request;
	*PendingRequest = RequestEntry;
	return STATUS_SUCCESS;
}

static void HalpIpcSendOneRequest(PIOS_IPC_REQUEST_ENTRY RequestEntry) {
	PIOS_IPC_REQUEST Request = RequestEntry->Request;
	// Raise irql whilst we hit the IPC registers
	KIRQL OldIrql = HalpRaiseDeviceIrql(VECTOR_VEGAS);
	
	do {
		// Get the offset of the request.
		ULONG RequestOffset = (ULONG)Request - (ULONG)HalpPxiBuffer;
		// Set the request physical address.
		PXI_REQUEST_WRITE(RequestOffset + HalpPxiBufferPhys);
		// Tell IOP we have a request for it.	
		PXI_CONTROL_SET(PXI_REQ_SEND);
	} while (FALSE);
	// Lower irql.
	KeLowerIrql(OldIrql);
	// Free the request entry if it's asynchronous
	if ((Request->Flags & IPC_FLAG_SYNC) == 0) {
		ExFreePool(RequestEntry);
	}
}

static void HalpIpcSendOneRequestFromDpcLevel(PLIST_ENTRY SendList) {
	// Grab the request to send.
	PIOS_IPC_REQUEST_ENTRY RequestEntry = (PIOS_IPC_REQUEST_ENTRY) SendList->Flink;
	
	PIOS_IPC_REQUEST Request = RequestEntry->Request;
	
	// Remove the request from the list
	HalpPxiRemoveRequest(RequestEntry);
	// Release the spinlock.
	KeReleaseSpinLockFromDpcLevel(&s_IpcRequestPendingSpinLock);
	// Send the request.
	HalpIpcSendOneRequest(RequestEntry);
}

// Sends a request.
static void HalpIpcSendRequest(PIOS_IPC_REQUEST_ENTRY RequestEntry) {
	// Check that there's a request to send.
	if (RequestEntry == NULL) return;
	
	// Grab the request to send.
	PIOS_IPC_REQUEST Request = RequestEntry->Request;
			
	// Ensure this request looks good.
	if (Request == NULL) return;
	
	// Flush dcache.
	//HalSweepDcacheRange(Request, sizeof(*Request));
	
	// Wait until IOP is ready to handle a new request.
	KIRQL CurrentIrql = KeGetCurrentIrql();
	#if 0
	if (CurrentIrql <= APC_LEVEL) {
		KeWaitForSingleObject( &s_IpcSendReadyEvent, Executive, KernelMode, FALSE, NULL);
	}
	else
	#endif
	if (CurrentIrql <= DISPATCH_LEVEL) {
		// at DISPATCH_LEVEL we can't wait on an object
		LARGE_INTEGER Timeout = {.QuadPart = 0};
		NTSTATUS Status = KeWaitForSingleObject( &s_IpcSendReadyEvent, Executive, KernelMode, FALSE, &Timeout);
		if (Status == STATUS_TIMEOUT) {
			// Add to the pending list.
			HalpPxiAddRequest(RequestEntry);
			return;
		}
	} else {
		// not sure what to do here?
		KeBugCheck(IRQL_NOT_LESS_OR_EQUAL);
	}
	
	// Only CPU 0 can touch the device registers.
	if (HALPCR->PhysicalProcessor != 0) {
		// Running on CPU other than CPU0.
		// Add to the pending list.
		HalpPxiAddRequest(RequestEntry);
		// Queue an ack DPC to CPU0, which will cause the pending request to be sent.
		BOOLEAN AlreadyQueued = FALSE;
		for (ULONG i = 0; i < IPC_REQUEST_COUNT; i++) {
			AlreadyQueued = KeInsertQueueDpc(&s_DpcRequestAck[i], NULL, NULL);
			if (AlreadyQueued) break;
		}
		if (!AlreadyQueued) KeBugCheckEx(NO_MORE_IRP_STACK_LOCATIONS, 0, 0, 0, 'HWD');
		return;
	}

	// Send a pending request.
	HalpIpcSendOneRequest(RequestEntry);
/*
	// Raise irql to DIRQL so we don't get interrupted by anything.
	KIRQL OldIrql = HalpRaiseDeviceIrql(VECTOR_VEGAS);
	// Increment the send count.
	if (InterlockedIncrement(&s_IpcDpcSendCount) <= 1) {
		// Queue the DPC. If it's already queued, this will do nothing.
		KeInsertQueueDpc(&s_DpcSendRequests, NULL, NULL);
	}
	// Lower irql.
	KeLowerIrql(OldIrql);
*/
}

static NTSTATUS HalpPxiNewRequestImpl(IOS_OPERATION Op, IOS_HANDLE Handle, NTSTATUS* Status, PRKEVENT Event, PIOS_IPC_REQUEST* AllocatedRequest) {
	if (AllocatedRequest == NULL) return STATUS_INVALID_PARAMETER;
	
	PIOS_IPC_REQUEST Request = HalpIpcAlloc();
	if (Request == NULL) return STATUS_INSUFFICIENT_RESOURCES;
	
	Request->IpcVirt.Result = 0;
	Request->IpcVirt.Operation = Op;
	Request->IpcVirt.Handle = Handle;
	Request->Status = Status;
	Request->Event = Event;
	Request->Flags = Request->SwapModeInput = Request->SwapModeOutput = 0;
	
	*AllocatedRequest = Request;
	return STATUS_SUCCESS;
}

static NTSTATUS HalpPxiNewRequestAsync(IOS_OPERATION Op, IOS_HANDLE Handle, PVOID Status, PVOID Event, PIOS_IPC_REQUEST* AllocatedRequest) {
	if (Status == NULL || Event == NULL) return STATUS_INVALID_PARAMETER;
	return HalpPxiNewRequestImpl(Op, Handle, (NTSTATUS*)Status, (PRKEVENT)Event, AllocatedRequest);
}

static NTSTATUS HalpPxiNewRequestDpc(IOS_OPERATION Op, IOS_HANDLE Handle, PVOID Callback, PIOS_IPC_REQUEST* AllocatedRequest) {
	if (Callback == NULL) return STATUS_INVALID_PARAMETER;
	NTSTATUS Status = HalpPxiNewRequestImpl(Op, Handle, NULL, (PRKEVENT)Callback, AllocatedRequest);
	if (NT_SUCCESS(Status)) {
		AllocatedRequest[0]->Flags |= IPC_FLAG_CALLBACK;
	}
	return Status;
}

static NTSTATUS HalpPxiNewRequestSync(IOS_OPERATION Op, IOS_HANDLE Handle, PIOS_IPC_REQUEST* AllocatedRequest) {
	return HalpPxiNewRequestImpl(Op, Handle, NULL, NULL, AllocatedRequest);
}

static NTSTATUS HalpPxiNewRequest(IOS_OPERATION Op, IOS_HANDLE Handle, PVOID Status, PVOID EventOrCallback, PIOS_IPC_REQUEST* AllocatedRequest) {
	if (Status == NULL && EventOrCallback == NULL) {
		return HalpPxiNewRequestSync(Op, Handle, AllocatedRequest);
	}
	if (Status == NULL) {
		return HalpPxiNewRequestDpc(Op, Handle, EventOrCallback, AllocatedRequest);
	}
	return HalpPxiNewRequestAsync(Op, Handle, Status, EventOrCallback, AllocatedRequest);
}

static NTSTATUS HalpPxiWaitForRequest(PIOS_IPC_SYNC Sync) {
	// Wait for the request to complete.
	KeWaitForSingleObject( &Sync->Event, Executive, KernelMode, FALSE, NULL );
	// Return the status code.
	return Sync->Status;
}

static NTSTATUS HalpPxiPerformRequest(PIOS_IPC_REQUEST Request, BOOLEAN SynchronousRequest) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	do {
		// Prepare the request.
		PIOS_IPC_REQUEST_ENTRY RequestEntry = NULL;
		PIOS_IPC_SYNC Sync;
		Status = HalpIpcPrepareSendRequest(Request, &RequestEntry, SynchronousRequest != FALSE ? &Sync : NULL);
		if (!NT_SUCCESS(Status)) break;
		IOS_HANDLE* pHandle = Request->Handle;
		HalpIpcSendRequest(RequestEntry);
		if (SynchronousRequest == FALSE) {
			return STATUS_SUCCESS;
		}
		// Wait for the request.
		Status = HalpPxiWaitForRequest(Sync);
		// Free the request entry.
		ExFreePool(RequestEntry);
		// Return the status from the synchronous request.
		return Status;
	} while (FALSE);
	// Free the request buffer.
	HalpIpcFree(Request);
	return Status;
}

PVOID HalIopAlloc(ULONG Size) {
	if (HalpPxiRegisters == NULL) return NULL;
	
	KIRQL OldIrql = PxipAcquireSpinLock(&s_IpcMemorySpinLock);
	PVOID Buffer = PhAlloc( &s_HalpPxiHeap, Size );
	PxipReleaseSpinLock(&s_IpcMemorySpinLock, OldIrql);
	if (Buffer == NULL) {
		return NULL;
	}
	return Buffer;
}

void HalIopFree(PVOID Buffer) {
	if (HalpPxiRegisters == NULL) return;
	KIRQL OldIrql = PxipAcquireSpinLock(&s_IpcMemorySpinLock);
	PhFree( &s_HalpPxiHeap, Buffer );
	PxipReleaseSpinLock(&s_IpcMemorySpinLock, OldIrql);
}

static BOOLEAN HalpIopBufferAlignedForSwap(ULONG PhysAddr, ULONG Length) {
	// If physical address is inside PXI RAM, then caller got a 256-bit aligned buffer so ignore the alignment requirements.
	if (HalpPxiPhysToVirt(PhysAddr) != NULL && HalpPxiPhysToVirt(PhysAddr + Length - 1) != NULL) return TRUE;
	// If both physical address and length are correctly aligned, ORing them together will produce a value with correct alignment.
	// Otherwise, if either or both are misaligned, then ORing them together will produce a value with incorrect alignment.
	return ((PhysAddr | Length) & 7) == 0;
}

static void HalpIopOpenInit(PIOS_IPC_REQUEST Request, const char * Path, IOS_OPEN_MODE Mode, ULONG PathPhys) {
	// Initialise the arguments.
	Request->IpcVirt.Args.Open.Name = (ULONG)Path;
	Request->IpcVirt.Args.Open.Mode = Mode;
	// Convert from virtual to physical.
	RtlCopyMemory(&Request->Ipc, &Request->IpcVirt, sizeof(Request->Ipc));
	Request->Ipc.Args.Open.Name = PathPhys;
	HalSweepDcacheRange((PVOID)Path, strlen(Path) + 1);
}

static NTSTATUS HalpIopOpen(const char * Path, IOS_OPEN_MODE Mode, PVOID ContextOrRet, PVOID Async1, PVOID Async2) {
	if (HalpPxiRegisters == NULL) return STATUS_DEVICE_DOES_NOT_EXIST;
	if (ContextOrRet == NULL) return STATUS_INVALID_PARAMETER;
	if (Path == NULL) return STATUS_INVALID_PARAMETER;
	// Get the physical address for the provided pointer.
	PHYSICAL_ADDRESS PathPhys = MmGetPhysicalAddress((PVOID)Path);
	if (PathPhys.LowPart == 0) return STATUS_INVALID_PARAMETER;
	// Create the request.
	PIOS_IPC_REQUEST Request;
	NTSTATUS Status = HalpPxiNewRequest(IOS_OPEN, 0, Async1, Async2, &Request);
	if (!NT_SUCCESS(Status)) return Status;
	// Initialise the arguments.
	Request->Context = ContextOrRet;
	HalpIopOpenInit(Request, Path, Mode, PathPhys.LowPart);
	// Perform the request.
	return HalpPxiPerformRequest(Request, Async1 == NULL && Async2 == NULL);
}

NTSTATUS HalIopOpen(const char * Path, IOS_OPEN_MODE Mode, IOS_HANDLE* Handle) {
	return HalpIopOpen(Path, Mode, Handle, NULL, NULL);
}

NTSTATUS HalIopOpenAsync(const char * Path, IOS_OPEN_MODE Mode, IOS_HANDLE* Handle, NTSTATUS* pStatus, PRKEVENT Event) {
	if (pStatus == NULL || Event == NULL) return STATUS_INVALID_PARAMETER;
	return HalpIopOpen(Path, Mode, Handle, pStatus, Event);
}

NTSTATUS HalIopOpenAsyncDpc(const char * Path, IOS_OPEN_MODE Mode, IOP_CALLBACK Callback, PVOID Context) {
	if (Callback == NULL) return STATUS_INVALID_PARAMETER;
	return HalpIopOpen(Path, Mode, Context, NULL, Callback);
}

static NTSTATUS HalpIopClose(IOS_HANDLE Handle, PVOID Context, PVOID Async1, PVOID Async2) {
	if (HalpPxiRegisters == NULL) return STATUS_DEVICE_DOES_NOT_EXIST;
	// Create the request.
	PIOS_IPC_REQUEST Request;
	NTSTATUS Status = HalpPxiNewRequest(IOS_CLOSE, Handle, Async1, Async2, &Request);
	if (!NT_SUCCESS(Status)) return Status;
	// Convert from virtual to physical.
	Request->Context = Context;
	RtlCopyMemory(&Request->Ipc, &Request->IpcVirt, sizeof(Request->Ipc));
	// Perform the request.
	return HalpPxiPerformRequest(Request, Async1 == NULL && Async2 == NULL);
}

NTSTATUS HalIopClose(IOS_HANDLE Handle) {
	return HalpIopClose(Handle, NULL, NULL, NULL);
}

NTSTATUS HalIopCloseAsync(IOS_HANDLE Handle, NTSTATUS* pStatus, PRKEVENT Event) {
	if (pStatus == NULL || Event == NULL) return STATUS_INVALID_PARAMETER;
	return HalpIopClose(Handle, NULL, pStatus, Event);
}

NTSTATUS HalIopCloseAsyncDpc(IOS_HANDLE Handle, IOP_CALLBACK Callback, PVOID Context) {
	if (Callback == NULL) return STATUS_INVALID_PARAMETER;
	return HalpIopClose(Handle, Context, NULL, Callback);
}

static void HalpIopReadInit(PIOS_IPC_REQUEST Request, PVOID Buffer, ULONG Length, ULONG BufferPhys) {
	// Initialise the arguments.
	Request->IpcVirt.Args.Read.Pointer = (ULONG)Buffer;
	Request->IpcVirt.Args.Read.Length = Length;
	// Convert from virtual to physical.
	RtlCopyMemory(&Request->Ipc, &Request->IpcVirt, sizeof(Request->Ipc));
	Request->Ipc.Args.Read.Pointer = BufferPhys;
	HalpInvalidateDcacheRange((PVOID)Request->IpcVirt.Args.Read.Pointer, Request->IpcVirt.Args.Read.Length);
	// Assumption: read means IOS will never read from the buffer. So ignore the swapmode of input here.
}

static NTSTATUS HalpIopRead(IOS_HANDLE Handle, PVOID Buffer, ULONG Length, IOS_RW_MODE SwapMode, PVOID ContextOrRet, PVOID Async1, PVOID Async2) {
	if (HalpPxiRegisters == NULL) return STATUS_DEVICE_DOES_NOT_EXIST;
	if (Buffer == NULL) return STATUS_INVALID_PARAMETER;
	// Get the physical address for the provided pointer.
	PHYSICAL_ADDRESS BufferPhys = MmGetPhysicalAddress(Buffer);
	if (BufferPhys.LowPart == 0) return STATUS_INVALID_PARAMETER;
	// Ensure the alignment is valid for swapping if needed.
	if (SwapMode != 0 && !HalpIopBufferAlignedForSwap(BufferPhys.LowPart, Length)) return STATUS_INVALID_PARAMETER;
	// Create the request.
	PIOS_IPC_REQUEST Request;
	NTSTATUS Status = HalpPxiNewRequest(IOS_READ, Handle, Async1, Async2, &Request);
	if (!NT_SUCCESS(Status)) return Status;
	// Initialise the arguments.
	Request->Context = ContextOrRet;
	Request->SwapModeInput = Request->SwapModeOutput = SwapMode;
	HalpIopReadInit(Request, Buffer, Length, BufferPhys.LowPart);
	
	// Perform the request.
	return HalpPxiPerformRequest(Request, Async1 == NULL && Async2 == NULL);
}

NTSTATUS HalIopRead(IOS_HANDLE Handle, PVOID Buffer, ULONG Length, IOS_RW_MODE SwapMode, PULONG NumberOfBytesTransferred) {
	return HalpIopRead(Handle, Buffer, Length, SwapMode, NumberOfBytesTransferred, NULL, NULL);
}

NTSTATUS HalIopReadAsync(IOS_HANDLE Handle, PVOID Buffer, ULONG Length, IOS_RW_MODE SwapMode, PULONG NumberOfBytesTransferred, NTSTATUS* pStatus, PRKEVENT Event) {
	if (pStatus == NULL || Event == NULL) return STATUS_INVALID_PARAMETER;
 	return HalpIopRead(Handle, Buffer, Length, SwapMode, NumberOfBytesTransferred, pStatus, Event);
}

NTSTATUS HalIopReadAsyncDpc(IOS_HANDLE Handle, PVOID Buffer, ULONG Length, IOS_RW_MODE SwapMode, IOP_CALLBACK Callback, PVOID Context) {
	if (Callback == NULL) return STATUS_INVALID_PARAMETER;
	return HalpIopRead(Handle, Buffer, Length, SwapMode, Context, NULL, Callback);
}

static void HalpIopWriteInit(PIOS_IPC_REQUEST Request, PVOID Buffer, ULONG Length, ULONG BufferPhys) {
	// Initialise the arguments.
	Request->IpcVirt.Args.Write.Pointer = (ULONG)Buffer;
	Request->IpcVirt.Args.Write.Length = Length;
	// Convert from virtual to physical.
	RtlCopyMemory(&Request->Ipc, &Request->IpcVirt, sizeof(Request->Ipc));
	Request->Ipc.Args.Write.Pointer = BufferPhys;
	// If caller asked to swap the input, do it.
	if ((Request->SwapModeInput & RW_SWAP_INPUT) != 0) {
		HalpEndianSwapInPlace64((PVOID)Request->IpcVirt.Args.Write.Pointer, Request->IpcVirt.Args.Write.Length);
	}
	HalSweepDcacheRange((PVOID)Request->IpcVirt.Args.Write.Pointer, Request->IpcVirt.Args.Write.Length);
}

static NTSTATUS HalpIopWrite(IOS_HANDLE Handle, PVOID Buffer, ULONG Length, IOS_RW_MODE SwapMode, PVOID ContextOrRet, PVOID Async1, PVOID Async2) {
	if (HalpPxiRegisters == NULL) return STATUS_DEVICE_DOES_NOT_EXIST;
	if (Buffer == NULL) return STATUS_INVALID_PARAMETER;
	// Get the physical address for the provided pointer.
	PHYSICAL_ADDRESS BufferPhys = MmGetPhysicalAddress(Buffer);
	if (BufferPhys.LowPart == 0) return STATUS_INVALID_PARAMETER;
	// Ensure the alignment is valid for swapping if needed.
	if (SwapMode != 0 && !HalpIopBufferAlignedForSwap(BufferPhys.LowPart, Length)) return STATUS_INVALID_PARAMETER;
	// Create the request.
	PIOS_IPC_REQUEST Request;
	NTSTATUS Status = HalpPxiNewRequest(IOS_WRITE, Handle, Async1, Async2, &Request);
	if (!NT_SUCCESS(Status)) return Status;
	// Initialise the arguments.
	Request->Context = ContextOrRet;
	Request->SwapModeInput = Request->SwapModeOutput = SwapMode;
	HalpIopWriteInit(Request, Buffer, Length, BufferPhys.LowPart);
	// Perform the request.
	return HalpPxiPerformRequest(Request, Async1 == NULL && Async2 == NULL);
}

NTSTATUS HalIopWrite(IOS_HANDLE Handle, PVOID Buffer, ULONG Length, IOS_RW_MODE SwapMode, PULONG NumberOfBytesTransferred) {
	return HalpIopWrite(Handle, Buffer, Length, SwapMode, NumberOfBytesTransferred, NULL, NULL);
}

NTSTATUS HalIopWriteAsync(IOS_HANDLE Handle, PVOID Buffer, ULONG Length, IOS_RW_MODE SwapMode, PULONG NumberOfBytesTransferred, NTSTATUS* pStatus, PRKEVENT Event) {
	if (pStatus == NULL || Event == NULL) return STATUS_INVALID_PARAMETER;
	return HalpIopWrite(Handle, Buffer, Length, SwapMode, NumberOfBytesTransferred, pStatus, Event);
}

NTSTATUS HalIopWriteAsyncDpc(IOS_HANDLE Handle, PVOID Buffer, ULONG Length, IOS_RW_MODE SwapMode, IOP_CALLBACK Callback, PVOID Context) {
	if (Callback == NULL) return STATUS_INVALID_PARAMETER;
	return HalpIopWrite(Handle, Buffer, Length, SwapMode, Context, NULL, Callback);
}

static void HalpIopSeekInit(PIOS_IPC_REQUEST Request, LONG Offset, IOS_SEEK_MODE Mode) {
	// Initialise the arguments.
	Request->IpcVirt.Args.Seek.Offset = Offset;
	Request->IpcVirt.Args.Seek.Mode = Mode;
	// Convert from virtual to physical.
	RtlCopyMemory(&Request->Ipc, &Request->IpcVirt, sizeof(Request->Ipc));
}

static NTSTATUS HalpIopSeek(IOS_HANDLE Handle, LONG Offset, IOS_SEEK_MODE Mode, PVOID ContextOrRet, PVOID Async1, PVOID Async2) {
	if (HalpPxiRegisters == NULL) return STATUS_DEVICE_DOES_NOT_EXIST;
	// Create the request.
	PIOS_IPC_REQUEST Request;
	NTSTATUS Status = HalpPxiNewRequest(IOS_SEEK, Handle, Async1, Async2, &Request);
	if (!NT_SUCCESS(Status)) return Status;
	// Initialise the arguments.
	Request->Context = ContextOrRet;
	HalpIopSeekInit(Request, Offset, Mode);
	// Perform the request.
	return HalpPxiPerformRequest(Request, Async1 == NULL && Async2 == NULL);
}

NTSTATUS HalIopSeek(IOS_HANDLE Handle, LONG Offset, IOS_SEEK_MODE Mode, PULONG FileOffset) {
	return HalpIopSeek(Handle, Offset, Mode, FileOffset, NULL, NULL);
}

NTSTATUS HalIopSeekAsync(IOS_HANDLE Handle, LONG Offset, IOS_SEEK_MODE Mode, PULONG FileOffset, NTSTATUS* pStatus, PRKEVENT Event) {
	if (pStatus == NULL || Event == NULL) return STATUS_INVALID_PARAMETER;
	return HalpIopSeek(Handle, Offset, Mode, FileOffset, pStatus, Event);
}

NTSTATUS HalIopSeekAsyncDpc(IOS_HANDLE Handle, LONG Offset, IOS_SEEK_MODE Mode, IOP_CALLBACK Callback, PVOID Context) {
	if (Callback == NULL) return STATUS_INVALID_PARAMETER;
	return HalpIopSeek(Handle, Offset, Mode, Context, NULL, Callback);
}

static void HalpIopIoctlInit(PIOS_IPC_REQUEST Request, ULONG ControlCode, PVOID Input, ULONG LengthInput, PVOID Output, ULONG LengthOutput, ULONG PhysInput, ULONG PhysOutput) {
	// Initialise the arguments.
	Request->IpcVirt.Args.Ioctl.ControlCode = ControlCode;
	Request->IpcVirt.Args.Ioctl.Input.Pointer = (ULONG)Input;
	Request->IpcVirt.Args.Ioctl.Input.Length = LengthInput;
	Request->IpcVirt.Args.Ioctl.Output.Pointer = (ULONG)Output;
	Request->IpcVirt.Args.Ioctl.Output.Length = LengthOutput;
	// Convert from virtual to physical.
	RtlCopyMemory(&Request->Ipc, &Request->IpcVirt, sizeof(Request->Ipc));
	Request->Ipc.Args.Ioctl.Input.Pointer = PhysInput;
	Request->Ipc.Args.Ioctl.Output.Pointer = PhysOutput;
	// If caller asked to swap the input, do it.
	if ((Request->SwapModeInput & IOCTL_SWAP_INPUT) != 0) {
		HalpEndianSwapInPlace64((PVOID)Request->IpcVirt.Args.Ioctl.Input.Pointer, Request->IpcVirt.Args.Ioctl.Input.Length);
	}
	if ((Request->SwapModeOutput & IOCTL_SWAP_OUTPUT) != 0) {
		HalpEndianSwapInPlace64((PVOID)Request->IpcVirt.Args.Ioctl.Output.Pointer, Request->IpcVirt.Args.Ioctl.Output.Length);
	}
	HalSweepDcacheRange((PVOID)Request->IpcVirt.Args.Ioctl.Input.Pointer, Request->IpcVirt.Args.Ioctl.Input.Length);
	HalSweepDcacheRange((PVOID)Request->IpcVirt.Args.Ioctl.Output.Pointer, Request->IpcVirt.Args.Ioctl.Output.Length);
}

static NTSTATUS HalpIopIoctl(IOS_HANDLE Handle, ULONG ControlCode, PVOID Input, ULONG LengthInput, PVOID Output, ULONG LengthOutput, IOS_IOCTL_MODE SwapModeInput, IOS_IOCTL_MODE SwapModeOutput, PVOID Context, PVOID Async1, PVOID Async2) {
	if (HalpPxiRegisters == NULL) return STATUS_DEVICE_DOES_NOT_EXIST;
	// Get the physical address for the provided buffers.
	PHYSICAL_ADDRESS InputPhys;
	PHYSICAL_ADDRESS OutputPhys;
	if (Input != NULL) {
		InputPhys = MmGetPhysicalAddress(Input);
		if (InputPhys.LowPart == 0) return STATUS_INVALID_PARAMETER;
		if (SwapModeInput != 0 && !HalpIopBufferAlignedForSwap(InputPhys.LowPart, LengthInput)) return STATUS_INVALID_PARAMETER;
	} else {
		if (LengthInput != 0) return STATUS_INVALID_PARAMETER;
		InputPhys.LowPart = 0;
	}
	if (Output != NULL) {
		OutputPhys = MmGetPhysicalAddress(Output);
		if (OutputPhys.LowPart == 0) return STATUS_INVALID_PARAMETER;
		if (SwapModeOutput != 0 && !HalpIopBufferAlignedForSwap(OutputPhys.LowPart, LengthOutput)) return STATUS_INVALID_PARAMETER;
	} else {
		if (LengthOutput != 0) return STATUS_INVALID_PARAMETER;
		OutputPhys.LowPart = 0;
	}
	// Create the request.
	PIOS_IPC_REQUEST Request;
	NTSTATUS Status = HalpPxiNewRequest(IOS_IOCTL, Handle, Async1, Async2, &Request);
	if (!NT_SUCCESS(Status)) return Status;
	// Initialise the arguments.
	Request->Context = Context;
	Request->SwapModeInput = SwapModeInput;
	Request->SwapModeOutput = SwapModeOutput;
	HalpIopIoctlInit(Request, ControlCode, Input, LengthInput, Output, LengthOutput, InputPhys.LowPart, OutputPhys.LowPart);
	// Perform the request.
	return HalpPxiPerformRequest(Request, Async1 == NULL && Async2 == NULL);
}

NTSTATUS HalIopIoctl(IOS_HANDLE Handle, ULONG ControlCode, PVOID Input, ULONG LengthInput, PVOID Output, ULONG LengthOutput, IOS_IOCTL_MODE SwapModeInput, IOS_IOCTL_MODE SwapModeOutput) {
	return HalpIopIoctl(Handle, ControlCode, Input, LengthInput, Output, LengthOutput, SwapModeInput, SwapModeOutput, NULL, NULL, NULL);
}

NTSTATUS HalIopIoctlAsync(IOS_HANDLE Handle, ULONG ControlCode, PVOID Input, ULONG LengthInput, PVOID Output, ULONG LengthOutput, IOS_IOCTL_MODE SwapModeInput, IOS_IOCTL_MODE SwapModeOutput, NTSTATUS* pStatus, PRKEVENT Event) {
	if (pStatus == NULL || Event == NULL) return STATUS_INVALID_PARAMETER;
	return HalpIopIoctl(Handle, ControlCode, Input, LengthInput, Output, LengthOutput, SwapModeInput, SwapModeOutput, NULL, pStatus, Event);
}

NTSTATUS HalIopIoctlAsyncDpc(IOS_HANDLE Handle, ULONG ControlCode, PVOID Input, ULONG LengthInput, PVOID Output, ULONG LengthOutput, IOS_IOCTL_MODE SwapModeInput, IOS_IOCTL_MODE SwapModeOutput, IOP_CALLBACK Callback, PVOID Context) {
	if (Callback == NULL) return STATUS_INVALID_PARAMETER;
	return HalpIopIoctl(Handle, ControlCode, Input, LengthInput, Output, LengthOutput, SwapModeInput, SwapModeOutput, Context, NULL, Callback);
}

static NTSTATUS HalpIopIoctlvInit(PIOS_IPC_REQUEST Request, ULONG ControlCode, ULONG NumRead, ULONG NumWritten, PIOS_IOCTL_VECTOR Buffers) {
	// Allocate some room inside the IOP IPC heap to describe the buffers as physical addresses.
	ULONG BuffersCount = NumRead + NumWritten;
	PIOS_IPC_BUFFER BuffersPhys = HalpIpcBufferAlloc(Request, BuffersCount);
	if (BuffersPhys == NULL) return STATUS_INSUFFICIENT_RESOURCES;
	// Get the physical address of that buffer.
	ULONG PhysAddrBuffersPhys = HalpPxiVirtToPhys(BuffersPhys);
	// Following should never happen, but check anyway:
	if (PhysAddrBuffersPhys == 0) {
		HalpIpcBufferFreeVirt(Request, BuffersPhys);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	// Init the buffers.
	ULONG AllSwapped = Request->SwapModeInput | Request->SwapModeOutput;
	for (ULONG i = 0; i < BuffersCount; i++) {
		PHYSICAL_ADDRESS PhysAddr = {.QuadPart = 0};
		BOOLEAN Invalid = FALSE;
		if (Buffers[i].Pointer != NULL) {
			PhysAddr = MmGetPhysicalAddress(Buffers[i].Pointer);
			Invalid = PhysAddr.LowPart == 0;
			if (!Invalid && ((AllSwapped & BIT(i)) != 0)) {
				Invalid = !HalpIopBufferAlignedForSwap(PhysAddr.LowPart, Buffers[i].Length);
			}
			if (!Invalid) {
				if ((Request->SwapModeInput & BIT(i)) != 0) {
					HalpEndianSwapInPlace64(Buffers[i].Pointer, Buffers[i].Length);
				}
				HalSweepDcacheRange(Buffers[i].Pointer, Buffers[i].Length);
			}
		} else {
			PhysAddr.LowPart = 0;
			Invalid = Buffers[i].Length != 0;
		}
		if (Invalid) {
			HalpIpcBufferFreeVirt(Request, BuffersPhys);
			return STATUS_INVALID_PARAMETER;
		}
		
		BuffersPhys[i].Pointer = PhysAddr.LowPart;
		BuffersPhys[i].Length = Buffers[i].Length;
	}
	// Guaranteed success now.
	
	// Initialise the arguments.
	Request->IpcVirt.Args.Ioctlv.ControlCode = ControlCode;
	Request->IpcVirt.Args.Ioctlv.NumRead = NumRead;
	Request->IpcVirt.Args.Ioctlv.NumWritten = NumWritten;
	Request->IpcVirt.Args.Ioctlv.Buffers = (ULONG) Buffers;
	// Convert from virtual to physical.
	RtlCopyMemory(&Request->Ipc, &Request->IpcVirt, sizeof(Request->Ipc));
	Request->Ipc.Args.Ioctlv.Buffers = PhysAddrBuffersPhys;
	HalSweepDcacheRange(BuffersPhys, BuffersCount * sizeof(*BuffersPhys));
	return STATUS_SUCCESS;
}

static NTSTATUS HalpIopIoctlv(IOS_HANDLE Handle, ULONG ControlCode, ULONG NumRead, ULONG NumWritten, PIOS_IOCTL_VECTOR Buffers, ULONG SwapBuffersIn, ULONG SwapBuffersOut, PVOID Context, PVOID Async1, PVOID Async2) {
	if (HalpPxiRegisters == NULL) return STATUS_DEVICE_DOES_NOT_EXIST;
	// Create the request.
	PIOS_IPC_REQUEST Request;
	NTSTATUS Status = HalpPxiNewRequest(IOS_IOCTLV, Handle, Async1, Async2, &Request);
	if (!NT_SUCCESS(Status)) return Status;
	// Initialise the arguments.
	Request->Context = Context;
	Request->SwapModeInput = SwapBuffersIn;
	Request->SwapModeOutput = SwapBuffersOut;
	Status = HalpIopIoctlvInit(Request, ControlCode, NumRead, NumWritten, Buffers);
	if (!NT_SUCCESS(Status)) {
		HalpIpcFree(Request);
		return Status;
	}
	// Perform the request.
	return HalpPxiPerformRequest(Request, Async1 == NULL && Async2 == NULL);
}

NTSTATUS HalIopIoctlv(IOS_HANDLE Handle, ULONG ControlCode, ULONG NumRead, ULONG NumWritten, PIOS_IOCTL_VECTOR Buffers, ULONG SwapBuffersIn, ULONG SwapBuffersOut) {
	return HalpIopIoctlv(Handle, ControlCode, NumRead, NumWritten, Buffers, SwapBuffersIn, SwapBuffersOut, NULL, NULL, NULL);
}

NTSTATUS HalIopIoctlvAsync(IOS_HANDLE Handle, ULONG ControlCode, ULONG NumRead, ULONG NumWritten, PIOS_IOCTL_VECTOR Buffers, ULONG SwapBuffersIn, ULONG SwapBuffersOut, NTSTATUS* pStatus, PRKEVENT Event) {
	if (pStatus == NULL || Event == NULL) return STATUS_INVALID_PARAMETER;
	return HalpIopIoctlv(Handle, ControlCode, NumRead, NumWritten, Buffers, SwapBuffersIn, SwapBuffersOut, NULL, pStatus, Event);
}

NTSTATUS HalIopIoctlvAsyncDpc(IOS_HANDLE Handle, ULONG ControlCode, ULONG NumRead, ULONG NumWritten, PIOS_IOCTL_VECTOR Buffers, ULONG SwapBuffersIn, ULONG SwapBuffersOut, IOP_CALLBACK Callback, PVOID Context) {
	if (Callback == NULL) return STATUS_INVALID_PARAMETER;
	return HalpIopIoctlv(Handle, ControlCode, NumRead, NumWritten, Buffers, SwapBuffersIn, SwapBuffersOut, Context, NULL, Callback);
}

BOOLEAN HalpPxiInit(void) {
	// don't try a second time.
	if (HalpPxiRegisters != NULL) return TRUE;
	// if this system is flipper then there's no such thing as PXI
	if ((ULONG)RUNTIME_BLOCK[RUNTIME_SYSTEM_TYPE] == ARTX_SYSTEM_FLIPPER) return TRUE;
	
	// Initialise the DPCs.
	for (ULONG i = 0; i < IPC_REQUEST_COUNT; i++) {
		KeInitializeDpc(&s_DpcRequestAck[i], HalpPxiRequestAck, NULL);
		KeSetTargetProcessorDpc(&s_DpcRequestAck[i], 0);
		KeInitializeDpc(&s_DpcResponseSent[i], HalpPxiResponseSent, NULL);
		KeSetTargetProcessorDpc(&s_DpcRequestAck[i], 0);
	}
	//KeInitializeDpc(&s_DpcSendRequests, HalpIpcSendPendingRequests, NULL);
	// Initialise the events for locking IPC send requests.
	KeInitializeEvent(&s_IpcSendReadyEvent, SynchronizationEvent, TRUE);
	KeInitializeEvent(&s_IpcSendPrepareEvent, SynchronizationEvent, TRUE);
	// Initialise the pending requests linked list, and its protective spinlock.
	KeInitializeSpinLock(&s_IpcRequestPendingSpinLock);
	InitializeListHead(&s_IpcRequestPendingList);
	// Initialise other spinlocks.
	KeInitializeSpinLock(&s_IpcMemorySpinLock);
	// Map the PXI registers.
	PHYSICAL_ADDRESS PxiPhysAddr;
	PxiPhysAddr.HighPart = 0;
	PxiPhysAddr.LowPart = PXI_REGISTER_BASE;
	HalpPxiRegisters = (PPXI_REGISTERS) MmMapIoSpace( PxiPhysAddr, PAGE_SIZE, MmNonCached);
	if (HalpPxiRegisters == NULL) {
		HalDisplayString("PXI: could not map MMIO\n");
		return FALSE;
	}

	do {
		// Disable all PXI interrupts, clear all pending interrupts.
		PXI_CONTROL_WRITE( PXI_REQ_ACK | PXI_RES_SENT );
		
		// Map the IPC buffer in DDR
		// IPC can be anywhere in Napa or anywhere below the IOS cutoff in DDR
		// However, IOS specifies 128KB at the end of PPC-accessible DDR for IPC buffers.
		// Official SDK does set up a heap there using port of IOS heap code.
		// We also specify 1MB at start of DDR for any IPC client to use
		// (for things like USB EHCI that require buffers in DDR)
		// We will set up a heap for PXI buffer allocations using tinyheap.
		PMEMORY_AREA IpcMem = (PMEMORY_AREA)RUNTIME_BLOCK[RUNTIME_IPC_AREA];
		if (IpcMem == NULL) {
			HalDisplayString("PXI: RUNTIME_BLOCK[RUNTIME_IPC_AREA] not filled in\n");
			break;
		}
		PxiPhysAddr.LowPart = IpcMem->PointerArc;
		HalpPxiBuffer = MmMapIoSpace( PxiPhysAddr, IpcMem->Length, MmNonCached);
		if (HalpPxiBuffer == 0) {
			HalDisplayString("PXI: Could not map IPC buffer\n");
			break;
		}
		HalpPxiLength = IpcMem->Length;
		HalpPxiBufferPhys = IpcMem->PointerArc;
		HalpPxiBufferEnd = (PVOID)((ULONG)HalpPxiBuffer + HalpPxiLength);
		// Wipe PXI memory.
		RtlZeroMemory(HalpPxiBuffer, HalpPxiLength);
		// Initialise PXI heap.
		const int HEAP_OFFSET = 0;
		BOOLEAN HeapInit = PhCreate( &s_HalpPxiHeap, HalpPxiBuffer + HEAP_OFFSET, HalpPxiLength - HEAP_OFFSET);
		if (!HeapInit || s_HalpPxiHeap.FreeList->Size == 0) {
			HalDisplayString("PXI: Could not init IPC heap\n");
			break;
		}
		
		// Register the interrupt vector.
		if (!HalpEnableDeviceInterruptHandler(&s_PxiInterrupt,
			(PKSERVICE_ROUTINE) HalpPxiInterrupt,
			NULL,
			NULL,
			VECTOR_VEGAS,
			Latched,
			FALSE,
			0,
			FALSE,
			InternalUsage
		)) {
			HalDisplayString("PXI: Could not register interrupt\n");
			// Unmap IPC buffer
			MmUnmapIoSpace( HalpPxiBuffer, HalpPxiLength );
			break;
		}
		
		// Set up the Vegas interrupt mask.
		if (HalpSystemIsCafe()) MmioWriteBase32( MMIO_INTLT_OFFSET(Mask[1]), 0 );
		VEGAS_INTERRUPT_MASK_SET( VEGAS_INTERRUPT_PXI );
		// Handle any existing interrupts.
		VEGAS_INTERRUPT_CLEAR( VEGAS_INTERRUPT_GPIO | VEGAS_INTERRUPT_PXI );
		
		// Enable the interrupt at the hardware.
		PXI_CONTROL_WRITE( PXI_RES_SENT_INT | PXI_REQ_ACK_INT );
		
		// Done.
		return TRUE;
	} while (FALSE);
	
	// Unmap PXI registers.
	MmUnmapIoSpace(HalpPxiRegisters, sizeof(*HalpPxiRegisters));
	HalpPxiRegisters = NULL;
	return FALSE;
}
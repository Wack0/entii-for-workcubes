// SDMC over IOS driver.
#define DEVL 1
#include <ntddk.h>
#include <hal.h>
#include "backport.h"
#include "sdmc.h"
#include "iosapi.h"
#include "sdmcraw.h"
#include "sdmclow.h"

#include <stdio.h>

static IOS_HANDLE s_hIosSdmc = IOS_HANDLE_INVALID;

static PVOID s_SdmcDmaBuffer = NULL;

static KSPIN_LOCK s_SdmcDmaMapLock;
static RTL_BITMAP s_SdmcDmaMap;
static ULONG s_SdmcDmaMapData[4] = {0};

//static ULONG s_SdmcSelectRefCount = 0;

//static KSPIN_LOCK s_SdmcSelectSpinLock;

static KTIMER s_SdmcTimer;
static KDPC s_SdmcDpc;

enum {
	COUNT_EMERGENCY_BLOCKS = 32,
	COUNT_COPY_DPC = 16,
};

typedef struct _SDMC_DPC_CONTEXT {
	NTSTATUS Status;
	KEVENT Event;
	PVOID Dest;
	PVOID Source;
	ULONG Length;
	ULONG ToMdl;
	BOOLEAN InUse;
} SDMC_DPC_CONTEXT, *PSDMC_DPC_CONTEXT;

typedef struct _SDMC_LOCK_CONTEXT {
	NTSTATUS Status;
	KEVENT Event;
	ULONG Sector;
	ULONG Count;
	PVOID Buffer;
	PMDL Mdl;
	SDMC_LOCK_STATE State;
	ULONG IoCount;
	ULONG BufferPage;
	PVOID DmaBuffer;
	BOOLEAN InUse;
} SDMC_LOCK_CONTEXT, *PSDMC_LOCK_CONTEXT;

static KDPC s_DpcCopy[COUNT_COPY_DPC];

typedef void (*SDMC_LOCK_CALLBACK)(PSDMC_LOCK_CONTEXT Context);

typedef struct _SDMC_WAIT_CONTROL_BLOCK {
	KDEVICE_QUEUE_ENTRY DeviceQueueEntry;
	SDMC_LOCK_CALLBACK Callback;
	PSDMC_LOCK_CONTEXT Context;
} SDMC_WAIT_CONTROL_BLOCK, *PSDMC_WAIT_CONTROL_BLOCK;

static KEVENT s_SdmcReadyEvent;
static KDEVICE_QUEUE s_SdmcLockQueue = {0};
static SDMC_WAIT_CONTROL_BLOCK s_EmergencyBlocks[COUNT_EMERGENCY_BLOCKS] = {0};
static SDMC_LOCK_CONTEXT s_StateContext[COUNT_EMERGENCY_BLOCKS];
static SDMC_DPC_CONTEXT s_DpcContext[COUNT_COPY_DPC];

static BOOLEAN s_SdmcIsHighCapacity = FALSE;
static BOOLEAN s_SdmcIsInitialised = FALSE;

static USHORT s_SdmcRca = 0;

static UCHAR s_SdmcCid[16];
static UCHAR s_SdmcCsd[16];

static PDEVICE_OBJECT s_SdmcLowDevice = NULL;

// https://github.com/fail0verflow/hbc/blob/a8e5f6c0f7e484c7f7112967eee6eee47b27d9ac/wiipax/stub/sync.c#L29
static void sync_before_exec_this_cpu(const void* p, ULONG len)
{

	ULONG a, b;

	a = (ULONG)p & ~0x1f;
	b = ((ULONG)p + len + 0x1f) & ~0x1f;

	for (; a < b; a += 32)
		asm("dcbst 0,%0 ; sync ; icbi 0,%0" : : "b"(a));

	asm("sync ; isync");
}

static void endian_swap64(void* dest, const void* src, ULONG len);
NTHALAPI void HalSyncBeforeExecution(const void* BaseAddress, ULONG Length);

#define sync_before_exec(a,b) HalSyncBeforeExecution(a,b)

static void SdmcpCopyDpc(PKDPC Dpc, PVOID Unused, PVOID ContextVoid, PVOID Unused2) {
	PSDMC_DPC_CONTEXT Context = (PSDMC_DPC_CONTEXT)ContextVoid;
	
	// Map the DPC.
	PVOID Dest = Context->Dest;
	PVOID Source = Context->Source;
	ULONG Length = Context->Length;
	NTSTATUS Status = STATUS_SUCCESS;
	if (Context->ToMdl) {
		// Destination is really MDL:
		PMDL Mdl = (PMDL)Dest;
		Dest = MmGetSystemAddressForMdl(Mdl);
		if (Dest == NULL) Status = STATUS_UNSUCCESSFUL;
	} else {
		// Source is really MDL
		PMDL Mdl = (PMDL)Source;
		Source = MmGetSystemAddressForMdl(Mdl);
		if (Source == NULL) Status = STATUS_UNSUCCESSFUL;
	}
	
	if (NT_SUCCESS(Status)) {
		memcpy(Dest, Source, Length);
		if (Context->ToMdl) sync_before_exec(Dest, Length);
	}
	
	Context->Status = Status;
	
	KeSetEvent(&Context->Event, (KPRIORITY) 0, FALSE);
}

static BOOLEAN SdmcpQueueDpc(PSDMC_DPC_CONTEXT Context) {
	BOOLEAN AlreadyQueued = FALSE;
	for (ULONG i = 0; i < COUNT_COPY_DPC; i++) {
		AlreadyQueued = KeInsertQueueDpc(&s_DpcCopy[i], Context, NULL);
		if (AlreadyQueued) break;
	}
	return !AlreadyQueued;
}

static PSDMC_DPC_CONTEXT SdmcpGetDpcContext(void) {
	for (ULONG i = 0; i < COUNT_COPY_DPC; i++) {
		PSDMC_DPC_CONTEXT ctx = &s_DpcContext[i];
		if (!ctx->InUse) {
			KeInitializeEvent(&ctx->Event, NotificationEvent, FALSE);
			ctx->Status = STATUS_SUCCESS;
			ctx->InUse = 1;
			return ctx;
		}
	}
	return NULL;
}

static void SdmcpReleaseDpcContext(PSDMC_DPC_CONTEXT ctx) {
	ctx->InUse = 0;
}

static PSDMC_LOCK_CONTEXT SdmcpGetStateContext(void) {
	for (ULONG i = 0; i < COUNT_EMERGENCY_BLOCKS; i++) {
		PSDMC_LOCK_CONTEXT ctx = &s_StateContext[i];
		if (!ctx->InUse) {
			KeInitializeEvent(&ctx->Event, NotificationEvent, FALSE);
			ctx->Status = STATUS_SUCCESS;
			ctx->State = LOCK_STATE_SELECT;
			ctx->BufferPage = 0xFFFFFFFF;
			ctx->DmaBuffer = NULL;
			ctx->InUse = 1;
			return ctx;
		}
	}
	return NULL;
}

static void SdmcpReleaseStateContext(PSDMC_LOCK_CONTEXT ctx) {
	ctx->InUse = 0;
}

static NTSTATUS SdmcpLockController(SDMC_LOCK_CALLBACK callback, PSDMC_LOCK_CONTEXT context) {
#if 0
	if (*KeNumberProcessors > 1) {
		// Wait on the sdmc ready event.
		KeWaitForSingleObject( &s_SdmcReadyEvent, Executive, KernelMode, FALSE, NULL);
		// Call the callback, which should be synchronous.
		callback(context);
		// Raise the ready event to allow some other thread to call the callback.
		KeSetEvent(&s_SdmcReadyEvent, (KPRIORITY)0, FALSE);
		return STATUS_SUCCESS;
	}
#endif
	// Allocate a control block to store the callback.
	PSDMC_WAIT_CONTROL_BLOCK Block = (PSDMC_WAIT_CONTROL_BLOCK) ExAllocatePool(NonPagedPool, sizeof(SDMC_WAIT_CONTROL_BLOCK));
	if (Block == NULL) {
		// Pick out the first emergency block with a null callback.
		for (ULONG i = 0; i < COUNT_EMERGENCY_BLOCKS; i++) {
			if (s_EmergencyBlocks[i].Callback != NULL) continue;
			Block = &s_EmergencyBlocks[i];
			break;
		}
		// If none were found, return insufficient resources.
		if (Block == NULL) return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	RtlZeroMemory(Block, sizeof(*Block));
	Block->Callback = callback;
	Block->Context = context;
	
	
	// Go to DISPATCH_LEVEL when calling device queue related functions
	KIRQL CurrentIrql;
	KeRaiseIrql(DISPATCH_LEVEL, &CurrentIrql);
	BOOLEAN Result = KeInsertDeviceQueue(&s_SdmcLockQueue, &Block->DeviceQueueEntry);
	KeLowerIrql(CurrentIrql);
	
	if (!Result) {
		// The controller is not busy.
		// While a lock callback is present, call it and free the block.
		do {
			Block->Callback(Block->Context);
			
			if (Block >= &s_EmergencyBlocks[0] && Block < &s_EmergencyBlocks[COUNT_EMERGENCY_BLOCKS]) {
				Block->Callback = NULL;
			} else ExFreePool(Block);
			
			KeRaiseIrql(DISPATCH_LEVEL, &CurrentIrql);
			Block = (PSDMC_WAIT_CONTROL_BLOCK) KeRemoveDeviceQueue(&s_SdmcLockQueue);
			KeLowerIrql(CurrentIrql);
		} while (Block != NULL);
		
		return STATUS_SUCCESS;
	}
	
	return STATUS_PENDING;
}

static void SdmcpUnlockController(void) {
	while (TRUE) {
		KIRQL CurrentIrql;
		KeRaiseIrql(DISPATCH_LEVEL, &CurrentIrql);
		PSDMC_WAIT_CONTROL_BLOCK Block = (PSDMC_WAIT_CONTROL_BLOCK) KeRemoveDeviceQueue(&s_SdmcLockQueue);
		KeLowerIrql(CurrentIrql);
		
		if (Block == NULL) break;
		
		Block->Callback(Block->Context);
		
		if (Block >= &s_EmergencyBlocks[0] && Block < &s_EmergencyBlocks[COUNT_EMERGENCY_BLOCKS]) {
			Block->Callback = NULL;
		} else ExFreePool(Block);
	}
}

static void SdmcpCopyResponse(PVOID Destination, PIOS_SDMC_RESPONSE Source, ULONG Length) {
	if ((Length & 3) != 0) return;
	if (Length > sizeof(IOS_SDMC_RESPONSE)) Length = sizeof(IOS_SDMC_RESPONSE) / sizeof(ULONG);
	else Length /= sizeof(ULONG);
	PULONG Buffer32 = (PULONG)Destination;

	ULONG Index = 0;
	if (Length == 0) return;
	Buffer32[Index++] = Source->Field0;
	if ((--Length) == 0) return;
	Buffer32[Index++] = Source->Field1;
	if ((--Length) == 0) return;
	Buffer32[Index++] = Source->Field2;
	if ((--Length) == 0) return;
	Buffer32[Index++] = Source->ACmd12Response;
}

static void endian_swap64(void* dest, const void* src, ULONG len) {
	const ULONG* src32 = (const ULONG*)src;
	ULONG* dest32 = (ULONG*)dest;
	for (ULONG i = 0; i < len; i += sizeof(ULONG) * 2) {
		ULONG idx = i / sizeof(ULONG);
		ULONG buf0 = __builtin_bswap32(src32[idx + 0]);
		dest32[idx + 0] = __builtin_bswap32(src32[idx + 1]);
		dest32[idx + 1] = buf0;
	}
}

static void endian_swap64by8(void* dest, const void* src, ULONG len) {
	const UCHAR* src8 = (const UCHAR*)src;
	UCHAR* dest8 = (UCHAR*)dest;

	UCHAR arr[8];
	for (ULONG i = 0; i < len; i += sizeof(ULONG) * 2) {
		memcpy(arr, &src8[i], sizeof(arr));

		NativeWrite8(&dest8[0], arr[0]);
		NativeWrite8(&dest8[1], arr[1]);
		NativeWrite8(&dest8[2], arr[2]);
		NativeWrite8(&dest8[3], arr[3]);
		NativeWrite8(&dest8[4], arr[4]);
		NativeWrite8(&dest8[5], arr[5]);
		NativeWrite8(&dest8[6], arr[6]);
		NativeWrite8(&dest8[7], arr[7]);
	}
}

enum {
	SDMC_DMA_BUFFER_SIZE = 0x10 * SDMC_SECTOR_SIZE
};

static const char sc_SdmcDev[] ARC_ALIGNED(32) = STRING_BYTESWAP("/dev/sdio/slot0");

#if 0
typedef struct _IOS_ASYNC_CONTEXT {
	NTSTATUS Status;
	KEVENT Event;
	KEVENT EventSent;
	BOOLEAN ForceIoctl;
	BOOLEAN TimedOut;
} IOS_ASYNC_CONTEXT, *PIOS_ASYNC_CONTEXT;
#endif

typedef struct _IOS_SDMC_SEND_COMMAND_BUFFER {
	IOS_IOCTL_VECTOR Vectors[3] ARC_ALIGNED(32);
	IOS_SDMC_COMMAND Command ARC_ALIGNED(32);
	IOS_SDMC_RESPONSE Response ARC_ALIGNED(32);
#if 0
	PIOS_ASYNC_CONTEXT Async;
#endif
	IOP_CALLBACK Callback;
	PVOID Context;
} IOS_SDMC_SEND_COMMAND_BUFFER, *PIOS_SDMC_SEND_COMMAND_BUFFER;

#if 0
static NTSTATUS SdmcpInitIo(void);

#define MS_TO_TIMEOUT(ms) ((ms) * 10000)

void AsyncTimerSet(PKTIMER Timer, PRKDPC Dpc) {
	LARGE_INTEGER DueTime;
	DueTime.QuadPart = -MS_TO_TIMEOUT(10);
	KeSetTimer(Timer, DueTime, Dpc);
}

// Assumption that only ONE IOCTL_SDIO_SENDCMD request will be in flight at any one time.
static volatile PIOS_SDMC_SEND_COMMAND_BUFFER s_SendCmdBuf = NULL;
static PIOS_ASYNC_CONTEXT s_AsyncContext = NULL;

static void SdmcpSendCommandInFlight(void);

static void SdmcpSendCommandCallback(NTSTATUS Status, ULONG Result, PVOID Context) {
	PIOS_ASYNC_CONTEXT AsyncCtx = (PIOS_ASYNC_CONTEXT)Context;
	if (AsyncCtx->TimedOut) {
		ExFreePool(AsyncCtx);
		return;
	}
	AsyncCtx->Status = Status;
	KeSetEvent(&AsyncCtx->Event, (KPRIORITY) 0, FALSE);
}

static void SdmcpTimerCallback(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
	SdmcpSendCommandInFlight();
}

static void SdmcpSendCommandInFlight(void) {
	PIOS_SDMC_SEND_COMMAND_BUFFER CmdBuf = s_SendCmdBuf;
	PIOS_ASYNC_CONTEXT Async = CmdBuf->Async;
	if (Async->TimedOut) {
		// Set the event so caller knows that the static global isn't being used any more
		KeSetEvent(&Async->Event, (KPRIORITY) 0, FALSE);
		return;
	}
	
	// Assumption: don't need to deal with endianness swap here, it will be dealt with further up the call stack for reads/writes.
	
	NTSTATUS Status;
	if (CmdBuf->Async->ForceIoctl || s_SendCmdBuf->Vectors[0].Pointer == NULL) {
		Status = HalIopIoctlAsyncDpc(
			s_hIosSdmc,
			IOCTL_SDIO_SENDCMD,
			&CmdBuf->Command,
			sizeof(IOS_SDMC_COMMAND),
			&CmdBuf->Response,
			sizeof(IOS_SDMC_RESPONSE),
			SdmcpSendCommandCallback,
			IOCTL_SWAP_NONE, IOCTL_SWAP_NONE,
			Async
		);
	} else {
		Status = HalIopIoctlvAsyncDpc(
			s_hIosSdmc,
			IOCTL_SDIO_SENDCMD,
			2,
			1,
			CmdBuf->Vectors,
			0, 0,
			SdmcpSendCommandCallback,
			Async
		);
	}
	if (!NT_SUCCESS(Status)) {
		AsyncTimerSet(&s_SdmcTimer, &s_SdmcDpc);
	} else {
		KeSetEvent(&Async->EventSent, (KPRIORITY) 0, FALSE);
	}
}

static NTSTATUS SdmcpInitIo(void);

static NTSTATUS SdmcpSendCommandImpl(
	PIOS_SDMC_SEND_COMMAND_BUFFER CmdBuf,
	BOOLEAN CanTimeoutOnIosSide
) {
	// This should never happen, but check anyway before setting
	if (s_SendCmdBuf != NULL) {
		LARGE_INTEGER DueTime;
		DueTime.QuadPart = -MS_TO_TIMEOUT(10);
		while (s_SendCmdBuf != NULL) {
			KeDelayExecutionThread(KernelMode, FALSE, &DueTime);
		}
	}
	CmdBuf->Async = ExAllocatePool(NonPagedPool, sizeof(*CmdBuf->Async));
	if (CmdBuf->Async == NULL) {
		//HalDisplayString("SDMC: using fallback async context\n");
		// Use the already allocated one as fallback.
		CmdBuf->Async = s_AsyncContext;
	}
	PIOS_ASYNC_CONTEXT Async = CmdBuf->Async;
	RtlZeroMemory(Async, sizeof(*Async));
	ULONG Attempt = 0;
	NTSTATUS Status = STATUS_SUCCESS;
	for (; Attempt < 2; Attempt++) {
		Async->TimedOut = FALSE;
		s_SendCmdBuf = CmdBuf;
		KeInitializeEvent(&Async->Event, NotificationEvent, FALSE);
		KeInitializeEvent(&Async->EventSent, NotificationEvent, FALSE);
		
		// Go to DISPATCH_LEVEL
		KIRQL OldIrql;
		KeRaiseIrql( DISPATCH_LEVEL, &OldIrql );
		// Send command in flight.
		SdmcpSendCommandInFlight();
		// Lower IRQ level
		KeLowerIrql( OldIrql );
		
		
		if (CanTimeoutOnIosSide) {
			// Just wait forever if this command can timeout on IOS side.
			KeWaitForSingleObject( &Async->Event, Executive, KernelMode, FALSE, NULL );
			// Get the status code.
			Status = Async->Status;
			break;
		}
		
		// Wait for ioctl to be sent, time out after 2 seconds.
		LARGE_INTEGER DueTime;
		DueTime.QuadPart = -MS_TO_TIMEOUT(2000);
		Status = KeWaitForSingleObject( &Async->EventSent, Executive, KernelMode, FALSE, &DueTime );
		if (Status == STATUS_TIMEOUT) {
			HalDisplayString("SDMC: timed out trying to send IPC\n");
			// Set timed out and wait for the async call to return.
			Async->TimedOut = TRUE;
			KeWaitForSingleObject( &Async->Event, Executive, KernelMode, FALSE, NULL );
			// Try again forcing ioctl. Ignore this attempt.
			Async->ForceIoctl = TRUE;
			Attempt--;
			continue;
		}
		// Wait for command to complete, time out after 2 seconds.
		Status = KeWaitForSingleObject( &Async->Event, Executive, KernelMode, FALSE, &DueTime );
		if (Status == STATUS_TIMEOUT) {
			HalDisplayString("SDMC: timed out trying to receive IPC\n");
			// Timed out.
			// Clean up for the commands we are about to send.
			Async->TimedOut = TRUE;
			s_SendCmdBuf = NULL;
			// Try again.
			Status = STATUS_IO_TIMEOUT;
			continue;
		}
		// Get the status code.
		Status = Async->Status;
		break;
	}
	// Clean up.
	if (CmdBuf->Async != s_AsyncContext) {
		ExFreePool(CmdBuf->Async);
	}
	s_SendCmdBuf = NULL;
	// Return.
	return Status;
}
#endif

static void SdmcpCommandAsyncFinish(NTSTATUS Status, ULONG Result, PVOID Context) {
	PIOS_SDMC_SEND_COMMAND_BUFFER CmdBuf = (PIOS_SDMC_SEND_COMMAND_BUFFER)Context;
	
	if (!NT_SUCCESS(Status) && CmdBuf->Vectors[0].Pointer != NULL) {
		// fall back to ioctl
		CmdBuf->Vectors[0].Pointer = NULL;
		Status = HalIopIoctlAsyncDpc(
			s_hIosSdmc,
			IOCTL_SDIO_SENDCMD,
			&CmdBuf->Command,
			sizeof(IOS_SDMC_COMMAND),
			&CmdBuf->Response,
			sizeof(IOS_SDMC_RESPONSE),
			IOCTL_SWAP_NONE, IOCTL_SWAP_NONE,
			SdmcpCommandAsyncFinish, CmdBuf
		);
		if (NT_SUCCESS(Status)) return;
	}
	
	IOP_CALLBACK Callback = CmdBuf->Callback;
	Context = CmdBuf->Context;
	ULONG Command = CmdBuf->Command.Command;
	BOOLEAN CanTimeoutOnIosSide = TRUE;
	if (
		Command == SDIO_CMD_READBLOCK ||
		Command == SDIO_CMD_READMULTIBLOCK ||
		Command == SDIO_CMD_WRITEBLOCK ||
		Command == SDIO_CMD_WRITEMULTIBLOCK
	) {
		CanTimeoutOnIosSide = FALSE;
	}
	
	HalIopFree(CmdBuf);
	// Toggle the disc LED gpio.
	if (!CanTimeoutOnIosSide)
		MmioWrite32((PVOID)0x8d8000c0, MmioRead32((PVOID)0x8d8000c0) ^ 0x20);
	
	Callback(Status, Result, Context);
}

static NTSTATUS SdmcpSendCommandImpl(
	PIOS_SDMC_SEND_COMMAND_BUFFER CmdBuf,
	BOOLEAN CanTimeoutOnIosSide
) {
	(void)CanTimeoutOnIosSide;

	// Assumption: don't need to deal with endianness swap here, it will be dealt with further up the call stack for reads/writes.
	
	if (CmdBuf->Vectors[0].Pointer != NULL) {
		NTSTATUS Status = HalIopIoctlv(
			s_hIosSdmc,
			IOCTL_SDIO_SENDCMD,
			2,
			1,
			CmdBuf->Vectors,
			0, 0
		);
		if (NT_SUCCESS(Status)) return Status;
		// fallback to ioctl
	}
	return HalIopIoctl(
		s_hIosSdmc,
		IOCTL_SDIO_SENDCMD,
		&CmdBuf->Command,
		sizeof(IOS_SDMC_COMMAND),
		&CmdBuf->Response,
		sizeof(IOS_SDMC_RESPONSE),
		IOCTL_SWAP_NONE, IOCTL_SWAP_NONE
	);
}

static NTSTATUS SdmcpSendCommandAsyncImpl(
	PIOS_SDMC_SEND_COMMAND_BUFFER CmdBuf,
	BOOLEAN CanTimeoutOnIosSide
) {
	(void)CanTimeoutOnIosSide;

	// Assumption: don't need to deal with endianness swap here, it will be dealt with further up the call stack for reads/writes.
	
	if (CmdBuf->Vectors[0].Pointer != NULL) {
		return HalIopIoctlvAsyncDpc(
			s_hIosSdmc,
			IOCTL_SDIO_SENDCMD,
			2,
			1,
			CmdBuf->Vectors,
			0, 0,
			SdmcpCommandAsyncFinish, CmdBuf
		);
	}
	return HalIopIoctlAsyncDpc(
		s_hIosSdmc,
		IOCTL_SDIO_SENDCMD,
		&CmdBuf->Command,
		sizeof(IOS_SDMC_COMMAND),
		&CmdBuf->Response,
		sizeof(IOS_SDMC_RESPONSE),
		IOCTL_SWAP_NONE, IOCTL_SWAP_NONE,
		SdmcpCommandAsyncFinish, CmdBuf
	);
}

static NTSTATUS SdmcpSendCommand(
	SDIO_COMMAND Command,
	SDIO_COMMAND_TYPE Type,
	SDIO_RESPONSE ResponseType,
	ULONG Argument,
	ULONG BlockCount,
	ULONG BlockSize,
	PVOID Buffer,
	PIOS_SDMC_RESPONSE Reply
) {
	// Get the physical address for the DMA.
	PHYSICAL_ADDRESS BufferPhys = {.QuadPart = 0};
	BOOLEAN IsDma = (Buffer != NULL);
	if (Buffer != NULL) {
		BufferPhys = MmGetPhysicalAddress(Buffer);
		if (BufferPhys.LowPart == 0) return STATUS_INVALID_PARAMETER;
	}
	
	// Allocate command buffer in IPC RAM.
	PIOS_SDMC_SEND_COMMAND_BUFFER CmdBuf = (PIOS_SDMC_SEND_COMMAND_BUFFER)
		HalIopAlloc(sizeof(IOS_SDMC_SEND_COMMAND_BUFFER));
	if (CmdBuf == NULL) return STATUS_INSUFFICIENT_RESOURCES;
	
	BOOLEAN CanTimeoutOnIosSide = TRUE;
	if (
		Command == SDIO_CMD_READBLOCK ||
		Command == SDIO_CMD_READMULTIBLOCK ||
		Command == SDIO_CMD_WRITEBLOCK ||
		Command == SDIO_CMD_WRITEMULTIBLOCK
	) {
		CanTimeoutOnIosSide = FALSE;
	}
	
	// Toggle the disc LED gpio.
	if (!CanTimeoutOnIosSide)
		MmioWrite32((PVOID)0x8d8000c0, MmioRead32((PVOID)0x8d8000c0) ^ 0x20);
	
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	do {
		CmdBuf->Command.Command = Command;
		CmdBuf->Command.CommandType = Type;
		CmdBuf->Command.ResponseType = ResponseType;
		CmdBuf->Command.Argument = Argument;
		CmdBuf->Command.BlockCount = BlockCount;
		CmdBuf->Command.BlockSize = BlockSize;
		CmdBuf->Command.Padding0 = CmdBuf->Command.Padding1 = 0;
		CmdBuf->Command.IsDma = IsDma;
		CmdBuf->Command.UserBuffer = BufferPhys.LowPart;
		
		if (s_SdmcIsHighCapacity || IsDma) {
			CmdBuf->Vectors[0].Pointer = &CmdBuf->Command;
			CmdBuf->Vectors[0].Length = sizeof(IOS_SDMC_COMMAND);
			CmdBuf->Vectors[1].Pointer = Buffer;
			CmdBuf->Vectors[1].Length = (BlockCount * BlockSize);
			CmdBuf->Vectors[2].Pointer = &CmdBuf->Response;
			CmdBuf->Vectors[2].Length = sizeof(IOS_SDMC_RESPONSE);
		} else {
			CmdBuf->Vectors[0].Pointer = NULL;
		}
		Status = SdmcpSendCommandImpl(CmdBuf, CanTimeoutOnIosSide);

		// libogc doesn't check error first...
		
		if (Reply != NULL)
			RtlCopyMemory(Reply, &CmdBuf->Response, sizeof(CmdBuf->Response));
	} while (FALSE);
	HalIopFree(CmdBuf);
	// Toggle the disc LED gpio.
	if (!CanTimeoutOnIosSide)
		MmioWrite32((PVOID)0x8d8000c0, MmioRead32((PVOID)0x8d8000c0) ^ 0x20);
	return Status;
}

static NTSTATUS SdmcpSendCommandAsync(
	SDIO_COMMAND Command,
	SDIO_COMMAND_TYPE Type,
	SDIO_RESPONSE ResponseType,
	ULONG Argument,
	ULONG BlockCount,
	ULONG BlockSize,
	PVOID Buffer,
	IOP_CALLBACK Callback,
	PVOID Context
) {
	// Get the physical address for the DMA.
	PHYSICAL_ADDRESS BufferPhys = {.QuadPart = 0};
	BOOLEAN IsDma = (Buffer != NULL);
	if (Buffer != NULL) {
		BufferPhys = MmGetPhysicalAddress(Buffer);
		if (BufferPhys.LowPart == 0) return STATUS_INVALID_PARAMETER;
	}
	
	// Allocate command buffer in IPC RAM.
	PIOS_SDMC_SEND_COMMAND_BUFFER CmdBuf = (PIOS_SDMC_SEND_COMMAND_BUFFER)
		HalIopAlloc(sizeof(IOS_SDMC_SEND_COMMAND_BUFFER));
	if (CmdBuf == NULL) return STATUS_INSUFFICIENT_RESOURCES;
	
	BOOLEAN CanTimeoutOnIosSide = TRUE;
	if (
		Command == SDIO_CMD_READBLOCK ||
		Command == SDIO_CMD_READMULTIBLOCK ||
		Command == SDIO_CMD_WRITEBLOCK ||
		Command == SDIO_CMD_WRITEMULTIBLOCK
	) {
		CanTimeoutOnIosSide = FALSE;
	}
	
	// Toggle the disc LED gpio.
	if (!CanTimeoutOnIosSide)
		MmioWrite32((PVOID)0x8d8000c0, MmioRead32((PVOID)0x8d8000c0) ^ 0x20);
	
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	do {
		CmdBuf->Callback = Callback;
		CmdBuf->Context = Context;
		CmdBuf->Command.Command = Command;
		CmdBuf->Command.CommandType = Type;
		CmdBuf->Command.ResponseType = ResponseType;
		CmdBuf->Command.Argument = Argument;
		CmdBuf->Command.BlockCount = BlockCount;
		CmdBuf->Command.BlockSize = BlockSize;
		CmdBuf->Command.Padding0 = CmdBuf->Command.Padding1 = 0;
		CmdBuf->Command.IsDma = IsDma;
		CmdBuf->Command.UserBuffer = BufferPhys.LowPart;
		
		if (s_SdmcIsHighCapacity || IsDma) {
			CmdBuf->Vectors[0].Pointer = &CmdBuf->Command;
			CmdBuf->Vectors[0].Length = sizeof(IOS_SDMC_COMMAND);
			CmdBuf->Vectors[1].Pointer = Buffer;
			CmdBuf->Vectors[1].Length = (BlockCount * BlockSize);
			CmdBuf->Vectors[2].Pointer = &CmdBuf->Response;
			CmdBuf->Vectors[2].Length = sizeof(IOS_SDMC_RESPONSE);
		} else {
			CmdBuf->Vectors[0].Pointer = NULL;
		}
		Status = SdmcpSendCommandAsyncImpl(CmdBuf, CanTimeoutOnIosSide);
	} while (FALSE);
	return Status;
}

static NTSTATUS SdmcpSendCommandEx(
	SDIO_COMMAND Command,
	SDIO_COMMAND_TYPE Type,
	SDIO_RESPONSE ResponseType,
	ULONG Argument,
	ULONG BlockCount,
	ULONG BlockSize,
	PVOID Buffer,
	PVOID Reply,
	ULONG ReplyLength
) {
	IOS_SDMC_RESPONSE Response;
	NTSTATUS Status = SdmcpSendCommand(Command, Type, ResponseType, Argument, BlockCount, BlockSize, Buffer, &Response);
	if (!NT_SUCCESS(Status)) return Status;
	if (Reply != NULL && ReplyLength <= sizeof(Response))
		SdmcpCopyResponse(Reply, &Response, ReplyLength);
	return Status;
}

static NTSTATUS SdmcpSetClock(ULONG Set) {
	static STACK_ALIGN(ULONG, Clock, 1, 32);
	// we are 32 byte aligned
	// therefore, the correct index is 1
	Clock[1] = Set;
	return HalIopIoctl(s_hIosSdmc, IOCTL_SDIO_SETCLK, Clock, sizeof(ULONG), NULL, 0, IOCTL_SWAP_NONE, IOCTL_SWAP_NONE);
}

static NTSTATUS SdmcpGetStatus(PULONG Status) {
	static STACK_ALIGN(ULONG, lStatus, 1, 32);
	NTSTATUS NtStatus = HalIopIoctl(s_hIosSdmc, IOCTL_SDIO_GETSTATUS, NULL, 0, lStatus, sizeof(ULONG), IOCTL_SWAP_NONE, IOCTL_SWAP_NONE);
	if (NT_SUCCESS(NtStatus)) *Status = lStatus[1];
	return NtStatus;
}

static void SdmcpGetStatusLocked(PSDMC_LOCK_CONTEXT Context) {
	Context->Status = SdmcpGetStatus((PULONG)Context->Buffer);
	KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
}

static NTSTATUS SdmcpGetStatusExt(PULONG Buffer) {
	PSDMC_LOCK_CONTEXT Context = SdmcpGetStateContext();
	if (Context == NULL) return STATUS_INSUFFICIENT_RESOURCES;
	
	Context->Buffer = Buffer;
	
	NTSTATUS Status = SdmcpLockController(SdmcpGetStatusLocked, Context);
	if (!NT_SUCCESS(Status)) {
		SdmcpReleaseStateContext(Context);
		return Status;
	}
	
	KeWaitForSingleObject( &Context->Event, Executive, KernelMode, FALSE, NULL);
	Status = Context->Status;
	SdmcpReleaseStateContext(Context);
	return Status;
}

static NTSTATUS SdmcpResetCard(void) {
	static STACK_ALIGN(ULONG, lStatus, 1, 32);
	s_SdmcRca = 0;
	NTSTATUS NtStatus = HalIopIoctl(s_hIosSdmc, IOCTL_SDIO_RESETCARD, NULL, 0, lStatus, sizeof(ULONG), IOCTL_SWAP_NONE, IOCTL_SWAP_NONE);
	if (!NT_SUCCESS(NtStatus)) return NtStatus;
	s_SdmcRca = (USHORT) ( LoadToRegister32(lStatus[1]) >> 16 );
	return NtStatus;
}

static NTSTATUS SdmcpReadRegister(UCHAR Reg, UCHAR Size, PULONG Value) {
	static STACK_ALIGN(IOS_SDMC_MMIO, Mmio, 1, 32);
	static STACK_ALIGN(ULONG, lValue, 1, 32);
	if (Value == NULL) return STATUS_INVALID_PARAMETER;
	
	Mmio->Address = Reg;
	Mmio->BlockSize = 0;
	Mmio->BlockCount = 0;
	Mmio->Width = Size;
	Mmio->Value = 0;
	Mmio->IsDma = 0;
	
	NTSTATUS Status = HalIopIoctl(s_hIosSdmc, IOCTL_SDIO_READHCREG, Mmio, sizeof(*Mmio), lValue, sizeof(*lValue), IOCTL_SWAP_NONE, IOCTL_SWAP_NONE);
	if (NT_SUCCESS(Status)) *Value = lValue[1];
	
	return Status;
}

static NTSTATUS SdmcpWriteRegister(UCHAR Reg, UCHAR Size, ULONG Value) {
	static STACK_ALIGN(IOS_SDMC_MMIO, Mmio, 1, 32);
	
	Mmio->Address = Reg;
	Mmio->BlockSize = 0;
	Mmio->BlockCount = 0;
	Mmio->Width = Size;
	Mmio->Value = Value;
	Mmio->IsDma = 0;
	
	return HalIopIoctl(s_hIosSdmc, IOCTL_SDIO_WRITEHCREG, Mmio, sizeof(*Mmio), NULL, 0, IOCTL_SWAP_NONE, IOCTL_SWAP_NONE);
}

static LARGE_INTEGER s_Timeout = { .QuadPart = -100000 }; // 10ms

static NTSTATUS SdmcpWaitRegister(UCHAR Reg, UCHAR Size, BOOLEAN Unset, ULONG Mask) {
	ULONG Value;
	NTSTATUS Status;
	
	for (ULONG Try = 0; Try < 10; Try++) {
		if (Try != 0) {
			KeDelayExecutionThread(KernelMode, FALSE, &s_Timeout);
		}
		Status = SdmcpReadRegister(Reg, Size, &Value);
		if (!NT_SUCCESS(Status)) return Status;
		ULONG Masked = Value & Mask;
		if (Unset) {
			if (Masked == 0) return STATUS_SUCCESS;
		} else {
			if (Masked != 0) return STATUS_SUCCESS;
		}
	}
	return STATUS_UNSUCCESSFUL;
}

static NTSTATUS SdmcpGetRca(void) {
	static STACK_ALIGN(ULONG, lStatus, 1, 32);
	NTSTATUS Status = SdmcpSendCommandEx(SDIO_CMD_SENDRCA, 0, SDIO_RESPONSE_R5, 0, 0, 0, NULL, lStatus, sizeof(*lStatus));
	if (!NT_SUCCESS(Status)) return Status;
	s_SdmcRca = (USHORT) ( LoadToRegister32(lStatus[1]) >> 16 );
	return Status;
}

static NTSTATUS SdmcpSelect(void) {
	return SdmcpSendCommand(SDIO_CMD_SELECT, SDIO_TYPE_CMD, SDIO_RESPONSE_R1B, s_SdmcRca << 16, 0, 0, NULL, NULL);
}

static NTSTATUS SdmcpDeSelect(void) {
	return SdmcpSendCommand(SDIO_CMD_DESELECT, SDIO_TYPE_CMD, SDIO_RESPONSE_R1B, 0, 0, 0, NULL, NULL);
}

static NTSTATUS SdmcpSelectAsync(IOP_CALLBACK Callback, PVOID Context) {
	return SdmcpSendCommandAsync(SDIO_CMD_SELECT, SDIO_TYPE_CMD, SDIO_RESPONSE_R1B, s_SdmcRca << 16, 0, 0, NULL, Callback, Context);
}

static NTSTATUS SdmcpDeSelectAsync(IOP_CALLBACK Callback, PVOID Context) {
	return SdmcpSendCommandAsync(SDIO_CMD_DESELECT, SDIO_TYPE_CMD, SDIO_RESPONSE_R1B, 0, 0, 0, NULL, Callback, Context);
}

static NTSTATUS SdmcpSetBlockLength(ULONG BlockLen) {
	return SdmcpSendCommand(SDIO_CMD_SETBLOCKLEN, SDIO_TYPE_CMD, SDIO_RESPONSE_R1, BlockLen, 0, 0, NULL, NULL);
}

static NTSTATUS SdmcpSetBusWidth(ULONG BusWidth) {
	USHORT Value = 0;
	if (BusWidth == 4) Value = 2;
	
	NTSTATUS Status = SdmcpSendCommand(SDIO_CMD_APPCMD, SDIO_TYPE_CMD, SDIO_RESPONSE_R1, s_SdmcRca << 16, 0, 0, NULL, NULL);
	if (!NT_SUCCESS(Status)) return Status;
	
	return SdmcpSendCommand(SDIO_ACMD_SETBUSWIDTH, SDIO_TYPE_CMD, SDIO_RESPONSE_R1, Value, 0, 0, NULL, NULL);
}

static NTSTATUS SdmcpIoSetBusWidth(ULONG BusWidth) {
	ULONG Reg;
	NTSTATUS Status = SdmcpReadRegister(SDIOHCR_HOSTCONTROL, 1, &Reg);
	if (!NT_SUCCESS(Status)) return Status;
	
	Reg &= 0xff;
	Reg &= ~SDIOHCR_HOSTCONTROL_4BIT;
	if (BusWidth == 4) Reg |= SDIOHCR_HOSTCONTROL_4BIT;
	
	return SdmcpWriteRegister(SDIOHCR_HOSTCONTROL, 1, Reg);
}

static NTSTATUS SdmcpGetCsd(void) {
	NTSTATUS Status = SdmcpSendCommandEx(SDIO_CMD_SENDCSD, SDIO_TYPE_CMD, SDIO_RESPONSE_R2, s_SdmcRca << 16, 0, 0, NULL, s_SdmcCsd, sizeof(s_SdmcCsd));
	if (NT_SUCCESS(Status)) endian_swap64(s_SdmcCsd, s_SdmcCsd, sizeof(s_SdmcCsd));
	return Status;
}

static NTSTATUS SdmcpGetCid(void) {
	NTSTATUS Status = SdmcpSendCommandEx(SDIO_CMD_ALL_SENDCID, 0, SDIO_RESPONSE_R2, s_SdmcRca << 16, 0, 0, NULL, s_SdmcCid, sizeof(s_SdmcCid));
	if (NT_SUCCESS(Status)) endian_swap64(s_SdmcCid, s_SdmcCid, sizeof(s_SdmcCid));
	return Status;
}

static NTSTATUS SdmcpIopReOpen(void) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	if (s_hIosSdmc != IOS_HANDLE_INVALID) {
		Status = HalIopClose(s_hIosSdmc);
		if (!NT_SUCCESS(Status)) return Status;
		s_hIosSdmc = IOS_HANDLE_INVALID;
	}
	return HalIopOpen(sc_SdmcDev, IOSOPEN_READ, &s_hIosSdmc);
}

static NTSTATUS SdmcpInitIoEx(void) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	IOS_SDMC_RESPONSE Response;
	do {
		// Reset the sdmmc block.
		Status = SdmcpWriteRegister(SDIOHCR_SOFTWARERESET, 1, 7);
		if (!NT_SUCCESS(Status)) break;
		Status = SdmcpWaitRegister(SDIOHCR_SOFTWARERESET, 1, TRUE, 7);
		if (!NT_SUCCESS(Status)) break;
		
		// Initialise interrupts.
		Status = SdmcpWriteRegister(0x34, 4, 0x13f00c3);
		if (!NT_SUCCESS(Status)) break;
		Status = SdmcpWriteRegister(0x38, 4, 0x13f00c3);
		if (!NT_SUCCESS(Status)) break;
		
		// Enable power.
		s_SdmcIsHighCapacity = TRUE;
		Status = SdmcpWriteRegister(SDIOHCR_POWERCONTROL, 1, 0xe);
		if (!NT_SUCCESS(Status)) break;
		Status = SdmcpWriteRegister(SDIOHCR_POWERCONTROL, 1, 0xf);
		if (!NT_SUCCESS(Status)) break;
		
		// Enable internal clock.
		Status = SdmcpWriteRegister(SDIOHCR_CLOCKCONTROL, 2, 0);
		if (!NT_SUCCESS(Status)) break;
		Status = SdmcpWriteRegister(SDIOHCR_CLOCKCONTROL, 2, 0x101);
		if (!NT_SUCCESS(Status)) break;
		// Wait until it gets stable.
		Status = SdmcpWaitRegister(SDIOHCR_CLOCKCONTROL, 2, FALSE, 2);
		if (!NT_SUCCESS(Status)) break;
		// Enable SD clock.
		Status = SdmcpWriteRegister(SDIOHCR_CLOCKCONTROL, 2, 0x107);
		if (!NT_SUCCESS(Status)) break;
		
		// Setup timeout.
		Status = SdmcpWriteRegister(SDIOHCR_TIMEOUTCONTROL, 1, SDIO_DEFAULT_TIMEOUT);
		if (!NT_SUCCESS(Status)) break;
		
		// SDHC init
		Status = SdmcpSendCommand(
			SDIO_CMD_GOIDLE,
			SDIO_TYPE_NONE,
			SDIO_RESPONSE_NONE,
			0, 0, 0, NULL, NULL
		);
		if (!NT_SUCCESS(Status)) break;
		Status = SdmcpSendCommand(
			SDIO_CMD_SENDIFCOND,
			SDIO_TYPE_NONE,
			SDIO_RESPONSE_R6,
			0x1aa,
			0, 0, NULL, &Response
		);
		if (!NT_SUCCESS(Status)) break;
		if ((Response.Field0 & 0xFF) != 0xAA) break;
		
		BOOLEAN Success = FALSE;
		for (ULONG Try = 0; Try < 10; Try++) {
			if (Try != 0) {
				KeDelayExecutionThread(KernelMode, FALSE, &s_Timeout);
			}
			Status = SdmcpSendCommand(
				SDIO_CMD_APPCMD,
				SDIO_TYPE_CMD,
				SDIO_RESPONSE_R1,
				0, 0, 0, NULL, NULL
			);
			if (!NT_SUCCESS(Status)) break;
			Status = SdmcpSendCommand(
				SDIO_ACMD_SENDOPCOND,
				SDIO_TYPE_NONE,
				SDIO_RESPONSE_R3,
				0x40300000,
				0, 0, NULL, &Response
			);
			if (!NT_SUCCESS(Status)) break;
			if ((Response.Field0 & BIT(31)) != 0) {
				Success = TRUE;
				break;
			}
		}
		
		if (Success == FALSE) break;
		
		// BUGBUG: SDv2 cards which are not high capacity won't work
		// ...but how many of those actually exist?
		s_SdmcIsHighCapacity = (Response.Field0 & BIT(30)) != 0;
		
		Status = SdmcpGetCid();
		if (!NT_SUCCESS(Status)) break;
		Status = SdmcpGetRca();
		if (!NT_SUCCESS(Status)) break;
		return STATUS_SUCCESS;	
	} while (FALSE);
	
	SdmcpWriteRegister(SDIOHCR_SOFTWARERESET, 1, 7);
	SdmcpWaitRegister(SDIOHCR_SOFTWARERESET, 1, TRUE, 7);
	
	SdmcpIopReOpen();
	return Status;
}

static NTSTATUS SdmcpInitIo(void) {
	NTSTATUS Status = SdmcpResetCard();
	if (!NT_SUCCESS(Status)) return Status;
	ULONG SdmcStatus;
	Status = SdmcpGetStatus(&SdmcStatus);
	if (!NT_SUCCESS(Status)) return Status;
	
	if ((SdmcStatus & SDIO_STATUS_CARD_INSERTED) == 0)
		return STATUS_DEVICE_NOT_READY;
	
	if ((SdmcStatus & SDIO_TYPE_MEMORY) == 0) {
		// IOS doesn't know what this sdmmc device is.
		// Clean up by closing and reopening the handle.
		Status = SdmcpIopReOpen();
		if (!NT_SUCCESS(Status)) return Status;
		Status = SdmcpInitIoEx();
		if (!NT_SUCCESS(Status)) return Status;
	}
	else {
		s_SdmcIsHighCapacity = (SdmcStatus & SDIO_TYPE_SDHC) != 0;
	}
	
	Status = SdmcpIoSetBusWidth(4);
	if (!NT_SUCCESS(Status)) return Status;
	Status = SdmcpSetClock(1);
	if (!NT_SUCCESS(Status)) return Status;
	Status = SdmcpSelect();
	if (!NT_SUCCESS(Status)) return Status;
	Status = SdmcpSetBlockLength(SDMC_SECTOR_SIZE);
	if (NT_SUCCESS(Status)) {
		Status = SdmcpSetBusWidth(4);
	}
	SdmcpDeSelect();
	if (!NT_SUCCESS(Status)) return Status;
	
	s_SdmcIsInitialised = TRUE;
	return STATUS_SUCCESS;
}

NTSTATUS SdmcFinalise(void) {
	if (s_hIosSdmc != IOS_HANDLE_INVALID) {
		NTSTATUS Status = HalIopClose(s_hIosSdmc);
		if (!NT_SUCCESS(Status)) return Status;
		s_hIosSdmc = IOS_HANDLE_INVALID;
	}
	s_SdmcIsInitialised = FALSE;
	return STATUS_SUCCESS;
}

NTSTATUS SdmcStartup(void) {
	if (s_SdmcIsInitialised != FALSE) return STATUS_SUCCESS;
	
	if (s_SdmcDmaBuffer == NULL) {
		// Map the DMA buffer
		PHYSICAL_ADDRESS PhysAddr;
		PhysAddr.QuadPart = SDMC_BUFFER_PHYS_START;
		s_SdmcDmaBuffer = MmMapIoSpace(PhysAddr, SDMC_BUFFER_LENGTH, FALSE);
		if (s_SdmcDmaBuffer == NULL) {
			HalDisplayString("SDMC: could not map DMA buffer\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		
		// Initialise the bitmap.
		RtlInitializeBitMap(&s_SdmcDmaMap, s_SdmcDmaMapData, sizeof(s_SdmcDmaMap) * 8);
		
		// Initialise the spinlock.
		KeInitializeSpinLock(&s_SdmcDmaMapLock);
		
		KeInitializeDeviceQueue(&s_SdmcLockQueue);
		KeInitializeEvent(&s_SdmcReadyEvent, SynchronizationEvent, TRUE);
#if 0
		// Initialise the timer and DPC.
		KeInitializeDpc(&s_SdmcDpc, SdmcpTimerCallback, NULL);
		KeInitializeTimer(&s_SdmcTimer);
#endif

		// Initialise the byteswap DPCs.
		for (ULONG i = 0; i < COUNT_COPY_DPC; i++) {
			KeInitializeDpc(&s_DpcCopy[i], SdmcpCopyDpc, NULL);
			KeSetTargetProcessorDpc(&s_DpcCopy[i], 0);
		}
	}
#if 0
	if (s_AsyncContext == NULL) {
		s_AsyncContext = ExAllocatePool(NonPagedPool, sizeof(*s_AsyncContext));
		if (s_AsyncContext == NULL) {
			HalDisplayString("SDMC: could not allocate async context\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}
#endif
	
	CCHAR Buffer[512];
	NTSTATUS Status = SdmcpIopReOpen();
	if (!NT_SUCCESS(Status)) {
		_snprintf(Buffer, sizeof(Buffer), "SDMC: IOS_Open failed %08x\n", Status);
		HalDisplayString(Buffer);
		return Status;
	}
	
	Status = SdmcpInitIo();
	if (!NT_SUCCESS(Status)) {
		SdmcFinalise();
		_snprintf(Buffer, sizeof(Buffer), "SDMC: InitIo failed %08x\n", Status);
		HalDisplayString(Buffer);
		return Status;
	}
	
	return STATUS_SUCCESS;
}

static void SdmcpSectorIoFreeMapBuffer(PSDMC_LOCK_CONTEXT Context) {
	if (Context->DmaBuffer == NULL) return;
	KeAcquireSpinLockAtDpcLevel(&s_SdmcDmaMapLock);
	RtlClearBits(&s_SdmcDmaMap, Context->BufferPage, 1);
	Context->DmaBuffer = NULL;
	KeReleaseSpinLockFromDpcLevel(&s_SdmcDmaMapLock);
}

static void SdmcpReadSectorsLockedAsync(NTSTATUS Status, ULONG Result, PSDMC_LOCK_CONTEXT Context);

static void SdmcpSectorIoAsyncDeSelect(NTSTATUS Status, PSDMC_LOCK_CONTEXT Context) {
	// Set the returning status.
	Context->Status = Status;
		
	// Deselect the SD card.
	Context->State = LOCK_STATE_FINISHED;
	Status = SdmcpDeSelectAsync((IOP_CALLBACK)SdmcpReadSectorsLockedAsync, Context);
	if (!NT_SUCCESS(Status)) {
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	}
}

static void SdmcpReadSectorsLockedAsync(NTSTATUS Status, ULONG Result, PSDMC_LOCK_CONTEXT Context) {
	// Async is used on a multiprocessor system, reading into MDL.
	// This ensures all accesses through an MDL do use CPU 0 exclusively, which is where all IOP requests end up.
	if (Context->State == LOCK_STATE_SELECT) {
		// First SdmcpSelect async. On success, the callback will execute on CPU 0 in DPC context.
		Context->State = LOCK_STATE_FIRST_PAGE;
		Status = SdmcpSelectAsync((IOP_CALLBACK)SdmcpReadSectorsLockedAsync, Context);
		if (!NT_SUCCESS(Status)) {
			Context->Status = Status;
			KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
		}
		return;
	}
	
	if (Context->State == LOCK_STATE_FINISHED) {
		// Callback from final SdmcpDeSelectAsync.
		// Assume Context->Status was already set in a previous callback.
		// Set the finalise event and return.
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
		return;
	}
	
	if (!NT_SUCCESS(Status)) {
		// Previous call did not succeed.
#if 0
		char Buffer[1024];
		_snprintf(Buffer, sizeof(Buffer), "SDMC: Read failed, state %d, status %08x, result %d\n", Context->State, Status, Result);
		HalDisplayString(Buffer);
#endif
		
		// Free the map buffer.
		SdmcpSectorIoFreeMapBuffer(Context);
		
		SdmcpSectorIoAsyncDeSelect(Status, Context);
		return;
	}
	
	
	PUCHAR Pointer = (PUCHAR)Context->Buffer;
	if (Context->State == LOCK_STATE_FIRST_PAGE || Context->State == LOCK_STATE_NEXT_PAGE || Context->State == LOCK_STATE_LAST_PAGE) {
		if (Context->State == LOCK_STATE_FIRST_PAGE) {
			// Executing on CPU 0.
			// If caller passed an MDL, ensure that it is mapped.
			if (Context->Mdl != NULL) {
				PUCHAR MdlBuffer = (PUCHAR)MmGetSystemAddressForMdl(Context->Mdl);
				if (MdlBuffer == NULL) {
					SdmcpSectorIoAsyncDeSelect(STATUS_UNSUCCESSFUL, Context);
					return;
				}
				
				// MDL is mapped. Fix the buffer.
				Context->Buffer = (PVOID)&MdlBuffer[(ULONG)Context->Buffer];
				Pointer = (PUCHAR)Context->Buffer;
			}
			
			if (Context->DmaBuffer == NULL) {
				// Allocate a clear map buffer.
				KeAcquireSpinLockAtDpcLevel(&s_SdmcDmaMapLock);
				ULONG BufferPage = RtlFindClearBitsAndSet(&s_SdmcDmaMap, 1, 0);
				KeReleaseSpinLockFromDpcLevel(&s_SdmcDmaMapLock);
				if (BufferPage == 0xFFFFFFFF) {
					SdmcpSectorIoAsyncDeSelect(STATUS_INSUFFICIENT_RESOURCES, Context);
					return;
				}
				Context->DmaBuffer = (PUCHAR)s_SdmcDmaBuffer + (BufferPage * PAGE_SIZE);
				Context->BufferPage = BufferPage;
			}
		} else {
			// Swap64 from the map buffer into the original buffer.
			ULONG IoCount = Context->IoCount;
			if (((ULONG)Pointer & 7) == 0) {
				// Pointer is 64-bit aligned, swap from the DMA buffer copying into the buffer.
				endian_swap64(Pointer, Context->DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
			}
			else {
				endian_swap64(Context->DmaBuffer, Context->DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
				RtlCopyMemory(Pointer, Context->DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
			}
			sync_before_exec(Pointer, SDMC_SECTOR_SIZE * IoCount);
			
			Pointer += SDMC_SECTOR_SIZE * IoCount;
			Context->Sector += IoCount;
			Context->Count -= IoCount;
		}
		
		if (Context->State == LOCK_STATE_LAST_PAGE || Context->Count == 0) {
			// Free the map buffer.
			SdmcpSectorIoFreeMapBuffer(Context);
			
			SdmcpSectorIoAsyncDeSelect(Status, Context);
			return;
		}
		
		// Calculate the parameters for the next read operation.
		ULONG Offset = Context->Sector;
		if (s_SdmcIsHighCapacity == FALSE) Offset *= SDMC_SECTOR_SIZE;
		ULONG IoCount = SDMC_SECTORS_IN_PAGE;
		if (Context->Count < SDMC_SECTORS_IN_PAGE) IoCount = Context->Count;
		Context->IoCount = IoCount;
		Context->Buffer = Pointer;
		
		if (IoCount == Context->Count) Context->State = LOCK_STATE_LAST_PAGE;
		else Context->State = LOCK_STATE_NEXT_PAGE;
		
		Status = SdmcpSendCommandAsync(
			SDIO_CMD_READMULTIBLOCK,
			SDIO_TYPE_CMD,
			SDIO_RESPONSE_R1,
			Offset,
			IoCount,
			SDMC_SECTOR_SIZE,
			Context->DmaBuffer,
			(IOP_CALLBACK)SdmcpReadSectorsLockedAsync,
			Context
		);
		
		if (!NT_SUCCESS(Status)) {
			// Previous call did not succeed.
			
			// Free the map buffer.
			SdmcpSectorIoFreeMapBuffer(Context);
			
			SdmcpSectorIoAsyncDeSelect(Status, Context);
			return;
		}
		
		return;
	}
	
	// Unknown state?
	// Free the map buffer, if needed.
	SdmcpSectorIoFreeMapBuffer(Context);
	
	SdmcpSectorIoAsyncDeSelect(STATUS_UNSUCCESSFUL, Context);
}

static NTSTATUS SdmcpReadSectorsLockedSync(ULONG Sector, ULONG NumSector, PVOID Buffer, PMDL Mdl) {
	// If MDL is non-null, fix up the buffer.
	if (Mdl != NULL) {
		PUCHAR MdlBuffer = (PUCHAR)MmGetSystemAddressForMdl(Mdl);
		if (MdlBuffer == NULL) return STATUS_UNSUCCESSFUL;
		Buffer = (PVOID)&MdlBuffer[(ULONG)Buffer];
	} else if (Buffer == NULL) return STATUS_INVALID_PARAMETER;
	
	NTSTATUS Status = SdmcpSelect();
	if (!NT_SUCCESS(Status)) {
		return Status;
	}
	
	ULONG BufferPage = 0xFFFFFFFF;
	PVOID DmaBuffer = NULL;
	
	// Read up to 16 sectors at a time, into the DMA buffer.
	PUCHAR Pointer = (PUCHAR)Buffer;
	while (NumSector != 0) {
		ULONG Offset = Sector;
		if (s_SdmcIsHighCapacity == FALSE) Offset *= SDMC_SECTOR_SIZE;
		ULONG IoCount = SDMC_SECTORS_IN_PAGE;
		if (NumSector < SDMC_SECTORS_IN_PAGE) IoCount = NumSector;
#if 0 // Must go through map buffer for swapping
		// If the operation is not spanning pages,
		// then we can read directly into the provided buffer.
		BOOLEAN OnePage = (((ULONG)Pointer & (0x20 - 1)) == 0);
		if (OnePage) {
			ULONG Length = SDMC_SECTOR_SIZE * IoCount;
			ULONG End = (ULONG)Pointer + Length - 1;
			ULONG PageStart = (ULONG)Pointer & ~(PAGE_SIZE - 1);
			ULONG PageEnd = End & ~(PAGE_SIZE - 1);
			OnePage = PageStart == PageEnd;
		}
#endif
		if (DmaBuffer == NULL) {
			// Allocate a clear map buffer.
			KIRQL OldIrql;
			KeAcquireSpinLock(&s_SdmcDmaMapLock, &OldIrql);
			BufferPage = RtlFindClearBitsAndSet(&s_SdmcDmaMap, 1, 0);
			KeReleaseSpinLock(&s_SdmcDmaMapLock, OldIrql);
			if (BufferPage == 0xFFFFFFFF) {
				Status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			DmaBuffer = (PUCHAR)s_SdmcDmaBuffer + (BufferPage * PAGE_SIZE);
		}
		
		Status = SdmcpSendCommand(
			SDIO_CMD_READMULTIBLOCK,
			SDIO_TYPE_CMD,
			SDIO_RESPONSE_R1,
			Offset,
			IoCount,
			SDMC_SECTOR_SIZE,
			DmaBuffer,
			NULL
		);
		if (!NT_SUCCESS(Status)) {
			break;
		}
		
		// Swap64 from the map buffer into the original buffer.
		if (((ULONG)Pointer & 7) == 0) {
			// Pointer is 64-bit aligned, swap from the DMA buffer copying into the buffer.
			endian_swap64(Pointer, DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
		}
		else {
			endian_swap64(DmaBuffer, DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
			RtlCopyMemory(Pointer, DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
		}
		sync_before_exec(Pointer, SDMC_SECTOR_SIZE * IoCount);
		Pointer += SDMC_SECTOR_SIZE * IoCount;
		Sector += IoCount;
		NumSector -= IoCount;
	}
	
	// Free the map buffer.
	if (DmaBuffer != NULL) {
		KIRQL OldIrql;
		KeAcquireSpinLock(&s_SdmcDmaMapLock, &OldIrql);
		RtlClearBits(&s_SdmcDmaMap, BufferPage, 1);
		KeReleaseSpinLock(&s_SdmcDmaMapLock, OldIrql);
	}
	
	SdmcpDeSelect();
	return Status;
}

static void SdmcpReadSectorsLocked(PSDMC_LOCK_CONTEXT Context) {
	#if 0
	if (*KeNumberProcessors > 1) {
		// Multiprocessor system.
		// Start the asynchronous operation by CPU 0, and wait for it to complete.
		SdmcpReadSectorsLockedAsync(STATUS_SUCCESS, 0, Context);
		KeWaitForSingleObject( &Context->Event, Executive, KernelMode, FALSE, NULL);
		return;
	}
	#endif
	Context->Status = SdmcpReadSectorsLockedSync(Context->Sector, Context->Count, Context->Buffer, Context->Mdl);
	KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
}

NTSTATUS SdmcReadSectors(ULONG Sector, ULONG NumSector, PVOID Buffer, PMDL Mdl) {
	if (Mdl == NULL && Buffer == NULL) return STATUS_INVALID_PARAMETER;
	if (Mdl != NULL && (ULONG)Buffer >= Mdl->ByteCount) return STATUS_INVALID_PARAMETER;
	if (NumSector == 0) return STATUS_SUCCESS;
	
	PSDMC_LOCK_CONTEXT Context = SdmcpGetStateContext();
	if (Context == NULL) return STATUS_INSUFFICIENT_RESOURCES;
	
	Context->Sector = Sector;
	Context->Count = NumSector;
	Context->Buffer = Buffer;
	Context->Mdl = Mdl;
	
	NTSTATUS Status = SdmcpLockController(SdmcpReadSectorsLocked, Context);
	if (!NT_SUCCESS(Status)) {
		SdmcpReleaseStateContext(Context);
		return Status;
	}
	
	KeWaitForSingleObject( &Context->Event, Executive, KernelMode, FALSE, NULL);
	Status = Context->Status;
	SdmcpReleaseStateContext(Context);
	return Status;
}

static void SdmcpWriteSectorsLockedAsync(NTSTATUS Status, ULONG Result, PSDMC_LOCK_CONTEXT Context) {
	// Async is used on a multiprocessor system, writing from MDL.
	// This ensures all accesses through an MDL do use CPU 0 exclusively, which is where all IOP requests end up.
	if (Context->State == LOCK_STATE_SELECT) {
		// First SdmcpSelect async. On success, the callback will execute on CPU 0 in DPC context.
		Context->State = LOCK_STATE_FIRST_PAGE;
		Status = SdmcpSelectAsync((IOP_CALLBACK)SdmcpWriteSectorsLockedAsync, Context);
		if (!NT_SUCCESS(Status)) {
			Context->Status = Status;
			KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
		}
		return;
	}
	
	if (Context->State == LOCK_STATE_FINISHED) {
		// Callback from final SdmcpDeSelectAsync.
		// Should never get here, as the read implementation is used instead (it's the same, for both read and write)
		// Assume Context->Status was already set in a previous callback.
		// Set the finalise event and return.
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
		return;
	}
	
	if (!NT_SUCCESS(Status)) {
		// Previous call did not succeed.
		
		// Free the map buffer.
		SdmcpSectorIoFreeMapBuffer(Context);
		
		SdmcpSectorIoAsyncDeSelect(Status, Context);
		return;
	}
	
	
	PUCHAR Pointer = (PUCHAR)Context->Buffer;
	if (Context->State == LOCK_STATE_FIRST_PAGE || Context->State == LOCK_STATE_NEXT_PAGE || Context->State == LOCK_STATE_LAST_PAGE) {
		if (Context->State == LOCK_STATE_FIRST_PAGE) {
			// Executing on CPU 0.
			// If caller passed an MDL, ensure that it is mapped.
			if (Context->Mdl != NULL) {
				PUCHAR MdlBuffer = (PUCHAR)MmGetSystemAddressForMdl(Context->Mdl);
				if (MdlBuffer == NULL) {
					SdmcpSectorIoAsyncDeSelect(STATUS_UNSUCCESSFUL, Context);
					return;
				}
				
				// MDL is mapped. Fix the buffer.
				Context->Buffer = (PVOID)&MdlBuffer[(ULONG)Context->Buffer];
				Pointer = (PUCHAR)Context->Buffer;
			}
			
			if (Context->DmaBuffer == NULL) {
				// Allocate a clear map buffer.
				KeAcquireSpinLockAtDpcLevel(&s_SdmcDmaMapLock);
				ULONG BufferPage = RtlFindClearBitsAndSet(&s_SdmcDmaMap, 1, 0);
				KeReleaseSpinLockFromDpcLevel(&s_SdmcDmaMapLock);
				if (BufferPage == 0xFFFFFFFF) {
					SdmcpSectorIoAsyncDeSelect(STATUS_INSUFFICIENT_RESOURCES, Context);
					return;
				}
				Context->DmaBuffer = (PUCHAR)s_SdmcDmaBuffer + (BufferPage * PAGE_SIZE);
				Context->BufferPage = BufferPage;
			}
		} else {
			ULONG IoCount = Context->IoCount;
			Pointer += SDMC_SECTOR_SIZE * IoCount;
			Context->Sector += IoCount;
			Context->Count -= IoCount;
		}
		
		if (Context->State == LOCK_STATE_LAST_PAGE || Context->Count == 0) {
			// Free the map buffer.
			SdmcpSectorIoFreeMapBuffer(Context);
			
			SdmcpSectorIoAsyncDeSelect(Status, Context);
			return;
		}
		
		// Calculate the parameters for the next read operation.
		ULONG Offset = Context->Sector;
		if (s_SdmcIsHighCapacity == FALSE) Offset *= SDMC_SECTOR_SIZE;
		ULONG IoCount = SDMC_SECTORS_IN_PAGE;
		if (Context->Count < SDMC_SECTORS_IN_PAGE) IoCount = Context->Count;
		Context->IoCount = IoCount;
		Context->Buffer = Pointer;
		
		// Swap64 from the original buffer into the map buffer.
		if (((ULONG)Pointer & 7) == 0) {
			// Pointer is 64-bit aligned, swap from the pointer directly into the DMA buffer
			endian_swap64(Context->DmaBuffer, Pointer, SDMC_SECTOR_SIZE * IoCount);
		}
		else {
			// Not 64-bit aligned, copy then swap.
			RtlCopyMemory(Context->DmaBuffer, Pointer, SDMC_SECTOR_SIZE * IoCount);
			endian_swap64(Context->DmaBuffer, Context->DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
		}
		// Cache invalidation not needed as IOP PXI driver does that.
		
		if (IoCount == Context->Count) Context->State = LOCK_STATE_LAST_PAGE;
		else Context->State = LOCK_STATE_NEXT_PAGE;
		
		Status = SdmcpSendCommandAsync(
			SDIO_CMD_WRITEMULTIBLOCK,
			SDIO_TYPE_CMD,
			SDIO_RESPONSE_R1,
			Offset,
			IoCount,
			SDMC_SECTOR_SIZE,
			Context->DmaBuffer,
			(IOP_CALLBACK)SdmcpWriteSectorsLockedAsync,
			Context
		);
		
		if (!NT_SUCCESS(Status)) {
			// Previous call did not succeed.
			
			// Free the map buffer.
			SdmcpSectorIoFreeMapBuffer(Context);
			
			SdmcpSectorIoAsyncDeSelect(Status, Context);
			return;
		}
		
		return;
	}
	
	// Unknown state?
	// Free the map buffer, if needed.
	SdmcpSectorIoFreeMapBuffer(Context);
	
	SdmcpSectorIoAsyncDeSelect(STATUS_UNSUCCESSFUL, Context);
}

static NTSTATUS SdmcpWriteSectorsLockedSync(ULONG Sector, ULONG NumSector, const void* Buffer, PMDL Mdl) {
	// If MDL is non-null, fix up the buffer.
	if (Mdl != NULL) {
		PUCHAR MdlBuffer = (PUCHAR)MmGetSystemAddressForMdl(Mdl);
		if (MdlBuffer == NULL) return STATUS_UNSUCCESSFUL;
		Buffer = (PVOID)&MdlBuffer[(ULONG)Buffer];
	} else if (Buffer == NULL) return STATUS_INVALID_PARAMETER;
	
	NTSTATUS Status = SdmcpSelect();
	if (!NT_SUCCESS(Status)) return Status;
	
	ULONG BufferPage = 0xFFFFFFFF;
	PVOID DmaBuffer = NULL;
	
	PUCHAR Pointer = (PUCHAR)Buffer;
	while (NumSector != 0) {
		ULONG Offset = Sector;
		if (s_SdmcIsHighCapacity == FALSE) Offset *= SDMC_SECTOR_SIZE;
		ULONG IoCount = SDMC_SECTORS_IN_PAGE;
		if (NumSector < SDMC_SECTORS_IN_PAGE) IoCount = NumSector;
		
#if 0 // Must go through map buffer for swapping
		// If the operation is not spanning pages,
		// then we can write directly into the provided buffer.
		BOOLEAN OnePage = (((ULONG)Pointer & (0x20 - 1)) == 0);
		if (OnePage) {
			ULONG Length = SDMC_SECTOR_SIZE * IoCount;
			ULONG End = (ULONG)Pointer + Length - 1;
			ULONG PageStart = (ULONG)Pointer & ~(PAGE_SIZE - 1);
			ULONG PageEnd = End & ~(PAGE_SIZE - 1);
			OnePage = PageStart == PageEnd;
		}
#endif
		if (DmaBuffer == NULL) {
			// Allocate a clear map buffer.
			KIRQL OldIrql;
			KeAcquireSpinLock(&s_SdmcDmaMapLock, &OldIrql);
			BufferPage = RtlFindClearBitsAndSet(&s_SdmcDmaMap, 1, 0);
			KeReleaseSpinLock(&s_SdmcDmaMapLock, OldIrql);
			if (BufferPage == 0xFFFFFFFF) {
				Status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			DmaBuffer = (PUCHAR)s_SdmcDmaBuffer + (BufferPage * PAGE_SIZE);
		}
		
		if (((ULONG)Pointer & 7) == 0) {
			// Pointer is 64-bit aligned, swap from the pointer directly into the DMA buffer
			endian_swap64(DmaBuffer, Pointer, SDMC_SECTOR_SIZE * IoCount);
		}
		else {
			// Not 64-bit aligned, copy then swap.
			RtlCopyMemory(DmaBuffer, Pointer, SDMC_SECTOR_SIZE * IoCount);
			endian_swap64(DmaBuffer, DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
		}
		
		Status = SdmcpSendCommand(
			SDIO_CMD_WRITEMULTIBLOCK,
			SDIO_TYPE_CMD,
			SDIO_RESPONSE_R1,
			Offset,
			IoCount,
			SDMC_SECTOR_SIZE,
			DmaBuffer,
			NULL
		);
		if (!NT_SUCCESS(Status)) break;
		Pointer += SDMC_SECTOR_SIZE * IoCount;
		Sector += IoCount;
		NumSector -= IoCount;
	}
	
	// Free the map buffer.
	if (DmaBuffer != NULL) {
		KIRQL OldIrql;
		KeAcquireSpinLock(&s_SdmcDmaMapLock, &OldIrql);
		RtlClearBits(&s_SdmcDmaMap, BufferPage, 1);
		KeReleaseSpinLock(&s_SdmcDmaMapLock, OldIrql);
	}
	
	SdmcpDeSelect();
	return Status;
}

static void SdmcpWriteSectorsLocked(PSDMC_LOCK_CONTEXT Context) {
	#if 0
	if (*KeNumberProcessors > 1) {
		// Multiprocessor system.
		// Start the asynchronous operation by CPU 0, and wait for it to complete.
		SdmcpWriteSectorsLockedAsync(STATUS_SUCCESS, 0, Context);
		KeWaitForSingleObject( &Context->Event, Executive, KernelMode, FALSE, NULL);
		return;
	}
	#endif
	Context->Status = SdmcpWriteSectorsLockedSync(Context->Sector, Context->Count, Context->Buffer, Context->Mdl);
	KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
}

NTSTATUS SdmcWriteSectors(ULONG Sector, ULONG NumSector, const void* Buffer, PMDL Mdl) {
	if (Mdl == NULL && Buffer == NULL) return STATUS_INVALID_PARAMETER;
	if (Mdl != NULL && (ULONG)Buffer >= Mdl->ByteCount) return STATUS_INVALID_PARAMETER;
	if (NumSector == 0) return STATUS_SUCCESS;
	
	PSDMC_LOCK_CONTEXT Context = SdmcpGetStateContext();
	if (Context == NULL) return STATUS_INSUFFICIENT_RESOURCES;
	
	Context->Sector = Sector;
	Context->Count = NumSector;
	Context->Buffer = (PVOID)Buffer;
	Context->Mdl = Mdl;
	
	NTSTATUS Status = SdmcpLockController(SdmcpWriteSectorsLocked, Context);
	if (!NT_SUCCESS(Status)) {
		SdmcpReleaseStateContext(Context);
		return Status;
	}
	
	KeWaitForSingleObject( &Context->Event, Executive, KernelMode, FALSE, NULL);
	Status = Context->Status;
	SdmcpReleaseStateContext(Context);
	return Status;
}

NTSTATUS SdmcLowDiskRw(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	// Start the pending operation.
	Irp->IoStatus.Information = 0;
	IoMarkIrpPending(Irp);
	ULONG Key = 0;
	// Flush to cache.
	sync_before_exec_this_cpu(Irp, sizeof(*Irp) + sizeof(IO_STACK_LOCATION));
	IoStartPacket(DeviceObject, Irp, &Key, NULL);
	return STATUS_PENDING;
}

NTSTATUS SdmcLowDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG LenIn = Stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG LenOut = Stack->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG Key = 0;
	
	switch (Stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_SDMC_GET_STATUS:
		if (LenOut < sizeof(ULONG)) {
				Status = STATUS_INVALID_PARAMETER;
				break;
		}
		Irp->IoStatus.Information = 0;
		IoMarkIrpPending(Irp);
		sync_before_exec_this_cpu(Irp, sizeof(*Irp) + sizeof(IO_STACK_LOCATION));
		IoStartPacket(DeviceObject, Irp, &Key, NULL);
		return STATUS_PENDING;
	default:
		Status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

static void SdmcpLowFinishPacket(PSDMC_SEIZED_CONTEXT Context) {
	PSDMC_LOWLEVEL_EXTENSION Ext = (PSDMC_LOWLEVEL_EXTENSION)Context->DeviceObject->DeviceExtension;
	// Get the used variables from the context, following calls may overwrite them.
	PIRP Irp = Context->Irp;
	PDEVICE_OBJECT DeviceObject = Context->DeviceObject;
	PCONTROLLER_OBJECT ControllerObject = Context->DiskController;
	sync_before_exec_this_cpu(Irp, sizeof(*Irp));
	// Complete the IRP.
	IoCompleteRequest(Irp, IO_DISK_INCREMENT);
	// Free the controller, and let any pending IRPs proceed.
#if 0
	{
		char Buffer[1024];
		_snprintf(Buffer, sizeof(Buffer), "(%08x)\n", ControllerObject);
		HalDisplayString(Buffer);
	}
#endif
	IoFreeController(ControllerObject);
	// Start next IRP request.
	IoStartNextPacket(DeviceObject, FALSE);
}

static void SdmcpReadSectorsSeizedAsync(NTSTATUS Status, ULONG Result, PSDMC_SEIZED_CONTEXT Context);
static void SdmcpLowAsyncDeSelect(NTSTATUS Status, PSDMC_SEIZED_CONTEXT Context) {
	// Set the returning status.
	Context->Irp->IoStatus.Status = Status;
		
	// Deselect the SD card.
	Context->State = LOCK_STATE_FINISHED;
	Status = SdmcpDeSelectAsync((IOP_CALLBACK)SdmcpReadSectorsSeizedAsync, Context);
	if (!NT_SUCCESS(Status)) {
		SdmcpLowFinishPacket(Context);
	}
}

static void SdmcpLowFreeMapBuffer(PSDMC_SEIZED_CONTEXT Context) {
	if (Context->DmaBuffer == NULL) return;
	KeAcquireSpinLockAtDpcLevel(&s_SdmcDmaMapLock);
	RtlClearBits(&s_SdmcDmaMap, Context->BufferPage, 1);
	Context->DmaBuffer = NULL;
	KeReleaseSpinLockFromDpcLevel(&s_SdmcDmaMapLock);
}

static void SdmcpReadSectorsSeizedAsync(NTSTATUS Status, ULONG Result, PSDMC_SEIZED_CONTEXT Context) {
	// Async is used on a multiprocessor system, reading into MDL.
	// This ensures all accesses through an MDL do use CPU 0 exclusively, which is where all IOP requests end up.
	if (Context->State == LOCK_STATE_SELECT) {
		// First SdmcpSelect async. On success, the callback will execute on CPU 0 in DPC context.
		Context->State = LOCK_STATE_FIRST_PAGE;
		Status = SdmcpSelectAsync((IOP_CALLBACK)SdmcpReadSectorsSeizedAsync, Context);
		if (!NT_SUCCESS(Status)) {
			Context->Irp->IoStatus.Status = Status;
			SdmcpLowFinishPacket(Context);
		}
		return;
	}
	
	if (Context->State == LOCK_STATE_FINISHED) {
		// Callback from final SdmcpDeSelectAsync.
		// Assume Context->Status was already set in a previous callback.
		// Set the finalise event and return.
		SdmcpLowFinishPacket(Context);
		return;
	}
	
	if (!NT_SUCCESS(Status)) {
		// Previous call did not succeed.
#if 0
		char Buffer[1024];
		_snprintf(Buffer, sizeof(Buffer), "SDMC: Read failed, state %d, status %08x, result %d\n", Context->State, Status, Result);
		HalDisplayString(Buffer);
#endif
		
		// Free the map buffer.
		SdmcpLowFreeMapBuffer(Context);
		
		SdmcpLowAsyncDeSelect(Status, Context);
		return;
	}
	
	
	PUCHAR Pointer = (PUCHAR)Context->Buffer;
	if (Context->State == LOCK_STATE_FIRST_PAGE || Context->State == LOCK_STATE_NEXT_PAGE || Context->State == LOCK_STATE_LAST_PAGE) {
		if (Context->State == LOCK_STATE_FIRST_PAGE) {
			// Executing on CPU 0.
			// If caller passed an MDL, ensure that it is mapped.
			if (Context->Mdl != NULL) {
				PUCHAR MdlBuffer = (PUCHAR)MmGetSystemAddressForMdl(Context->Mdl);
				if (MdlBuffer == NULL) {
					SdmcpLowAsyncDeSelect(STATUS_UNSUCCESSFUL, Context);
					return;
				}
				
				// MDL is mapped. Fix the buffer.
				Context->Buffer = (PVOID)&MdlBuffer[(ULONG)Context->Buffer];
				Pointer = (PUCHAR)Context->Buffer;
			}
			
			if (Context->DmaBuffer == NULL) {
				// Allocate a clear map buffer.
				KeAcquireSpinLockAtDpcLevel(&s_SdmcDmaMapLock);
				ULONG BufferPage = RtlFindClearBitsAndSet(&s_SdmcDmaMap, 1, 0);
				KeReleaseSpinLockFromDpcLevel(&s_SdmcDmaMapLock);
				if (BufferPage == 0xFFFFFFFF) {
					SdmcpLowAsyncDeSelect(STATUS_INSUFFICIENT_RESOURCES, Context);
					return;
				}
				Context->DmaBuffer = (PUCHAR)s_SdmcDmaBuffer + (BufferPage * PAGE_SIZE);
				Context->BufferPage = BufferPage;
			}
		} else {
			// Swap64 from the map buffer into the original buffer.
			ULONG IoCount = Context->IoCount;
			if (((ULONG)Pointer & 7) == 0) {
				// Pointer is 64-bit aligned, swap from the DMA buffer copying into the buffer.
				endian_swap64(Pointer, Context->DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
			}
			else {
				endian_swap64(Context->DmaBuffer, Context->DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
				RtlCopyMemory(Pointer, Context->DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
			}
			sync_before_exec(Pointer, SDMC_SECTOR_SIZE * IoCount);
			
			Pointer += SDMC_SECTOR_SIZE * IoCount;
			Context->Sector += IoCount;
			Context->Count -= IoCount;
			Context->Irp->IoStatus.Information += IoCount;
		}
		
		if (Context->State == LOCK_STATE_LAST_PAGE || Context->Count == 0) {
			// Free the map buffer.
			SdmcpLowFreeMapBuffer(Context);
			
			SdmcpLowAsyncDeSelect(Status, Context);
			return;
		}
		
		// Calculate the parameters for the next read operation.
		ULONG Offset = Context->Sector;
		if (s_SdmcIsHighCapacity == FALSE) Offset *= SDMC_SECTOR_SIZE;
		ULONG IoCount = SDMC_SECTORS_IN_PAGE;
		if (Context->Count < SDMC_SECTORS_IN_PAGE) IoCount = Context->Count;
		Context->IoCount = IoCount;
		Context->Buffer = Pointer;
		
		if (IoCount == Context->Count) Context->State = LOCK_STATE_LAST_PAGE;
		else Context->State = LOCK_STATE_NEXT_PAGE;
		
		Status = SdmcpSendCommandAsync(
			SDIO_CMD_READMULTIBLOCK,
			SDIO_TYPE_CMD,
			SDIO_RESPONSE_R1,
			Offset,
			IoCount,
			SDMC_SECTOR_SIZE,
			Context->DmaBuffer,
			(IOP_CALLBACK)SdmcpReadSectorsSeizedAsync,
			Context
		);
		
		if (!NT_SUCCESS(Status)) {
			// Previous call did not succeed.
			
			// Free the map buffer.
			SdmcpLowFreeMapBuffer(Context);
			
			SdmcpLowAsyncDeSelect(Status, Context);
			return;
		}
		
		return;
	}
	
	// Unknown state?
	// Free the map buffer, if needed.
	SdmcpLowFreeMapBuffer(Context);
	
	SdmcpLowAsyncDeSelect(STATUS_UNSUCCESSFUL, Context);
}

static void SdmcpWriteSectorsSeizedAsync(NTSTATUS Status, ULONG Result, PSDMC_SEIZED_CONTEXT Context) {
	// Async is used on a multiprocessor system, writing from MDL.
	// This ensures all accesses through an MDL do use CPU 0 exclusively, which is where all IOP requests end up.
	if (Context->State == LOCK_STATE_SELECT) {
		// First SdmcpSelect async. On success, the callback will execute on CPU 0 in DPC context.
		Context->State = LOCK_STATE_FIRST_PAGE;
		Status = SdmcpSelectAsync((IOP_CALLBACK)SdmcpWriteSectorsSeizedAsync, Context);
		if (!NT_SUCCESS(Status)) {
			Context->Irp->IoStatus.Status = Status;
			SdmcpLowFinishPacket(Context);
		}
		return;
	}
	
	if (Context->State == LOCK_STATE_FINISHED) {
		// Callback from final SdmcpDeSelectAsync.
		// Should never get here, as the read implementation is used instead (it's the same, for both read and write)
		// Assume Context->Status was already set in a previous callback.
		// Set the finalise event and return.
		SdmcpLowFinishPacket(Context);
		return;
	}
	
	if (!NT_SUCCESS(Status)) {
		// Previous call did not succeed.
		
		// Free the map buffer.
		SdmcpLowFreeMapBuffer(Context);
		
		SdmcpLowAsyncDeSelect(Status, Context);
		return;
	}
	
	
	PUCHAR Pointer = (PUCHAR)Context->Buffer;
	if (Context->State == LOCK_STATE_FIRST_PAGE || Context->State == LOCK_STATE_NEXT_PAGE || Context->State == LOCK_STATE_LAST_PAGE) {
		if (Context->State == LOCK_STATE_FIRST_PAGE) {
			// Executing on CPU 0.
			// If caller passed an MDL, ensure that it is mapped.
			if (Context->Mdl != NULL) {
				PUCHAR MdlBuffer = (PUCHAR)MmGetSystemAddressForMdl(Context->Mdl);
				if (MdlBuffer == NULL) {
					SdmcpLowAsyncDeSelect(STATUS_UNSUCCESSFUL, Context);
					return;
				}
				
				// MDL is mapped. Fix the buffer.
				Context->Buffer = (PVOID)&MdlBuffer[(ULONG)Context->Buffer];
				Pointer = (PUCHAR)Context->Buffer;
			}
			
			if (Context->DmaBuffer == NULL) {
				// Allocate a clear map buffer.
				KeAcquireSpinLockAtDpcLevel(&s_SdmcDmaMapLock);
				ULONG BufferPage = RtlFindClearBitsAndSet(&s_SdmcDmaMap, 1, 0);
				KeReleaseSpinLockFromDpcLevel(&s_SdmcDmaMapLock);
				if (BufferPage == 0xFFFFFFFF) {
					SdmcpLowAsyncDeSelect(STATUS_INSUFFICIENT_RESOURCES, Context);
					return;
				}
				Context->DmaBuffer = (PUCHAR)s_SdmcDmaBuffer + (BufferPage * PAGE_SIZE);
				Context->BufferPage = BufferPage;
			}
		} else {
			ULONG IoCount = Context->IoCount;
			Pointer += SDMC_SECTOR_SIZE * IoCount;
			Context->Sector += IoCount;
			Context->Count -= IoCount;
			Context->Irp->IoStatus.Information += IoCount;
		}
		
		if (Context->State == LOCK_STATE_LAST_PAGE || Context->Count == 0) {
			// Free the map buffer.
			SdmcpLowFreeMapBuffer(Context);
			
			SdmcpLowAsyncDeSelect(Status, Context);
			return;
		}
		
		// Calculate the parameters for the next read operation.
		ULONG Offset = Context->Sector;
		if (s_SdmcIsHighCapacity == FALSE) Offset *= SDMC_SECTOR_SIZE;
		ULONG IoCount = SDMC_SECTORS_IN_PAGE;
		if (Context->Count < SDMC_SECTORS_IN_PAGE) IoCount = Context->Count;
		Context->IoCount = IoCount;
		Context->Buffer = Pointer;
		
		// Swap64 from the original buffer into the map buffer.
		if (((ULONG)Pointer & 7) == 0) {
			// Pointer is 64-bit aligned, swap from the pointer directly into the DMA buffer
			endian_swap64(Context->DmaBuffer, Pointer, SDMC_SECTOR_SIZE * IoCount);
		}
		else {
			// Not 64-bit aligned, copy then swap.
			RtlCopyMemory(Context->DmaBuffer, Pointer, SDMC_SECTOR_SIZE * IoCount);
			endian_swap64(Context->DmaBuffer, Context->DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
		}
		// Cache invalidation not needed as IOP PXI driver does that.
		
		if (IoCount == Context->Count) Context->State = LOCK_STATE_LAST_PAGE;
		else Context->State = LOCK_STATE_NEXT_PAGE;
		
		Status = SdmcpSendCommandAsync(
			SDIO_CMD_WRITEMULTIBLOCK,
			SDIO_TYPE_CMD,
			SDIO_RESPONSE_R1,
			Offset,
			IoCount,
			SDMC_SECTOR_SIZE,
			Context->DmaBuffer,
			(IOP_CALLBACK)SdmcpWriteSectorsSeizedAsync,
			Context
		);
		
		if (!NT_SUCCESS(Status)) {
			// Previous call did not succeed.
			
			// Free the map buffer.
			SdmcpLowFreeMapBuffer(Context);
			
			SdmcpLowAsyncDeSelect(Status, Context);
			return;
		}
		
		return;
	}
	
	// Unknown state?
	// Free the map buffer, if needed.
	SdmcpLowFreeMapBuffer(Context);
	
	SdmcpLowAsyncDeSelect(STATUS_UNSUCCESSFUL, Context);
}

void SdmcpReadSectorsArrSeizedAsync(NTSTATUS Status, ULONG Result, PSDMC_SECTARR_SEIZED_CONTEXT ContextArr) {
	// Async is used on a multiprocessor system, reading into MDL.
	// This ensures all accesses through an MDL do use CPU 0 exclusively, which is where all IOP requests end up.
	PSDMC_SEIZED_CONTEXT Context = &ContextArr->Base;
	
	if (Context->State == LOCK_STATE_STATUS) {
#if 0
		char Buffer[1024];
		_snprintf(Buffer, sizeof(Buffer), "SDMC: LowRead %08x(%d)\n", Context->Sector, ContextArr->Length);
		HalDisplayString(Buffer);
#endif
		sync_before_exec_this_cpu(Context->Irp, sizeof(*Context->Irp) + sizeof(IO_STACK_LOCATION));
		// Sdmc GetStatus. The callback will execute on CPU 0 in DPC context.
		Context->State = LOCK_STATE_SELECT;
		Status = HalIopIoctlAsyncDpc(
			s_hIosSdmc,
			IOCTL_SDIO_GETSTATUS,
			NULL,
			0,
			ContextArr->StatusPtr,
			sizeof(ULONG),
			IOCTL_SWAP_NONE,
			IOCTL_SWAP_NONE,
			(IOP_CALLBACK)SdmcpReadSectorsArrSeizedAsync,
			Context
		);
		if (!NT_SUCCESS(Status)) {
			Context->Irp->IoStatus.Status = Status;
			SdmcpLowFinishPacket(Context);
		}
		return;
	}
#if 0
	{
		char Buffer[1024];
		_snprintf(Buffer, sizeof(Buffer), "%d", Context->State);
		HalDisplayString(Buffer);
	}
#endif
	
	if (Context->State == LOCK_STATE_SELECT) {
		if (!NT_SUCCESS(Status)) {
			HalDisplayString("x\n");
			Context->Irp->IoStatus.Status = Status;
			SdmcpLowFinishPacket(Context);
			return;
		}
		// First SdmcpSelect async. On success, the callback will execute on CPU 0 in DPC context.
		// Check the GetStatus return first.
		ULONG CardStatus = ContextArr->StatusPtr[1];
		HalIopFree(ContextArr->StatusPtr);
		if ((CardStatus & SDIO_STATUS_CARD_INSERTED) == 0) {
			// Device not ready.
			Context->Irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
			SdmcpLowFinishPacket(Context);
			return;
		}
		if ((CardStatus & SDIO_STATUS_CARD_WRITEPROT) != 0) {
			// Write protect. This is read so it doesn't matter, but for write it would.
		}
		
		Context->State = LOCK_STATE_FIRST_PAGE;
		Status = SdmcpSelectAsync((IOP_CALLBACK)SdmcpReadSectorsArrSeizedAsync, Context);
		if (!NT_SUCCESS(Status)) {
			Context->Irp->IoStatus.Status = Status;
			SdmcpLowFinishPacket(Context);
		}
		return;
	}
	
	if (Context->State == LOCK_STATE_FINISHED) {
		// Callback from final SdmcpDeSelectAsync.
		// Assume Context->Status was already set in a previous callback.
		// Set the finalise event and return.
		SdmcpLowFinishPacket(Context);
		return;
	}
	
	if (!NT_SUCCESS(Status)) {
		// Previous call did not succeed.
#if 0
		char Buffer[1024];
		_snprintf(Buffer, sizeof(Buffer), "SDMC: Read failed, state %d, status %08x, result %d\n", Context->State, Status, Result);
		HalDisplayString(Buffer);
#endif
		
		// Free the map buffer.
		SdmcpLowFreeMapBuffer(Context);
		
		SdmcpLowAsyncDeSelect(Status, Context);
		return;
	}
	
	
	PUCHAR Pointer = (PUCHAR)Context->Buffer;
	if (Context->State == LOCK_STATE_FIRST_PAGE || Context->State == LOCK_STATE_NEXT_PAGE || Context->State == LOCK_STATE_LAST_PAGE) {
		if (Context->State == LOCK_STATE_FIRST_PAGE) {
			// Executing on CPU 0.
			// If caller passed an MDL, ensure that it is mapped.
			if (Context->Mdl != NULL) {
				PUCHAR MdlBuffer = (PUCHAR)MmGetSystemAddressForMdl(Context->Mdl);
				if (MdlBuffer == NULL) {
					SdmcpLowAsyncDeSelect(STATUS_UNSUCCESSFUL, Context);
					return;
				}
				
				// MDL is mapped. Fix the buffer.
				Context->Buffer = (PVOID)&MdlBuffer[(ULONG)Context->Buffer];
				Pointer = (PUCHAR)Context->Buffer;
			}
			
			if (Context->DmaBuffer == NULL) {
				// Allocate a clear map buffer.
				KeAcquireSpinLockAtDpcLevel(&s_SdmcDmaMapLock);
				ULONG BufferPage = RtlFindClearBitsAndSet(&s_SdmcDmaMap, 1, 0);
				KeReleaseSpinLockFromDpcLevel(&s_SdmcDmaMapLock);
				if (BufferPage == 0xFFFFFFFF) {
					SdmcpLowAsyncDeSelect(STATUS_INSUFFICIENT_RESOURCES, Context);
					return;
				}
				Context->DmaBuffer = (PUCHAR)s_SdmcDmaBuffer + (BufferPage * PAGE_SIZE);
				Context->BufferPage = BufferPage;
			}
		} else {
			// Swap64 from the map buffer into the original buffer.
			ULONG IoCount = Context->IoCount;
			if (((ULONG)Pointer & 7) == 0) {
				// Pointer is 64-bit aligned, swap from the DMA buffer copying into the buffer.
				endian_swap64(Pointer, Context->DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
			}
			else {
				endian_swap64(Context->DmaBuffer, Context->DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
				RtlCopyMemory(Pointer, Context->DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
			}
			sync_before_exec(Pointer, SDMC_SECTOR_SIZE * IoCount);
			
			Pointer += SDMC_SECTOR_SIZE * IoCount;
			Context->Sector += IoCount;
			Context->Count -= IoCount;
			Context->Irp->IoStatus.Information += (IoCount * SDMC_SECTOR_SIZE);
			ContextArr->Length -= IoCount;
		}
		
		if (Context->State == LOCK_STATE_LAST_PAGE || Context->Count == 0) {
			// This chunk is finished. Is the whole read request finished?
			if (ContextArr->Length == 0 || ContextArr->SectorTableRemaining == 0) {
				// Free the map buffer.
				SdmcpLowFreeMapBuffer(Context);
				
#if 0
				HalDisplayString("y\n");
#endif
				SdmcpLowAsyncDeSelect(Status, Context);
				return;
			}
			
			// Still data to read.
			Context->State = LOCK_STATE_NEXT_PAGE;
			ContextArr->Offset = 0;
			ContextArr->SectorTableEntry++;
			ContextArr->SectorTableRemaining--;
			Context->Sector = ContextArr->SectorTableEntry->sector;
			Context->Count = ContextArr->SectorTableEntry->count;
		}
		
		// Calculate the parameters for the next read operation.
		ULONG Offset = Context->Sector;
		if (s_SdmcIsHighCapacity == FALSE) Offset *= SDMC_SECTOR_SIZE;
		ULONG IoCount = SDMC_SECTORS_IN_PAGE;
		if (Context->Count < SDMC_SECTORS_IN_PAGE) IoCount = Context->Count;
		Context->IoCount = IoCount;
		Context->Buffer = Pointer;
		
		if (IoCount == Context->Count) Context->State = LOCK_STATE_LAST_PAGE;
		else Context->State = LOCK_STATE_NEXT_PAGE;
		
		Status = SdmcpSendCommandAsync(
			SDIO_CMD_READMULTIBLOCK,
			SDIO_TYPE_CMD,
			SDIO_RESPONSE_R1,
			Offset,
			IoCount,
			SDMC_SECTOR_SIZE,
			Context->DmaBuffer,
			(IOP_CALLBACK)SdmcpReadSectorsArrSeizedAsync,
			Context
		);
		
		if (!NT_SUCCESS(Status)) {
			// Previous call did not succeed.
			
			// Free the map buffer.
			SdmcpLowFreeMapBuffer(Context);
			
			SdmcpLowAsyncDeSelect(Status, Context);
			return;
		}
		
		return;
	}
	
	// Unknown state?
	// Free the map buffer, if needed.
	SdmcpLowFreeMapBuffer(Context);
	
	SdmcpLowAsyncDeSelect(STATUS_UNSUCCESSFUL, Context);
}

void SdmcpWriteSectorsArrSeizedAsync(NTSTATUS Status, ULONG Result, PSDMC_SECTARR_SEIZED_CONTEXT ContextArr) {
	// Async is used on a multiprocessor system, writing from MDL.
	// This ensures all accesses through an MDL do use CPU 0 exclusively, which is where all IOP requests end up.
	PSDMC_SEIZED_CONTEXT Context = &ContextArr->Base;
	
	if (Context->State == LOCK_STATE_STATUS) {
		// Sdmc GetStatus. The callback will execute on CPU 0 in DPC context.
		sync_before_exec_this_cpu(Context->Irp, sizeof(*Context->Irp) + sizeof(IO_STACK_LOCATION));
		Context->State = LOCK_STATE_SELECT;
		Status = HalIopIoctlAsyncDpc(
			s_hIosSdmc,
			IOCTL_SDIO_GETSTATUS,
			NULL,
			0,
			ContextArr->StatusPtr,
			sizeof(ULONG),
			IOCTL_SWAP_NONE,
			IOCTL_SWAP_NONE,
			(IOP_CALLBACK)SdmcpWriteSectorsArrSeizedAsync,
			Context
		);
		if (!NT_SUCCESS(Status)) {
			Context->Irp->IoStatus.Status = Status;
			SdmcpLowFinishPacket(Context);
		}
		return;
	}
	
	if (Context->State == LOCK_STATE_SELECT) {
		if (!NT_SUCCESS(Status)) {
			Context->Irp->IoStatus.Status = Status;
			SdmcpLowFinishPacket(Context);
			return;
		}
		// First SdmcpSelect async. On success, the callback will execute on CPU 0 in DPC context.
		// Check the GetStatus return first.
		ULONG CardStatus = ContextArr->StatusPtr[1];
		HalIopFree(ContextArr->StatusPtr);
		if ((CardStatus & SDIO_STATUS_CARD_INSERTED) == 0) {
			// Device not ready.
			Context->Irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
			SdmcpLowFinishPacket(Context);
			return;
		}
		if ((CardStatus & SDIO_STATUS_CARD_WRITEPROT) != 0) {
			// Write protected.
			Context->Irp->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
			SdmcpLowFinishPacket(Context);
			return;
		}
		
		Context->State = LOCK_STATE_FIRST_PAGE;
		Status = SdmcpSelectAsync((IOP_CALLBACK)SdmcpWriteSectorsArrSeizedAsync, Context);
		if (!NT_SUCCESS(Status)) {
			Context->Irp->IoStatus.Status = Status;
			SdmcpLowFinishPacket(Context);
		}
		return;
	}
	
	if (Context->State == LOCK_STATE_FINISHED) {
		// Callback from final SdmcpDeSelectAsync.
		// Should never get here, as the read implementation is used instead (it's the same, for both read and write)
		// Assume Context->Status was already set in a previous callback.
		// Set the finalise event and return.
		SdmcpLowFinishPacket(Context);
		return;
	}
	
	if (!NT_SUCCESS(Status)) {
		// Previous call did not succeed.
		
		// Free the map buffer.
		SdmcpLowFreeMapBuffer(Context);
		
		SdmcpLowAsyncDeSelect(Status, Context);
		return;
	}
	
	
	PUCHAR Pointer = (PUCHAR)Context->Buffer;
	if (Context->State == LOCK_STATE_FIRST_PAGE || Context->State == LOCK_STATE_NEXT_PAGE || Context->State == LOCK_STATE_LAST_PAGE) {
		if (Context->State == LOCK_STATE_FIRST_PAGE) {
			// Executing on CPU 0.
			// If caller passed an MDL, ensure that it is mapped.
			if (Context->Mdl != NULL) {
				PUCHAR MdlBuffer = (PUCHAR)MmGetSystemAddressForMdl(Context->Mdl);
				if (MdlBuffer == NULL) {
					SdmcpLowAsyncDeSelect(STATUS_UNSUCCESSFUL, Context);
					return;
				}
				
				// MDL is mapped. Fix the buffer.
				Context->Buffer = (PVOID)&MdlBuffer[(ULONG)Context->Buffer];
				Pointer = (PUCHAR)Context->Buffer;
			}
			
			if (Context->DmaBuffer == NULL) {
				// Allocate a clear map buffer.
				KeAcquireSpinLockAtDpcLevel(&s_SdmcDmaMapLock);
				ULONG BufferPage = RtlFindClearBitsAndSet(&s_SdmcDmaMap, 1, 0);
				KeReleaseSpinLockFromDpcLevel(&s_SdmcDmaMapLock);
				if (BufferPage == 0xFFFFFFFF) {
					SdmcpLowAsyncDeSelect(STATUS_INSUFFICIENT_RESOURCES, Context);
					return;
				}
				Context->DmaBuffer = (PUCHAR)s_SdmcDmaBuffer + (BufferPage * PAGE_SIZE);
				Context->BufferPage = BufferPage;
			}
		} else {
			ULONG IoCount = Context->IoCount;
			Pointer += SDMC_SECTOR_SIZE * IoCount;
			Context->Sector += IoCount;
			Context->Count -= IoCount;
			Context->Irp->IoStatus.Information += (IoCount * SDMC_SECTOR_SIZE);
			ContextArr->Length -= IoCount;
		}
		
		if (Context->State == LOCK_STATE_LAST_PAGE || Context->Count == 0) {
			// This chunk is finished. Is the whole write request finished?
			if (ContextArr->Length == 0 || ContextArr->SectorTableRemaining == 0) {
				// Free the map buffer.
				SdmcpLowFreeMapBuffer(Context);
				
				SdmcpLowAsyncDeSelect(Status, Context);
				return;
			}
			
			// Still data to write.
			Context->State = LOCK_STATE_NEXT_PAGE;
			ContextArr->Offset = 0;
			ContextArr->SectorTableEntry++;
			ContextArr->SectorTableRemaining--;
			Context->Sector = ContextArr->SectorTableEntry->sector;
			Context->Count = ContextArr->SectorTableEntry->count;
		}
		
		// Calculate the parameters for the next read operation.
		ULONG Offset = Context->Sector;
		if (s_SdmcIsHighCapacity == FALSE) Offset *= SDMC_SECTOR_SIZE;
		ULONG IoCount = SDMC_SECTORS_IN_PAGE;
		if (Context->Count < SDMC_SECTORS_IN_PAGE) IoCount = Context->Count;
		Context->IoCount = IoCount;
		Context->Buffer = Pointer;
		
		// Swap64 from the original buffer into the map buffer.
		if (((ULONG)Pointer & 7) == 0) {
			// Pointer is 64-bit aligned, swap from the pointer directly into the DMA buffer
			endian_swap64(Context->DmaBuffer, Pointer, SDMC_SECTOR_SIZE * IoCount);
		}
		else {
			// Not 64-bit aligned, copy then swap.
			RtlCopyMemory(Context->DmaBuffer, Pointer, SDMC_SECTOR_SIZE * IoCount);
			endian_swap64(Context->DmaBuffer, Context->DmaBuffer, SDMC_SECTOR_SIZE * IoCount);
		}
		// Cache invalidation not needed as IOP PXI driver does that.
		
		if (IoCount == Context->Count) Context->State = LOCK_STATE_LAST_PAGE;
		else Context->State = LOCK_STATE_NEXT_PAGE;
		
		Status = SdmcpSendCommandAsync(
			SDIO_CMD_WRITEMULTIBLOCK,
			SDIO_TYPE_CMD,
			SDIO_RESPONSE_R1,
			Offset,
			IoCount,
			SDMC_SECTOR_SIZE,
			Context->DmaBuffer,
			(IOP_CALLBACK)SdmcpWriteSectorsArrSeizedAsync,
			Context
		);
		
		if (!NT_SUCCESS(Status)) {
			// Previous call did not succeed.
			
			// Free the map buffer.
			SdmcpLowFreeMapBuffer(Context);
			
			SdmcpLowAsyncDeSelect(Status, Context);
			return;
		}
		
		return;
	}
	
	// Unknown state?
	// Free the map buffer, if needed.
	SdmcpLowFreeMapBuffer(Context);
	
	SdmcpLowAsyncDeSelect(STATUS_UNSUCCESSFUL, Context);
}

static void SdmcpGetStatusSeizedAsync(NTSTATUS Status, ULONG Result, PSDMC_SEIZED_CONTEXT Context) {
	if (Context->State == LOCK_STATE_SELECT) {
		Context->State = LOCK_STATE_FINISHED;
		NTSTATUS Status = HalIopIoctlAsyncDpc(
			s_hIosSdmc,
			IOCTL_SDIO_GETSTATUS,
			NULL,
			0,
			Context->DmaBuffer,
			sizeof(ULONG),
			IOCTL_SWAP_NONE,
			IOCTL_SWAP_NONE,
			(IOP_CALLBACK)SdmcpGetStatusSeizedAsync,
			Context
		);
		if (!NT_SUCCESS(Status)) {
			Context->Irp->IoStatus.Status = Status;
			SdmcpLowFinishPacket(Context);
		}
		return;
	}
	
	if (!NT_SUCCESS(Status)) {
		// Previous call did not succeed.
		Context->Irp->IoStatus.Status = Status;
		SdmcpLowFinishPacket(Context);
		return;
	}
	
	// must be LOCK_STATE_FINISHED
	Context->Irp->IoStatus.Status = Status;
	Context->Irp->IoStatus.Information = sizeof(ULONG) * 2;
	SdmcpLowFinishPacket(Context);
	return;
}


IO_ALLOCATION_ACTION SdmcLowSeizedController(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID NullBase, PSDMC_LOWLEVEL_EXTENSION Ext) {
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	
	// Fill in the context in the controller extension.
	PSDMC_SEIZED_CONTEXT Context = *(PSDMC_SEIZED_CONTEXT*)Ext->DiskController->ControllerExtension;
	Context->DeviceObject = DeviceObject;
	Context->Irp = Irp;
	Context->DiskController = Ext->DiskController;
	Context->State = LOCK_STATE_SELECT;
	Context->BufferPage = 0xFFFFFFFF;
	Context->DmaBuffer = NULL;
	
	if (Stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
		// GetStatus
		Context->DmaBuffer = Irp->UserBuffer;
		SdmcpGetStatusSeizedAsync(STATUS_SUCCESS, 0, Context);
		return KeepObject;
	}
	
	Context->Sector = Stack->Parameters.Read.ByteOffset.LowPart;
	Context->Buffer = Irp->UserBuffer;
	Context->Count = Stack->Parameters.Read.Length;
	Context->Mdl = Irp->MdlAddress;
	
	if (Stack->MajorFunction == IRP_MJ_READ) {
		SdmcpReadSectorsSeizedAsync(STATUS_SUCCESS, 0, Context);
	} else if (Stack->MajorFunction == IRP_MJ_WRITE) {
		SdmcpWriteSectorsSeizedAsync(STATUS_SUCCESS, 0, Context);
	} else {
		// Should not get here.
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		// Complete the IRP.
		IoCompleteRequest(Irp, IO_DISK_INCREMENT);
		// Start next IRP request.
		IoStartNextPacket(DeviceObject, FALSE);
		return DeallocateObject;
	}
	
	return KeepObject;
}

NTSTATUS SdmcLowStartIo(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	PSDMC_LOWLEVEL_EXTENSION Ext = (PSDMC_LOWLEVEL_EXTENSION)DeviceObject->DeviceExtension;
	
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	if (Stack->MajorFunction != IRP_MJ_READ && Stack->MajorFunction != IRP_MJ_WRITE && Stack->MajorFunction != IRP_MJ_DEVICE_CONTROL) {
		IoStartNextPacket(DeviceObject, FALSE);
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		sync_before_exec_this_cpu(Irp, sizeof(*Irp));
		IoCompleteRequest(Irp, IO_DISK_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}
	
	// Seize the controller object of the disk device
	IoAllocateController(
		Ext->DiskController,
		DeviceObject,
		(PDRIVER_CONTROL)SdmcLowSeizedController,
		Ext
	);
}

void SdmcLowUseLowDevice(PDEVICE_OBJECT DeviceObject) {
	//HalDisplayString("SDMC: Using low device\n");
	s_SdmcLowDevice = DeviceObject;
}

enum {
	STA_NOINIT = BIT(0),
	STA_NODISK = BIT(1),
	STA_PROTECT = BIT(2),
	STA_NONE = 0
};

typedef UCHAR DSTATUS;

typedef enum {
	RES_OK = 0,		/* 0: Successful */
	RES_ERROR,		/* 1: R/W Error */
	RES_WRPRT,		/* 2: Write Protected */
	RES_NOTRDY,		/* 3: Not Ready */
	RES_PARERR		/* 4: Invalid Parameter */
} DRESULT;

DSTATUS SdmcFfsStatus(void) {
	if (s_SdmcIsInitialised == FALSE) return STA_NOINIT;
	
	ULONG CardStatus;
	NTSTATUS Status;
	if (s_SdmcLowDevice != NULL) {
		KEVENT Event;
		IO_STATUS_BLOCK Iosb;
		KeInitializeEvent(&Event, NotificationEvent, FALSE);
		PULONG lStatus = HalIopAlloc(0x20);
		if (lStatus == NULL) return STA_NOINIT;
		PIRP Irp = IoBuildDeviceIoControlRequest(IOCTL_SDMC_GET_STATUS, s_SdmcLowDevice, NULL, 0, lStatus, 0x20, FALSE, &Event, &Iosb);
		if (Irp == NULL) {
			//HalDisplayString("SDMC: IOCTL_SDMC_GET_STATUS could not allocate IRP\n");
			return STA_NOINIT;
		}
		// Set the flags for synchronous paging IO as the caller may be for that.
		// If the caller is not for paging IO, setting these flags just leads to the fast path and not unlocking MDL
		// (which is the correct decision for when MDL is used as the caller's MDL is passed in)
		// If the caller is for paging IO, not setting these flags is a bug which leads to hang as the IRP doesn't complete correctly.
		Irp->Flags |= IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO;
		sync_before_exec_this_cpu(Irp, sizeof(*Irp));
		Status = IoCallDriver(s_SdmcLowDevice, Irp);
		if (Status == STATUS_PENDING) {
			KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
			Status = Iosb.Status;
		}
		if (NT_SUCCESS(Status)) CardStatus = lStatus[1];
#if 0
		if (!NT_SUCCESS(Status)) {
			char Buffer[1024];
			_snprintf(Buffer, sizeof(Buffer), "SDMC: IOCTL_SDMC_GET_STATUS failed %08x\n", Status);
			HalDisplayString(Buffer);
		} else {
			char Buffer[1024];
			_snprintf(Buffer, sizeof(Buffer), "SDMC: IOCTL_SDMC_GET_STATUS success %08x\n", CardStatus);
			HalDisplayString(Buffer);
		}
#endif
		HalIopFree(lStatus);
	} else Status = SdmcpGetStatusExt(&CardStatus);
	if (!NT_SUCCESS(Status)) {
		return STA_NOINIT;
	}
	
	UCHAR Result = STA_NONE;
	if ((CardStatus & SDIO_STATUS_CARD_INSERTED) == 0)
		Result |= STA_NODISK;
	if ((CardStatus & SDIO_STATUS_CARD_WRITEPROT) != 0)
		Result |= STA_PROTECT;
	return Result;
}

DSTATUS SdmcFfsInit(void) {
	NTSTATUS Status = SdmcStartup();
	if (!NT_SUCCESS(Status)) return STA_NOINIT;
	return SdmcFfsStatus();
}

static DRESULT SdmcpStatusToDresult(NTSTATUS Status) {
	if (NT_SUCCESS(Status)) return RES_OK;
	switch (Status) {
		case STATUS_INVALID_PARAMETER:
			return RES_PARERR;
		case STATUS_DEVICE_NOT_READY:
			return RES_NOTRDY;
		case STATUS_MEDIA_WRITE_PROTECTED:
			return RES_WRPRT;
		default:
			return RES_ERROR;
	}
}


DRESULT SdmcFfsRead(
	PVOID buff,		/* Data buffer to store read data */
	ULONG sector,	/* Start sector in LBA */
	ULONG count,		/* Number of sectors to read */
	PMDL mdl
) {
	if (SdmcFfsStatus() & (STA_NODISK|STA_NOINIT)) return RES_NOTRDY;
	NTSTATUS Status;
	if (s_SdmcLowDevice != NULL) {
#if 0
		{
			char Buffer[1024];
			_snprintf(Buffer, sizeof(Buffer), "SDMC: LowRead %08x(%d)\n", sector, count);
			HalDisplayString(Buffer);
		}
#endif
		KEVENT Event;
		IO_STATUS_BLOCK Iosb;
		KeInitializeEvent(&Event, NotificationEvent, FALSE);
		PIRP Irp = IoAllocateIrp(s_SdmcLowDevice->StackSize, FALSE);
		if (Irp == NULL) {
			//HalDisplayString("SDMC: LowRead could not allocate IRP\n");
			return RES_ERROR;
		}
		PIO_STACK_LOCATION Stack = IoGetNextIrpStackLocation(Irp);
		Stack->MajorFunction = IRP_MJ_READ;
		Irp->MdlAddress = mdl;
		Irp->UserBuffer = buff;
		Stack->Parameters.Read.Length = count;
		Stack->Parameters.Read.ByteOffset.QuadPart = sector;
		Irp->UserIosb = &Iosb;
		Irp->UserEvent = &Event;
		// Set the flags for synchronous paging IO as the caller may be for that.
		// If the caller is not for paging IO, setting these flags just leads to the fast path and not unlocking MDL
		// (which is the correct decision for when MDL is used as the caller's MDL is passed in)
		// If the caller is for paging IO, not setting these flags is a bug which leads to hang as the IRP doesn't complete correctly.
		KIRQL CurrentIrql;
		KeRaiseIrql(APC_LEVEL, &CurrentIrql);
		Irp->Flags |= IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO;
		Irp->Tail.Overlay.Thread = PsGetCurrentThread();
		IoQueueThreadIrp(Irp);
		sync_before_exec_this_cpu(Irp, sizeof(*Irp));
		Status = IoCallDriver(s_SdmcLowDevice, Irp);
		if (Status == STATUS_PENDING) {
			KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
			Status = Iosb.Status;
		}
		KeLowerIrql(CurrentIrql);
#if 0
		if (!NT_SUCCESS(Status)) {
			char Buffer[1024];
			_snprintf(Buffer, sizeof(Buffer), "SDMC: LowRead failed %08x\n", Status);
			HalDisplayString(Buffer);
		}
		else if (Iosb.Information != count) {
			char Buffer[1024];
			_snprintf(Buffer, sizeof(Buffer), "SDMC: LowRead failed %d!=%d\n", count, Iosb.Information);
			HalDisplayString(Buffer);
			return RES_ERROR;
		}
#endif
	} else Status = SdmcReadSectors(sector, count, buff, mdl);
	return SdmcpStatusToDresult(Status);
}

DRESULT SdmcFfsWrite(
	const void* buff,		/* Data buffer to store read data */
	ULONG sector,	/* Start sector in LBA */
	ULONG count,		/* Number of sectors to read */
	PMDL mdl
) {
	DSTATUS FfsStatus = SdmcFfsStatus();
	if (FfsStatus & (STA_NODISK|STA_NOINIT)) return RES_NOTRDY;
	if (FfsStatus & STA_PROTECT) return RES_WRPRT;
	NTSTATUS Status;
	if (s_SdmcLowDevice != NULL) {
#if 0
		{
			char Buffer[1024];
			_snprintf(Buffer, sizeof(Buffer), "SDMC: LowWrite %08x(%d)\n", sector, count);
			HalDisplayString(Buffer);
		}
#endif
		KEVENT Event;
		IO_STATUS_BLOCK Iosb;
		KeInitializeEvent(&Event, NotificationEvent, FALSE);
		PIRP Irp = IoAllocateIrp(s_SdmcLowDevice->StackSize, FALSE);
		if (Irp == NULL) {
			//HalDisplayString("SDMC: LowWrite could not allocate IRP\n");
			return RES_ERROR;
		}
		PIO_STACK_LOCATION Stack = IoGetNextIrpStackLocation(Irp);
		Stack->MajorFunction = IRP_MJ_WRITE;
		Irp->MdlAddress = mdl;
		Irp->UserBuffer = buff;
		Stack->Parameters.Read.Length = count;
		Stack->Parameters.Read.ByteOffset.QuadPart = sector;
		Irp->UserIosb = &Iosb;
		Irp->UserEvent = &Event;
		// Set the flags for synchronous paging IO as the caller may be for that.
		// If the caller is not for paging IO, setting these flags just leads to the fast path and not unlocking MDL
		// (which is the correct decision for when MDL is used as the caller's MDL is passed in)
		// If the caller is for paging IO, not setting these flags is a bug which leads to hang as the IRP doesn't complete correctly.
		KIRQL CurrentIrql;
		KeRaiseIrql(APC_LEVEL, &CurrentIrql);
		Irp->Flags |= IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO;
		Irp->Tail.Overlay.Thread = PsGetCurrentThread();
		IoQueueThreadIrp(Irp);
		sync_before_exec_this_cpu(Irp, sizeof(*Irp));
		Status = IoCallDriver(s_SdmcLowDevice, Irp);
		if (Status == STATUS_PENDING) {
			KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
			Status = Iosb.Status;
		}
		KeLowerIrql(CurrentIrql);
#if 0
		if (!NT_SUCCESS(Status)) {
			char Buffer[1024];
			_snprintf(Buffer, sizeof(Buffer), "SDMC: LowWrite failed %08x\n", Status);
			HalDisplayString(Buffer);
		}
		else if (Iosb.Information != count) {
			char Buffer[1024];
			_snprintf(Buffer, sizeof(Buffer), "SDMC: LowWrite failed %d!=%d\n", count, Iosb.Information);
			HalDisplayString(Buffer);
			return RES_ERROR;
		}
#endif
	} else Status = SdmcWriteSectors(sector, count, buff, mdl);
	return SdmcpStatusToDresult(Status);
}

DRESULT SdmcFfsCopy(
	void* dest,
	void* src,
	ULONG count,
	ULONG toMdl
) {
	
	PSDMC_DPC_CONTEXT Context = SdmcpGetDpcContext();
	if (Context == NULL) return SdmcpStatusToDresult(STATUS_INSUFFICIENT_RESOURCES);
	
	Context->Dest = dest;
	Context->Source = src;
	Context->Length = count;
	Context->ToMdl = toMdl;
	
	if (!SdmcpQueueDpc(Context)) {
		SdmcpReleaseDpcContext(Context);
		return SdmcpStatusToDresult(STATUS_INSUFFICIENT_RESOURCES);
	}
	
	KeWaitForSingleObject( &Context->Event, Executive, KernelMode, FALSE, NULL);
	NTSTATUS Status = Context->Status;
	SdmcpReleaseDpcContext(Context);
	return SdmcpStatusToDresult(Status);
}

enum {
	FFS_CTRL_SYNC = 0,
	FFS_GET_SECTOR_COUNT,
	FFS_GET_SECTOR_SIZE,
	FFS_GET_BLOCK_SIZE,
	FFS_GET_CTRL_TRIM
};

DRESULT SdmcFfsIoctl(UCHAR cmd, PVOID buff) {
	if (SdmcFfsStatus() & (STA_NODISK|STA_NOINIT)) return RES_NOTRDY;

	NTSTATUS Status;
	
	switch (cmd) {
		case FFS_CTRL_SYNC:
			return RES_OK;
		case FFS_GET_SECTOR_COUNT:
			Status = SdmcpGetCsd();
			if (!NT_SUCCESS(Status)) return SdmcpStatusToDresult(Status);
			if ((s_SdmcCsd[0] >> 6) == 1) {	/* SDC ver 2.00 */
				ULONG cs = s_SdmcCsd[9] + ((USHORT)s_SdmcCsd[8] << 8) + ((ULONG)(s_SdmcCsd[7] & 63) << 16) + 1;
				*(PULONG)buff = cs << 10;
			} else {					/* SDC ver 1.XX or MMC */
				UCHAR n = (s_SdmcCsd[5] & 15) + ((s_SdmcCsd[10] & 128) >> 7) + ((s_SdmcCsd[9] & 3) << 1) + 2;
				ULONG cs = (s_SdmcCsd[8] >> 6) + ((USHORT)s_SdmcCsd[7] << 2) + ((USHORT)(s_SdmcCsd[6] & 3) << 10) + 1;
				*(PULONG)buff = cs << (n - 9);
			}
			return RES_OK;
		case FFS_GET_BLOCK_SIZE:
			*(PULONG)buff = 128; // BUGBUG: is this correct?
			return RES_OK;
		default:
			return RES_PARERR;
	}
}
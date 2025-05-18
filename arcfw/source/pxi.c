// PXI driver; IOS IPC.
// Somewhat based on the HBC reload stub IOS IPC driver: https://github.com/fail0verflow/hbc/blob/a8e5f6c0f7e484c7f7112967eee6eee47b27d9ac/channel/channelapp/stub/ios.c
// We allow for five requests to be going off at once: one synchronous and up to four asynchronous.
// (two will be used for required lowlevel USB background requests. leaving an additionl two to be used for higher level USB requests)

#include <stdio.h>
#include <memory.h>
#include "arc.h"
#include "types.h"
#include "runtime.h"
#include "pxi.h"
#include "arcmem.h"
#include "timer.h"

// PXI register definitions, etc, originally from HAL

typedef enum _PXI_CONTROL {
	PXI_REQ_SEND = BIT(0), /// < Send request to IOP.
	PXI_REQ_ACK = BIT(1), /// < IOP acknowledged request. Write to clear.
	PXI_RES_SENT = BIT(2), /// < IOP responded. Write to clear.
	PXI_RES_ACK = BIT(3), /// < Acknowledge response to IOP.
	PXI_RES_SENT_INT = BIT(4), /// < Raise interrupt when IOP responds.
	PXI_REQ_ACK_INT = BIT(5), /// < Raise interrupt when IOP acks.

	PXI_BITS_PRESERVE = PXI_RES_SENT_INT | PXI_REQ_ACK_INT /// < Bits to preserve when clearing interrupt statuses.
} PXI_CONTROL;

typedef struct _PXI_CORE_REGISTERS {
	ULONG Message;
	ULONG Control; // PXI_CONTROL
} PXI_CORE_REGISTERS, * PPXI_CORE_REGISTERS;

typedef struct _PXI_REGISTERS {
	PXI_CORE_REGISTERS Request, Response;
	ULONG Reserved[(0x30 - 0x10) / sizeof(ULONG)];
	ULONG InterruptCause;
	ULONG InterruptMask;
} PXI_REGISTERS, * PPXI_REGISTERS;

_Static_assert(sizeof(PXI_REGISTERS) == 0x38);

typedef struct _PXI_REGISTERS_CPU {
	PXI_CORE_REGISTERS Request, Response;
} PXI_REGISTERS_CPU, *PPXI_REGISTERS_CPU;

_Static_assert(sizeof(PXI_REGISTERS_CPU) == 0x10);

typedef struct _INTERRUPT_REGISTERS_CPU {
	ULONG Cause[2];
	ULONG Mask[2];
} INTERRUPT_REGISTERS_CPU, *PINTERRUPT_REGISTERS_CPU;

_Static_assert(sizeof(INTERRUPT_REGISTERS_CPU) == 0x10);

typedef struct _PXI_REGISTERS_LATTE {
	PXI_REGISTERS Vegas;
	ULONG Reserved[(0x400 - 0x38) / sizeof(ULONG)];
	PXI_REGISTERS_CPU PerCore[3];
	ULONG Reserved2[(0x440 - 0x430) / sizeof(ULONG)];
	INTERRUPT_REGISTERS_CPU Interrupt[3];
} PXI_REGISTERS_LATTE, *PPXI_REGISTERS_LATTE;

_Static_assert(sizeof(PXI_REGISTERS_LATTE) == 0x470);

enum {
	VEGAS_INTERRUPT_GPIO = BIT(10),
	VEGAS_INTERRUPT_PXI = BIT(30)
};

enum {
	PXI_REGISTER_BASE = 0x0d800000
};

static bool PxipIsLatte(void);

#define PxiRegisters ((PPXI_REGISTERS)MEM_PHYSICAL_TO_K1(PXI_REGISTER_BASE))
#define PxiRegistersLatte ((PPXI_REGISTERS_LATTE)PxiRegisters)

#define PXI_REQUEST_READ() MmioReadBase32( MMIO_OFFSET(PxiRegisters, Request.Message) )
#define PXI_REQUEST_WRITE(x) MmioWriteBase32( MMIO_OFFSET(PxiRegisters, Request.Message), (ULONG)((x)) )
#define PXI_CONTROL_READ() ((PXI_CONTROL) MmioReadBase32( MMIO_OFFSET(PxiRegisters, Request.Control) ))
#define PXI_CONTROL_WRITE(x) MmioWriteBase32( MMIO_OFFSET(PxiRegisters, Request.Control), (ULONG)((x)) )
#define PXI_CONTROL_SET(x) do { \
	PXI_CONTROL Control = PXI_CONTROL_READ() & PXI_BITS_PRESERVE; \
	Control |= (x); \
	PXI_CONTROL_WRITE(Control); \
} while (false)
#define PXI_RESPONSE_READ() MmioReadBase32( MMIO_OFFSET(PxiRegisters, Response.Message) )
#define VEGAS_INTERRUPT_MASK_SET(x) do { \
	MmioWriteBase32( MMIO_OFFSET(PxiRegisters, InterruptMask), (ULONG)((x)) ); \
	if (PxipIsLatte()) MmioWriteBase32( MMIO_OFFSET(PxiRegistersLatte, Interrupt[0].Mask), (ULONG)((x)) ); \
} while (0)
#define VEGAS_INTERRUPT_CLEAR(x) do { \
	MmioWriteBase32( MMIO_OFFSET(PxiRegisters, InterruptCause), (ULONG)((x)) ); \
	if (PxipIsLatte()) MmioWriteBase32( MMIO_OFFSET(PxiRegistersLatte, Interrupt[0].Cause), (ULONG)((x)) ); \
} while (0)

static void PxiEnsureRepliesAsync(void);

// Returns true if some PXI control bits are set.
static bool PxiReqBitsSet(ULONG Value) {
	// Ignore the interrupt flags, they may or may not be enabled here.
	Value &= ~PXI_BITS_PRESERVE;
	return (PXI_CONTROL_READ() & Value) == Value;
}

// Returns true if some PXI control bits are set.
static bool PxiReqBitsPresent(ULONG Set, ULONG Unset) {
	// Ignore the interrupt flags, they may or may not be enabled here.
	Set &= ~PXI_BITS_PRESERVE;
	Unset &= ~PXI_BITS_PRESERVE;
	ULONG Control = PXI_CONTROL_READ();
	if ((Control & Set) != Set) return false;
	return ((Control & Unset) == 0);
}

// Clears the IPC interrupt of Vegas.
static void PxiIntClear(void) {
	VEGAS_INTERRUPT_CLEAR(VEGAS_INTERRUPT_PXI);
}

// Tell IOP that an IPC request is available to process.
static void PxiReqSend(ULONG Address) {
	while (PxiReqBitsSet(PXI_REQ_SEND)) udelay(100);

	PXI_REQUEST_WRITE(Address);
	PXI_CONTROL_SET(PXI_REQ_SEND);
}

// Clear the acknowledgement that IOP is processing an IPC request
static void PxiReqAck(void) {
	PXI_CONTROL_SET(PXI_REQ_ACK);
}

// Clear the acknowledgement that IOP has processed an IPC request
static void PxiResAck(void) {
	PXI_CONTROL_SET(PXI_RES_SENT);
}

// Tell IOP that we are done with the response buffer and IOP can clobber it.
static void PxiResFinished(void) {
	PXI_CONTROL_SET(PXI_RES_ACK);
}

// Returns true if IOP has started processing an IPC request
static bool PxiReqInProgress(void) {
	return PxiReqBitsSet(PXI_REQ_ACK_INT | PXI_REQ_ACK);
}

// Returns true if IOP has replied to an IPC request
static bool PxiResDone(void) {
	return PxiReqBitsSet(PXI_RES_SENT_INT | PXI_RES_SENT);
}

// Waits for IOP to start processing an IPC request
static void PxiWaitReqInProgress(void) {
	while (!PxiReqInProgress()) { PxiEnsureRepliesAsync(); }
	udelay(100);
}

// Waits for IOP to reply to an IPC request
static void PxiWaitResDone(void) {
	while (!PxiResDone()) {}
	udelay(100);
}

// IOS IPC structures.
typedef enum _IOS_OPERATION {
	IOSOP_NONE = 0,
	IOS_OPEN = 1,
	IOS_CLOSE,
	IOS_READ,
	IOS_WRITE,
	IOS_SEEK,
	IOS_IOCTL,
	IOS_IOCTLV,
	IOS_ASYNC_RESPONSE,
	__IOS_OPERATION_U32_MARKER = 0xFFFFFFFF
} IOS_OPERATION;

#if 0
// Memory as IOP sees it.
// Thus, must be accessed using NativeRead/Write32.
typedef struct _IOS_IPC_OPEN {
	union {
		ULONG Name;
		PCHAR _le_Name;
	};
	IOS_OPEN_MODE Mode;
} IOS_IPC_OPEN, * PIOS_IPC_OPEN;

typedef struct _IOS_IPC_BUFFER {
	union {
		ULONG Pointer;
		PVOID _le_Pointer;
	};
	ULONG Length;
} IOS_IPC_BUFFER, * PIOS_IPC_BUFFER;

typedef struct _IOS_IPC_SEEK {
	LONG Offset;
	IOS_SEEK_MODE Mode;
} IOS_IPC_SEEK, * PIOS_IPC_SEEK;

typedef struct _IOS_IPC_IOCTL {
	ULONG ControlCode;
	IOS_IPC_BUFFER Input;
	IOS_IPC_BUFFER Output;
} IOS_IPC_IOCTL, * PIOS_IPC_IOCTL;

typedef struct _IOS_IPC_IOCTLV {
	ULONG ControlCode;
	ULONG NumRead;
	ULONG NumWritten;
	union {
		ULONG Buffers;
		PIOS_IPC_BUFFER _le_Buffers;
	};
} IOS_IPC_IOCTLV, * PIOS_IPC_IOCTLV;

typedef union _IOS_IPC_ARGS {
	IOS_IPC_OPEN Open;
	struct { } Close;
	IOS_IPC_BUFFER Read, Write;
	IOS_IPC_SEEK Seek;
	IOS_IPC_IOCTL Ioctl;
	IOS_IPC_IOCTLV Ioctlv;
} IOS_IPC_ARGS, * PIOS_IPC_ARGS;

typedef struct _IOS_IPC_DESC {
	IOS_OPERATION Operation;
	LONG Result;
	union {
		IOS_HANDLE Handle;
		IOS_OPERATION ReqOp;
	};
	IOS_IPC_ARGS Args;
} IOS_IPC_DESC, * PIOS_IPC_DESC;
#else
// Memory as PPC(MSR_LE) sees it.
typedef struct _IOS_IPC_OPEN {
	union {
		ULONG Name;
		PCHAR _le_Name;
	};
	ULONG Handle;
	ULONG Padding;
	IOS_OPEN_MODE Mode;
} IOS_IPC_OPEN, *PIOS_IPC_OPEN;

typedef struct _IOS_IPC_BUFFER {
	ULONG Length;
	union {
		ULONG Pointer;
		PVOID _le_Pointer;
	};
} IOS_IPC_BUFFER, *PIOS_IPC_BUFFER;

typedef struct _IOS_IPC_RW {
	ULONG Length;
	ULONG Handle;
	ULONG Padding;
	union {
		ULONG Pointer;
		PVOID _le_Pointer;
	};
} IOS_IPC_RW, *PIOS_IPC_RW;

typedef struct _IOS_IPC_SEEK {
	LONG Offset;
	ULONG Handle;
	ULONG Padding;
	IOS_SEEK_MODE Mode;
} IOS_IPC_SEEK, *PIOS_IPC_SEEK;

typedef struct _IOS_IPC_IOCTL {
	ULONG ControlCode;
	ULONG Handle;
	IOS_IPC_BUFFER Input;
	IOS_IPC_BUFFER Output;
} IOS_IPC_IOCTL, *PIOS_IPC_IOCTL;

typedef struct _IOS_IPC_IOCTLV {
	ULONG ControlCode;
	ULONG Handle;
	ULONG NumWritten;
	ULONG NumRead;
	ULONG Padding;
	union {
		ULONG Buffers;
		PIOS_IPC_BUFFER _le_Buffers;
	};
} IOS_IPC_IOCTLV, *PIOS_IPC_IOCTLV;

typedef union _IOS_IPC_ARGS {
	IOS_IPC_OPEN Open;
	struct { } Close;
	IOS_IPC_RW Read, Write;
	IOS_IPC_SEEK Seek;
	IOS_IPC_IOCTL Ioctl;
	IOS_IPC_IOCTLV Ioctlv;
} IOS_IPC_ARGS, *PIOS_IPC_ARGS;

typedef struct _IOS_IPC_DESC {
	LONG Result;
	IOS_OPERATION Operation;
	union {
		IOS_IPC_ARGS Args;
		struct {
			ULONG IpcArg0;
			union {
				IOS_HANDLE Handle;
				IOS_OPERATION ReqOp;
			};
		};
	};
} IOS_IPC_DESC, *PIOS_IPC_DESC;
#endif

_Static_assert(sizeof(IOS_IPC_DESC) == 0x20);

typedef struct _PXI_DESC {
	IOS_IPC_DESC Ipc;
	ULONG User[8];
} PXI_DESC, *PPXI_DESC;

static PXI_DESC s_IpcDesc __attribute__((aligned(64)));
static PXI_DESC s_IpcDescAsync __attribute__((aligned(64)));
static PXI_DESC s_IpcDescAsync2 __attribute__((aligned(64)));
static PXI_DESC s_IpcDescAsync3 __attribute__((aligned(64)));
static PXI_DESC s_IpcDescAsync4 __attribute__((aligned(64)));
static const PPXI_DESC s_pIpcDescAsyncs[] = { &s_IpcDescAsync, &s_IpcDescAsync2, &s_IpcDescAsync3, &s_IpcDescAsync4 };
static IOS_OPERATION s_IpcAsyncOperation[4] = { IOSOP_NONE, IOSOP_NONE, IOSOP_NONE, IOSOP_NONE };
static bool s_IpcAsyncCompleted[4] = { false, false, false, false };
static bool s_IpcSyncCompleted = false;
static bool s_IsLatte = false;

static BYTE s_IpcBuffer[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

static bool PxipIsLatte(void) { return s_IsLatte; }

static void PxiEnsureRepliesAsync(void) {
	if (!PxiResDone()) return;

	do {
		udelay(100);
		ULONG reply = PXI_RESPONSE_READ();
		PxiResAck();
		PxiIntClear();
		PxiResFinished();
		if (MEM_PHYSICAL_TO_K0(reply) == &s_IpcDesc) {
			// sync reply.
			s_IpcSyncCompleted = true;
		}
		else {
			for (ULONG i = 0; i < sizeof(s_IpcAsyncCompleted); i++) {
				if (MEM_PHYSICAL_TO_K0(reply) == s_pIpcDescAsyncs[i]) {
					// some async reply.
					s_IpcAsyncCompleted[i] = true;
					break;
				}
			}
		}

		udelay(100);
	} while (PxiResDone());
}

// Sends a regular IOS IPC request
static void PxiSendRequest(void) {
	data_cache_flush(&s_IpcDesc, sizeof(PXI_DESC));

	PxiEnsureRepliesAsync();
	s_IpcSyncCompleted = false;

	PxiReqSend((ULONG)MEM_K0_TO_PHYSICAL(&s_IpcDesc));

	PxiWaitReqInProgress();

	PxiReqAck();
	PxiIntClear();
}

// Sends an async IOS IPC request
static void PxiSendRequestAsync(ULONG index) {
	data_cache_flush(s_pIpcDescAsyncs[index], sizeof(PXI_DESC));

	PxiEnsureRepliesAsync();

	PxiReqSend((ULONG)MEM_K0_TO_PHYSICAL(s_pIpcDescAsyncs[index]));

	PxiWaitReqInProgress();

	PxiReqAck();
	PxiIntClear();
}

// Sends an IOS IPC request that causes an IOS reboot
static void PxiSendRequestReboot(void) {
	data_cache_flush(&s_IpcDesc, sizeof(PXI_DESC));
	NativeWriteBase32((PVOID)0x60000000, 0x3140, 0);

	PxiReqSend((ULONG)MEM_K0_TO_PHYSICAL(&s_IpcDesc));

	PxiWaitReqInProgress();
	PxiIntClear();
	PxiReqAck();

	PxiWaitReqInProgress();
	PxiIntClear();
	PxiReqAck();

	PxiResFinished();

	while ((LoadToRegister32(NativeReadBase32((PVOID)0x60000000, 0x3140)) >> 16) == 0) udelay(1000);
}

// Receives a reply to an IOS IPC request
static void PxiReceiveReply(void) {
	while (true) {
		if (s_IpcSyncCompleted) break;

		PxiWaitResDone();

		ULONG reply = PXI_RESPONSE_READ();
		PxiResAck();

		PxiIntClear();
		PxiResFinished();

		if (MEM_PHYSICAL_TO_K0(reply) == &s_IpcDesc) break;

		// this is not our IPC reply???
		for (ULONG i = 0; i < sizeof(s_IpcAsyncCompleted); i++) {
			if (MEM_PHYSICAL_TO_K0(reply) == s_pIpcDescAsyncs[i]) {
				// ...this is an async reply
				s_IpcAsyncCompleted[i] = true;
				break;
			}
		}

		udelay(100);
	}

	data_cache_invalidate(&s_IpcDesc, sizeof(s_IpcDesc));
}

// Returns true if a reply to an in-flight async request was obtained.
static bool PxiHasReplyAsync(ULONG index) {
	if (index >= sizeof(s_IpcAsyncCompleted)) return false;
	if (s_IpcAsyncOperation[index] == IOSOP_NONE) return false;

	if (s_IpcAsyncCompleted[index]) {
		data_cache_invalidate(s_pIpcDescAsyncs[index], sizeof(s_IpcDescAsync));
		s_IpcAsyncCompleted[index] = false;
		s_IpcAsyncOperation[index] = IOSOP_NONE;
		return true;
	}
	if (!PxiResDone()) return false;

	udelay(100);
	ULONG reply = PXI_RESPONSE_READ();
	PxiResAck();

	PxiIntClear();
	PxiResFinished();
	if (MEM_PHYSICAL_TO_K0(reply) == &s_IpcDesc) {
		// sync reply.
		s_IpcSyncCompleted = true;
		return false;
	}
	if (MEM_PHYSICAL_TO_K0(reply) == s_pIpcDescAsyncs[index]) {
		// this is our reply so make it so
		data_cache_invalidate(s_pIpcDescAsyncs[index], sizeof(s_IpcDescAsync));
		s_IpcAsyncOperation[index] = IOSOP_NONE;

		return true;
	}
	else {
		for (ULONG i = 0; i < sizeof(s_IpcAsyncCompleted); i++) {
			if (i == index) continue;
			if (MEM_PHYSICAL_TO_K0(reply) == s_pIpcDescAsyncs[i]) {
				// some other async reply.
				s_IpcAsyncCompleted[i] = true;
				break;
			}
		}
	}

	// this is not our reply
	return false;
}

// Acknowledge any request in flight
static void PxiCleanupRequest(void) {
	if (!PxiReqInProgress()) return;
	PxiReqAck();
}

// Acknowledge any reply in flight
static void PxiCleanupReply(void) {
	if (!PxiResDone()) return;

	PXI_RESPONSE_READ();
	PxiResAck();
	PxiIntClear();
	PxiResFinished();
}


// Endianness swapping functionality.
// Swap64 where length is 64 bits aligned, and dest+src are 32 bits aligned
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

// Swap8cpy, slowest but no alignment requirements (requires that dest and src do not overlap)
static void endian_swap8cpy(void* dest, const void* src, ULONG len) {
	const UCHAR* src8 = (const UCHAR*)src;
	UCHAR* dest8 = (UCHAR*)dest;

	for (ULONG i = 0; i < len; i++) {
		UCHAR val = src8[i];
		NativeWrite8(&dest8[i], val);
	}
}

// Swap8move, same as Swap8 but works with overlapping buffers
static void endian_swap8move(void* dest, const void* src, ULONG len) {
	const UCHAR* src8 = (const UCHAR*)src;
	UCHAR* dest8 = (UCHAR*)dest;

	UCHAR arr[8];
	for (ULONG idx64 = 0; idx64 < len; idx64 += sizeof(ULONG) * 2) {
		memcpy(arr, &src8[idx64], sizeof(arr));

		ULONG end64 = idx64 + 8;
		if (end64 > len) end64 = len;
		end64 -= idx64;
		for (ULONG i = 0; i < end64; i++) {
			NativeWrite8(&dest8[idx64 + i], arr[i]);
		}
	}
}

// Swap8, picks the correct function based on how the buffers overlap
static void endian_swap8(void* dest, const void* src, ULONG len) {
	ULONG destOl = ((ULONG)dest) & ~7;
	ULONG srcOl = ((ULONG)src) & ~7;
	if (srcOl == destOl) endian_swap8move(dest, src, len);
	else endian_swap8cpy(dest, src, len);
}

// Swap64by8, swaps 64 bit chunks by 8 bits (no alignment requirements)
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

static void memcpy_swap(void* dest, const void* src, ULONG len) {
	// Assumption: all buffers are either 64-bit aligned or in PXI heap, which aligns the requested heap length to 256 bits
#if 0
	ULONG destAlign = ((ULONG)dest & 3);
	ULONG srcAlign = ((ULONG)src & 3);

	const UCHAR* src8 = (const UCHAR*)src;
	UCHAR* dest8 = (UCHAR*)dest;

	if (len >= 8) {
		ULONG lenAlign = (len & 7);
		ULONG lenFor64 = len - lenAlign;

		if (lenFor64 != 0) {
			if (destAlign == srcAlign && destAlign == 0) {
				// everything is fine for endian_swap64 as much as possible
				endian_swap64(dest8, src8, lenFor64);
			}
			else {
				// buffers are not aligned so use swap64by8
				endian_swap64by8(dest8, src8, lenFor64);
			}
			src8 += lenFor64;
			dest8 += lenFor64;
			len -= lenFor64;
		}
	}

	if (len == 0) return;

	// swap the last bytes.
	endian_swap8(dest8, src8, len);
#endif
	endian_swap64(dest, src, len);
}

static void strcpy_swap(char* dest, const char* src) {
	for (char chr = *src; ; src++, dest++, chr = *src) {
		NativeWrite8(dest, chr);
		if (chr == 0) return;
	}
}

// High-level IOS API.
LONG PxiIopOpen(const char* Path, IOS_OPEN_MODE Mode, IOS_HANDLE* Handle) {
	// Copy the path to the buffer.
	strcpy_swap((char*)s_IpcBuffer, Path);
	data_cache_flush(s_IpcBuffer, PAGE_SIZE);

	memset(&s_IpcDesc, 0, sizeof(s_IpcDesc));
	s_IpcDesc.Ipc.Operation = IOS_OPEN;
	// no need to do this, we just memset the entire thing to zero
	//s_IpcDesc.Ipc.Handle, 0);
	s_IpcDesc.Ipc.Args.Open.Name = (ULONG)MEM_VIRTUAL_TO_PHYSICAL(s_IpcBuffer);
	s_IpcDesc.Ipc.Args.Open.Mode = Mode;

	PxiSendRequest();
	PxiReceiveReply();

	LONG Result = s_IpcDesc.Ipc.Result;
	if (Result < 0) {
		*Handle = IOS_HANDLE_INVALID;
		return Result;
	}

	*Handle = (IOS_HANDLE)Result;
	return 0;
}

LONG PxiIopClose(IOS_HANDLE Handle) {
	memset(&s_IpcDesc, 0, sizeof(s_IpcDesc));
	s_IpcDesc.Ipc.Operation = IOS_CLOSE;
	s_IpcDesc.Ipc.Handle = Handle;

	PxiSendRequest();
	PxiReceiveReply();

	return s_IpcDesc.Ipc.Result;
}

static LONG PxiIopRw(IOS_HANDLE Handle, PVOID Buffer, ULONG Length, IOS_RW_MODE SwapMode, PULONG NumberOfBytesTransferred, IOS_OPERATION Operation) {
	if ((SwapMode & RW_SWAP_INPUT) != 0) {
		// Endianness swap the buffer.
		memcpy_swap(Buffer, Buffer, Length);
		data_cache_flush(Buffer, Length);
	}
	else if (Operation == IOS_WRITE) {
		data_cache_flush(Buffer, Length);
	}
	memset(&s_IpcDesc, 0, sizeof(s_IpcDesc));
	s_IpcDesc.Ipc.Operation = Operation;
	s_IpcDesc.Ipc.Handle = Handle;
	s_IpcDesc.Ipc.Args.Read.Pointer = (ULONG)MEM_VIRTUAL_TO_PHYSICAL(Buffer);
	s_IpcDesc.Ipc.Args.Read.Length = Length;

	PxiSendRequest();
	PxiReceiveReply();

	LONG Result = s_IpcDesc.Ipc.Result;

	data_cache_invalidate(Buffer, Length);
	
	// Endianness swap the buffer.
	if ((SwapMode & RW_SWAP_OUTPUT) != 0) memcpy_swap(Buffer, Buffer, Length);

	if (Result < 0) {
		*NumberOfBytesTransferred = 0;
		return Result;
	}

	*NumberOfBytesTransferred = Result;
	return 0;
}

LONG PxiIopRead(IOS_HANDLE Handle, PVOID Buffer, ULONG Length, IOS_RW_MODE SwapMode, PULONG NumberOfBytesTransferred) {
	return PxiIopRw(Handle, Buffer, Length, SwapMode, NumberOfBytesTransferred, IOS_READ);
}

LONG PxiIopWrite(IOS_HANDLE Handle, PVOID Buffer, ULONG Length, IOS_RW_MODE SwapMode, PULONG NumberOfBytesTransferred) {
	return PxiIopRw(Handle, Buffer, Length, SwapMode, NumberOfBytesTransferred, IOS_WRITE);
}

LONG PxiIopSeek(IOS_HANDLE Handle, LONG Offset, IOS_SEEK_MODE Mode, PULONG FileOffset) {
	memset(&s_IpcDesc, 0, sizeof(s_IpcDesc));
	s_IpcDesc.Ipc.Operation = IOS_SEEK;
	s_IpcDesc.Ipc.Handle = Handle;
	s_IpcDesc.Ipc.Args.Seek.Offset = Offset;
	s_IpcDesc.Ipc.Args.Seek.Mode = Mode;

	PxiSendRequest();
	PxiReceiveReply();

	LONG Result = s_IpcDesc.Ipc.Result;

	if (Result < 0) {
		*FileOffset = 0xFFFFFFFF;
		return Result;
	}

	*FileOffset = Result;
	return 0;
}

LONG PxiIopIoctl(IOS_HANDLE Handle, ULONG ControlCode, PVOID Input, ULONG LengthInput, PVOID Output, ULONG LengthOutput, IOS_IOCTL_MODE SwapModeInput, IOS_IOCTL_MODE SwapModeOutput) {
	if (Input != NULL && LengthInput != 0) {
		// Endianness swap the input buffer.
		if ((SwapModeInput & IOCTL_SWAP_INPUT) != 0) memcpy_swap(Input, Input, LengthInput);
		data_cache_flush(Input, LengthInput);
	}

	if (Output != NULL && LengthOutput != 0) {
		// Endianness swap the input buffer.
		if ((SwapModeInput & IOCTL_SWAP_OUTPUT) != 0) memcpy_swap(Output, Output, LengthOutput);
		data_cache_flush(Output, LengthOutput);
	}
	
	memset(&s_IpcDesc, 0, sizeof(s_IpcDesc));
	s_IpcDesc.Ipc.Operation = IOS_IOCTL;
	s_IpcDesc.Ipc.Handle = Handle;
	s_IpcDesc.Ipc.Args.Ioctl.ControlCode = ControlCode;
	s_IpcDesc.Ipc.Args.Ioctl.Input.Pointer = (ULONG)MEM_VIRTUAL_TO_PHYSICAL(Input);
	s_IpcDesc.Ipc.Args.Ioctl.Input.Length = LengthInput;
	s_IpcDesc.Ipc.Args.Ioctl.Output.Pointer = (ULONG)MEM_VIRTUAL_TO_PHYSICAL(Output);
	s_IpcDesc.Ipc.Args.Ioctl.Output.Length = LengthOutput;

	PxiSendRequest();
	PxiReceiveReply();

	LONG Result = s_IpcDesc.Ipc.Result;


	if (Input != NULL && LengthInput != 0) {
		data_cache_invalidate(Input, LengthInput);
		// Endianness swap the input buffer.
		if ((SwapModeOutput & IOCTL_SWAP_INPUT) != 0) memcpy_swap(Input, Input, LengthInput);
	}

	if (Result >= 0 && Output != NULL && LengthOutput != 0) {
		data_cache_invalidate(Output, LengthOutput);
		// Endianness swap the output buffer.
		if ((SwapModeOutput & IOCTL_SWAP_OUTPUT) != 0) memcpy_swap(Output, Output, LengthOutput);
	}

	return Result;
}

static LONG PxiIopIoctlvImpl(IOS_HANDLE Handle, ULONG ControlCode, ULONG NumRead, ULONG NumWritten, PIOS_IOCTL_VECTOR Buffers, ULONG SwapBuffersIn, ULONG SwapBuffersOut, bool Reboot) {
	// SwapBuffersIn/SwapBuffersOut are 32 bits. this should be more than enough for any ioctlv call on IOS or IOSU. (on Cafe we expect to have a patched vWii IOS58 running though!)
	if ((NumRead + NumWritten) > 32) return -1;
	for (ULONG i = 0; i < (NumRead + NumWritten); i++) {
		ULONG Length = Buffers[i].Length;
		if (Buffers[i].Pointer == NULL) {
			if (Length != 0) return -1; // pointer==null && length!=0 is invalid
			continue;
		}
		// Endianness swap the buffer.
		if ((SwapBuffersIn & BIT(i)) != 0) memcpy_swap(Buffers[i].Pointer, Buffers[i].Pointer, Length);
		// Flush dcache.
		data_cache_flush(Buffers[i].Pointer, Length);
		// Convert to physical address.
		Buffers[i].Pointer = MEM_VIRTUAL_TO_PHYSICAL(Buffers[i].Pointer);
	}

	// Flush dcache for the vector descriptors
	data_cache_flush(Buffers, (NumRead + NumWritten) * sizeof(*Buffers));

	memset(&s_IpcDesc, 0, sizeof(s_IpcDesc));
	s_IpcDesc.Ipc.Operation = IOS_IOCTLV;
	s_IpcDesc.Ipc.Handle = Handle;
	s_IpcDesc.Ipc.Args.Ioctlv.ControlCode = ControlCode;
	s_IpcDesc.Ipc.Args.Ioctlv.NumRead = NumRead;
	s_IpcDesc.Ipc.Args.Ioctlv.NumWritten = NumWritten;
	s_IpcDesc.Ipc.Args.Ioctlv.Buffers = (ULONG)MEM_VIRTUAL_TO_PHYSICAL(Buffers);

	if (Reboot) {
		PxiSendRequestReboot();
		return 0;
	}

	PxiSendRequest();
	PxiReceiveReply();

	LONG IosResult = s_IpcDesc.Ipc.Result;

	for (ULONG i = 0; i < (NumRead + NumWritten); i++) {
		if (Buffers[i].Pointer == NULL) continue;
		ULONG Length = Buffers[i].Length;
		Buffers[i].Pointer = MEM_PHYSICAL_TO_K0(Buffers[i].Pointer);
		Buffers[i].Length = Length;
		if (IosResult < 0) continue; // if ioctlv call failed, caller shouldn't be using any out buffer anyway.
		if (Length == 0) continue;
		data_cache_invalidate(Buffers[i].Pointer, Length);
		if ((SwapBuffersOut & BIT(i)) != 0) memcpy_swap(Buffers[i].Pointer, Buffers[i].Pointer, Length);
	}

	return IosResult;
}

LONG PxiIopIoctlv(IOS_HANDLE Handle, ULONG ControlCode, ULONG NumRead, ULONG NumWritten, PIOS_IOCTL_VECTOR Buffers, ULONG SwapBuffersIn, ULONG SwapBuffersOut) {
	return PxiIopIoctlvImpl(Handle, ControlCode, NumRead, NumWritten, Buffers, SwapBuffersIn, SwapBuffersOut, false);
}

LONG PxiIopIoctlvReboot(IOS_HANDLE Handle, ULONG ControlCode, ULONG NumRead, ULONG NumWritten, PIOS_IOCTL_VECTOR Buffers, ULONG SwapBuffersIn, ULONG SwapBuffersOut) {
	return PxiIopIoctlvImpl(Handle, ControlCode, NumRead, NumWritten, Buffers, SwapBuffersIn, SwapBuffersOut, true);
}

LONG PxiIopIoctlAsync(IOS_HANDLE Handle, ULONG ControlCode, PVOID Input, ULONG LengthInput, PVOID Output, ULONG LengthOutput, IOS_IOCTL_MODE SwapModeInput, IOS_IOCTL_MODE SwapModeOutput, PVOID Context) {
	ULONG index = 0;
	for (; index < sizeof(s_IpcAsyncCompleted); index++) {
		if (s_IpcAsyncOperation[index] == IOSOP_NONE) break;
	}
	if (index >= sizeof(s_IpcAsyncCompleted)) return -1; // can't start an async operation if all of them are already in flight
	
	if (Input != NULL && LengthInput != 0) {
		// Endianness swap the input buffer.
		if ((SwapModeInput & IOCTL_SWAP_INPUT) != 0) memcpy_swap(Input, Input, LengthInput);
		data_cache_flush(Input, LengthInput);
	}

	if (Output != NULL && LengthOutput != 0) {
		// Endianness swap the input buffer.
		if ((SwapModeInput & IOCTL_SWAP_OUTPUT) != 0) memcpy_swap(Output, Output, LengthOutput);
		data_cache_flush(Output, LengthOutput);
	}

	s_IpcAsyncOperation[index] = IOS_IOCTL;
	memset(s_pIpcDescAsyncs[index], 0, sizeof(s_IpcDescAsync));
	s_pIpcDescAsyncs[index]->Ipc.Operation = IOS_IOCTL;
	s_pIpcDescAsyncs[index]->Ipc.Handle = Handle;
	s_pIpcDescAsyncs[index]->Ipc.Args.Ioctl.ControlCode = ControlCode;
	s_pIpcDescAsyncs[index]->Ipc.Args.Ioctl.Input.Pointer = (ULONG)MEM_VIRTUAL_TO_PHYSICAL(Input);
	s_pIpcDescAsyncs[index]->Ipc.Args.Ioctl.Input.Length = LengthInput;
	s_pIpcDescAsyncs[index]->Ipc.Args.Ioctl.Output.Pointer = (ULONG)MEM_VIRTUAL_TO_PHYSICAL(Output);
	s_pIpcDescAsyncs[index]->Ipc.Args.Ioctl.Output.Length = LengthOutput;
	s_pIpcDescAsyncs[index]->User[0] = SwapModeOutput;
	s_pIpcDescAsyncs[index]->User[1] = (ULONG)Input;
	s_pIpcDescAsyncs[index]->User[2] = LengthInput;
	s_pIpcDescAsyncs[index]->User[3] = (ULONG)Output;
	s_pIpcDescAsyncs[index]->User[4] = LengthOutput;
	s_pIpcDescAsyncs[index]->User[5] = (ULONG)Context;
	ULONG BuffersInPhysSpace = 0;
	if ((ULONG)Input < 0x80000000) BuffersInPhysSpace |= BIT(0);
	if ((ULONG)Output < 0x80000000) BuffersInPhysSpace |= BIT(1);
	s_pIpcDescAsyncs[index]->User[6] = BuffersInPhysSpace;


	PxiSendRequestAsync(index);
	return (LONG)index;
}

bool PxiIopIoctlAsyncPoll(ULONG index, LONG* Result, PVOID* Context) {
	if (index >= sizeof(s_IpcAsyncCompleted)) return false; // index out of range
	if (Result == NULL) return false; // must pass out-ptr for result
	if (s_IpcAsyncOperation[index] != IOS_IOCTL) return false; // ioctl not in progress
	if (!PxiHasReplyAsync(index)) return false; // hasn't replied yet

	IOS_IOCTL_MODE SwapMode = s_pIpcDescAsyncs[index]->User[0];

	PVOID Input = (PVOID)s_pIpcDescAsyncs[index]->User[1];
	ULONG LengthInput = s_pIpcDescAsyncs[index]->User[2];
	PVOID Output = (PVOID)s_pIpcDescAsyncs[index]->User[3];
	ULONG LengthOutput = s_pIpcDescAsyncs[index]->User[4];

	ULONG BuffersInPhysSpace = s_pIpcDescAsyncs[index]->User[6];

	LONG IosResult = s_pIpcDescAsyncs[index]->Ipc.Result;

	//data_cache_invalidate(Input, LengthInput);
	//data_cache_invalidate(Output, LengthOutput);

	*Result = IosResult;
	*Context = (PVOID)s_pIpcDescAsyncs[index]->User[5];
	if (Input != NULL && LengthInput != 0) {
		if ((BuffersInPhysSpace & BIT(0)) != 0) data_cache_invalidate(Input, LengthInput);
		// Endianness swap the input buffer.
		if ((SwapMode & IOCTL_SWAP_INPUT) != 0) memcpy_swap(Input, Input, LengthInput);
	}

	if (IosResult < 0) return true;

	if (Output != NULL && LengthOutput != 0) {
		if ((BuffersInPhysSpace & BIT(1)) != 0) data_cache_invalidate(Output, LengthOutput);
		// Endianness swap the output buffer.
		if ((SwapMode & IOCTL_SWAP_OUTPUT) != 0) memcpy_swap(Output, Output, LengthOutput);
	}

	return true;
}

bool PxiIopIoctlAsyncActive(ULONG index) {
	return index < sizeof(s_IpcAsyncCompleted) && s_IpcAsyncOperation[index] == IOS_IOCTL;
}

LONG PxiIopIoctlvAsync(IOS_HANDLE Handle, ULONG ControlCode, ULONG NumRead, ULONG NumWritten, PIOS_IOCTL_VECTOR Buffers, ULONG SwapBuffersIn, ULONG SwapBuffersOut, PVOID Context) {
	ULONG index = 0;
	for (; index < sizeof(s_IpcAsyncCompleted); index++) {
		if (s_IpcAsyncOperation[index] == IOSOP_NONE) break;
	}
	if (index >= sizeof(s_IpcAsyncCompleted)) return -1; // can't start an async operation if all of them are already in flight

	ULONG BuffersInPhysSpace = 0;
	for (ULONG i = 0; i < (NumRead + NumWritten); i++) {
		ULONG Length = Buffers[i].Length;
		if (Buffers[i].Pointer == NULL) {
			if (Length != 0) return -1; // pointer==null && length!=0 is invalid
			continue;
		}
		// Endianness swap the buffer.
		if ((SwapBuffersIn & BIT(i)) != 0) memcpy_swap(Buffers[i].Pointer, Buffers[i].Pointer, Length);
		// Flush dcache.
		ULONG virt = (ULONG)Buffers[i].Pointer;
		if (virt < 0x80000000) BuffersInPhysSpace |= BIT(i);
		else data_cache_flush(Buffers[i].Pointer, Length);
		// Convert to physical address.
		Buffers[i].Pointer = MEM_VIRTUAL_TO_PHYSICAL(Buffers[i].Pointer);
	}

	// Flush dcache for the vector descriptors
	data_cache_flush(Buffers, (NumRead + NumWritten) * sizeof(*Buffers));

	memset(s_pIpcDescAsyncs[index], 0, sizeof(s_IpcDescAsync));
	s_IpcAsyncOperation[index] = IOS_IOCTLV;
	s_pIpcDescAsyncs[index]->Ipc.Operation = IOS_IOCTLV;
	s_pIpcDescAsyncs[index]->Ipc.Handle = Handle;
	s_pIpcDescAsyncs[index]->Ipc.Args.Ioctlv.ControlCode = ControlCode;
	s_pIpcDescAsyncs[index]->Ipc.Args.Ioctlv.NumRead = NumRead;
	s_pIpcDescAsyncs[index]->Ipc.Args.Ioctlv.NumWritten = NumWritten;
	s_pIpcDescAsyncs[index]->Ipc.Args.Ioctlv.Buffers = (ULONG)MEM_VIRTUAL_TO_PHYSICAL(Buffers);

	s_pIpcDescAsyncs[index]->User[0] = (ULONG)Buffers;
	s_pIpcDescAsyncs[index]->User[1] = SwapBuffersOut;
	s_pIpcDescAsyncs[index]->User[2] = NumRead + NumWritten;
	s_pIpcDescAsyncs[index]->User[3] = (ULONG)Context;
	s_pIpcDescAsyncs[index]->User[4] = BuffersInPhysSpace;

	PxiSendRequestAsync(index);
	return index;
}

bool PxiIopIoctlvAsyncPoll(ULONG index, LONG* Result, PVOID* Context) {
	if (index >= sizeof(s_IpcAsyncCompleted)) return false; // index out of range
	if (Result == NULL) return false; // must pass out-ptr for result
	if (s_IpcAsyncOperation[index] != IOS_IOCTLV) return false; // ioctl not in progress
	if (!PxiHasReplyAsync(index)) return false; // hasn't replied yet

	PIOS_IOCTL_VECTOR Buffers = (PIOS_IOCTL_VECTOR)s_pIpcDescAsyncs[index]->User[0];
	ULONG SwapBuffersOut = s_pIpcDescAsyncs[index]->User[1];
	ULONG NumBuffers = s_pIpcDescAsyncs[index]->User[2];
	ULONG BuffersInPhysSpace = s_pIpcDescAsyncs[index]->User[4];

	LONG IosResult = (LONG)s_pIpcDescAsyncs[index]->Ipc.Result;
	*Result = IosResult;
	*Context = (PVOID)s_pIpcDescAsyncs[index]->User[3];

	for (ULONG i = 0; i < NumBuffers; i++) {
		if (Buffers[i].Pointer == NULL) continue;
		ULONG Length = Buffers[i].Length;
		ULONG phys = (ULONG)Buffers[i].Pointer;
		Buffers[i].Pointer = MEM_PHYSICAL_TO_K0(phys);
		if ((BuffersInPhysSpace & BIT(i)) != 0) Buffers[i].Pointer = MEM_PHYSICAL_TO_K1(phys);
		Buffers[i].Length = Length;
		if (IosResult < 0) continue; // if ioctlv call failed, caller shouldn't be using any out buffer anyway.
		if (Length == 0) continue;
		PULONG buf = (PULONG)Buffers[i].Pointer;
		if ((BuffersInPhysSpace & BIT(i)) == 0) data_cache_invalidate(Buffers[i].Pointer, Length);
		if ((SwapBuffersOut & BIT(i)) != 0) memcpy_swap(Buffers[i].Pointer, Buffers[i].Pointer, Length);
	}

	return true;
}

bool PxiIopIoctlvAsyncActive(ULONG index) {
	return index < sizeof(s_IpcAsyncCompleted) && s_IpcAsyncOperation[index] == IOS_IOCTLV;
}

void PxiInit(ARTX_SYSTEM_TYPE SystemType) {
	// Unmask interrupts at the PXI block.
	PXI_CONTROL_SET(PXI_BITS_PRESERVE);

	if (SystemType == ARTX_SYSTEM_LATTE) {
		s_IsLatte = true;
		// Wait for IOS kernel init.
		while (NativeReadBase32(MEM_PHYSICAL_TO_K1(0), 0x314C) == 0) {
			udelay(1000);
		}

		// Finish up the IOS reboot sequence.
		PxiWaitReqInProgress();
		PxiIntClear();
		PxiReqAck();
		PxiResFinished();

		// Wait a while for IOS to fully init.
		udelay(1000000);
	}

	// Cleanup any existing IPC transactions
	for (int i = 0; i < 10; i++) {
		PxiCleanupRequest();
		PxiCleanupReply();
		PxiIntClear();
		udelay(1000);
	}

#if 0
	// Close handles.
	// BUGBUG: Is this needed? When getting here, should have just rebooted IOS.
	for (int i = 0; i < 32; i++) {
		PxiIopClose((IOS_HANDLE)i);
	}
#endif
}

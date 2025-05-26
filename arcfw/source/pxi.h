#pragma once
#include "types.h"
#include "runtime.h"
#include "pxiheap.h"

// IOS file/device handle.
typedef ULONG IOS_HANDLE, * PIOS_HANDLE;
enum {
	IOS_HANDLE_INVALID = 0xffffffff
};

// IOS open mode bitflags (read/write)
typedef enum _IOS_OPEN_MODE {
	IOSOPEN_NONE = 0,
	IOSOPEN_READ = BIT(0),
	IOSOPEN_WRITE = BIT(1)
} IOS_OPEN_MODE;

// IOS seek mode
typedef enum _IOS_SEEK_MODE {
	IOSSEEK_SET,
	IOSSEEK_CURRENT,
	IOSSEEK_END
} IOS_SEEK_MODE;

// Describes a buffer sent to a vectored IOCTL handler.
// Supposedly requires 256-bit alignment
typedef struct _IOS_IOCTL_VECTOR {
	ULONG Length;
	PVOID Pointer;
} IOS_IOCTL_VECTOR, * PIOS_IOCTL_VECTOR;

// IOS read/write mode bitflags (buffer swap)
typedef enum _IOS_RW_MODE {
	RW_SWAP_NONE = 0, // Do not endianness swap the buffer.
	RW_SWAP_INPUT = BIT(0), // Endianness swap the buffer before ioctl call.
	RW_SWAP_OUTPUT = BIT(1), // Endianness swap the buffer after ioctl response.
	RW_SWAP_BOTH = RW_SWAP_INPUT | RW_SWAP_OUTPUT // Endianness swap buffer both before call and after response.
} IOS_RW_MODE;

// IOS ioctl mode bitflags (buffer swap)
typedef enum _IOS_IOCTL_MODE {
	IOCTL_SWAP_NONE = 0, // Do not endianness swap either buffer.
	IOCTL_SWAP_INPUT = BIT(0), // Endianness swap the input buffer.
	IOCTL_SWAP_OUTPUT = BIT(1), // Endianness swap the output buffer.
	IOCTL_SWAP_BOTH = IOCTL_SWAP_INPUT | IOCTL_SWAP_OUTPUT, // Endianness swap both buffers.
} IOS_IOCTL_MODE;

LONG PxiIopOpen(const char* Path, IOS_OPEN_MODE Mode, IOS_HANDLE* Handle);
LONG PxiIopClose(IOS_HANDLE Handle);
LONG PxiIopRead(IOS_HANDLE Handle, PVOID Buffer, ULONG Length, IOS_RW_MODE SwapMode, PULONG NumberOfBytesTransferred);
LONG PxiIopWrite(IOS_HANDLE Handle, PVOID Buffer, ULONG Length, IOS_RW_MODE SwapMode, PULONG NumberOfBytesTransferred);
LONG PxiIopSeek(IOS_HANDLE Handle, LONG Offset, IOS_SEEK_MODE Mode, PULONG FileOffset);
LONG PxiIopIoctl(IOS_HANDLE Handle, ULONG ControlCode, PVOID Input, ULONG LengthInput, PVOID Output, ULONG LengthOutput, IOS_IOCTL_MODE SwapModeInput, IOS_IOCTL_MODE SwapModeOutput);
LONG PxiIopIoctlv(IOS_HANDLE Handle, ULONG ControlCode, ULONG NumRead, ULONG NumWritten, PIOS_IOCTL_VECTOR Buffers, ULONG SwapBuffersIn, ULONG SwapBuffersOut);
LONG PxiIopIoctlvReboot(IOS_HANDLE Handle, ULONG ControlCode, ULONG NumRead, ULONG NumWritten, PIOS_IOCTL_VECTOR Buffers, ULONG SwapBuffersIn, ULONG SwapBuffersOut);
LONG PxiIopIoctlAsync(IOS_HANDLE Handle, ULONG ControlCode, PVOID Input, ULONG LengthInput, PVOID Output, ULONG LengthOutput, IOS_IOCTL_MODE SwapModeInput, IOS_IOCTL_MODE SwapModeOutput, PVOID Context);
bool PxiIopIoctlAsyncPoll(ULONG index, LONG* Result, PVOID* Context);
bool PxiIopIoctlAsyncActive(ULONG index);
LONG PxiIopIoctlvAsync(IOS_HANDLE Handle, ULONG ControlCode, ULONG NumRead, ULONG NumWritten, PIOS_IOCTL_VECTOR Buffers, ULONG SwapBuffersIn, ULONG SwapBuffersOut, PVOID Context);
bool PxiIopIoctlvAsyncPoll(ULONG index,LONG* Result, PVOID* Context);
bool PxiIopIoctlvAsyncActive(ULONG index);
void PxiInit(ARTX_SYSTEM_TYPE SystemType);
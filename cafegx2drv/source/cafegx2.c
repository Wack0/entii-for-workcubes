// NT driver for using the flat GX2 framebuffer.
// The GX2 is set up to use 8in64 swapping.
// This combined with the endian swap elsewhere means the GPU does effective accesses with MSR_LE bitswizzling!
// Therefore we can just provide a flat framebuffer to NT.
// TODO:
// - support other display resolutions (is letterboxing required or can the registers for that just be changed?)
// - support other colour depths
// - support letterboxed 640x480 on the gamepad framebuffer

#define DEVL 1
#include <ntddk.h>
#include <hal.h>
#include <halppc.h>
#include <arc.h>
#include <miniport.h>
#include <ntstatus.h>
#include <devioctl.h>
#include <ntddvdeo.h>
#define VIDEOPORT_API __declspec(dllimport)
#define _NTOSDEF_ 1 // we want internal video.h, because we basically are
#include <video.h>
#include <winerror.h>
#define KIPCR 0xffffd000

extern ULONG NtBuildNumber;

#include "runtime.h"

#define RtlCopyMemory(Destination,Source,Length) memcpy((Destination),(Source),(Length))

#define MS_TO_TIMEOUT(ms) ((ms) * 10000)

// Define hardware device extension.
typedef struct _DEVICE_EXTENSION {
	FRAME_BUFFER PhysicalFrameBuffer;
	ULONG OriginalFrameBuffer;
	ULONG FrameBufferOffset;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

static VIDEO_MODE_INFORMATION s_VideoMode = {0};

VP_STATUS FbFindAdapter(PVOID HwDeviceExtension, PVOID HwContext, PWSTR ArgumentString, PVIDEO_PORT_CONFIG_INFO ConfigInfo, PUCHAR Again) {
	PDEVICE_EXTENSION Extension = (PDEVICE_EXTENSION)HwDeviceExtension;
	
	if (ConfigInfo->Length < sizeof(VIDEO_PORT_CONFIG_INFO)) return ERROR_INVALID_PARAMETER;
	
	// Check that the runtime block is present and sane.
	if (SYSTEM_BLOCK->Length < (sizeof(SYSTEM_PARAMETER_BLOCK) + sizeof(PVOID))) return ERROR_DEV_NOT_EXIST;
	if ((ULONG)RUNTIME_BLOCK < 0x80000000) return ERROR_DEV_NOT_EXIST;
	if ((ULONG)RUNTIME_BLOCK >= 0x90000000) return ERROR_DEV_NOT_EXIST;
	
	// System must be Cafe
	if (RUNTIME_BLOCK[RUNTIME_SYSTEM_TYPE] < ARTX_SYSTEM_LATTE) return ERROR_DEV_NOT_EXIST;
	
	// Grab the framebuffer config and check that it's not NULL and sane.
	PFRAME_BUFFER FbConfig = RUNTIME_BLOCK[RUNTIME_FRAME_BUFFER];
	if ((ULONG)FbConfig == 0) return ERROR_DEV_NOT_EXIST;
	if ((ULONG)FbConfig < 0x80000000) return ERROR_DEV_NOT_EXIST;
	if ((ULONG)FbConfig > 0x90000000) return ERROR_DEV_NOT_EXIST;
	
	
	// Zero out emulator parameters.
	ConfigInfo->NumEmulatorAccessEntries = 0;
	ConfigInfo->EmulatorAccessEntries = NULL;
	ConfigInfo->EmulatorAccessEntriesContext = 0;
	ConfigInfo->VdmPhysicalVideoMemoryAddress.QuadPart = 0;
	ConfigInfo->VdmPhysicalVideoMemoryLength = 0;
	ConfigInfo->HardwareStateSize = 0;
	
	// Set frame buffer information.
	RtlCopyMemory(&Extension->PhysicalFrameBuffer, FbConfig, sizeof(*FbConfig));
	ULONG Height = FbConfig->Height + 1;
	Extension->OriginalFrameBuffer = Extension->PhysicalFrameBuffer.PointerArc;
	
	// If the frame buffer physical address and length is not aligned to 64k,
	// we need to fix a bug in NT.
	ULONG FbAlign = (Extension->OriginalFrameBuffer & 0xffff);
	Extension->FrameBufferOffset = FbAlign;
	
	// Initialise the video mode.
	s_VideoMode.Length = sizeof(s_VideoMode);
	s_VideoMode.ModeIndex = 0;
	s_VideoMode.VisScreenWidth = Extension->PhysicalFrameBuffer.Width;
	s_VideoMode.VisScreenHeight = Extension->PhysicalFrameBuffer.Height;
	s_VideoMode.ScreenStride = Extension->PhysicalFrameBuffer.Stride;
	s_VideoMode.NumberOfPlanes = 1;
	s_VideoMode.BitsPerPlane = 32;
	s_VideoMode.Frequency = 60;
	// todo: Is this correct?
	s_VideoMode.XMillimeter = 320;
	s_VideoMode.YMillimeter = 240;
	s_VideoMode.NumberRedBits = 8;
	s_VideoMode.NumberGreenBits = 8;
	s_VideoMode.NumberBlueBits = 8;
	s_VideoMode.RedMask =   0x00ff0000;
	s_VideoMode.GreenMask = 0x0000ff00;
	s_VideoMode.BlueMask  = 0x000000ff;
	s_VideoMode.AttributeFlags = VIDEO_MODE_GRAPHICS;
	
	// We are done. Only one GX2 device exists.
	*Again = FALSE;
	
	return NO_ERROR;
}

BOOLEAN FbInitialise(PVOID HwDeviceExtension) {
	PDEVICE_EXTENSION Extension = (PDEVICE_EXTENSION)HwDeviceExtension;
	// Nothing needs to be done.
	return TRUE;
}

VP_STATUS FbStartIoImpl(PDEVICE_EXTENSION Extension, PVIDEO_REQUEST_PACKET RequestPacket) {
	switch (RequestPacket->IoControlCode) {
		case IOCTL_VIDEO_SHARE_VIDEO_MEMORY:
		{
			// Map the framebuffer into a process.
			
			// Check buffer lengths.
			if (RequestPacket->OutputBufferLength < sizeof(VIDEO_SHARE_MEMORY_INFORMATION)) return ERROR_INSUFFICIENT_BUFFER;
			if (RequestPacket->InputBufferLength < sizeof(VIDEO_SHARE_MEMORY)) return ERROR_INSUFFICIENT_BUFFER;
			
			// Grab the input buffer.
			PVIDEO_SHARE_MEMORY ShareMemory = (PVIDEO_SHARE_MEMORY) RequestPacket->InputBuffer;
			
			// Ensure what the caller wants is actually inside the framebuffer.
			ULONG MaximumLength = Extension->PhysicalFrameBuffer.Length;
			if (ShareMemory->ViewOffset > MaximumLength) return ERROR_INVALID_PARAMETER;
			if ((ShareMemory->ViewOffset + ShareMemory->ViewSize) > MaximumLength) return ERROR_INVALID_PARAMETER;
			
			RequestPacket->StatusBlock->Information = sizeof(VIDEO_SHARE_MEMORY_INFORMATION);
			
			PVOID VirtualAddress = ShareMemory->ProcessHandle; // you're right, win32k shouldn't exist
			ULONG ViewSize = ShareMemory->ViewSize + Extension->FrameBufferOffset;
			
			// grab the physaddr of the framebuffer
			PHYSICAL_ADDRESS FrameBufferPhys;
			FrameBufferPhys.QuadPart = 0;
			FrameBufferPhys.LowPart = Extension->OriginalFrameBuffer;
			ULONG InIoSpace = FALSE;
			
			VP_STATUS Status = VideoPortMapMemory(Extension, FrameBufferPhys, &ViewSize, &InIoSpace, &VirtualAddress);
			
			PVIDEO_SHARE_MEMORY_INFORMATION Information = (PVIDEO_SHARE_MEMORY_INFORMATION) RequestPacket->OutputBuffer;
			
			Information->SharedViewOffset = ShareMemory->ViewOffset;
			Information->VirtualAddress = VirtualAddress;
			Information->SharedViewSize = ViewSize;
			return Status;
		}
			break;
		case IOCTL_VIDEO_UNSHARE_VIDEO_MEMORY:
		{
			// Unmaps a previously mapped framebuffer.
			if (RequestPacket->InputBufferLength < sizeof(VIDEO_SHARE_MEMORY)) return ERROR_INSUFFICIENT_BUFFER;
			
			PVIDEO_SHARE_MEMORY SharedMem = RequestPacket->InputBuffer;
			return VideoPortUnmapMemory(Extension, SharedMem->RequestedVirtualAddress, SharedMem->ProcessHandle);
		}
			break;
		case IOCTL_VIDEO_MAP_VIDEO_MEMORY:
		{
			// Maps the entire framebuffer into the caller's address space.
			
			if (RequestPacket->OutputBufferLength < sizeof(VIDEO_MEMORY_INFORMATION)) return ERROR_INSUFFICIENT_BUFFER;
			if (RequestPacket->InputBufferLength < sizeof(VIDEO_MEMORY)) return ERROR_INSUFFICIENT_BUFFER;
			
			RequestPacket->StatusBlock->Information = sizeof(VIDEO_MEMORY_INFORMATION);
			
			PVIDEO_MEMORY_INFORMATION MemInfo = (PVIDEO_MEMORY_INFORMATION) RequestPacket->OutputBuffer;
			PVIDEO_MEMORY Mem = (PVIDEO_MEMORY) RequestPacket->InputBuffer;
			
			MemInfo->VideoRamBase = Mem->RequestedVirtualAddress;
			ULONG MaximumLength = Extension->PhysicalFrameBuffer.Length + Extension->FrameBufferOffset;
			MemInfo->VideoRamLength = MaximumLength;
			ULONG InIoSpace = FALSE;
			PHYSICAL_ADDRESS FrameBufferPhys;
			FrameBufferPhys.QuadPart = 0;
			FrameBufferPhys.LowPart = Extension->OriginalFrameBuffer;
			VP_STATUS Status = VideoPortMapMemory(Extension, FrameBufferPhys, &MemInfo->VideoRamLength, &InIoSpace, &MemInfo->VideoRamBase);
			MemInfo->FrameBufferBase = MemInfo->VideoRamBase;
			MemInfo->FrameBufferLength = MemInfo->VideoRamLength;
			return Status;
		}
			break;
		case IOCTL_VIDEO_UNMAP_VIDEO_MEMORY:
		{
			// Unmaps the framebuffer from the caller's address space.
			if (RequestPacket->InputBufferLength < sizeof(VIDEO_MEMORY)) return ERROR_INSUFFICIENT_BUFFER;
			PVIDEO_MEMORY Mem = (PVIDEO_MEMORY)RequestPacket->InputBuffer;
			return VideoPortUnmapMemory(Extension, Mem->RequestedVirtualAddress, 0);
		}
			break;
		case IOCTL_VIDEO_QUERY_CURRENT_MODE:
			// Gets the current video mode.
		case IOCTL_VIDEO_QUERY_AVAIL_MODES:
			// Returns information about available video modes (array of VIDEO_MODE_INFORMATION), of which there is exactly one.
			// Thus for Open Firmware frame buffer, implementation is same as QUERY_CURRENT_MODE.
		{
			if (RequestPacket->OutputBufferLength < sizeof(VIDEO_MODE_INFORMATION)) return ERROR_INSUFFICIENT_BUFFER;
			RequestPacket->StatusBlock->Information = sizeof(VIDEO_MODE_INFORMATION);
			RtlCopyMemory(RequestPacket->OutputBuffer, &s_VideoMode, sizeof(s_VideoMode));
			return NO_ERROR;
		}
		case IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES:
		{
			// Returns number of valid mode and size of each structure returned.
			if (RequestPacket->OutputBufferLength < sizeof(VIDEO_NUM_MODES)) return ERROR_INSUFFICIENT_BUFFER;
			
			RequestPacket->StatusBlock->Information = sizeof(VIDEO_NUM_MODES);
			PVIDEO_NUM_MODES NumModes = (PVIDEO_NUM_MODES)RequestPacket->OutputBuffer;
			NumModes->NumModes = 1;
			NumModes->ModeInformationLength = sizeof(VIDEO_MODE_INFORMATION);
			return NO_ERROR;
		}
		case IOCTL_VIDEO_SET_CURRENT_MODE:
		{
			if (RequestPacket->InputBufferLength < sizeof(VIDEO_MODE)) return ERROR_INSUFFICIENT_BUFFER;
			PVIDEO_MODE Mode = (PVIDEO_MODE)RequestPacket->InputBuffer;
			if (Mode->RequestedMode >= 1) return ERROR_INVALID_PARAMETER;
			// Only a single video mode available, so, no operation.
			return NO_ERROR;
		}
		case IOCTL_VIDEO_RESET_DEVICE:
		{
			// Reset device. No operation for now.
			return NO_ERROR;
		}
	}
	
	return ERROR_INVALID_FUNCTION;
}

BOOLEAN FbStartIo(PVOID HwDeviceExtension, PVIDEO_REQUEST_PACKET RequestPacket) {
	PDEVICE_EXTENSION Extension = (PDEVICE_EXTENSION)HwDeviceExtension;
	RequestPacket->StatusBlock->Status = FbStartIoImpl(Extension, RequestPacket);
	return TRUE;
}

NTSTATUS DriverEntry(PVOID DriverObject, PVOID RegistryPath) {
	VIDEO_HW_INITIALIZATION_DATA InitData;
	RtlZeroMemory(&InitData, sizeof(InitData));
	
	InitData.HwInitDataSize = sizeof(VIDEO_HW_INITIALIZATION_DATA);
	
	InitData.HwFindAdapter = FbFindAdapter;
	InitData.HwInitialize = FbInitialise;
	InitData.HwStartIO = FbStartIo;
	
	InitData.HwDeviceExtensionSize = sizeof(DEVICE_EXTENSION);
	
	// Internal does not work here.
	// Our HAL(s) configure VMEBus to be equal to Internal, nothing else uses it.
	InitData.AdapterInterfaceType = VMEBus;
	NTSTATUS Status = VideoPortInitialize(DriverObject, RegistryPath, &InitData, NULL);
	return Status;
}
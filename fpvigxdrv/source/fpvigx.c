// NT driver for Flipper GPU/Video Interface.
// The framebuffer already mapped by the ARC firmware is used as XFB.
// We allocate a framebuffer to send to clients.
// Under text setup, we copy that to real EFB on a timer.
// If not under text setup, we use BP/XF/SU to copy the framebuffer as ARGB8 texture to EFB, on vblank.
// (as GDI driver can write to framebuffer in the correct format for that)
// Under NT4, GDI driver runs in kernel mode so can write to EFB directly through a BAT.
// On vblank, no matter what, PE raster registers are poked to copy EFB->XFB.

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

extern ULONG NtBuildNumber;

#include "runtime.h"
#include "efb.h"
#include "cp.h"
#include "vi.h"

// Only define this if testing the GDI-specific codepaths under setupdd
//#define SETUPDD_TEST

#define RtlCopyMemory(Destination,Source,Length) memcpy((Destination),(Source),(Length))

#define MS_TO_TIMEOUT(ms) ((ms) * 10000)

// Define hardware device extension.
typedef struct _DEVICE_EXTENSION {
	FRAME_BUFFER PhysicalFrameBuffer;
	MEMORY_AREA GxFifoMem;
	PVOID FpRegisters;
	//PVI_REGISTERS ViRegisters;
	ULONG OriginalFrameBuffer;
	ULONG FrameBufferOffset;
	PVOID MappedFrameBuffer;
	PULONG DoubleFrameBufferAlloc;
	PULONG DoubleFrameBuffer;
	ULONG DoubleFrameBufferPhys;
	PUSHORT ArrayVerticies;
	ULONG ArrayVerticiesPhys;
	KDPC TimerDpc;
	KTIMER Timer;
	//BOOLEAN InIoSpace;
	BOOLEAN SetupddLoaded;
	BOOLEAN DirectEfbWrites;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

enum {
	DOUBLE_FRAMEBUFFER_WIDTH = 640,
	DOUBLE_FRAMEBUFFER_HEIGHT = 480,
	DOUBLE_FRAMEBUFFER_STRIDE = DOUBLE_FRAMEBUFFER_WIDTH * sizeof(ULONG),
	DOUBLE_FRAMEBUFFER_LENGTH = DOUBLE_FRAMEBUFFER_HEIGHT * DOUBLE_FRAMEBUFFER_STRIDE
};

static VIDEO_MODE_INFORMATION s_VideoMode = {0};

// Use the pixel engine to copy the embedded framebuffer to the video interface framebuffer.
// Ensure the GPU registers are initialised for the copy.
void PeCopyEfbToXfbWithoutDrawDone(PDEVICE_EXTENSION Extension) {
	ULONG NumberOfBpRegWrites = 0;
	// Set blend mode
	CppWriteBpReg(BPMEM_BLENDMODE | 0x6bd);
	NumberOfBpRegWrites++;
	// Set Z mode
	CppWriteBpReg(BPMEM_ZMODE | 0x1f);
	NumberOfBpRegWrites++;
	// Set blend mode again with enable off
	CppWriteBpReg(BPMEM_BLENDMODE | 0x6bc);
	NumberOfBpRegWrites++;
	// Set Z compare
	CppWriteBpReg(BPMEM_ZCOMPARE);
	NumberOfBpRegWrites++;
	
	
	// Set EFB source rectangle (top, left)
	CppWriteBpReg(BPMEM_EFB_TL);
	NumberOfBpRegWrites++;
	// Set EFB source rectangle (width, height)
	CppWriteBpReg(
		BPMEM_EFB_WH |
		(639 << 0) |
		(479 << 10)
	);
	NumberOfBpRegWrites++;
	// Set destination physical address.
	CppWriteBpReg(
		BPMEM_EFB_ADDR |
		(Extension->PhysicalFrameBuffer.PointerArc >> 5)
	);
	NumberOfBpRegWrites++;
	// Set destination stride.
	CppWriteBpReg(
		BPMEM_EFB_STRIDE |
		(Extension->PhysicalFrameBuffer.Stride >> 5)
	);
	NumberOfBpRegWrites++;
	// Start copy.
	ULONG Clear = 1;
#ifndef SETUPDD_TEST
	if (Extension->SetupddLoaded) Clear = 0;
#endif
	CppWriteBpReg(
		BPMEM_TRIGGER_EFB_COPY |
		(1 << 0)      | // Clamp top.
		(1 << 1)      | // Clamp bottom.
		(Clear << 11) | // Clear EFB.
		(1 << 14)       // Copy to XFB.
	);
	NumberOfBpRegWrites++;
	// Set Z mode
	CppWriteBpReg(BPMEM_ZMODE | 0x17);
	NumberOfBpRegWrites++;
	// Set blend mode
	CppWriteBpReg(BPMEM_BLENDMODE | 0x6bd);
	NumberOfBpRegWrites++;
	// Set Z compare
	CppWriteBpReg(BPMEM_ZCOMPARE | 0x40);
	NumberOfBpRegWrites++;
	
	// Fill the rest of the buffer with nops to flush it and start the operations.
	for (ULONG i = NumberOfBpRegWrites * 5; (i & 31) != 0; i++) {
	//for (ULONG i = 0; i < 32; i++) {
		CppWrite8(0);
	}
}

// Use the pixel engine to copy the embedded framebuffer to the video interface framebuffer.
// Ensure the GPU registers are initialised for the copy.
void PeCopyEfbToXfbInit(PDEVICE_EXTENSION Extension) {
	ULONG NumberOfBpRegWrites = 0;
	// Set blend mode
	CppWriteBpReg(BPMEM_BLENDMODE | 0x6bd);
	NumberOfBpRegWrites++;
	// Set Z mode
	CppWriteBpReg(BPMEM_ZMODE | 0x1f);
	NumberOfBpRegWrites++;
	// Set blend mode again with enable off
	CppWriteBpReg(BPMEM_BLENDMODE | 0x6bc);
	NumberOfBpRegWrites++;
	// Set Z compare
	CppWriteBpReg(BPMEM_ZCOMPARE);
	NumberOfBpRegWrites++;
	
	
	// Set EFB source rectangle (top, left)
	CppWriteBpReg(BPMEM_EFB_TL);
	NumberOfBpRegWrites++;
	// Set EFB source rectangle (width, height)
	CppWriteBpReg(
		BPMEM_EFB_WH |
		(639 << 0) |
		(479 << 10)
	);
	NumberOfBpRegWrites++;
	// Set destination physical address.
	CppWriteBpReg(
		BPMEM_EFB_ADDR |
		(Extension->PhysicalFrameBuffer.PointerArc >> 5)
	);
	NumberOfBpRegWrites++;
	// Set destination stride.
	CppWriteBpReg(
		BPMEM_EFB_STRIDE |
		(Extension->PhysicalFrameBuffer.Stride >> 5)
	);
	NumberOfBpRegWrites++;
	// Start copy.
	ULONG Clear = 1;
#ifndef SETUPDD_TEST
	if (Extension->SetupddLoaded) Clear = 0;
#endif
	CppWriteBpReg(
		BPMEM_TRIGGER_EFB_COPY |
		(1 << 0)      | // Clamp top.
		(1 << 1)      | // Clamp bottom.
		(Clear << 11) | // Clear EFB.
		(1 << 14)       // Copy to XFB.
	);
	NumberOfBpRegWrites++;
	// Set Z mode
	CppWriteBpReg(BPMEM_ZMODE | 0x17);
	NumberOfBpRegWrites++;
	// Set blend mode
	CppWriteBpReg(BPMEM_BLENDMODE | 0x6bd);
	NumberOfBpRegWrites++;
	// Set Z compare
	CppWriteBpReg(BPMEM_ZCOMPARE | 0x40);
	NumberOfBpRegWrites++;
	// Set draw done.
	CppWriteBpReg(
		BPMEM_SETDRAWDONE |
		0x02
	);
	NumberOfBpRegWrites++;
	
	// Fill the rest of the buffer with nops to flush it and start the operations.
	for (ULONG i = NumberOfBpRegWrites * 5; (i & 31) != 0; i++) {
	//for (ULONG i = 0; i < 32; i++) {
		CppWrite8(0);
	}
}

// Use the pixel engine to copy the embedded framebuffer to the video interface framebuffer.
static void PeCopyEfbToXfb(void) {
	ULONG NumberOfBpRegWrites = 0;
	// Start copy.
	CppWriteBpReg(
		BPMEM_TRIGGER_EFB_COPY |
		(1 << 0) | // Clamp top.
		(1 << 1) | // Clamp bottom.
		(1 << 14) // Copy to XFB.
	);
	NumberOfBpRegWrites++;
	// Set draw done.
	CppWriteBpReg(
		BPMEM_SETDRAWDONE |
		0x02
	);
	NumberOfBpRegWrites++;
	
	// Fill the rest of the buffer with nops to flush it and start the operations.
	for (ULONG i = NumberOfBpRegWrites * 5; (i & 31) != 0; i++) {
	//for (ULONG i = 0; i < 32; i++) {
		CppWrite8(0);
	}
}

#define __mfdec() \
	({ ULONG result; \
	__asm__ volatile ("mfdec %0" : "=r" (result)); \
	/*return*/ result; })
	
#undef _disable
#undef _enable
#define _disable()    \
  ({ ULONG result; \
     __asm__ volatile ("mfmsr %0" : "=r" (result)); \
     ULONG mcrNew = result & ~0x8000; \
     __asm__ volatile ("mtmsr %0 ; isync" : : "r" (mcrNew)); \
     /*return*/ result & 0x8000; })

#define _enable()     \
  ({ ULONG result; \
     __asm__ volatile ("mfmsr %0" : "=r" (result)); \
     ULONG mcrNew = result | 0x8000; \
     __asm__ volatile ("mtmsr %0 ; isync" : : "r" (mcrNew)); })

static void PepCopyLeDoubleBufferToEfb(PDEVICE_EXTENSION Extension) {
	PULONG DoubleFrameBuffer = (PULONG)Extension->DoubleFrameBuffer;
	volatile ULONG* ExternalFrameBuffer = (volatile ULONG*)( (PUCHAR)EFB_VIRT_ADDR );
	for (ULONG Height = 0; Height < DOUBLE_FRAMEBUFFER_HEIGHT; Height++) {
		for (ULONG Width = 0; Width < DOUBLE_FRAMEBUFFER_WIDTH; Width++) {
			// Take an interrupt here and we are dead
			_disable();
			EfbWrite32( &ExternalFrameBuffer[ Width ], DoubleFrameBuffer[ Width ] );
			_enable();
		}
		ExternalFrameBuffer = (volatile ULONG*)( (PUCHAR)ExternalFrameBuffer + EFB_STRIDE );
		DoubleFrameBuffer = (PULONG)( (PUCHAR)DoubleFrameBuffer + DOUBLE_FRAMEBUFFER_STRIDE );
	}
}

static void PepCopyBeDoubleBufferToEfb(PDEVICE_EXTENSION Extension) {
	// Flush dcache for double buffer.
	// Not actually needed as the double buffer is always mapped uncached.
	//HalSweepDcacheRange(Extension->DoubleFrameBuffer, DOUBLE_FRAMEBUFFER_LENGTH);
	
	ULONG NumberOfBytesWritten = 0;
	// Invalidate vertex cache.
	CppWrite8(0x48);
	NumberOfBytesWritten++;
	// Invalidate all textures.
	CppWriteBpReg(BPMEM_IND_IMASK);
	NumberOfBytesWritten += 5;
	CppWriteBpReg(BPMEM_TEXINVALIDATE | (8 << 9) | 0x000);
	NumberOfBytesWritten += 5;
	CppWriteBpReg(BPMEM_TEXINVALIDATE | (8 << 9) | 0x100);
	NumberOfBytesWritten += 5;
	CppWriteBpReg(BPMEM_IND_IMASK);
	NumberOfBytesWritten += 5;
	// Initialise the array verticies physical address.
	CppWrite8(0x08);
	CppWrite8(0xA0);
	CppWrite32(Extension->ArrayVerticiesPhys);
	NumberOfBytesWritten += 6;
	// Set up the texture dma.
	CppWriteBpReg(
		BPMEM_TX_SETMODE0 | 
		(1 << 4) |
		(4 << 5)
	);
	NumberOfBytesWritten += 5;
	CppWriteBpReg(BPMEM_TX_SETMODE1); // no lod set
	NumberOfBytesWritten += 5;
	CppWriteBpReg(
		BPMEM_TX_SETIMAGE0 |
		((640 - 1) << 0) | // width
		((480 - 1) << 10) | // height
		(6 << 20) // format: RGBA8
		//(4 << 20) // format: RGB565
	);
	NumberOfBytesWritten += 5;
	CppWriteBpReg(
		BPMEM_TX_SETIMAGE1 |
		(3 << 15) | // even tmem width?
		(3 << 18)   // even tmem height?
	);
	NumberOfBytesWritten += 5;
	CppWriteBpReg(
		BPMEM_TX_SETIMAGE2 |
		0x4000 |    // odd tmem line
		(3 << 15) | // odd tmem width?
		(3 << 18)   // odd tmem height?
	);
	NumberOfBytesWritten += 5;
	CppWriteBpReg(BPMEM_TX_SETIMAGE3 |
		(Extension->DoubleFrameBufferPhys >> 5)
	);
	NumberOfBytesWritten += 5;
	
	// Write XF registers
	// These are actually floats, but as we don't care about custom params (we just blit the whole framebuffer),
	// we can just hardcode the correct values
	CppWrite8(0x10);
	CppWrite32(
		0 |          // XF address 0
		((12 - 1) << 16)   // number of registers to set
	);
	NumberOfBytesWritten += 5;
	CppWrite32(0x3f7fffff);
	CppWrite32(0x00000000);
	CppWrite32(0x00000000);
	CppWrite32(0x00000000);
	CppWrite32(0x00000000);
	CppWrite32(0x3f7ffffe);
	CppWrite32(0x00000000);
	CppWrite32(0x00000000);
	CppWrite32(0x00000000);
	CppWrite32(0x00000000);
	CppWrite32(0x3f7fffff);
	CppWrite32(0xc2c7ffff);
	NumberOfBytesWritten += (12 * 4);
	
	// Write scaling registers (this is basically just height and width again)
	CppWriteBpReg(
		BPMEM_SU_SSIZE |
		(640 - 1)
	);
	NumberOfBytesWritten += 5;
	
	CppWriteBpReg(
		BPMEM_SU_TSIZE |
		(480 - 1)
	);
	NumberOfBytesWritten += 5;
	
	// And finally draw the texture to efb
	CppWrite8(0x80); // Draw quads
	CppWrite16(4); // 4 of them
	
	CppWrite8(0); // index 0
	CppWrite8(0); // colour 0
	CppWrite32(0); // from 0.0
	CppWrite32(0); // to 0.0
	
	CppWrite8(1); // index 1
	CppWrite8(0); // colour 0
	CppWrite32(0x3f800000); // from 1.0
	CppWrite32(0); // to 0.0
	
	CppWrite8(2); // index 2
	CppWrite8(0); // colour 0
	CppWrite32(0x3f800000); // from 1.0
	CppWrite32(0x3f800000); // to 1.0
	
	CppWrite8(3); // index 3
	CppWrite8(0); // colour 0
	CppWrite32(0); // from 0
	CppWrite32(0x3f800000); // to 1.0
	NumberOfBytesWritten += 3 + (4 * 10);
	
	for (ULONG i = NumberOfBytesWritten; (i & 31) != 0; i++) {
		CppWrite8(0);
	}
}

// Video Interface interrupt handler
BOOLEAN ViInterruptHandler(PVOID HwDeviceExtension) {
	PDEVICE_EXTENSION Extension = (PDEVICE_EXTENSION)HwDeviceExtension;
	
	// Get the status of the interrupt that should be handled.
	BOOLEAN RaisedInt0 = VI_INTERRUPT_STATUS(0);
	BOOLEAN RaisedInt1 = VI_INTERRUPT_STATUS(1);
	
	// Clear all interrupts.
	for (ULONG i = 0; i < VI_INTERRUPT_COUNT; i++) {
		VI_INTERRUPT_CLEAR(i);
	}

	// If interrupt zero or one were not raised, return.
	if (!RaisedInt1) return TRUE;
	//if (!RaisedInt0 && !RaisedInt1) return TRUE;
	//if (!RaisedInt0) return TRUE;
	
	// If CP is not idle, return.
	if ((PE_FIFO_INTSTAT() & 0xC) != 0xC) return TRUE;
	// If write gather pipe not empty, return.
	if (CppFifoNotEmpty()) return TRUE;
	// If GPU is busy, return.
	if (!PE_FINISHED_RENDER) return TRUE;
	PE_FINISHED_CLEAR();
	
#if 0
	// Ensure CP FIFO looks ok.
	ULONG WriteAddr = PI_CP_WRITE_ADDR();
	ULONG WriteAddrEnd = WriteAddr + 0x20;
	ULONG GxFifoStart = Extension->GxFifoMem.PointerArc;
	ULONG GxFifoEnd = Extension->GxFifoMem.PointerArc + Extension->GxFifoMem.Length;
	if (WriteAddr < GxFifoStart || WriteAddrEnd > GxFifoEnd) {
		KeBugCheckEx(0xdeaddead, WriteAddr, WriteAddrEnd, GxFifoStart, GxFifoEnd);
	}
	
	// Grab CP FIFO on GPU side.
	ULONG WritePointer = CP_READ32(FifoWritePointer);
	ULONG ReadPointer = CP_READ32(FifoReadPointer);
	ULONG Count = CP_READ32(FifoCount);
#endif
	
	if ((PE_FIFO_INTSTAT() & 2) != 0) {
		// PE underflow.
		PE_FIFO_CLEAR();
	}
	
	// Copy double buffer to EFB.
#ifndef SETUPDD_TEST
	if (!Extension->DirectEfbWrites && !Extension->SetupddLoaded)
#else
	if (!Extension->DirectEfbWrites)
#endif
	{
		PepCopyBeDoubleBufferToEfb(Extension);
	}
	// Copy EFB to XFB.
	PeCopyEfbToXfb();
	//PeCopyEfbToXfbInit(Extension);
#if 0
	// Spin and wait for the render to finish?
	ULONG Ticks = 0;
	ULONG Dec = __mfdec();
	while (!PE_FINISHED_RENDER) {
		if (__mfdec() != Dec) {
			Ticks++;
			Dec = __mfdec();
		}
		if (Ticks == 10000) {
			//KeBugCheckEx(0xdeaddead, CP_READ32(FifoWritePointer), CP_READ32(FifoReadPointer), CP_READ32(FifoCount), PE_FIFO_INTSTAT());
			KeBugCheckEx(0xdeaddead, Extension->GxFifoMem.PointerArc, Extension->GxFifoMem.PointerArc + Extension->GxFifoMem.Length, PE_FIFO_INTSTAT(), __mfspr(SPR_WPAR));
		}
	}
	PE_FINISHED_CLEAR();
#endif
	
	return TRUE;
}

static BOOLEAN FbpSetupddLoaded(void) {
	// Determine if setupdd is loaded.
	// We do this by checking if KeLoaderBlock->SetupLoaderBlock is non-NULL.
	// This is the same way that kernel itself does it, and offset of this elem is stable.
	PLOADER_PARAMETER_BLOCK LoaderBlock = *(PLOADER_PARAMETER_BLOCK*)KeLoaderBlock;
	return LoaderBlock->SetupLoaderBlock != NULL;
}

static BOOLEAN FbpHasWin32k(void) {
	// Determine if GDI drivers run in kernel mode.
	// This is a simple build number check.
	return ((NtBuildNumber & ~0xF0000000) > 1057);
}

static void FbpStartTimer(PDEVICE_EXTENSION Extension) {
	LARGE_INTEGER DueTime;
	DueTime.QuadPart = -MS_TO_TIMEOUT(100); // roughly 10fps
	KeSetTimer(&Extension->Timer, DueTime, &Extension->TimerDpc);
}

static void FbpTimerCallback(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
	PDEVICE_EXTENSION Extension = (PDEVICE_EXTENSION)DeferredContext;
	
#ifndef SETUPDD_TEST
	PepCopyLeDoubleBufferToEfb(Extension);
#endif
	
	FbpStartTimer(Extension);
}

VP_STATUS ViFindAdapter(PVOID HwDeviceExtension, PVOID HwContext, PWSTR ArgumentString, PVIDEO_PORT_CONFIG_INFO ConfigInfo, PUCHAR Again) {
	PDEVICE_EXTENSION Extension = (PDEVICE_EXTENSION)HwDeviceExtension;
	
	if (ConfigInfo->Length < sizeof(VIDEO_PORT_CONFIG_INFO)) return ERROR_INVALID_PARAMETER;
	
	// Check that the runtime block is present and sane.
	if (SYSTEM_BLOCK->Length < (sizeof(SYSTEM_PARAMETER_BLOCK) + sizeof(PVOID))) return ERROR_DEV_NOT_EXIST;
	if ((ULONG)RUNTIME_BLOCK < 0x80000000) return ERROR_DEV_NOT_EXIST;
	if ((ULONG)RUNTIME_BLOCK >= 0x90000000) return ERROR_DEV_NOT_EXIST;
	
	// Grab the framebuffer config and check that it's not NULL and sane.
	PFRAME_BUFFER FbConfig = RUNTIME_BLOCK[RUNTIME_FRAME_BUFFER];
	if ((ULONG)FbConfig == 0) return ERROR_DEV_NOT_EXIST;
	if ((ULONG)FbConfig < 0x80000000) return ERROR_DEV_NOT_EXIST;
	if ((ULONG)FbConfig > 0x90000000) return ERROR_DEV_NOT_EXIST;
	
	// Grab the GX fifo memory, and check that it's sane.
	PMEMORY_AREA GxFifoMem = RUNTIME_BLOCK[RUNTIME_GX_FIFO];
	if ((ULONG)GxFifoMem == 0) return ERROR_DEV_NOT_EXIST;
	if ((ULONG)GxFifoMem < 0x80000000) return ERROR_DEV_NOT_EXIST;
	if ((ULONG)GxFifoMem > 0x90000000) return ERROR_DEV_NOT_EXIST;
	
	
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
	if (Height > 480) {
		// Set the destination address such that the copy will be centered.
		ULONG Offset = FbConfig->Stride;
		ULONG CentreHeight = (Height / 2) - (480 / 2);
		Offset *= CentreHeight;
		Extension->PhysicalFrameBuffer.PointerArc += Offset;
	}
	BOOLEAN SetupddLoaded = FbpSetupddLoaded();
	Extension->SetupddLoaded = SetupddLoaded;
	//BOOLEAN HasWin32k = FbpHasWin32k();
	// Do not use direct EFB writes in win32k.
	// For them to work:
	// - we can't get context switched out of the way (ie, we must be in DPC IRQL or lower)
	// - sync instruction must be before and
	// - has to be mapped by BAT, thanks to above any page fault when doing EFB write will cause issues
	BOOLEAN HasWin32k = FALSE;
	Extension->DirectEfbWrites = HasWin32k;
	
	// If the frame buffer physical address and length is not aligned to 64k,
	// we need to fix a bug in NT.
	ULONG FbAlign = (Extension->OriginalFrameBuffer & 0xffff);
	Extension->FrameBufferOffset = FbAlign;
	
	// Set the GX fifo memory information.
	RtlCopyMemory(&Extension->GxFifoMem, GxFifoMem, sizeof(*GxFifoMem));
	
	// Fill in the array verticies.
	if (!HasWin32k && !SetupddLoaded) {
		PHYSICAL_ADDRESS HighestAcceptable;
		HighestAcceptable.HighPart = 0;
		HighestAcceptable.LowPart = 0x0FFFFFFF;
		ULONG ArrayVerticiesBase = (ULONG)
			MmAllocateContiguousMemory( 12 * sizeof(USHORT) + 0x20, HighestAcceptable );
		if ((ArrayVerticiesBase & 31) != 0)
			ArrayVerticiesBase += 32 - (ArrayVerticiesBase & 31);
		PUSHORT ArrayVerticies = (PUSHORT)ArrayVerticiesBase;
		PHYSICAL_ADDRESS ArrayVerticiesPhys = MmGetPhysicalAddress( ArrayVerticies );
		Extension->ArrayVerticiesPhys = ArrayVerticiesPhys.LowPart;
		Extension->ArrayVerticies = ArrayVerticies;
		
		RtlZeroMemory(ArrayVerticies, sizeof(USHORT) * 12);
		
		NativeWriteBase16(ArrayVerticies, 2 * ((3 * 0) + 0), -320);
		NativeWriteBase16(ArrayVerticies, 2 * ((3 * 3) + 0), -320);
		NativeWriteBase16(ArrayVerticies, 2 * ((3 * 0) + 1), 240);
		NativeWriteBase16(ArrayVerticies, 2 * ((3 * 1) + 1), 240);
		NativeWriteBase16(ArrayVerticies, 2 * ((3 * 2) + 1), -240);
		NativeWriteBase16(ArrayVerticies, 2 * ((3 * 3) + 1), -240);
		NativeWriteBase16(ArrayVerticies, 2 * ((3 * 1) + 0), 320);
		NativeWriteBase16(ArrayVerticies, 2 * ((3 * 2) + 0), 320);
	}
	
	
	// Ensure all VI interrupts are cleared and unset.
	for (ULONG i = 0; i < VI_INTERRUPT_COUNT; i++) {
		VI_INTERRUPT_DISABLE(i);
		VI_INTERRUPT_CLEAR(i);
	}
	
	// Configure the interrupt.
	ConfigInfo->BusInterruptVector = VECTOR_VI;
	ConfigInfo->BusInterruptLevel = 1;
	
	// Enable the command processor FIFO.
	CppFifoEnable();
	
	// If setupdd is loaded, we need to set up a framebuffer copy in main memory.
	// We'll use only 640x480x32 for this.
	Extension->DoubleFrameBuffer = NULL;
	Extension->MappedFrameBuffer = NULL;
	Extension->DoubleFrameBufferPhys = 0;
	Extension->FrameBufferOffset = 0;
	if (SetupddLoaded || !HasWin32k)
	{
		PHYSICAL_ADDRESS HighestAcceptable;
		//HighestAcceptable.LowPart = HighestAcceptable.HighPart = 0xFFFFFFFFu;
		HighestAcceptable.HighPart = 0;
		HighestAcceptable.LowPart = 0x0FFFFFFF;
		Extension->DoubleFrameBufferAlloc = (PULONG)
			MmAllocateContiguousMemory( DOUBLE_FRAMEBUFFER_LENGTH + 0x20, HighestAcceptable );
		if (Extension->DoubleFrameBufferAlloc == NULL) return ERROR_DEV_NOT_EXIST;
		ULONG DoubleFbAlign = ((ULONG)Extension->DoubleFrameBufferAlloc) & 0x1f;
		if (DoubleFbAlign != 0) {
			ULONG AlignOffset = 0x20 - DoubleFbAlign;
			Extension->DoubleFrameBufferAlloc = (PULONG)
				((ULONG)Extension->DoubleFrameBufferAlloc + AlignOffset);
		}
		PHYSICAL_ADDRESS DoubleFrameBufferPhys = MmGetPhysicalAddress( Extension->DoubleFrameBufferAlloc );
		Extension->DoubleFrameBufferPhys = DoubleFrameBufferPhys.LowPart;
		FbAlign = (Extension->DoubleFrameBufferPhys & 0xffff);
		Extension->FrameBufferOffset = FbAlign;
		Extension->DoubleFrameBuffer = MmMapIoSpace( DoubleFrameBufferPhys, DOUBLE_FRAMEBUFFER_LENGTH, MmNonCached );
		
#if 0
		// Map the frame buffer.
		PHYSICAL_ADDRESS FrameBufferPhys;
		FrameBufferPhys.QuadPart = 0;
		FrameBufferPhys.LowPart = EFB_PHYS_ADDR;
		PVOID MappedFb = MmMapIoSpace(FrameBufferPhys, EFB_LENGTH, MmNonCached);
		if (MappedFb == NULL) {
			return ERROR_INVALID_PARAMETER;
		}
		Extension->MappedFrameBuffer = MappedFb;
#endif
		if (SetupddLoaded) {
			// Also initialise the timer and DPC.
			KeInitializeDpc(&Extension->TimerDpc, FbpTimerCallback, Extension);
			KeInitializeTimer(&Extension->Timer);
		}
	}
	
	// Initialise the video mode.
	s_VideoMode.Length = sizeof(s_VideoMode);
	s_VideoMode.ModeIndex = 0;
#if 0
	if (SetupddLoaded) {
		s_VideoMode.VisScreenWidth = DOUBLE_FRAMEBUFFER_WIDTH;
		s_VideoMode.VisScreenHeight = DOUBLE_FRAMEBUFFER_HEIGHT;
		s_VideoMode.ScreenStride = DOUBLE_FRAMEBUFFER_STRIDE;
	} else {	
		// EFB is 640x480 or 640x528, we will always render 640x480.
		s_VideoMode.VisScreenWidth = 640;
		s_VideoMode.VisScreenHeight = 480;
		s_VideoMode.ScreenStride = EFB_STRIDE;
	}
#endif
	if (!SetupddLoaded && HasWin32k) {
		// EFB is 640x480 or 640x528, we will always render 640x480.
		s_VideoMode.VisScreenWidth = 640;
		s_VideoMode.VisScreenHeight = 480;
		s_VideoMode.ScreenStride = EFB_STRIDE;
	} else {
		s_VideoMode.VisScreenWidth = DOUBLE_FRAMEBUFFER_WIDTH;
		s_VideoMode.VisScreenHeight = DOUBLE_FRAMEBUFFER_HEIGHT;
		s_VideoMode.ScreenStride = DOUBLE_FRAMEBUFFER_STRIDE;
	}
	s_VideoMode.NumberOfPlanes = 1;
	s_VideoMode.BitsPerPlane = 32;
	s_VideoMode.Frequency = 60;
	// todo: Is this correct?
	s_VideoMode.XMillimeter = 320;
	s_VideoMode.YMillimeter = 240;
	s_VideoMode.NumberRedBits = 8;
	s_VideoMode.NumberGreenBits = 8;
	s_VideoMode.NumberBlueBits = 8;
	// watch out for endianness!
	s_VideoMode.BlueMask =  0x000000ff;
	s_VideoMode.GreenMask = 0x0000ff00;
	s_VideoMode.RedMask =   0x00ff0000;
	s_VideoMode.AttributeFlags = VIDEO_MODE_GRAPHICS;
#ifdef SETUPDD_TEST
	if (SetupddLoaded) {
		s_VideoMode.BitsPerPlane = 16;
		s_VideoMode.RedMask = 0x001f;
		s_VideoMode.GreenMask = 0x07e0;
		s_VideoMode.BlueMask = 0xf800;
	}
#endif
#if 0
	if (!SetupddLoaded) {
		s_VideoMode.BitsPerPlane = 16;
		s_VideoMode.RedMask = 0x001f;
		s_VideoMode.GreenMask = 0x07e0;
		s_VideoMode.BlueMask = 0xf800;
	}
#endif
	
	// We are done. Only one device exists.
	*Again = FALSE;
	
	return NO_ERROR;
}

BOOLEAN ViInitialise(PVOID HwDeviceExtension) {
	// Initialisation for after we get control of VI from the HAL.
	
	PDEVICE_EXTENSION Extension = (PDEVICE_EXTENSION)HwDeviceExtension;

	// Clear the GPU interrupt and the CP interrupt.
	PE_FINISHED_CLEAR();
	PE_FIFO_CLEAR();

	// Map the original framebuffer, fill it with black, unmap it.
	PHYSICAL_ADDRESS FrameBufferPhys;
	FrameBufferPhys.QuadPart = 0;
	FrameBufferPhys.LowPart = Extension->OriginalFrameBuffer;
	volatile ULONG * Xfb = (volatile ULONG * ) MmMapIoSpace( FrameBufferPhys, Extension->PhysicalFrameBuffer.Length, FALSE );
	if (Xfb != NULL) {
		
		ULONG Count = (Extension->PhysicalFrameBuffer.Width * (Extension->PhysicalFrameBuffer.Height + 1)) / 2;
		volatile ULONG * pXfb = Xfb;
		register ULONG Black = 0x10801080;
		while (Count--) {
			NativeWrite32(pXfb, Black);
			pXfb++;
		}
		
		MmUnmapIoSpace((PVOID)Xfb, Extension->PhysicalFrameBuffer.Length);
	}
	if (!Extension->SetupddLoaded && Extension->DoubleFrameBuffer != NULL) {
		ULONG Count = DOUBLE_FRAMEBUFFER_LENGTH / 4;
		volatile ULONG * pTex = (volatile ULONG*) Extension->DoubleFrameBuffer;
		register ULONG Black = 0;
		while (Count--) {
			NativeWrite32(pTex, Black);
			pTex++;
		}
	}
	
	// Copy EFB to XFB and initialise GPU registers.
	PeCopyEfbToXfbInit(Extension);

	// Spin and wait for the render to finish.
	while (!PE_FINISHED_RENDER) {}
	
	// Enable VI interrupt zero and one.
	VI_INTERRUPT_ENABLE(0);
	VI_INTERRUPT_ENABLE(1);
	
#ifndef SETUPDD_TEST
	if (Extension->SetupddLoaded) {
		// Start the timer.
		FbpStartTimer(Extension);
	}
#endif
	return TRUE;
}

VP_STATUS ViStartIoImpl(PDEVICE_EXTENSION Extension, PVIDEO_REQUEST_PACKET RequestPacket) {
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
			ULONG MaximumLength = DOUBLE_FRAMEBUFFER_LENGTH;
			if (Extension->DirectEfbWrites && !Extension->SetupddLoaded) MaximumLength = EFB_LENGTH;
			if (ShareMemory->ViewOffset > MaximumLength) return ERROR_INVALID_PARAMETER;
			if ((ShareMemory->ViewOffset + ShareMemory->ViewSize) > MaximumLength) return ERROR_INVALID_PARAMETER;
			
			RequestPacket->StatusBlock->Information = sizeof(VIDEO_SHARE_MEMORY_INFORMATION);
			
			PVOID VirtualAddress = ShareMemory->ProcessHandle; // you're right, win32k shouldn't exist
			ULONG ViewSize = ShareMemory->ViewSize + Extension->FrameBufferOffset;
			
			// grab the physaddr of the framebuffer
			PHYSICAL_ADDRESS FrameBufferPhys;
			FrameBufferPhys.QuadPart = 0;
			FrameBufferPhys.LowPart = Extension->DoubleFrameBufferPhys;
			if (Extension->DirectEfbWrites && !Extension->SetupddLoaded) FrameBufferPhys.LowPart = EFB_PHYS_ADDR;
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
			ULONG MaximumLength = DOUBLE_FRAMEBUFFER_LENGTH;
			if (Extension->DirectEfbWrites && !Extension->SetupddLoaded) MaximumLength = EFB_LENGTH;
			MemInfo->VideoRamLength = MaximumLength;
			ULONG InIoSpace = FALSE;
			PHYSICAL_ADDRESS FrameBufferPhys;
			FrameBufferPhys.QuadPart = 0;
			FrameBufferPhys.LowPart = Extension->DoubleFrameBufferPhys;
			if (Extension->DirectEfbWrites && !Extension->SetupddLoaded) FrameBufferPhys.LowPart = EFB_PHYS_ADDR;
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
			// Thus for Flipper VI, implementation is same as QUERY_CURRENT_MODE.
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
			// Reset device. No operation as we just have a framebuffer
			return NO_ERROR;
		}
	}
	
	return ERROR_INVALID_FUNCTION;
}

BOOLEAN ViStartIo(PVOID HwDeviceExtension, PVIDEO_REQUEST_PACKET RequestPacket) {
	PDEVICE_EXTENSION Extension = (PDEVICE_EXTENSION)HwDeviceExtension;
	RequestPacket->StatusBlock->Status = ViStartIoImpl(Extension, RequestPacket);
	return TRUE;
}

NTSTATUS DriverEntry(PVOID DriverObject, PVOID RegistryPath) {
	VIDEO_HW_INITIALIZATION_DATA InitData;
	RtlZeroMemory(&InitData, sizeof(InitData));
	
	InitData.HwInitDataSize = sizeof(VIDEO_HW_INITIALIZATION_DATA);
	
	InitData.HwFindAdapter = ViFindAdapter;
	InitData.HwInitialize = ViInitialise;
	InitData.HwInterrupt = ViInterruptHandler;
	InitData.HwStartIO = ViStartIo;
	
	InitData.HwDeviceExtensionSize = sizeof(DEVICE_EXTENSION);
	
	// Internal does not work here.
	// Our HAL(s) configure VMEBus to be equal to Internal, nothing else uses it.
	InitData.AdapterInterfaceType = VMEBus;
	NTSTATUS Status = VideoPortInitialize(DriverObject, RegistryPath, &InitData, NULL);
	return Status;
}
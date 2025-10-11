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
#define KIPCR 0xffffd000

extern ULONG NtBuildNumber;

#include "runtime.h"
#include "efb.h"
#include "cp.h"
#include "vi.h"
#include "ioctl.h"
#include "texdraw.h"

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
	PULONG BankBufferAlloc;
	PULONG BankBuffer;
	ULONG BankBufferPhys;
	ULONG BankCurrent;
	PULONG BitmapBuffer;
	PUSHORT ArrayVerticies;
	ULONG ArrayVerticiesPhys;
	ULONG VideoModeIndex;
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

enum {
	VIDEO_MODE_480P32,
	VIDEO_MODE_480P16,
	VIDEO_MODE_480P8,
	VIDEO_MODE_240P32,
	VIDEO_MODE_240P16,
	VIDEO_MODE_240P8,
	VIDEO_MODE_COUNT
};

enum {
	COLOUR_DEPTH_32,
	COLOUR_DEPTH_16,
	COLOUR_DEPTH_8,
	COLOUR_DEPTH_COUNT
};

enum {
	RESOLUTION_480P,
	RESOLUTION_240P,
	RESOLUTION_COUNT
};

enum {
	COLOUR_TABLE_OFFSET = (DOUBLE_FRAMEBUFFER_WIDTH * DOUBLE_FRAMEBUFFER_HEIGHT) * 2
};

#define VideoModeFromResolutionAndDepth(Res, Depth) (((ULONG)(Res) * (ULONG)COLOUR_DEPTH_COUNT) + (ULONG)(Depth))

static VIDEO_MODE_INFORMATION s_VideoModes[VIDEO_MODE_COUNT] = {0};

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
	
	// Initialise variables based on the set display mode.
	ULONG ModeIndex = Extension->VideoModeIndex;
	ULONG Format;
	// For an invalid mode default to 640x480x32
	if (ModeIndex >= VIDEO_MODE_COUNT) ModeIndex = VIDEO_MODE_480P32;
	switch (ModeIndex % COLOUR_DEPTH_COUNT) {
		case COLOUR_DEPTH_32:
		default:
			Format = 6; // RGBA8
			break;
		case COLOUR_DEPTH_16:
			Format = 4; // RGB565
			break;
		case COLOUR_DEPTH_8:
			Format = 9; // Colour index 8-bit
			//Format = 10; // Colour index 14-bit
			break;
	}
	
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
	// For CI8, set up the colour table, texture stages etc
	if (Format >= 9) {
		CppWriteBpReg(BPMEM_IND_IMASK);
		NumberOfBytesWritten += 5;
		// First set of palette entries (r,g)
		// Physical address.
		CppWriteBpReg(
			BPMEM_LOADTLUT0 |
			((Extension->DoubleFrameBufferPhys + COLOUR_TABLE_OFFSET) >> 5)
		);
		NumberOfBytesWritten += 5;
		// TMEM offset, length
		CppWriteBpReg(
			BPMEM_LOADTLUT1 |
			(0x200 << 0) | // TMEM offset : ((0xC0000 - 0x80000) >> 9)
			(0x10 << 10)   // Texture count: 256 entries
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg(BPMEM_IND_IMASK);
		NumberOfBytesWritten += 5;
		// Second set of palette entries (b)
		// Physical address.
		CppWriteBpReg(
			BPMEM_LOADTLUT0 |
			((Extension->DoubleFrameBufferPhys + COLOUR_TABLE_OFFSET + 0x200) >> 5)
		);
		NumberOfBytesWritten += 5;
		// TMEM offset, length
		CppWriteBpReg(
			BPMEM_LOADTLUT1 |
			(0x210 << 0) | // TMEM offset : ((0xC2000 - 0x80000) >> 9)
			(0x10 << 10)   // Texture count: 256 entries
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg(BPMEM_IND_IMASK);
		NumberOfBytesWritten += 5;
		// Set up the texture dma for the second engine.
		CppWriteBpReg(
			(BPMEM_TX_SETMODE0 + (1 << 24)) |
			(1 << 4) |
			(4 << 5)
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg(BPMEM_TX_SETMODE1 + (1 << 24)); // no lod set
		NumberOfBytesWritten += 5;
		CppWriteBpReg(
			(BPMEM_TX_SETIMAGE0 + (1 << 24)) |
			((640 - 1) << 0) | // width
			((480 - 1) << 10) | // height
			(Format << 20)
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg(
			(BPMEM_TX_SETIMAGE1 + (1 << 24)) |
			0x800 |     // even tmem line
			(3 << 15) | // even tmem width?
			(3 << 18)   // even tmem height?
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg(
			(BPMEM_TX_SETIMAGE2 + (1 << 24)) |
			0xC00 |     // odd tmem line
			(3 << 15) | // odd tmem width?
			(3 << 18)   // odd tmem height?
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TX_SETIMAGE3 + (1 << 24)) |
			(Extension->DoubleFrameBufferPhys >> 5)
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TX_SETTLUT + (1 << 24)) |
			(0x210 << 0) | // TMEM offset : ((0xC2000 - 0x80000) >> 9)
			(0 << 10)      // Format: IA8
		);
		NumberOfBytesWritten += 5;
		// Texture colour: ar,gb
		CppWriteBpReg((BPMEM_TEV_COLOR_RA + (2 << 24)) |
			0x00FF
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_COLOR_BG + (2 << 24)) |
			0xFF000
		);
		NumberOfBytesWritten += 5;
		// Needs two more dummy loads for some reason (hardware bug workaround?)
		CppWriteBpReg((BPMEM_TEV_COLOR_BG + (2 << 24)) |
			0xFF000
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_COLOR_BG + (2 << 24)) |
			0xFF000
		);
		NumberOfBytesWritten += 5;
		// Set texture colour swap tables.
		//  TODO: these are just being pulled from a register dump, maybe split out the bitfields at some point?
		CppWriteBpReg((BPMEM_TEV_KSEL + (2 << 24)) |
			0x1806C
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_KSEL + (3 << 24)) |
			0x1806E
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_KSEL + (4 << 24)) |
			0x1806F
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_KSEL + (5 << 24)) |
			0x1806E
		);
		NumberOfBytesWritten += 5;
		// Configure texture stages.
		//  TODO: these are just being pulled from a register dump, maybe split out the bitfields at some point?
		CppWriteBpReg((BPMEM_TEV_ALPHA_ENV + (0 << 24)) |
			0x8ffc4
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_COLOR_ENV + (0 << 24)) |
			0x8f82f
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_COLOR_ENV + (2 << 24)) |
			0xc8f
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_ALPHA_ENV + (2 << 24)) |
			0xf050
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_COLOR_ENV + (2 << 24)) |
			0x80c8f
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_ALPHA_ENV + (2 << 24)) |
			0x8f050
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TREF + (0 << 24)) |
			0x3c13c0
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_ALPHA_ENV + (2 << 24)) |
			0x8f058
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_COLOR_ENV + (2 << 24)) |
			0x88ff0
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_ALPHA_ENV + (2 << 24)) |
			0x8ffe8
		);
		NumberOfBytesWritten += 5;
		
	} else {
		// Ensure first texture stage is correct for 16/32bpp.
		//  TODO: these are just being pulled from a register dump, maybe split out the bitfields at some point?
		CppWriteBpReg((BPMEM_TEV_KSEL + (2 << 24)) |
			0x18060
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_KSEL + (3 << 24)) |
			0x1806C
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_KSEL + (4 << 24)) |
			0x18065
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_KSEL + (5 << 24)) |
			0x1806D
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_COLOR_ENV + (0 << 24)) |
			0x8fff8
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TEV_ALPHA_ENV + (0 << 24)) |
			0x8ffc0
		);
		NumberOfBytesWritten += 5;
		CppWriteBpReg((BPMEM_TREF + (0 << 24)) |
			0x493c0
		);
		NumberOfBytesWritten += 5;
	}
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
		(Format << 20)
	);
	NumberOfBytesWritten += 5;
	CppWriteBpReg(
		BPMEM_TX_SETIMAGE1 |
		(3 << 15) | // even tmem width?
		(3 << 18)   // even tmem height?
	);
	NumberOfBytesWritten += 5;
	if (Format >= 9) {
		CppWriteBpReg(
			BPMEM_TX_SETIMAGE2 |
			0x400 |     // odd tmem line
			(3 << 15) | // odd tmem width?
			(3 << 18)   // odd tmem height?
		);
	} else {
		CppWriteBpReg(
			BPMEM_TX_SETIMAGE2 |
			0x4000 |    // odd tmem line
			(3 << 15) | // odd tmem width?
			(3 << 18)   // odd tmem height?
		);
	}
	NumberOfBytesWritten += 5;
	CppWriteBpReg(BPMEM_TX_SETIMAGE3 |
		(Extension->DoubleFrameBufferPhys >> 5)
	);
	NumberOfBytesWritten += 5;
	
	// Enable the colour table for CI8
	if (Format >= 9) {
		CppWriteBpReg(BPMEM_TX_SETTLUT |
			(0x200 << 0) | // TMEM offset : ((0xC0000 - 0x80000) >> 9)
			(0 << 10)      // Format: IA8
		);
		NumberOfBytesWritten += 5;
	}
	
	
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
	
	// Set the gen mode depending on CI8 or not
	if (Format >= 9) {
		CppWriteBpReg(BPMEM_GENMODE |
			(1 << 0) | // 1 texture
			(1 << 10)  // 2 TEV stages 
		);
	} else {
		CppWriteBpReg(BPMEM_GENMODE |
			(1 << 0)  // 1 texture, 1 TEV stage
		);
	}
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
	
	// If this is Cafe, this device is not enabled.
	if (RUNTIME_BLOCK[RUNTIME_SYSTEM_TYPE] >= ARTX_SYSTEM_LATTE) return ERROR_DEV_NOT_EXIST;
	
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
	// This must be done on CPU 0.
	{
		KAFFINITY OldAffinity = KeSetAffinityThread(PsGetCurrentThread(), 1);
		CppFifoEnable();
		KeSetAffinityThread(PsGetCurrentThread(), OldAffinity);
	}
	
	// If setupdd is loaded, we need to set up a framebuffer copy in main memory.
	// We'll use only 640x480x32 for this.
	Extension->DoubleFrameBuffer = NULL;
	Extension->MappedFrameBuffer = NULL;
	Extension->BitmapBuffer = NULL;
	Extension->DoubleFrameBufferPhys = 0;
	Extension->FrameBufferOffset = 0;
	Extension->VideoModeIndex = 0;
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
			KeSetTargetProcessorDpc(&Extension->TimerDpc, 0);
			KeInitializeTimer(&Extension->Timer);
		} else {
			// Allocate and map the bank buffer. Must be used uncached here as the physical page will get mapped elsewhere as uncached.
			// BUGBUG: this will only work correctly on 32bpp for now due to the flipper memory controller issue!
			Extension->BankBufferAlloc = (PULONG)MmAllocateContiguousMemory(PAGE_SIZE, HighestAcceptable);
			if (Extension->BankBufferAlloc == NULL) return ERROR_DEV_NOT_EXIST;
			PHYSICAL_ADDRESS BankBufferPhys = MmGetPhysicalAddress(Extension->BankBufferAlloc);
			Extension->BankBufferPhys = BankBufferPhys.LowPart;
			Extension->BankBuffer = MmMapIoSpace( BankBufferPhys, PAGE_SIZE, MmNonCached );
			RtlZeroMemory(Extension->BankBuffer, PAGE_SIZE);
			Extension->BankCurrent = 0;
			
			if (FbpHasWin32k()) {
				// Allocate and map the bitmap buffer for GDI to use as a framebuffer.
				// This is needed so the bank buffer changes can be visible to GDI as well.
				// A cached mapping is fine for this.
				Extension->BitmapBuffer = (PULONG)MmAllocateContiguousMemory(DOUBLE_FRAMEBUFFER_LENGTH, HighestAcceptable);
				if (Extension->BitmapBuffer == NULL) return ERROR_DEV_NOT_EXIST;
				RtlZeroMemory(Extension->BitmapBuffer, DOUBLE_FRAMEBUFFER_LENGTH);
			}
		}
	}
	
	// Initialise the video modes.
	s_VideoModes[0].Length = sizeof(s_VideoModes[0]);
	s_VideoModes[0].ModeIndex = 0;
#if 0
	if (SetupddLoaded) {
		s_VideoModes[0].VisScreenWidth = DOUBLE_FRAMEBUFFER_WIDTH;
		s_VideoModes[0].VisScreenHeight = DOUBLE_FRAMEBUFFER_HEIGHT;
		s_VideoModes[0].ScreenStride = DOUBLE_FRAMEBUFFER_STRIDE;
	} else {	
		// EFB is 640x480 or 640x528, we will always render 640x480.
		s_VideoModes[0].VisScreenWidth = 640;
		s_VideoModes[0].VisScreenHeight = 480;
		s_VideoModes[0].ScreenStride = EFB_STRIDE;
	}
#endif
	if (!SetupddLoaded && HasWin32k) {
		// EFB is 640x480 or 640x528, we will always render 640x480.
		s_VideoModes[0].VisScreenWidth = 640;
		s_VideoModes[0].VisScreenHeight = 480;
		s_VideoModes[0].ScreenStride = EFB_STRIDE;
	} else {
		s_VideoModes[0].VisScreenWidth = DOUBLE_FRAMEBUFFER_WIDTH;
		s_VideoModes[0].VisScreenHeight = DOUBLE_FRAMEBUFFER_HEIGHT;
		s_VideoModes[0].ScreenStride = DOUBLE_FRAMEBUFFER_STRIDE;
	}
	s_VideoModes[0].NumberOfPlanes = 1;
	s_VideoModes[0].BitsPerPlane = 32;
	s_VideoModes[0].Frequency = 60;
	// todo: Is this correct?
	s_VideoModes[0].XMillimeter = 320;
	s_VideoModes[0].YMillimeter = 240;
	s_VideoModes[0].NumberRedBits = 8;
	s_VideoModes[0].NumberGreenBits = 8;
	s_VideoModes[0].NumberBlueBits = 8;
	// watch out for endianness!
	s_VideoModes[0].BlueMask =  0x000000ff;
	s_VideoModes[0].GreenMask = 0x0000ff00;
	s_VideoModes[0].RedMask =   0x00ff0000;
	s_VideoModes[0].AttributeFlags = VIDEO_MODE_GRAPHICS;
#ifdef SETUPDD_TEST
	if (SetupddLoaded) {
		s_VideoModes[0].BitsPerPlane = 16;
		s_VideoModes[0].RedMask = 0x001f;
		s_VideoModes[0].GreenMask = 0x07e0;
		s_VideoModes[0].BlueMask = 0xf800;
	}
#endif
#if 0
	if (!SetupddLoaded) {
		s_VideoModes[0].BitsPerPlane = 16;
		s_VideoModes[0].RedMask = 0x001f;
		s_VideoModes[0].GreenMask = 0x07e0;
		s_VideoModes[0].BlueMask = 0xf800;
	}
#endif
	if (!SetupddLoaded) {
		// Other modes.
		for (ULONG i = 1; i < VIDEO_MODE_COUNT; i++) {
			RtlCopyMemory(&s_VideoModes[i], &s_VideoModes[0], sizeof(s_VideoModes[0]));
			s_VideoModes[i].ModeIndex = i;
			ULONG Depth = i % COLOUR_DEPTH_COUNT;
			ULONG Res = i / RESOLUTION_COUNT;
			if (Res == RESOLUTION_240P) {
				s_VideoModes[i].VisScreenWidth = 320;
				s_VideoModes[i].VisScreenHeight = 240;
				s_VideoModes[i].ScreenStride = 320 * sizeof(ULONG);
			}
			
			if (Depth == COLOUR_DEPTH_16) {
				s_VideoModes[i].BitsPerPlane = 16;
				s_VideoModes[i].NumberRedBits = 5;
				s_VideoModes[i].NumberGreenBits = 6;
				s_VideoModes[i].NumberBlueBits = 5;
				s_VideoModes[i].BlueMask = 0x001f;
				s_VideoModes[i].GreenMask = 0x07e0;
				s_VideoModes[i].RedMask = 0xf800;
			} else if (Depth == COLOUR_DEPTH_8) {
				s_VideoModes[i].BitsPerPlane = 8;
				s_VideoModes[i].AttributeFlags |= VIDEO_MODE_PALETTE_DRIVEN | VIDEO_MODE_MANAGED_PALETTE;
			}
		}
		
	}
	
	// We are done. Only one device exists.
	*Again = FALSE;
	
	return NO_ERROR;
}

static USHORT Convert888ToGR(ULONG value) {
	USHORT ret = 0;
	value = LoadToRegister32(value);
	USHORT r = (value >> 0) & 0xFF;
	USHORT g = (value >> 8) & 0xFF;
	//USHORT b = (value >> 16) & 0xFF;
	ret = (g << 8);
	ret |= r;
	return ret;
}

static USHORT Convert888ToB(ULONG value) {
	USHORT ret = 0;
	value = LoadToRegister32(value);
	USHORT b = (value >> 16) & 0xFF;
	return b;
}

BOOLEAN ViInitialise(PVOID HwDeviceExtension) {
	// Initialisation for after we get control of VI from the HAL.
	
	PDEVICE_EXTENSION Extension = (PDEVICE_EXTENSION)HwDeviceExtension;
	
	// This code must run on CPU 0.
	KAFFINITY OldAffinity = KeSetAffinityThread(PsGetCurrentThread(), 1);

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
		register ULONG Black = 0; // for CI8: under GDI, colour index 0 is always black
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
	
	// Switch affinity back to what it was.
	KeSetAffinityThread(PsGetCurrentThread(), OldAffinity);
	return TRUE;
}

static void ViFlip8(PUCHAR Tex, PUCHAR Bank, ULONG Width, ULONG Line, BOOLEAN ToTex) {
	PUCHAR Source = Bank;
	ULONG cyIdx = Line;
	{
		PUCHAR thisSource = Source;
		ULONG TexOffsetY = CalculateTexYOffset8(cyIdx, Width);
		ULONG cxIdx = 0;
		ULONG cxTemp = Width;
		while (cxTemp) {
			// Guaranteed to be aligned, so we can do this:
			ULONG TexOffset = CalculateTexOffsetWithYOffset8(cxIdx, TexOffsetY);
			if (ToTex) NativeWriteBase32( Tex, TexOffset, __builtin_bswap32(*(PULONG)thisSource) );
			else *(PULONG)thisSource = __builtin_bswap32(NativeReadBase32( Tex, TexOffset ));
			cxTemp -= 4;
			cxIdx += 4;
			thisSource += 4;
		}
	}
}

static ULONG Rol32(ULONG Value, ULONG Count) {
	const ULONG mask = (8 * sizeof(Value) - 1);
	Count &= mask;
	return (Value << Count) | (Value >> ( (-Count) & mask));
}

static void ViFlip16(PUCHAR Tex, PUCHAR Bank, ULONG Width, ULONG Line, BOOLEAN ToTex) {
	PUCHAR Source = Bank;
	ULONG cyIdx = Line;
	{
		PUCHAR thisSource = Source;
		ULONG TexOffsetY = CalculateTexYOffset16(cyIdx, Width);
		ULONG cxIdx = 0;
		ULONG cxTemp = Width;
		while (cxTemp) {
			// Guaranteed to be aligned, so we can do this:
			ULONG TexOffset = CalculateTexOffsetWithYOffset16(cxIdx, TexOffsetY);
			
			if (ToTex) NativeWriteBase32( Tex, TexOffset, Rol32(*(PULONG)thisSource, 16) );
			else *(PULONG)thisSource = Rol32(NativeReadBase32(Tex, TexOffset), 16);
			cxTemp -= 2;
			cxIdx += 2;
			thisSource += 4;
		}
	}
}

static void ViFlip32(PUCHAR Tex, PUCHAR Bank, ULONG Width, ULONG Line, BOOLEAN ToTex) {
	PUCHAR Source = Bank;
	ULONG cyIdx = Line;
	{
		PUCHAR thisSource = Source;
		ULONG TexOffsetY = CalculateTexYOffset32(cyIdx, Width);
		ULONG cxIdx = 0;
		ULONG cxTemp = Width;
		while (cxTemp) {
			// Guaranteed to be aligned, so we can do this:
			ULONG TexOffset = CalculateTexOffsetWithYOffset32(cxIdx, TexOffsetY);
			if (ToTex) {
				ULONG rgb0 = *(PULONG)thisSource;
				thisSource += 4;
				ULONG rgb1 = *(PULONG)thisSource;
				thisSource += 4;
				ULONG value = 0xFF00FF00 | (rgb1 >> 16) | (rgb0 & 0xFF0000);
				ULONG value2 = ((rgb0 & 0xFFFF) << 16) | (rgb1 & 0xFFFF);
				NativeWriteBase32( Tex, TexOffset, value );
				NativeWriteBase32( Tex, TexOffset + 0x20, value2 );
			} else {
				ULONG tex0 = NativeReadBase32( Tex, TexOffset );
				ULONG tex1 = NativeReadBase32( Tex, TexOffset + 0x20 );
				ULONG rgb0 = (tex1 >> 16) | ((tex0 >> 16) & 0xFF);
				ULONG rgb1 = (tex1 & 0xFFFF) | (tex0 & 0xFF);
				*(PULONG)thisSource = rgb0;
				thisSource += 4;
				*(PULONG)thisSource = rgb1;
				thisSource += 4;
			}
			cxTemp -= 2;
			cxIdx += 2;
		}
	}
}

void ViBankSwitch(ULONG ReadBank, ULONG WriteBank, PDEVICE_EXTENSION Extension) {
	// Called on bank switch.
	// WriteBank is the new bank to switch to.
	ULONG CurrentLine = Extension->BankCurrent;
	ULONG ModeIndex = Extension->VideoModeIndex;
	// For an invalid mode default to 640x480x32
	if (ModeIndex >= VIDEO_MODE_COUNT) ModeIndex = VIDEO_MODE_480P32;
	ULONG Width = s_VideoModes[ModeIndex].VisScreenWidth;
	switch (ModeIndex % COLOUR_DEPTH_COUNT) {
		case COLOUR_DEPTH_32:
		default:
			ViFlip32(Extension->DoubleFrameBuffer, Extension->BankBuffer, Width, CurrentLine, TRUE);
			if (Extension->BitmapBuffer != NULL) RtlCopyMemory( (PVOID)((ULONG)Extension->BitmapBuffer + (CurrentLine * (Width * 4))), Extension->BankBuffer, Width * 4 );
			ViFlip32(Extension->DoubleFrameBuffer, Extension->BankBuffer, Width, WriteBank, FALSE);
			break;
		case COLOUR_DEPTH_16:
			ViFlip16(Extension->DoubleFrameBuffer, Extension->BankBuffer, Width, CurrentLine, TRUE);
			if (Extension->BitmapBuffer != NULL) RtlCopyMemory( (PVOID)((ULONG)Extension->BitmapBuffer + (CurrentLine * (Width * 2))), Extension->BankBuffer, Width * 2 );
			ViFlip16(Extension->DoubleFrameBuffer, Extension->BankBuffer, Width, WriteBank, FALSE);
			break;
		case COLOUR_DEPTH_8:
			ViFlip8(Extension->DoubleFrameBuffer, Extension->BankBuffer, Width, CurrentLine, TRUE);
			if (Extension->BitmapBuffer != NULL) RtlCopyMemory( (PVOID)((ULONG)Extension->BitmapBuffer + (CurrentLine * (Width * 1))), Extension->BankBuffer, Width * 1 );
			ViFlip8(Extension->DoubleFrameBuffer, Extension->BankBuffer, Width, WriteBank, FALSE);
			break;
	}
	
	Extension->BankCurrent = WriteBank;
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
			ULONG MaximumLength;// = DOUBLE_FRAMEBUFFER_LENGTH;
			if (Extension->DirectEfbWrites && !Extension->SetupddLoaded) MaximumLength = EFB_LENGTH;
			else MaximumLength = (DOUBLE_FRAMEBUFFER_HEIGHT * PAGE_SIZE);
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
			else if (!Extension->SetupddLoaded) FrameBufferPhys.LowPart = Extension->BankBufferPhys;
			ULONG InIoSpace = FALSE;
			
			VP_STATUS Status;
			if (Extension->SetupddLoaded || Extension->DirectEfbWrites) {
				Status = VideoPortMapMemory(Extension, FrameBufferPhys, &ViewSize, &InIoSpace, &VirtualAddress);
			} else {
				Status = VideoPortMapBankedMemory(Extension, FrameBufferPhys, &ViewSize, &InIoSpace, &VirtualAddress, PAGE_SIZE, FALSE, ViBankSwitch, Extension);
			}
			//VP_STATUS Status = VideoPortMapMemory(Extension, FrameBufferPhys, &ViewSize, &InIoSpace, &VirtualAddress);
			
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
		{
			if (RequestPacket->OutputBufferLength < sizeof(VIDEO_MODE_INFORMATION)) return ERROR_INSUFFICIENT_BUFFER;
			RequestPacket->StatusBlock->Information = sizeof(VIDEO_MODE_INFORMATION);
			RtlCopyMemory(RequestPacket->OutputBuffer, &s_VideoModes[Extension->VideoModeIndex], sizeof(s_VideoModes[0]));
#if 0
			if (!Extension->SetupddLoaded) {
				PVIDEO_MODE_INFORMATION OutputInfo = (PVIDEO_MODE_INFORMATION)RequestPacket->OutputBuffer;
				OutputInfo->ScreenStride = PAGE_SIZE;
			}
#endif
			return NO_ERROR;
		}
		case IOCTL_VIDEO_QUERY_AVAIL_MODES:
			// Returns information about available video modes (array of VIDEO_MODE_INFORMATION).
		{
			ULONG ModeCount = VIDEO_MODE_COUNT;
			if (Extension->SetupddLoaded) ModeCount = 1;
			if (RequestPacket->OutputBufferLength < (sizeof(VIDEO_MODE_INFORMATION) * ModeCount)) return ERROR_INSUFFICIENT_BUFFER;
			RequestPacket->StatusBlock->Information = sizeof(VIDEO_MODE_INFORMATION) * ModeCount;
			RtlCopyMemory(RequestPacket->OutputBuffer, s_VideoModes, sizeof(VIDEO_MODE_INFORMATION) * ModeCount);
#if 0
			if (!Extension->SetupddLoaded) {
				PVIDEO_MODE_INFORMATION OutputInfo = (PVIDEO_MODE_INFORMATION)RequestPacket->OutputBuffer;
				for (ULONG i = 0; i < ModeCount; i++) {
					OutputInfo[i].ScreenStride = PAGE_SIZE;
				}
			}
#endif
			return NO_ERROR;
		}
		case IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES:
		{
			// Returns number of valid mode and size of each structure returned.
			if (RequestPacket->OutputBufferLength < sizeof(VIDEO_NUM_MODES)) return ERROR_INSUFFICIENT_BUFFER;
			
			RequestPacket->StatusBlock->Information = sizeof(VIDEO_NUM_MODES);
			PVIDEO_NUM_MODES NumModes = (PVIDEO_NUM_MODES)RequestPacket->OutputBuffer;
			NumModes->NumModes = Extension->SetupddLoaded ? 1 : VIDEO_MODE_COUNT;
			NumModes->ModeInformationLength = sizeof(VIDEO_MODE_INFORMATION);
			return NO_ERROR;
		}
		case IOCTL_VIDEO_SET_CURRENT_MODE:
		{
			if (RequestPacket->InputBufferLength < sizeof(VIDEO_MODE)) return ERROR_INSUFFICIENT_BUFFER;
			PVIDEO_MODE Mode = (PVIDEO_MODE)RequestPacket->InputBuffer;
			ULONG ModeCount = VIDEO_MODE_COUNT;
			if (Extension->SetupddLoaded) ModeCount = 1;
			if (Mode->RequestedMode >= ModeCount) return ERROR_INVALID_PARAMETER;
			if (Extension->VideoModeIndex == Mode->RequestedMode) return NO_ERROR;
			// Disable VI interrupt zero and one
			VI_INTERRUPT_DISABLE(0);
			VI_INTERRUPT_DISABLE(1);
			Extension->VideoModeIndex = Mode->RequestedMode;
			ViInitialise(Extension);
			return NO_ERROR;
		}
		case IOCTL_VIDEO_RESET_DEVICE:
		{
			// Reset device.
			return NO_ERROR;
		}
		case IOCTL_VIDEO_SET_COLOR_REGISTERS:
		{
			// Set the colour palette.
			ULONG Depth = Extension->VideoModeIndex % COLOUR_DEPTH_COUNT;
			if (Depth != COLOUR_DEPTH_8) return ERROR_INVALID_FUNCTION;
			if (RequestPacket->InputBufferLength < __builtin_offsetof(VIDEO_CLUT, LookupTable)) return ERROR_INSUFFICIENT_BUFFER;
			PVIDEO_CLUT Clut = (PVIDEO_CLUT)RequestPacket->InputBuffer;
			if (RequestPacket->InputBufferLength < __builtin_offsetof(VIDEO_CLUT, LookupTable) + (sizeof(ULONG) * Clut->NumEntries)) return ERROR_INSUFFICIENT_BUFFER;
			ULONG LastEntry = Clut->FirstEntry + Clut->NumEntries;
			if (LastEntry > 256) return ERROR_INVALID_PARAMETER;
			PULONG ColourTable = (PULONG)((ULONG)Extension->DoubleFrameBuffer + COLOUR_TABLE_OFFSET);
			ULONG FirstEntry = Clut->FirstEntry;
			if ((Clut->FirstEntry & 1) != 0) {
				ULONG value = NativeReadBase32(ColourTable, (Clut->FirstEntry - 1) * 2);
				ULONG value2 = NativeReadBase32(ColourTable, ((Clut->FirstEntry - 1) * 2) + 0x200);
				value &= 0xFFFF0000;
				value2 &= 0xFFFF0000;
				value |= (ULONG) Convert888ToGR(Clut->LookupTable[Clut->FirstEntry].RgbLong);
				value2 |= (ULONG) Convert888ToB(Clut->LookupTable[Clut->FirstEntry].RgbLong);
				NativeWriteBase32(ColourTable, (Clut->FirstEntry - 1) * 2, value);
				NativeWriteBase32(ColourTable, ((Clut->FirstEntry - 1) * 2) + 0x200, value2);
				FirstEntry++;
			}
			for (ULONG i = FirstEntry; i < (LastEntry & ~1); i += 2) {
				ULONG value = (ULONG)Convert888ToGR(Clut->LookupTable[i].RgbLong);
				ULONG value2 = (ULONG)Convert888ToB(Clut->LookupTable[i].RgbLong);
				value <<= 16;
				value2 <<= 16;
				value |= (ULONG) Convert888ToGR(Clut->LookupTable[i + 1].RgbLong);
				value2 |= (ULONG) Convert888ToB(Clut->LookupTable[i + 1].RgbLong);
				NativeWriteBase32(ColourTable, i * 2, value);
				NativeWriteBase32(ColourTable, (i * 2) + 0x200, value2);
			}
			if ((LastEntry & 1) != 0) {
				ULONG value = NativeReadBase32(ColourTable, (LastEntry - 1) * 2);
				ULONG value2 = NativeReadBase32(ColourTable, ((LastEntry - 1) * 2) + 0x200);
				value &= 0xFFFF0000;
				value2 &= 0xFFFF0000;
				value |= (ULONG) Convert888ToGR(Clut->LookupTable[LastEntry].RgbLong);
				value2 |= (ULONG) Convert888ToB(Clut->LookupTable[LastEntry].RgbLong);
				NativeWriteBase32(ColourTable, (LastEntry - 1) * 2, value);
				NativeWriteBase32(ColourTable, ((LastEntry - 1) * 2) + 0x200, value2);
			}
			return NO_ERROR;
		}
		case IOCTL_VIDEO_GET_BITMAP_BUFFER:
		{
			// Caller asked for the bitmap buffer we allocated.
			if (Extension->BitmapBuffer == NULL) return ERROR_INVALID_FUNCTION;
			if (RequestPacket->OutputBufferLength < sizeof(VIDEO_MEMORY_INFORMATION)) return ERROR_INSUFFICIENT_BUFFER;
			if (RequestPacket->InputBufferLength < sizeof(VIDEO_MEMORY)) return ERROR_INSUFFICIENT_BUFFER;
			
			RequestPacket->StatusBlock->Information = sizeof(VIDEO_MEMORY_INFORMATION);
			
			PVIDEO_MEMORY_INFORMATION MemInfo = (PVIDEO_MEMORY_INFORMATION) RequestPacket->OutputBuffer;
			PVIDEO_MEMORY Mem = (PVIDEO_MEMORY) RequestPacket->InputBuffer;
			
			MemInfo->VideoRamBase = Mem->RequestedVirtualAddress;
			ULONG MaximumLength = DOUBLE_FRAMEBUFFER_LENGTH;
			MemInfo->VideoRamLength = MaximumLength;
			MemInfo->FrameBufferBase = Extension->BitmapBuffer;
			MemInfo->FrameBufferLength = MemInfo->VideoRamLength;
			return NO_ERROR;
		}
	}
	
	return ERROR_INVALID_FUNCTION;
}

BOOLEAN ViStartIo(PVOID HwDeviceExtension, PVIDEO_REQUEST_PACKET RequestPacket) {
	// This code must run on CPU 0.
	KAFFINITY OldAffinity = KeSetAffinityThread(PsGetCurrentThread(), 1);
	
	PDEVICE_EXTENSION Extension = (PDEVICE_EXTENSION)HwDeviceExtension;
	RequestPacket->StatusBlock->Status = ViStartIoImpl(Extension, RequestPacket);
	
	// Switch affinity back to what it was.
	KeSetAffinityThread(PsGetCurrentThread(), OldAffinity);
	return TRUE;
}

NTSTATUS DriverEntry(PVOID DriverObject, PVOID RegistryPath) {
	// This code must run on CPU 0.
	KAFFINITY OldAffinity = KeSetAffinityThread(PsGetCurrentThread(), 1);
	
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
	
	// Switch affinity back to what it was.
	KeSetAffinityThread(PsGetCurrentThread(), OldAffinity);
	return Status;
}
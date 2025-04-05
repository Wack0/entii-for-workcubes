// DirectDraw implementation.

#include "driver.h"
#include "runtime.h"
#include "texdraw.h"

#if 0
#include "../../fpvigxdrv/source/vi.h"
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

static BOOL ViIsInVblank(void) {
	USHORT InterruptLine = MmioReadBase16(VI_REGISTER_BAT, 0x32) & 0x3FF;
	
	VI_INTERRUPT_DISABLE(0);
	VI_INTERRUPT_DISABLE(1);
	USHORT CurrentLine = MmioReadBase16(VI_REGISTER_BAT, 0x2C);
	{
		USHORT Temp;
		do {
			Temp = CurrentLine;
			CurrentLine = MmioReadBase16(VI_REGISTER_BAT, 0x2C);
		} while (CurrentLine != Temp);
	}
	VI_INTERRUPT_ENABLE(0);
	VI_INTERRUPT_ENABLE(1);
	
	return (CurrentLine == 1 || CurrentLine == InterruptLine);
}

static DWORD DdrawWaitForVblank(PDD_WAITFORVERTICALBLANKDATA Data) {
	Data->ddRVal = DD_OK;
	
	switch (Data->dwFlags) {
		case DDWAITVB_I_TESTVB:
			Data->bIsInVB = ViIsInVblank();
			break;
		case DDWAITVB_BLOCKBEGIN:
			while (ViIsInVblank()) {}
			while (!ViIsInVblank()) {}
			break;
		case DDWAITVB_BLOCKEND:
			while (!ViIsInVblank()) {}
			while (ViIsInVblank()) {}
			break;
	}
	
	return DDHAL_DRIVER_HANDLED;
}

static DWORD DdrawCreateSurface(PDD_CREATESURFACEDATA Data) {
	PPDEV pdev = (PPDEV) Data->lpDD->dhpdev;
	PDD_SURFACE_GLOBAL SurfaceGlobal = Data->lplpSList[0]->lpGbl;
	PDD_SURFACEDESC SurfaceDesc = Data->lpDDSurfaceDesc;
	if (SurfaceGlobal->ddpfSurface.dwSize != sizeof(DDPIXELFORMAT)) return DDHAL_DRIVER_NOTHANDLED;
	if (SurfaceGlobal->ddpfSurface.dwRGBBitCount != pdev->ulBitCount) return DDHAL_DRIVER_NOTHANDLED;
	
	if (SurfaceGlobal->wWidth != pdev->cxScreen) return DDHAL_DRIVER_NOTHANDLED;
	if (SurfaceGlobal->wHeight != pdev->cyScreen) return DDHAL_DRIVER_NOTHANDLED;
	
	// Return NOTHANDLED with this value in fpVidMem gets us some usermode memory allocation.
	SurfaceGlobal->fpVidMem = DDHAL_PLEASEALLOC_USERMEM;
	SurfaceGlobal->dwUserMemSize = pdev->cxScreen * pdev->cyScreen * (pdev->ulBitCount / 8);
	SurfaceGlobal->lPitch = SurfaceDesc->lPitch = pdev->cxScreen * (pdev->ulBitCount / 8);
	SurfaceDesc->dwFlags |= DDSD_PITCH;
	return DDHAL_DRIVER_NOTHANDLED;
}
#endif

static void DbgPrint(PCSTR Format, ...) {
	va_list ap;
	va_start(ap, Format);
	EngDebugPrint("", Format, ap);
	va_end(ap);
}

static DWORD DdrawLock(PDD_LOCKDATA Data) {
	PPDEV pdev = (PPDEV) Data->lpDD->dhpdev;
	PDD_SURFACE_LOCAL SurfaceLocal = Data->lpDDSurface;
	PDD_SURFACE_GLOBAL SurfaceGlobal = SurfaceLocal->lpGbl;
	
	DbgPrint("DdrawLock: primary=%d, locked=%d\n", (SurfaceLocal->ddsCaps.dwCaps & DDSCAPS_PRIMARYSURFACE) != 0, pdev->pLockedSurface != NULL);
	if ((SurfaceLocal->ddsCaps.dwCaps & DDSCAPS_PRIMARYSURFACE) == 0) {
		// um..?
		Data->ddRVal = DDERR_CANTLOCKSURFACE;
		return DDHAL_DRIVER_HANDLED;
	}
	if (pdev->pLockedSurface != NULL) {
		Data->ddRVal = DDERR_CANTLOCKSURFACE;
		return DDHAL_DRIVER_HANDLED;
	}
	
	VIDEO_SHARE_MEMORY shareMemory;
    VIDEO_SHARE_MEMORY_INFORMATION shareMemoryInformation;
	DWORD returnedDataLength;
	shareMemory.ProcessHandle = 0xFFFFFFFF; // NtCurrentProcess()
	shareMemory.RequestedVirtualAddress = 0;
	shareMemory.ViewOffset = 0;
	shareMemory.ViewSize = pdev->cyScreen * (pdev->cxScreen * 0x1000);
	DWORD retval = EngDeviceIoControl(
		pdev->hDriver,
		IOCTL_VIDEO_SHARE_VIDEO_MEMORY,
		&shareMemory,
		sizeof(VIDEO_SHARE_MEMORY),
		&shareMemoryInformation,
		sizeof(VIDEO_SHARE_MEMORY_INFORMATION),
		&returnedDataLength
	);
	if (retval != 0) {
		DbgPrint("IOCTL_VIDEO_SHARE_VIDEO_MEMORY failed 0x%x\n", retval);
		Data->ddRVal = DDERR_CANTLOCKSURFACE;
		return DDHAL_DRIVER_HANDLED;
	}
	
	pdev->pLockedSurface = shareMemoryInformation.VirtualAddress;
	
	Data->ddRVal = DD_OK;
	PUCHAR Pointer = shareMemoryInformation.VirtualAddress;
	if (Data->bHasRect) {
		Pointer += Data->rArea.top * SurfaceGlobal->lPitch;
		Pointer += Data->rArea.left;
	}
	
	Data->lpSurfData = Pointer;
	return DDHAL_DRIVER_HANDLED;
}

static DWORD DdrawUnlock(PDD_UNLOCKDATA Data) {
	PPDEV pdev = (PPDEV) Data->lpDD->dhpdev;
	PDD_SURFACE_LOCAL SurfaceLocal = Data->lpDDSurface;
	PDD_SURFACE_GLOBAL SurfaceGlobal = SurfaceLocal->lpGbl;
	
	if ((SurfaceLocal->ddsCaps.dwCaps & DDSCAPS_PRIMARYSURFACE) == 0) {
		// um..?
		return DDHAL_DRIVER_NOTHANDLED;
	}
	if (pdev->pLockedSurface == NULL) {
		return DDHAL_DRIVER_NOTHANDLED;
	}
	
	VIDEO_SHARE_MEMORY shareMemory;
	DWORD returnedDataLength;
	shareMemory.ProcessHandle = 0xFFFFFFFF; // NtCurrentProcess()
	shareMemory.RequestedVirtualAddress = pdev->pLockedSurface;
	shareMemory.ViewOffset = 0;
	shareMemory.ViewSize = 0;
	DWORD retval = EngDeviceIoControl(
		pdev->hDriver,
		IOCTL_VIDEO_UNSHARE_VIDEO_MEMORY,
		&shareMemory,
		sizeof(VIDEO_SHARE_MEMORY),
		NULL,
		0,
		&returnedDataLength
	);
	if (retval != 0) {
		DbgPrint("IOCTL_VIDEO_UNSHARE_VIDEO_MEMORY failed 0x%x\n", retval);
		RIP("DISP failed IOCTL_VIDEO_UNSHARE_VIDEO_MEMORY");
	}
	
	pdev->pLockedSurface = NULL;
	// win32k doesn't care about what is returned here.
	return DDHAL_DRIVER_NOTHANDLED;
}

#if 0
static void DdrawFlip8(PUCHAR Dest, PUCHAR Source, ULONG Width, ULONG Height, ULONG Delta) {
	ULONG cyIdx = 0;
	while (Height) {
		PUCHAR thisSource = Source;
		ULONG TexOffsetY = CalculateTexYOffset8(cyIdx, Width);
		ULONG cxIdx = 0;
		ULONG cxTemp = Width;
		while (cxTemp) {
			// Guaranteed to be aligned, so we can do this:
			ULONG TexOffset = CalculateTexOffsetWithYOffset8(cxIdx, TexOffsetY);
			NativeWriteBase32( Dest, TexOffset, __builtin_bswap32(*(PULONG)thisSource) );
			cxTemp -= 4;
			cxIdx += 4;
			thisSource += 4;
		}
		Height--;
		cyIdx++;
		Source += Delta;
	}
}

static ULONG Rol32(ULONG Value, ULONG Count) {
	const ULONG mask = (8 * sizeof(Value) - 1);
	Count &= mask;
	return (Value << Count) | (Value >> ( (-Count) & mask));
}

static void DdrawFlip16(PUCHAR Dest, PUCHAR Source, ULONG Width, ULONG Height, ULONG Delta) {
	ULONG cyIdx = 0;
	while (Height) {
		PUCHAR thisSource = Source;
		ULONG TexOffsetY = CalculateTexYOffset16(cyIdx, Width);
		ULONG cxIdx = 0;
		ULONG cxTemp = Width;
		while (cxTemp) {
			// Guaranteed to be aligned, so we can do this:
			ULONG TexOffset = CalculateTexOffsetWithYOffset16(cxIdx, TexOffsetY);
			
			NativeWriteBase32( Dest, TexOffset, Rol32(*(PULONG)thisSource, 16) );
			cxTemp -= 2;
			cxIdx += 2;
			thisSource += 4;
		}
		Height--;
		cyIdx++;
		Source += Delta;
	}
}

static void DdrawFlip32(PUCHAR Dest, PUCHAR Source, ULONG Width, ULONG Height, ULONG Delta) {
	ULONG cyIdx = 0;
	while (Height) {
		PUCHAR thisSource = Source;
		ULONG TexOffsetY = CalculateTexYOffset32(cyIdx, Width);
		ULONG cxIdx = 0;
		ULONG cxTemp = Width;
		while (cxTemp) {
			// Guaranteed to be aligned, so we can do this:
			ULONG TexOffset = CalculateTexOffsetWithYOffset32(cxIdx, TexOffsetY);
			ULONG rgb0 = *(PULONG)Dest;
			Dest += 4;
			ULONG rgb1 = *(PULONG)Dest;
			Dest += 4;
			ULONG value = 0xFF00FF00 | (rgb1 >> 16) | (rgb0 & 0xFF0000);
			ULONG value2 = ((rgb0 & 0xFFFF) << 16) | (rgb1 & 0xFFFF);
			NativeWriteBase32( Dest, TexOffset, value );
			NativeWriteBase32( Dest, TexOffset + 0x20, value2 );
			cxTemp -= 2;
			cxIdx += 2;
		}
		Height--;
		cyIdx++;
		Source += Delta;
	}
}

static DWORD DdrawFlip(PDD_FLIPDATA Data) {
	PPDEV pdev = (PPDEV) Data->lpDD->dhpdev;
	PDD_SURFACE_GLOBAL SurfaceGlobal = Data->lpSurfTarg->lpGbl;
	PVOID SourceStart = SurfaceGlobal->fpVidMem;
	if (SourceStart == NULL) {
		// ???
		Data->ddRVal = DD_OK;
		return DDHAL_DRIVER_HANDLED;
	}
	
	PVOID DestinationStart = pdev->pjScreen;
	
	switch (SurfaceGlobal->ddpfSurface.dwRGBBitCount) {
		case 8:
			DdrawFlip8(DestinationStart, SourceStart, SurfaceGlobal->wWidth, SurfaceGlobal->wHeight, SurfaceGlobal->lPitch);
			break;
		case 16:
			DdrawFlip16(DestinationStart, SourceStart, SurfaceGlobal->wWidth, SurfaceGlobal->wHeight, SurfaceGlobal->lPitch);
			break;
		case 32:
			DdrawFlip32(DestinationStart, SourceStart, SurfaceGlobal->wWidth, SurfaceGlobal->wHeight, SurfaceGlobal->lPitch);
			break;
	}
	
	
	Data->ddRVal = DD_OK;
	return DDHAL_DRIVER_HANDLED;
}
#endif

VOID DrvDisableDirectDraw(DHPDEV dhpdev) {
}

BOOL DrvEnableDirectDraw(DHPDEV dhpdev, DD_CALLBACKS* CallBacks, DD_SURFACECALLBACKS *SurfaceCallBacks, DD_PALETTECALLBACKS* PaletteCallBacks) {
	CallBacks->dwSize = sizeof(*CallBacks);
	CallBacks->dwFlags = 0;//DDHAL_CB32_CREATESURFACE;
	//CallBacks->CreateSurface = DdrawCreateSurface;
	SurfaceCallBacks->dwSize = sizeof(*SurfaceCallBacks);
	SurfaceCallBacks->dwFlags = DDHAL_SURFCB32_LOCK | DDHAL_SURFCB32_UNLOCK;
	SurfaceCallBacks->Lock = DdrawLock;
	SurfaceCallBacks->Unlock = DdrawUnlock;
	PaletteCallBacks->dwSize = sizeof(*PaletteCallBacks);
	PaletteCallBacks->dwFlags = 0;
	return TRUE;
}

BOOL DrvGetDirectDrawInfo(DHPDEV dhpdev, DD_HALINFO* HalInfo, DWORD* NumHeaps, VIDEOMEMORY* VideoMemoryList, DWORD* NumFourCC, DWORD* FourCC) {
	*NumHeaps = 0;
	*NumFourCC = 0;
	
	PPDEV pdev = (PPDEV)dhpdev;
	
	HalInfo->dwSize = sizeof(*HalInfo);
	HalInfo->vmiData.dwFlags = 0;
	HalInfo->ddCaps.dwCaps = 0;
	HalInfo->ddCaps.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_PRIMARYSURFACE;
	HalInfo->vmiData.fpPrimary = DDHAL_PLEASEALLOC_USERMEM;
	HalInfo->vmiData.dwDisplayWidth = pdev->cxScreen;
	HalInfo->vmiData.dwDisplayHeight = pdev->cyScreen;
	HalInfo->vmiData.lDisplayPitch = 0x1000;
	HalInfo->vmiData.ddpfDisplay.dwSize = sizeof(DDPIXELFORMAT);
	HalInfo->vmiData.ddpfDisplay.dwFlags = DDPF_RGB;
	HalInfo->vmiData.ddpfDisplay.dwRGBBitCount = pdev->ulBitCount;
	HalInfo->vmiData.ddpfDisplay.dwRBitMask = pdev->flRed;
	HalInfo->vmiData.ddpfDisplay.dwGBitMask = pdev->flGreen;
	HalInfo->vmiData.ddpfDisplay.dwBBitMask = pdev->flBlue;
	HalInfo->vmiData.dwOffscreenAlign = 8;
	
	if (pdev->ulBitCount == 8) {
		HalInfo->vmiData.ddpfDisplay.dwFlags |= DDPF_PALETTEINDEXED8;
		HalInfo->vmiData.ddpfDisplay.dwRBitMask = 0;
		HalInfo->vmiData.ddpfDisplay.dwGBitMask = 0;
		HalInfo->vmiData.ddpfDisplay.dwBBitMask = 0;
	}
	
	return TRUE;
}
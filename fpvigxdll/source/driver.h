/******************************Module*Header*******************************\
* Module Name: driver.h
*
* contains prototypes for the frame buffer driver.
*
* Copyright (c) 1992-1995 Microsoft Corporation
\**************************************************************************/
#include "stddef.h"
#include <stdarg.h>
#include "windef.h"
#include "wingdi.h"
typedef LONG HRESULT;
#include "winddi.h"
#include "devioctl.h"
#include "ntddvdeo.h"
#include "debug.h"
#include "runtime.h"

#define RtlCopyMemory memcpy

typedef struct  _PDEV
{
    HANDLE  hDriver;                    // Handle to \Device\Screen
    HDEV    hdevEng;                    // Engine's handle to PDEV
    HSURF   hsurfEng;                   // Engine's handle to surface
    SURFOBJ* psurfBigFb;                // Pointer to big-endian framebuffer where bIsBigEndian==true
    HSURF   hsurfDouble;                // Handle to framebuffer copy where bIsBigEndian==true
    SURFOBJ* psurfDouble;               // Pointer to framebuffer copy where bIsBigEndian==true
    HPALETTE hpalDefault;               // Handle to the default palette for device.
    PBYTE   pjScreen;                   // This is pointer to base screen address
	PBYTE   pjBitmap;                   // This is a pointer to the bitmap that the driver allocated for us to draw into
    ULONG   cxScreen;                   // Visible screen width
    ULONG   cyScreen;                   // Visible screen height
    ULONG   ulMode;                     // Mode the mini-port driver is in.
    LONG    lDeltaScreen;               // Distance from one scan to the next.
    ULONG   cScreenSize;                // size of video memory, including
                                        // offscreen memory.
    PVOID   pOffscreenList;             // linked list of DCI offscreen surfaces.
    FLONG   flRed;                      // For bitfields device, Red Mask
    FLONG   flGreen;                    // For bitfields device, Green Mask
    FLONG   flBlue;                     // For bitfields device, Blue Mask
    ULONG   cPaletteShift;              // number of bits the 8-8-8 palette must
                                        // be shifted by to fit in the hardware
                                        // palette.
    ULONG   ulBitCount;                 // # of bits per pel 8,16,24,32 are only supported.
    POINTL  ptlHotSpot;                 // adjustment for pointer hot spot
    VIDEO_POINTER_CAPABILITIES PointerCapabilities; // HW pointer abilities
    PVIDEO_POINTER_ATTRIBUTES pPointerAttributes; // hardware pointer attributes
    DWORD   cjPointerAttributes;        // Size of buffer allocated
    PALETTEENTRY *pPal;                 // If this is pal managed, this is the pal
	PVOID   pLockedSurface;             // If ddraw surface is locked down this is the pointer to it
    BOOL    fHwCursorActive;            // Are we currently using the hw cursor
    BOOL    bSupportDCI;                // Does the miniport support DCI?
    BOOL    bIsBigEndian;               // Vram is mapped big endian and so needs swaps done
} PDEV, *PPDEV;

DWORD getAvailableModes(HANDLE, PVIDEO_MODE_INFORMATION *, DWORD *);
BOOL bInitPDEV(PPDEV, PDEVMODEW, GDIINFO *, DEVINFO *);
BOOL bInitSURF(PPDEV, BOOL);
BOOL bInitPaletteInfo(PPDEV, DEVINFO *);
BOOL bInitPointer(PPDEV, DEVINFO *);
BOOL bInit256ColorPalette(PPDEV);
VOID vDisablePalette(PPDEV);
VOID vDisableSURF(PPDEV);

#define MAX_CLUT_SIZE (sizeof(VIDEO_CLUT) + (sizeof(ULONG) * 256))

//
// Determines the size of the DriverExtra information in the DEVMODE
// structure passed to and from the display driver.
//

#define DRIVER_EXTRA_SIZE 0

//extern USHORT s_DllName[];
#define DLL_NAME                s_DllName   // Name of the DLL in UNICODE
#define STANDARD_DEBUG_PREFIX   "FRAMEBUF: "  // All debug output is prefixed
#define ALLOC_TAG               'bfDD'        // Four byte tag (characters in
                                              // reverse order) used for memory
                                              // allocations

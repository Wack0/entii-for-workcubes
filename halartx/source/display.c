// HAL display driver.
// Text-mode only, uses VI only, not the GX blocks.
// NT does use the framebuffer set up by the ARC firmware.

#include "halp.h"
#include "ints.h"

VOID HalpDisplayCharacter(IN UCHAR Character);
VOID HalpOutputCharacter(IN PUCHAR Glyph);
extern ULONG HalpInitPhase;
extern PPI_INTERRUPT_REGS HalpPiInterruptRegs;

static PFRAME_BUFFER s_FbConfig;
static PVOID s_FrameBuffer = NULL;
static BOOLEAN s_FbReInitialised = FALSE;
// Multiprocessor-safety spinlock.
KSPIN_LOCK HalpDisplayAdapterLock;
// Console/font stuff.
BOOLEAN HalpDisplayOwnedByHal;
ULONG HalpBytesPerRow;
ULONG HalpCharacterHeight;
ULONG HalpCharacterWidth;
ULONG HalpColumn;
ULONG HalpDisplayText;
ULONG HalpDisplayWidth;
POEM_FONT_FILE_HEADER HalpFontHeader;
ULONG HalpRow;
ULONG HalpScrollLength;
ULONG HalpScrollLine;
ULONG HalpStride;

enum {
	COLOUR_BACKGROUND = 0x29F0296E, // bright blue
	COLOUR_FOREGROUND = 0xEB80EB80, // bright white
#if 0
	COLOUR_BACKGROUND_HIGH = 0x29F00000,
	COLOUR_FOREGROUND_HIGH = 0xEB800000,
	COLOUR_BACKGROUND_LOW = 0x296E,
	COLOUR_FOREGROUND_LOW = 0xEB80
#endif
	COLOUR_BACKGROUND_LOW = 0x00002900,
	COLOUR_FOREGROUND_LOW = 0x0000EB00,
	COLOUR_BACKGROUND_HIGH = 0x29F0006E,
	COLOUR_FOREGROUND_HIGH = 0xEB800080
};

// static const UCHAR sc_Background[] = { 0x29, 0xF0, 0x29, 0x6E }; // bright blue
// static const UCHAR sc_Foreground[] = { 0xEB, 0x80, 0xEB, 0x80 }; // bright white

static void ViWipeScreen(void) {
	// fill in the whole framebuffer with sc_Background
	ULONG Count = (s_FbConfig->Width * s_FbConfig->Height) / 2;
	volatile ULONG* Fb = (volatile ULONG*)((ULONG)s_FrameBuffer);
	register ULONG bg = COLOUR_BACKGROUND;
	while (Count--) {
		NativeWrite32(Fb, bg);
		Fb++;
	}
}

static BOOLEAN ViInit0(void) {
	// map the framebuffer
	if (s_FrameBuffer == NULL)
		s_FrameBuffer = KePhase0MapIo(
			s_FbConfig->PointerArc,
			s_FbConfig->Length
		);
	return s_FrameBuffer != NULL;
}

static BOOLEAN
ViInit1 (void)
{
	if (HalpInitPhase == 0) return FALSE;
	if (s_FbReInitialised) return TRUE;
	// Ensure the BAT mapping is gone
	if (s_FrameBuffer != NULL) KePhase0DeleteIoMap(s_FbConfig->PointerArc, s_FbConfig->Length);
	// And map it via NT memory manager
	PHYSICAL_ADDRESS physAddr = {0};
	physAddr.LowPart = s_FbConfig->PointerArc;
	s_FrameBuffer = MmMapIoSpace(physAddr, s_FbConfig->Length, FALSE);
	if (s_FrameBuffer == NULL) return FALSE;
	s_FbReInitialised = TRUE;
	return TRUE;
}

// Init VI for HAL's use
BOOLEAN HalpInitializeDisplay0 (IN PLOADER_PARAMETER_BLOCK LoaderBlock) {
	// Set the address of the font file.
	HalpFontHeader = (POEM_FONT_FILE_HEADER)LoaderBlock->OemFontFile;
	POEM_FONT_FILE_HEADER FontHeader = HalpFontHeader;
	HalpBytesPerRow = (FontHeader->PixelWidth + 7) / 8;
	HalpCharacterHeight = FontHeader->PixelHeight;
	HalpCharacterWidth = FontHeader->PixelWidth;
	
	// Initialise VI.
	// The ARC firmware already did the low-level setup of VI,
	// in the correct mode,
	// and so all that's needed is to map the registers,
	// and set a framebuffer.
	
	s_FbConfig = (PFRAME_BUFFER) RUNTIME_BLOCK[RUNTIME_FRAME_BUFFER];
	if ((ULONG)s_FbConfig == 0) return FALSE;
	
	HalpDisplayText = s_FbConfig->Height / HalpCharacterHeight;
	HalpScrollLine = s_FbConfig->Stride * HalpCharacterHeight;
	HalpScrollLength = HalpScrollLine * (HalpDisplayText - 1);
	HalpDisplayWidth = s_FbConfig->Width / HalpCharacterWidth;
	HalpStride = s_FbConfig->Stride;
	
	if (!ViInit0()) return FALSE;
	HalpDisplayOwnedByHal = TRUE;
	ViWipeScreen();
	HalpColumn = 1;
	HalpRow = 3;
	
	return TRUE;
	
}

// Init VI after memory manager available
BOOLEAN HalpInitializeDisplay1(void) {
	// Remap VI to use pagetables instead of a BAT
	if (!ViInit1()) return FALSE;
	
	// Copy the font to newly allocated memory
	PVOID FontHeader = ExAllocatePool(NonPagedPool, HalpFontHeader->FileSize);
	if (FontHeader == NULL) return FALSE;
	
	RtlMoveMemory(FontHeader, HalpFontHeader, HalpFontHeader->FileSize);
	// Flush it out of dcache
	HalSweepDcacheRange(FontHeader, HalpFontHeader->FileSize);
	HalpFontHeader = (POEM_FONT_FILE_HEADER) FontHeader;
	return TRUE;
}

// Allows the system display driver to use the VI framebuffer.
VOID HalAcquireDisplayOwnership (IN PHAL_RESET_DISPLAY_PARAMETERS  ResetDisplayParameters)
{
	HalpDisplayOwnedByHal = FALSE;
}

static void HalpDisplayAbortWait(ULONG Clocks) {
	register ULONGLONG Time0, Time1;
	Time0 = HalpReadTimeBase();
	do {
		Time1 = HalpReadTimeBase();
	} while ( (Time1 - Time0) <= (Clocks / 4) );
}

#if 0
static ULONG HalpReadMemCounterPe32(void) {
	volatile USHORT * _memReg = (volatile USHORT * ) 0x8C004000;
	USHORT temp, first, second;
	temp = MmioRead16(&_memReg[39]);
	do {
		first = temp;
		second = MmioRead16(&_memReg[40]);
		temp = MmioRead16(&_memReg[39]);
	} while (temp != first);
	ULONG ret = first;
	ret <<= 16;
	ret |= second;
	return ret;
}

static void HalpDisplayWaitAbortPe(void) {
	ULONG Count, Temp;
	Count = HalpReadMemCounterPe32();
	do {
		Temp = Count;
		HalpDisplayAbortWait(8);
		Count = HalpReadMemCounterPe32();
	} while (Count != Temp);
}
#endif

// Get display rights back from system display driver
static void HalpDisplayOwnByHal(void) {
	if (HalpDisplayOwnedByHal) return;
	
	HalpDisplayOwnedByHal = TRUE;
	// Disable VI/PEFinish interrupts.
	HalpDisableDeviceInterruptHandler(VECTOR_VI);
	//HalpDisableDeviceInterruptHandler(VECTOR_PE_FINISH);
	// Wait for GPU to be done
	//HalpDisplayWaitAbortPe();
	// Tell GPU to stop rendering
	MmioWriteBase32(MMIO_OFFSET(HalpPiInterruptRegs, CpAbort), TRUE);
	// Wait a bit
	//HalpDisplayAbortWait(1000);
	ViWipeScreen();
	HalpColumn = 1;
	HalpRow = 3;
	
}

// Prints a string to the VI framebuffer.
VOID HalDisplayString (PUCHAR String) {
	KiAcquireSpinLock(&HalpDisplayAdapterLock);
	
	HalpDisplayOwnByHal();
	
	while (*String != 0) {
		HalpDisplayCharacter(*String);
		String++;
	}
	
	KiReleaseSpinLock(&HalpDisplayAdapterLock);
}

// Prints a character to the VI framebuffer.
VOID HalpDisplayCharacter(IN UCHAR Character) {
	if (Character == '\n') {
		HalpColumn = 1;
		if (HalpRow < (HalpDisplayText - 1)) HalpRow ++;
		else {
			RtlMoveMemory(
				s_FrameBuffer,
				(PVOID)((ULONG)s_FrameBuffer + HalpScrollLine),
				HalpScrollLength
			);
			volatile ULONG* Destination = (volatile ULONG*)((ULONG)s_FrameBuffer + HalpScrollLength);
			register ULONG bg = COLOUR_BACKGROUND;
			for (ULONG Index = 0; Index < (HalpScrollLine / 2); Index++) {
				NativeWriteBase32(Destination, Index * sizeof(*Destination), bg);
			}
		}
		return;
	}
	if (Character == '\r') {
		HalpColumn = 1;
		return;
	}
	
	if (
		(Character < HalpFontHeader->FirstCharacter) ||
		(Character > HalpFontHeader->LastCharacter)
	) {
		Character = HalpFontHeader->DefaultCharacter;
	}
	
	Character -= HalpFontHeader->FirstCharacter;
	HalpOutputCharacter((PUCHAR)HalpFontHeader + HalpFontHeader->Map[Character].Offset);
}

// Returns display information.
VOID
HalQueryDisplayParameters (
    OUT PULONG WidthInCharacters,
    OUT PULONG HeightInLines,
    OUT PULONG CursorColumn,
    OUT PULONG CursorRow
    )
{
	KiAcquireSpinLock(&HalpDisplayAdapterLock);
	
	*WidthInCharacters = HalpDisplayWidth;
	*HeightInLines = HalpDisplayText;
	*CursorColumn = HalpColumn;
	*CursorRow = HalpRow;
	
	KiReleaseSpinLock(&HalpDisplayAdapterLock);
}

// Sets the current cursor position.
VOID
HalSetDisplayParameters (
    IN ULONG CursorColumn,
    IN ULONG CursorRow
    )
{
	KiAcquireSpinLock(&HalpDisplayAdapterLock);
	
	if (CursorColumn > HalpDisplayWidth) {
		CursorColumn = HalpDisplayWidth;
	}
	if (CursorRow > HalpDisplayText) {
		CursorRow = HalpDisplayText;
	}
	HalpColumn = CursorColumn;
	HalpRow = CursorRow;
	
	KiReleaseSpinLock(&HalpDisplayAdapterLock);
}

// Outputs a character whose font data is specified.
VOID
HalpOutputCharacter(
    IN PUCHAR Glyph
    )
{
	// Insert a newline if required.
	if (HalpColumn == HalpDisplayWidth) {
		HalpDisplayCharacter('\n');
	}
	
	// Output the character and update the cursor column.
	ULONG Offset = (HalpRow * HalpScrollLine) + (HalpColumn * HalpCharacterWidth * 2);
	volatile ULONG* Destination = (volatile ULONG*)((ULONG)s_FrameBuffer + Offset);
	
	ULONG Stride = HalpStride;
	for (ULONG i = 0; i < HalpCharacterHeight; i++) {
		ULONG FontValue = 0;
		for (ULONG fontIdx = 0; fontIdx < HalpBytesPerRow; fontIdx++) {
			FontValue |= Glyph[fontIdx * HalpCharacterHeight] << (24 - (fontIdx * 8));
		}
		Glyph++;
		for (ULONG charBit = 0; charBit < HalpCharacterWidth; charBit += 2) {
			UCHAR bit = (FontValue >> 31);
			register ULONG colour = (bit == 1 ? COLOUR_FOREGROUND_HIGH : COLOUR_BACKGROUND_HIGH);
			FontValue <<= 1;
			bit = (FontValue >> 31);
			colour |= (bit == 1 ? COLOUR_FOREGROUND_LOW : COLOUR_BACKGROUND_LOW);
			NativeWrite32(Destination, colour);
			Destination++;
			//Destination += 2; //4;
			FontValue <<= 1;
		}
		Offset += Stride;
		Destination = (volatile ULONG*)((ULONG)s_FrameBuffer + Offset);
	}
	
	HalpColumn++;
}
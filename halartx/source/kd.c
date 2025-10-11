// Implements the kernel debugger over USB Gecko.

#include "halp.h"
#include "exi.h"

enum {
	TIMEOUT_COUNT = 1024 * 512
};

PUCHAR KdComPortInUse = NULL;

PEXI_REGISTERS HalpExiRegs = NULL;
static ULONG s_ExiRegisterBase = 0;

#define EXI_CHAN1 Channel[1]

static ULONG UsbGeckoSendAndReceive(ULONG Data) {
	// Send the command and wait for response.
	MmioWriteBase32(MMIO_OFFSET(HalpExiRegs, EXI_CHAN1.Parameter), 0xD0);
	MmioWriteBase32(MMIO_OFFSET(HalpExiRegs, EXI_CHAN1.Data), Data);
	MmioWriteBase32(MMIO_OFFSET(HalpExiRegs, EXI_CHAN1.Transfer), 0x19);
	while ((MmioReadBase32(MMIO_OFFSET(HalpExiRegs, EXI_CHAN1.Transfer)) & 1) != 0) { }
	ULONG Recv = MmioReadBase32(MMIO_OFFSET(HalpExiRegs, EXI_CHAN1.Data));
	MmioWriteBase32(MMIO_OFFSET(HalpExiRegs, EXI_CHAN1.Parameter), 0);
	return Recv;
}

static BOOLEAN UsbGeckoReadyToReceive(void) {
	return (UsbGeckoSendAndReceive(0xD0000000) & 0x04000000) != 0;
}

static ULONG HalpGetByteImpl(IN PCHAR Input, IN BOOLEAN Wait) {
	ULONG TimeoutCount = Wait ? TIMEOUT_COUNT : 1;
	while (TimeoutCount) {
		TimeoutCount--;
		KeStallExecutionProcessor(1);
		if (!UsbGeckoReadyToReceive()) continue;
		ULONG Recv = UsbGeckoSendAndReceive(0xA0000000);
		if ((Recv & 0x08000000) == 0) return CP_GET_ERROR;
		*Input = (Recv >> 16) & 0xff;
		return CP_GET_SUCCESS;
	}
	return CP_GET_NODATA;
}

static ULONG HalpGetByte(IN PCHAR Input, IN BOOLEAN Wait) {
	if (KdComPortInUse == NULL) return CP_GET_NODATA;
	return HalpGetByteImpl(Input, Wait);
}

BOOLEAN HalpMapExiRegs(void) {
	// Ensure the BAT mapping is gone
	if (HalpExiRegs != NULL) KePhase0DeleteIoMap(s_ExiRegisterBase, sizeof(EXI_REGISTERS));
	
	// Map by MM
	PHYSICAL_ADDRESS physAddr;
	physAddr.HighPart = 0;
	physAddr.LowPart = s_ExiRegisterBase;
	HalpExiRegs = (PEXI_REGISTERS)
		MmMapIoSpace(physAddr, sizeof(EXI_REGISTERS), FALSE);
	if (HalpExiRegs == NULL) return FALSE;
	return TRUE;
}

BOOLEAN HalpMapExiRegsByBAT(void) {
	if (HalpExiRegs == NULL) {
		if (s_ExiRegisterBase == 0) {
			ULONG ExiRegisterBase = EXI_REGISTER_BASE_FLIPPER;
			if ((ULONG)RUNTIME_BLOCK[RUNTIME_SYSTEM_TYPE] > ARTX_SYSTEM_FLIPPER) ExiRegisterBase += (EXI_REGISTER_BASE - EXI_REGISTER_BASE_FLIPPER);
			s_ExiRegisterBase = ExiRegisterBase;
		}
		HalpExiRegs = KePhase0MapIo(s_ExiRegisterBase, sizeof(EXI_REGISTERS));
	}
	return HalpExiRegs != NULL;
}

// Initialise the usb gecko used by the kernel debugger.

BOOLEAN
KdPortInitialize (
    PDEBUG_PARAMETERS DebugParameters,
    PLOADER_PARAMETER_BLOCK LoaderBlock,
    BOOLEAN Initialize
    )
{
	
	// If the EXI registers have not yet been mapped, map them by a BAT.
	if (!HalpMapExiRegsByBAT()) return FALSE;
	
	// If the debugger is not being enabled, do nothing more.
	if (!Initialize) return TRUE;
	
	// On Cafe, there are no devices on the EXI bus
	if (HalpSystemIsCafe()) return FALSE;
	
	// If some block device is at EXI1, bail.
	ULONG ExiDevices = (ULONG)RUNTIME_BLOCK[RUNTIME_EXI_DEVICES];
	if ((ExiDevices & 0x02) != 0) return FALSE;
	
	// Check that a USB Gecko is connected to EXI port 1.
	if (UsbGeckoSendAndReceive(0x90000000) != 0x04700000) {
		// it's not, byebye
		return FALSE;
	}
	
	// Flush the FIFO.
	{
		BOOLEAN Wait = TRUE;
		CHAR Received;
		while (HalpGetByteImpl(&Received, Wait) != CP_GET_NODATA) {
			Wait = FALSE;
		}
	}
	
	KdComPortInUse = (PUCHAR)0x03F8; // COM1_PORT
	
	// Kernel debugger is ready!
	return TRUE;
}

// Read a byte (blocking until timeout) from usb gecko.
ULONG KdPortGetByte(OUT PUCHAR Input) {
	return HalpGetByte(Input, TRUE);
}

// Read a byte from usb gecko if available
ULONG KdPortPollByte(OUT PUCHAR Input) {
	return HalpGetByte(Input, FALSE);
}

// Write a byte to usb gecko.
// Interrupts should be disabled (IRQL at highest) before calling this.
VOID KdPortPutByte(IN UCHAR Output) {
	if (KdComPortInUse == NULL) return;
	// Wait for FIFO to be ready
	while ((UsbGeckoSendAndReceive(0xC0000000) & 0x04000000) == 0) { }
	// Send the byte
	ULONG ret = 0;
	do {
		ret = UsbGeckoSendAndReceive(0xB0000000 | (Output << 20));
	} while ((ret & 0x04000000) == 0);
}

// No-op, as nothing else uses EXI bus and especially channel 1.
VOID KdPortRestore(VOID) { }

// No-op, as nothing else uses EXI bus and especially channel 1.
VOID KdPortSave(VOID) { }


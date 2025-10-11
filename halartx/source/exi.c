// Implements an EXI driver.

#include "halp.h"
#include "exiapi.h"
#include "exi.h"
#include "ints.h"

#define ExiRegisters HalpExiRegs
extern PEXI_REGISTERS HalpExiRegs;
extern PUCHAR KdComPortInUse;

static KINTERRUPT s_ExiInterrupt;

static PUCHAR s_DmaMapBuffer;
static ULONG s_DmaMapBufferPhys;

enum {
	EXI_ASYNC_NONE,
	EXI_ASYNC_IMM,
	EXI_ASYNC_IMMBUF,
	EXI_ASYNC_IMMOUTBUF,
	EXI_ASYNC_DMA,
	EXI_ASYNC_FROMSYNC
};

typedef struct _EXI_ASYNC_WORK_ITEM {
	WORK_QUEUE_ITEM WorkItem;
	ULONG Channel;
} EXI_ASYNC_WORK_ITEM, *PEXI_ASYNC_WORK_ITEM;

typedef struct _EXI_ASYNC_DESCRIPTOR {
	ULONG Type;
	ULONG Part;
	PUCHAR BufferRead;
	PUCHAR BufferWrite;
	ULONG Length;
	ULONG PartLength;
	EXI_SWAP_MODE SwapMode;
	EXI_TRANSFER_TYPE TransferType;
	union {
		HAL_EXI_IMMASYNC_CALLBACK ImmAsync;
		HAL_EXI_ASYNC_CALLBACK Async;
	} Callback;
	PVOID Context;
	EXI_ASYNC_WORK_ITEM WorkItem;
} EXI_ASYNC_DESCRIPTOR, *PEXI_ASYNC_DESCRIPTOR;


static KDPC s_DpcTransferComplete[EXI_CHANNEL_COUNT * 0x10],
	s_DpcDevice[EXI_CHANNEL_COUNT];
static EXI_ASYNC_DESCRIPTOR s_AsyncDesc[EXI_CHANNEL_COUNT];

static HAL_EXI_INTERRUPT_CALLBACK s_InterruptCallbacks[EXI_CHANNEL_COUNT];

void HalExiLockInit(void);
BOOLEAN HalExiLocked(ULONG channel);

#define EXI_CLOCK_ZERO EXI_CLOCK_0_8

static BOOLEAN HalpExiInterrupt(PKINTERRUPT InterruptRoutine, PVOID ServiceContext, PVOID TrapFrame) {
	EXI_CHANNEL_PARAMETER_REGISTER Cpr;
	EXI_CHANNEL_PARAMETER_REGISTER CprNoAck;
	EXI_CHANNEL_PARAMETER_REGISTER CprAck;
	for (ULONG i = 0; i < EXI_CHANNEL_COUNT; i++) {
		Cpr.Value = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[i].Parameter));
		CprNoAck.Value = Cpr.Value;
		CprNoAck.DeviceInterruptStatus = CprNoAck.UnplugInterruptStatus = CprNoAck.TransferInterruptStatus = 0;
		
		if (Cpr.TransferInterruptStatus) {
			CprAck.Value = CprNoAck.Value;
			CprAck.TransferInterruptStatus = 1;
			MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[i].Parameter), CprAck.Value);
			//DbgPrint("%d", i);
			
			BOOLEAN GotOne = FALSE;
			for (ULONG d = 0; d < 0x10; d++) {
				GotOne = KeInsertQueueDpc(&s_DpcTransferComplete[i * 0x10 + d], (PVOID)i, NULL);
				if (GotOne) break;
			}
			if (!GotOne) KeBugCheckEx(NO_MORE_IRP_STACK_LOCATIONS, i, 0, 0, 'EXI');
		}
		
		if (Cpr.UnplugInterruptStatus) {
			// just ack it
			CprAck.Value = CprNoAck.Value;
			CprAck.UnplugInterruptStatus = 1;
			MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[i].Parameter), CprAck.Value);
		}
		
		if (Cpr.DeviceInterruptStatus) {
			// mask it, and send dpc
			CprAck.Value = CprNoAck.Value;
			CprAck.DeviceInterruptMask = 0;
			MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[i].Parameter), CprAck.Value);
			
			KeInsertQueueDpc(&s_DpcDevice[i], (PVOID)i, NULL);
		}
	}
	
	return TRUE;
}

static BOOLEAN ExipDeviceSelected(ULONG channel) {
	// Ensure a chip select line is pulled low, or frequency is non-zero
	EXI_CHANNEL_PARAMETER_REGISTER Cpr;
	Cpr.Value = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter));
	if (Cpr.ChipSelect0 == 0 && Cpr.ChipSelect1 == 0 && Cpr.ChipSelect2 == 0) {
		if (Cpr.ClockFrequency == EXI_CLOCK_ZERO) return FALSE; // No device selected.
	}
	
	if (s_AsyncDesc[channel].Type != EXI_ASYNC_NONE) return FALSE; // Async transfer in progress.
	
	// Ensure transfer is not currently in progress.
	EXI_CHANNEL_TRANSFER_REGISTER Ctr;
	Ctr.Value = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Transfer));
	return (Ctr.Start == 0);
}

static void ExipEnableTransferCompleteInterrupt(ULONG channel, BOOLEAN value) {
	EXI_CHANNEL_PARAMETER_REGISTER Cpr;
	Cpr.Value = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter));
	Cpr.TransferInterruptMask = value;
	Cpr.TransferInterruptStatus = 0;
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter), Cpr.Value);
}

BOOLEAN HalExiIsDevicePresent(ULONG channel, ULONG device) {
	if (channel >= EXI_CHANNEL_COUNT) return FALSE;
	if (device >= EXI_DEVICE_COUNT) return FALSE;
	// for channel 0, this only detects memcard.
	if (channel == 0 && device != EXI_CHAN0_DEVICE_MEMCARD) return TRUE;
	// for channel 1 and 2, only device 0 exists
	if (channel != 0 && device != 0) return FALSE;
	// EXI2EXTIN pin does not exist on any system, so always assume a device is present on channel 2
	if (channel == 2) return TRUE;
	// For channel 1, if kernel debugger is present, return false; as kd device is there.
	if (channel == 1 && KdComPortInUse != NULL) return FALSE;

	EXI_CHANNEL_PARAMETER_REGISTER Cpr;
	Cpr.Value = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter));

	return Cpr.Connected;
}

NTSTATUS HalExiSelectDevice(ULONG channel, ULONG device, EXI_CLOCK_FREQUENCY frequency, BOOLEAN CsHigh) {
	if (channel >= EXI_CHANNEL_COUNT) return STATUS_INVALID_PARAMETER_1;
	if (device >= EXI_DEVICE_COUNT) return STATUS_INVALID_PARAMETER_2;
	if (channel != 0 && device != 0) return STATUS_INVALID_PARAMETER;
	if ((ULONG)frequency > EXI_CLOCK_54) return STATUS_INVALID_PARAMETER_3;
	// Do not allow high chip select with 0.8MHz clock.
	if (CsHigh && frequency == EXI_CLOCK_ZERO) return STATUS_INVALID_PARAMETER_4;
	// Make sure frequency is valid for this system.
	if (frequency == EXI_CLOCK_54) {
		if ((ULONG)RUNTIME_BLOCK[RUNTIME_SYSTEM_TYPE] == ARTX_SYSTEM_FLIPPER) {
			// Flipper, 54MHz frequency is not valid here.
			return STATUS_INVALID_PARAMETER_3;
		}
	}
	
	// Channel must be locked.
	if (!HalExiLocked(channel)) return STATUS_INVALID_PARAMETER_1;

	EXI_CHANNEL_PARAMETER_REGISTER Cpr;
	Cpr.Value = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter));
	// If one of the chip select lines are pulled low already, fail.
	if (Cpr.ChipSelect0 != 0 || Cpr.ChipSelect1 != 0 || Cpr.ChipSelect2 != 0) return STATUS_INVALID_DEVICE_STATE;
	// Could be selected for SDMC reset sequence, so check the clock frequency too.
	// If it's not zero, then some device was selected with all CS lines pulled up.
	if (Cpr.ClockFrequency != EXI_CLOCK_ZERO) return STATUS_INVALID_DEVICE_STATE;
	// For a memory card device (channel 1 or channel 0, device 0), if no device is present on the bus, fail.
	if ((channel == 1 || (channel == 0 && device == 0)) && !Cpr.Connected) return STATUS_DEVICE_NOT_READY;
	// Mask out all read bits other than the interrupt mask bits.
	// This has the effect of zeroing out clock frequency and all chip select bits.
	{
		EXI_CHANNEL_PARAMETER_REGISTER CprMask;
		CprMask.Value = 0;
		CprMask.DeviceInterruptMask = 1;
		CprMask.TransferInterruptMask = 1;
		CprMask.UnplugInterruptMask = 1;
		Cpr.Value &= CprMask.Value;
	}
	// Set the requested clock frequency.
	Cpr.ClockFrequency = frequency;
	// if requested, keep all CS lines pulled up (for example SDMC reset sequence needs this)
	// otherwise, pull requested CS line down
	if (!CsHigh) {
		EXI_CHANNEL_PARAMETER_REGISTER CprCs;
		CprCs.Value = 0;
		CprCs.ChipSelect0 = 1;
		Cpr.Value |= (CprCs.Value << device);
	}
	// Write the new channel parameter register value.
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter), Cpr.Value);

	return STATUS_SUCCESS;
}

static void ExipUnselectDevice(ULONG channel, ULONG cpr) {
	// Mask out all read bits other than the interrupt mask bits.
	// This has the effect of zeroing out clock frequency and all chip select bits.
	{
		EXI_CHANNEL_PARAMETER_REGISTER CprMask;
		CprMask.Value = 0;
		CprMask.DeviceInterruptMask = 1;
		CprMask.TransferInterruptMask = 1;
		CprMask.UnplugInterruptMask = 1;
		cpr &= CprMask.Value;
	}

	// Write the new channel parameter register value.
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter), cpr);
}

NTSTATUS HalExiUnselectDevice(ULONG channel) {
	if (channel >= EXI_CHANNEL_COUNT) return STATUS_INVALID_PARAMETER;
	// Channel must be locked.
	if (!HalExiLocked(channel)) return STATUS_INVALID_PARAMETER;

	EXI_CHANNEL_PARAMETER_REGISTER Cpr;
	Cpr.Value = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter));
	// If none of the chip select lines are pulled low already.
	if (Cpr.ChipSelect0 == 0 && Cpr.ChipSelect1 == 0 && Cpr.ChipSelect2 == 0) {
		// If clock frequency is zero, then there's nothing that needs to be done.
		if (Cpr.ClockFrequency == EXI_CLOCK_ZERO) return STATUS_SUCCESS;
	}

	ExipUnselectDevice(channel, Cpr.Value);
	return STATUS_SUCCESS;
}

NTSTATUS HalExiRefreshDevice(ULONG channel) {
	if (channel >= EXI_CHANNEL_COUNT) return STATUS_INVALID_PARAMETER;
	// Channel must be locked.
	if (!HalExiLocked(channel)) return STATUS_INVALID_PARAMETER;

	// Read the channel parameter register
	EXI_CHANNEL_PARAMETER_REGISTER Cpr;
	Cpr.Value = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter));
	// If none of the chip select lines are pulled low already, fail.
	if (Cpr.ChipSelect0 == 0 && Cpr.ChipSelect1 == 0 && Cpr.ChipSelect2 == 0) return STATUS_INVALID_DEVICE_STATE;

	// Unselect the device.
	ExipUnselectDevice(channel, Cpr.Value);

	// Write the old channel parameter register, reselecting the device.
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter), Cpr.Value);
	return STATUS_SUCCESS;
}

static NTSTATUS ExipTransferImmediate(ULONG channel, ULONG data, ULONG length, EXI_TRANSFER_TYPE type, PULONG dataRead) {
	// Shift the data into the correct bits for length.
	if (type != EXI_TRANSFER_READ) {
		data <<= (4 - length) * 8; // 4=>0, 3=>8, 2=>16, 1=>24
		MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Data), data);
	}
	
	ExipEnableTransferCompleteInterrupt(channel, FALSE);

	KIRQL OldIrql = HalpRaiseDeviceIrql(VECTOR_EXI);
	// Start the transfer.
	EXI_CHANNEL_TRANSFER_REGISTER Ctr;
	Ctr.Value = 0;
	Ctr.Start = 1;
	Ctr.EnableDma = 0;
	Ctr.Type = type;
	Ctr.Length = length - 1;
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Transfer), Ctr.Value);

	// Wait for transfer to complete.
	do {
		Ctr.Value = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Transfer));
	} while (Ctr.Start);
	KeLowerIrql(OldIrql);
	
	if (type != EXI_TRANSFER_WRITE) {
		ULONG Ret = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Data));
		Ret >>= (4 - length) * 8;
		*dataRead = Ret;
	}
	
	return STATUS_SUCCESS;
}

NTSTATUS HalExiTransferImmediate(ULONG channel, ULONG data, ULONG length, EXI_TRANSFER_TYPE type, PULONG dataRead) {
	if (channel >= EXI_CHANNEL_COUNT) return STATUS_INVALID_PARAMETER_1;
	if (type != EXI_TRANSFER_WRITE && dataRead == NULL) return STATUS_INVALID_PARAMETER_5;
	if (length > sizeof(ExiRegisters->Channel[0].Data)) return STATUS_INVALID_PARAMETER_3;

	// Channel must be locked.
	if (!HalExiLocked(channel)) return STATUS_INVALID_PARAMETER_1;
	
	// Ensure a device is selected.
	if (!ExipDeviceSelected(channel)) return STATUS_INVALID_DEVICE_STATE;

	return ExipTransferImmediate(channel, data, length, type, dataRead);
}

NTSTATUS HalExiTransferImmediateBuffer(ULONG channel, PVOID bufferRead, PVOID bufferWrite, ULONG length, EXI_TRANSFER_TYPE type) {
	PUCHAR pRead = (PUCHAR)bufferRead;
	PUCHAR pWrite = (PUCHAR)bufferWrite;

	if (channel >= EXI_CHANNEL_COUNT) return STATUS_INVALID_PARAMETER_1;
	if (type != EXI_TRANSFER_READ && pRead == NULL) return STATUS_INVALID_PARAMETER_2;
	if (type != EXI_TRANSFER_WRITE && pWrite == NULL) return STATUS_INVALID_PARAMETER_3;

	// Channel must be locked.
	if (!HalExiLocked(channel)) return STATUS_INVALID_PARAMETER_1;
	
	// Ensure a device is selected.
	if (!ExipDeviceSelected(channel)) return STATUS_INVALID_DEVICE_STATE;

	enum {
		EXI_BUFFER_INCREMENT = sizeof(ExiRegisters->Channel[0].Data)
	};

	ULONG thisLength = 0;
	for (; length != 0; pRead += thisLength, pWrite += thisLength, length -= thisLength) {
		thisLength = length;
		if (thisLength > EXI_BUFFER_INCREMENT)
			thisLength = EXI_BUFFER_INCREMENT;

		ULONG thisData = 0;
		if (type != EXI_TRANSFER_READ) {
			for (ULONG i = 0; i < thisLength; i++) {
				thisData |= pRead[i] << ((thisLength - i - 1) * 8);
			}
		}

		ULONG thisOutput = 0;
		NTSTATUS Status = ExipTransferImmediate(channel, thisData, thisLength, type, &thisOutput);
		if (!NT_SUCCESS(Status)) return Status;

		if (type != EXI_TRANSFER_WRITE) {
			for (ULONG i = 0; i < thisLength; i++) {
				pWrite[i] = (UCHAR)(thisOutput >> ((thisLength - i - 1) * 8));
			}
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS HalExiReadWriteImmediateOutBuffer(ULONG channel, UCHAR byteRead, PVOID buffer, ULONG length) {
	PUCHAR pWrite = (PUCHAR)buffer;

	if (channel >= EXI_CHANNEL_COUNT) return STATUS_INVALID_PARAMETER_1;
	if (pWrite == NULL) return STATUS_INVALID_PARAMETER_3;
	
	// Channel must be locked.
	if (!HalExiLocked(channel)) return STATUS_INVALID_PARAMETER_1;

	// Ensure a device is selected.
	if (!ExipDeviceSelected(channel)) return STATUS_INVALID_DEVICE_STATE;

	enum {
		EXI_BUFFER_INCREMENT = sizeof(ExiRegisters->Channel[0].Data)
	};

	ULONG wordRead = (ULONG)byteRead * 0x01010101;
	ULONG thisLength = 0;
	for (; length != 0; pWrite += thisLength, length -= thisLength) {
		thisLength = length;
		if (thisLength > EXI_BUFFER_INCREMENT)
			thisLength = EXI_BUFFER_INCREMENT;

		ULONG thisOutput = 0;
		NTSTATUS Status = ExipTransferImmediate(channel, wordRead, thisLength, EXI_TRANSFER_READWRITE, &thisOutput);
		if (!NT_SUCCESS(Status)) return Status;

		for (ULONG i = 0; i < thisLength; i++) {
				pWrite[i] = (UCHAR)(thisOutput >> ((thisLength - i - 1) * 8));
		}
	}

	return STATUS_SUCCESS;
}

// DMA transfers must be 32-byte aligned, so this swap function is guaranteed to work
static void ExipEndianSwap64(void* dest, const void* src, ULONG len) {
	const ULONG* src32 = (const ULONG*)src;
	ULONG* dest32 = (ULONG*)dest;
	for (ULONG i = 0; i < len; i += sizeof(ULONG) * 2) {
		ULONG idx = i / sizeof(ULONG);
		ULONG buf0 = __builtin_bswap32(src32[idx + 0]);
		dest32[idx + 0] = __builtin_bswap32(src32[idx + 1]);
		dest32[idx + 1] = buf0;
	}
}

static void ExipTransferDma(ULONG channel, PVOID buffer, ULONG length, EXI_TRANSFER_TYPE type, EXI_SWAP_MODE swap) {
	ULONG MapOffset = PAGE_SIZE * channel;
	PUCHAR MapBuffer = &s_DmaMapBuffer[MapOffset];
	
	// For a DMA write, copy the buffer contents into the map buffer, swapping if necessary, then flush dcache.
	if (type == EXI_TRANSFER_WRITE) {
		if ((swap & EXI_SWAP_INPUT) != 0) {
			if (((ULONG)buffer & 7) != 0) {
				RtlCopyMemory(MapBuffer, buffer, length);
				ExipEndianSwap64(MapBuffer, MapBuffer, length);
			}
			else ExipEndianSwap64(MapBuffer, buffer, length);
		} else {
			RtlCopyMemory(MapBuffer, buffer, length);
		}
		HalSweepDcacheRange(MapBuffer, length);
	}
	
	// Set DMA pointer and length.
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].DmaAddress), s_DmaMapBufferPhys + MapOffset);
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].DmaLength), length);
	
	ExipEnableTransferCompleteInterrupt(channel, FALSE);

	// Start the transfer.
	EXI_CHANNEL_TRANSFER_REGISTER Ctr;
	Ctr.Value = 0;
	Ctr.Start = 1;
	Ctr.EnableDma = 1;
	Ctr.Type = type;
	Ctr.Length = 0;
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Transfer), Ctr.Value);

	// Wait for transfer to complete.
	do {
		Ctr.Value = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Transfer));
	} while (Ctr.Start);

	// If the buffer got written to by DMA, invalidate data cache for the map buffer, then copy back to the original buffer, swapping if necessary.
	if (type == EXI_TRANSFER_READ) {
		HalpInvalidateDcacheRange(MapBuffer, length);
		if (swap != EXI_SWAP_NONE) {
			if (((ULONG)buffer & 7) != 0) {
				ExipEndianSwap64(MapBuffer, MapBuffer, length);
				RtlCopyMemory(buffer, MapBuffer, length);
			}
			else ExipEndianSwap64(buffer, MapBuffer, length);
		} else {
			RtlCopyMemory(buffer, MapBuffer, length);
		}
	}
}

NTSTATUS HalExiTransferDma(ULONG channel, PVOID buffer, ULONG length, EXI_TRANSFER_TYPE type, EXI_SWAP_MODE swap) {
	if (channel >= EXI_CHANNEL_COUNT) return STATUS_INVALID_PARAMETER_1;
	// EXI DMA does not support read+write
	if (type == EXI_TRANSFER_READWRITE) return STATUS_INVALID_PARAMETER_4;
	
	// Channel must be locked.
	if (!HalExiLocked(channel)) return STATUS_INVALID_PARAMETER_1;
	
	// Ensure a device is selected.
	if (!ExipDeviceSelected(channel)) return STATUS_INVALID_DEVICE_STATE;
	
	ULONG DmaMisalignedLength = (-((ULONG)buffer)) & (0x20 - 1);
	
	if ((length - DmaMisalignedLength) < 0x20) {
		// Tried to DMA less than 32 bytes, just use immediate transfer.
		return HalExiTransferImmediateBuffer(channel, buffer, buffer, length, type);
	}
	
	PUCHAR Pointer = (PUCHAR)buffer;
	
	if (DmaMisalignedLength != 0) {
		// Use an immediate transfer for the misaligned part of the buffer.
		NTSTATUS Status = HalExiTransferImmediateBuffer(channel, Pointer, Pointer, DmaMisalignedLength, type);
		if (!NT_SUCCESS(Status)) return Status;
		length -= DmaMisalignedLength;
		Pointer += DmaMisalignedLength;
	}
	
	ULONG AlignedLength = length & ~(0x20 - 1);
	
	// Do DMA up until the next page boundary.
	DmaMisalignedLength = (-((ULONG)Pointer)) & (PAGE_SIZE - 1);
	if (AlignedLength < DmaMisalignedLength) {
		// Less than a page needed to DMA, in total.
		ExipTransferDma(channel, Pointer, AlignedLength, type, swap);
		length -= AlignedLength;
		Pointer += AlignedLength;
	} else {
		if ((AlignedLength - DmaMisalignedLength) != 0 && (AlignedLength - DmaMisalignedLength) < PAGE_SIZE) {
			// Less than a page needed to DMA.
			ExipTransferDma(channel, Pointer, AlignedLength, type, swap);
			length -= AlignedLength;
			Pointer += AlignedLength;
		}
	}
	
	// DMA whole pages until that's no longer possible.
	AlignedLength = length & ~(0x20 - 1);
	while (AlignedLength >= PAGE_SIZE) {
		ExipTransferDma(channel, Pointer, PAGE_SIZE, type, swap);
		length -= PAGE_SIZE;
		AlignedLength -= PAGE_SIZE;
		Pointer += PAGE_SIZE;
	}
	
	if (AlignedLength != 0) {
		// DMA the final chunk that can be DMA'd.
		ExipTransferDma(channel, Pointer, AlignedLength, type, swap);
		length -= AlignedLength;
		Pointer += AlignedLength;
	}
	
	if (length != 0) {
		// Final misaligned transfer.
		return HalExiTransferImmediateBuffer(channel, Pointer, Pointer, length, type);
	}
	
	// All done.
	return STATUS_SUCCESS;
}

static void ExipAsyncTransferImmediateStart(ULONG channel, ULONG data, ULONG length, EXI_TRANSFER_TYPE type) {
	// Shift the data into the correct bits for length.
	if (type != EXI_TRANSFER_READ) {
		data <<= (4 - length) * 8; // 4=>0, 3=>8, 2=>16, 1=>24
		MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Data), data);
	}
	
	// Ensure transfer complete interrupt is enabled.
	ExipEnableTransferCompleteInterrupt(channel, TRUE);

	// Start the asynchronous transfer.
	EXI_CHANNEL_TRANSFER_REGISTER Ctr;
	Ctr.Value = 0;
	Ctr.Start = 1;
	Ctr.EnableDma = 0;
	Ctr.Type = type;
	Ctr.Length = length - 1;
	//DbgPrint("i");
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Transfer), Ctr.Value);
}

static void ExipTransferImmediateBufferAsync(ULONG channel, PVOID bufferRead, PVOID bufferWrite, ULONG length, EXI_TRANSFER_TYPE type, HAL_EXI_ASYNC_CALLBACK callback, PVOID context, ULONG asyncType, ULONG partLength, EXI_SWAP_MODE swap) {
	PUCHAR pRead = (PUCHAR)bufferRead;
	PUCHAR pWrite = (PUCHAR)bufferWrite;
	
	PEXI_ASYNC_DESCRIPTOR AsyncDesc = &s_AsyncDesc[channel];
	AsyncDesc->Type = asyncType;
	AsyncDesc->Part = 0;
	AsyncDesc->BufferRead = pRead;
	AsyncDesc->BufferWrite = pWrite;
	AsyncDesc->Length = length;
	AsyncDesc->PartLength = (partLength == 0 ? length : partLength);
	if (asyncType == EXI_ASYNC_DMA) AsyncDesc->SwapMode = swap;
	AsyncDesc->TransferType = type;
	AsyncDesc->Callback.Async = callback;
	AsyncDesc->Context = context;
	
	// Start the first async transfer.
	enum {
		EXI_BUFFER_INCREMENT = sizeof(ExiRegisters->Channel[0].Data)
	};
	ULONG thisLength = AsyncDesc->PartLength;
	if (thisLength > EXI_BUFFER_INCREMENT)
		thisLength = EXI_BUFFER_INCREMENT;
	
	ULONG thisData = 0;
	if (asyncType != EXI_ASYNC_IMMOUTBUF) {
		if (type != EXI_TRANSFER_READ) {
			for (ULONG i = 0; i < thisLength; i++) {
				thisData |= pRead[i] << ((thisLength - i - 1) * 8);
			}
		}
	} else {
		thisData = (ULONG)bufferRead;
	}
	
	ExipAsyncTransferImmediateStart(channel, thisData, thisLength, type);
}

#if FORCE_ASYNC // Use the slow async implementations even for small immediate (8-32 bits at a time) SPI transfers.
NTSTATUS HalExiTransferImmediateAsync(ULONG channel, ULONG data, ULONG length, EXI_TRANSFER_TYPE type, HAL_EXI_IMMASYNC_CALLBACK callback, PVOID context) {
	if (callback == NULL) return STATUS_INVALID_PARAMETER_5;
	if (channel >= EXI_CHANNEL_COUNT) return STATUS_INVALID_PARAMETER_1;
	if (length > sizeof(ExiRegisters->Channel[0].Data)) return STATUS_INVALID_PARAMETER_3;

	// Channel must be locked.
	if (!HalExiLocked(channel)) return STATUS_INVALID_PARAMETER_1;
	
	// Ensure a device is selected.
	if (!ExipDeviceSelected(channel)) return STATUS_INVALID_DEVICE_STATE;
	
	// Initialise the async descriptor.
	PEXI_ASYNC_DESCRIPTOR AsyncDesc = &s_AsyncDesc[channel];
	AsyncDesc->Type = EXI_ASYNC_IMM;
	AsyncDesc->TransferType = type;
	AsyncDesc->Part = 0;
	AsyncDesc->BufferRead = NULL;
	AsyncDesc->BufferWrite = NULL;
	AsyncDesc->Length = length;
	AsyncDesc->Callback.ImmAsync = callback;
	AsyncDesc->Context = context;
	
	ExipAsyncTransferImmediateStart(channel, data, length, type);
	return STATUS_PENDING;
}

NTSTATUS HalExiTransferImmediateBufferAsync(ULONG channel, PVOID bufferRead, PVOID bufferWrite, ULONG length, EXI_TRANSFER_TYPE type, HAL_EXI_ASYNC_CALLBACK callback, PVOID context) {
	PUCHAR pRead = (PUCHAR)bufferRead;
	PUCHAR pWrite = (PUCHAR)bufferWrite;

	if (channel >= EXI_CHANNEL_COUNT) return STATUS_INVALID_PARAMETER_1;
	if (type != EXI_TRANSFER_READ && pRead == NULL) return STATUS_INVALID_PARAMETER_2;
	if (type != EXI_TRANSFER_WRITE && pWrite == NULL) return STATUS_INVALID_PARAMETER_3;

	// Channel must be locked.
	if (!HalExiLocked(channel)) return STATUS_INVALID_PARAMETER_1;
	
	// Ensure a device is selected.
	if (!ExipDeviceSelected(channel)) return STATUS_INVALID_DEVICE_STATE;
	
	ExipTransferImmediateBufferAsync(channel, bufferRead, bufferWrite, length, type, callback, context, EXI_ASYNC_IMMBUF, 0, EXI_SWAP_NONE);
	return STATUS_PENDING;
}

NTSTATUS HalExiReadWriteImmediateOutBufferAsync(ULONG channel, UCHAR byteRead, PVOID buffer, ULONG length, HAL_EXI_ASYNC_CALLBACK callback, PVOID context) {
	PUCHAR pWrite = (PUCHAR)buffer;

	if (channel >= EXI_CHANNEL_COUNT) return STATUS_INVALID_PARAMETER_1;
	if (pWrite == NULL) return STATUS_INVALID_PARAMETER_3;

	// Channel must be locked.
	if (!HalExiLocked(channel)) return STATUS_INVALID_PARAMETER_1;
	
	// Ensure a device is selected.
	if (!ExipDeviceSelected(channel)) return STATUS_INVALID_DEVICE_STATE;
	
	ULONG wordRead = (ULONG)byteRead * 0x01010101;
	
	ExipTransferImmediateBufferAsync(channel, (PVOID)wordRead, buffer, length, EXI_TRANSFER_READWRITE, callback, context, EXI_ASYNC_IMMOUTBUF, 0, EXI_SWAP_NONE);
	return STATUS_PENDING;
}
#else // Use faster synchronous implementations for small transfers even if caller wants them async.

static void ExipSyncToAsyncCallbackImm(ULONG channel, ULONG data, HAL_EXI_IMMASYNC_CALLBACK callback, PVOID context) {
	PEXI_ASYNC_DESCRIPTOR AsyncDesc = &s_AsyncDesc[channel];
	
	if (AsyncDesc->Type == EXI_ASYNC_NONE) {
		// first callback
		AsyncDesc->Type = EXI_ASYNC_FROMSYNC;
		AsyncDesc->Part = 0;
		ULONG CurrentPart = 0;
		// Call the initial callback.
		callback(channel, data, context);
		// Make sure it didn't start an async DMA.
		if (AsyncDesc->Type != EXI_ASYNC_FROMSYNC) return;
		while (CurrentPart != AsyncDesc->Part) {
			CurrentPart = AsyncDesc->Part;
			AsyncDesc->Callback.ImmAsync(channel, AsyncDesc->PartLength, AsyncDesc->Context);
			// Make sure it didn't start an async DMA.
			if (AsyncDesc->Type != EXI_ASYNC_FROMSYNC) return;
		}
		// Finished.
		AsyncDesc->Type = EXI_ASYNC_NONE;
	} else if (AsyncDesc->Type == EXI_ASYNC_FROMSYNC) {
		// inside a previous callback.
		// save off the data, and use it later.
		AsyncDesc->Part++;
		AsyncDesc->Callback.ImmAsync = callback;
		AsyncDesc->Context = context;
		AsyncDesc->PartLength = data;
	} else {
		// shouldn't happen, just call the callback
		callback(channel, data, context);
	}
}

static void ExipSyncToAsyncCallback(ULONG channel, HAL_EXI_ASYNC_CALLBACK callback, PVOID context) {
	PEXI_ASYNC_DESCRIPTOR AsyncDesc = &s_AsyncDesc[channel];
	
	if (AsyncDesc->Type == EXI_ASYNC_NONE) {
		// first callback
		AsyncDesc->Type = EXI_ASYNC_FROMSYNC;
		AsyncDesc->Part = 0;
		ULONG CurrentPart = 0;
		// Call the initial callback.
		callback(channel, context);
		// Make sure it didn't start an async DMA.
		if (AsyncDesc->Type != EXI_ASYNC_FROMSYNC) return;
		while (CurrentPart != AsyncDesc->Part) {
			CurrentPart = AsyncDesc->Part;
			AsyncDesc->Callback.Async(channel, AsyncDesc->Context);
			// Make sure it didn't start an async DMA.
			if (AsyncDesc->Type != EXI_ASYNC_FROMSYNC) return;
		}
		// Finished.
		AsyncDesc->Type = EXI_ASYNC_NONE;
	} else if (AsyncDesc->Type == EXI_ASYNC_FROMSYNC) {
		// inside a previous callback.
		AsyncDesc->Part++;
		AsyncDesc->Callback.Async = callback;
		AsyncDesc->Context = context;
	} else {
		// shouldn't happen, just call the callback
		callback(channel, context);
	}
}

NTSTATUS HalExiTransferImmediateAsync(ULONG channel, ULONG data, ULONG length, EXI_TRANSFER_TYPE type, HAL_EXI_IMMASYNC_CALLBACK callback, PVOID context) {
	ULONG dataRead = 0;
	NTSTATUS Status = HalExiTransferImmediate(channel, data, length, type, &dataRead);
	if (NT_SUCCESS(Status)) ExipSyncToAsyncCallbackImm(channel, data, callback, context);
	return Status;
}

NTSTATUS HalExiTransferImmediateBufferAsync(ULONG channel, PVOID bufferRead, PVOID bufferWrite, ULONG length, EXI_TRANSFER_TYPE type, HAL_EXI_ASYNC_CALLBACK callback, PVOID context) {
	NTSTATUS Status = HalExiTransferImmediateBuffer(channel, bufferRead, bufferWrite, length, type);
	if (NT_SUCCESS(Status)) ExipSyncToAsyncCallback(channel, callback, context);
	return Status;
}

NTSTATUS HalExiReadWriteImmediateOutBufferAsync(ULONG channel, UCHAR byteRead, PVOID buffer, ULONG length, HAL_EXI_ASYNC_CALLBACK callback, PVOID context) {
	NTSTATUS Status = HalExiReadWriteImmediateOutBuffer(channel, byteRead, buffer, length);
	if (NT_SUCCESS(Status)) ExipSyncToAsyncCallback(channel, callback, context);
	return Status;
}
#endif

static void ExipTransferDmaAsync(ULONG channel, PVOID buffer, ULONG totalLength, EXI_TRANSFER_TYPE type, EXI_SWAP_MODE swap, HAL_EXI_ASYNC_CALLBACK callback, ULONG length) {
	PEXI_ASYNC_DESCRIPTOR AsyncDesc = &s_AsyncDesc[channel];
	AsyncDesc->PartLength = length;
	AsyncDesc->Part = 1;
	AsyncDesc->SwapMode = swap;
	AsyncDesc->TransferType = type;
	
	ULONG MapOffset = PAGE_SIZE * channel;
	PUCHAR MapBuffer = &s_DmaMapBuffer[MapOffset];
	
	// For a DMA write, copy the buffer contents into the map buffer, swapping if necessary, then flush dcache.
	if (type == EXI_TRANSFER_WRITE) {
		if ((swap & EXI_SWAP_INPUT) != 0) {
			if (((ULONG)buffer & 7) != 0) {
				RtlCopyMemory(MapBuffer, buffer, length);
				ExipEndianSwap64(MapBuffer, MapBuffer, length);
			}
			else ExipEndianSwap64(MapBuffer, buffer, length);
		} else {
			RtlCopyMemory(MapBuffer, buffer, length);
		}
		HalSweepDcacheRange(MapBuffer, length);
	}
	
	// Set DMA pointer and length.
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].DmaAddress), s_DmaMapBufferPhys + MapOffset);
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].DmaLength), length);
	
	
	ExipEnableTransferCompleteInterrupt(channel, TRUE);

	// Start the asynchronous transfer.
	EXI_CHANNEL_TRANSFER_REGISTER Ctr;
	Ctr.Value = 0;
	Ctr.Start = 1;
	Ctr.EnableDma = 1;
	Ctr.Type = type;
	Ctr.Length = 0;
	//DbgPrint("d");
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Transfer), Ctr.Value);
}

static void ExipTransferDmaStartAsync(ULONG channel, PVOID buffer, ULONG totalLength, EXI_TRANSFER_TYPE type, EXI_SWAP_MODE swap, HAL_EXI_ASYNC_CALLBACK callback, PVOID context, ULONG length) {
	
	
	PEXI_ASYNC_DESCRIPTOR AsyncDesc = &s_AsyncDesc[channel];
	AsyncDesc->Type = EXI_ASYNC_DMA;
	AsyncDesc->BufferRead = buffer;
	AsyncDesc->BufferWrite = buffer;
	AsyncDesc->Length = totalLength;
	AsyncDesc->Callback.Async = callback;
	AsyncDesc->Context = context;
	
	ExipTransferDmaAsync(channel, buffer, totalLength, type, swap, callback, length);
}

static void ExipTransferDmaAsyncNext(PEXI_ASYNC_WORK_ITEM Parameter) {
	ULONG channel = Parameter->Channel;
	PEXI_ASYNC_DESCRIPTOR AsyncDesc = &s_AsyncDesc[channel];
	
	ULONG Length = AsyncDesc->Length - AsyncDesc->PartLength;
	PUCHAR Pointer = AsyncDesc->BufferWrite;
	
	// If here, then at least one transfer has already been completed...
	
	ULONG MapOffset = PAGE_SIZE * channel;
	PUCHAR MapBuffer = &s_DmaMapBuffer[MapOffset];
	
	if (AsyncDesc->Part == 1) {
		// Last transfer was a DMA transfer.
		// If the buffer got written to by DMA, invalidate data cache for the map buffer, then copy back to the original buffer, swapping if necessary.
		if (AsyncDesc->TransferType == EXI_TRANSFER_READ) {
			HalpInvalidateDcacheRange(MapBuffer, AsyncDesc->PartLength);
			if (AsyncDesc->SwapMode != EXI_SWAP_NONE) {
				if (((ULONG)Pointer & 7) != 0) {
					ExipEndianSwap64(MapBuffer, MapBuffer, AsyncDesc->PartLength);
					RtlCopyMemory(Pointer, MapBuffer, AsyncDesc->PartLength);
				}
				else ExipEndianSwap64(Pointer, MapBuffer, AsyncDesc->PartLength);
			} else {
				RtlCopyMemory(Pointer, MapBuffer, AsyncDesc->PartLength);
			}
		}
		AsyncDesc->BufferRead += AsyncDesc->PartLength;
		AsyncDesc->BufferWrite += AsyncDesc->PartLength;
		AsyncDesc->Length = Length;
		Pointer += AsyncDesc->PartLength;
	} else {
		// Last transfer was an immbuf transfer.
		enum {
			EXI_BUFFER_INCREMENT = sizeof(ExiRegisters->Channel[0].Data)
		};
		
		ULONG thisLength = AsyncDesc->PartLength;
		if (thisLength > EXI_BUFFER_INCREMENT)
			thisLength = EXI_BUFFER_INCREMENT;
		
		// Write out the data to the buffer if needed.
		if (AsyncDesc->TransferType == EXI_TRANSFER_READ) {
			ULONG data = 0;
			data = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Data));
			data >>= (4 - thisLength) * 8;
			
			for (ULONG i = 0; i < thisLength; i++) {
				Pointer[i] = (UCHAR)(data >> ((thisLength - i - 1) * 8));
			}
		}
		
		AsyncDesc->BufferRead += thisLength;
		AsyncDesc->BufferWrite += thisLength;
		AsyncDesc->PartLength -= thisLength;
		AsyncDesc->Length -= thisLength;
		Pointer += thisLength;
		Length = AsyncDesc->Length;
		
		if (AsyncDesc->PartLength != 0) {
			// Additional transfer required.
			thisLength = AsyncDesc->PartLength;
			if (thisLength > EXI_BUFFER_INCREMENT)
				thisLength = EXI_BUFFER_INCREMENT;
			
			ULONG thisData = 0;
			if (AsyncDesc->TransferType != EXI_TRANSFER_READ) {
				for (ULONG i = 0; i < thisLength; i++) {
					thisData |= AsyncDesc->BufferRead[i] << ((thisLength - i - 1) * 8);
				}
			}
			
			ExipAsyncTransferImmediateStart(channel, thisData, thisLength, AsyncDesc->TransferType);
			return;
		}
	}
	
	do {
		KeStallExecutionProcessor(1000);
		if (Length == 0) break;
	
		if (Length < 0x20) {
			// Remaining length is less than a DMA transfer.
			// Turn this into an immediate buffer transfer.
			ExipTransferImmediateBufferAsync(channel, Pointer, Pointer, Length, AsyncDesc->TransferType, AsyncDesc->Callback.Async, AsyncDesc->Context, EXI_ASYNC_DMA, 0, AsyncDesc->SwapMode);
			return;
		}
		
		ULONG AlignedLength = Length & ~(0x20 - 1);
		
		// Do DMA up until the next page boundary.
		ULONG DmaMisalignedLength = (-((ULONG)Pointer)) & (PAGE_SIZE - 1);
		if (AlignedLength < DmaMisalignedLength) {
			// Less than a page needed to DMA, in total.
			ExipTransferDmaAsync(channel, Pointer, Length, AsyncDesc->TransferType, AsyncDesc->SwapMode, AsyncDesc->Callback.Async, AlignedLength);
			return;
		} else {
			if ((AlignedLength - DmaMisalignedLength) != 0 && (AlignedLength - DmaMisalignedLength) < PAGE_SIZE) {
				// Less than a page needed to DMA.
				ExipTransferDmaAsync(channel, Pointer, Length, AsyncDesc->TransferType, AsyncDesc->SwapMode, AsyncDesc->Callback.Async, AlignedLength);
				return;
			}
		}
		
		// DMA whole pages until that's no longer possible.
		if (AlignedLength >= PAGE_SIZE) {
			ExipTransferDmaAsync(channel, Pointer, Length, AsyncDesc->TransferType, AsyncDesc->SwapMode, AsyncDesc->Callback.Async, PAGE_SIZE);
			return;
		}
		
		if (AlignedLength != 0) {
			// DMA the final chunk that can be DMA'd.
			ExipTransferDmaAsync(channel, Pointer, Length, AsyncDesc->TransferType, AsyncDesc->SwapMode, AsyncDesc->Callback.Async, AlignedLength);
			return;
		}
		
		if (Length != 0) {
			// Final misaligned transfer.
			ExipTransferImmediateBufferAsync(channel, Pointer, Pointer, Length, AsyncDesc->TransferType, AsyncDesc->Callback.Async, AsyncDesc->Context, EXI_ASYNC_DMA, 0, AsyncDesc->SwapMode);
			return;
		}
	} while (FALSE);
	
	
	// Transfer complete.
	HAL_EXI_ASYNC_CALLBACK Callback = AsyncDesc->Callback.Async;
	PVOID context = AsyncDesc->Context;
	AsyncDesc->Type = EXI_ASYNC_NONE;
	EXI_LOCK_ACTION action = Callback(channel, context);
	
	if (action == ExiUnlock) HalExiUnlockNonpaged(channel);
}

NTSTATUS HalExiTransferDmaAsync(ULONG channel, PVOID buffer, ULONG length, EXI_TRANSFER_TYPE type, EXI_SWAP_MODE swap, HAL_EXI_ASYNC_CALLBACK callback, PVOID context) {
	if (channel >= EXI_CHANNEL_COUNT) return STATUS_INVALID_PARAMETER_1;
	// EXI DMA does not support read+write
	if (type == EXI_TRANSFER_READWRITE) return STATUS_INVALID_PARAMETER_4;
	
	// Channel must be locked.
	if (!HalExiLocked(channel)) return STATUS_INVALID_PARAMETER_1;
	
	// Ensure a device is selected.
	if (!ExipDeviceSelected(channel)) return STATUS_INVALID_DEVICE_STATE;
	
	ULONG DmaMisalignedLength = (-((ULONG)buffer)) & (0x20 - 1);
	
	if ((length - DmaMisalignedLength) < 0x20) {
		// Tried to DMA less than 32 bytes, just use immediate transfer.
		return HalExiTransferImmediateBufferAsync(channel, buffer, buffer, length, type, callback, context);
	}
	
	PUCHAR Pointer = (PUCHAR)buffer;
	
	if (DmaMisalignedLength != 0) {
		// Use an immediate transfer for the misaligned part of the buffer.
		ExipTransferImmediateBufferAsync(channel, Pointer, Pointer, length, type, callback, context, EXI_ASYNC_DMA, DmaMisalignedLength, swap);
		return STATUS_PENDING;
	}
	
	ULONG AlignedLength = length & ~(0x20 - 1);
	
	// Do DMA up until the next page boundary.
	DmaMisalignedLength = (-((ULONG)Pointer)) & (PAGE_SIZE - 1);
	if (AlignedLength < DmaMisalignedLength) {
		// Less than a page needed to DMA, in total.
		ExipTransferDmaStartAsync(channel, Pointer, length, type, swap, callback, context, AlignedLength);
		return STATUS_PENDING;
	} else {
		if ((AlignedLength - DmaMisalignedLength) != 0 && (AlignedLength - DmaMisalignedLength) < PAGE_SIZE) {
			// Less than a page needed to DMA.
			ExipTransferDmaStartAsync(channel, Pointer, length, type, swap, callback, context, AlignedLength);
			return STATUS_PENDING;
		}
	}
	
	// DMA whole pages until that's no longer possible.
	if (AlignedLength >= PAGE_SIZE) {
		ExipTransferDmaStartAsync(channel, Pointer, length, type, swap, callback, context, PAGE_SIZE);
		return STATUS_PENDING;
	}
	
	if (AlignedLength != 0) {
		// DMA the final chunk that can be DMA'd.
		ExipTransferDmaStartAsync(channel, Pointer, length, type, swap, callback, context, AlignedLength);
		return STATUS_PENDING;
	}
	
	if (length != 0) {
		// Final misaligned transfer.
		return HalExiTransferImmediateBufferAsync(channel, Pointer, Pointer, length, type, callback, context);
	}
	
	// If we got here, then there was nothing to transfer.
	return STATUS_INVALID_PARAMETER;
}

static void ExipImmBufTransferComplete(PEXI_ASYNC_WORK_ITEM Parameter) {
	ULONG channel = Parameter->Channel;
	
	EXI_LOCK_ACTION action = ExiKeepLocked;
	
	PEXI_ASYNC_DESCRIPTOR AsyncDesc = &s_AsyncDesc[channel];
	
	enum {
		EXI_BUFFER_INCREMENT = sizeof(ExiRegisters->Channel[0].Data)
	};
	
	ULONG thisLength = AsyncDesc->PartLength;
	if (thisLength > EXI_BUFFER_INCREMENT)
		thisLength = EXI_BUFFER_INCREMENT;
	
	if (AsyncDesc->TransferType != EXI_TRANSFER_WRITE) {
		ULONG data = 0;
		data = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Data));
		data >>= (4 - thisLength) * 8;
		
		for (ULONG i = 0; i < thisLength; i++) {
			AsyncDesc->BufferWrite[i] = (UCHAR)(data >> ((thisLength - i - 1) * 8));
		}
	}
	
	if (AsyncDesc->Type != EXI_ASYNC_IMMOUTBUF) AsyncDesc->BufferRead += thisLength;
	AsyncDesc->BufferWrite += thisLength;
	AsyncDesc->Length -= thisLength;
	AsyncDesc->PartLength -= thisLength;
	
	if (AsyncDesc->PartLength != 0) {
		// Additional transfer required.
		thisLength = AsyncDesc->PartLength;
		if (thisLength > EXI_BUFFER_INCREMENT)
			thisLength = EXI_BUFFER_INCREMENT;
		
		ULONG thisData = 0;
		if (AsyncDesc->Type != EXI_ASYNC_IMMOUTBUF) {
			if (AsyncDesc->TransferType != EXI_TRANSFER_READ) {
				for (ULONG i = 0; i < thisLength; i++) {
					thisData |= AsyncDesc->BufferRead[i] << ((thisLength - i - 1) * 8);
				}
			}
		} else {
			thisData = (ULONG)AsyncDesc->BufferRead;
		}
		
		ExipAsyncTransferImmediateStart(channel, thisData, thisLength, AsyncDesc->TransferType);
		return;
	}
	
	// Transfer completed.
	HAL_EXI_ASYNC_CALLBACK Callback = AsyncDesc->Callback.Async;
	PVOID context = AsyncDesc->Context;
	AsyncDesc->Type = EXI_ASYNC_NONE;
	action = Callback(channel, context);
	
	if (action == ExiUnlock) HalExiUnlockNonpaged(channel);
}

static void ExipImmTransferComplete(PEXI_ASYNC_WORK_ITEM Parameter) {
	ULONG channel = Parameter->Channel;
	
	EXI_LOCK_ACTION action = ExiKeepLocked;
	
	PEXI_ASYNC_DESCRIPTOR AsyncDesc = &s_AsyncDesc[channel];
	
	ULONG data = 0;
		
	if (AsyncDesc->TransferType != EXI_TRANSFER_WRITE) {
		data = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Data));
		data >>= (4 - AsyncDesc->Length) * 8;
	}
		
	// Clear the async descriptor type so it can be reused
	HAL_EXI_IMMASYNC_CALLBACK Callback = AsyncDesc->Callback.ImmAsync;
	PVOID context = AsyncDesc->Context;
	AsyncDesc->Type = EXI_ASYNC_NONE;
	action = Callback(channel, data, context);
	
	if (action == ExiUnlock) HalExiUnlockNonpaged(channel);
}

static void ExipDpcTransferComplete(PKDPC Dpc, PVOID Unused, PVOID ChannelArg, PVOID Unused2) {
	ULONG channel = (ULONG)ChannelArg;
	//DbgPrint("%d\n", channel + EXI_CHANNEL_COUNT);
	
	PEXI_ASYNC_DESCRIPTOR AsyncDesc = &s_AsyncDesc[channel];
	PWORKER_THREAD_ROUTINE WorkerRoutine = NULL;
	AsyncDesc->WorkItem.Channel = channel;
	if (AsyncDesc->Type == EXI_ASYNC_IMM) {
		// Single immediate transfer is complete.
		//WorkerRoutine = (PWORKER_THREAD_ROUTINE)ExipImmTransferComplete;
		ExipImmTransferComplete(&AsyncDesc->WorkItem);
		return;
	} else if (AsyncDesc->Type == EXI_ASYNC_IMMBUF || AsyncDesc->Type == EXI_ASYNC_IMMOUTBUF) {
		// Part of buffer immediate transfer is complete.
		//WorkerRoutine = (PWORKER_THREAD_ROUTINE)ExipImmBufTransferComplete;
		ExipImmBufTransferComplete(&AsyncDesc->WorkItem);
		return;
	} else if (AsyncDesc->Type == EXI_ASYNC_DMA) {
		// Part of DMA transfer is complete.
		//WorkerRoutine = (PWORKER_THREAD_ROUTINE)ExipTransferDmaAsyncNext;
		ExipTransferDmaAsyncNext(&AsyncDesc->WorkItem);
		return;
	} else {
		// ???
		AsyncDesc->Type = EXI_ASYNC_NONE;
		return;
	}
	
	ExInitializeWorkItem(
		&AsyncDesc->WorkItem.WorkItem,
		WorkerRoutine,
		&AsyncDesc->WorkItem
	);
	
	// Queue it
	ExQueueWorkItem(&AsyncDesc->WorkItem.WorkItem, CriticalWorkQueue);
}

static EXI_LOCK_ACTION ExipDpcDeviceInterruptLockHandler(ULONG channel, PVOID context) {
	EXI_INTERRUPT_ACTION action = s_InterruptCallbacks[channel](channel, TRUE, FALSE);
	
	if (action == ExiInterruptDisable) return ExiUnlock;
	
	// Unmask and acknowledge interrupt. We assume callback acked interrupt on device side if it requested int re-enable.
	EXI_CHANNEL_PARAMETER_REGISTER Cpr;
	Cpr.Value = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter));
	Cpr.DeviceInterruptStatus = Cpr.UnplugInterruptStatus = Cpr.TransferInterruptStatus = 0;
	Cpr.DeviceInterruptStatus = 1;
	Cpr.DeviceInterruptMask = 1;
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter), Cpr.Value);
	
	return ExiUnlock;
}

static void ExipDpcDeviceInterrupt(PKDPC Dpc, PVOID Unused, PVOID ChannelArg, PVOID Unused2) {
	ULONG channel = (ULONG)ChannelArg;
	
	EXI_INTERRUPT_ACTION action = ExiInterruptDisable;
	if (s_InterruptCallbacks[channel] != NULL) {
		if (!HalExiLocked(channel)) {
			if (!NT_SUCCESS(HalExiLock(channel, ExipDpcDeviceInterruptLockHandler, NULL))) {
				EXI_INTERRUPT_ACTION unlockedAction = s_InterruptCallbacks[channel](channel, FALSE, FALSE);
				if (unlockedAction != ExiInterruptDisable) {
					// TODO: something? probably needs at last debug log, at worst bugcheck.
					// for now, do nothing.
				}
			}
			return;
		}
		action = s_InterruptCallbacks[channel](channel, TRUE, TRUE);
	}
	
	if (action == ExiInterruptDisable) return;
	
	// Unmask and acknowledge interrupt. We assume callback acked interrupt on device side if it requested int re-enable.
	EXI_CHANNEL_PARAMETER_REGISTER Cpr;
	Cpr.Value = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter));
	Cpr.DeviceInterruptStatus = Cpr.UnplugInterruptStatus = Cpr.TransferInterruptStatus = 0;
	Cpr.DeviceInterruptStatus = 1;
	Cpr.DeviceInterruptMask = 1;
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter), Cpr.Value);
}

static NTSTATUS ExipGetDeviceIdentifierAttempt(ULONG channel, ULONG device, PULONG deviceIdentifier) {
	enum {
		EXI_CMD_DEVICE_ID = 0
	};

	NTSTATUS Status = HalExiSelectDevice(channel, device, EXI_CLOCK_0_8, FALSE);
	if (!NT_SUCCESS(Status)) return Status;
	Status = ExipTransferImmediate(channel, EXI_CMD_DEVICE_ID, 2, EXI_TRANSFER_WRITE, NULL);
	if (!NT_SUCCESS(Status)) return Status;
	Status = ExipTransferImmediate(channel, 0, sizeof(*deviceIdentifier), EXI_TRANSFER_READ, deviceIdentifier);
	if (!NT_SUCCESS(Status)) return Status;
	Status = HalExiUnselectDevice(channel);
	return Status;
}

NTSTATUS HalExiGetDeviceIdentifier(ULONG channel, ULONG device, PULONG deviceIdentifier) {
	if (deviceIdentifier == NULL) return STATUS_INVALID_PARAMETER_3;
	if (channel >= EXI_CHANNEL_COUNT) return STATUS_INVALID_PARAMETER_1;

	// If this device is a mounted SD card, don't touch it.
	ULONG ExiDevices = (ULONG)RUNTIME_BLOCK[RUNTIME_EXI_DEVICES];
	ULONG drive;
	if (channel == 0) {
		if (device == 0) drive = 0;
		if (device == 2) drive = 2;
	}
	else {
		if (channel == 1) drive = 1;
		if (channel == 2) drive = 3;
	}
	if ((ExiDevices & (BIT(drive) | BIT(drive + 4))) == BIT(drive)) {
		*deviceIdentifier = 0xFFFFFFFF;
		return STATUS_SUCCESS;
	}

	ULONG thisId = 0xFFFFFFFF;
	// Try several times and make sure the same identifier is obtained twice in a row.
	// Give up after many tries and return the last obtained identifier.
	for (ULONG attempt = 0; attempt < 4; attempt++) {
		NTSTATUS Status = ExipGetDeviceIdentifierAttempt(channel, device, deviceIdentifier);
		if (!NT_SUCCESS(Status)) return Status;
		if (thisId == *deviceIdentifier) break;
		thisId = *deviceIdentifier;
	}

	return STATUS_SUCCESS;
}

NTSTATUS HalExiToggleInterrupt(ULONG channel, HAL_EXI_INTERRUPT_CALLBACK callback) {
	if (channel >= EXI_CHANNEL_COUNT) return STATUS_INVALID_PARAMETER_1;
	// Channel must be locked.
	if (!HalExiLocked(channel)) return STATUS_INVALID_PARAMETER_1;
	
	s_InterruptCallbacks[channel] = callback;
	// Mask or unmask and acknowledge interrupt.
	EXI_CHANNEL_PARAMETER_REGISTER Cpr;
	Cpr.Value = MmioReadBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter));
	Cpr.DeviceInterruptStatus = Cpr.UnplugInterruptStatus = Cpr.TransferInterruptStatus = 0;
	Cpr.DeviceInterruptStatus = 1;
	Cpr.DeviceInterruptMask = callback != NULL;
	MmioWriteBase32(MMIO_OFFSET(ExiRegisters, Channel[channel].Parameter), Cpr.Value);
	return STATUS_SUCCESS;
}

BOOLEAN HalExiInit(void) {
	if (HalpExiRegs == NULL) return FALSE; // should have been mapped very early in boot, wtf?
	
	PHYSICAL_ADDRESS HighestAddress = {0};
	HighestAddress.LowPart = HighestAddress.HighPart = 0xFFFFFFFFul;
	
	s_DmaMapBuffer = MmAllocateContiguousMemory(PAGE_SIZE * EXI_CHANNEL_COUNT, HighestAddress);
	if (s_DmaMapBuffer == NULL) return FALSE;
	
	PHYSICAL_ADDRESS MapPhys = MmGetPhysicalAddress(s_DmaMapBuffer);
	if (MapPhys.LowPart == 0) {
		MmFreeContiguousMemory(s_DmaMapBuffer);
		s_DmaMapBuffer = NULL;
		return FALSE;
	}
	
	s_DmaMapBufferPhys = MapPhys.LowPart;
	
	HalExiLockInit();
	
	// Initialise the DPCs.
	for (ULONG i = 0; i < EXI_CHANNEL_COUNT * 0x10; i++) {
		KeInitializeDpc(&s_DpcTransferComplete[i], ExipDpcTransferComplete, NULL);
	}
	for (ULONG i = 0; i < EXI_CHANNEL_COUNT; i++) {
		KeInitializeDpc(&s_DpcDevice[i], ExipDpcDeviceInterrupt, NULL);
	}
	
	// Register the interrupt vector.
	if (!HalpEnableDeviceInterruptHandler(&s_ExiInterrupt,
		(PKSERVICE_ROUTINE) HalpExiInterrupt,
		NULL,
		NULL,
		VECTOR_EXI,
		Latched,
		FALSE,
		0,
		FALSE,
		InternalUsage
	)) {
		MmFreeContiguousMemory(s_DmaMapBuffer);
		s_DmaMapBuffer = NULL;
		return FALSE;
	}
	
	return TRUE;
}
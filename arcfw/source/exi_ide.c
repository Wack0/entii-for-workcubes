// IDE over SPI (EXI) driver
#include <stdio.h>
#include <memory.h>
#include "arc.h"
#include "types.h"
#include "runtime.h"
#include "exi.h"
#include "exi_ide.h"
#include "exi_sdmc.h"
#include "timer.h"

enum {
	IDE_DRIVE_COUNT = 4,
	IDE_SECTOR_SIZE = 0x200
};

// IDE registers.
enum {
	IDE_REG_DATA = 0x10,
	IDE_REG_ERROR,
	IDE_REG_SECTOR_COUNT,
	IDE_REG_START_SECTOR,
	IDE_REG_CYLINDER_LOW,
	IDE_REG_CYLINDER_HIGH,
	IDE_REG_DEVICE_SELECT,
	IDE_REG_STATUS,

	IDE_REG_ALTERNATE_STATUS = 0x08 | 6,
	IDE_REG_DRIVE_ADDRESS,

	// Write-only registers
	IDE_REG_FEATURES = IDE_REG_ERROR,
	IDE_REG_COMMAND = IDE_REG_STATUS,
	IDE_REG_DEVICE_CONTROL = IDE_REG_ALTERNATE_STATUS,

	// Alternate names
	IDE_REG_LBA0 = IDE_REG_START_SECTOR,
	IDE_REG_LBA1 = IDE_REG_CYLINDER_LOW,
	IDE_REG_LBA2 = IDE_REG_CYLINDER_HIGH,
	
	// Upper command bits.
	IDE_CMD_MULTI_TRANSFER = ARC_BIT(5),
	IDE_CMD_WORD_TRANSFER = ARC_BIT(6),
	IDE_CMD_WRITE = ARC_BIT(7),
};

enum {
	IDE_EXI_LEN_READ8 = 2,
	IDE_EXI_LEN_WRITE8 = 3,
	IDE_EXI_LEN_READ16 = 2,
	IDE_EXI_LEN_WRITE16 = 4,
	IDE_EXI_LEN_READMULTI32 = 4,
	IDE_EXI_LEN_WRITEMULTI32 = 3
};

enum {
	IDE_MULTI32_MAX_LENGTH = 0x3FFFC
};

// ATA command set.
enum {
	ATA_CMD_IDENTIFY = 0xEC,
	ATA_CMD_READ_SECTOR = 0x21,
	ATA_CMD_READ_SECTOR_EXT = 0x24,
	ATA_CMD_READ_MULTIPLE_EXT = 0x29,
	ATA_CMD_WRITE_SECTOR = 0x30,
	ATA_CMD_WRITE_SECTOR_EXT = 0x34,
	ATA_CMD_WRITE_MULTIPLE_EXT = 0x39,
	ATA_CMD_READ_MULTIPLE = 0xC4,
	ATA_CMD_WRITE_MULTIPLE = 0xC5,
	ATA_CMD_SET_MULTIPLE_MODE = 0xC6,
	ATA_CMD_UNLOCK = 0xF2,
	ATA_CMD_SECURITY_DISABLE = 0xF6,
};

// ATA IDENTIFY 16-bit offsets.
enum {
	ATA_IDENTIFY_CYLINDERS = 1,
	ATA_IDENTIFY_HEADS = 3,
	ATA_IDENTIFY_SECTORS = 6,
	ATA_IDENTIFY_SERIAL = 10,
	ATA_IDENTIFY_MODEL = 27,
	ATA_IDENTIFY_MULTIPLE = 47,
	ATA_IDENTIFY_CAPABILITY = 49,
	ATA_IDENTIFY_LBASECTORS = 60,
	ATA_IDENTIFY_COMMANDSET = 83,
	ATA_IDENTIFY_LBA48SECTORS = 100,

	ATA_IDENTIFY_LBA48MASK = ARC_BIT(10), // Mask for LBA support in COMMANDSET
	ATA_IDENTIFY_LBA28MASK = ARC_BIT(9), // Mask for LBA support in CAPABILITY
};

// Status register bits
enum {
	SR_ERR = ARC_BIT(0),
	SR_IDX = ARC_BIT(1),
	SR_CORR = ARC_BIT(2),
	SR_DRQ = ARC_BIT(3),
	SR_DSC = ARC_BIT(4),
	SR_DF = ARC_BIT(5),
	SR_DRDY = ARC_BIT(6),
	SR_BSY = ARC_BIT(7)
};

// Error register bits
enum {
	ER_AMNF = ARC_BIT(0),
	ER_TK0NF = ARC_BIT(1),
	ER_ABRT = ARC_BIT(2),
	ER_MCR = ARC_BIT(3),
	ER_IDNF = ARC_BIT(4),
	ER_MC = ARC_BIT(5),
	ER_UNC = ARC_BIT(6)
};

// Head register bits
enum {
	HEAD_USE_LBA = ARC_BIT(6)
};

// Device control bits
enum {
	DCON_NIEN = ARC_BIT(1),
	DCON_SRST = ARC_BIT(2)
};

enum {
	IDEEXI_ID_V2 = 0x49444532,
	IDEEXI_ID_V3 = 0x49444533
};

typedef enum {
	IDEEXI_UNKNOWN,
	IDEEXI_V1,
	IDEEXI_V2,
	IDEEXI_V3
} IDEEXI_HW_VERSION;

typedef enum {
	CAPABILITY_CHS,
	CAPABILITY_LBA28,
	CAPABILITY_LBA48
} IDE_CAPABILITY;

typedef struct _IDE_STATE {
	uint64_t NumberOfSectors;
	ULONG SizeInMegabytes;
	ULONG SizeInGigabytes;
	ULONG Cylinders, Heads, Sectors;
	ULONG MultipleSectorCount;
	UCHAR HwVersion; // IDEEXI_HW_VERSION
	UCHAR ClockFreq; // EXI_CLOCK_FREQUENCY
	UCHAR Capability; // IDE_CAPABILITY
	bool Initialised;
	char Model[48];
	char Serial[24];
} IDE_STATE, *PIDE_STATE;

// Temporary transfer buffer used for ATA IDENTIFY output.
static UCHAR s_TransferBuffer[IDE_SECTOR_SIZE] ARC_ALIGNED(32);

// IDE state for each EXI device
static IDE_STATE s_IdeState[IDE_DRIVE_COUNT];

static ULONG IdepCreateCommandRead8(UCHAR Register) {
	return (ULONG)Register << 8;
}

static ULONG IdepCreateCommandWrite8(UCHAR Register, UCHAR Value) {
	ULONG Ret = Register | IDE_CMD_WRITE;
	Ret <<= 8;
	Ret |= Value;
	Ret <<= 8;
	return Ret;
}

// there's only one single register that can be read by 16-bit!
static ULONG IdepCreateCommandRead16(void) {
	return (ULONG)(IDE_REG_DATA | IDE_CMD_WORD_TRANSFER) << 8;
}

static ULONG IdepCreateCommandWrite16(USHORT Value) {
	ULONG Ret = (ULONG)IDE_REG_DATA | IDE_CMD_WORD_TRANSFER | IDE_CMD_WRITE;
	Ret <<= 8;
	Ret |= (Value >> 8);
	Ret <<= 8;
	Ret |= (Value & 0xFF);
	Ret <<= 8;
	return Ret;
}

// same for by 32-bit
// expect caller to verify length, maximum length is 0x3FFFC bytes, therefore 511 sectors
static ULONG IdepCreateCommandReadMulti32(ULONG Length) {
	Length /= sizeof(ULONG);
	ULONG Ret = (ULONG)IDE_REG_DATA | IDE_CMD_WORD_TRANSFER | IDE_CMD_MULTI_TRANSFER;
	Ret <<= 8;
	Ret |= (Length & 0xFF);
	Ret <<= 8;
	Ret |= ((Length >> 8) & 0xFF);
	Ret <<= 8;
	return Ret;
}

// expect caller to verify length, maximum length is 0x3FFFC bytes, therefore 511 sectors
static ULONG IdepCreateCommandWriteMulti32(ULONG Length) {
	Length /= sizeof(ULONG);
	ULONG Ret = (ULONG)IDE_REG_DATA | IDE_CMD_WORD_TRANSFER | IDE_CMD_MULTI_TRANSFER | IDE_CMD_WRITE;
	Ret <<= 8;
	Ret |= (Length & 0xFF);
	Ret <<= 8;
	Ret |= ((Length >> 8) & 0xFF);
	return Ret;
}

static UCHAR IdepGetReadByte(ULONG readByte) {
	return (UCHAR)(LoadToRegister32(readByte) & 0xFF);
}

static USHORT IdepGetRead16(ULONG readData) {
	return (USHORT)(LoadToRegister32(readData) & 0xFFFF);
}

static bool IdepReadRegister8(PIDE_STATE State, ULONG Channel, ULONG Device, UCHAR Register, PUCHAR ReadRegister) {
	if (!ExiSelectDevice(Channel, Device, State->ClockFreq, false)) return false;
	bool success = false;
	do {
		ULONG Value;
		if (!ExiTransferImmediate(Channel, IdepCreateCommandRead8(Register), IDE_EXI_LEN_READ8, EXI_TRANSFER_WRITE, NULL)) break;
		if (!ExiTransferImmediate(Channel, 0, 1, EXI_TRANSFER_READ, &Value)) break;
		*ReadRegister = IdepGetReadByte(Value);
		success = true;
	} while (false);
	ExiUnselectDevice(Channel);
	return success;
}

static bool IdepReadStatusReg(PIDE_STATE State, ULONG Channel, ULONG Device, PUCHAR Register) {
	return IdepReadRegister8(State, Channel, Device, IDE_REG_STATUS, Register);
}

static bool IdepReadErrorReg(PIDE_STATE State, ULONG Channel, ULONG Device, PUCHAR Register) {
	return IdepReadRegister8(State, Channel, Device, IDE_REG_ERROR, Register);
}

static bool IdepWriteRegister8(PIDE_STATE State, ULONG Channel, ULONG Device, UCHAR Register, UCHAR Value) {
	if (!ExiSelectDevice(Channel, Device, State->ClockFreq, false)) return false;
	bool success = false;
	do {
		if (!ExiTransferImmediate(Channel, IdepCreateCommandWrite8(Register, Value), IDE_EXI_LEN_WRITE8, EXI_TRANSFER_WRITE, NULL)) break;
		success = true;
	} while (false);
	ExiUnselectDevice(Channel);
	return success;
}

static bool IdepWriteData16(PIDE_STATE State, ULONG Channel, ULONG Device, USHORT Value) {
	if (!ExiSelectDevice(Channel, Device, State->ClockFreq, false)) return false;
	bool success = false;
	do {
		if (!ExiTransferImmediate(Channel, IdepCreateCommandWrite16(Value), IDE_EXI_LEN_WRITE16, EXI_TRANSFER_WRITE, NULL)) break;
		success = true;
	} while (false);
	ExiUnselectDevice(Channel);
	return success;
}

static bool IdepReadData16(PIDE_STATE State, ULONG Channel, ULONG Device, PUSHORT ReadRegister) {
	if (!ExiSelectDevice(Channel, Device, State->ClockFreq, false)) return false;
	bool success = false;
	do {
		ULONG Value;
		if (!ExiTransferImmediate(Channel, IdepCreateCommandRead16(), IDE_EXI_LEN_READ16, EXI_TRANSFER_WRITE, NULL)) break;
		if (!ExiTransferImmediate(Channel, 0, 2, EXI_TRANSFER_READ, &Value)) break;
		*ReadRegister = IdepGetRead16(Value);
		success = true;
	} while (false);
	ExiUnselectDevice(Channel);
	return success;
}

static bool IdepReadBuffer(PIDE_STATE State, ULONG Channel, ULONG Device, PVOID Buffer, ULONG Length) {
	if (Length > IDE_MULTI32_MAX_LENGTH) return false;
	if ((Length & 3) != 0) return false;
	PULONG buf32 = (PULONG)Buffer;

	if (!ExiSelectDevice(Channel, Device, State->ClockFreq, false)) return false;
	bool success = false;
	do {
		ULONG Value;
		if (!ExiTransferImmediate(Channel, IdepCreateCommandReadMulti32(Length), IDE_EXI_LEN_READMULTI32, EXI_TRANSFER_WRITE, NULL)) break;
		if (State->HwVersion == IDEEXI_V1) {
			// Oldest hw version, cannot use dma and must toggle the chip select after every 32 bits transferred.
			if (!ExiRefreshDevice(Channel)) break;
			bool InnerSuccess = true;
			for (ULONG i = 0; i < (Length / sizeof(buf32[0])); i++) {
				if (!ExiTransferImmediate(Channel, 0, sizeof(buf32[0]), EXI_TRANSFER_READ, &buf32[i])) {
					InnerSuccess = false;
					break;
				}
				if (!ExiRefreshDevice(Channel)) {
					InnerSuccess = false;
					break;
				}
			}
			if (!InnerSuccess) break;
			// Read another 32 bits for some reason
			if (!ExiTransferImmediate(Channel, 0, sizeof(Value), EXI_TRANSFER_READ, &Value)) break;
		}
		else {
			// Just dma the data, if possible, otherwise receive via immediate
			if (ExiBufferCanDma(Buffer, Length)) {
				if (!ExiTransferDma(Channel, Buffer, Length, EXI_TRANSFER_READ, EXI_SWAP_BOTH)) break;
			}
			else {
				if (!ExiTransferImmediateBuffer(Channel, NULL, Buffer, Length, EXI_TRANSFER_READ)) break;
				// Buffer needs bswap16.
#if 0
				PUSHORT buf16 = (PUSHORT)Buffer;
				for (ULONG i = 0; i < (Length / sizeof(USHORT)); i++) buf16[i] = __builtin_bswap16(buf16[i]);
#endif
			}
		}

		success = true;
	} while (false);
	ExiUnselectDevice(Channel);
	return success;
}

static bool IdepWriteBuffer(PIDE_STATE State, ULONG Channel, ULONG Device, PVOID Buffer, ULONG Length) {
	if (Length > IDE_MULTI32_MAX_LENGTH) return false;
	if ((Length & 3) != 0) return false;

	if (State->HwVersion < IDEEXI_V3) {
		// v1 and v2 can only do PIO writes
		PUSHORT ptr = (PUSHORT)Buffer;
		for (ULONG i = 0; i < (Length / sizeof(ptr[0])); i++) {
			if (!IdepWriteData16(State, Channel, Device, ptr[i])) return false;
		}
		return true;
	}

	if (!ExiSelectDevice(Channel, Device, State->ClockFreq, false)) return false;
	bool success = false;
	do {
		if (!ExiTransferImmediate(Channel, IdepCreateCommandWriteMulti32(Length), IDE_EXI_LEN_WRITEMULTI32, EXI_TRANSFER_WRITE, NULL)) break;
		// Send the data
		if (ExiBufferCanDma(Buffer, Length)) {
			if (!ExiTransferDma(Channel, Buffer, Length, EXI_TRANSFER_WRITE, EXI_SWAP_BOTH)) break;
		}
		else {
			if (!ExiTransferImmediateBuffer(Channel, Buffer, NULL, Length, EXI_TRANSFER_WRITE)) break;
		}
		// Finish the write operation
		if (!ExiTransferImmediate(Channel, 0, 1, EXI_TRANSFER_WRITE, NULL)) break;

		success = true;
	} while (false);
	ExiUnselectDevice(Channel);
	return success;
}

static IDEEXI_HW_VERSION IdepGetVersion(PIDE_STATE state, ULONG channel, ULONG device) {
	ULONG DeviceId;
	// If this device is a mounted SD card, don't touch it.
	EXI_SDMC_DRIVE drive;
	if (channel == 0) {
		if (device == 0) drive = SDMC_DRIVE_CARD_A;
		if (device == 2) drive = SDMC_DRIVE_SP1;
	}
	else {
		if (channel == 1) drive = SDMC_DRIVE_CARD_B;
		if (channel == 2) drive = SDMC_DRIVE_SP2;
	}
	IDEEXI_HW_VERSION ret = IDEEXI_UNKNOWN;
	do {
		if (SdmcexiIsMounted(drive)) {
			break;
		}

		// get the deviceID
		if (!ExiGetDeviceIdentifier(channel, device, &DeviceId)) {
			break;
		}

		if (DeviceId == IDEEXI_ID_V2) {
			ret = IDEEXI_V2;
			break;
		}
		if (DeviceId == IDEEXI_ID_V3) {
			ret = IDEEXI_V3;
			break;
		}
		// if it's an unknown version act as if it's v3
		if ((DeviceId & ~0xFF) == (IDEEXI_ID_V2 & ~0xFF)) {
			ret = IDEEXI_V3;
			break;
		}

		// might be v1?
		// this check might not actually work, but theoretically it should? the result of read8 with no chip select line pulled down
		if ((DeviceId & 0xFF000000) == 0xFF000000) ret = IDEEXI_V1;
		break;
	} while (false);
	state->HwVersion = ret;
	return ret;
}

static void
ob_ide_fixup_string(unsigned char* s, unsigned int len)
{
	unsigned char* p = s, * end = &s[len & ~1];

	/*
	 * if big endian arch, byte swap the string
	 */
	 //#ifdef CONFIG_BIG_ENDIAN
	for (p = end; p != s;) {
		unsigned short* pp = (unsigned short*)(p -= 2);
		*pp = __builtin_bswap16(*pp);
	}
	//#endif

	while (s != end && *s == ' ')
		++s;
	while (s != end && *s)
		if (*s++ != ' ' || (s != end && *s && *s != ' '))
			*p++ = *(s - 1);
	while (p != end)
		*p++ = '\0';
}

static bool IdepWaitStatus(PIDE_STATE state, ULONG channel, ULONG device, UCHAR bits_wanted, UCHAR bits_not_wanted, PUCHAR output) {
	udelay(1);
	UCHAR status;
	for (ULONG i = 0; i < 5000; i++) {
		if (!IdepReadStatusReg(state, channel, device, &status)) status = bits_not_wanted & ~bits_wanted;
		if ((status & SR_BSY) == 0) break;
		udelay(1000);
	}

	if (output != NULL) *output = status;
	if ((status & bits_not_wanted) != 0) return false;
	if (bits_wanted == 0) return true;
	return ((status & bits_wanted) != 0);
}

static bool IdepMountDrive(PIDE_STATE state, ULONG channel, ULONG device) {
	memset(state, 0, sizeof(*state));
	state->ClockFreq = EXI_CLOCK_27;

	IDEEXI_HW_VERSION version = IdepGetVersion(state, channel, device);
	if (version == IDEEXI_UNKNOWN) return false;
	if (version == IDEEXI_V1 && channel == 2) return false;

	if (version == IDEEXI_V1) {
		// double check
		UCHAR Status;
		if (!IdepReadStatusReg(state, channel, device, &Status) || Status == 0xFF) {
			state->HwVersion = IDEEXI_UNKNOWN;
			return false;
		}
	}

	// Select ide0
	if (!IdepWriteRegister8(state, channel, device, IDE_REG_DEVICE_SELECT, 0)) return false;
	// Wait for drive to be ready
	if (!IdepWaitStatus(state, channel, device, 0, SR_BSY, NULL)) return false;

	// Soft-reset it
	if (!IdepWriteRegister8(state, channel, device, IDE_REG_DEVICE_CONTROL, DCON_NIEN | DCON_SRST)) return false;
	udelay(1);
	if (!IdepWriteRegister8(state, channel, device, IDE_REG_DEVICE_CONTROL, DCON_NIEN)) return false;
	udelay(1);

	// Ensure registers are valid for ATA device after reset
	{
		UCHAR Register;
		if (!IdepReadRegister8(state, channel, device, IDE_REG_SECTOR_COUNT, &Register)) return false;
		if (Register != 0x01) return false;
		if (!IdepReadRegister8(state, channel, device, IDE_REG_START_SECTOR, &Register)) return false;
		if (Register != 0x01) return false;
		UCHAR CL, CH, Status;
		if (!IdepReadRegister8(state, channel, device, IDE_REG_CYLINDER_LOW, &CL)) return false;
		if (!IdepReadRegister8(state, channel, device, IDE_REG_CYLINDER_HIGH, &CH)) return false;
		if (!IdepReadRegister8(state, channel, device, IDE_REG_STATUS, &Status)) return false;
		if (CL != 0 || CH != 0 || Status == 0) return false;
	}

	// Wait for drive to be ready
	if (!IdepWaitStatus(state, channel, device, 0, SR_BSY, NULL)) return false;

	// Write the identify command
	if (!IdepWriteRegister8(state, channel, device, IDE_REG_COMMAND, ATA_CMD_IDENTIFY)) return false;

	// Wait for drive to respond
	if (!IdepWaitStatus(state, channel, device, SR_DRQ, 0, NULL)) return false;
	udelay(2000);

	// Read IDENTIFY data by PIO
	PUSHORT buf = (PUSHORT)s_TransferBuffer;
	for (ULONG i = 0; i < 0x200 / sizeof(USHORT); i++) {
		if (!IdepReadData16(state, channel, device, &buf[i])) return false;
		//buf[i] = __builtin_bswap16(buf[i]);
	}

	// Get the info out of the buffer
	if ((buf[ATA_IDENTIFY_COMMANDSET] & ATA_IDENTIFY_LBA48MASK) != 0) state->Capability = CAPABILITY_LBA48;
	else if ((buf[ATA_IDENTIFY_CAPABILITY] & ATA_IDENTIFY_LBA28MASK) != 0) state->Capability = CAPABILITY_LBA28;
	else state->Capability = CAPABILITY_CHS;


	uint64_t NumberOfSectors = 0;
	if (state->Capability == CAPABILITY_LBA48) {
		USHORT Lba[3] = {
			buf[ATA_IDENTIFY_LBA48SECTORS], buf[ATA_IDENTIFY_LBA48SECTORS + 1], buf[ATA_IDENTIFY_LBA48SECTORS + 2]
		};

		NumberOfSectors = (uint64_t)Lba[2] << 32;
		NumberOfSectors |= (ULONG)Lba[1] << 16;
		NumberOfSectors |= Lba[0];
		state->NumberOfSectors = NumberOfSectors;
	}
	else {
		state->Cylinders = buf[ATA_IDENTIFY_CYLINDERS];
		state->Heads = buf[ATA_IDENTIFY_HEADS];
		state->Sectors = buf[ATA_IDENTIFY_SECTORS];
		NumberOfSectors = ((ULONG)(buf[ATA_IDENTIFY_LBASECTORS + 1]) << 16) | buf[ATA_IDENTIFY_LBASECTORS];
		state->NumberOfSectors = NumberOfSectors;
	}

	state->SizeInMegabytes = (NumberOfSectors / 2) / 1024;
	state->SizeInGigabytes = (NumberOfSectors / 2) / 1024 / 1024;

	state->MultipleSectorCount = 1;
	UCHAR MultipleSectorCount = IdepGetReadByte(buf[ATA_IDENTIFY_MULTIPLE]);
	if (MultipleSectorCount != 0) {
		if (IdepWriteRegister8(state, channel, device, IDE_REG_SECTOR_COUNT, MultipleSectorCount)) {
			if (IdepWriteRegister8(state, channel, device, IDE_REG_COMMAND, ATA_CMD_SET_MULTIPLE_MODE)) {
				// Wait for drive to respond
				if (IdepWaitStatus(state, channel, device, 0, SR_ERR, NULL)) state->MultipleSectorCount = MultipleSectorCount;
			}
		}
	}

	// copy serial string
	memcpy(state->Serial, &buf[ATA_IDENTIFY_SERIAL], 20);
	ob_ide_fixup_string((UCHAR*)state->Serial, 20);

	// same for model string
	memcpy(state->Model, &buf[ATA_IDENTIFY_MODEL], 40);
	ob_ide_fixup_string((UCHAR*)state->Model, 40);

	state->Initialised = true;

	return true;
}


static bool IdepReadSectors(PIDE_STATE state, ULONG channel, ULONG device, uint64_t Sector, ULONG SectorCount, PVOID buffer) {
	bool NeedsLba48 = ((Sector + SectorCount) > (1ULL << 28));

	if (SectorCount > state->MultipleSectorCount) return false;
	if ((Sector + SectorCount) > state->NumberOfSectors) return false;
	if (state->Capability != CAPABILITY_LBA48 && NeedsLba48) return false;
	if (!NeedsLba48 && SectorCount >= 0x100) return false;
	// Wait for drive to be ready
	if (!IdepWaitStatus(state, channel, device, 0, 0, NULL)) return false;

	if (NeedsLba48) {
		// LBA48
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_DEVICE_SELECT, HEAD_USE_LBA)) return false;

		if (!IdepWriteRegister8(state, channel, device, IDE_REG_SECTOR_COUNT, (SectorCount >> 8) & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA0, (Sector >> 24) & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA1, (Sector >> 32) & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA2, (Sector >> 40) & 0xFF)) return false;

		if (!IdepWriteRegister8(state, channel, device, IDE_REG_SECTOR_COUNT, SectorCount & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA0, Sector & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA1, (Sector >> 8) & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA2, (Sector >> 16) & 0xFF)) return false;
	}
	else if (state->Capability >= CAPABILITY_LBA28) {
		// LBA28
		UCHAR SectorTop = (Sector >> 24) & 0xF;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_DEVICE_SELECT, 0xE0 | SectorTop)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_SECTOR_COUNT, SectorCount & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA0, Sector & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA1, (Sector >> 8) & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA2, (Sector >> 16) & 0xFF)) return false;
	}
	else {
		// CHS
		ULONG track = (Sector / state->Sectors);
		ULONG sect = (Sector % state->Sectors) + 1;
		ULONG head = (track % state->Heads);
		ULONG cyl = (track / state->Heads);

		if (!IdepWriteRegister8(state, channel, device, IDE_REG_DEVICE_SELECT, head)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_SECTOR_COUNT, SectorCount & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_START_SECTOR, sect)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_CYLINDER_LOW, cyl & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_CYLINDER_HIGH, (cyl >> 8) & 0xFF)) return false;
	}

	UCHAR Command;
	if (SectorCount > 1) {
		Command = NeedsLba48 ? ATA_CMD_READ_MULTIPLE_EXT : ATA_CMD_READ_MULTIPLE;
	}
	else {
		Command = NeedsLba48 ? ATA_CMD_READ_SECTOR_EXT : ATA_CMD_READ_SECTOR;
	}

	ULONG Length = SectorCount * IDE_SECTOR_SIZE;

	if (!IdepWriteRegister8(state, channel, device, IDE_REG_COMMAND, Command)) return false;

	UCHAR Status;
	if (!IdepWaitStatus(state, channel, device, 0, SR_ERR, &Status)) {
		return false;
	}

	if (!IdepWaitStatus(state, channel, device, SR_DRQ, 0, NULL)) return false;

	if (!IdepReadBuffer(state, channel, device, buffer, Length)) return false;

	if (!IdepReadStatusReg(state, channel, device, &Status)) return false;
	return (Status & SR_ERR) == 0;
}

static bool IdepWriteSectors(PIDE_STATE state, ULONG channel, ULONG device, uint64_t Sector, ULONG SectorCount, PVOID buffer) {
	bool NeedsLba48 = ((Sector + SectorCount) > (1ULL << 28));

	if (SectorCount > state->MultipleSectorCount) return false;
	if ((Sector + SectorCount) > state->NumberOfSectors) return false;
	if (state->Capability != CAPABILITY_LBA48 && NeedsLba48) return false;
	if (!NeedsLba48 && SectorCount >= 0x100) return false;
	// Wait for drive to be ready
	if (!IdepWaitStatus(state, channel, device, 0, 0, NULL)) return false;

	if (NeedsLba48) {
		// LBA48
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_DEVICE_SELECT, HEAD_USE_LBA)) return false;

		if (!IdepWriteRegister8(state, channel, device, IDE_REG_SECTOR_COUNT, (SectorCount >> 8) & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA0, (Sector >> 24) & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA1, (Sector >> 32) & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA2, (Sector >> 40) & 0xFF)) return false;

		if (!IdepWriteRegister8(state, channel, device, IDE_REG_SECTOR_COUNT, SectorCount & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA0, Sector & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA1, (Sector >> 8) & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA2, (Sector >> 16) & 0xFF)) return false;
	}
	else if (state->Capability >= CAPABILITY_LBA28) {
		// LBA28
		UCHAR SectorTop = (Sector >> 24) & 0xF;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_DEVICE_SELECT, 0xE0 | SectorTop)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_SECTOR_COUNT, SectorCount & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA0, Sector & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA1, (Sector >> 8) & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_LBA2, (Sector >> 16) & 0xFF)) return false;
	}
	else {
		// CHS
		ULONG track = (Sector / state->Sectors);
		ULONG sect = (Sector % state->Sectors) + 1;
		ULONG head = (track % state->Heads);
		ULONG cyl = (track / state->Heads);

		if (!IdepWriteRegister8(state, channel, device, IDE_REG_DEVICE_SELECT, head)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_SECTOR_COUNT, SectorCount & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_START_SECTOR, sect)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_CYLINDER_LOW, cyl & 0xFF)) return false;
		if (!IdepWriteRegister8(state, channel, device, IDE_REG_CYLINDER_HIGH, (cyl >> 8) & 0xFF)) return false;
	}

	UCHAR Command;
	if (SectorCount > 1) {
		Command = NeedsLba48 ? ATA_CMD_WRITE_MULTIPLE_EXT : ATA_CMD_WRITE_MULTIPLE;
	}
	else {
		Command = NeedsLba48 ? ATA_CMD_WRITE_SECTOR_EXT : ATA_CMD_WRITE_SECTOR;
	}

	ULONG Length = SectorCount * IDE_SECTOR_SIZE;

	if (!IdepWriteRegister8(state, channel, device, IDE_REG_COMMAND, Command)) return false;

	UCHAR Status;
	if (!IdepWaitStatus(state, channel, device, 0, SR_ERR, &Status)) {
		return false;
	}

	if (!IdepWaitStatus(state, channel, device, SR_DRQ, 0, NULL)) return false;

	if (!IdepWriteBuffer(state, channel, device, buffer, Length)) return false;

	if (!IdepWaitStatus(state, channel, device, 0, 0, NULL)) return false;

	if (!IdepReadStatusReg(state, channel, device, &Status)) return false;
	return (Status & SR_ERR) == 0;
}

static PIDE_STATE IdepGetMountedState(EXI_IDE_DRIVE drive) {
	if ((ULONG)drive >= IDE_DRIVE_COUNT) return false;
	PIDE_STATE state = &s_IdeState[drive];

	if (state->Initialised) {
		return state;
	}

	return NULL;
}

static ULONG IdepGetExiChannel(EXI_IDE_DRIVE drive) {
	// 0,1,0,2
	ULONG driveIdx = (ULONG)drive;
	if ((driveIdx & 1) == 0) return 0;
	return (driveIdx + 1) / 2;
}

static ULONG IdepGetExiDevice(EXI_IDE_DRIVE drive) {
	// 0,0,2,0
	return (drive == IDE_DRIVE_SP1) ? 2 : 0;
}

bool IdeexiIsMounted(EXI_IDE_DRIVE drive) {
	return IdepGetMountedState(drive) != NULL;
}

bool IdeexiMount(EXI_IDE_DRIVE drive) {
	if ((ULONG)drive >= IDE_DRIVE_COUNT) return false;
	PIDE_STATE state = &s_IdeState[drive];

	if (state->Initialised) {
		return true;
	}

	ULONG channel = IdepGetExiChannel(drive);
	ULONG device = IdepGetExiDevice(drive);

	return IdepMountDrive(state, channel, device);
}

ULONG IdeexiTransferrableSectorCount(EXI_IDE_DRIVE drive) {
	if ((ULONG)drive >= IDE_DRIVE_COUNT) return 0;

	PIDE_STATE state = &s_IdeState[drive];
	if (!state->Initialised) return 0;

	return state->MultipleSectorCount;
}

uint64_t IdeexiSectorCount(EXI_IDE_DRIVE drive) {
	if ((ULONG)drive >= IDE_DRIVE_COUNT) return 0;

	PIDE_STATE state = &s_IdeState[drive];
	if (!state->Initialised) return 0;

	return state->NumberOfSectors;
}

uint64_t IdeexiReadBlocks(EXI_IDE_DRIVE drive, PVOID buffer, uint64_t sector, ULONG count) {
	if (count == 0) return 0;

	PIDE_STATE state = IdepGetMountedState(drive);
	if (state == NULL) return 0;

	ULONG channel = IdepGetExiChannel(drive);
	ULONG device = IdepGetExiDevice(drive);
	PUCHAR buf8 = (PUCHAR)buffer;

	uint64_t readCount = 0;

	for (ULONG i = 0; i < count; i += state->MultipleSectorCount) {
		ULONG thisCount = state->MultipleSectorCount;
		if ((count - i) < thisCount) thisCount = (count - i);

		if (!IdepReadSectors(state, channel, device, sector + i, thisCount, buf8)) break;
		buf8 += (thisCount * IDE_SECTOR_SIZE);
		readCount += thisCount;
	}

	return readCount;
}

uint64_t IdeexiWriteBlocks(EXI_IDE_DRIVE drive, PVOID buffer, uint64_t sector, ULONG count) {
	if (count == 0) return 0;

	PIDE_STATE state = IdepGetMountedState(drive);
	if (state == NULL) return 0;

	ULONG channel = IdepGetExiChannel(drive);
	ULONG device = IdepGetExiDevice(drive);
	PUCHAR buf8 = (PUCHAR)buffer;

	uint64_t readCount = 0;

	for (ULONG i = 0; i < count; i += state->MultipleSectorCount) {
		ULONG thisCount = state->MultipleSectorCount;
		if ((count - i) < thisCount) thisCount = (count - i);

		if (!IdepWriteSectors(state, channel, device, sector + i, thisCount, buf8)) break;
		buf8 += (thisCount * IDE_SECTOR_SIZE);
		readCount += thisCount;
	}

	return readCount;
}

void IdeexiInit(void) {
	// Initialise every drive.
	for (ULONG i = 0; i < IDE_DRIVE_COUNT; i++) {
		memset(&s_IdeState[i], 0, sizeof(s_IdeState[i]));
	}

	// Try to mount every drive.
	for (ULONG i = 0; i < IDE_DRIVE_COUNT; i++) {
		PIDE_STATE state = &s_IdeState[i];
		ULONG channel = IdepGetExiChannel(i);
		ULONG device = IdepGetExiDevice(i);
		IdepMountDrive(state, channel, device);
	}
}
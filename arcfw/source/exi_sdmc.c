// SDMC over SPI (EXI) driver
#include <stdio.h>
#include <memory.h>
#include "arc.h"
#include "types.h"
#include "runtime.h"
#include "exi.h"
#include "exi_sdmc.h"
#include "timer.h"

//#define EXISDMC_DEBUG

enum {
	SDMC_DRIVE_COUNT = 4
};

enum {
	SDMC_TIMEOUT_MS = 1501
};

enum {
	MMC_ERROR_IDLE = ARC_BIT(0),
	MMC_ERROR_ERASE_RES = ARC_BIT(1),
	MMC_ERROR_ILL = ARC_BIT(2),
	MMC_ERROR_CRC = ARC_BIT(3),
	MMC_ERROR_ERASE_SEQ = ARC_BIT(4),
	MMC_ERROR_ADDRESS = ARC_BIT(5),
	MMC_ERROR_PARAM = ARC_BIT(6),

	MMC_ERROR_WRITE = ARC_BIT(7), // Not actually present in card response, set by driver under certain conditions

	MMC_ERROR_FATAL = MMC_ERROR_PARAM | MMC_ERROR_ADDRESS | MMC_ERROR_CRC | MMC_ERROR_ILL,
	MMC_ERROR_FATAL2 = MMC_ERROR_FATAL | MMC_ERROR_WRITE
};

typedef enum {
	SDMC_TYPE_UNUSABLE,
	SDMC_TYPE_SDMC,
	SDMC_TYPE_SDHC,
} SDMC_CARD_TYPE;

typedef enum {
	SDMC_OFFSET_SECTOR,
	SDMC_OFFSET_BYTE
} SDMC_PROTOCOL_TYPE;

typedef union _SDMC_INIT_TYPE {
	struct {
		SDMC_CARD_TYPE Type : 2;
		BOOLEAN InitInProgress : 1;
		BOOLEAN DmaEnabled : 1;
	};
	UCHAR Value;
} SDMC_INIT_TYPE, *PSDMC_INIT_TYPE;

typedef struct _SDMC_STATE {
	UCHAR CID[16];
	UCHAR CSD[16];
	UCHAR Status[64];
	UCHAR Response[128];
	ULONG RetryCount;
	ULONG SectorSize;
	ULONG SectorCount;
	EXI_CLOCK_FREQUENCY ClockFreq;
	SDMC_PROTOCOL_TYPE ProtocolType;
	SDMC_INIT_TYPE InitType;
	UCHAR ErrorFlags;
	UCHAR ClearFlag;
	bool WpFlag;
	bool Inserted;
} SDMC_STATE, *PSDMC_STATE;

static const UCHAR s_crc7_table[256] = {
	0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f,
	0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77,
	0x19, 0x10, 0x0b, 0x02, 0x3d, 0x34, 0x2f, 0x26,
	0x51, 0x58, 0x43, 0x4a, 0x75, 0x7c, 0x67, 0x6e,
	0x32, 0x3b, 0x20, 0x29, 0x16, 0x1f, 0x04, 0x0d,
	0x7a, 0x73, 0x68, 0x61, 0x5e, 0x57, 0x4c, 0x45,
	0x2b, 0x22, 0x39, 0x30, 0x0f, 0x06, 0x1d, 0x14,
	0x63, 0x6a, 0x71, 0x78, 0x47, 0x4e, 0x55, 0x5c,
	0x64, 0x6d, 0x76, 0x7f, 0x40, 0x49, 0x52, 0x5b,
	0x2c, 0x25, 0x3e, 0x37, 0x08, 0x01, 0x1a, 0x13,
	0x7d, 0x74, 0x6f, 0x66, 0x59, 0x50, 0x4b, 0x42,
	0x35, 0x3c, 0x27, 0x2e, 0x11, 0x18, 0x03, 0x0a,
	0x56, 0x5f, 0x44, 0x4d, 0x72, 0x7b, 0x60, 0x69,
	0x1e, 0x17, 0x0c, 0x05, 0x3a, 0x33, 0x28, 0x21,
	0x4f, 0x46, 0x5d, 0x54, 0x6b, 0x62, 0x79, 0x70,
	0x07, 0x0e, 0x15, 0x1c, 0x23, 0x2a, 0x31, 0x38,
	0x41, 0x48, 0x53, 0x5a, 0x65, 0x6c, 0x77, 0x7e,
	0x09, 0x00, 0x1b, 0x12, 0x2d, 0x24, 0x3f, 0x36,
	0x58, 0x51, 0x4a, 0x43, 0x7c, 0x75, 0x6e, 0x67,
	0x10, 0x19, 0x02, 0x0b, 0x34, 0x3d, 0x26, 0x2f,
	0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c,
	0x3b, 0x32, 0x29, 0x20, 0x1f, 0x16, 0x0d, 0x04,
	0x6a, 0x63, 0x78, 0x71, 0x4e, 0x47, 0x5c, 0x55,
	0x22, 0x2b, 0x30, 0x39, 0x06, 0x0f, 0x14, 0x1d,
	0x25, 0x2c, 0x37, 0x3e, 0x01, 0x08, 0x13, 0x1a,
	0x6d, 0x64, 0x7f, 0x76, 0x49, 0x40, 0x5b, 0x52,
	0x3c, 0x35, 0x2e, 0x27, 0x18, 0x11, 0x0a, 0x03,
	0x74, 0x7d, 0x66, 0x6f, 0x50, 0x59, 0x42, 0x4b,
	0x17, 0x1e, 0x05, 0x0c, 0x33, 0x3a, 0x21, 0x28,
	0x5f, 0x56, 0x4d, 0x44, 0x7b, 0x72, 0x69, 0x60,
	0x0e, 0x07, 0x1c, 0x15, 0x2a, 0x23, 0x38, 0x31,
	0x46, 0x4f, 0x54, 0x5d, 0x62, 0x6b, 0x70, 0x79
};

static const USHORT s_crc16_table[256] = {
	0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
	0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
	0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
	0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
	0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
	0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
	0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
	0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
	0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
	0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
	0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
	0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
	0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
	0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
	0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
	0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
	0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
	0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
	0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
	0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
	0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
	0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
	0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
	0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
	0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
	0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
	0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
	0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
	0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
	0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
	0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
	0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};

static SDMC_STATE s_SdmcState[SDMC_DRIVE_COUNT];

static UCHAR SdmcpCrc7(PVOID buffer, ULONG length) {
	PUCHAR buf8 = (PUCHAR)buffer;

	UCHAR crc = 0;
	for (ULONG i = 0; i < length; i++) {
		crc = s_crc7_table[(crc << 1) ^ buf8[i]];
	}

	return ((crc << 1) | 1);;
}

static USHORT SdmcpCrc16(PVOID buffer, ULONG length) {
	PUCHAR buf8 = (PUCHAR)buffer;

	USHORT crc = 0;
	for (ULONG i = 0; i < length; i++) {
		UCHAR shifted = (UCHAR)(crc >> 8);
		crc = (crc << 8) ^ s_crc16_table[shifted ^ buf8[i]];
	}

	return crc;
}

static ULONG SdmcpGetExiChannel(EXI_SDMC_DRIVE drive) {
	// 0,1,0,2
	ULONG driveIdx = (ULONG)drive;
	if ((driveIdx & 1) == 0) return 0;
	return (driveIdx + 1) / 2;
}

static ULONG SdmcpGetExiDevice(EXI_SDMC_DRIVE drive) {
	// 0,0,2,0
	return (drive == SDMC_DRIVE_SP1) ? 2 : 0;
}

static EXI_CLOCK_FREQUENCY SdmcpTransferSpeedToExiFrequency(UCHAR TransferSpeed) {
	UCHAR TransferUnit = TransferSpeed & 7;
	UCHAR TimeValue = (TransferSpeed >> 3) & 0xF;
	if (TimeValue == 0) return EXI_CLOCK_0_8; // invalid time value

	switch (TransferUnit) {
	case 1: // 1Mbit/s
		if (TimeValue <= 4) return EXI_CLOCK_0_8; // 1,1.2,1.3.1.5 x 1Mbit/s -> 1M,1.2M,1.3M,1.5M
		if (TimeValue <= 8) return EXI_CLOCK_1_6; // 2.0,2.5,3.0,3.5 x 1Mbit/s -> 2M,2.5M,3M,3.5M
		if (TimeValue != 15) return EXI_CLOCK_6_7; // 8 x 1Mbit/s -> 8M
		return EXI_CLOCK_3_3; // 4,4.5,5,5.5,6,7 x 1Mbit/s -> 4M,4.5M,5M,5.5M,6M,7M
	case 2: // 10Mbit/s
		if (TimeValue <= 4) return EXI_CLOCK_6_7; // 1,1.2,1.3.1.5 x 10Mbit/s -> 10M,12M,13M,15M
		if (TimeValue <= 7) return EXI_CLOCK_13_5; // 2.0,2.5,3.0 x 10Mbit/s -> 20M,25M,30M,35M
		// BUGBUG: could probably go faster on Vegas/Latte?
		return EXI_CLOCK_27; // 4,4.5,5,5.5,6,7,8 x 10Mbit/s -> 40M,45M,50M,55M,60M,70M,80M
	case 3: // 100Mbit/s
		// BUGBUG: could probably go faster on Vegas/Latte?
		return EXI_CLOCK_27;
	case 0: // 100kbit/s
	default:
		return EXI_CLOCK_0_8;
	}
}

static void SdmcpSetExiFrequency(PSDMC_STATE state) {
	state->ClockFreq = SdmcpTransferSpeedToExiFrequency(state->CSD[3]);
}

static UCHAR SdmcpGetSectorSizeBits(PSDMC_STATE state) {
	return (UCHAR)(((state->CSD[12] & 0x03) << 2) | ((state->CSD[13] >> 6) & 0x03));
}

static bool SdmcpCheckResponse(PSDMC_STATE state, UCHAR value) {
	if (state->InitType.InitInProgress && (value & MMC_ERROR_IDLE) != 0) {
		state->ErrorFlags = MMC_ERROR_IDLE;
		return true;
	}

	state->ErrorFlags = value & MMC_ERROR_FATAL;
	return (value & MMC_ERROR_FATAL) == 0;
}

static bool SdmcpSpiPowerOn(PSDMC_STATE state, ULONG channel, ULONG device) {
	UCHAR command[5] = { 0,0,0,0,0 };
	state->ClearFlag = 0xFF;
	ULONG WakeupCommand = 0xFFFFFFFF;
	command[0] = 0x40;
	UCHAR crc = SdmcpCrc7(command, sizeof(command)); // BUGBUG: this is a constant value and could be precalced!

	if (state->WpFlag) {
		state->ClearFlag = 0;
		WakeupCommand = 0;
		for (ULONG i = 0; i < sizeof(command); i++) command[i] ^= 0xFF;
	}

	// Set up the EXI bus to transmit with no chip select line pulled down.
	// This is required for the SDMC reset sequence.
	if (!ExiSelectDevice(channel, device, state->ClockFreq, true)) return false;

	// Tell the card to wake up.
	for (ULONG count = 0; count < 20; count++) {
		for (ULONG i = 0; i < 128 / sizeof(ULONG); i++) {
			if (!ExiTransferImmediate(channel, WakeupCommand, sizeof(ULONG), EXI_TRANSFER_WRITE, NULL)) {
				ExiUnselectDevice(channel);
				return false;
			}
		}
	}
	// Unselect the device, and reselect it with the chip select line pulled down
	ExiUnselectDevice(channel);
	if (!ExiSelectDevice(channel, device, state->ClockFreq, false)) return false;

	// Send cmd0.
	bool ret = false;
	do {
		crc |= 1;
		if (state->WpFlag) crc ^= 0xFF;

#ifdef EXISDMC_DEBUG
		printf("sd command0: %02x %02x %02x %02x %02x %02x\r\n", command[0], command[1], command[2], command[3], command[4], crc);
#endif
		if (!ExiTransferImmediateBuffer(channel, command, NULL, sizeof(command), EXI_TRANSFER_WRITE)) break;
		if (!ExiTransferImmediate(channel, crc, sizeof(crc), EXI_TRANSFER_WRITE, NULL)) break;
		ret = true;
	} while (0);

	ExiUnselectDevice(channel);
	return ret;
}

static bool SdmcpSpiSendCommand(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length) {
	PUCHAR buf8 = (PUCHAR)buffer;

	buf8[0] |= 0x40;
	UCHAR crc = SdmcpCrc7(buffer, length);

	ULONG WakeupCommand = 0xFFFFFFFF;
	if (state->WpFlag) {
		WakeupCommand = 0;
		for (ULONG i = 0; i < sizeof(length); i++) buf8[i] ^= 0xFF;
	}

	if (!ExiSelectDevice(channel, device, state->ClockFreq, false)) return false;

	bool ret = false;
	do {
		// other SPI-SD driver READS bytes until we get 0xFF here
		// this WRITES 10 0xFF bytes
		// the original matsushita driver does the same
		if (!ExiTransferImmediate(channel, WakeupCommand, 4, EXI_TRANSFER_WRITE, NULL)) break; // 4
		if (!ExiTransferImmediate(channel, WakeupCommand, 4, EXI_TRANSFER_WRITE, NULL)) break; // 8
		if (!ExiTransferImmediate(channel, WakeupCommand, 2, EXI_TRANSFER_WRITE, NULL)) break; // 10

		crc |= 1;
		if (state->WpFlag) crc ^= 0xFF;
#ifdef EXISDMC_DEBUG
		printf("sd command: %02x %02x %02x %02x %02x %02x\r\n", buf8[0], buf8[1], buf8[2], buf8[3], buf8[4], crc);
#endif

		if (!ExiTransferImmediateBuffer(channel, buffer, NULL, length, EXI_TRANSFER_WRITE)) break;
		if (!ExiTransferImmediate(channel, crc, sizeof(crc), EXI_TRANSFER_WRITE, NULL)) break;
		ret = true;
	} while (0);

	ExiUnselectDevice(channel);
	return ret;
}

static UCHAR SdmcpGetReadByte(ULONG readByte) {
	return (UCHAR)(LoadToRegister32(readByte) & 0xFF);
}

#define READ_BYTE() SdmcpGetReadByte(readByte)

static bool SdmcpSpiReadResponse(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length) {
	PUCHAR buf8 = (PUCHAR)buffer;

	if (!ExiSelectDevice(channel, device, state->ClockFreq, state->InitType.DmaEnabled)) return false;

	bool ret = false;
	do {
		ULONG count = 0;
		for (count = 0; count < 16; count++) {
			ULONG readByte = 0;
			if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) {
				count = 16;
				break;
			}

			if ((readByte & 0x80) == 0) {
				buf8[0] = READ_BYTE();
				break;
			}
		}
		if (count >= 16) break;

		if (length > 1) {
			if (!ExiReadWriteImmediateOutBuffer(channel, state->ClearFlag, &buf8[1], length - 1)) {
				break;
			}
		}

#ifdef EXISDMC_DEBUG
		printf("sd response: %02x\r\n", buf8[0]);
#endif

		ret = true;
	} while (0);

	ExiUnselectDevice(channel);
	return ret;
}

static bool SdmcpSpiStopReadResponse(PSDMC_STATE state, ULONG channel, ULONG device, PUCHAR buffer) {
	if (!ExiSelectDevice(channel, device, state->ClockFreq, state->InitType.DmaEnabled)) return false;

	bool ret = false;
	do {
		ULONG readByte = 0;
		if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;
#ifdef EXISDMC_DEBUG
		printf("sd response0: %02x\r\n", READ_BYTE());
#endif
		if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;
#ifdef EXISDMC_DEBUG
		printf("sd response1: %02x\r\n", READ_BYTE());
#endif

		ULONG EndTime = currmsecs() + SDMC_TIMEOUT_MS;
		bool IoError = (readByte & 0x80) != 0;
		while ((readByte & 0x80) != 0) {
			if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;
			if ((readByte & 0x80) == 0) {
				IoError = false;
				break;
			}

			if (currmsecs() >= EndTime) {
				// timed out. try once more.
				if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;
				if ((readByte & 0x80) == 0) IoError = false;
				break;
			}
		}

		if (IoError) {
#ifdef EXISDMC_DEBUG
			printf("sd response2: error\r\n");
#endif
			break;
		}

		buffer[0] = READ_BYTE();
#ifdef EXISDMC_DEBUG
		printf("sd response2: %02x\r\n", READ_BYTE());
#endif

		// spi_read until getting 0xFF
		IoError = readByte != 0xFF;
		while (readByte != 0xFF) {
			if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;

			if (readByte == 0xFF) {
				IoError = false;
				break;
			}

			if (currmsecs() >= EndTime) {
				// timed out. try once more.
				if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;
				if (readByte == 0xFF) IoError = false;
				break;
			}
		}

		if (IoError) {
#ifdef EXISDMC_DEBUG
			printf("sd response3: error\r\n");
#endif
			break;
		}

#ifdef EXISDMC_DEBUG
		printf("sd response3: %02x\r\n", READ_BYTE());
#endif

		ret = true;
	} while (0);

	ExiUnselectDevice(channel);
	return ret;
}

static bool SdmcpSpiDataResponse(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer) {
	PUCHAR buf8 = (PUCHAR)buffer;
	if (!ExiSelectDevice(channel, device, state->ClockFreq, state->InitType.DmaEnabled)) return false;

	bool ret = false;
	do {
		ULONG readByte = 0;
		if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;
#ifdef EXISDMC_DEBUG
		printf("sd response0: %02x\r\n", READ_BYTE());
#endif

		ULONG EndTime = currmsecs() + SDMC_TIMEOUT_MS;
		bool IoError = (readByte & 0x10) != 0;
		while ((readByte & 0x10) != 0) {
			if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;
			if ((readByte & 0x10) == 0) {
				IoError = false;
				break;
			}

			if (currmsecs() >= EndTime) {
				// timed out. try once more.
				if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;
				if ((readByte & 0x10) == 0) IoError = false;
				break;
			}
		}

		if (IoError) {
#ifdef EXISDMC_DEBUG
			printf("sd response1: error\r\n");
#endif
			break;
		}

		buf8[0] = READ_BYTE();
#ifdef EXISDMC_DEBUG
		printf("sd response1: %02x\r\n", READ_BYTE());
#endif

		if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;

		EndTime = currmsecs() + SDMC_TIMEOUT_MS;

		IoError = (readByte == 0);
		while (readByte == 0) {
			if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;
			if (readByte != 0) {
				IoError = false;
				break;
			}

			if (currmsecs() >= EndTime) {
				// timed out. try once more.
				if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;
				if (readByte != 0) IoError = false;
				break;
			}
		}

		if (IoError) {
#ifdef EXISDMC_DEBUG
			printf("sd response2: error\r\n");
#endif
			break;
		}
		buf8[1] = READ_BYTE();
#ifdef EXISDMC_DEBUG
		printf("sd response2: %02x\r\n", READ_BYTE());
#endif

		ret = true;
	} while (0);

	ExiUnselectDevice(channel);
	return ret;
}

static bool SdmcpSpiDataRead(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length, bool allowDma) {
	if (!state->InitType.DmaEnabled) allowDma = false;
	if (!ExiSelectDevice(channel, device, state->ClockFreq, allowDma)) return false;

	bool ret = false;
	bool didDma = false;
	USHORT crc16expect = 0;
	do {
		ULONG readByte = 0;
		if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;
#ifdef EXISDMC_DEBUG
		printf("dataread sd response0: %02x\r\n", READ_BYTE());
#endif

		ULONG EndTime = currmsecs() + SDMC_TIMEOUT_MS;
		bool IoError = (readByte != 0xFE);
		while (readByte != 0xFE) {
			if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;

			if (readByte == 0xFE) {
				IoError = false;
				break;
			}

			if (currmsecs() >= EndTime) {
				// timed out. try once more.
				if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;
				if (readByte == 0xFE) IoError = false;
				break;
			}
		}

		if (IoError) {
#ifdef EXISDMC_DEBUG
			printf("dataread sd response1: error\r\n");
#endif
			break;
		}

#ifdef EXISDMC_DEBUG
		printf("dataread sd response1: %02x\r\n", READ_BYTE());
#endif

		ULONG crc16;
		// If possible (ie, reading single sector only), use DMA.
		// For some reason, can't read the CRC16 correctly when using DMA...
		if (allowDma && ExiBufferCanDma(buffer, length)) {
			if (!ExiReadDmaWithImmediate(channel, state->ClearFlag, buffer, length, EXI_SWAP_OUTPUT)) break;
#if 0
			ret = true;
			didDma = true;
			crc16 = 0;
			printf("D: %08x\r\n", ExiReadDataRegister(channel));
			for (int i = 0; i < 0x10; i++) {
				if (!ExiTransferImmediate(channel, state->ClearFlag * 0x01010101, 4, EXI_TRANSFER_READWRITE, &readByte)) break;
				printf("%d: %08x\r\n", i, readByte);
			}
			break;
#endif
		}
		else
		{
			if (!ExiReadWriteImmediateOutBuffer(channel, state->ClearFlag, buffer, length)) {
#ifdef EXISDMC_DEBUG
				printf("dataread sd read data: error\r\n");
#endif
				break;
			}

			udelay(1);
		}

		if (!ExiTransferImmediate(channel, state->ClearFlag * 0x0101, 2, EXI_TRANSFER_READWRITE, &crc16)) {
#ifdef EXISDMC_DEBUG
			printf("dataread sd read crc: error\r\n");
#endif
			break;
		}

		// force crc16 into a register
		asm volatile ("" : : "r"(crc16));
		crc16expect = (USHORT)(crc16 & 0xFFFF);
		ret = true;
	} while (0);

	ExiUnselectDevice(channel);
	if (!ret) return ret;
	if (didDma) return ret;

	USHORT crc16calc = SdmcpCrc16(buffer, length);
#ifdef EXISDMC_DEBUG
	printf("dataread sd crc calc=%04x expected=%04x\r\n", crc16calc, crc16expect);
	if (crc16calc != crc16expect) {
#ifdef EXISDMC_DEBUG
		printf("dataread sd crc mismatch\r\n");
		printf("dumping end of buffer:\r\n");
		PUCHAR ExiDmaBuf = (PUCHAR)buffer;
		for (ULONG i = (length - (0x200 - 0x1B0)); i < length; i += 0x10) {
			printf("%02x %02x %02x %02x %02x %02x %02x %02x ",
				ExiDmaBuf[i + 0], ExiDmaBuf[i + 1], ExiDmaBuf[i + 2], ExiDmaBuf[i + 3],
				ExiDmaBuf[i + 4], ExiDmaBuf[i + 5], ExiDmaBuf[i + 6], ExiDmaBuf[i + 7]);
			ULONG j = i + 8;
			printf("%02x %02x %02x %02x %02x %02x %02x %02x\r\n",
				ExiDmaBuf[j + 0], ExiDmaBuf[j + 1], ExiDmaBuf[j + 2], ExiDmaBuf[j + 3],
				ExiDmaBuf[j + 4], ExiDmaBuf[j + 5], ExiDmaBuf[j + 6], ExiDmaBuf[j + 7]);
		}
#endif
	}
#endif
	return (crc16calc == crc16expect);
}

static bool SdmcpSpiDataWrite(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length) {
	USHORT crc16 = SdmcpCrc16(buffer, length);

	if (!ExiSelectDevice(channel, device, state->ClockFreq, false)) return false;

	bool ret = false;
	do {
		if (!ExiTransferImmediate(channel, 0xFE, 1, EXI_TRANSFER_WRITE, NULL)) break;
		// dma supposedly just works here
		if (ExiBufferCanDma(buffer, length)) {
			if (!ExiTransferDma(channel, buffer, length, EXI_TRANSFER_WRITE, EXI_SWAP_BOTH)) break;
		}
		else {
			if (!ExiTransferImmediateBuffer(channel, NULL, buffer, length, EXI_TRANSFER_WRITE)) break;
		}
		//udelay(1);

		if (!ExiTransferImmediate(channel, crc16, sizeof(crc16), EXI_TRANSFER_WRITE, NULL)) break;
		ret = true;
	} while (0);

	ExiUnselectDevice(channel);
	return ret;
}

static bool SdmcpSpiMultiDataWrite(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length) {
	USHORT crc16 = SdmcpCrc16(buffer, length);

	if (!ExiSelectDevice(channel, device, state->ClockFreq, false)) return false;

	bool ret = false;
	do {
		if (!ExiTransferImmediate(channel, 0xFC, 1, EXI_TRANSFER_WRITE, NULL)) break;
		// dma supposedly just works here
		if (ExiBufferCanDma(buffer, length)) {
			if (!ExiTransferDma(channel, buffer, length, EXI_TRANSFER_WRITE, EXI_SWAP_BOTH)) break;
		}
		else {
			if (!ExiTransferImmediateBuffer(channel, NULL, buffer, length, EXI_TRANSFER_WRITE)) break;
		}
		//udelay(1);

		if (!ExiTransferImmediate(channel, crc16, sizeof(crc16), EXI_TRANSFER_WRITE, NULL)) break;
		ret = true;
	} while (0);

	ExiUnselectDevice(channel);
	return ret;
}

static bool SdmcpSpiMultiDataWriteStop(PSDMC_STATE state, ULONG channel, ULONG device) {
	if (!ExiSelectDevice(channel, device, state->ClockFreq, false)) return false;

	bool ret = false;
	do {
		ULONG readByte = 0;
		if (!ExiTransferImmediate(channel, 0xFD, 1, EXI_TRANSFER_WRITE, NULL)) break;
		if (!ExiTransferImmediate(channel, 0, 1, EXI_TRANSFER_READ, &readByte)) break;
		if (!ExiTransferImmediate(channel, 0, 1, EXI_TRANSFER_READ, &readByte)) break;
		if (!ExiTransferImmediate(channel, 0, 1, EXI_TRANSFER_READ, &readByte)) break;
		if (!ExiTransferImmediate(channel, 0, 1, EXI_TRANSFER_READ, &readByte)) break;

		ULONG EndTime = currmsecs() + SDMC_TIMEOUT_MS;
		bool IoError = (readByte == 0);
		while (readByte == 0) {
			if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;

			if (readByte != 0) {
				IoError = false;
				break;
			}

			if (currmsecs() >= EndTime) {
				// timed out. try once more.
				if (!ExiTransferImmediate(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, &readByte)) break;
				if (readByte != 0) IoError = false;
				break;
			}
		}
		if (IoError) break;
		ret = true;
	} while (0);

	ExiUnselectDevice(channel);
	return ret;
}

static bool SdmcpStopResponse(PSDMC_STATE state, ULONG channel, ULONG device) {
	if (!SdmcpSpiStopReadResponse(state, channel, device, state->Response)) return false;
	return SdmcpCheckResponse(state, state->Response[0]);
}

static bool SdmcpDataResponse(PSDMC_STATE state, ULONG channel, ULONG device) {
	if (!SdmcpSpiDataResponse(state, channel, device, state->Response)) return false;
	UCHAR ErrorCode = (state->Response[0] >> 1) & 7;
	return (ErrorCode != 5) && (ErrorCode != 6);
}

static bool SdmcpResponse1(PSDMC_STATE state, ULONG channel, ULONG device) {
	if (!SdmcpSpiReadResponse(state, channel, device, state->Response, 1)) return false;
	return SdmcpCheckResponse(state, state->Response[0]);
}

static bool SdmcpResponse2(PSDMC_STATE state, ULONG channel, ULONG device) {
	if (!SdmcpSpiReadResponse(state, channel, device, state->Response, 2)) return false;
	return ((state->Response[0] & 0x7c) == 0) && ((state->Response[1] & 0x9e) == 0);
}

static bool SdmcpResponse5(PSDMC_STATE state, ULONG channel, ULONG device) {
	if (!SdmcpSpiReadResponse(state, channel, device, state->Response, 5)) return false;
	return SdmcpCheckResponse(state, state->Response[0]);
}

static bool SdmcpSendCommandImpl1(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length) {
	if (!SdmcpSpiSendCommand(state, channel, device, buffer, length)) return false;
	return SdmcpResponse1(state, channel, device);
}

static bool SdmcpSendCommandImpl2(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length) {
	if (!SdmcpSpiSendCommand(state, channel, device, buffer, length)) return false;
	return SdmcpResponse2(state, channel, device);
}

static bool SdmcpSendCommandImpl5(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length) {
	if (!SdmcpSpiSendCommand(state, channel, device, buffer, length)) return false;
	return SdmcpResponse5(state, channel, device);
}

static bool SdmcpSendAppCommand(PSDMC_STATE state, ULONG channel, ULONG device) {
	UCHAR command[5] = { 0x37, 0, 0, 0, 0 };
	bool ret = SdmcpSendCommandImpl1(state, channel, device, command, sizeof(command));
#ifdef EXISDMC_DEBUG
	if (!ret) {
		printf("SdmcpSendAppCommand failed\r\n");
	}
#endif
	return ret;
}

static bool SdmcpSendOpCond(PSDMC_STATE state, ULONG channel, ULONG device) {
	ULONG EndTime = currmsecs() + SDMC_TIMEOUT_MS;
	do {
		UCHAR command[5] = { 0, 0, 0, 0, 0 };
		if (state->InitType.Type == SDMC_TYPE_SDHC) {
			if (!SdmcpSendAppCommand(state, channel, device)) return false;
			command[0] = 0x29;
			command[1] = 0x40;
		}
		else {
			command[0] = 0x01;
		}

		if (!SdmcpSendCommandImpl1(state, channel, device, command, sizeof(command))) {
#ifdef EXISDMC_DEBUG
				printf("SdmcpSendOpCond cmd01 failed\r\n");
#endif
			return false;
		}
		
		if ((state->ErrorFlags & MMC_ERROR_IDLE) == 0) return true;
	} while (currmsecs() < EndTime);

	// timed out, last chance
	UCHAR command[5] = { 0, 0, 0, 0, 0 };
	if (state->InitType.Type == SDMC_TYPE_SDHC) {
		if (!SdmcpSendAppCommand(state, channel, device)) return false;
		command[0] = 0x29;
		command[1] = 0x40;
	}
	else {
		command[0] = 0x01;
	}

	if (!SdmcpSendCommandImpl1(state, channel, device, command, sizeof(command))) {
#ifdef EXISDMC_DEBUG
		printf("SdmcpSendOpCond cmd01 failed\r\n");
#endif
		return false;
	}

	return (state->ErrorFlags & MMC_ERROR_IDLE) == 0;
}

static bool SdmcpSendInitSdhc(PSDMC_STATE state, ULONG channel, ULONG device) {
	UCHAR command[5] = { 0x08, 0, 0, 0x01, 0xAA };
	bool ret = SdmcpSendCommandImpl5(state, channel, device, command, sizeof(command));
	if (!ret) {
#ifdef EXISDMC_DEBUG
		printf("SdmcpSendInitSdhc cmd08 failed\r\n");
#endif
	}
	return ret;
}

static bool SdmcpSendAddressModeSwitch(PSDMC_STATE state, ULONG channel, ULONG device) {
	UCHAR command[5] = { 0x3A, 0, 0, 0, 0 };
	bool ret = SdmcpSendCommandImpl5(state, channel, device, command, sizeof(command));
	if (!ret) {
#ifdef EXISDMC_DEBUG
		printf("SdmcpSendAddressModeSwitch cmd3A failed\r\n");
#endif
	}
	return ret;
}

static bool SdmcpSendToggleCrc(PSDMC_STATE state, ULONG channel, ULONG device, bool crc_enabled) {
	UCHAR command[5] = { 0x3B, 0, 0, 0, (UCHAR)crc_enabled };
	bool ret = SdmcpSendCommandImpl1(state, channel, device, command, sizeof(command));
	if (!ret) {
#ifdef EXISDMC_DEBUG
		printf("SdmcpSendInitSdhc cmd08 failed\r\n");
#endif
	}
	return ret;
}

static bool SdmcpSendCommand(PSDMC_STATE state, ULONG channel, ULONG device, UCHAR command, PUCHAR arguments) {
	UCHAR commandBuf[5] = { command, 0, 0, 0, 0 };
	if (arguments != NULL) {
		commandBuf[1] = arguments[0];
		commandBuf[2] = arguments[1];
		commandBuf[3] = arguments[2];
		commandBuf[4] = arguments[3];
	}
	return SdmcpSpiSendCommand(state, channel, device, commandBuf, sizeof(commandBuf));
}

static bool SdmcpSendCommand1(PSDMC_STATE state, ULONG channel, ULONG device, UCHAR command, PUCHAR arguments) {
	if (!SdmcpSendCommand(state, channel, device, command, arguments)) return false;
	return SdmcpResponse1(state, channel, device);
}

static bool SdmcpSendCommand2(PSDMC_STATE state, ULONG channel, ULONG device, UCHAR command, PUCHAR arguments) {
	if (!SdmcpSendCommand(state, channel, device, command, arguments)) return false;
	return SdmcpResponse2(state, channel, device);
}

static bool SdmcpSetSectorSize(PSDMC_STATE state, ULONG channel, ULONG device, ULONG sectorSize) {
	// maximum sector size is 0x200
	if (sectorSize > 0x200) sectorSize = 0x200;

	UCHAR command[5] = { 0x10, (UCHAR)(sectorSize >> 24), (UCHAR)(sectorSize >> 16), (UCHAR)(sectorSize >> 8), (UCHAR)sectorSize };
	bool ret = SdmcpSendCommandImpl1(state, channel, device, command, sizeof(command));
	if (!ret) {
#ifdef EXISDMC_DEBUG
		printf("SdmcpSetSectorSize cmd10 failed\r\n");
#endif
	}
	state->SectorSize = sectorSize;

	return true;
}

static bool SdmcpReadCsd(PSDMC_STATE state, ULONG channel, ULONG device) {
	UCHAR command[5] = { 0x09, 0, 0, 0, 0 };
	if (!SdmcpSendCommandImpl1(state, channel, device, command, sizeof(command))) {
#ifdef EXISDMC_DEBUG
		printf("SdmcpReadCsd cmd09 failed\r\n");
#endif
		return false;
	}
	return SdmcpSpiDataRead(state, channel, device, state->CSD, sizeof(state->CSD), false);
}

static bool SdmcpReadCid(PSDMC_STATE state, ULONG channel, ULONG device) {
	UCHAR command[5] = { 0x0A, 0, 0, 0, 0 };
	if (!SdmcpSendCommandImpl1(state, channel, device, command, sizeof(command))) {
#ifdef EXISDMC_DEBUG
		printf("SdmcpReadCid cmd0A failed\r\n");
#endif
		return false;
	}
	return SdmcpSpiDataRead(state, channel, device, state->CID, sizeof(state->CID), false);
}

static bool SdmcpSdStatus(PSDMC_STATE state, ULONG channel, ULONG device) {
	ULONG oldSectorSize = state->SectorSize;
	if (state->SectorSize != 64) {
		if (!SdmcpSetSectorSize(state, channel, device, 64)) return false;
	}

	bool ret = false;
	do {
		if (!SdmcpSendAppCommand(state, channel, device)) break;
		UCHAR commandBuf[5] = { 0x0d, 0, 0, 0, 0 };
		if (!SdmcpSendCommandImpl2(state, channel, device, commandBuf, sizeof(commandBuf))) break;
		if (!SdmcpSpiDataRead(state, channel, device, state->Status, sizeof(state->Status), false)) break;
		ret = true;
	} while (0);

	if (oldSectorSize != state->SectorSize) {
		if (!SdmcpSetSectorSize(state, channel, device, oldSectorSize)) return ret;
	}

	return ret;
}

static bool SdmcpSoftReset(PSDMC_STATE state, ULONG channel, ULONG device) {
	while (true) {
		if (!SdmcpSpiPowerOn(state, channel, device)) {
#ifdef EXISDMC_DEBUG
			printf("SdmcpSoftReset SpiPowerOn failed\r\n");
#endif
			return false;
		}
		if (!SdmcpSpiReadResponse(state, channel, device, state->Response, 1)) {
			if (!state->InitType.DmaEnabled) return false;
			state->InitType.DmaEnabled = false;
			if (!SdmcpSpiReadResponse(state, channel, device, state->Response, 1)) continue;
		}
		if (!SdmcpCheckResponse(state, state->Response[0])) return false;
		return SdmcpSendToggleCrc(state, channel, device, true);
	}
}

static bool SdmcpCheckInserted(PSDMC_STATE state, ULONG channel, ULONG device) {
	bool ret = ExiIsDevicePresent(channel, device);
	state->Inserted = ret;
	return ret;
}

static bool SdmcpConvertSector(PSDMC_STATE state, ULONG sector, PUCHAR buffer) {
	if (state->ProtocolType == SDMC_OFFSET_BYTE) {
		if (sector >= 0x800000) return false; // Byte-addressing can't address a sector past 4GB
		sector *= 0x200;
	}

	buffer[0] = (UCHAR)(sector >> 24);
	buffer[1] = (UCHAR)(sector >> 16);
	buffer[2] = (UCHAR)(sector >> 8);
	buffer[3] = (UCHAR)sector;

	return true;
}

static ULONG SdmcpGetSectorCount(PSDMC_STATE state)
{
	ULONG result = 0;
	PUCHAR csd = state->CSD;
	UCHAR type = csd[0] >> 6;
	switch (type)
	{
	case 0:
	{
		ULONG block_len = csd[5] & 0xf;
		block_len = 1u << block_len;
		ULONG mult = (ULONG)((csd[10] >> 7) | ((csd[9] & 3) << 1));
		mult = 1u << (mult + 2);
		result = csd[6] & 3;
		result = (result << 8) | csd[7];
		result = (result << 2) | (csd[8] >> 6);
		result = (result + 1) * mult * block_len / 512;
	}
	break;
	case 1:
		result = csd[7] & 0x3f;
		result = (result << 8) | csd[8];
		result = (result << 8) | csd[9];
		result = (result + 1) * 1024;
		break;
	default:
		break;
	}
	return result;
}

static bool SdmcpUnmountDrive(PSDMC_STATE state, ULONG channel, ULONG device) {
	// these are unused now but may not be in future if we have to send a command/etc here
	(void)channel;
	(void)device;

	if (!state->Inserted) return true;

	state->Inserted = false;
	state->InitType.Value = 0;
	state->ProtocolType = SDMC_OFFSET_BYTE;
	state->ClockFreq = EXI_CLOCK_13_5;

	return true;
}

static bool SdmcpMountDrive(PSDMC_STATE state, ULONG channel, ULONG device) {
	// Check the EXI device ID. SD card returns all-FF.
	ULONG deviceId = 0;
	if (!ExiGetDeviceIdentifier(channel, device, &deviceId)) return false;
	if (deviceId != 0xFFFFFFFF) return false;

	for (ULONG i = 0; i < 5; i++) {
		if (!SdmcpCheckInserted(state, channel, device)) return false;

		bool mounted = false;
		do {
			state->WpFlag = false;
			state->InitType.Value = 0;
			state->InitType.InitInProgress = true;
			state->InitType.DmaEnabled = channel != 0; // EXI1/2 only have one device
			state->ProtocolType = SDMC_OFFSET_BYTE;
			state->ClockFreq = EXI_CLOCK_13_5;

			if (!SdmcpSoftReset(state, channel, device)) {
				state->WpFlag = true;
				state->InitType.DmaEnabled = channel != 0;
				if (!SdmcpSoftReset(state, channel, device)) {
					SdmcpUnmountDrive(state, channel, device);
					continue;
				}
			}

			if (!SdmcpSendInitSdhc(state, channel, device)) break;
#ifdef EXISDMC_DEBUG
			printf("SdmcpSendInitSdhc response: %02x %02x %02x %02x %02x\r\n", state->Response[0], state->Response[1], state->Response[2], state->Response[3], state->Response[4]);
#endif

			SDMC_CARD_TYPE CardType = SDMC_TYPE_SDMC;
			if (state->Response[3] == 1 && state->Response[4] == 0xAA) CardType = SDMC_TYPE_SDHC;
			state->InitType.Type = CardType;

			if (!SdmcpSendOpCond(state, channel, device)) break;
			if (!SdmcpSendToggleCrc(state, channel, device, true)) break;
			if (!SdmcpReadCsd(state, channel, device)) break;
			if (!SdmcpReadCid(state, channel, device)) break;

			if (CardType == SDMC_TYPE_SDHC) {
				if (!SdmcpSendAddressModeSwitch(state, channel, device)) break;
#ifdef EXISDMC_DEBUG
				printf("SdmcpSendAddressModeSwitch response: %02x %02x %02x %02x %02x\r\n", state->Response[0], state->Response[1], state->Response[2], state->Response[3], state->Response[4]);
#endif
				if ((state->Response[1] & 0x40)) {
					state->ProtocolType = SDMC_OFFSET_SECTOR;
				}
			}

			ULONG SectorSize = 1 << SdmcpGetSectorSizeBits(state);
#ifdef EXISDMC_DEBUG
			printf("Sector size: %x\r\n", SectorSize);
#endif
			if (SectorSize > 0x200) SectorSize = 0x200;

			if (!SdmcpSetSectorSize(state, channel, device, SectorSize)) break;
			SdmcpSetExiFrequency(state);
#ifdef EXISDMC_DEBUG
			printf("EXI frequency: %d\r\n", state->ClockFreq);
#endif
			if (!SdmcpSdStatus(state, channel, device)) break;

			state->SectorCount = SdmcpGetSectorCount(state);
#ifdef EXISDMC_DEBUG
			printf("Sector count: %d (%dMB)\r\n", state->SectorCount, state->SectorCount / 2 / 1024);
#endif
			state->InitType.InitInProgress = false;

			mounted = true;
		} while (0);

		if (mounted) return true;
		SdmcpUnmountDrive(state, channel, device);
	}

	return false;
}

static PSDMC_STATE SdmcpGetMountedState(EXI_SDMC_DRIVE drive) {
	if ((ULONG)drive >= SDMC_DRIVE_COUNT) return false;
	PSDMC_STATE state = &s_SdmcState[drive];

	if (state->Inserted && !state->InitType.InitInProgress && state->InitType.Type != SDMC_TYPE_UNUSABLE) {
		return state;
	}

	return NULL;
}

void SdmcexiInit(void) {
	// Initialise every drive.
	for (ULONG i = 0; i < SDMC_DRIVE_COUNT; i++) {
		memset(&s_SdmcState[i], 0, sizeof(s_SdmcState[i]));
		PSDMC_STATE state = &s_SdmcState[i];
		state->ProtocolType = SDMC_OFFSET_BYTE;
		state->ClockFreq = EXI_CLOCK_13_5;
	}

	// Try to mount every drive.
	for (ULONG i = 0; i < SDMC_DRIVE_COUNT; i++) {
		PSDMC_STATE state = &s_SdmcState[i];
		ULONG channel = SdmcpGetExiChannel(i);
		ULONG device = SdmcpGetExiDevice(i);
		SdmcpMountDrive(state, channel, device);
	}
}

bool SdmcexiIsMounted(EXI_SDMC_DRIVE drive) {
	return SdmcpGetMountedState(drive) != NULL;
}

bool SdmcexiWriteProtected(EXI_SDMC_DRIVE drive) {
	PSDMC_STATE state = SdmcpGetMountedState(drive);
	if (state == NULL) return false;

	UCHAR flags = state->CSD[14];
	// bit0: temp write protect, bit1: perm write protect
	UCHAR protectFlags = (flags >> 4) & 3;
	return (protectFlags != 0);
}

bool SdmcexiMount(EXI_SDMC_DRIVE drive) {
	if ((ULONG)drive >= SDMC_DRIVE_COUNT) return false;
	PSDMC_STATE state = &s_SdmcState[drive];

	if (state->Inserted && !state->InitType.InitInProgress && state->InitType.Type != SDMC_TYPE_UNUSABLE) {
		return true;
	}

	ULONG channel = SdmcpGetExiChannel(drive);
	ULONG device = SdmcpGetExiDevice(drive);

	SdmcpUnmountDrive(state, channel, device);
	return SdmcpMountDrive(state, channel, device);
}

ULONG SdmcexiSectorCount(EXI_SDMC_DRIVE drive) {
	if ((ULONG)drive >= SDMC_DRIVE_COUNT) return 0;
	return s_SdmcState[drive].SectorCount;
}

ULONG SdmcexiReadBlocks(EXI_SDMC_DRIVE drive, PVOID buffer, ULONG sector, ULONG count) {
	if (count == 0) return 0;

	PSDMC_STATE state = SdmcpGetMountedState(drive);
	if (state == NULL) return 0;

	ULONG channel = SdmcpGetExiChannel(drive);
	ULONG device = SdmcpGetExiDevice(drive);
	PUCHAR buf8 = (PUCHAR)buffer;

	if (state->SectorSize != 0x200) {
		if (!SdmcpSetSectorSize(state, channel, device, 0x200)) return 0;
	}

	UCHAR Argument[4];
	if (!SdmcpConvertSector(state, sector, Argument)) return 0;

	if (!SdmcpSendCommand1(state, channel, device, 0x12, Argument)) return 0;
	ULONG readCount = 0;
	for (ULONG i = 0; i < count; i++) {
		if (!SdmcpSpiDataRead(state, channel, device, buf8, state->SectorSize, count == 1)) break;
		buf8 += state->SectorSize;
		readCount++;
	}

	if (!SdmcpSendCommand(state, channel, device, 0x0C, NULL)) return readCount;
	if (!SdmcpStopResponse(state, channel, device)) return readCount;

	return readCount;
}

static ULONG SdmcexiWriteBlock(EXI_SDMC_DRIVE drive, PVOID buffer, ULONG sector) {
	PSDMC_STATE state = SdmcpGetMountedState(drive);
	if (state == NULL) return 0;

	ULONG channel = SdmcpGetExiChannel(drive);
	ULONG device = SdmcpGetExiDevice(drive);
	PUCHAR buf8 = (PUCHAR)buffer;

	if (state->SectorSize != 0x200) {
		if (!SdmcpSetSectorSize(state, channel, device, 0x200)) return 0;
	}

	UCHAR ArgSector[4];
	if (!SdmcpConvertSector(state, sector, ArgSector)) return 0;

	if (!SdmcpSendCommand1(state, channel, device, 0x18, ArgSector)) return 0;

	ULONG writeCount = 0;
	if (!SdmcpSpiDataWrite(state, channel, device, buf8, state->SectorSize)) return 0;
	if (!SdmcpDataResponse(state, channel, device)) return 0;
	if (!SdmcpSendCommand2(state, channel, device, 0x0D, NULL)) return 0;
	return 1;
}


ULONG SdmcexiWriteBlocks(EXI_SDMC_DRIVE drive, PVOID buffer, ULONG sector, ULONG count) {
	if (count == 0) return 0;
	if (count == 1) return SdmcexiWriteBlock(drive, buffer, sector);

#if 1
	// something wrong with multiwrite
	PUCHAR buf8 = (PUCHAR)buffer;

	ULONG writeCount = 0;
	for (ULONG i = 0; i < count; i++) {
		ULONG thisCount = SdmcexiWriteBlock(drive, buf8, sector + i);
		if (thisCount == 0) break;
		writeCount += thisCount;
		buf8 += 0x200;
	}

	return writeCount;

#else
	PSDMC_STATE state = SdmcpGetMountedState(drive);
	if (state == NULL) return 0;

	ULONG channel = SdmcpGetExiChannel(drive);
	ULONG device = SdmcpGetExiDevice(drive);
	PUCHAR buf8 = (PUCHAR)buffer;

	if (state->SectorSize != 0x200) {
		if (!SdmcpSetSectorSize(state, channel, device, 0x200)) return 0;
	}

	UCHAR ArgSector[4];
	if (!SdmcpConvertSector(state, sector, ArgSector)) return 0;

	UCHAR Argument[4] = {
		(UCHAR)(count >> 24),
		(UCHAR)(count >> 16),
		(UCHAR)(count >> 8),
		(UCHAR)count
	};
	if (!SdmcpSendAppCommand(state, channel, device)) return 0;
	if (!SdmcpSendCommand1(state, channel, device, 0x17, Argument)) return 0;

	if (!SdmcpSendCommand1(state, channel, device, 0x19, ArgSector)) return 0;

	ULONG writeCount = 0;
	for (ULONG i = 0; i < count; i++) {
		if (!SdmcpSpiMultiDataWrite(state, channel, device, buf8, state->SectorSize)) break;
		if (!SdmcpDataResponse(state, channel, device)) {
			if (!SdmcpSendCommand(state, channel, device, 0x0C, NULL)) return writeCount;
			if (!SdmcpStopResponse(state, channel, device)) return writeCount;
			return writeCount;
		}
		buf8 += state->SectorSize;
		writeCount++;
	}

	if (!SdmcpSpiMultiDataWriteStop(state, channel, device)) return writeCount;
	if (!SdmcpSendCommand2(state, channel, device, 0x0D, NULL)) return writeCount;

	return writeCount;
#endif
}
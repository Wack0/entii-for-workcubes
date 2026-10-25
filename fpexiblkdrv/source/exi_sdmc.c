// SDMC over SPI (EXI) driver
#define DEVL 1
#include <ntddk.h>
#include "hal.h"
#include <stdio.h>
#include <memory.h>
#include "exiapi.h"
#include "runtime.h"
#include "exi_sdmc.h"
#include "exi_map.h"
#define ARC_BIT(x) BIT(x)

//#define EXISDMC_DEBUG

enum {
	SDMC_SECTORS_IN_PAGE = PAGE_SIZE / 0x200
};

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
	BOOLEAN WpFlag;
	BOOLEAN Inserted;
} SDMC_STATE, *PSDMC_STATE;

typedef struct _SDMC_ASYNC_CONTEXT {
	KEVENT Event;
	NTSTATUS Status;
	PUCHAR Data;
	ULONG Length;
	PSDMC_STATE State;
	
	ULONG Count;
	HAL_EXI_IMMASYNC_CALLBACK BytewaitCallback;
	UCHAR BitsWanted, BitsNotWanted;
	
	UCHAR Command[5];
	UCHAR Crc;
} SDMC_ASYNC_CONTEXT, *PSDMC_ASYNC_CONTEXT;

typedef struct _SDMC_ASYNC_STATE_CONTEXT {
	KEVENT Event;
	UCHAR Drive;
	UCHAR Channel;
	UCHAR Device;
	BOOLEAN Result;
	PVOID Buffer;
	ULONG Sector;
	ULONG SectorCount;
	ULONG InUse;
} SDMC_ASYNC_STATE_CONTEXT, *PSDMC_ASYNC_STATE_CONTEXT;

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
// SDMC async context for each EXI channel
static SDMC_ASYNC_CONTEXT s_AsyncContext[EXI_CHANNEL_COUNT];
// 0x10 state contexts per drive
static SDMC_ASYNC_STATE_CONTEXT s_StateContext[SDMC_DRIVE_COUNT * 0x10];

static ULONG currmsecs(void) {
	// shitty impl for shitty rush job port lol
	LARGE_INTEGER PerformanceFrequency;
	LARGE_INTEGER Counter = KeQueryPerformanceCounter(&PerformanceFrequency);
	unsigned long long currusecs = Counter.QuadPart / (PerformanceFrequency.QuadPart / 1000000);
	return (ULONG)(currusecs / 1000);
}

static PSDMC_ASYNC_STATE_CONTEXT SdmcpGetStateContext(ULONG drive) {
	for (ULONG i = 0; i < 0x10; i++) {
		PSDMC_ASYNC_STATE_CONTEXT ctx = &s_StateContext[(SDMC_DRIVE_COUNT * drive) + i];
		if (!ctx->InUse) {
			KeInitializeEvent(&ctx->Event, SynchronizationEvent, FALSE);
			ctx->Drive = drive;
			ctx->InUse = 1;
			return ctx;
		}
	}
	return NULL;
}

static void SdmcpReleaseStateContext(PSDMC_ASYNC_STATE_CONTEXT ctx) {
	ctx->InUse = 0;
}

static PSDMC_ASYNC_CONTEXT SdmcpInitContext(ULONG channel, PVOID data) {
	PSDMC_ASYNC_CONTEXT Context = &s_AsyncContext[channel];
	KeInitializeEvent(&Context->Event, SynchronizationEvent, FALSE);
	Context->Status = STATUS_PENDING;
	Context->Data = data;
	return Context;
}

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

static BOOLEAN SdmcpCheckResponse(PSDMC_STATE state, UCHAR value) {
	if (state->InitType.InitInProgress && (value & MMC_ERROR_IDLE) != 0) {
		state->ErrorFlags = MMC_ERROR_IDLE;
		return TRUE;
	}

	state->ErrorFlags = value & MMC_ERROR_FATAL;
	return (value & MMC_ERROR_FATAL) == 0;
}

static EXI_LOCK_ACTION SdmcpFinishedCallback(ULONG channel, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	Context->Status = STATUS_SUCCESS;
	KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	return ExiKeepLocked;
}

static EXI_LOCK_ACTION SdmcpFinishedImmediateCallback(ULONG channel, ULONG data, PVOID context) {
	return SdmcpFinishedCallback(channel, context);
}

static EXI_LOCK_ACTION SdmcpCommandCallback(ULONG channel, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	NTSTATUS Status = HalExiTransferImmediateAsync(channel, Context->Crc, sizeof(Context->Crc), EXI_TRANSFER_WRITE, SdmcpFinishedImmediateCallback, context);
	if (!NT_SUCCESS(Status)) {
		Context->Status = Status;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	}
	
	return ExiKeepLocked;
}

static EXI_LOCK_ACTION SdmcpPowerOnCallback(ULONG channel, ULONG data, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	Context->Length -= sizeof(ULONG);
	if (Context->Length == 0) {
		Context->Status = STATUS_SUCCESS;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
		return ExiKeepLocked;
	}
	
	ULONG WakeupCommand = 0xFFFFFFFF;
	if (Context->State->WpFlag) WakeupCommand = 0;
	
	ULONG length = sizeof(ULONG);
	//if (Context->Length < length) length = Context->Length;
	NTSTATUS Status = HalExiTransferImmediateAsync(channel, WakeupCommand, length, EXI_TRANSFER_WRITE, SdmcpPowerOnCallback, context);
	if (!NT_SUCCESS(Status)) {
		Context->Status = Status;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	}
	
	return ExiKeepLocked;
}

static BOOLEAN SdmcpSpiPowerOn(PSDMC_STATE state, ULONG channel, ULONG device) {
	UCHAR command[5] = { 0,0,0,0,0 };
	state->ClearFlag = 0xFF;
	ULONG WakeupCommand = 0xFFFFFFFF;
	command[0] = 0x40;
	PSDMC_ASYNC_CONTEXT context = SdmcpInitContext(channel,  NULL);
	ULONG crc = SdmcpCrc7(command, sizeof(command)); // BUGBUG: this is a constant value and could be precalced!
	context->State = state;

	if (state->WpFlag) {
		state->ClearFlag = 0;
		WakeupCommand = 0;
		for (ULONG i = 0; i < sizeof(command); i++) command[i] ^= 0xFF;
	}
	//context->Command = command;

	// Set up the EXI bus to transmit with no chip select line pulled down.
	// This is required for the SDMC reset sequence.
	NTSTATUS Status = HalExiSelectDevice(channel, device, state->ClockFreq, TRUE);
	if (!NT_SUCCESS(Status)) return FALSE;

	// Tell the card to wake up.
	context->Length = (128 / sizeof(ULONG)) * 20;
	Status = HalExiTransferImmediateAsync(channel, WakeupCommand, sizeof(ULONG), EXI_TRANSFER_WRITE, SdmcpPowerOnCallback, context);
	if (!NT_SUCCESS(Status)) {
		HalExiUnselectDevice(channel);
		return FALSE;
	}
	KeWaitForSingleObject( &context->Event, Executive, KernelMode, FALSE, NULL);
	Status = context->Status;
	
	KeInitializeEvent(&context->Event, SynchronizationEvent, FALSE);
	
	// Unselect the device, and reselect it with the chip select line pulled down
	HalExiUnselectDevice(channel);
	if (!NT_SUCCESS(Status)) return FALSE;
	
	Status = HalExiSelectDevice(channel, device, state->ClockFreq, FALSE);
	if (!NT_SUCCESS(Status)) return FALSE;

	// Send cmd0.
	do {
		crc |= 1;
		if (state->WpFlag) crc ^= 0xFF;
		context->Crc = crc;

#ifdef EXISDMC_DEBUG
		printf("sd command0: %02x %02x %02x %02x %02x %02x\r\n", command[0], command[1], command[2], command[3], command[4], crc);
#endif
		Status = HalExiTransferImmediateBufferAsync(channel, command, NULL, sizeof(command), EXI_TRANSFER_WRITE, SdmcpCommandCallback, context);
		if (!NT_SUCCESS(Status)) break;
		KeWaitForSingleObject( &context->Event, Executive, KernelMode, FALSE, NULL);
		Status = context->Status;
	} while (0);

	HalExiUnselectDevice(channel);
	return NT_SUCCESS(Status);
}

static EXI_LOCK_ACTION SdmcpSendCommandCallback0(ULONG channel, ULONG data, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	if (Context->Length < sizeof(ULONG)) Context->Length = 0;
	else Context->Length -= sizeof(ULONG);
	NTSTATUS Status;
	if (Context->Length == 0) {
		Status = HalExiTransferImmediateBufferAsync(channel, Context->Command, NULL, sizeof(Context->Command), EXI_TRANSFER_WRITE, SdmcpCommandCallback, context);
	} else {
		ULONG WakeupCommand = 0xFFFFFFFF;
		if (Context->State->WpFlag) WakeupCommand = 0;
		
		ULONG length = sizeof(ULONG);
		if (Context->Length < length) length = Context->Length;
		Status = HalExiTransferImmediateAsync(channel, WakeupCommand, length, EXI_TRANSFER_WRITE, SdmcpSendCommandCallback0, context);
	}
	
	if (!NT_SUCCESS(Status)) {
		Context->Status = Status;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	}
	
	return ExiKeepLocked;
}

static BOOLEAN SdmcpSpiSendCommand(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length) {
	if (length != 5) return FALSE;
	PUCHAR buf8 = (PUCHAR)buffer;

	buf8[0] |= 0x40;
	PSDMC_ASYNC_CONTEXT context = SdmcpInitContext(channel, NULL);
	context->State = state;
	UCHAR crc = SdmcpCrc7(buffer, length);

	ULONG WakeupCommand = 0xFFFFFFFF;
	if (state->WpFlag) {
		WakeupCommand = 0;
		for (ULONG i = 0; i < sizeof(length); i++) buf8[i] ^= 0xFF;
	}
	
	crc |= 1;
	if (state->WpFlag) crc ^= 0xFF;
	memcpy(context->Command, buf8, sizeof(context->Command));
	context->Crc = crc;

	NTSTATUS Status = HalExiSelectDevice(channel, device, state->ClockFreq, FALSE);
	if (!NT_SUCCESS(Status)) return FALSE;
	
	
	

	BOOLEAN ret = FALSE;
	do {
		// other SPI-SD driver READS bytes until we get 0xFF here
		// this WRITES 10 0xFF bytes
		// the original matsushita driver does the same
		context->Length = 10;
		
		Status = HalExiTransferImmediateAsync(channel, WakeupCommand, 4, EXI_TRANSFER_WRITE, SdmcpSendCommandCallback0, context);
		if (!NT_SUCCESS(Status)) break;
		KeWaitForSingleObject( &context->Event, Executive, KernelMode, FALSE, NULL);
		Status = context->Status;
	} while (0);

	HalExiUnselectDevice(channel);
	return NT_SUCCESS(Status);
}

static UCHAR SdmcpGetReadByte(ULONG readByte) {
	return (UCHAR)(LoadToRegister32(readByte) & 0xFF);
}

#define READ_BYTE() SdmcpGetReadByte(readByte)

static EXI_LOCK_ACTION SdmcpWaitForByteCallbackImpl(ULONG channel, ULONG data, PVOID context, BOOLEAN delay);

static EXI_LOCK_ACTION SdmcpWaitForByteCallbackNoDelay(ULONG channel, ULONG data, PVOID context) {
	return SdmcpWaitForByteCallbackImpl(channel, data, context, FALSE);
}

static EXI_LOCK_ACTION SdmcpWaitForByteCallback(ULONG channel, ULONG data, PVOID context) {
	return SdmcpWaitForByteCallbackImpl(channel, data, context, TRUE);
}

static EXI_LOCK_ACTION SdmcpWaitForByteCallbackImpl(ULONG channel, ULONG data, PVOID context, BOOLEAN delay) {
	PSDMC_ASYNC_CONTEXT Context = context;
	UCHAR byte = SdmcpGetReadByte(data);
	BOOLEAN fail = FALSE;
	if (Context->BitsNotWanted == Context->BitsWanted) {
		if (Context->BitsWanted == 0) fail = byte == 0;
		else fail = byte != Context->BitsWanted;
	} else {
		fail = ((byte & Context->BitsNotWanted) != 0);
		if (!fail) fail = ((byte & Context->BitsWanted) != Context->BitsWanted);
	}
	
	NTSTATUS Status;
	
	if (fail) {
		Context->Count--;
		if (!delay && Context->Count == 0) {
			Context->Count = SDMC_TIMEOUT_MS;
			Status = HalExiTransferImmediateAsync(channel, Context->State->ClearFlag, sizeof(Context->State->ClearFlag), EXI_TRANSFER_READWRITE, SdmcpWaitForByteCallback, context);
			if (!NT_SUCCESS(Status)) {
				Context->Status = Status;
				KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
			}
			return ExiKeepLocked;
		}
		if (Context->Count == 0) {
			Context->Status = STATUS_IO_TIMEOUT;
			KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
			return ExiKeepLocked;
		}
		
		if (delay) KeStallExecutionProcessor(1000);
		HAL_EXI_IMMASYNC_CALLBACK Callback = delay ? SdmcpWaitForByteCallback : SdmcpWaitForByteCallbackNoDelay;
		Status = HalExiTransferImmediateAsync(channel, Context->State->ClearFlag, sizeof(Context->State->ClearFlag), EXI_TRANSFER_READWRITE, Callback, context);
		if (!NT_SUCCESS(Status)) {
			Context->Status = Status;
			KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
		}
		return ExiKeepLocked;
	}
	
	if (Context->BytewaitCallback != NULL) {
		return Context->BytewaitCallback(channel, data, context);
	}
	
	Context->Status = STATUS_SUCCESS;
	KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	return ExiKeepLocked;
}

static EXI_LOCK_ACTION SdmcpReadResponseCallback(ULONG channel, ULONG data, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	Context->Data[0] = SdmcpGetReadByte(data);
	Context->Length--;
	if (Context->Length == 0) {
		Context->Status = STATUS_SUCCESS;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
		return ExiKeepLocked;
	}
	
	NTSTATUS Status = HalExiReadWriteImmediateOutBufferAsync(channel, Context->State->ClearFlag, &Context->Data[1], Context->Length, SdmcpFinishedCallback, context);
	if (!NT_SUCCESS(Status)) {
		Context->Status = Status;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	}
	return ExiKeepLocked;
}


static BOOLEAN SdmcpSpiReadResponse(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length) {
	PUCHAR buf8 = (PUCHAR)buffer;
	PSDMC_ASYNC_CONTEXT context = SdmcpInitContext(channel, buffer);
	context->State = state;
	context->BytewaitCallback = SdmcpReadResponseCallback;

	NTSTATUS Status = HalExiSelectDevice(channel, device, state->ClockFreq, state->InitType.DmaEnabled);
	if (!NT_SUCCESS(Status)) return FALSE;

	do {
		context->Count = 16;
		context->Length = length;
		context->BitsWanted = 0;
		context->BitsNotWanted = 0x80;
		Status = HalExiTransferImmediateAsync(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, SdmcpWaitForByteCallbackNoDelay, context);
		
		if (!NT_SUCCESS(Status)) break;
		KeWaitForSingleObject( &context->Event, Executive, KernelMode, FALSE, NULL);
		Status = context->Status;
	} while (0);

	HalExiUnselectDevice(channel);
	return NT_SUCCESS(Status);
}

static EXI_LOCK_ACTION SdmcpStopReadResponseCallback0(ULONG channel, ULONG data, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	Context->Count = SDMC_TIMEOUT_MS;
	Context->BitsWanted = 0;
	Context->BitsNotWanted = 0x80;
	NTSTATUS Status = HalExiTransferImmediateAsync(channel, Context->State->ClearFlag, sizeof(Context->State->ClearFlag), EXI_TRANSFER_READWRITE, SdmcpWaitForByteCallback, context);
	
	if (!NT_SUCCESS(Status)) {
		Context->Status = Status;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	}
	return ExiKeepLocked;
}

static EXI_LOCK_ACTION SdmcpStopReadResponseCallback1(ULONG channel, ULONG data, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	Context->Data[0] = SdmcpGetReadByte(data);
	
	Context->BytewaitCallback = SdmcpFinishedImmediateCallback;
	Context->Count = SDMC_TIMEOUT_MS;
	Context->BitsWanted = 0xFF;
	Context->BitsNotWanted = 0xFF;
	NTSTATUS Status = HalExiTransferImmediateAsync(channel, Context->State->ClearFlag, sizeof(Context->State->ClearFlag), EXI_TRANSFER_READWRITE, SdmcpWaitForByteCallback, context);
	if (!NT_SUCCESS(Status)) {
		Context->Status = Status;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	}
	return ExiKeepLocked;
}

static BOOLEAN SdmcpSpiStopReadResponse(PSDMC_STATE state, ULONG channel, ULONG device, PUCHAR buffer) {
	PSDMC_ASYNC_CONTEXT context = SdmcpInitContext(channel, buffer);
	context->State = state;
	context->BytewaitCallback = SdmcpStopReadResponseCallback1;
	
	NTSTATUS Status = HalExiSelectDevice(channel, device, state->ClockFreq, state->InitType.DmaEnabled);
	if (!NT_SUCCESS(Status)) return FALSE;

	
	do {
		Status = HalExiTransferImmediateAsync(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, SdmcpStopReadResponseCallback0, context);
		
		if (!NT_SUCCESS(Status)) break;
		KeWaitForSingleObject( &context->Event, Executive, KernelMode, FALSE, NULL);
		Status = context->Status;
	} while (0);

	HalExiUnselectDevice(channel);
	return NT_SUCCESS(Status);
}

static EXI_LOCK_ACTION SdmcpDataResponseCallback1(ULONG channel, ULONG data, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	Context->Data[1] = SdmcpGetReadByte(data);
	
	return SdmcpFinishedImmediateCallback(channel, data, context);
}

static EXI_LOCK_ACTION SdmcpDataResponseCallback0(ULONG channel, ULONG data, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	Context->Data[0] = SdmcpGetReadByte(data);
	
	Context->BytewaitCallback = SdmcpDataResponseCallback1;
	Context->Count = SDMC_TIMEOUT_MS;
	Context->BitsWanted = 0;
	Context->BitsNotWanted = 0;
	NTSTATUS Status = HalExiTransferImmediateAsync(channel, Context->State->ClearFlag, sizeof(Context->State->ClearFlag), EXI_TRANSFER_READWRITE, SdmcpWaitForByteCallback, context);
	if (!NT_SUCCESS(Status)) {
		Context->Status = Status;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	}
	return ExiKeepLocked;
}

static BOOLEAN SdmcpSpiDataResponse(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer) {
	PSDMC_ASYNC_CONTEXT context = SdmcpInitContext(channel, buffer);
	context->State = state;
	context->BytewaitCallback = SdmcpDataResponseCallback0;
	
	NTSTATUS Status = HalExiSelectDevice(channel, device, state->ClockFreq, state->InitType.DmaEnabled);
	if (!NT_SUCCESS(Status)) return FALSE;
	
	do {
		context->Count = SDMC_TIMEOUT_MS;
		context->BitsWanted = 0;
		context->BitsNotWanted = 0x10;
		Status = HalExiTransferImmediateAsync(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, SdmcpWaitForByteCallback, context);
		
		if (!NT_SUCCESS(Status)) break;
		KeWaitForSingleObject( &context->Event, Executive, KernelMode, FALSE, NULL);
		Status = context->Status;
	} while (0);

	HalExiUnselectDevice(channel);
	return NT_SUCCESS(Status);
}

static EXI_LOCK_ACTION SdmcpDataReadCallback2(ULONG channel, ULONG data, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	asm volatile ("" : : "r"(data)); // make sure it's not spilled to stack
	USHORT crc16expect = (USHORT)(data & 0xFFFF);
	USHORT crc16calc = SdmcpCrc16(Context->Data, Context->Length);
	NTSTATUS Status = STATUS_SUCCESS;
	if (crc16expect != crc16calc) Status = STATUS_CRC_ERROR;
	Context->Status = Status;
	KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	return ExiKeepLocked;
}

static EXI_LOCK_ACTION SdmcpDataReadCallback1(ULONG channel, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	HalSweepDcacheRange(Context->Data, Context->Length);
	NTSTATUS Status = HalExiTransferImmediateAsync(channel, Context->State->ClearFlag * 0x0101, 2, EXI_TRANSFER_READWRITE, SdmcpDataReadCallback2, context);
	if (!NT_SUCCESS(Status)) {
		Context->Status = Status;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	}
	return ExiKeepLocked;
}

static EXI_LOCK_ACTION SdmcpDataReadCallback0(ULONG channel, ULONG data, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	
	NTSTATUS Status;
	
	// overloaded here for allowDma
	if (Context->Crc) {
		Status = HalExiTransferDmaAsync(channel, Context->Data, Context->Length, EXI_TRANSFER_READ, EXI_SWAP_OUTPUT, SdmcpDataReadCallback1, context);
	} else {
		Status = HalExiReadWriteImmediateOutBufferAsync(channel, Context->State->ClearFlag, Context->Data, Context->Length, SdmcpDataReadCallback1, context);
	}
	
	if (!NT_SUCCESS(Status)) {
		Context->Status = Status;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	}
	return ExiKeepLocked;
}

static BOOLEAN SdmcpSpiDataRead(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length, BOOLEAN allowDma) {
	if (!state->InitType.DmaEnabled) allowDma = FALSE;
	
	PSDMC_ASYNC_CONTEXT context = SdmcpInitContext(channel, buffer);
	context->Length = length;
	context->State = state;
	context->BytewaitCallback = SdmcpDataReadCallback0;
	context->Crc = allowDma;
	
	NTSTATUS Status = HalExiSelectDevice(channel, device, state->ClockFreq, state->InitType.DmaEnabled);
	if (!NT_SUCCESS(Status)) return FALSE;

	
	do {
		context->Count = SDMC_TIMEOUT_MS;
		context->BitsWanted = 0xFE;
		context->BitsNotWanted = 0xFE;
		Status = HalExiTransferImmediateAsync(channel, state->ClearFlag, sizeof(state->ClearFlag), EXI_TRANSFER_READWRITE, SdmcpWaitForByteCallback, context);
		if (!NT_SUCCESS(Status)) break;
		KeWaitForSingleObject( &context->Event, Executive, KernelMode, FALSE, NULL);
		Status = context->Status;
	} while (0);

	HalExiUnselectDevice(channel);
	return NT_SUCCESS(Status);
}

static EXI_LOCK_ACTION SdmcpMultiDataWriteCallback1(ULONG channel, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	KeStallExecutionProcessor(1);
	NTSTATUS Status = HalExiTransferImmediateAsync(channel, Context->Count, sizeof(USHORT), EXI_TRANSFER_WRITE, SdmcpFinishedImmediateCallback, context);
	if (!NT_SUCCESS(Status)) {
		Context->Status = Status;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	}
	return ExiKeepLocked;
}

static EXI_LOCK_ACTION SdmcpMultiDataWriteCallback0(ULONG channel, ULONG data, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	
	NTSTATUS Status = HalExiTransferDmaAsync(channel, Context->Data, Context->Length, EXI_TRANSFER_WRITE, EXI_SWAP_BOTH, SdmcpMultiDataWriteCallback1, context);
	if (!NT_SUCCESS(Status)) {
		Context->Status = Status;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	}
	return ExiKeepLocked;
}

static BOOLEAN SdmcpSpiMultiDataWrite(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length) {
	USHORT crc16 = SdmcpCrc16(buffer, length);

	PSDMC_ASYNC_CONTEXT context = SdmcpInitContext(channel, buffer);
	context->Length = length;
	context->State = state;
	context->Count = crc16;

	NTSTATUS Status = HalExiSelectDevice(channel, device, state->ClockFreq, FALSE);
	if (!NT_SUCCESS(Status)) return FALSE;

	do {
		Status = HalExiTransferImmediateAsync(channel, 0xFC, 1, EXI_TRANSFER_WRITE, SdmcpMultiDataWriteCallback0, context);
		if (!NT_SUCCESS(Status)) break;
		KeWaitForSingleObject( &context->Event, Executive, KernelMode, FALSE, NULL);
		Status = context->Status;
	} while (0);

	HalExiUnselectDevice(channel);
	return NT_SUCCESS(Status);
}

static BOOLEAN SdmcpSpiDataWrite(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length) {
	USHORT crc16 = SdmcpCrc16(buffer, length);

	PSDMC_ASYNC_CONTEXT context = SdmcpInitContext(channel, buffer);
	context->Length = length;
	context->State = state;
	context->Count = crc16;

	NTSTATUS Status = HalExiSelectDevice(channel, device, state->ClockFreq, FALSE);
	if (!NT_SUCCESS(Status)) return FALSE;

	do {
		Status = HalExiTransferImmediateAsync(channel, 0xFE, 1, EXI_TRANSFER_WRITE, SdmcpMultiDataWriteCallback0, context);
		if (!NT_SUCCESS(Status)) break;
		KeWaitForSingleObject( &context->Event, Executive, KernelMode, FALSE, NULL);
		Status = context->Status;
	} while (0);

	HalExiUnselectDevice(channel);
	return NT_SUCCESS(Status);
}

static EXI_LOCK_ACTION SdmcpMultiDataWriteStopCallback1(ULONG channel, ULONG data, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	NTSTATUS Status = HalExiTransferImmediateAsync(channel, Context->State->ClearFlag, sizeof(Context->State->ClearFlag), EXI_TRANSFER_READWRITE, SdmcpWaitForByteCallback, context);
	if (!NT_SUCCESS(Status)) {
		Context->Status = Status;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	}
	return ExiKeepLocked;
}

static EXI_LOCK_ACTION SdmcpMultiDataWriteStopCallback0(ULONG channel, ULONG data, PVOID context) {
	PSDMC_ASYNC_CONTEXT Context = context;
	NTSTATUS Status = HalExiTransferImmediateAsync(channel, 0, 3, EXI_TRANSFER_READ, SdmcpMultiDataWriteStopCallback1, context);
	if (!NT_SUCCESS(Status)) {
		Context->Status = Status;
		KeSetEvent(&Context->Event, (KPRIORITY)0, FALSE);
	}
	return ExiKeepLocked;
}

static BOOLEAN SdmcpSpiMultiDataWriteStop(PSDMC_STATE state, ULONG channel, ULONG device) {
	PSDMC_ASYNC_CONTEXT context = SdmcpInitContext(channel, NULL);
	context->State = state;
	context->Count = SDMC_TIMEOUT_MS;
	context->BitsWanted = 0;
	context->BitsNotWanted = 0;
	context->BytewaitCallback = NULL;
	
	NTSTATUS Status = HalExiSelectDevice(channel, device, state->ClockFreq, FALSE);
	if (!NT_SUCCESS(Status)) return FALSE;
	
	do {
		Status = HalExiTransferImmediateAsync(channel, 0xFD, 1, EXI_TRANSFER_WRITE, SdmcpMultiDataWriteStopCallback0, context);
		if (!NT_SUCCESS(Status)) break;
		KeWaitForSingleObject( &context->Event, Executive, KernelMode, FALSE, NULL);
		Status = context->Status;
	} while (0);

	HalExiUnselectDevice(channel);
	return NT_SUCCESS(Status);
}

static BOOLEAN SdmcpStopResponse(PSDMC_STATE state, ULONG channel, ULONG device) {
	if (!SdmcpSpiStopReadResponse(state, channel, device, state->Response)) return FALSE;
	return SdmcpCheckResponse(state, state->Response[0]);
}

static BOOLEAN SdmcpDataResponse(PSDMC_STATE state, ULONG channel, ULONG device) {
	if (!SdmcpSpiDataResponse(state, channel, device, state->Response)) return FALSE;
	UCHAR ErrorCode = (state->Response[0] >> 1) & 7;
	return (ErrorCode != 5) && (ErrorCode != 6);
}

static BOOLEAN SdmcpResponse1(PSDMC_STATE state, ULONG channel, ULONG device) {
	if (!SdmcpSpiReadResponse(state, channel, device, state->Response, 1)) return FALSE;
	return SdmcpCheckResponse(state, state->Response[0]);
}

static BOOLEAN SdmcpResponse2(PSDMC_STATE state, ULONG channel, ULONG device) {
	if (!SdmcpSpiReadResponse(state, channel, device, state->Response, 2)) {
		////DbgPrint("SdmcpResponse2: SdmcpSpiReadResponse failed\n");
		return FALSE;
	}
	////DbgPrint("SdmcpResponse2: %02x %02x\n", state->Response[0], state->Response[1]);
	return ((state->Response[0] & 0x7c) == 0) && ((state->Response[1] & 0x9e) == 0);
}

static BOOLEAN SdmcpResponse5(PSDMC_STATE state, ULONG channel, ULONG device) {
	if (!SdmcpSpiReadResponse(state, channel, device, state->Response, 5)) return FALSE;
	return SdmcpCheckResponse(state, state->Response[0]);
}

static BOOLEAN SdmcpSendCommandImpl1(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length) {
	if (!SdmcpSpiSendCommand(state, channel, device, buffer, length)) return FALSE;
	return SdmcpResponse1(state, channel, device);
}

static BOOLEAN SdmcpSendCommandImpl2(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length) {
	if (!SdmcpSpiSendCommand(state, channel, device, buffer, length)) return FALSE;
	return SdmcpResponse2(state, channel, device);
}

static BOOLEAN SdmcpSendCommandImpl5(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG length) {
	if (!SdmcpSpiSendCommand(state, channel, device, buffer, length)) return FALSE;
	return SdmcpResponse5(state, channel, device);
}

static BOOLEAN SdmcpSendAppCommand(PSDMC_STATE state, ULONG channel, ULONG device) {
	UCHAR command[5] = { 0x37, 0, 0, 0, 0 };
	BOOLEAN ret = SdmcpSendCommandImpl1(state, channel, device, command, sizeof(command));
#ifdef EXISDMC_DEBUG
	if (!ret) {
		printf("SdmcpSendAppCommand failed\r\n");
	}
#endif
	return ret;
}

static BOOLEAN SdmcpSendOpCond(PSDMC_STATE state, ULONG channel, ULONG device) {
	ULONG EndTime = currmsecs() + SDMC_TIMEOUT_MS;
	do {
		UCHAR command[5] = { 0, 0, 0, 0, 0 };
		if (state->InitType.Type == SDMC_TYPE_SDHC) {
			if (!SdmcpSendAppCommand(state, channel, device)) return FALSE;
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
			return FALSE;
		}
		
		if ((state->ErrorFlags & MMC_ERROR_IDLE) == 0) return TRUE;
	} while (currmsecs() < EndTime);

	// timed out, last chance
	UCHAR command[5] = { 0, 0, 0, 0, 0 };
	if (state->InitType.Type == SDMC_TYPE_SDHC) {
		if (!SdmcpSendAppCommand(state, channel, device)) return FALSE;
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
		return FALSE;
	}

	return (state->ErrorFlags & MMC_ERROR_IDLE) == 0;
}

static BOOLEAN SdmcpSendInitSdhc(PSDMC_STATE state, ULONG channel, ULONG device) {
	UCHAR command[5] = { 0x08, 0, 0, 0x01, 0xAA };
	BOOLEAN ret = SdmcpSendCommandImpl5(state, channel, device, command, sizeof(command));
	if (!ret) {
#ifdef EXISDMC_DEBUG
		printf("SdmcpSendInitSdhc cmd08 failed\r\n");
#endif
	}
	return ret;
}

static BOOLEAN SdmcpSendAddressModeSwitch(PSDMC_STATE state, ULONG channel, ULONG device) {
	UCHAR command[5] = { 0x3A, 0, 0, 0, 0 };
	BOOLEAN ret = SdmcpSendCommandImpl5(state, channel, device, command, sizeof(command));
	if (!ret) {
#ifdef EXISDMC_DEBUG
		printf("SdmcpSendAddressModeSwitch cmd3A failed\r\n");
#endif
	}
	return ret;
}

static BOOLEAN SdmcpSendToggleCrc(PSDMC_STATE state, ULONG channel, ULONG device, BOOLEAN crc_enabled) {
	UCHAR command[5] = { 0x3B, 0, 0, 0, (UCHAR)crc_enabled };
	BOOLEAN ret = SdmcpSendCommandImpl1(state, channel, device, command, sizeof(command));
	if (!ret) {
#ifdef EXISDMC_DEBUG
		printf("SdmcpSendInitSdhc cmd08 failed\r\n");
#endif
	}
	return ret;
}

static BOOLEAN SdmcpSendCommand(PSDMC_STATE state, ULONG channel, ULONG device, UCHAR command, PUCHAR arguments) {
	UCHAR commandBuf[5] = { command, 0, 0, 0, 0 };
	if (arguments != NULL) {
		commandBuf[1] = arguments[0];
		commandBuf[2] = arguments[1];
		commandBuf[3] = arguments[2];
		commandBuf[4] = arguments[3];
	}
	return SdmcpSpiSendCommand(state, channel, device, commandBuf, sizeof(commandBuf));
}

static BOOLEAN SdmcpSendCommand1(PSDMC_STATE state, ULONG channel, ULONG device, UCHAR command, PUCHAR arguments) {
	if (!SdmcpSendCommand(state, channel, device, command, arguments)) return FALSE;
	return SdmcpResponse1(state, channel, device);
}

static BOOLEAN SdmcpSendCommand2(PSDMC_STATE state, ULONG channel, ULONG device, UCHAR command, PUCHAR arguments) {
	if (!SdmcpSendCommand(state, channel, device, command, arguments)) return FALSE;
	return SdmcpResponse2(state, channel, device);
}

static BOOLEAN SdmcpSetSectorSize(PSDMC_STATE state, ULONG channel, ULONG device, ULONG sectorSize) {
	// maximum sector size is 0x200
	if (sectorSize > 0x200) sectorSize = 0x200;

	UCHAR command[5] = { 0x10, (UCHAR)(sectorSize >> 24), (UCHAR)(sectorSize >> 16), (UCHAR)(sectorSize >> 8), (UCHAR)sectorSize };
	BOOLEAN ret = SdmcpSendCommandImpl1(state, channel, device, command, sizeof(command));
	if (!ret) {
#ifdef EXISDMC_DEBUG
		printf("SdmcpSetSectorSize cmd10 failed\r\n");
#endif
	}
	state->SectorSize = sectorSize;

	return TRUE;
}

static BOOLEAN SdmcpReadCsd(PSDMC_STATE state, ULONG channel, ULONG device) {
	UCHAR command[5] = { 0x09, 0, 0, 0, 0 };
	if (!SdmcpSendCommandImpl1(state, channel, device, command, sizeof(command))) {
#ifdef EXISDMC_DEBUG
		printf("SdmcpReadCsd cmd09 failed\r\n");
#endif
		return FALSE;
	}
	return SdmcpSpiDataRead(state, channel, device, state->CSD, sizeof(state->CSD), FALSE);
}

static BOOLEAN SdmcpReadCid(PSDMC_STATE state, ULONG channel, ULONG device) {
	UCHAR command[5] = { 0x0A, 0, 0, 0, 0 };
	if (!SdmcpSendCommandImpl1(state, channel, device, command, sizeof(command))) {
#ifdef EXISDMC_DEBUG
		printf("SdmcpReadCid cmd0A failed\r\n");
#endif
		return FALSE;
	}
	return SdmcpSpiDataRead(state, channel, device, state->CID, sizeof(state->CID), FALSE);
}

static BOOLEAN SdmcpSdStatus(PSDMC_STATE state, ULONG channel, ULONG device) {
	ULONG oldSectorSize = state->SectorSize;
	if (state->SectorSize != 64) {
		if (!SdmcpSetSectorSize(state, channel, device, 64)) return FALSE;
	}

	BOOLEAN ret = FALSE;
	do {
		if (!SdmcpSendAppCommand(state, channel, device)) break;
		UCHAR commandBuf[5] = { 0x0d, 0, 0, 0, 0 };
		if (!SdmcpSendCommandImpl2(state, channel, device, commandBuf, sizeof(commandBuf))) break;
		if (!SdmcpSpiDataRead(state, channel, device, state->Status, sizeof(state->Status), FALSE)) break;
		ret = TRUE;
	} while (0);

	if (oldSectorSize != state->SectorSize) {
		if (!SdmcpSetSectorSize(state, channel, device, oldSectorSize)) return ret;
	}

	return ret;
}

static BOOLEAN SdmcpSoftReset(PSDMC_STATE state, ULONG channel, ULONG device) {
	while (TRUE) {
		if (!SdmcpSpiPowerOn(state, channel, device)) {
#ifdef EXISDMC_DEBUG
			printf("SdmcpSoftReset SpiPowerOn failed\r\n");
#endif
			return FALSE;
		}
		if (!SdmcpSpiReadResponse(state, channel, device, state->Response, 1)) {
			if (!state->InitType.DmaEnabled) return FALSE;
			state->InitType.DmaEnabled = FALSE;
			if (!SdmcpSpiReadResponse(state, channel, device, state->Response, 1)) continue;
		}
		if (!SdmcpCheckResponse(state, state->Response[0])) return FALSE;
		return SdmcpSendToggleCrc(state, channel, device, TRUE);
	}
}

static BOOLEAN SdmcpCheckInserted(PSDMC_STATE state, ULONG channel, ULONG device) {
	BOOLEAN ret = HalExiIsDevicePresent(channel, device);
	state->Inserted = ret;
	return ret;
}

static BOOLEAN SdmcpConvertSector(PSDMC_STATE state, ULONG sector, PUCHAR buffer) {
	if (state->ProtocolType == SDMC_OFFSET_BYTE) {
		if (sector >= 0x800000) return FALSE; // Byte-addressing can't address a sector past 4GB
		sector *= 0x200;
	}

	buffer[0] = (UCHAR)(sector >> 24);
	buffer[1] = (UCHAR)(sector >> 16);
	buffer[2] = (UCHAR)(sector >> 8);
	buffer[3] = (UCHAR)sector;

	return TRUE;
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

static BOOLEAN SdmcpUnmountDrive(PSDMC_STATE state, ULONG channel, ULONG device) {
	// these are unused now but may not be in future if we have to send a command/etc here
	(void)channel;
	(void)device;

	if (!state->Inserted) return TRUE;

	state->Inserted = FALSE;
	state->InitType.Value = 0;
	state->ProtocolType = SDMC_OFFSET_BYTE;
	state->ClockFreq = EXI_CLOCK_13_5;

	return TRUE;
}

static BOOLEAN SdmcpMountDriveLockedImpl(PSDMC_STATE state, ULONG channel, ULONG device) {
	// Check the EXI device ID. SD card returns all-FF.
	ULONG deviceId = 0;
	if (!NT_SUCCESS(HalExiGetDeviceIdentifier(channel, device, &deviceId))) return FALSE;
	if (deviceId != 0xFFFFFFFF) return FALSE;

	for (ULONG i = 0; i < 5; i++) {
		if (!SdmcpCheckInserted(state, channel, device)) return FALSE;

		BOOLEAN mounted = FALSE;
		do {
			state->WpFlag = FALSE;
			state->InitType.Value = 0;
			state->InitType.InitInProgress = TRUE;
			state->InitType.DmaEnabled = channel != 0; // EXI1/2 only have one device
			state->ProtocolType = SDMC_OFFSET_BYTE;
			state->ClockFreq = EXI_CLOCK_13_5;

			if (!SdmcpSoftReset(state, channel, device)) {
				state->WpFlag = TRUE;
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
			if (!SdmcpSendToggleCrc(state, channel, device, TRUE)) break;
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
			
			state->InitType.InitInProgress = FALSE;

			mounted = TRUE;
		} while (0);

		if (mounted) return TRUE;
		SdmcpUnmountDrive(state, channel, device);
	}

	return FALSE;
}

static EXI_LOCK_ACTION SdmcpMountDriveLocked(ULONG channel, PVOID context) {
	PSDMC_ASYNC_STATE_CONTEXT state = context;
	state->Result = SdmcpMountDriveLockedImpl(&s_SdmcState[state->Drive], channel, state->Device);
	KeSetEvent(&state->Event, (KPRIORITY)0, FALSE);
	return ExiUnlock;
}

static BOOLEAN SdmcpMountDrive(PSDMC_STATE state, ULONG channel, ULONG device, EXI_SDMC_DRIVE drive) {
	PSDMC_ASYNC_STATE_CONTEXT StateCtx = SdmcpGetStateContext(drive);
	if (StateCtx == NULL) return FALSE;
	StateCtx->Channel = channel;
	StateCtx->Device = device;
	
	NTSTATUS Status = HalExiLock(channel, SdmcpMountDriveLocked, StateCtx);
	if (!NT_SUCCESS(Status)) return FALSE;
	KeWaitForSingleObject( &StateCtx->Event, Executive, KernelMode, FALSE, NULL);
	BOOLEAN ret = StateCtx->Result;
	SdmcpReleaseStateContext(StateCtx);
	return ret;
}

static PSDMC_STATE SdmcpGetMountedState(EXI_SDMC_DRIVE drive) {
	if ((ULONG)drive >= SDMC_DRIVE_COUNT) return FALSE;
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
}

BOOLEAN SdmcexiIsMounted(EXI_SDMC_DRIVE drive) {
	return SdmcpGetMountedState(drive) != NULL;
}

BOOLEAN SdmcexiWriteProtected(EXI_SDMC_DRIVE drive) {
	PSDMC_STATE state = SdmcpGetMountedState(drive);
	if (state == NULL) return FALSE;

	UCHAR flags = state->CSD[14];
	// bit0: temp write protect, bit1: perm write protect
	UCHAR protectFlags = (flags >> 4) & 3;
	return (protectFlags != 0);
}

BOOLEAN SdmcexiMount(EXI_SDMC_DRIVE drive) {
	if ((ULONG)drive >= SDMC_DRIVE_COUNT) return FALSE;
	PSDMC_STATE state = &s_SdmcState[drive];

	if (state->Inserted && !state->InitType.InitInProgress && state->InitType.Type != SDMC_TYPE_UNUSABLE) {
		return TRUE;
	}

	ULONG channel = SdmcpGetExiChannel(drive);
	ULONG device = SdmcpGetExiDevice(drive);

	SdmcpUnmountDrive(state, channel, device);
	return SdmcpMountDrive(state, channel, device, drive);
}

ULONG SdmcexiSectorCount(EXI_SDMC_DRIVE drive) {
	if ((ULONG)drive >= SDMC_DRIVE_COUNT) return 0;
	return s_SdmcState[drive].SectorCount;
}

static ULONG SdmcpReadBlockLockedImpl(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG sector) {
	//DbgPrint("EXISD%d%d read %08x", channel, device, sector);
	PUCHAR buf8 = (PUCHAR)buffer;
	
	if (state->SectorSize != 0x200) {
		if (!SdmcpSetSectorSize(state, channel, device, 0x200)) {
			//DbgPrint("x\n");
			return 0;
		}
	}
	//DbgPrint(".");

	UCHAR Argument[4];
	if (!SdmcpConvertSector(state, sector, Argument)) {
		//DbgPrint("x\n");
		return 0;
	}
	//DbgPrint(".");

	if (!SdmcpSendCommand1(state, channel, device, 0x11, Argument)) {
		//DbgPrint("x\n");
		return 0;
	}
	//DbgPrint(".");
	
	ULONG readCount = 0;
	{
		if (!SdmcpSpiDataRead(state, channel, device, buf8, state->SectorSize, TRUE)) {
			//DbgPrint("x\n");
			return readCount;
		}
		//DbgPrint("o");
		buf8 += state->SectorSize;
		readCount++;
	}
	
	//DbgPrint("!\n");
	return readCount;
}

static ULONG SdmcpReadBlocksLockedImpl(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG sector, ULONG count) {
	if (count == 1) return SdmcpReadBlockLockedImpl(state, channel, device, buffer, sector);
	PUCHAR buf8 = (PUCHAR)buffer;
	//DbgPrint("EXISD%d%d read %08x-%08x", channel, device, sector, sector + count);
	
	#if 0
	ULONG readCount = 0;
	for (ULONG i = 0; i < count; i++) {
		ULONG thisCount = SdmcpReadBlockLockedImpl(state, channel, device, buf8, sector + i);
		if (thisCount == 0) break;
		buf8 += 0x200;
		readCount += thisCount;
	}
	return readCount;
	
	#else
	
	if (state->SectorSize != 0x200) {
		if (!SdmcpSetSectorSize(state, channel, device, 0x200)) {
			//DbgPrint("x\n");
			return 0;
		}
	}
	//DbgPrint(".");

	UCHAR Argument[4];
	if (!SdmcpConvertSector(state, sector, Argument)) {
		//DbgPrint("x\n");
		return 0;
	}
	//DbgPrint(".");

	if (!SdmcpSendCommand1(state, channel, device, 0x12, Argument)) {
		//DbgPrint("x\n");
		return 0;
	}
	//DbgPrint(".");
	ULONG readCount = 0;
	for (ULONG i = 0; i < count; i++) {
		if (!SdmcpSpiDataRead(state, channel, device, buf8, state->SectorSize, count == 1)) break;
		//DbgPrint("o");
		buf8 += 0x200;
		readCount++;
	}

	if (!SdmcpSendCommand(state, channel, device, 0x0C, NULL)) {
		//DbgPrint("x\n");
		return readCount;
	}
	//DbgPrint(".");
	if (!SdmcpStopResponse(state, channel, device)) {
		//DbgPrint("x\n");
		return readCount;
	}
	//DbgPrint("!\n");

	return readCount;
	#endif
}

static EXI_LOCK_ACTION SdmcpReadBlocksLocked(ULONG channel, PVOID context) {
	PSDMC_ASYNC_STATE_CONTEXT state = context;
	state->Sector = SdmcpReadBlocksLockedImpl(&s_SdmcState[state->Drive], channel, state->Device, state->Buffer, state->Sector, state->SectorCount);
	KeSetEvent(&state->Event, (KPRIORITY)0, FALSE);
	return ExiUnlock;
}

static ULONG SdmcpReadBlocks(PSDMC_STATE state, ULONG channel, ULONG device, EXI_SDMC_DRIVE drive, ULONG Sector, ULONG SectorCount, PVOID buffer) {
	PSDMC_ASYNC_STATE_CONTEXT StateCtx = SdmcpGetStateContext(drive);
	if (StateCtx == NULL) return FALSE;
	StateCtx->Channel = channel;
	StateCtx->Device = device;
	StateCtx->Sector = Sector;
	StateCtx->SectorCount = SectorCount;
	StateCtx->Buffer = buffer;
	
	NTSTATUS Status = HalExiLockNonpaged(channel, SdmcpReadBlocksLocked, StateCtx);
	if (!NT_SUCCESS(Status)) {
		SdmcpReleaseStateContext(StateCtx);
		return FALSE;
	}
	KeWaitForSingleObject( &StateCtx->Event, Executive, KernelMode, FALSE, NULL);
	ULONG ret = StateCtx->Sector;
	SdmcpReleaseStateContext(StateCtx);
	#if 0
	if (ret) {
		HalSweepDcacheRange(buffer, SectorCount * 0x200);
	}
	#endif
	return ret;
}

ULONG SdmcexiReadBlocks(EXI_SDMC_DRIVE drive, PVOID buffer, ULONG sector, ULONG count) {
	if (count == 0) return 0;

	PSDMC_STATE state = SdmcpGetMountedState(drive);
	if (state == NULL) return 0;
	#if 0
	ULONG bufferPage;
	PVOID mapBuffer = ExiAllocateBufferPage(&bufferPage);
	if (mapBuffer == NULL) return 0;

	ULONG channel = SdmcpGetExiChannel(drive);
	ULONG device = SdmcpGetExiDevice(drive);
	
	ULONG transferred = 0;
	PUCHAR buf8 = (PUCHAR)buffer;
	
	KIRQL OldIrql;
	
	while (count != 0) {
		// Transfer a page's worth of sectors using nonpaged map buffer with the EXI lock held
		ULONG IoCount = SDMC_SECTORS_IN_PAGE;
		if (count < SDMC_SECTORS_IN_PAGE) IoCount = count;
		ULONG TransferredIo = SdmcpReadBlocks(state, channel, device, drive, sector, IoCount, mapBuffer);
		if (TransferredIo == 0) break;
		
		// With the EXI lock not held, copy into output buffer and flush dcache.
		ULONG ByteCount = IoCount * 0x200;
		//KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
		RtlCopyMemory(buf8, mapBuffer, ByteCount);
		HalSweepDcacheRange(buf8, ByteCount);
		//KeLowerIrql(OldIrql);
		buf8 += ByteCount;
		sector += IoCount;
		transferred += IoCount;
		count -= IoCount;
	}
	
	ExiFreeBufferPage(bufferPage);

	return transferred;
	#else
		
	ULONG channel = SdmcpGetExiChannel(drive);
	ULONG device = SdmcpGetExiDevice(drive);
	
	return SdmcpReadBlocks(state, channel, device, drive, sector, count, buffer);
	#endif
}

static ULONG SdmcpWriteBlockLockedImpl(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG sector) {
	//DbgPrint("EXISD%d%d write %08x", channel, device, sector);
	PUCHAR buf8 = (PUCHAR)buffer;

	if (state->SectorSize != 0x200) {
		if (!SdmcpSetSectorSize(state, channel, device, 0x200)) {
			//DbgPrint("\nEXISDMC: writing sector %08x - SdmcpSetSectorSize failed\n", sector);
			return 0;
		}
	}
	//DbgPrint(".");

	UCHAR ArgSector[4];
	if (!SdmcpConvertSector(state, sector, ArgSector)) {
		//DbgPrint("\nEXISDMC: writing sector %08x - SdmcpConvertSector failed\n", sector);
		return 0;
	}
	//DbgPrint(".");

	if (!SdmcpSendCommand1(state, channel, device, 0x18, ArgSector)) {
			//DbgPrint("\nEXISDMC: writing sector %08x - SdmcpSendCommand1 failed\n", sector);
			return 0;
		}
	//DbgPrint(".");

	ULONG writeCount = 0;
	if (!SdmcpSpiDataWrite(state, channel, device, buf8, state->SectorSize)) {
			//DbgPrint("\nEXISDMC: writing sector %08x - SdmcpSpiDataWrite failed\n", sector);
			return 0;
		}
	//DbgPrint(".");
	if (!SdmcpDataResponse(state, channel, device)) {
			//DbgPrint("\nEXISDMC: writing sector %08x - SdmcpDataResponse failed\n", sector);
			return 0;
		}
	//DbgPrint(".");
	if (!SdmcpSendCommand2(state, channel, device, 0x0D, NULL)) {
			//DbgPrint("\nEXISDMC: writing sector %08x - SdmcpSendCommand2 failed\n", sector);
			return 0;
		}
	//DbgPrint("!\n");
	return 1;
}

static ULONG SdmcpWriteBlocksLockedImpl(PSDMC_STATE state, ULONG channel, ULONG device, PVOID buffer, ULONG sector, ULONG count) {
	if (count == 1) return SdmcpWriteBlockLockedImpl(state, channel, device, buffer, sector);
	
#if 0
	// something wrong with multiwrite
	PUCHAR buf8 = (PUCHAR)buffer;

	ULONG writeCount = 0;
	for (ULONG i = 0; i < count; i++) {
		KeStallExecutionProcessor(100);
		ULONG thisCount = SdmcpWriteBlockLockedImpl(state, channel, device, buf8, sector + i);
		if (thisCount == 0) break;
		buf8 += 0x200;
		writeCount++;
	}

	return writeCount;

#else
	//DbgPrint("EXISD%d%d write %08x-%08x", channel, device, sector, sector + count);
	PUCHAR buf8 = (PUCHAR)buffer;

	if (state->SectorSize != 0x200) {
		if (!SdmcpSetSectorSize(state, channel, device, 0x200)) {
			//DbgPrint("\nEXISD%d%d write SdmcpSetSectorSize failed\n", channel, device);
			return 0;
		}
	}
	//DbgPrint(".");

	UCHAR ArgSector[4];
	if (!SdmcpConvertSector(state, sector, ArgSector)) {
		//DbgPrint("\nEXISD%d%d write SdmcpConvertSector failed\n", channel, device);
		return 0;
	}
	//DbgPrint(".");

	UCHAR Argument[4] = {
		(UCHAR)(count >> 24),
		(UCHAR)(count >> 16),
		(UCHAR)(count >> 8),
		(UCHAR)count
	};
	if (!SdmcpSendAppCommand(state, channel, device)) {
		//DbgPrint("\nEXISD%d%d write SdmcpSendAppCommand failed\n", channel, device);
		return 0;
	}
	//DbgPrint(".");
	if (!SdmcpSendCommand1(state, channel, device, 0x17, Argument)) {
		//DbgPrint("\nEXISD%d%d write SdmcpSendCommand1 failed\n", channel, device);
		return 0;
	}
	//DbgPrint(".");

	if (!SdmcpSendCommand1(state, channel, device, 0x19, ArgSector)) {
		//DbgPrint("\nEXISD%d%d write SdmcpSendCommand1 failed\n", channel, device);
		return 0;
	}
	//DbgPrint(".");

	ULONG writeCount = 0;
	for (ULONG i = 0; i < count; i++) {
		if (!SdmcpSpiMultiDataWrite(state, channel, device, buf8, state->SectorSize)) {
			//DbgPrint("\nEXISD%d%d write SdmcpSpiMultiDataWrite failed\n", channel, device);
			break;
		}
		if (!SdmcpDataResponse(state, channel, device)) {
			//DbgPrint("\nEXISD%d%d write SdmcpDataResponse failed\n", channel, device);
			if (!SdmcpSendCommand(state, channel, device, 0x0C, NULL)) {
				//DbgPrint("\nEXISD%d%d write SdmcpSendCommand failed\n", channel, device);
				return writeCount;
			}
			if (!SdmcpStopResponse(state, channel, device)) return writeCount;{
				//DbgPrint("\nEXISD%d%d write SdmcpStopResponse failed\n", channel, device);
				return writeCount;
			}
			return writeCount;
		}
		//DbgPrint("o");
		buf8 += 0x200;
		writeCount++;
	}

	if (!SdmcpSpiMultiDataWriteStop(state, channel, device)) {
		//DbgPrint("\nEXISD%d%d write SdmcpSpiMultiDataWriteStop failed\n", channel, device);
		return writeCount;
	}
	//DbgPrint(".");
	if (!SdmcpSendCommand2(state, channel, device, 0x0D, NULL)) {
		//DbgPrint("\nEXISD%d%d write SdmcpSendCommand2 failed\n", channel, device);
		return writeCount;
	}

	//DbgPrint("!\n");
	return writeCount;
#endif
}

static EXI_LOCK_ACTION SdmcpWriteBlocksLocked(ULONG channel, PVOID context) {
	PSDMC_ASYNC_STATE_CONTEXT state = context;
	state->Sector = SdmcpWriteBlocksLockedImpl(&s_SdmcState[state->Drive], channel, state->Device, state->Buffer, state->Sector, state->SectorCount);
	KeSetEvent(&state->Event, (KPRIORITY)0, FALSE);
	return ExiUnlock;
}

static ULONG SdmcpWriteBlocks(PSDMC_STATE state, ULONG channel, ULONG device, EXI_SDMC_DRIVE drive, ULONG Sector, ULONG SectorCount, PVOID buffer) {
	PSDMC_ASYNC_STATE_CONTEXT StateCtx = SdmcpGetStateContext(drive);
	if (StateCtx == NULL) return FALSE;
	StateCtx->Channel = channel;
	StateCtx->Device = device;
	StateCtx->Sector = Sector;
	StateCtx->SectorCount = SectorCount;
	StateCtx->Buffer = buffer;
	
	//ExiInvalidateDcache(buffer, SectorCount * 0x200);
	
	NTSTATUS Status = HalExiLockNonpaged(channel, SdmcpWriteBlocksLocked, StateCtx);
	if (!NT_SUCCESS(Status)) {
		SdmcpReleaseStateContext(StateCtx);
		return FALSE;
	}
	KeWaitForSingleObject( &StateCtx->Event, Executive, KernelMode, FALSE, NULL);
	ULONG ret = StateCtx->Sector;
	SdmcpReleaseStateContext(StateCtx);
	return ret;
}

ULONG SdmcexiWriteBlocks(EXI_SDMC_DRIVE drive, PVOID buffer, ULONG sector, ULONG count) {
	if (count == 0) return 0;

	PSDMC_STATE state = SdmcpGetMountedState(drive);
	if (state == NULL) return 0;
	
	#if 0
	ULONG bufferPage;
	PVOID mapBuffer = ExiAllocateBufferPage(&bufferPage);
	if (mapBuffer == NULL) return 0;

	ULONG channel = SdmcpGetExiChannel(drive);
	ULONG device = SdmcpGetExiDevice(drive);
	
	ULONG transferred = 0;
	PUCHAR buf8 = (PUCHAR)buffer;
	
	KIRQL OldIrql;
	
	while (count != 0) {
		// Transfer a page's worth of sectors using nonpaged map buffer with the EXI lock held
		ULONG IoCount = SDMC_SECTORS_IN_PAGE;
		if (count < SDMC_SECTORS_IN_PAGE) IoCount = count;
		
		ULONG ByteCount = IoCount * 0x200;
		//KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
		ExiInvalidateDcache(buf8, ByteCount);
		RtlCopyMemory(mapBuffer, buf8, ByteCount);
		//KeLowerIrql(OldIrql);
		//HalSweepDcacheRange(mapBuffer, ByteCount);
		
		ULONG TransferredIo = SdmcpWriteBlocks(state, channel, device, drive, sector, IoCount, mapBuffer);
		if (TransferredIo == 0) break;
		
		// With the EXI lock not held, copy into output buffer and flush dcache.
		buf8 += ByteCount;
		sector += IoCount;
		transferred += IoCount;
		count -= IoCount;
	}
	
	ExiFreeBufferPage(bufferPage);

	return transferred;
	#else
	
	ULONG channel = SdmcpGetExiChannel(drive);
	ULONG device = SdmcpGetExiDevice(drive);
	
	return SdmcpWriteBlocks(state, channel, device, drive, sector, count, buffer);
	
	#endif
	
}
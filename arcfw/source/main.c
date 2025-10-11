#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include "arc.h"
#include "runtime.h"
#include "hwdesc.h"
#include "arcconfig.h"
#include "arcdisk.h"
#include "arcload.h"
#include "arcio.h"
#include "arcenv.h"
#include "arcterm.h"
#include "arcmem.h"
#include "arctime.h"
#include "arcconsole.h"
#include "arcfs.h"
#include "getstr.h"
//#include "ppchook.h"
#include "hwdesc.h"

#include "pxi.h"
#include "ios_sdmc.h"
#include "ios_usb.h"
#include "ios_usb_kbd.h"
#include "ios_usb_ms.h"
#include "si.h"
#include "si_kbd.h"
#include "exi.h"
#include "exi_sdmc.h"
#include "exi_ide.h"

#include "fatfs/ff.h"
#include "fatfs/diskio.h"

ULONG s_MacIoStart;

void ArcFwSetup(void);

static const PCHAR s_ArcErrors[] = {
	"Argument list is too long",
	"Access violation",
	"Resource temporarily unavailable",
	"Bad image file type",
	"Device is busy",
	"Fault occured",
	"Invalid argument",
	"Device error",
	"File is a directory",
	"Too many open files",
	"Too many links",
	"Name is too long",
	"Invalid device name",
	"The file or device does not exist",
	"Execute format error",
	"Not enough memory",
	"File is not a directory",
	"Inappropriate control operation",
	"Media not loaded",
	"Read-only file system"
};

PCHAR ArcGetErrorString(ARC_STATUS Status) {
	ULONG Idx = Status - 1;
	if (Idx > sizeof(s_ArcErrors) / sizeof(*s_ArcErrors)) return "";
	return s_ArcErrors[Status - 1];
}

extern size_t __FirmwareToVendorTable[];

static void ArcNotImplemented() {
	printf("\nUnimplemented ARC function called from %08x\n", (size_t)__builtin_return_address(0));
	while (1) {}
}

typedef struct ARC_LE {
	size_t Function;
	size_t Toc;
} FIRMWARE_CALLER;

static FIRMWARE_CALLER __FirmwareToVendorTable2[sizeof(FIRMWARE_VECTOR_TABLE) / sizeof(PVOID)];
extern void* _SDA2_BASE_;

bool g_UsbInitialised = false;
bool g_SdInitialised = false;

typedef char ARC_ENV_VAR[ARC_ENV_MAXIMUM_VALUE_SIZE];
typedef struct {
	ARC_ENV_VAR
		SystemPartition, OsLoader, OsLoadPartition, OsLoadFilename, OsLoadOptions, LoadIdentifier;
} BOOT_ENTRIES, *PBOOT_ENTRIES;

typedef struct {
	PCHAR SystemPartition, OsLoader, OsLoadPartition, OsLoadFilename, OsLoadOptions, LoadIdentifier;
} BOOT_ENTRY, *PBOOT_ENTRY;

enum {
	BOOT_ENTRY_MAXIMUM_COUNT = 5
};

static BOOT_ENTRIES s_BootEntries;
static BOOT_ENTRY s_BootEntryTable[BOOT_ENTRY_MAXIMUM_COUNT];
static ARC_ENV_VAR s_BootEntryChoices[BOOT_ENTRY_MAXIMUM_COUNT];
static BYTE s_BootEntryCount;

#if 0
static LONG s_hUsbHid = -1;
static LONG s_hUsbVen = -1;
#endif

static inline ARC_FORCEINLINE bool InitVariable(PVENDOR_VECTOR_TABLE Api, PCHAR Key, PCHAR Value, ULONG ValueLength) {
	PCHAR StaticValue = Api->GetEnvironmentRoutine(Key);
	if (StaticValue == NULL) return false;
	snprintf(Value, ValueLength, "%s", StaticValue);
	return true;
}

#define INIT_BOOT_VARIABLE(Key) InitVariable(Api, #Key, s_BootEntries . Key , sizeof( s_BootEntries . Key ))
#define INIT_BOOT_ARGV(Key, Str) snprintf(BootEntryArgv . Key, sizeof(BootEntryArgv . Key ), Str "=%s", s_BootEntryTable[DefaultChoice]. Key )

static bool SearchBootEntry(ULONG Index) {
	PCHAR* LastEntry = (PCHAR*)&s_BootEntryTable[Index - 1];
	PCHAR* ThisEntry = (PCHAR*)&s_BootEntryTable[Index];
	bool RetVal = true;
	for (int EntryIdx = 0; EntryIdx < sizeof(s_BootEntryTable[0]) / sizeof(s_BootEntryTable[0].LoadIdentifier); EntryIdx++) {
		PCHAR Entry = strchr(LastEntry[EntryIdx], ';');
		// even if one is not present, the rest still need to be cut
		if (Entry == NULL) {
			RetVal = false;
			ThisEntry[EntryIdx] = NULL;
			continue;
		}
		*Entry = 0;
		ThisEntry[EntryIdx] = Entry + 1;
	}
	return RetVal;
}

static bool InitBootEntriesImpl(PVENDOR_VECTOR_TABLE Api) {
	if (!INIT_BOOT_VARIABLE(SystemPartition)) return false;
	if (!INIT_BOOT_VARIABLE(OsLoader)) return false;
	if (!INIT_BOOT_VARIABLE(OsLoadPartition)) return false;
	if (!INIT_BOOT_VARIABLE(OsLoadFilename)) return false;
	if (!INIT_BOOT_VARIABLE(OsLoadOptions)) {
		// OsLoadOptions is not required. Ensure it's empty string.
		s_BootEntries.OsLoadOptions[0] = 0;
	}
	if (!INIT_BOOT_VARIABLE(LoadIdentifier)) return false;

	// Each boot variable is split by ";"
	// Handle up to five boot entries.
	// First one is always at the start.
	s_BootEntryTable[0].SystemPartition = s_BootEntries.SystemPartition;
	s_BootEntryTable[0].OsLoader = s_BootEntries.OsLoader;
	s_BootEntryTable[0].OsLoadPartition = s_BootEntries.OsLoadPartition;
	s_BootEntryTable[0].OsLoadFilename = s_BootEntries.OsLoadFilename;
	s_BootEntryTable[0].OsLoadOptions = s_BootEntries.OsLoadOptions;
	s_BootEntryTable[0].LoadIdentifier = s_BootEntries.LoadIdentifier;
	s_BootEntryCount = 1;
	// Search through all of them, looking for ';'. If it's not found in one var, then stop.
	for (int i = 1; i < sizeof(s_BootEntryTable) / sizeof(s_BootEntryTable[0]); i++) {
		if (!SearchBootEntry(i)) break;
		s_BootEntryCount++;
	}
	// Boot entries are now known. Initialise the menu choices.
	for (int i = 0; i < s_BootEntryCount; i++) {
		PBOOT_ENTRY Entry = &s_BootEntryTable[i];
		PCHAR EntryName = Entry->LoadIdentifier;
		if (*EntryName != 0) snprintf(s_BootEntryChoices[i], sizeof(s_BootEntryChoices[i]), "Start %s", EntryName);
		else {
			snprintf(s_BootEntryChoices[i], sizeof(s_BootEntryChoices[i]), "Start %s%s",
				Entry->OsLoadPartition, Entry->OsLoadFilename);
		}
	}
	return true;
}

static void InitBootEntries(PVENDOR_VECTOR_TABLE Api) {
	if (!InitBootEntriesImpl(Api)) {
		s_BootEntryCount = 0;
	}
}

static bool EnableTimeout(PVENDOR_VECTOR_TABLE Api) {
	PCHAR AutoLoad = Api->GetEnvironmentRoutine("AutoLoad");
	if (AutoLoad == NULL) return false;
	return (*AutoLoad == 'y' || *AutoLoad == 'Y');
}

static void ArcInitStdHandle(PVENDOR_VECTOR_TABLE Api, PCHAR Name, OPEN_MODE OpenMode, ULONG ExpectedHandle) {
	PCHAR Path = Api->GetEnvironmentRoutine(Name);
	if (Path == NULL) {
		printf("ARC firmware init failed: %s var was not set\n", Name);
		IOSKBD_ReadChar();
		Api->HaltRoutine();
	}
	U32LE DeviceId;
	ARC_STATUS Status = Api->OpenRoutine(Path, OpenMode, &DeviceId);
	if (ARC_FAIL(Status)) {
		printf("ARC firmware init failed: %s open error %s\n", Name, ArcGetErrorString(Status));
		IOSKBD_ReadChar();
		Api->HaltRoutine();
	}
	if (DeviceId.v != ExpectedHandle) {
		printf("ARC firmware init failed: %s expected fid=%d got %d\n", Name, ExpectedHandle, DeviceId.v);
		IOSKBD_ReadChar();
		Api->HaltRoutine();
	}
}

static void PrintDevices(ULONG DiskCount, ULONG CdromCount) {
	// hds first
	char PathName[ARC_ENV_MAXIMUM_VALUE_SIZE];
	for (ULONG Hd = 0; Hd < DiskCount; Hd++) {
		snprintf(PathName, sizeof(PathName), "hd%02d:", Hd);
		printf(" %s - %s\r\n", PathName, ArcEnvGetDevice(PathName));
		printf("  (Partitions: %d)\r\n", ArcDiskGetPartitionCount(Hd));
	}
	// then cds
	for (ULONG Cd = 0; Cd < CdromCount; Cd++) {
		snprintf(PathName, sizeof(PathName), "cd%02d:", Cd);
		printf(" %s - %s\r\n", Cd == 0 ? "cd:" : PathName, ArcEnvGetDevice(PathName));
	}
	// then ramdisk
	//if (s_RuntimeRamdisk.Buffer.Length != 0) printf(" drivers.img ramdisk loaded\r\n");
	// then syspart
	PCHAR SysPart = s_BootEntries.SystemPartition;
	if (SysPart[0] != 0) printf(" System partition: %s\r\n", SysPart);
}

static bool s_RamdiskLoaded = false;

bool ArcHasRamdiskLoaded(void) {
	return s_RamdiskLoaded;
}

PVOID ArcGetRamDisk(PULONG Length) {
#if 0
	*Length = s_RuntimeRamdisk.Buffer.Length;
	return (PVOID)(s_RuntimeRamdisk.Buffer.PointerArc | 0x80000000);
#endif
	return NULL;
}

void ArcInitRamDisk(ULONG ControllerKey, PVOID Pointer, ULONG Length) {
#if 0
	s_RuntimeRamdisk.ControllerKey = ControllerKey;
	s_RuntimeRamdisk.Buffer.PointerArc = (ULONG)Pointer & ~0x80000000;
	s_RuntimeRamdisk.Buffer.Length = Length;

	s_RuntimePointers[RUNTIME_RAMDISK].v = (ULONG)&s_RuntimeRamdisk;
	s_RamdiskLoaded = true;
#endif
}

static void ArcMain() {
	// Initialise the ARC firmware.
	PSYSTEM_PARAMETER_BLOCK Spb = ARC_SYSTEM_TABLE();
	size_t CurrentAddress = ARC_SYSTEM_TABLE_ADDRESS;
	// Zero out the entire block of memory used for the system table, before initialising fields.
	// Runtime block is at SYSTEM_TABLE_ADDRESS + PAGE_SIZE, so only zero out one page.
	memset(Spb, 0, PAGE_SIZE);
	Spb->Signature = ARC_SYSTEM_BLOCK_SIGNATURE;
	Spb->Length = sizeof(*Spb);
	Spb->Version = ARC_VERSION_MAJOR;
	Spb->Revision = ARC_VERSION_MINOR;

	// Restart block.
	CurrentAddress += sizeof(*Spb);
	ARC_SYSTEM_TABLE_LE()->RestartBlock = (CurrentAddress);
	// TODO: multiprocessor support

	// Firmware vectors.
	CurrentAddress += sizeof(Spb->RestartBlock[0]);
	ARC_SYSTEM_TABLE_LE()->FirmwareVector = (CurrentAddress);
	PLITTLE_ENDIAN32 FirmwareVector = (PLITTLE_ENDIAN32)CurrentAddress;
	Spb->FirmwareVectorLength = sizeof(Spb->FirmwareVector[0]);

	// Vendor vectors.
	// This implementation sets the vendor vectors to the big-endian firmware vendor function pointers.
	CurrentAddress += sizeof(Spb->FirmwareVector[0]);
	ARC_SYSTEM_TABLE_LE()->VendorVector = (CurrentAddress);
	PVENDOR_VECTOR_TABLE Api = (PVENDOR_VECTOR_TABLE)CurrentAddress;
	Spb->VendorVectorLength = sizeof(Spb->VendorVector[0]);
	// Initialise all vendor vectors to not implemented stub.
	for (int i = 0; i < sizeof(Spb->VendorVector[0]) / sizeof(PVOID); i++) {
		PVOID* vec = (PVOID*)CurrentAddress;
		vec[i] = ArcNotImplemented;
	}

	// Initialise sub-components.
	ArcMemInit();
	ArcTermInit();
	ArcEnvInit();
	ArcLoadInit();
	ArcConfigInit();
	ArcIoInit();
	ArcDiskInit();
	ArcTimeInit();

	// Load environment from USB HD if needed.
	ArcEnvLoad();

#if 0 // Already checked by stage1
	// Ensure we have valid decrementer frequency
	if (s_RuntimePointers[RUNTIME_DECREMENTER_FREQUENCY].v == 0) {
		printf("%s", "ARC firmware init failed: could not obtain decrementer frequency\r\n");
		IOSKBD_ReadChar();
		Api->HaltRoutine();
	}
#endif

	// stdout must be file id 0, stdin must be file id 1
	ArcInitStdHandle(Api, "consolein", ArcOpenReadOnly, 0);
	ArcInitStdHandle(Api, "consoleout", ArcOpenWriteOnly, 1);

	// Initialise all firmware vectors using the required calling convention.
	size_t* _OriginalVector = (size_t*)Api;
	_Static_assert(sizeof(VENDOR_VECTOR_TABLE) == sizeof(FIRMWARE_VECTOR_TABLE));
	for (int i = 0; i < sizeof(Spb->FirmwareVector[0]) / sizeof(PVOID); i++) {
		__FirmwareToVendorTable2[i].Function = _OriginalVector[i];
		__FirmwareToVendorTable2[i].Toc = (size_t)&_SDA2_BASE_;
		FirmwareVector[i].v = (size_t)&__FirmwareToVendorTable2[i];
	}

	// Set up the runtime pointer address.
	ARC_SYSTEM_TABLE_LE()->RuntimePointers = (ULONG)s_RuntimePointers;


	// Main loop.
	ULONG DiskCount, CdromCount;
	ArcDiskGetCounts(&DiskCount, &CdromCount);
	ULONG DefaultChoice = 0;
	bool Timeout = true;
	while (1) {
		// Initialise the boot entries.
		InitBootEntries(Api);

		// Initialise the menu.
		PCHAR MenuChoices[BOOT_ENTRY_MAXIMUM_COUNT + 4] = { 0 };
		ULONG NumberOfMenuChoices = s_BootEntryCount + 4;
		for (int i = 0; i < s_BootEntryCount; i++) {
			MenuChoices[i] = s_BootEntryChoices[i];
		}

		MenuChoices[s_BootEntryCount] = "Run a program";
		MenuChoices[s_BootEntryCount + 1] = "Run NT setup from cd00";
		MenuChoices[s_BootEntryCount + 2] = "Run firmware setup";
		MenuChoices[s_BootEntryCount + 3] = "Restart system";

		if (DefaultChoice >= NumberOfMenuChoices) DefaultChoice = NumberOfMenuChoices - 1;

		// Display the menu.
		ArcSetScreenColour(ArcColourWhite, ArcColourBlue);
		ArcSetScreenAttributes(true, false, false);
		ArcClearScreen();
		ArcSetPosition(3, 0);
		printf(" Actions:\n");

		for (int i = 0; i < NumberOfMenuChoices; i++) {
			ArcSetPosition(i + 5, 5);

			if (i == DefaultChoice) ArcSetScreenAttributes(true, false, true);
			
			printf("%s", MenuChoices[i]);
			ArcSetScreenAttributes(true, false, false);
		}

		ArcSetPosition(NumberOfMenuChoices + 6, 0);

		printf(" Use the arrow keys to select.\r\n");
		printf(" Press Enter to choose.\r\n");
		printf("\r\n\n");
		printf("Detected block I/O devices:\r\n");
		PrintDevices(DiskCount, CdromCount);

		LONG Countdown = 5;
		ULONG PreviousTime = 0;
		static const char s_TimeoutMsg[] = " Seconds until auto-boot, select another option to override: ";
		if (Timeout) {
			Timeout = s_BootEntryCount != 0 && EnableTimeout(Api);
			if (Timeout) {
				ArcSetPosition(NumberOfMenuChoices + 8, 0);
				PCHAR CountdownEnv = Api->GetEnvironmentRoutine("Countdown");
				if (CountdownEnv != NULL) {
					LONG CountdownConv = atoi(CountdownEnv);
					if (CountdownConv != 0) Countdown = CountdownConv;
				}
				printf("%s%d ", s_TimeoutMsg, Countdown);
				PreviousTime = Api->GetRelativeTimeRoutine();
			}
		}

		// Implement the menu UI.
		UCHAR Character = 0;
		do {
			if (IOSKBD_CharAvailable()) {
				Character = IOSKBD_ReadChar();
				switch (Character) {
				case 0x1b:
					Character = IOSKBD_ReadChar();
					if (Character != '[') break;
					// fall-through: \x1b[ == \x9b
				case 0x9b:
					Character = IOSKBD_ReadChar();
					ArcSetPosition(DefaultChoice + 5, 5);
					printf("%s", MenuChoices[DefaultChoice]);

					switch (Character) {
					case 'A': // Up arrow
					case 'D': // Left arrow
						if (DefaultChoice == 0) DefaultChoice = NumberOfMenuChoices;
						DefaultChoice--;
						break;
					case 'B': // Down arrow
					case 'C': // Right arrow
						DefaultChoice++;
						if (DefaultChoice >= NumberOfMenuChoices) DefaultChoice = 0;
						break;
					case 'H': // Home
						DefaultChoice = 0;
						break;

					default:
						break;
					}

					ArcSetPosition(DefaultChoice + 5, 5);
					ArcSetScreenAttributes(true, false, true);
					printf("%s", MenuChoices[DefaultChoice]);
					ArcSetScreenAttributes(true, false, false);
					continue;

				// other ARC firmware can support 'D'/'d' to break on load
				// other ARC firmware can support 'K'/'k'/sysrq to enable kd

				default:
					break;
				}
			}

			// if menu option got moved, cancel the timeout
			if (Timeout && DefaultChoice != 0) {
				Timeout = false;
				ArcSetPosition(NumberOfMenuChoices + 8, 0);
				printf("%s", "\x1B[2K");
			}

			// if the timeout is active then update it
			if (Timeout) {
				ULONG RelativeTime = Api->GetRelativeTimeRoutine();
				if (RelativeTime != PreviousTime) {
					PreviousTime = RelativeTime;
					Countdown--;
					ArcSetPosition(NumberOfMenuChoices + 8, 0);
					printf("%s", "\x1B[2K");
					printf("%s%d ", s_TimeoutMsg, Countdown);
				}
			}
		} while ((Character != '\n') && (Character != '\r') && (Countdown >= 0));

		// Clear the menu.
		for (int i = 0; i < NumberOfMenuChoices; i++) {
			ArcSetPosition(i + 5, 5);
			printf("%s", "\x1B[2K");
		}

		// Execute the selected option.
		if (DefaultChoice == s_BootEntryCount + 3) {
			Api->RestartRoutine();
			ArcClearScreen();
			ArcSetPosition(5, 5);
			ArcSetScreenColour(ArcColourCyan, ArcColourBlack);
			printf("\r\n ArcRestart() failed, halting...");
			ArcSetScreenColour(ArcColourWhite, ArcColourBlue);
			while (1) {}
		}
		if (DefaultChoice == s_BootEntryCount + 2) {
			// Firmware setup.
			ArcClearScreen();
			ArcFwSetup();
			continue;
		}

		char PathName[ARC_ENV_MAXIMUM_VALUE_SIZE];
		PCHAR TempArgs = NULL;

		if (DefaultChoice == s_BootEntryCount + 1) {
			PCHAR EnvironmentValue = ArcEnvGetDevice("cd00:");
			if (EnvironmentValue == NULL) {
				ArcSetPosition(7, 0);
				ArcSetScreenColour(ArcColourCyan, ArcColourBlack);
				printf(" Path cannot be resolved");
				ArcSetScreenColour(ArcColourWhite, ArcColourBlue);
				Character = IOSKBD_ReadChar();
				continue;
			}

			snprintf(PathName, sizeof(PathName), "%s\\%s", EnvironmentValue, "ppc\\setupldr");
		}
		else {
			char TempName[ARC_ENV_MAXIMUM_VALUE_SIZE];
			if (DefaultChoice == s_BootEntryCount) {
				// User-specified program.
				ArcClearScreen();
				// Get the path.
				static const char s_PrgRunText[] = "Program to run: ";
				ArcSetPosition(5, 5);
				printf(s_PrgRunText);
				GETSTRING_ACTION Action;
				do {
					Action = KbdGetString(TempName, sizeof(TempName), NULL, 5, 5 + sizeof(s_PrgRunText) - 1);
				} while (Action != GetStringEscape && Action != GetStringSuccess);

				// Go back to menu if no path was specified.
				if (TempName[0] == 0) continue;

				// Grab the arguments.
				TempArgs = strchr(TempName, ' ');
				if (TempArgs == NULL) TempArgs = "";
				else {
					*TempArgs = 0;
					TempArgs++;
				}

				// If the name does not contain '(', then it's not an ARC path and needs to be resolved.
				if (strchr(TempName, '(') == NULL) {
					PCHAR Colon = strchr(TempName, ':');
					if (Colon != NULL) {
						// Copy out and convert to lower case.
						int i = 0;
						for (; TempName[i] != ':'; i++) {
							char Character = TempName[i];
							if (Character >= 'A' && Character <= 'Z') Character |= 0x20;
							PathName[i] = Character;
						}
						PathName[i] = ':';
						PathName[i + 1] = 0;

						// Get the env var.
						PCHAR EnvironmentValue = NULL;
						// First, check for "cd:", and instead use "cd00:", the first optical drive detected by the disk sub-component.
						if (PathName[0] == 'c' && PathName[1] == 'd' && PathName[2] == ':' && PathName[3] == 0) {
							EnvironmentValue = ArcEnvGetDevice("cd00:");
						}
						else {
							// Otherwise, use the drive name as obtained.
							EnvironmentValue = ArcEnvGetDevice(PathName);
						}

						if (EnvironmentValue == NULL || Colon[1] != '\\') {
							ArcSetPosition(7, 0);
							ArcSetScreenColour(ArcColourCyan, ArcColourBlack);
							printf(" Path cannot be resolved");
							ArcSetScreenColour(ArcColourWhite, ArcColourBlue);
							Character = IOSKBD_ReadChar();
							continue;
						}

						snprintf(PathName, sizeof(PathName), "%s\\%s", EnvironmentValue, &Colon[2]);
					}
					else {
						ArcSetPosition(7, 0);
						ArcSetScreenColour(ArcColourCyan, ArcColourBlack);
						printf(" Path cannot be resolved");
						ArcSetScreenColour(ArcColourWhite, ArcColourBlue);
						Character = IOSKBD_ReadChar();
						continue;
					}
				}
				else {
					// Looks like a full ARC path, use it.
					snprintf(PathName, sizeof(PathName), "%s", TempName);
				}
			}
			else {
				// Boot entry chosen, use it.
				snprintf(PathName, sizeof(PathName), "%s", s_BootEntryTable[DefaultChoice].OsLoader);
			}
		}

		// Get the environment table.
		PCHAR LoadEnvp[20];
		LoadEnvp[0] = (PCHAR) ArcEnvGetVars();

		if (LoadEnvp[0] != NULL) {
			// Fill up the table.
			ULONG Index = 0;
			while (Index < 19 && *LoadEnvp[Index]) {
				ULONG Next = Index + 1;
				LoadEnvp[Next] = LoadEnvp[Index] + strlen(LoadEnvp[Index]) + 1;
				Index = Next;
			}

			// Last one set to NULL
			LoadEnvp[Index] = NULL;
		}

		PCHAR LoadArgv[8];
		LoadArgv[0] = PathName;
#if 0 // We can't read HFS partitions either :)
		// HACK:
		// osloader can't read HFS partitions.
		// Open the raw drive, if it looks like an ISO (ISO/HFS hybrid) then pass partition(0) (raw drive) as argv[0]
		char ArgvPathName[ARC_ENV_MAXIMUM_VALUE_SIZE];
		strcpy(ArgvPathName, PathName);
		do {
			PCHAR partition = strstr(ArgvPathName, "partition(");
			if (partition == NULL) break;
			partition += (sizeof("partition(") - 1);
			if (*partition != ')' && *partition != '0') *partition = '0';
			PCHAR filepath = strchr(ArgvPathName, '\\');
			if (filepath == NULL) break;
			*filepath = 0;
			U32LE DeviceId;
			if (ARC_FAIL(Api->OpenRoutine(ArgvPathName, ArcOpenReadOnly, &DeviceId))) break;
			do {
				// Seek to sector 0x10
				LARGE_INTEGER Offset = INT64_TO_LARGE_INTEGER(0x800 * 0x10);
				if (ARC_FAIL(Api->SeekRoutine(DeviceId.v, &Offset, SeekAbsolute))) break;
				// Read single sector
				UCHAR IsoSector[2048];
				U32LE Count = { 0 };
				if (ARC_FAIL(Api->ReadRoutine(DeviceId.v, IsoSector, sizeof(IsoSector), &Count)) && Count.v == sizeof(IsoSector)) break;
				// If bytes 0x1fe-1ff are not printable ascii, this isn't an ISO image.
				// Technically, some printable ascii characters are disallowed;
				// this is intended to ensure a backup MBR in this position that also "looks like an ISO" is disallowed. 
				if (IsoSector[0x1fe] < 0x20 || IsoSector[0x1fe] > 0x7f) break;
				if (IsoSector[0x1ff] < 0x20 || IsoSector[0x1fe] > 0x7f) break;
				// Check for identifiers at the correct offset: ISO9660, HSF/High Sierra
				if (!memcmp(&IsoSector[1], "CD001", sizeof("CD001") - 1) || !memcmp(&IsoSector[9], "CDROM", sizeof("CDROM") - 1)) {
					// This looks like an ISO.
					*filepath = '\\';
					LoadArgv[0] = ArgvPathName;
				}
			} while (false);
			Api->CloseRoutine(DeviceId.v);
		} while (false);
#endif
		ULONG ArgCount = 1;
		// Load the standard arguments if needed.
		if (DefaultChoice < s_BootEntryCount) {
			static BOOT_ENTRIES BootEntryArgv = { 0 };
			INIT_BOOT_ARGV(OsLoader, "OSLOADER");
			INIT_BOOT_ARGV(SystemPartition, "SYSTEMPARTITION");
			INIT_BOOT_ARGV(OsLoadFilename, "OSLOADFILENAME");
			INIT_BOOT_ARGV(OsLoadPartition, "OSLOADPARTITION");
			INIT_BOOT_ARGV(OsLoadOptions, "OSLOADOPTIONS");

			LoadArgv[1] = BootEntryArgv.OsLoader;
			LoadArgv[2] = BootEntryArgv.SystemPartition;
			LoadArgv[3] = BootEntryArgv.OsLoadFilename;
			LoadArgv[4] = BootEntryArgv.OsLoadPartition;
			LoadArgv[5] = BootEntryArgv.OsLoadOptions;
			LoadArgv[6] = NULL;
			LoadArgv[7] = NULL;

			// Look through the environment to find consolein and consoleout
			for (ULONG Index = 0; (LoadArgv[6] == NULL || LoadArgv[7] == NULL) && LoadEnvp[Index] != NULL; Index++) {
				static const char s_ConsoleIn[] = "CONSOLEIN=";
				static const char s_ConsoleOut[] = "CONSOLEOUT=";

				if (LoadArgv[6] == NULL && memcmp(LoadEnvp[Index], s_ConsoleIn, sizeof(s_ConsoleIn) - 1) == 0)
					LoadArgv[6] = LoadEnvp[Index];

				if (LoadArgv[7] == NULL && memcmp(LoadEnvp[Index], s_ConsoleOut, sizeof(s_ConsoleOut) - 1) == 0)
					LoadArgv[7] = LoadEnvp[Index];
			}

			if (LoadArgv[7] != NULL && LoadArgv[6] == NULL) {
				LoadArgv[6] = LoadArgv[7];
				LoadArgv[7] = NULL;
				ArgCount = 7;
			}
			else if (LoadArgv[6] == NULL) ArgCount = 6;
			else if (LoadArgv[7] == NULL) ArgCount = 7;
			else ArgCount = 8;
		}
		else if (TempArgs != NULL) {
			// Set up argv based on the given cmdline.
			ULONG Index = 0;

			for (Index = 0; TempArgs[Index] && ArgCount < sizeof(LoadArgv) / sizeof(*LoadArgv); Index++) {
				if (TempArgs[Index] == ' ') TempArgs[Index] = 0;
				else {
					if (Index != 0 && TempArgs[Index - 1] == 0) {
						LoadArgv[ArgCount] = &TempArgs[Index];
						ArgCount++;
					}
				}
			}
		}

		// If the file can not be opened, add .exe extension
		U32LE FileId;
		if (ARC_FAIL(Api->OpenRoutine(PathName, ArcOpenReadOnly, &FileId))) {
			strcat(PathName, ".exe");
		}
		else {
			Api->CloseRoutine(FileId.v);
		}

		// Run the executable.
		ArcClearScreen();
		ARC_STATUS Status = Api->ExecuteRoutine(PathName, ArgCount, LoadArgv, LoadEnvp);

		if (ARC_SUCCESS(Status)) {
			printf("\n Press any key to continue...\n");
			IOSKBD_ReadChar();
		}
		else {
			ArcSetScreenColour(ArcColourCyan, ArcColourBlack);
			printf("\n Error: ");
			if (Status <= _EROFS) {
				printf("%s", s_ArcErrors[Status - 1]);
			}
			else {
				printf("Error code = %d", Status);
			}
			printf("\n Press any key to continue...\n");
			ArcSetScreenColour(ArcColourWhite, ArcColourBlue);
			IOSKBD_ReadChar();
		}
	}
}

static void ARC_NORETURN FwEarlyPanic(const char* error) {
	printf("%s\r\n%s\r\n", error, "System halting.");
	while (1);
}

#if 1 // Old driver test code
static void ARC_NORETURN KbdTest(void) {
	printf("Keyboard driver test:\r\n");
	while (1) {
		static const char s_ControlChars[] = "PQwxtuqrpMAB";
		UCHAR Character;
		if (IOSKBD_CharAvailable()) {
			Character = IOSKBD_ReadChar();

		AfterRead:
			switch (Character) {
			case 0x1b:
				Character = IOSKBD_ReadChar();
				if (Character != '[') {
					printf("[esc] ");
					goto AfterRead;
				}
				// fall-through: \x1b[ == \x9b
			case 0x9b:
				Character = IOSKBD_ReadChar();

				switch (Character) {
				case 'A': // Up arrow
					printf("[up] ");
					break;
				case 'D': // Left arrow
					printf("[left] ");
					break;
				case 'B': // Down arrow
					printf("[down] ");
					break;
				case 'C': // Right arrow
					printf("[right] ");
					break;
				case 'H': // Home
					printf("[home] ");
					break;
				case 'K': // End
					printf("[end] ");
					break;
				case '?': // pgup
					printf("[pgup] ");
					break;
				case '/': // pgdn
					printf("[pgdn] ");
					break;
				case '@': // insert
					printf("[ins] ");
					break;
				case 'P': // delete
					printf("[del] ");
					break;
				case 'O': // F-key
				{
					Character = IOSKBD_ReadChar();
					UCHAR index = 0;
					for (; index < sizeof(s_ControlChars); index++) {
						if (s_ControlChars[index] == 0) break;
						if (s_ControlChars[index] == Character) break;
					}

					if (s_ControlChars[index] == 0) break;
					printf("[F%d] ", index + 1);
					break;
				}

				default:
					break;
				}

				continue;

				// other ARC firmware can support 'D'/'d' to break on load
				// other ARC firmware can support 'K'/'k'/sysrq to enable kd

			default:
				printf("%c", Character);
				if (Character == '\n') printf("\r");
				break;
			}
		}
	}
}


static void ARC_NORETURN ExiTest(void) {
	static UCHAR ExiDmaBuf[0x200] ARC_ALIGNED(32) = { 0 };
	printf("EXI driver test\r\n");

	ULONG deviceId = 0;
	if (!ExiGetDeviceIdentifier(0, EXI_CHAN0_DEVICE_MEMCARD, &deviceId)) {
		printf("Could not get device id\r\n");
		while (1);
	}

	printf("Device ID is 0x%08x\r\n", deviceId);
	if ((deviceId >> 16) != 0) {
		printf("Device in memcard#1 is not a memory card\r\n");
		while (1);
	}

	if (!ExiSelectDevice(0, EXI_CHAN0_DEVICE_MEMCARD, EXI_CLOCK_13_5, false)) {
		printf("Could not select EXI0CS0\r\n");
		while (1);
	}

	bool done = false;
	do {
		// try reading block 0. this won't work with official card, but should be fine for testing DMA
		if (!ExiTransferImmediate(0, 0x52, 1, EXI_TRANSFER_WRITE, NULL)) {
			printf("Could not send write command\r\n");
			break;
		}
		if (!ExiTransferImmediate(0, 0, 4, EXI_TRANSFER_WRITE, NULL)) {
			printf("Could not send write offset\r\n");
			break;
		}
		if (!ExiTransferImmediate(0, 0, 4, EXI_TRANSFER_WRITE, NULL)) {
			printf("Could not send write offset\r\n");
			break;
		}
		if (!ExiTransferDma(0, ExiDmaBuf, sizeof(ExiDmaBuf), EXI_TRANSFER_READ, EXI_SWAP_OUTPUT)) {
			printf("Could not DMA-read sector\r\n");
			break;
		}

		done = true;
	} while (0);

	if (!ExiUnselectDevice(0)) {
		printf("Could not release CS lines on EXI0\r\n");
		while (1);
	}

	// Try getting the device identifer but using ExiTransferImmediateBuffer
	if (!ExiSelectDevice(0, EXI_CHAN0_DEVICE_MEMCARD, EXI_CLOCK_0_8, false)) {
		printf("Could not select EXI0CS0\r\n");
		while (1);
	}

	UCHAR cmd_device_id[2] = { 0,0 };
	if (!ExiTransferImmediateBuffer(0, cmd_device_id, NULL, sizeof(cmd_device_id), EXI_TRANSFER_WRITE)) {
		printf("Could not get device id by ExiTransferImmediateBuffer [W]\r\n");
		while (1);
	}
	ULONG deviceId2 = 0;
	if (!ExiTransferImmediateBuffer(0, NULL, &deviceId2, sizeof(deviceId2), EXI_TRANSFER_READ)) {
		printf("Could not get device id by ExiTransferImmediateBuffer [R]\r\n");
		while (1);
	}

	deviceId2 = __builtin_bswap32(deviceId2);
	printf("Device ID is 0x%08x\r\n", deviceId2);
	if (deviceId != deviceId2) {
		printf("Device ID was different from previously read\r\n");
		while (1);
	}

	if (done) {
		printf("EXI test complete, sector0 header:\r\n");
		for (ULONG i = 0; i < 0x30; i += 0x10) {
			printf("%02x %02x %02x %02x %02x %02x %02x %02x ",
				ExiDmaBuf[i + 0], ExiDmaBuf[i + 1], ExiDmaBuf[i + 2], ExiDmaBuf[i + 3],
				ExiDmaBuf[i + 4], ExiDmaBuf[i + 5], ExiDmaBuf[i + 6], ExiDmaBuf[i + 7]);
			ULONG j = i + 8;
			printf("%02x %02x %02x %02x %02x %02x %02x %02x\r\n",
				ExiDmaBuf[j + 0], ExiDmaBuf[j + 1], ExiDmaBuf[j + 2], ExiDmaBuf[j + 3],
				ExiDmaBuf[j + 4], ExiDmaBuf[j + 5], ExiDmaBuf[j + 6], ExiDmaBuf[j + 7]);
		}
	}
	while (1);
}

static void ARC_NORETURN ExiSdmcTest(void) {
	static UCHAR ExiDmaBuf[0x200] ARC_ALIGNED(32) = { 0 };
	printf("EXISDMC driver test\r\n");

	static const char s_ExiDevices[][4] = {
		{ 'M', 'C', 'A', 0 },
		{ 'M', 'C', 'B', 0 },
		{ 'S', 'P', '1', 0 },
		{ 'S', 'P', '2', 0 }
	};

	// Find the first exi_sdmc device that got mounted
	EXI_SDMC_DRIVE drive;

	for (ULONG i = 0; i < 4; i++) {
		drive = (EXI_SDMC_DRIVE)i;
		bool mounted = SdmcexiIsMounted(drive);
		printf("EXISDMC: drive %s is %spresent\r\n", s_ExiDevices[i], mounted ? "" : "not ");
		if (mounted) break;
		if (i == 3) {
			printf("EXISDMC: no drive is present\r\n");
			while (1);
		}
	}

	// Attempt to read sector 0.
	if (SdmcexiReadBlocks(drive, ExiDmaBuf, 0, 1) == 0) {
		printf("EXISDMC: could not read sector 0\r\n");
		while (1);
	}

	printf("EXISDMC test complete, sector0 header(0x50)/footer(0x50):\r\n");
	for (ULONG i = 0; i < 0x50; i += 0x10) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x ",
			ExiDmaBuf[i + 0], ExiDmaBuf[i + 1], ExiDmaBuf[i + 2], ExiDmaBuf[i + 3],
			ExiDmaBuf[i + 4], ExiDmaBuf[i + 5], ExiDmaBuf[i + 6], ExiDmaBuf[i + 7]);
		ULONG j = i + 8;
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\r\n",
			ExiDmaBuf[j + 0], ExiDmaBuf[j + 1], ExiDmaBuf[j + 2], ExiDmaBuf[j + 3],
			ExiDmaBuf[j + 4], ExiDmaBuf[j + 5], ExiDmaBuf[j + 6], ExiDmaBuf[j + 7]);
	}
	for (ULONG i = 0x1B0; i < 0x200; i += 0x10) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x ",
			ExiDmaBuf[i + 0], ExiDmaBuf[i + 1], ExiDmaBuf[i + 2], ExiDmaBuf[i + 3],
			ExiDmaBuf[i + 4], ExiDmaBuf[i + 5], ExiDmaBuf[i + 6], ExiDmaBuf[i + 7]);
		ULONG j = i + 8;
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\r\n",
			ExiDmaBuf[j + 0], ExiDmaBuf[j + 1], ExiDmaBuf[j + 2], ExiDmaBuf[j + 3],
			ExiDmaBuf[j + 4], ExiDmaBuf[j + 5], ExiDmaBuf[j + 6], ExiDmaBuf[j + 7]);
	}
	while (1);
}

static void ARC_NORETURN ExiIdeTest(void) {
	static UCHAR ExiDmaBuf[0x200] ARC_ALIGNED(32) = { 0 };
	printf("EXIIDE driver test\r\n");

	static const char s_ExiDevices[][4] = {
		{ 'M', 'C', 'A', 0 },
		{ 'M', 'C', 'B', 0 },
		{ 'S', 'P', '1', 0 },
		{ 'S', 'P', '2', 0 }
	};

	// Find the first exi_ide device that got mounted
	EXI_IDE_DRIVE drive;

	for (ULONG i = 0; i < 4; i++) {
		drive = (EXI_IDE_DRIVE)i;
		bool mounted = IdeexiIsMounted(drive);
		printf("EXIIDE: drive %s is %spresent\r\n", s_ExiDevices[i], mounted ? "" : "not ");
		if (mounted) break;
		if (i == 3) {
			printf("EXIIDE: no drive is present\r\n");
			while (1);
		}
	}

	// Attempt to read sector 0.
	if (IdeexiReadBlocks(drive, ExiDmaBuf, 0, 1) == 0) {
		printf("EXIDE: could not read sector 0\r\n");
		while (1);
	}

	printf("EXIIDE test complete, sector0 header(0x50)/footer(0x50):\r\n");
	for (ULONG i = 0; i < 0x50; i += 0x10) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x ",
			ExiDmaBuf[i + 0], ExiDmaBuf[i + 1], ExiDmaBuf[i + 2], ExiDmaBuf[i + 3],
			ExiDmaBuf[i + 4], ExiDmaBuf[i + 5], ExiDmaBuf[i + 6], ExiDmaBuf[i + 7]);
		ULONG j = i + 8;
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\r\n",
			ExiDmaBuf[j + 0], ExiDmaBuf[j + 1], ExiDmaBuf[j + 2], ExiDmaBuf[j + 3],
			ExiDmaBuf[j + 4], ExiDmaBuf[j + 5], ExiDmaBuf[j + 6], ExiDmaBuf[j + 7]);
	}
	for (ULONG i = 0x1B0; i < 0x200; i += 0x10) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x ",
			ExiDmaBuf[i + 0], ExiDmaBuf[i + 1], ExiDmaBuf[i + 2], ExiDmaBuf[i + 3],
			ExiDmaBuf[i + 4], ExiDmaBuf[i + 5], ExiDmaBuf[i + 6], ExiDmaBuf[i + 7]);
		ULONG j = i + 8;
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\r\n",
			ExiDmaBuf[j + 0], ExiDmaBuf[j + 1], ExiDmaBuf[j + 2], ExiDmaBuf[j + 3],
			ExiDmaBuf[j + 4], ExiDmaBuf[j + 5], ExiDmaBuf[j + 6], ExiDmaBuf[j + 7]);
	}
	while (1);
}

static void ARC_NORETURN IopSdmcTest(void) {
	static UCHAR ExiDmaBuf[0x200] ARC_ALIGNED(32) = { 0 };
	printf("IOSSDMC driver test\r\n");

	// Attempt to read sector 0.
	if (SdmcReadSectors(0, 1, ExiDmaBuf) == 0) {
		printf("IOSSDMC: could not read sector 0\r\n");
		while (1);
	}

	printf("IOSSDMC test complete, sector0 header(0x50)/footer(0x50):\r\n");
	for (ULONG i = 0; i < 0x50; i += 0x10) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x ",
			ExiDmaBuf[i + 0], ExiDmaBuf[i + 1], ExiDmaBuf[i + 2], ExiDmaBuf[i + 3],
			ExiDmaBuf[i + 4], ExiDmaBuf[i + 5], ExiDmaBuf[i + 6], ExiDmaBuf[i + 7]);
		ULONG j = i + 8;
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\r\n",
			ExiDmaBuf[j + 0], ExiDmaBuf[j + 1], ExiDmaBuf[j + 2], ExiDmaBuf[j + 3],
			ExiDmaBuf[j + 4], ExiDmaBuf[j + 5], ExiDmaBuf[j + 6], ExiDmaBuf[j + 7]);
	}
	for (ULONG i = 0x1B0; i < 0x200; i += 0x10) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x ",
			ExiDmaBuf[i + 0], ExiDmaBuf[i + 1], ExiDmaBuf[i + 2], ExiDmaBuf[i + 3],
			ExiDmaBuf[i + 4], ExiDmaBuf[i + 5], ExiDmaBuf[i + 6], ExiDmaBuf[i + 7]);
		ULONG j = i + 8;
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\r\n",
			ExiDmaBuf[j + 0], ExiDmaBuf[j + 1], ExiDmaBuf[j + 2], ExiDmaBuf[j + 3],
			ExiDmaBuf[j + 4], ExiDmaBuf[j + 5], ExiDmaBuf[j + 6], ExiDmaBuf[j + 7]);
	}
	while (1);
}

static void ARC_NORETURN IopUsbmsTest(void) {
	static UCHAR ExiDmaBuf[0x200] ARC_ALIGNED(32) = { 0 };
	printf("IOSUSBMS driver test\r\n");

	// Get the first device.
	USBMS_DEVICES Devices;
	UlmsGetDevices(&Devices);

	if (Devices.DeviceCount == 0) {
		printf("IOSUSBMS: no devices found\r\n");
		while (1);
	}

	printf("IOSUSBMS: Found device %08x\r\n", Devices.ArcKey[0]);

	PUSBMS_CONTROLLER Controller = UlmsGetController(Devices.ArcKey[0]);
	if (Controller == NULL) {
		printf("IOSUSBMS: could not get controller\r\n");
		while (1);
	}

	ULONG Luns = UlmsGetLuns(Controller);
	if (Luns == 0) {
		printf("IOSUSBMS: device has no luns\r\n");
		while (1);
	}

	ULONG SectorSize = UlmsGetSectorSize(Controller, 0);
	printf("IOSUSBMS: Sector size = %x\r\n", SectorSize);
	if (SectorSize != 0x200) {
		printf("IOSUSBMS: Sector size not 0x200\r\n");
		while (1);
	}

	ULONG SectorCount = UlmsGetSectorCount(Controller, 0);
	printf("IOSUSBMS: Sector count = %x (%dMB)\r\n", SectorCount, SectorCount / 2 / 1024);

	// Attempt to read sector 0.
	if (UlmsReadSectors(Controller, 0, 0, 1, ExiDmaBuf) == 0) {
		printf("IOSUSBMS: could not read sector 0\r\n");
		while (1);
	}

	printf("IOSUSBMS test complete, sector0 header(0x50)/footer(0x50):\r\n");
	for (ULONG i = 0; i < 0x50; i += 0x10) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x ",
			ExiDmaBuf[i + 0], ExiDmaBuf[i + 1], ExiDmaBuf[i + 2], ExiDmaBuf[i + 3],
			ExiDmaBuf[i + 4], ExiDmaBuf[i + 5], ExiDmaBuf[i + 6], ExiDmaBuf[i + 7]);
		ULONG j = i + 8;
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\r\n",
			ExiDmaBuf[j + 0], ExiDmaBuf[j + 1], ExiDmaBuf[j + 2], ExiDmaBuf[j + 3],
			ExiDmaBuf[j + 4], ExiDmaBuf[j + 5], ExiDmaBuf[j + 6], ExiDmaBuf[j + 7]);
	}
	for (ULONG i = 0x1B0; i < 0x200; i += 0x10) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x ",
			ExiDmaBuf[i + 0], ExiDmaBuf[i + 1], ExiDmaBuf[i + 2], ExiDmaBuf[i + 3],
			ExiDmaBuf[i + 4], ExiDmaBuf[i + 5], ExiDmaBuf[i + 6], ExiDmaBuf[i + 7]);
		ULONG j = i + 8;
		printf("%02x %02x %02x %02x %02x %02x %02x %02x\r\n",
			ExiDmaBuf[j + 0], ExiDmaBuf[j + 1], ExiDmaBuf[j + 2], ExiDmaBuf[j + 3],
			ExiDmaBuf[j + 4], ExiDmaBuf[j + 5], ExiDmaBuf[j + 6], ExiDmaBuf[j + 7]);
	}
	while (1);
}

static void UnalignedStoresTest(ULONG size) {
	const ULONG write32 = 0x12345678;
	volatile UCHAR* ptr = (volatile UCHAR*)0x6000C000;
	volatile UCHAR reference_buffer[32];
	bool unaligned_broken = false;
	for (ULONG i = 0; i <= 28; ++i) {
		for (ULONG fill = 0; i < 32; i += 4) NativeWriteBase32(ptr, i, 0);
		memset(reference_buffer, 0, sizeof(reference_buffer));

		switch (size) {
		case 1:
			NativeWriteBase8(ptr, i, write32);
			break;
		case 2:
			NativeWriteBase16(ptr, i, write32);
			break;
		case 4:
			NativeWriteBase32(ptr, i, write32);
			break;
		}

		switch (size) {
		case 1:
			NativeWriteBase8(reference_buffer, i, write32);
			break;
		case 2:
			NativeWriteBase16(reference_buffer, i, write32);
			break;
		case 4:
			NativeWriteBase32(reference_buffer, i, write32);
			break;
		}

		if (memcmp(ptr, reference_buffer, sizeof(reference_buffer)) != 0) {
			printf("Got erratum for %x(%d-byte): %08x %08x %08x %08x %08x %08x %08x %08x\r\n", i, size,
				NativeReadBase32(ptr, 0), NativeReadBase32(ptr, 4), NativeReadBase32(ptr, 8), NativeReadBase32(ptr, 0xC),
				NativeReadBase32(ptr, 0x10), NativeReadBase32(ptr, 0x14), NativeReadBase32(ptr, 0x18), NativeReadBase32(ptr, 0x1C));
			unaligned_broken = true;
		}
	}

	if (!unaligned_broken) printf("Unaligned stores fine for %d-byte\r\n", size);
}
#endif

//---------------------------------------------------------------------------------
void ARC_NORETURN FwMain(PHW_DESCRIPTION Desc) {
//---------------------------------------------------------------------------------
	// Copy HW_DESCRIPTION down to stack to avoid it from potentially getting overwritten by init code.
	HW_DESCRIPTION StackDesc;
	memcpy(&StackDesc, Desc, sizeof(StackDesc));
	Desc = &StackDesc;

	// Determine system type.
	ARTX_SYSTEM_TYPE SystemType = ARTX_SYSTEM_FLIPPER;
	if ((Desc->FpFlags & FPF_IS_VEGAS) != 0) SystemType = ARTX_SYSTEM_VEGAS;
	if ((Desc->FpFlags & FPF_IS_LATTE) != 0) SystemType = ARTX_SYSTEM_LATTE;

	if (SystemType != ARTX_SYSTEM_LATTE) {
		// Acknowledge and mask off all interrupts.
		MmioWriteBase32((PVOID)0x6C000000, 0x3004, 0); // PI_INTMASK = 0
		MmioWriteBase32((PVOID)0x6C000000, 0x3000, 0xFFFFFFFF); // PI_INTSTATUS = 0xFFFFFFFF
	}
	else {
		MmioWriteBase32((PVOID)0x6C000000, 0x7C, 0); // PI_INTMASK = 0
		MmioWriteBase32((PVOID)0x6C000000, 0x78, 0xFFFFFFFF); // PI_INTSTATUS = 0xFFFFFFFF
		MmioWriteBase32((PVOID)0x6C000000, 0x84, 0); // PI_INTMASK = 0
		MmioWriteBase32((PVOID)0x6C000000, 0x80, 0xFFFFFFFF); // PI_INTSTATUS = 0xFFFFFFFF
		MmioWriteBase32((PVOID)0x6C000000, 0x8C, 0); // PI_INTMASK = 0
		MmioWriteBase32((PVOID)0x6C000000, 0x88, 0xFFFFFFFF); // PI_INTSTATUS = 0xFFFFFFFF
	}


	// Latte uses an RGB framebuffer, not a YUV one.
	if (SystemType == ARTX_SYSTEM_LATTE) {
		ArcConsoleUseRgb();
		// Set the framebuffers to 64-bit endian swap.
		MmioWriteBase32((PVOID)0x6C200000, 0x610C, 3);
		MmioWriteBase32((PVOID)0x6C200000, 0x618C, 3);
		MmioWriteBase32((PVOID)0x6C200000, 0x690C, 3);
		MmioWriteBase32((PVOID)0x6C200000, 0x698C, 3);
	}
	// Initialise the console. We know where it is. Just convert it from physical address to our BAT mapping.
	ArcConsoleInit(MEM_PHYSICAL_TO_K1(Desc->FrameBufferBase), 20, 20, Desc->FrameBufferWidth, Desc->FrameBufferHeight, Desc->FrameBufferStride);
	if (SystemType == ARTX_SYSTEM_LATTE) {
		printf("\r\n\n\n");

#if 0
		// Check for the 60x bus erratum.
		UnalignedStoresTest(1);
		UnalignedStoresTest(2);
		UnalignedStoresTest(4);
#endif
	}
	
	// Initialise the exception handlers.
	//void ArcBugcheckInit(void);
	//ArcBugcheckInit();


	// Initialise ARC memory descriptors. 
	if (ArcMemInitDescriptors(Desc) < 0) {
		FwEarlyPanic("[ARC] Could not initialise memory description");
	}
	// Carve out some space for heap.
	// We will use 4MB of MEM1.
	PVOID HeapChunk = ArcMemAllocTemp(0x400000, false);
	if (HeapChunk == NULL) {
		FwEarlyPanic("[ARC] Could not allocate heap memory");
	}
	add_malloc_block(HeapChunk, 0x400000);
	
	// Zero out the entire runtime area.
	memset(s_RuntimeArea, 0, sizeof(*s_RuntimeArea));

	// Initialise hardware.
	// Timers.
	void setup_timers(ULONG DecrementerFreq);
	setup_timers(Desc->DecrementerFrequency);

	// SI
	printf("Init si...\r\n");
	SiInit(SystemType);
	SikbdInit();

	// EXI
	printf("Init exi...\r\n");
	ExiInit(SystemType);
	SdmcexiInit();
	IdeexiInit();

	ULONG ExiDevices = 0;
	for (int i = 0; i < 4; i++) {
		if (SdmcexiIsMounted((EXI_SDMC_DRIVE)i)) ExiDevices |= BIT(i);
		else if (IdeexiIsMounted((EXI_IDE_DRIVE)i)) ExiDevices |= BIT(i) | BIT(i + 4);
	}

	// PXI (where appropriate)
	if (SystemType >= ARTX_SYSTEM_VEGAS) {
		printf("Init pxi...\r\n");
		PxiInit(SystemType);
		PxiHeapInit(Desc->DdrIpcBase, Desc->DdrIpcLength);
		printf("Init sdmc...\r\n");
		SdmcStartup();
		printf("Init IOS USBv5...\r\n");
		if (UlInit() >= 0) {
			UlkInit();
			UlmsInit();
		}
	}

	// If reload code is around, copy it somewhere else, as NT will clobber it, and we want to keep it around
	ULONG ReloadStub = 0;
	if ((Desc->FpFlags & FPF_IN_EMULATOR) == 0 && (
		(*(PULONG)0x8000180c == 'STUB' && *(PULONG)0x80001808 == 'HAXX') ||
		(*(PULONG)0x80001800 == 'STUB' && *(PULONG)0x8000180c == 'HAXX')
	)) {
		ReloadStub = (ULONG)ArcMemAllocDirect(0x2000, false);
		for (ULONG i = 0; i < 0x1800; i += 4) {
			*(PULONG)(ReloadStub + i) = *(PULONG)(0x80001800 + i);
		}
		void sync_before_exec(const void* p, ULONG len);
		sync_before_exec((PVOID)ReloadStub, 0x1800);
	}

	disk_MountAll();

	printf("Early driver init done.\r\n");

	// Emulator status.
	s_RuntimePointers[RUNTIME_IN_EMULATOR].v = (Desc->FpFlags & FPF_IN_EMULATOR) != 0;

	// Initialise the first runtime pointer to the VI framebuffer information.
	s_RuntimeFb.PointerArc = Desc->FrameBufferBase;
	s_RuntimeFb.Length = Desc->FrameBufferHeight * Desc->FrameBufferStride;
	s_RuntimeFb.Width = Desc->FrameBufferWidth;
	s_RuntimeFb.Height = Desc->FrameBufferHeight;
	s_RuntimeFb.Stride = Desc->FrameBufferStride;
	s_RuntimePointers[RUNTIME_FRAME_BUFFER].v = (ULONG)&s_RuntimeFb;

	// Initialise the decrementer frequency.
	s_RuntimePointers[RUNTIME_DECREMENTER_FREQUENCY].v = Desc->DecrementerFrequency;

	// RTC bias.
	s_RuntimePointers[RUNTIME_RTC_BIAS].v = Desc->RtcBias;
	
	// IOS IPC area.
	if (Desc->DdrIpcBase != 0) {
		s_RuntimeIpc.PointerArc = Desc->DdrIpcBase;
		s_RuntimeIpc.Length = Desc->DdrIpcLength;
		s_RuntimePointers[RUNTIME_IPC_AREA].v = (ULONG)&s_RuntimeIpc;
	}

	// GX FIFO buffer.
	s_RuntimeGx.PointerArc = Desc->GxFifoBase;
	s_RuntimeGx.Length = Desc->FrameBufferBase - Desc->GxFifoBase;
	s_RuntimePointers[RUNTIME_GX_FIFO].v = (ULONG)&s_RuntimeGx;

	// System type.
	s_RuntimePointers[RUNTIME_SYSTEM_TYPE].v = (ULONG)SystemType;

	// Place where reload stub got moved to.
	if (ReloadStub != 0) s_RuntimePointers[RUNTIME_RESET_STUB].v = (ULONG)MEM_VIRTUAL_TO_PHYSICAL(ReloadStub);

	// EXI devices (bit 0-3 => EXI block device is present; bit 4-7 => that EXI device is EXI-IDE)
	s_RuntimePointers[RUNTIME_EXI_DEVICES].v = ExiDevices;

	ArcMain();
	// should never reach here
	while (1) {}
}

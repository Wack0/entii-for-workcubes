// ARC environment variable stuff.

#include "halp.h"
#include "arccodes.h"
#include "iosapi.h"
#include <stdio.h>

static const char sc_StmDev[] ARC_ALIGNED(32) = STRING_BYTESWAP("/dev/stm/immediate");

static PVOID s_ReloadStub = NULL;
static PVOID s_ReloadStubReal0 = NULL;
static PVOID s_FlipperResetRegisters = NULL;

static ULONG s_StmImmBufIn[8 + (32/4)];
static ULONG s_StmImmBufOut[8 + (32/4)];

void HalpTermInit(void) {
	// Map the reset registers.
	PHYSICAL_ADDRESS PhysAddr;
	PhysAddr.HighPart = 0;
	PhysAddr.LowPart = 0x0C002000;
	s_FlipperResetRegisters = MmMapIoSpace( PhysAddr, 0x2000, MmNonCached );
	// Map the reset stub.
	PhysAddr.LowPart = (ULONG)RUNTIME_BLOCK[RUNTIME_RESET_STUB];
	if (PhysAddr.LowPart == 0) return;
	
	s_ReloadStub = MmMapIoSpace( PhysAddr, 0x2000, MmCached);
	if (s_ReloadStub == NULL) return;
	
	PhysAddr.LowPart = 0x1800;
	s_ReloadStubReal0 = MmMapIoSpace( PhysAddr, 0x2000, MmCached);
}

void HalpBranchToResetStub(ULONG Address);

static void TermPowerOffSystem(BOOLEAN Reset) {
	KIRQL OldIrql;
	BOOLEAN IsFlipper = (ULONG)RUNTIME_BLOCK[RUNTIME_SYSTEM_TYPE] == ARTX_SYSTEM_FLIPPER;
	if (
		(Reset || IsFlipper) && s_ReloadStub != NULL && s_ReloadStubReal0 != NULL && (
		(NativeReadBase32(s_ReloadStub, 8) == 'STUB' && NativeReadBase32(s_ReloadStub, 0xC) == 'HAXX') ||
		(NativeReadBase32(s_ReloadStub, 4) == 'STUB' && NativeReadBase32(s_ReloadStub, 8) == 'HAXX')
	)) {
		// Copy reload stub back to where it's expected to be. (in physical address space, not virtual)
		RtlCopyMemory( s_ReloadStubReal0, s_ReloadStub, 0x1800 );
		// Flush dcache and icache for this range.
		HalSyncBeforeExecution( s_ReloadStubReal0, 0x1800 );
		// Disable interrupts.
		KeRaiseIrql(HIGH_LEVEL, &OldIrql);
		// Switch to big endian mode and branch to reset stub
		HalpBranchToResetStub( s_ReloadStubReal0 );
		// Above never returns.
		__builtin_unreachable();
	}

	if ((ULONG)RUNTIME_BLOCK[RUNTIME_SYSTEM_TYPE] == ARTX_SYSTEM_FLIPPER) {
		// Disable interrupts.
		KeRaiseIrql(HIGH_LEVEL, &OldIrql);
		// Can't shutdown a flipper system from software.
		// Just reset it, even if Reset is false.
		if (s_FlipperResetRegisters != NULL) {
			MmioWriteBase16(s_FlipperResetRegisters, 0, 0);
			MmioWriteBase32(s_FlipperResetRegisters, 0x1024, 3);
			MmioWriteBase32(s_FlipperResetRegisters, 0x1024, 0);
		}
		while (1);
	}
	
	// Restart or shutdown via IOS STM.

	PULONG StmBuffIn = (PULONG)((ULONG)s_StmImmBufIn + (0x20 - (((ULONG)s_StmImmBufIn) & 0x1F)));
	PULONG StmBuffOut = (PULONG)((ULONG)s_StmImmBufOut + (0x20 - (((ULONG)s_StmImmBufOut) & 0x1F)));
	RtlZeroMemory(StmBuffIn, 0x20);
	IOS_HANDLE hStm;
	NTSTATUS Status = HalIopOpen(sc_StmDev, IOSOPEN_NONE, &hStm);
	if (!NT_SUCCESS(Status)) {
		// Disable interrupts.
		KeRaiseIrql(HIGH_LEVEL, &OldIrql);
		while (1);
	}
	// try to IOCTL_STM_SHUTDOWN or IOCTL_STM_HOTRESET. don't bother swapping as everything in input is zero, and we shouldn't return.
	// under emulation, always use shutdown, hotreset is currently not implemented.
	if ((ULONG)RUNTIME_BLOCK[RUNTIME_IN_EMULATOR]) Reset = FALSE;
	Status = HalIopIoctl(hStm, Reset ? 0x2001 : 0x2003, StmBuffIn, 0x20, StmBuffOut, 0x20, IOCTL_SWAP_NONE, IOCTL_SWAP_NONE);
	
	// Disable interrupts.
	KeRaiseIrql(HIGH_LEVEL, &OldIrql);
	while (1);
}

// Return to firmware.
void HalReturnToFirmware(FIRMWARE_REENTRY Routine) {
	
	switch (Routine) {
		case HalHaltRoutine:
			TermPowerOffSystem(FALSE);
			break;
		case HalPowerDownRoutine:
			TermPowerOffSystem(FALSE);
			break;
		case HalRestartRoutine:
			TermPowerOffSystem(TRUE);
			break;
		case HalRebootRoutine:
			TermPowerOffSystem(TRUE);
			break;
		case HalInteractiveModeRoutine:
		default:
			// unknown ARC restart function
			// just call ArcReboot
			TermPowerOffSystem(TRUE);
			break;
	}

	// unreachable
}

// NV implementation by disk under NT.

enum {
	ARC_ENV_VARS_SIZE = 1024,
	ARC_ENV_MAXIMUM_VALUE_SIZE = 256,
	
	SIZE_OF_ENV = ARC_ENV_VARS_SIZE,
	SIZE_OF_VAL = ARC_ENV_MAXIMUM_VALUE_SIZE
};

static UCHAR s_EnvironmentVariableArea[SIZE_OF_ENV] = {0};
static PDEVICE_OBJECT s_NvDevice = NULL;
static ARC_STATUS s_NvInitError = ESUCCESS;
static ULONG s_EnvOffset = 0;

enum {
	REPART_SECTOR_SIZE = 0x200,
	REPART_KB_SECTORS = 0x400 / REPART_SECTOR_SIZE,
	REPART_U32_MAX_SECTORS_IN_MB = 0x1FFFFF,

	REPART_MBR_PART1_START = 1,
	REPART_MBR_PART1_SIZE = (0x100000 / REPART_SECTOR_SIZE) - REPART_MBR_PART1_START,
};

#define ARC_SUCCESS(code) ((code) == ESUCCESS)
#define ARC_FAIL(code) ((code) != ESUCCESS)

typedef struct _IRP_SYNC_DESC {
	KEVENT Event;
	IO_STATUS_BLOCK IoStatus;
} IRP_SYNC_DESC, *PIRP_SYNC_DESC;

typedef struct _DISK_IO_WORK_ITEM {
	WORK_QUEUE_ITEM WorkItem;
	PDEVICE_OBJECT DeviceObject;
	ULONG MajorFunction;
	PVOID Buffer;
	ULONG Length;
	LARGE_INTEGER StartingOffset;
	IRP_SYNC_DESC SyncDesc;
	KEVENT WorkEvent;
	NTSTATUS FinalStatus;
} DISK_IO_WORK_ITEM, *PDISK_IO_WORK_ITEM;

static ARC_STATUS NvpFindVar(PCHAR Variable, PULONG OffsetKey, PULONG OffsetValue);

static void NvpDiskWorkRoutine(PDISK_IO_WORK_ITEM WorkItem) {
	KeInitializeEvent(&WorkItem->SyncDesc.Event, NotificationEvent, FALSE);
	
	PDEVICE_OBJECT DeviceObject = WorkItem->DeviceObject;
	
	PIRP Irp = IoBuildSynchronousFsdRequest(
		WorkItem->MajorFunction,
		DeviceObject,
		WorkItem->Buffer,
		WorkItem->Length,
		&WorkItem->StartingOffset,
		&WorkItem->SyncDesc.Event,
		&WorkItem->SyncDesc.IoStatus
	);
	
	NTSTATUS Status = IoCallDriver(DeviceObject, Irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&WorkItem->SyncDesc.Event, Executive, KernelMode, FALSE, NULL);
		Status = WorkItem->SyncDesc.IoStatus.Status;
	}
	
	WorkItem->FinalStatus = Status;
	ObDereferenceObject(DeviceObject);
	KeSetEvent(&WorkItem->WorkEvent, 0, FALSE);
}

static NTSTATUS NvpTryDiskIo(PDEVICE_OBJECT DeviceObject, ULONG MajorFunction, PVOID Buffer, ULONG Length, PLARGE_INTEGER StartingOffset, PULONG TransferredLength) {
	PDISK_IO_WORK_ITEM WorkItem = ExAllocatePool(NonPagedPool, sizeof(DISK_IO_WORK_ITEM));
	if (WorkItem == NULL) return STATUS_NO_MEMORY;
	RtlZeroMemory(WorkItem, sizeof(*WorkItem));
	
	// Initialise the structure values
	KeInitializeEvent(&WorkItem->WorkEvent, NotificationEvent, FALSE);
	WorkItem->DeviceObject = DeviceObject;
	WorkItem->MajorFunction = MajorFunction;
	WorkItem->Buffer = Buffer;
	WorkItem->Length = Length;
	WorkItem->StartingOffset = *StartingOffset;
	
	// Initialise the ExWorkItem and queue it
	ExInitializeWorkItem(&WorkItem->WorkItem, (PWORKER_THREAD_ROUTINE) NvpDiskWorkRoutine, WorkItem);
	ObReferenceObject(DeviceObject);
	ExQueueWorkItem(&WorkItem->WorkItem, CriticalWorkQueue);
	
	// Wait for the work item to finiish running
	KeWaitForSingleObject(&WorkItem->WorkEvent, Executive, KernelMode, FALSE, NULL);
	NTSTATUS Status = WorkItem->FinalStatus;
	if (NT_SUCCESS(Status)) *TransferredLength = WorkItem->SyncDesc.IoStatus.Information;
	ExFreePool(WorkItem);
	return Status;
}

static NTSTATUS NvpTryReadDisk(PDEVICE_OBJECT DeviceObject, PVOID Buffer, ULONG Length, PLARGE_INTEGER StartingOffset, PULONG TransferredLength) {
#if 0
	// Reads sectors from a disk using the lowlevel IO functions.
	PIRP_SYNC_DESC SyncDesc = ExAllocatePool(NonPagedPool, sizeof(IRP_SYNC_DESC));
	if (SyncDesc == NULL) return STATUS_NO_MEMORY;
	RtlZeroMemory(SyncDesc, sizeof(*SyncDesc));
	
	KeInitializeEvent(&SyncDesc->Event, NotificationEvent, FALSE);
	
	PIRP Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ, DeviceObject, Buffer, Length, StartingOffset, &SyncDesc->Event, &SyncDesc->IoStatus);
	NTSTATUS Status = IoCallDriver(DeviceObject, Irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&SyncDesc->Event, Executive, KernelMode, FALSE, NULL);
		Status = SyncDesc->IoStatus.Status;
	}
	
	if (NT_SUCCESS(Status)) *TransferredLength = SyncDesc->IoStatus.Information;
	
	ExFreePool(SyncDesc);
	return Status;
#endif
	return NvpTryDiskIo(DeviceObject, IRP_MJ_READ, Buffer, Length, StartingOffset, TransferredLength);
}

static NTSTATUS NvpTryWriteDisk(PDEVICE_OBJECT DeviceObject, PVOID Buffer, ULONG Length, PLARGE_INTEGER StartingOffset, PULONG TransferredLength) {
#if 0
	// Writes sectors to a disk using the lowlevel IO functions.
	PIRP_SYNC_DESC SyncDesc = ExAllocatePool(NonPagedPool, sizeof(IRP_SYNC_DESC));
	if (SyncDesc == NULL) return STATUS_NO_MEMORY;
	RtlZeroMemory(SyncDesc, sizeof(*SyncDesc));
	
	KeInitializeEvent(&SyncDesc->Event, NotificationEvent, FALSE);
	
	PIRP Irp = IoBuildSynchronousFsdRequest(IRP_MJ_WRITE, DeviceObject, Buffer, Length, StartingOffset, &SyncDesc->Event, &SyncDesc->IoStatus);
#if 0
	// Claim the IRP is for paging I/O.
	// This is so the simplest possible code path is used on completion. (no APC being queued for the final operations)
	Irp->Flags |= IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO;
	// We need to free the MDL ourselves, "the simplest possible code path" doesn't do that (as MM owns the MDLs for paging IO)
	// So grab the MDL that the IRP is using.
	PMDL Mdl = Irp->MdlAddress;
	
	NTSTATUS Status = IoCallDriver(DeviceObject, Irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&SyncDesc->Event, Executive, KernelMode, FALSE, NULL);
		Status = SyncDesc->IoStatus.Status;
	}
	
	// Unlock any pages described by MDLs.
	for (PMDL ThisMdl = Mdl; ThisMdl != NULL; ThisMdl = ThisMdl->Next) {
		MmUnlockPages(ThisMdl);
	}
	
	// And free those MDLs.
	{
		PMDL NextMdl = NULL;
		for (PMDL ThisMdl = Mdl; ThisMdl != NULL; ThisMdl = NextMdl) {
			NextMdl = ThisMdl->Next;
			IoFreeMdl(ThisMdl);
		}
	}
#else
	// Quick question: why did I do this in the first place? Some sort of bug, right?
	NTSTATUS Status = IoCallDriver(DeviceObject, Irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&SyncDesc->Event, Executive, KernelMode, FALSE, NULL);
		Status = SyncDesc->IoStatus.Status;
	}
#endif
	
	if (NT_SUCCESS(Status)) *TransferredLength = SyncDesc->IoStatus.Information;
	
	ExFreePool(SyncDesc);
	return Status;
#endif
	
	return NvpTryDiskIo(DeviceObject, IRP_MJ_WRITE, Buffer, Length, StartingOffset, TransferredLength);
}

static NTSTATUS NvpTryInitNvramByDisk(ULONG DiskIndex) {
	// Generate the NT object path name for this device.
	UCHAR NtName[256];
	_snprintf(NtName, sizeof(NtName), "\\ArcName\\scsi(0)disk(%u)fdisk(0)", DiskIndex);
	
	// Wrap an ANSI string around it.
	STRING NtNameStr;
	RtlInitString(&NtNameStr, NtName);
	
	// Convert to unicode.
	UNICODE_STRING NtNameUs;
	NTSTATUS Status = RtlAnsiStringToUnicodeString(&NtNameUs, &NtNameStr, TRUE);
	if (!NT_SUCCESS(Status)) return Status;
	
	PFILE_OBJECT FileObject;
	PDEVICE_OBJECT DeviceObject;
	
	// Get the device object.
	Status = IoGetDeviceObjectPointer(&NtNameUs, FILE_READ_DATA | FILE_WRITE_DATA, &FileObject, &DeviceObject);
	RtlFreeUnicodeString(&NtNameUs);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}
	
	UCHAR Sector[REPART_SECTOR_SIZE];
	ULONG TransferredLength;
	LARGE_INTEGER Offset = {0};
	do {
		// Read the first sector.
		Status = NvpTryReadDisk(DeviceObject, Sector, sizeof(Sector), &Offset, &TransferredLength);
		if (NT_SUCCESS(Status) && TransferredLength != sizeof(Sector)) Status = STATUS_IO_DEVICE_ERROR;
		if (!NT_SUCCESS(Status)) {
			break;
		}
		
		Status = STATUS_FILE_INVALID;
		// Ensure MBR is present.
		if (Sector[0x1FE] != 0x55) break;
		if (Sector[0x1FF] != 0xAA) break;
		
		// Ensure first partition is correct:
		// Partition 1: 0x41
		if (Sector[0x1BE + 4] != 0x41) break;
		// number of sectors = 2047
		if (Sector[0x1BE + 0xC] != ((REPART_MBR_PART1_SIZE >> 0) & 0xFF)) break;
		if (Sector[0x1BE + 0xD] != ((REPART_MBR_PART1_SIZE >> 8) & 0xFF)) break;
		if (Sector[0x1BE + 0xE] != ((REPART_MBR_PART1_SIZE >> 16) & 0xFF)) break;
		if (Sector[0x1BE + 0xF] != ((REPART_MBR_PART1_SIZE >> 24) & 0xFF)) break;
		
		// Looks good. Read the NV sectors directly into the buffer.
		Offset.LowPart = REPART_MBR_PART1_START * REPART_SECTOR_SIZE;
		Status = NvpTryReadDisk(DeviceObject, s_EnvironmentVariableArea, sizeof(s_EnvironmentVariableArea), &Offset, &TransferredLength);
		if (NT_SUCCESS(Status) && TransferredLength != sizeof(s_EnvironmentVariableArea)) Status = STATUS_IO_DEVICE_ERROR;
		if (!NT_SUCCESS(Status)) {
			RtlZeroMemory(s_EnvironmentVariableArea, sizeof(s_EnvironmentVariableArea));
		}
		
		// All done.
	} while (FALSE);
	
	if (NT_SUCCESS(Status)) {
		// Keep the device object and keep a reference to the file object.
		// fastfat attaches later, we want and require the raw disk device!
		s_NvDevice = DeviceObject;
		s_EnvOffset = REPART_MBR_PART1_START * REPART_SECTOR_SIZE;
	} else {
		ObDereferenceObject(FileObject);
	}
	return Status;
}

static NTSTATUS NvpTryInitNvramByEnvironDevice(ULONG Index) {
	// Generate the NT object path name for this device.
	UCHAR NtName[256];
	_snprintf(NtName, sizeof(NtName), "\\Device\\ArcEnviron%d", Index);
	
	CHAR Buffer[512];
	
	// Wrap an ANSI string around it.
	STRING NtNameStr;
	RtlInitString(&NtNameStr, NtName);
	
	// Convert to unicode.
	UNICODE_STRING NtNameUs;
	NTSTATUS Status = RtlAnsiStringToUnicodeString(&NtNameUs, &NtNameStr, TRUE);
	if (!NT_SUCCESS(Status)) return Status;
	
	PFILE_OBJECT FileObject;
	PDEVICE_OBJECT DeviceObject;
	
	// Get the device object.
	Status = IoGetDeviceObjectPointer(&NtNameUs, FILE_READ_DATA | FILE_WRITE_DATA, &FileObject, &DeviceObject);
	RtlFreeUnicodeString(&NtNameUs);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}
	
	UCHAR Sector[REPART_SECTOR_SIZE];
	ULONG TransferredLength;
	LARGE_INTEGER Offset = {0};
	do {
		// Read the NV sectors directly into the buffer.
		Offset.LowPart = 0;
		Status = NvpTryReadDisk(DeviceObject, s_EnvironmentVariableArea, sizeof(s_EnvironmentVariableArea), &Offset, &TransferredLength);
		if (NT_SUCCESS(Status) && TransferredLength != sizeof(s_EnvironmentVariableArea)) Status = STATUS_IO_DEVICE_ERROR;
		if (!NT_SUCCESS(Status)) {
			RtlZeroMemory(s_EnvironmentVariableArea, sizeof(s_EnvironmentVariableArea));
		}
		
		// All done.
	} while (FALSE);
	
	if (NT_SUCCESS(Status)) {
		// Keep the device object and keep a reference to the file object.
		// fastfat attaches later, we want and require the raw disk device!
		s_NvDevice = DeviceObject;
		s_EnvOffset = 0;
	} else {
		ObDereferenceObject(FileObject);
	}
	return Status;
}

ARC_STATUS NvpInitNvram(void) {
	if (s_NvDevice != NULL) return ESUCCESS;
	if (s_NvInitError != ESUCCESS) return s_NvInitError;
	
	// ARC firmware told us what disk has the environment.
	ULONG EnvDisk = LoadToRegister32((ULONG)RUNTIME_BLOCK[RUNTIME_ENV_DISK]);
	
	if ((EnvDisk >> 16) == 0) {
		// The disk is on the EXI bus or is the IOSSDMC device.
		if (NT_SUCCESS(NvpTryInitNvramByEnvironDevice(EnvDisk))) return ESUCCESS;
	} else {
		// Otherwise, environment is on a correctly partitioned USB disk, EnvDisk is the arc device key.
		if (NT_SUCCESS(NvpTryInitNvramByDisk(EnvDisk))) return ESUCCESS;
	}
	
	s_NvInitError = ENODEV;
	return ENODEV;
}

static ARC_STATUS NvpWriteNvram(void) {
	if (s_NvDevice == NULL) return ENODEV;
	
	ARC_STATUS ArcStatus = EFAULT;
	
	// Write to disk.
	ULONG TransferredLength;
	LARGE_INTEGER Offset = {0};
	
	Offset.LowPart = s_EnvOffset;
	NTSTATUS Status = NvpTryWriteDisk(s_NvDevice, s_EnvironmentVariableArea, sizeof(s_EnvironmentVariableArea), &Offset, &TransferredLength);
	if (NT_SUCCESS(Status) && TransferredLength != sizeof(s_EnvironmentVariableArea)) Status = STATUS_IO_DEVICE_ERROR;
	if (!NT_SUCCESS(Status)) ArcStatus = EIO;
	
	if (!NT_SUCCESS(Status)) return ArcStatus;
	return ESUCCESS;
}

static ULONG NvpGetEmptySpace(ULONG Index) {
	for (; s_EnvironmentVariableArea[Index] == 0; Index--) {
		if (Index == 0) break;
	}

	if (Index != 0) {
		Index += sizeof(" "); // Increment past the non-null character, and null terminator
	}
	return Index;
}

static ARC_STATUS NvpFindVar(PCHAR Variable, PULONG OffsetKey, PULONG OffsetValue) {
	ULONG Index = 0;

	if (Variable == NULL || *Variable == 0) return ENOENT;

	while (TRUE) {
		PCHAR String = Variable;
		ULONG LocalOffsetKey = Index;
		for (; Index < SIZE_OF_ENV; Index++) {
			char Character = s_EnvironmentVariableArea[Index];
			char ExpectedChar = *String;
			// Convert to uppercase.
			if (ExpectedChar >= 'a' && ExpectedChar <= 'z') ExpectedChar &= ~0x20;
			if (Character != ExpectedChar) break;

			String++;
		}

		if (*String == 0 && s_EnvironmentVariableArea[Index] == '=') {
			// Found the match.
			*OffsetKey = LocalOffsetKey;
			*OffsetValue = Index + 1;
			return ESUCCESS;
		}

		// Move to the next var.
		for (; s_EnvironmentVariableArea[Index] != 0; Index++) {
			if (Index >= SIZE_OF_ENV) return ENOENT;
		}
		Index++;
	}
}

static ARC_STATUS NvpSetVarInMem(PCHAR Key, PCHAR Value) {
	// Check if variable already exists.
	ULONG OffsetKey, OffsetVal;
	ARC_STATUS Status = NvpFindVar(Key, &OffsetKey, &OffsetVal);
	// If variable does not exist and Value is empty string then just return success
	// (caller wanted to delete a variable that does not exist)
	if (ARC_FAIL(Status) && *Value == 0) return ESUCCESS;

	// Find the amount of space we have.
	ULONG Index = NvpGetEmptySpace(SIZE_OF_ENV - 1);
	ULONG Length = SIZE_OF_ENV - Index;

	ULONG KeyLen = strlen(Key);
	ULONG ValueLen = strlen(Value);

	// Variable already exists?
	if (ARC_SUCCESS(Status)) {
		// Does new value equal old value? If so, do nothing.
		ULONG ExistingValueLen = 0;
		BOOLEAN ValuesEqual = TRUE;
		for (; s_EnvironmentVariableArea[OffsetVal + ExistingValueLen] != 0; ExistingValueLen++) {
			if (ValuesEqual && (Value[ExistingValueLen] == 0 || Value[ExistingValueLen] != s_EnvironmentVariableArea[OffsetVal + ExistingValueLen])) {
				ValuesEqual = FALSE;
			}
		}
		if (ValuesEqual && Value[ExistingValueLen] == 0) return ESUCCESS;
		// Is there enough space to hold new value?
		Length += ExistingValueLen;
		if (Length < ValueLen) return ENOSPC;

		// Remove the existing variable.
		ULONG OffsetPastExisting = OffsetVal + ExistingValueLen + 1;
		ULONG LengthToCopy = SIZE_OF_ENV - OffsetPastExisting;
		memcpy(&s_EnvironmentVariableArea[OffsetKey], &s_EnvironmentVariableArea[OffsetPastExisting], LengthToCopy);
		memset(&s_EnvironmentVariableArea[OffsetKey + LengthToCopy], 0, SIZE_OF_ENV - OffsetKey - LengthToCopy);

		// If Value is empty string return success, variable has been deleted which is what caller wanted.
		if (*Value == 0) return ESUCCESS;

		// Correct the index to take the additional space into account
		Index = NvpGetEmptySpace(Index);
	}
	else {
		// Is there enough space to hold new variable?
		ULONG NewVarLen = KeyLen + ValueLen + 1;
		if (Length < NewVarLen) return ENOSPC;
	}

	// Write the key, converting to upper case.
	for (int i = 0; i < KeyLen; i++) {
		char Character = Key[i];
		if (Character >= 'a' && Character <= 'z') Character &= ~0x20;
		s_EnvironmentVariableArea[Index] = Character;
		Index++;
	}
	// Write equals character.
	s_EnvironmentVariableArea[Index] = '=';
	Index++;
	// Write value.
	for (int i = 0; i < ValueLen; i++) {
		s_EnvironmentVariableArea[Index] = Value[i];
		Index++;
	}
	// Ensure null terminated.
	s_EnvironmentVariableArea[Index] = 0;
	return ESUCCESS;
}

// Get environment variable.
ARC_STATUS HalGetEnvironmentVariable(IN PCHAR Variable, IN USHORT Length, OUT PCHAR Buffer) {
	// Ensure passed in pointers are non-NULL.
	if (Variable == NULL || Buffer == NULL) return EINVAL;
	
	// Ensure the ARC environment has been read from disk.
	ARC_STATUS Status = NvpInitNvram();
	if (ARC_FAIL(Status)) return Status;
	
	// Find the requested variable in memory.
	ULONG OffsetKey, OffsetVal;
	Status = NvpFindVar(Variable, &OffsetKey, &OffsetVal);
	if (ARC_FAIL(Status)) return Status;
	
	// Copy string to output.
	int i = 0;
	for (; i < (Length - 1); i++) {
		char Character = s_EnvironmentVariableArea[OffsetVal + i];
		if (Character == 0) break;
		Buffer[i] = Character;
	}
	// Null terminate string.
	Buffer[i] = 0;
	
	return ESUCCESS;
}

// Set environment variable.
ARC_STATUS HalSetEnvironmentVariable(IN PCHAR Variable, IN PCHAR Value) {
	// Ensure passed in variable name pointer is non-NULL.
	if (Variable == NULL) return EINVAL;
	
	// Ensure the ARC environment has been read from disk.
	ARC_STATUS Status = NvpInitNvram();
	if (ARC_FAIL(Status)) return Status;
	
	// If caller passed NULL value, assume they wanted to delete this variable.
	char EmptyString = 0;
	if (Value == NULL) Value = &EmptyString;
	
	// Set the variable contents in the in-memory store.
	Status = NvpSetVarInMem(Variable, Value);
	if (ARC_FAIL(Status)) return Status;
	
	// Write the in-memory store to disk.
	return NvpWriteNvram();
}
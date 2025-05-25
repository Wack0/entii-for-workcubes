// SDMC over IOS (driver entry)
#define DEVL 1
#include <ntddk.h>
#include <hal.h>
#include <ntstatus.h>
#include <ntddcdrm.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <stdio.h>
#include "zwdd.h"
#include "ff.h"
#include "sdmc.h"

// We wrap FATFS around the raw SDMC (over IOS) block IO driver.
// We expose FS images on SD card as raw disks.

#define FILENAME_FLOPPY_IMAGE "nt/drivers.img"
#define FILENAME_HARD_DISK_IMAGE "nt/disk%02d.img"
#define FILENAME_CDROM_IMAGE "nt/disk%02d.iso"
#define FILENAME_ENVIRONMENT "nt/environ.bin"

// The number after the device name here is the ARC fatfs device number
// 0-3 => EXI, 4 => IOSSDMC
#define DEVNAME_ENVIRONMENT "\\Device\\ArcEnviron4"

#define SIGNATURE_PARTITION 'PART'
#define SIGNATURE_DISK 'DISK'

// SD controller ARC path.
// Must be synchronised with arcfw\source\arcdisk.c
static const char s_SdControllerPath[] = "multi(1)";

static FATFS s_FatFs;
static PCONTROLLER_OBJECT s_ControllerObject = NULL;
static PDEVICE_OBJECT s_EnvironmentDevice = NULL;

BYTE s_Wtf[0x10];

typedef struct _SDMC_EMU_EXTENSION SDMC_EMU_EXTENSION, *PSDMC_EMU_EXTENSION;

typedef struct _SDMC_EMU_PARTITION {
	ULONG Signature;
	struct _SDMC_EMU_PARTITION * NextPartition;
	PSDMC_EMU_EXTENSION PhysicalDisk;
	LARGE_INTEGER PartitionLength;
	LARGE_INTEGER StartingOffset;
	// Extra stuff needed for PARTITION_INFORMATION
	ULONG HiddenSectors;
	ULONG PartitionNumber;
	UCHAR PartitionType;
} SDMC_EMU_PARTITION, *PSDMC_EMU_PARTITION;

struct _SDMC_EMU_EXTENSION {
	ULONG Signature;
	// Workaround for changer.sys bug and probably some other stupid drivers too:
	// changer.sys expects to see a scsiclass DEVICE_EXTENSION on any FILE_DEVICE_CD_ROM device.
	// and expects to see a device object at ->PortDeviceObject (offset 4) there.
	// so, put our device object pointer here, so it doesn't try to use something else as a device object!
	PDEVICE_OBJECT DeviceObject;
	FIL FfsFile;
	ULONG LinkMap[64];
	BOOLEAN WriteProtected;
	ULONG DiskNumber;
	ULONG IoCount;
	PSDMC_EMU_PARTITION NextPartition;
	PCONTROLLER_OBJECT DiskController;
	KDPC FinishDpc;
#if 0
	KDPC TimerDpc;
	KTIMER Timer;
	PIRP Irp;
#endif
};

typedef struct _SDMC_IO_WORK_ITEM {
	WORK_QUEUE_ITEM WorkItem;
	PDEVICE_OBJECT DeviceObject;
	PIRP Irp;
	BOOLEAN SinglePageAccess;
} SDMC_IO_WORK_ITEM, *PSDMC_IO_WORK_ITEM;

// PARTITION_INFORMATION should be 64 bits aligned
_Static_assert(sizeof(PARTITION_INFORMATION) == 0x20);

static NTSTATUS FresultToStatus(FRESULT Fr) {
	switch (Fr) {
		case FR_OK:
			return STATUS_SUCCESS;
		case FR_DISK_ERR:
			return STATUS_DISK_OPERATION_FAILED;
		case FR_INT_ERR:
			return STATUS_UNSUCCESSFUL;
		case FR_NOT_READY:
			return STATUS_DEVICE_NOT_READY;
		case FR_NO_FILE:
			return STATUS_OBJECT_NAME_NOT_FOUND;
		case FR_NO_PATH:
			return STATUS_OBJECT_PATH_NOT_FOUND;
		case FR_INVALID_NAME:
			return STATUS_OBJECT_NAME_INVALID;
		case FR_DENIED:
			return STATUS_ACCESS_DENIED;
		case FR_EXIST:
			return STATUS_OBJECT_NAME_COLLISION;
		case FR_INVALID_OBJECT:
			return STATUS_OBJECT_TYPE_MISMATCH;
		case FR_WRITE_PROTECTED:
			return STATUS_MEDIA_WRITE_PROTECTED;
		case FR_INVALID_DRIVE:
			return STATUS_OBJECT_PATH_NOT_FOUND;
		case FR_NOT_ENABLED:
			return STATUS_NO_SUCH_DEVICE;
		case FR_NO_FILESYSTEM:
			return STATUS_FS_DRIVER_REQUIRED;
		case FR_MKFS_ABORTED:
			return STATUS_UNSUCCESSFUL; // we shouldn't be calling mkfs anyway
		case FR_TIMEOUT:
			return STATUS_IO_TIMEOUT;
		case FR_LOCKED:
			return STATUS_SHARING_VIOLATION;
		case FR_NOT_ENOUGH_CORE:
			return STATUS_NO_MEMORY;
		case FR_TOO_MANY_OPEN_FILES:
			return STATUS_INSUFFICIENT_RESOURCES;
		case FR_INVALID_PARAMETER:
			return STATUS_INVALID_PARAMETER;
		default:
			return STATUS_UNSUCCESSFUL;
	}
}

static void SdmcEmuFinishDpc(
	PKDPC Dpc,
	PVOID DeferredContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
) {
	// Get the device object and the IRP.
	PDEVICE_OBJECT DeviceObject = (PDEVICE_OBJECT)SystemArgument1;
	PIRP Irp = (PIRP)SystemArgument2;
	
	PSDMC_EMU_EXTENSION Ext = (PSDMC_EMU_EXTENSION)DeviceObject->DeviceExtension;
	if (Ext->Signature == SIGNATURE_PARTITION) {
		PSDMC_EMU_PARTITION Partition = (PSDMC_EMU_PARTITION)
			DeviceObject->DeviceExtension;
		Ext = Partition->PhysicalDisk;
	}

	PCONTROLLER_OBJECT Controller = Ext->DiskController;
	
	// Complete the request.
	IoCompleteRequest(Irp, IO_DISK_INCREMENT);
	// Start next packet.
	IoStartNextPacket(DeviceObject, FALSE);
	// Release the controller object.
	IoFreeController(Controller);
}

#if 0
static void SdmcEmuTimerDpc(
	PKDPC Dpc,
	PVOID DeferredContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
) {
	// Get the device object and the IRP.
	PDEVICE_OBJECT DeviceObject = (PDEVICE_OBJECT)DeferredContext;
	PSDMC_EMU_EXTENSION Ext = (PSDMC_EMU_EXTENSION)DeviceObject->DeviceExtension;
	if (Ext->Signature == SIGNATURE_PARTITION) {
		PSDMC_EMU_PARTITION Partition = (PSDMC_EMU_PARTITION)
			DeviceObject->DeviceExtension;
		Ext = Partition->PhysicalDisk;
	}
	PIRP Irp = Ext->Irp;
	PCONTROLLER_OBJECT Controller = Ext->DiskController;
	
	Irp->IoStatus.Status = STATUS_IO_TIMEOUT;
	// Complete the request.
	IoCompleteRequest(Irp, IO_DISK_INCREMENT);
	// Start next packet.
	IoStartNextPacket(DeviceObject, FALSE);
	// Release the controller object.
	IoFreeController(Controller);
}
#endif

static void SdmcEmuFinishDispatch(
	PKDPC Dpc,
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp,
	PCONTROLLER_OBJECT Controller
) {
#if 0
	BOOLEAN Inserted = KeInsertQueueDpc(Dpc, DeviceObject, Irp);
	if (Inserted) return;
#endif
	
#if 0
	{
		PSDMC_EMU_EXTENSION Ext = (PSDMC_EMU_EXTENSION)DeviceObject->DeviceExtension;
		if (Ext->Signature == SIGNATURE_PARTITION) {
			PSDMC_EMU_PARTITION Partition = (PSDMC_EMU_PARTITION)
				DeviceObject->DeviceExtension;
			Ext = Partition->PhysicalDisk;
		}
		CHAR DebugText[100];
		_snprintf(DebugText, sizeof(DebugText),
			"SDMC: Disk %d finish packet %d\n",
			Ext->DiskNumber,
			Ext->IoCount
		);
		HalDisplayString(DebugText);
	}
#endif
#if 0
	// Raise to DISPATCH_LEVEL
	KIRQL OldIrql;
	KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
	// Call the DPC handler
	SdmcEmuFinishDpc(Dpc, DeviceObject, DeviceObject, Irp);
	// Lower IRQL
	KeLowerIrql(OldIrql);
#endif
	
	IoCompleteRequest(Irp, IO_DISK_INCREMENT);
}

static NTSTATUS SdmcEmuDeviceEnvCreate(
	PDRIVER_OBJECT DriverObject,
	FIL* FfsFile,
	ULONG DeviceIndex
) {
	
	if (s_EnvironmentDevice != NULL) return STATUS_OBJECT_NAME_COLLISION;
	
	if (s_ControllerObject == NULL) {
		s_ControllerObject = IoCreateController(0);
		if (s_ControllerObject == NULL) return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	STRING NtNameStr;
#if 0
	// Create the device name. Not needed for IOSSDMC as it only has 1 drive
	UCHAR NtName[256];
	sprintf(NtName, DEVNAME_ENVIRONMENT, DeviceIndex);
	// Wrap an ANSI string around it.
	RtlInitString(&NtNameStr, NtName);
#else
	(void)DeviceIndex;
	// Wrap an ANSI string around the device name.
	RtlInitString(&NtNameStr, DEVNAME_ENVIRONMENT);
#endif
	
	// Convert to unicode.
	UNICODE_STRING NtNameUs;
	NTSTATUS Status = RtlAnsiStringToUnicodeString(&NtNameUs, &NtNameStr, TRUE);
	if (!NT_SUCCESS(Status)) return Status;
	
	PDEVICE_OBJECT DeviceObject = NULL;
	do {
		// Create the device object.
		Status = IoCreateDevice(DriverObject, sizeof(SDMC_EMU_EXTENSION), &NtNameUs, FILE_DEVICE_DISK, 0, FALSE, &DeviceObject);
		if (!NT_SUCCESS(Status)) break;
		
		RtlFreeUnicodeString(&NtNameUs);
		
		// Initialise the new device object.
		DeviceObject->Flags |= DO_DIRECT_IO;
		DeviceObject->AlignmentRequirement = SDMC_SECTOR_SIZE - 1;
		DeviceObject->StackSize = 1;
		
		// Initialise the device extension.
		PSDMC_EMU_EXTENSION Ext = (PSDMC_EMU_EXTENSION) DeviceObject->DeviceExtension;
		RtlCopyMemory(&Ext->FfsFile, FfsFile, sizeof(Ext->FfsFile));
		Ext->FfsFile.cltbl = Ext->LinkMap;
		Ext->LinkMap[0] = sizeof(Ext->LinkMap) / sizeof(Ext->LinkMap[0]);
		if (f_lseek(&Ext->FfsFile, CREATE_LINKMAP) != FR_OK) Ext->FfsFile.cltbl = NULL;
		Ext->WriteProtected = FALSE;
		Ext->Signature = SIGNATURE_DISK;
		Ext->DeviceObject = DeviceObject;
		Ext->DiskNumber = -1;
		Ext->DiskController = s_ControllerObject;
		KeInitializeDpc(&Ext->FinishDpc, SdmcEmuFinishDpc, DeviceObject);
#if 0
		Ext->Irp = NULL;
		KeInitializeDpc(&Ext->TimerDpc, SdmcEmuTimerDpc, DeviceObject);
		KeInitializeTimer(&Ext->Timer);
#endif
		s_EnvironmentDevice = DeviceObject;
		return Status;
	} while (FALSE);
	if (DeviceObject != NULL) IoDeleteDevice(DeviceObject);
	return Status;
}

static NTSTATUS SdmcEmuDeviceCreateImpl(
	PDRIVER_OBJECT DriverObject,
	FIL* FfsFile,
	PULONG DeviceCount,
	ULONG BusCount,
	DEVICE_TYPE DeviceType,
	ULONG DeviceCharacteristics,
	const char * DevicePath
) {
	if (s_ControllerObject == NULL) {
		s_ControllerObject = IoCreateController(0);
		if (s_ControllerObject == NULL) return STATUS_INSUFFICIENT_RESOURCES;
	}
	BOOLEAN IsHardDisk = DeviceType == FILE_DEVICE_DISK && DeviceCharacteristics == 0;
	// Generate the NT object path name for this device.
	UCHAR NtName[256];
	sprintf(NtName, "\\Device\\%s%d", DevicePath, *DeviceCount);
	
	// Wrap an ANSI string around it.
	STRING NtNameStr;
	RtlInitString(&NtNameStr, NtName);
	
	// Convert to unicode.
	UNICODE_STRING NtNameUs;
	NTSTATUS Status = RtlAnsiStringToUnicodeString(&NtNameUs, &NtNameStr, TRUE);
	if (!NT_SUCCESS(Status)) return Status;

	HANDLE hDir = NULL;
	if (IsHardDisk) {
		// For hard disks, we create a directory, and Partition%d objects inside that
		// (where Partition0 means the entire disk)
		// We also don't need to symlink the arc name (kernel will do that for us)
		OBJECT_ATTRIBUTES Oa;
		InitializeObjectAttributes(&Oa, &NtNameUs, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL);
		Status = ZwCreateDirectoryObject(&hDir, DIRECTORY_ALL_ACCESS, &Oa);
		if (!NT_SUCCESS(Status)) return Status;
		RtlFreeUnicodeString(&NtNameUs);
		// Generate the NT object path name for the actual device.
		sprintf(NtName, "\\Device\\%s%d\\Partition0", DevicePath, *DeviceCount);
		RtlInitString(&NtNameStr, NtName);
		Status = RtlAnsiStringToUnicodeString(&NtNameUs, &NtNameStr, TRUE);
		// Let the following code create the device object.
	}
	
	PDEVICE_OBJECT DeviceObject = NULL;
	do {
		if (!NT_SUCCESS(Status)) break;
		// Create the device object.
		Status = IoCreateDevice(DriverObject, sizeof(SDMC_EMU_EXTENSION), &NtNameUs, DeviceType, DeviceCharacteristics, FALSE, &DeviceObject);
		if (!NT_SUCCESS(Status)) break;
	
		// Symlink it to the arc name.
		if (!IsHardDisk) {
			UCHAR ArcName[256];
			sprintf(ArcName,
				"\\ArcName\\%s%s(%d)fdisk(0)",
				s_SdControllerPath,
				DeviceType == FILE_DEVICE_CD_ROM ? "cdrom" : "disk",
				BusCount
			);
			STRING ArcNameStr;
			RtlInitString(&ArcNameStr, ArcName);
			UNICODE_STRING ArcNameUs;
			Status = RtlAnsiStringToUnicodeString(&ArcNameUs, &ArcNameStr, TRUE);
			if (!NT_SUCCESS(Status)) {
				RtlFreeUnicodeString(&NtNameUs);
				break;
			}
			IoAssignArcName(&ArcNameUs, &NtNameUs);
			RtlFreeUnicodeString(&ArcNameUs);
		}
		if (IsHardDisk) {
			// We don't need the directory handle any more.
			ZwClose(hDir);
			hDir = NULL;
		}
		RtlFreeUnicodeString(&NtNameUs);
		
		// Initialise the new device object.
		DeviceObject->Flags |= DO_DIRECT_IO;
		DeviceObject->AlignmentRequirement = SDMC_SECTOR_SIZE - 1;
		DeviceObject->StackSize = (DeviceType == FILE_DEVICE_CD_ROM ? 2 : 1);
		
		// Initialise the device extension.
		PSDMC_EMU_EXTENSION Ext = (PSDMC_EMU_EXTENSION) DeviceObject->DeviceExtension;
		RtlCopyMemory(&Ext->FfsFile, FfsFile, sizeof(Ext->FfsFile));
		Ext->FfsFile.cltbl = Ext->LinkMap;
		Ext->LinkMap[0] = sizeof(Ext->LinkMap) / sizeof(Ext->LinkMap[0]);
		if (f_lseek(&Ext->FfsFile, CREATE_LINKMAP) != FR_OK) Ext->FfsFile.cltbl = NULL;
		Ext->WriteProtected = (DeviceCharacteristics & FILE_READ_ONLY_DEVICE) != 0;
		Ext->Signature = SIGNATURE_DISK;
		Ext->DeviceObject = DeviceObject;
		Ext->DiskNumber = *DeviceCount;
		Ext->DiskController = s_ControllerObject;
		KeInitializeDpc(&Ext->FinishDpc, SdmcEmuFinishDpc, DeviceObject);
#if 0
		Ext->Irp = NULL;
		KeInitializeDpc(&Ext->TimerDpc, SdmcEmuTimerDpc, DeviceObject);
		KeInitializeTimer(&Ext->Timer);
#endif
		// TODO: more needed here?
		
		// For a hard disk, create all partition objects.
		if (IsHardDisk) {
			PDRIVE_LAYOUT_INFORMATION PartitionList;
			Status = IoReadPartitionTable(DeviceObject, SDMC_SECTOR_SIZE, TRUE, (PVOID)&PartitionList);
			if (NT_SUCCESS(Status)) {
				PSDMC_EMU_PARTITION ExtPart = NULL;
				for (ULONG Partition = 0; Partition < PartitionList->PartitionCount; Partition++) {
					sprintf(NtName, "\\Device\\%s%d\\Partition%d", DevicePath, *DeviceCount, Partition + 1);
					RtlInitString(&NtNameStr, NtName);
					Status = RtlAnsiStringToUnicodeString(&NtNameUs, &NtNameStr, TRUE);
					if (!NT_SUCCESS(Status)) return Status;
					Status = IoCreateDevice(DriverObject, sizeof(SDMC_EMU_PARTITION), &NtNameUs, DeviceType, DeviceCharacteristics, FALSE, &DeviceObject);
					
					RtlFreeUnicodeString(&NtNameUs);
					if (!NT_SUCCESS(Status)) {
						return Status;
					}
					
					DeviceObject->Flags |= DO_DIRECT_IO;
					DeviceObject->AlignmentRequirement = SDMC_SECTOR_SIZE - 1;
					DeviceObject->StackSize = 1;
					
					if (ExtPart == NULL) {
						Ext->NextPartition = (PSDMC_EMU_PARTITION) DeviceObject->DeviceExtension;
						ExtPart = Ext->NextPartition;
					} else {
						ExtPart->NextPartition = (PSDMC_EMU_PARTITION) DeviceObject->DeviceExtension;
						ExtPart = ExtPart->NextPartition;
					}
					ExtPart->PhysicalDisk = Ext;
					PPARTITION_INFORMATION PartitionInfo = &PartitionList->PartitionEntry[Partition];
					ExtPart->PartitionLength = PartitionInfo->PartitionLength;
					ExtPart->StartingOffset = PartitionInfo->StartingOffset;
					ExtPart->PartitionType = PartitionInfo->PartitionType;
					ExtPart->PartitionNumber = PartitionInfo->PartitionNumber;
					ExtPart->HiddenSectors = PartitionInfo->HiddenSectors;
					ExtPart->Signature = SIGNATURE_PARTITION;
				}
				ExFreePool(PartitionList);
			}
		}
		
		// All done.
		return Status;
	} while (FALSE);
	
	if (hDir != NULL) {
		// Delete the directory.
		ZwMakeTemporaryObject(hDir);
		ZwClose(hDir);
		RtlFreeUnicodeString(&NtNameUs);
	}
	if (DeviceObject != NULL) IoDeleteDevice(DeviceObject);
	return Status;
}

static NTSTATUS SdmcEmuDeviceCreate(
	PDRIVER_OBJECT DriverObject,
	FIL* FfsFile,
	PULONG DeviceCount,
	ULONG BusCount,
	DEVICE_TYPE DeviceType,
	ULONG DeviceCharacteristics,
	const char * DevicePath
) {
	NTSTATUS Status = SdmcEmuDeviceCreateImpl(
		DriverObject,
		FfsFile,
		DeviceCount,
		BusCount,
		DeviceType,
		DeviceCharacteristics,
		DevicePath
	);
	if (!NT_SUCCESS(Status)) return Status;
	*DeviceCount += 1;
	return Status;
}

static NTSTATUS SdmcEmuFloppyCreate(
	PDRIVER_OBJECT DriverObject,
	FIL* FfsFile,
	PULONG FloppyCount
) {
	// Floppy count should be exactly 0 here.
	if (*FloppyCount != 0) return STATUS_INVALID_PARAMETER;
	
	return SdmcEmuDeviceCreate(
		DriverObject,
		FfsFile,
		FloppyCount,
		0,
		FILE_DEVICE_DISK,
		FILE_REMOVABLE_MEDIA | FILE_FLOPPY_DISKETTE | FILE_READ_ONLY_DEVICE,
		"Floppy"
	);
}

static NTSTATUS SdmcEmuCdromCreate(
	PDRIVER_OBJECT DriverObject,
	FIL* FfsFile,
	PULONG CdromCount,
	ULONG BusCount
) {
	return SdmcEmuDeviceCreate(
		DriverObject,
		FfsFile,
		CdromCount,
		BusCount,
		FILE_DEVICE_CD_ROM,
		FILE_REMOVABLE_MEDIA | FILE_READ_ONLY_DEVICE,
		"CdRom"
	);
}

static NTSTATUS SdmcEmuDiskCreate(
	PDRIVER_OBJECT DriverObject,
	FIL* FfsFile,
	PULONG DiskCount,
	ULONG BusCount
) {
	return SdmcEmuDeviceCreate(
		DriverObject,
		FfsFile,
		DiskCount,
		BusCount,
		FILE_DEVICE_DISK,
		0,
		"Harddisk"
	);
}

NTSTATUS SdmcDiskCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	if (DeviceObject == s_EnvironmentDevice && Irp->RequestorMode != KernelMode) {
		Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_ACCESS_DENIED;
	}
	// just return success
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

static void SdmcDiskStartIoImpl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

extern __declspec(dllimport) KAFFINITY KeSetAffinityThread(PKTHREAD Thread, KAFFINITY Affinity);

NTSTATUS SdmcDiskRw(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	if (DeviceObject == s_EnvironmentDevice && Irp->RequestorMode != KernelMode) {
		Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_ACCESS_DENIED;
	}
	PSDMC_EMU_EXTENSION Ext = (PSDMC_EMU_EXTENSION)DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG Length = Stack->Parameters.Read.Length;
	LARGE_INTEGER Offset = Stack->Parameters.Read.ByteOffset;
	ULONG SectorOffset = Offset.LowPart % SDMC_SECTOR_SIZE;
	
	// Ensure the read is aligned to sector size.
	// We are going down to an fs r/w, but we expose a disk.
	if ((Length % SDMC_SECTOR_SIZE) != 0) {
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}
	
	// If this is a partition, get the physical disk.
	PSDMC_EMU_PARTITION Partition = NULL;
	if (Ext->Signature == SIGNATURE_PARTITION) {
		Partition = (PSDMC_EMU_PARTITION)DeviceObject->DeviceExtension;
		Ext = Partition->PhysicalDisk;
		// Get the ending offset of the read.
		LARGE_INTEGER OffsetEnd = Offset;
		OffsetEnd.QuadPart += Length;
		// Fix up the offset.
		Offset.QuadPart += Partition->StartingOffset.QuadPart;
		Stack->Parameters.Read.ByteOffset = Offset;
		// Get the partition length.
		LARGE_INTEGER PartitionLength = Partition->PartitionLength;
		// Ensure r/w in bounds of the partition.
		if (OffsetEnd.QuadPart > PartitionLength.QuadPart) {
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return STATUS_INVALID_PARAMETER;
		}
	}
	// ensure this is actually a disk
	if (Ext->Signature != SIGNATURE_DISK) {
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}
	
	// Get the file pointer.
	FIL* FfsFile = &Ext->FfsFile;
	// Get the file size.
	FSIZE_t DiskLength = f_size(FfsFile);
	// Ensure offset + length is not beyond the end of the img.
	// Also check for a 64bit end (impossible for an img on a fat32 fs)
	LARGE_INTEGER OffsetEnd = Offset;
	OffsetEnd.QuadPart += Length;
	if (
		OffsetEnd.QuadPart > DiskLength
	) {
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}
	
	// All looks good, start the operation on the physical disk device.
#if 0
	ULONG IoCount = InterlockedIncrement(&Ext->IoCount);
	{
		CHAR DebugText[100];
		_snprintf(DebugText, sizeof(DebugText),
			"SDMC: Disk %d starting packet %d\n",
			Ext->DiskNumber,
			IoCount
		);
		HalDisplayString(DebugText);
	}
#endif
#if 0
	Irp->IoStatus.Information = 0;
	IoMarkIrpPending(Irp);
	IoStartPacket(DeviceObject, Irp, &SectorOffset, NULL);
	return STATUS_PENDING;
#endif
	
	KAFFINITY OldAffinity = KeSetAffinityThread(KeGetCurrentThread(), 1);
	SdmcDiskStartIoImpl(DeviceObject, Irp);
	KeSetAffinityThread(KeGetCurrentThread(), OldAffinity);
	return Irp->IoStatus.Status;
}

static void SdmcDiskStartIoImpl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	PSDMC_EMU_EXTENSION Ext = (PSDMC_EMU_EXTENSION)DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	
	if (Ext->Signature == SIGNATURE_PARTITION) {
		PSDMC_EMU_PARTITION Partition = (PSDMC_EMU_PARTITION)
			DeviceObject->DeviceExtension;
		Ext = Partition->PhysicalDisk;
	}
	
#if 0
	{
		CHAR DebugText[100];
		_snprintf(DebugText, sizeof(DebugText),
			"SDMC: Disk %d startIO packet %d\n",
			Ext->DiskNumber,
			Ext->IoCount
		);
		HalDisplayString(DebugText);
	}
#endif
	
	PCONTROLLER_OBJECT Controller = Ext->DiskController;
	
#if 0
	// Cancel the timer.
	KeCancelTimer(&Ext->Timer);
#endif

	// Use a copy of the file on stack, to ensure thread safety
	FIL FfsFile = Ext->FfsFile;
	
	if (Stack->MajorFunction != IRP_MJ_DEVICE_CONTROL) {
		// Seek to the required offset.
		FRESULT fr = f_lseek(&FfsFile, Stack->Parameters.Read.ByteOffset.QuadPart);
		if (fr != FR_OK) {
			Irp->IoStatus.Status = FresultToStatus(fr);
			SdmcEmuFinishDispatch(&Ext->FinishDpc, DeviceObject, Irp, Controller);
			return;
		}
		ULONG MdlFlags = Irp->MdlAddress->MdlFlags;
		if ((MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL)) == 0) {
			BOOLEAN InvalidSystemMap = (MdlFlags & MDL_PARTIAL_HAS_BEEN_MAPPED) != 0;
			if (!InvalidSystemMap) {
				InvalidSystemMap = (MdlFlags & (MDL_PAGES_LOCKED | MDL_PARTIAL) == 0);
			}
			if (InvalidSystemMap) {
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				SdmcEmuFinishDispatch(&Ext->FinishDpc, DeviceObject, Irp, Controller);
				return;
			}
		}
		
		PVOID Buffer = MmGetSystemAddressForMdl(Irp->MdlAddress);
		if (Buffer == NULL) {
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			SdmcEmuFinishDispatch(&Ext->FinishDpc, DeviceObject, Irp, Controller);
			return;
		}
		UINT Transferred;
		ULONG Length = Stack->Parameters.Read.Length;
		if (Stack->MajorFunction == IRP_MJ_READ) {
			fr = f_read( &FfsFile, Buffer, Length, &Transferred);
		} else if (Stack->MajorFunction == IRP_MJ_WRITE) {
			//HalDisplayString("SDMC: write\n");
			fr = f_write( &FfsFile, Buffer, Length, &Transferred);
			// Ensure written data is flushed to disk.
			if (fr == FR_OK) {
				//HalDisplayString("SDMC: sync\n");
				fr = f_sync( &FfsFile );
				//HalDisplayString("SDMC: write_done\n");
			}
		} else fr = FR_INT_ERR;
		Irp->IoStatus.Status = FresultToStatus(fr);
		if (NT_SUCCESS(Irp->IoStatus.Status)) {
			Irp->IoStatus.Information = Transferred;
		}
		SdmcEmuFinishDispatch(&Ext->FinishDpc, DeviceObject, Irp, Controller);
		return;
	}
	
	// this is verify.
	// Seek to the required offset.
	FRESULT fr = f_lseek(&FfsFile, Stack->Parameters.Read.ByteOffset.QuadPart);
	if (fr != FR_OK) {
		Irp->IoStatus.Status = FresultToStatus(fr);
		SdmcEmuFinishDispatch(&Ext->FinishDpc, DeviceObject, Irp, Controller);
		return;
	}
	UINT Transferred;
	ULONG Length = Stack->Parameters.Read.Length;
	// allocate one page of non-paged memory
	PVOID Buffer = ExAllocatePool(NonPagedPool, 0x1000);
	if (Buffer == NULL) {
		Irp->IoStatus.Status = STATUS_NO_MEMORY;
		SdmcEmuFinishDispatch(&Ext->FinishDpc, DeviceObject, Irp, Controller);
		return;
	}
	while (Length > 0) {
		ULONG RoundLength = 0x1000;
		if (Length < 0x1000) RoundLength = Length;
		fr = f_read( &FfsFile, Buffer, RoundLength, &Transferred );
		if (fr == FR_OK && Transferred != RoundLength) fr = FR_MKFS_ABORTED;
		if (fr != FR_OK) {
			ExFreePool(Buffer);
			Irp->IoStatus.Status = FresultToStatus(fr);
			SdmcEmuFinishDispatch(&Ext->FinishDpc, DeviceObject, Irp, Controller);
			return;
		}
		Length -= RoundLength;
	}
	ExFreePool(Buffer);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	SdmcEmuFinishDispatch(&Ext->FinishDpc, DeviceObject, Irp, Controller);
}

void SdmcDiskPagingWorkRoutine(PSDMC_IO_WORK_ITEM Parameter) {
	// Grab the parameters.
	PDEVICE_OBJECT DeviceObject = Parameter->DeviceObject;
	PIRP Irp = Parameter->Irp;
	// Free the work item
	ExFreePool(Parameter);
	
	// Perform the I/O operation on the work thread
	SdmcDiskStartIoImpl(DeviceObject, Irp);
	// Dereference the device object, this is what Io*WorkItem in NT5 does
	ObDereferenceObject(DeviceObject);
}

#define MS_TO_TIMEOUT(ms) ((ms) * 10000)

IO_ALLOCATION_ACTION SdmcDiskSeizedController(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID NullBase, PVOID Context) {
	// Touching disk needs to be done by a worker.
	// This is because we need to wait on events, and we are currently at DISPATCH_LEVEL.
	
	// Oh, and Io*WorkItem got added in NT 5.
	
	// Double check this got called with a disk.
	PSDMC_EMU_EXTENSION Ext = (PSDMC_EMU_EXTENSION)Context;
	if (Ext->Signature != SIGNATURE_DISK) {	
		// ???
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		// Going to have to recurse here as we don't even have the DPC
		
		// Complete the request.
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		// Start next packet.
		IoStartNextPacket(DeviceObject, FALSE);
		// Release the controller on return so next packet can seize it.
		return DeallocateObject;
	}
	
	// Allocate the work item
	PSDMC_IO_WORK_ITEM WorkItem = (PSDMC_IO_WORK_ITEM)
		ExAllocatePool(NonPagedPool, sizeof(SDMC_IO_WORK_ITEM));
	if (WorkItem == NULL) {
		// um.
		Irp->IoStatus.Status = STATUS_NO_MEMORY;
		// Complete the request.
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		// Start next packet.
		IoStartNextPacket(DeviceObject, FALSE);
		// Release the controller on return so next packet can seize it.
		return DeallocateObject;
	}
	
	// Fill in the parameters.
	WorkItem->DeviceObject = DeviceObject;
	WorkItem->Irp = Irp;
	
	// Initialise the ExWorkItem
	ExInitializeWorkItem(
		&WorkItem->WorkItem,
		(PWORKER_THREAD_ROUTINE) SdmcDiskPagingWorkRoutine,
		WorkItem
	);
	
	// Reference the DeviceObject, this is what Io*WorkItem in NT5 is for
	ObReferenceObject(DeviceObject);
	// Queue it
	BOOLEAN IsForPaging = (Irp->Flags & IRP_PAGING_IO) != 0;
	ExQueueWorkItem(&WorkItem->WorkItem, CriticalWorkQueue); // IsForPaging ? CriticalWorkQueue : DelayedWorkQueue);
	
#if 0
	Ext->Irp = Irp;
	// Start the timer, allow one second for the work item to start running.
	LARGE_INTEGER DueTime;
	DueTime.QuadPart = -MS_TO_TIMEOUT(1000);
	KeSetTimer(&Ext->Timer, DueTime, &Ext->TimerDpc);
#endif
	
	return KeepObject;
}

void SdmcDiskStartIo(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	PSDMC_EMU_EXTENSION Ext = (PSDMC_EMU_EXTENSION)DeviceObject->DeviceExtension;
	// ensure this is actually a disk
	if (Ext->Signature == SIGNATURE_PARTITION) {
		PSDMC_EMU_PARTITION Partition = (PSDMC_EMU_PARTITION)
			DeviceObject->DeviceExtension;
		Ext = Partition->PhysicalDisk;
	}
	if (Ext->Signature != SIGNATURE_DISK) {
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		IoStartNextPacket(DeviceObject, FALSE);
		return;
	}
	
	// Seize the controller object of the disk device
	IoAllocateController(
		Ext->DiskController,
		DeviceObject,
		(PDRIVER_CONTROL)SdmcDiskSeizedController,
		Ext
	);
}

static void SdmcDiskUpdateDevices(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	PSDMC_EMU_EXTENSION Ext = (PSDMC_EMU_EXTENSION)DeviceObject->DeviceExtension;
	PSDMC_EMU_PARTITION Partition = NULL;
	if (Ext->Signature == SIGNATURE_PARTITION) {
		Partition = (PSDMC_EMU_PARTITION)DeviceObject->DeviceExtension;
		Ext = Partition->PhysicalDisk;
	}
	if (Ext->Signature != SIGNATURE_DISK) {
		return;
	}

	// Ensure that this device object describes a hard disk
	if (DeviceObject->DeviceType == FILE_DEVICE_CD_ROM) return;
	if ((DeviceObject->Characteristics & FILE_FLOPPY_DISKETTE) != 0) return;
	
	PDRIVE_LAYOUT_INFORMATION PartitionList = (PDRIVE_LAYOUT_INFORMATION) Irp->AssociatedIrp.SystemBuffer;
	
	ULONG PartitionCount = ((PartitionList->PartitionCount + 3) / 4) * 4;
	
	// Zero all the partition numbers.
	for (ULONG Partition = 0; Partition < PartitionCount; Partition++) {
		PartitionList->PartitionEntry[Partition].PartitionNumber = 0;
	}
	
	// Walk through the partitions to determine if any existing partitions were changed or deleted.
	ULONG LastPartitionNumber = 0;
	PSDMC_EMU_PARTITION LastPartition = NULL;
	for (PSDMC_EMU_PARTITION This = Ext->NextPartition; This != NULL; This = This->NextPartition) {
		LastPartition = This;
		
		if (This->PartitionNumber > LastPartitionNumber)
			LastPartitionNumber = This->PartitionNumber;
		
		// If the partition length is zero then it's unused.
		if (This->PartitionLength.QuadPart == 0) continue;
		
		// Look for a match in the partition list.
		BOOLEAN Found = FALSE;
		PPARTITION_INFORMATION PartitionEntry = NULL;
		for (ULONG Partition = 0; Partition < PartitionCount; Partition++) {
			PartitionEntry = &PartitionList->PartitionEntry[Partition];
			
			// Skip this if it's empty.
			if (PartitionEntry->PartitionType == PARTITION_ENTRY_UNUSED) continue;
			
			// Skip this if it's an extended partition.
			if (IsContainerPartition(PartitionEntry->PartitionType)) continue;
			
			// Offset is equal?
			if (PartitionEntry->StartingOffset.QuadPart != This->StartingOffset.QuadPart) continue;
			
			// Length is equal?
			if (PartitionEntry->PartitionLength.QuadPart != This->PartitionLength.QuadPart) continue;
			
			// Found the correct partition.
			Found = TRUE;
			PartitionEntry->PartitionNumber = This->PartitionNumber;
			break;
		}
		
		if (Found) {
			// Change the partition type if needed.
			if (PartitionEntry->RewritePartition)
				This->PartitionType = PartitionEntry->PartitionType;
		} else {
			// Didn't find a match, thus this partition was deleted.
			This->PartitionLength.QuadPart = 0;
		}
	}
	
	// Walk through the partitions to determine if any new partitions were created.
	for (ULONG Partition = 0; Partition < PartitionCount; Partition++) {
		PPARTITION_INFORMATION PartitionEntry = &PartitionList->PartitionEntry[Partition];
		
		// Skip this if it's empty.
		if (PartitionEntry->PartitionType == PARTITION_ENTRY_UNUSED) continue;
		
		// Skip this if it's an extended partition.
		if (IsContainerPartition(PartitionEntry->PartitionType)) continue;
		
		// Skip this if we know about it already
		if (PartitionEntry->PartitionNumber != 0) continue;
		
		// Find an existing, unused, partition.
		ULONG PartitionNumber = 0;
		PSDMC_EMU_PARTITION ModifiedPartition = NULL;
		for (PSDMC_EMU_PARTITION This = Ext->NextPartition; This != NULL; This = This->NextPartition) {
			if (This->PartitionLength.QuadPart != 0) continue;
			PartitionNumber = This->PartitionNumber;
			ModifiedPartition = This;
			break;
		}
		
		// If none was found then one needs to be created.
		if (PartitionNumber == 0) {
			LastPartitionNumber++;
			PartitionNumber = LastPartitionNumber;
			
			// Initialise the pathname.
			CCHAR NtName[MAXIMUM_FILENAME_LENGTH];
			sprintf(NtName, "\\Device\\Harddisk%d\\Partition%d", Ext->DiskNumber, PartitionNumber);
			STRING NtNameStr;
			RtlInitString(&NtNameStr, NtName);
			UNICODE_STRING NtNameUs;
			NTSTATUS Status = RtlAnsiStringToUnicodeString(&NtNameUs, &NtNameStr, TRUE);
			if (!NT_SUCCESS(Status)) continue;
			
			// Create the device object.
			PDEVICE_OBJECT NewDevice;
			Status = IoCreateDevice(DeviceObject->DriverObject, sizeof(SDMC_EMU_PARTITION), &NtNameUs, FILE_DEVICE_DISK, 0, FALSE, &NewDevice);
			RtlFreeUnicodeString(&NtNameUs);
			
			if (!NT_SUCCESS(Status)) continue;
			
			// Initialise the device object.
			NewDevice->Flags |= DO_DIRECT_IO;
			NewDevice->StackSize = DeviceObject->StackSize;
			NewDevice->Flags &= ~DO_DEVICE_INITIALIZING;
			
			// Initialise the device extension.
			PSDMC_EMU_PARTITION NewPartition = (PSDMC_EMU_PARTITION) NewDevice->DeviceExtension;
			NewPartition->Signature = SIGNATURE_PARTITION;
			NewPartition->PhysicalDisk = Ext;
			if (LastPartition != NULL) LastPartition->NextPartition = NewPartition;
			else Ext->NextPartition = NewPartition;
			NewPartition->NextPartition = NULL;
			
			ModifiedPartition = NewPartition;
			LastPartition = NewPartition;
		}
		// Update the partition information.
		ModifiedPartition->PartitionNumber = PartitionNumber;
		ModifiedPartition->PartitionType = PartitionEntry->PartitionType;
		ModifiedPartition->StartingOffset = PartitionEntry->StartingOffset;
		ModifiedPartition->PartitionLength = PartitionEntry->PartitionLength;
		ModifiedPartition->HiddenSectors = PartitionEntry->HiddenSectors;
		
		PartitionEntry->PartitionNumber = PartitionNumber;
	}
}

NTSTATUS SdmcDiskDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	if (DeviceObject == s_EnvironmentDevice) {
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	PSDMC_EMU_EXTENSION Ext = (PSDMC_EMU_EXTENSION)DeviceObject->DeviceExtension;
	PSDMC_EMU_PARTITION Partition = NULL;
	if (Ext->Signature == SIGNATURE_PARTITION) {
		Partition = (PSDMC_EMU_PARTITION)DeviceObject->DeviceExtension;
		Ext = Partition->PhysicalDisk;
	}
	if (Ext->Signature != SIGNATURE_DISK) {
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG LenIn = Stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG LenOut = Stack->Parameters.DeviceIoControl.OutputBufferLength;
	BOOLEAN IsCdRom = DeviceObject->DeviceType == FILE_DEVICE_CD_ROM;
	BOOLEAN IsFloppy = (DeviceObject->Characteristics & FILE_FLOPPY_DISKETTE) != 0;
	BOOLEAN FallThrough = FALSE;
	
	if (IsCdRom) {
		switch (Stack->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_CDROM_GET_DRIVE_GEOMETRY:
			FallThrough = TRUE;
			break;
		// Multisession / CD audio stuff : unimplemented.
		// We only support a single data track as .ISO.
		// If this stuff is unimplemented cdfs.sys does fall back to such anyways.
		// case IOCTL_CDROM_GET_LAST_SESSION:
		// case IOCTL_CDROM_READ_TOC:
		// case IOCTL_CDROM_PLAY_AUDIO_MSF:
		// case IOCTL_CDROM_SEEK_AUDIO_MSF:
		// case IOCTL_CDROM_PAUSE_AUDIO:
		// case IOCTL_CDROM_RESUME_AUDIO:
		// case IOCTL_CDROM_READ_Q_CHANNEL:
		// case IOCTL_CDROM_GET_CONTROL:
		// case IOCTL_CDROM_GET_VOLUME:
		// case IOCTL_CDROM_SET_VOLUME:
		// case IOCTL_CDROM_STOP_AUDIO:
		
		case IOCTL_CDROM_CHECK_VERIFY:
			// no implementation, moving files out from underneath us is unsupported
			break;
		default:
			Status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
	}
	else if (IsFloppy) {
		// we only have to implement this because things want to read from a floppy drive...
		switch (Stack->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_DISK_FORMAT_TRACKS:
		case IOCTL_DISK_FORMAT_TRACKS_EX:
        case IOCTL_DISK_IS_WRITABLE:
			Status = STATUS_MEDIA_WRITE_PROTECTED;
			break;
		case IOCTL_DISK_CHECK_VERIFY:
			// don't even bother to fall through, just return success
			break;
		case IOCTL_DISK_GET_DRIVE_GEOMETRY:
		case IOCTL_DISK_GET_MEDIA_TYPES:
			FallThrough = TRUE;
			break;
		default:
			Status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
	}
	else {
		FallThrough = TRUE;
	}
	
	if (!FallThrough) {
		Irp->IoStatus.Status = Status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return Status;
	}
	
	// not cdrom or floppy, or we fell through to common code
	switch (Stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_DISK_IS_WRITABLE:
		// only get here for a disk which is mounted rw anyway,  but..
		Status = STATUS_SUCCESS;
		if (Ext->WriteProtected) Status = STATUS_MEDIA_WRITE_PROTECTED;
		break;
	case IOCTL_DISK_GET_MEDIA_TYPES:
		if (!IsFloppy) {
			Status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
		// fall through, we only support the one geometry, which is the fatfs image we say is a floppy
	case IOCTL_DISK_GET_DRIVE_GEOMETRY:
	case IOCTL_CDROM_GET_DRIVE_GEOMETRY:
		{
			if (LenOut < sizeof(DISK_GEOMETRY)) {
				Status = STATUS_INVALID_PARAMETER;
				break;
			}
			PDISK_GEOMETRY Geometry = (PDISK_GEOMETRY) Irp->AssociatedIrp.SystemBuffer;
			// Set up the disk geometry.
			if (IsFloppy) {
				// setupdd expects floppy mediatype to be an actual floppy mediatype
				// thus, specify the highest capacity superfloppy :)
				Geometry->MediaType = F3_20Pt8_512;
			} else if (DeviceObject->Characteristics & FILE_REMOVABLE_MEDIA) {
				Geometry->MediaType = RemovableMedia;
			} else {
				Geometry->MediaType = FixedMedia;
			}
			// Default sectors per track / tracks per head as per what SCSI devices do
			Geometry->SectorsPerTrack = 32;
			Geometry->TracksPerCylinder = 64;
			// set BytesPerSector to the specified value.
			// For an ISO use 2048 byte sectors as expected; it's a multiple of 512 anyway
			// We will allow rws aligned to 512 no matter what.
			FSIZE_t DeviceLength = f_size(&Ext->FfsFile);
			if (Partition != NULL) DeviceLength = Partition->PartitionLength.QuadPart;
			if (IsCdRom) {
				_Static_assert((2048 % SDMC_SECTOR_SIZE) == 0);
				Geometry->BytesPerSector = 2048;
				Geometry->Cylinders.LowPart = DeviceLength / (32 * 64 * 2048);
			} else {
				Geometry->BytesPerSector = SDMC_SECTOR_SIZE;
				Geometry->Cylinders.LowPart = DeviceLength / (32 * 64 * SDMC_SECTOR_SIZE);
			}
			Geometry->Cylinders.HighPart = 0;
			// all done.
			Irp->IoStatus.Information = sizeof(*Geometry);
		}
		break;
	case IOCTL_DISK_CHECK_VERIFY:
		// Just return success here.
		break;
	case IOCTL_DISK_VERIFY:
		{
			if (LenIn < sizeof(VERIFY_INFORMATION)) {
				Status = STATUS_INVALID_PARAMETER;
				break;
			}
			Irp->IoStatus.Information = 0;
			//IoMarkIrpPending(Irp);
			// Make it look like a rw request for the async code.
			PVERIFY_INFORMATION VerifyInfo = (PVERIFY_INFORMATION)Irp->AssociatedIrp.SystemBuffer;
			Stack->Parameters.Read.Length = VerifyInfo->Length;
			Stack->Parameters.Read.ByteOffset.QuadPart = VerifyInfo->StartingOffset.QuadPart;
			if (Partition != NULL)
				Stack->Parameters.Read.ByteOffset.QuadPart += Partition->StartingOffset.QuadPart;
			// make sure the end looks ok
			FSIZE_t DeviceLength = f_size(&Ext->FfsFile);
			LARGE_INTEGER OffsetEnd = Stack->Parameters.Read.ByteOffset;
			OffsetEnd.QuadPart += Stack->Parameters.Read.Length;
			if (OffsetEnd.QuadPart > DeviceLength) {
				Status = STATUS_INVALID_PARAMETER;
				break;
			}
			//ULONG SectorOffset = Stack->Parameters.Read.ByteOffset.QuadPart % SDMC_SECTOR_SIZE;
			//IoStartPacket(DeviceObject, Irp, &SectorOffset, NULL);
			//return STATUS_PENDING;
			// Just return success here.
		}
		break;
	case IOCTL_DISK_GET_PARTITION_INFO:
		{
			if (LenOut < sizeof(PARTITION_INFORMATION)) {
				Status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (Partition == NULL) {
				Status = STATUS_INVALID_DEVICE_REQUEST;
				break;
			}
			PPARTITION_INFORMATION Info = (PPARTITION_INFORMATION)Irp->AssociatedIrp.SystemBuffer;
			Info->PartitionType = Partition->PartitionType;
			Info->StartingOffset = Partition->StartingOffset;
			Info->PartitionLength = Partition->PartitionLength;
			Info->HiddenSectors = Partition->HiddenSectors;
			Info->PartitionNumber = Partition->PartitionNumber;
			
			Irp->IoStatus.Information = sizeof(*Info);
		}
		break;
	case IOCTL_DISK_SET_PARTITION_INFO:
		{
			if (LenIn < sizeof(SET_PARTITION_INFORMATION)) {
				Status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (Partition == NULL) {
				Status = STATUS_INVALID_DEVICE_REQUEST;
				break;
			}
			PSET_PARTITION_INFORMATION Info = (PSET_PARTITION_INFORMATION)Irp->AssociatedIrp.SystemBuffer;
			Status = IoSetPartitionInformation(Ext->DeviceObject, SDMC_SECTOR_SIZE, (ULONG) Partition->PartitionNumber, Info->PartitionType);
			if (NT_SUCCESS(Status)) Partition->PartitionType = Info->PartitionType;
		}
		break;
	case IOCTL_DISK_GET_DRIVE_LAYOUT:
		{
			if (LenOut < sizeof(DRIVE_LAYOUT_INFORMATION)) {
				Status = STATUS_INVALID_PARAMETER;
				break;
			}
			
			if (IsFloppy) {
				Status = STATUS_INVALID_DEVICE_REQUEST;
				break;
			}
			
			PDRIVE_LAYOUT_INFORMATION PartitionList;
			Status = IoReadPartitionTable(Ext->DeviceObject, SDMC_SECTOR_SIZE, FALSE, &PartitionList);
			if (!NT_SUCCESS(Status)) break;
			
			// what's the size of the buffer we were given?
			ULONG Size = __builtin_offsetof(DRIVE_LAYOUT_INFORMATION, PartitionEntry);
			Size += PartitionList->PartitionCount * sizeof(PartitionList->PartitionEntry[0]);
			if (LenOut < Size) {
				Status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			Status = STATUS_SUCCESS;
			RtlMoveMemory(Irp->AssociatedIrp.SystemBuffer, PartitionList, Size);
			Irp->IoStatus.Information = Size;
			SdmcDiskUpdateDevices(DeviceObject, Irp);
			ExFreePool(PartitionList);
		}
		break;
	case IOCTL_DISK_SET_DRIVE_LAYOUT:
		{
			if (LenIn < sizeof(DRIVE_LAYOUT_INFORMATION)) {
				Status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (IsFloppy) {
				Status = STATUS_INVALID_DEVICE_REQUEST;
				break;
			}
			
			PDRIVE_LAYOUT_INFORMATION PartitionList = (PDRIVE_LAYOUT_INFORMATION) Irp->AssociatedIrp.SystemBuffer;
			
			SdmcDiskUpdateDevices(DeviceObject, Irp);
			
			Status = IoWritePartitionTable(Ext->DeviceObject, SDMC_SECTOR_SIZE, 32, 64, PartitionList);
			if (!NT_SUCCESS(Status)) break;
			Irp->IoStatus.Information = Stack->Parameters.DeviceIoControl.OutputBufferLength;			
		}
		break;
	case IOCTL_DISK_INTERNAL_SET_VERIFY:
		if (Irp->RequestorMode != KernelMode) break;
		DeviceObject->Flags |= DO_VERIFY_VOLUME;
		break;
	case IOCTL_DISK_INTERNAL_CLEAR_VERIFY:
		if (Irp->RequestorMode != KernelMode) break;
		DeviceObject->Flags &= ~DO_VERIFY_VOLUME;
		break;
	case IOCTL_SCSI_GET_ADDRESS:
	{
		if (LenOut < sizeof(SCSI_ADDRESS)) {
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		
		PSCSI_ADDRESS ScsiAddress = (PSCSI_ADDRESS) Irp->AssociatedIrp.SystemBuffer;
		
		ScsiAddress->Length = sizeof(ScsiAddress);
		ScsiAddress->PortNumber = 0;
		if (IsFloppy) ScsiAddress->PathId = 0;
		else if (IsCdRom) ScsiAddress->PathId = 1;
		else ScsiAddress->PathId = 2;
		ScsiAddress->TargetId = Ext->DiskNumber;
		ScsiAddress->Lun = 0;
		
		break;
	}
	default:
		Status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

static void SdmcpSetEntryPoints(PDRIVER_OBJECT DriverObject) {
	// Set up the device driver entry points.
	DriverObject->MajorFunction[IRP_MJ_CREATE] = SdmcDiskCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = SdmcDiskCreate;
	DriverObject->DriverStartIo = SdmcDiskStartIo;
	DriverObject->MajorFunction[IRP_MJ_READ] = SdmcDiskRw;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = SdmcDiskRw;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SdmcDiskDeviceControl;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	// If this system is flipper, then it's not running IOS
	if ((ULONG)RUNTIME_BLOCK[RUNTIME_SYSTEM_TYPE] == ARTX_SYSTEM_FLIPPER) return STATUS_NO_SUCH_DEVICE;
	
	CHAR Buffer[512];
	// Mount the sd card
	FRESULT fr = f_mount(&s_FatFs, "", 1);
	if (fr != FR_OK) {
		_snprintf(Buffer, sizeof(Buffer), "IOSSDMC: f_mount failed %d\n", fr);
		HalDisplayString(Buffer);
		return STATUS_NO_SUCH_DEVICE;
	}
	
	// Get the configuration information.
	PCONFIGURATION_INFORMATION Config = IoGetConfigurationInformation();
	
	// First, check the floppy drive.
	// Even though we technically open rw in ARCfw,
	// we shall open ro here.
	BOOLEAN OpenedAtLeastOneDevice = FALSE;
	FIL fp;
	RtlZeroMemory(&fp, sizeof(fp));
	
	// Before doing anything, check the environment.
	if ((ULONG)RUNTIME_BLOCK[RUNTIME_ENV_DISK] == 4) {
		// Firmware used environment from this sd card.
		fr = f_open(&fp, "/" FILENAME_ENVIRONMENT, FA_READ | FA_WRITE);
		if (fr == FR_OK) {
			NTSTATUS Status = SdmcEmuDeviceEnvCreate(DriverObject, &fp, 4);
			if (NT_SUCCESS(Status)) {
				OpenedAtLeastOneDevice = TRUE;
			} else {
				_snprintf(Buffer, sizeof(Buffer), "IOSSDMC: SdmcEmuDeviceEnvCreate failed %08x\n", Status);
				HalDisplayString(Buffer);
			}
		} else {
			_snprintf(Buffer, sizeof(Buffer), "IOSSDMC: f_open(environ) failed %d\n", fr);
			HalDisplayString(Buffer);
		}
	}
	
	RtlZeroMemory(&fp, sizeof(fp));
	fr = f_open(&fp, "/" FILENAME_FLOPPY_IMAGE, FA_READ);
	if (fr == FR_OK) {
		// Got a floppy drive.
		if (NT_SUCCESS(
			SdmcEmuFloppyCreate(DriverObject, &fp, &Config->FloppyCount)
		)) {
			OpenedAtLeastOneDevice = TRUE;
		}
	// Do not print an error if that error was file not found.
	} else if (fr != FR_NO_FILE) {
		_snprintf(Buffer, sizeof(Buffer), "IOSSDMC: f_open(floppy) failed %d\n", fr);
		HalDisplayString(Buffer);
	}
	
	// Check for ISO images. We support a max of 100.
	CCHAR FileName[32];
	for (ULONG i = 0; i < 100; i++) {
		sprintf(FileName, "/" FILENAME_CDROM_IMAGE, i);
		RtlZeroMemory(&fp, sizeof(fp));
		fr = f_open(&fp, FileName, FA_READ | FA_WRITE);
		if (fr != FR_OK) {
			// Do not print an error if that error was file not found.
			if (fr == FR_NO_FILE) break;
			_snprintf(Buffer, sizeof(Buffer), "IOSSDMC: f_open(cd%d) failed %d\n", i, fr);
			HalDisplayString(Buffer);
			break;
		}
		// Got an ISO image.
		if (NT_SUCCESS(
			SdmcEmuCdromCreate(DriverObject, &fp, &Config->CdRomCount, i)
		)) {
			OpenedAtLeastOneDevice = TRUE;
		}
	}
	
	BOOLEAN EntryPointsSet = FALSE;
	
	// Check for hard disk images. We support a max of 100.
	for (ULONG i = 0; i < 100; i++) {
		sprintf(FileName, "/" FILENAME_HARD_DISK_IMAGE, i);
		RtlZeroMemory(&fp, sizeof(fp));
		fr = f_open(&fp, FileName, FA_READ | FA_WRITE);
		if (fr != FR_OK) {
			// Do not print an error if that error was file not found.
			if (fr == FR_NO_FILE) break;
			_snprintf(Buffer, sizeof(Buffer), "IOSSDMC: f_open(hd%d) failed %d\n", i, fr);
			HalDisplayString(Buffer);
			break;
		}
		// Got a hard disk image.
		// If the entry points weren't already set, set them now;
		// IoReadPartitionTable tries to make an IRP_MJ_READ...
		if (!EntryPointsSet) {
			SdmcpSetEntryPoints(DriverObject);
			EntryPointsSet = TRUE;
		}
		if (NT_SUCCESS(
			SdmcEmuDiskCreate(DriverObject, &fp, &Config->DiskCount, i)
		)) {
			OpenedAtLeastOneDevice = TRUE;
		}
	}

	if (!OpenedAtLeastOneDevice) {
		// SD card mounted, but no image files could be opened.
		// Unmount the sd card.
		f_unmount("");
		// Return no such device.
		return STATUS_NO_SUCH_DEVICE;
	}
	
	if (!EntryPointsSet) {
		SdmcpSetEntryPoints(DriverObject);
	}
	
	return STATUS_SUCCESS;
}
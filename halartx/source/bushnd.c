// Bus handler stubs
// Our drivers just won't care about such things

// This is for exported functions called by various things;
// (kernel and drivers);
// it gets movable data for things like addrs/interrupts that can move with different slots;
// RVL has none of that (directly at PPC anyway);
// anything like that would be USB and IOS handles that anyway.

#include "halp.h"
#include "ints.h"


extern const ULONG HalpInterruptToIrql[];

enum {
	AFFINITY_CORE0 = (1 << 0),
	AFFINITY_CORE1 = (1 << 1),
	AFFINITY_CORE2 = (1 << 2),
	AFFINITY_ALL = AFFINITY_CORE0 | AFFINITY_CORE1 | AFFINITY_CORE2
};

static const UCHAR HalpInterruptAffinity[] = {
	AFFINITY_ALL, // ERROR
	AFFINITY_ALL, // RESET
	AFFINITY_ALL, // DVD
	AFFINITY_ALL, // SERIAL
	AFFINITY_CORE0, // EXI (used for USB gecko thus kd)
	AFFINITY_ALL, // AUDIO
	AFFINITY_ALL, // DSP
	AFFINITY_ALL, // MEM
	AFFINITY_CORE0, // VI
	AFFINITY_CORE0, // PE_TOKEN
	AFFINITY_CORE0, // PE_FINISH
	AFFINITY_CORE0, // CP_FIFO
	AFFINITY_ALL, // DEBUG
	AFFINITY_ALL, // HIGHSPEED_PORT (gone from RVL)
	AFFINITY_CORE0, // VEGAS (IOS IPC)
	AFFINITY_CORE0, // (15)
	AFFINITY_CORE0, // (16)
	AFFINITY_CORE0, AFFINITY_CORE1, AFFINITY_CORE2, // CP_FIFO for each core
	AFFINITY_CORE0, AFFINITY_CORE1, AFFINITY_CORE2, // IPI
	AFFINITY_ALL, // GPU7
	AFFINITY_ALL, // LATTE
};

ULONG
HalGetBusData(
	IN BUS_DATA_TYPE  BusDataType,
	IN ULONG BusNumber,
	IN ULONG SlotNumber,
	IN PVOID Buffer,
	IN ULONG Length
	)
{
	return HalGetBusDataByOffset (BusDataType,BusNumber,SlotNumber,Buffer,0,Length);
}

ULONG
HalGetBusDataByOffset (
	IN BUS_DATA_TYPE  BusDataType,
	IN ULONG BusNumber,
	IN ULONG SlotNumber,
	IN PVOID Buffer,
	IN ULONG Offset,
	IN ULONG Length
    )
{
	return 0;
}

ULONG
HalSetBusData(
    IN BUS_DATA_TYPE  BusDataType,
    IN ULONG BusNumber,
    IN ULONG SlotNumber,
    IN PVOID Buffer,
    IN ULONG Length
    )
{
	return 0;
}

ULONG
HalSetBusDataByOffset(
    IN BUS_DATA_TYPE  BusDataType,
    IN ULONG BusNumber,
    IN ULONG SlotNumber,
    IN PVOID Buffer,
    IN ULONG Offset,
    IN ULONG Length
    )
{
	return 0;
}

NTSTATUS
HalAdjustResourceList (
    IN OUT PIO_RESOURCE_REQUIREMENTS_LIST   *pResourceList
    )
{
	return STATUS_SUCCESS;
}

NTSTATUS
HalAssignSlotResources (
    IN PUNICODE_STRING          RegistryPath,
    IN PUNICODE_STRING          DriverClassName       OPTIONAL,
    IN PDRIVER_OBJECT           DriverObject,
    IN PDEVICE_OBJECT           DeviceObject          OPTIONAL,
    IN INTERFACE_TYPE           BusType,
    IN ULONG                    BusNumber,
    IN ULONG                    SlotNumber,
    IN OUT PCM_RESOURCE_LIST   *AllocatedResources
    )
{
	return STATUS_NOT_FOUND;
}

// This needs an actual implementation.
ULONG
HalGetInterruptVector(
    IN INTERFACE_TYPE  InterfaceType,
    IN ULONG BusNumber,
    IN ULONG BusInterruptLevel,
    IN ULONG BusInterruptVector,
    OUT PKIRQL Irql,
    OUT PKAFFINITY Affinity
    )
{
	
	*Irql = 0;
	*Affinity = 0;
	
	if (!HalpBusIsInternal(InterfaceType)) return 0;
	
	// Caller asked for an interrupt on the internal bus.
	if (BusNumber != 0) return 0;
	
	// Check if passed interrupt number is valid.
	BOOLEAN IsCafe = HalpSystemIsCafe();
	if (BusInterruptVector > VECTOR_RVL_MAX) {
		if (IsCafe) {
			if (BusInterruptVector > VECTOR_CAFE_MAX) return 0;
		} else {
			return 0;
		}
	}
	
	ULONG iAffinity = 1;
	if (IsCafe) {
		iAffinity = HalpInterruptAffinity[BusInterruptVector];
	}
	*Affinity = iAffinity;
	*Irql = HalpInterruptToIrql[BusInterruptVector];
	
	return DEVICE_VECTORS + BusInterruptVector;
}

// This needs an actual implementation.
BOOLEAN
HalTranslateBusAddress(
    IN INTERFACE_TYPE  InterfaceType,
    IN ULONG BusNumber,
    IN PHYSICAL_ADDRESS BusAddress,
    IN OUT PULONG AddressSpace,
    OUT PPHYSICAL_ADDRESS TranslatedAddress
    )
{
	// For internal bus, just pass out the same physical address.
	if (!HalpBusIsInternal(InterfaceType)) return FALSE;
	if (BusNumber != 0) return FALSE;
	
	*AddressSpace = 0;
	*TranslatedAddress = BusAddress;
	return TRUE;
}


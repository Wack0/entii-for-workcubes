#pragma once

#include "nthal.h"

#include <ppcdef.h>

// Declare this struct as hal.h declares it inside a function definition
struct _DEVICE_CONTROL_CONTEXT;

#include <hal.h>

#include "../../inc/runtime.h"

// Parts of NT require a non-internal bus for some device classes (hi videoprt) to work at all.
// We use VME bus for this. Nothing in base NT uses it at all.
static inline BOOLEAN HalpBusIsInternal(INTERFACE_TYPE InterfaceType) {
	return InterfaceType == Internal || InterfaceType == VMEBus;
}

#define BIT(x) (1 << (x))

#define __mfspr(spr)    \
  ({ ULONG mfsprResult; \
     __asm__ volatile ("mfspr %0, %1" : "=r" (mfsprResult) : "n" (spr)); \
     mfsprResult; })

#define __mtspr(spr, value)     \
  __asm__ volatile ("mtspr %0, %1" : : "n" (spr), "r" (value))

#define SPR_HID0 1008
#define SPR_HID1 1009
#define SPR_HID2 920
#define SPR_HID4 1011
// Espresso extra SPRs that we care about
#define SPR_HID5 944
#define SPR_SCR 947
#define SPR_CAR 948
#define SPR_BCR 949
#define SPR_PIR 1007

enum {
	HID4_SBE = 0x02000000,
	
	HID5_H5A = 0x80000000, // enable HID5
	HID5_PIRE = 0x40000000, // enable PIR
	
	SCR_IPI_BIT = 18,
	SCR_WAKE_BIT = 21,
	
	SCR_IPI2 = BIT(SCR_IPI_BIT + 0),
	SCR_IPI1 = BIT(SCR_IPI_BIT + 1),
	SCR_IPI0 = BIT(SCR_IPI_BIT + 2),
	SCR_WAKE2 = BIT(SCR_WAKE_BIT + 0),
	SCR_WAKE1 = BIT(SCR_WAKE_BIT + 1),
	SCR_WAKE0 = BIT(SCR_WAKE_BIT + 2),
};

static inline BOOLEAN HalpCpuIsEspresso(void) {
	ULONG ProcessorType;
	asm volatile("mfpvr %0\n" : "=r" (ProcessorType));
	ProcessorType >>= 16;
	return ProcessorType == 0x7001;
}

ULONGLONG HalpReadTimeBase(void);

//
// Resource usage information
//

#define MAXIMUM_IDTVECTOR 255

typedef struct {
    UCHAR   Flags;
    KIRQL   Irql;
    UCHAR   BusReleativeVector;
} IDTUsage;

typedef struct _HalAddressUsage{
    struct _HalAddressUsage *Next;
    CM_RESOURCE_TYPE        Type;       // Port or Memory
    UCHAR                   Flags;      // same as IDTUsage.Flags
    struct {
        ULONG   Start;
        USHORT  Length;
    }                       Element[];
} ADDRESS_USAGE;

#define IDTOwned            0x01        // IDT is not available for others
#define InterruptLatched    0x02        // Level or Latched
#define InternalUsage       0x11        // Report usage on internal bus
#define DeviceUsage         0x21        // Report usage on device bus

extern IDTUsage         HalpIDTUsage[];
extern ADDRESS_USAGE   *HalpAddressUsageList;

#define HalpRegisterAddressUsage(a) \
    (a)->Next = HalpAddressUsageList, HalpAddressUsageList = (a);

extern ULONG HalpPciMaxBuses;  // in pxpcibus.c


//
// Define PER processor HAL data.
//
// This structure is assigned the address &PCR->HalReserved which is
// an array of 16 ULONGs in the architectually defined section of the
// PCR.
//

typedef struct {
    ULONG                    PhysicalProcessor;
    ULONG                    HardPriority;
} UNIPROCESSOR_DATA, *PUNIPROCESSOR_DATA;

#define HALPCR  ((PUNIPROCESSOR_DATA)&PCR->HalReserved)

//
// Override standard definition of _enable/_disable for this compiler.
//


#if defined(_enable)

#undef _enable
#undef _disable

#endif


#define _disable()    \
  ({ ULONG result; \
     __asm__ volatile ("mfmsr %0" : "=r" (result)); \
     ULONG mcrNew = result & ~0x8000; \
     __asm__ volatile ("mtmsr %0 ; isync" : : "r" (mcrNew)); \
     /*return*/ result & 0x8000; })

#define _enable()     \
  ({ ULONG result; \
     __asm__ volatile ("mfmsr %0" : "=r" (result)); \
     ULONG mcrNew = result | 0x8000; \
     __asm__ volatile ("mtmsr %0 ; isync" : : "r" (mcrNew)); })

#define HalpEnableInterrupts()    _enable()
#define HalpDisableInterrupts()   _disable()

extern KSPIN_LOCK HalpBeepLock;
extern KSPIN_LOCK HalpDisplayAdapterLock;
extern KSPIN_LOCK HalpSystemInterruptLock;
extern ULONG HalpProfileCount;
extern ULONG HalpCurrentTimeIncrement;
extern ULONG HalpNewTimeIncrement;

BOOLEAN
HalpCalibrateStall (
    VOID
    );

BOOLEAN
HalpInitialiseInterrupts (
    VOID
    );

VOID
HalpIpiInterrupt (
    VOID
    );

BOOLEAN
HalpInitializeDisplay0 (
    IN PLOADER_PARAMETER_BLOCK LoaderBlock
    );

BOOLEAN
HalpMapIoSpace (
    VOID
    );



VOID
HalpRegisterVector (
    IN UCHAR    ReportFlags,
    IN ULONG    BusInterruptVector,
    IN ULONG    SystemInterruptVector,
    IN KIRQL    SystemIrql
    );

BOOLEAN
HalpCreateSioStructures(
    VOID
    );

BOOLEAN
HalpHandleExternalInterrupt(
    IN PKINTERRUPT Interrupt,
    IN PVOID ServiceContext,
    IN PVOID TrapFrame
    );

ULONG
HalpUpdateDecrementer(
    ULONG
    );

NTKERNELAPI
PVOID
KePhase0MapIo(
    IN ULONG MemoryBase,
    IN ULONG MemorySize
    );

NTKERNELAPI
PVOID
KePhase0DeleteIoMap(
    IN ULONG MemoryBase,
    IN ULONG MemorySize
    );

BOOLEAN
HalpHandleDecrementerInterrupt (
    IN PKINTERRUPT Interrupt,
    IN PVOID ServiceContext,
    IN PVOID TrapFrame
    );

VOID
HalpZeroPerformanceCounter(
    VOID
    );

BOOLEAN
HalpHandleMachineCheck(
  IN PKINTERRUPT Interrupt,
  IN PVOID ServiceContext
  );

void HalpInvalidateDcacheRange(PVOID Start, ULONG Length);
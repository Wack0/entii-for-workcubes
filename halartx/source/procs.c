// Start other processors.

#include "halp.h"
#include "exi.h"
#include "pxi_regs.h"

#include <stdio.h>

extern PEXI_REGISTERS HalpExiRegs;
extern PPXI_REGISTERS HalpPxiRegisters;
extern IDTUsage        HalpIDTUsage[MAXIMUM_IDTVECTOR];
static ULONG s_LastProcessorStarted = 0;


static const USHORT s_HalName[] = {
	'A', 'r', 't', 'X', ' ', 'H', 'A', 'L', 0
};

static const UNICODE_STRING s_UsHalName = {
	(sizeof(s_HalName) / sizeof(*s_HalName)) - 1,
	(sizeof(s_HalName) / sizeof(*s_HalName)),
	(USHORT*)s_HalName
};

static BOOLEAN HalpSystemIsUniprocessor(void) {
	if (!HalpCpuIsEspresso()) return TRUE; // non-Espresso uniprocessor
	if (*(PULONG)(0x80000008) == 0) return TRUE; // don't bring other cores up if stwcx errata isn't worked around
	return FALSE;
}

// https://github.com/fail0verflow/hbc/blob/a8e5f6c0f7e484c7f7112967eee6eee47b27d9ac/wiipax/stub/sync.c#L29
static void sync_before_exec(const void* p, ULONG len)
{

	ULONG a, b;

	a = (ULONG)p & ~0x1f;
	b = ((ULONG)p + len + 0x1f) & ~0x1f;

	for (; a < b; a += 32)
		asm("dcbst 0,%0 ; sync ; icbi 0,%0" : : "b"(a));

	asm("sync ; isync");
}

#define EXI_WRITE_BOOT_VECTOR(Index) MmioWriteBase32(MMIO_OFFSET(HalpExiRegs, BootVector[Index]), BootCode[Index])
#define WRITE_BOOT_VECTOR(Index) MmioWriteBase32(BootVector, Index * sizeof(ULONG), BootCode[Index])

// Start the next processor.
BOOLEAN HalStartNextProcessor(IN PLOADER_PARAMETER_BLOCK LoaderBlock, IN PKPROCESSOR_STATE ProcessorState) {
	if (HalpSystemIsUniprocessor()) return FALSE;
	if (s_LastProcessorStarted == 2) return FALSE;
	BOOLEAN IsCafe = HalpSystemIsCafe();
	if (!IsCafe && s_LastProcessorStarted == 1) return FALSE;
	
	// Violate the license agreement. (NT Workstation only allows 2 CPUs)
	// KeRegisteredProcessors located 4 bytes after exported KeNumberProcessors, this is true in all of PPC NT
	// KeRegisteredProcessors gets set to min of KeLicensedProcessors and max of 32 before entering here.
	// So setting in here will always cause max CPUs to come up.
	if (s_LastProcessorStarted == 0) {
		PUCHAR pKeNumberProcessors = (PUCHAR)&KeNumberProcessors;
		// work around compiler bug
		asm volatile("");
		pKeNumberProcessors = *(PUCHAR*)pKeNumberProcessors;
		PULONG KeRegisteredProcessors = (PULONG)&pKeNumberProcessors[4];
		
		*KeRegisteredProcessors = 32;
		sync_before_exec(KeRegisteredProcessors, sizeof(*KeRegisteredProcessors));
	}
	
	// Write some code at the boot vector.
	if (HalpExiRegs == NULL || HalpPxiRegisters == NULL) return FALSE;
	static ULONG s_BootCode[] = {
		0x60000000, // nop
		0x60000000, // nop
		// initialise the registers for the kernel
		0x3cc00000, // lis r6, 0
		0x60c60000, // ori r6, r6, 0
		0x3c200000, // lis r1, 0
		0x60210000, // ori r1, r1, 0
		0x3c600000, // lis r3, 0
		0x60630000, // ori r3, r3, 0
		0x3c800000, // lis r4, 0
		0x60840000, // ori r4, r4, 0
		// initialise the entry point
		0x3c400000, // lis r2, 0
		0x60420000, // ori r2, r2, 0
		0x7cda03a6, // mtspr SRR0, r6
		0x38a00001, // li r5, MSR_LE
		0x7cbb03a6, // mtspr SRR1, r5
		0x4c000064, // rfi
	};
	_Static_assert(sizeof(s_BootCode) <= sizeof(HalpExiRegs->BootVector));
	
	// Make sure the cache is flushed for KeStartProcessor.
	sync_before_exec((PVOID)ProcessorState->ContextFrame.Iar, 0x100);
	
	// Copy the bootcode to the stack.
	ULONG BootCode[sizeof(s_BootCode) / sizeof(s_BootCode[0])];
	_Static_assert(sizeof(BootCode) == sizeof(s_BootCode));
	memcpy(BootCode, s_BootCode, sizeof(s_BootCode));
	// Set the correct values of r1 (stack), r3 (argument1), r4 (argument2), r2 (entrypoint) and r6 (HalpProcessorReset)
	extern ULONG HalpProcessorReset[];
	BootCode[2] |= (((ULONG)HalpProcessorReset >> 16) & 0x7FFF); // unset bit31 for physical address
	BootCode[3] |= (((ULONG)HalpProcessorReset >>  0) & 0xFFFF);
	BootCode[4] |= ((ProcessorState->ContextFrame.Gpr1 >> 16) & 0xFFFF);
	BootCode[5] |= ((ProcessorState->ContextFrame.Gpr1 >>  0) & 0xFFFF);
	BootCode[6] |= ((ProcessorState->ContextFrame.Gpr3 >> 16) & 0xFFFF);
	BootCode[7] |= ((ProcessorState->ContextFrame.Gpr3 >>  0) & 0xFFFF);
	BootCode[8] |= ((ProcessorState->ContextFrame.Gpr4 >> 16) & 0xFFFF);
	BootCode[9] |= ((ProcessorState->ContextFrame.Gpr4 >>  0) & 0xFFFF);
	BootCode[10] |= ((ProcessorState->ContextFrame.Iar >> 16) & 0x7FFF); // unset bit31 for physical address
	BootCode[11] |= ((ProcessorState->ContextFrame.Iar >>  0) & 0xFFFF);
	if (IsCafe) {
		// Map the boot vector, copy there, flush caches, unmap boot vector.
		// We are still in stage 0 so must use a BAT mapping.
		PULONG BootVector = KePhase0MapIo(0x08100100, 0x40);
		WRITE_BOOT_VECTOR(0);
		WRITE_BOOT_VECTOR(1);
		WRITE_BOOT_VECTOR(2);
		WRITE_BOOT_VECTOR(3);
		WRITE_BOOT_VECTOR(4);
		WRITE_BOOT_VECTOR(5);
		WRITE_BOOT_VECTOR(6);
		WRITE_BOOT_VECTOR(7);
		WRITE_BOOT_VECTOR(8);
		WRITE_BOOT_VECTOR(9);
		WRITE_BOOT_VECTOR(10);
		WRITE_BOOT_VECTOR(11);
		WRITE_BOOT_VECTOR(12);
		WRITE_BOOT_VECTOR(13);
		WRITE_BOOT_VECTOR(14);
		WRITE_BOOT_VECTOR(15);
		sync_before_exec(BootVector, 0x40);
		KePhase0DeleteIoMap(0x08100100, 0x40);
	} else {
		// Wiimode
		// Copy to the EXI boot vector.
		EXI_WRITE_BOOT_VECTOR(0);
		EXI_WRITE_BOOT_VECTOR(1);
		EXI_WRITE_BOOT_VECTOR(2);
		EXI_WRITE_BOOT_VECTOR(3);
		EXI_WRITE_BOOT_VECTOR(4);
		EXI_WRITE_BOOT_VECTOR(5);
		EXI_WRITE_BOOT_VECTOR(6);
		EXI_WRITE_BOOT_VECTOR(7);
		EXI_WRITE_BOOT_VECTOR(8);
		EXI_WRITE_BOOT_VECTOR(9);
		EXI_WRITE_BOOT_VECTOR(10);
		EXI_WRITE_BOOT_VECTOR(11);
		EXI_WRITE_BOOT_VECTOR(12);
		EXI_WRITE_BOOT_VECTOR(13);
		EXI_WRITE_BOOT_VECTOR(14);
		EXI_WRITE_BOOT_VECTOR(15);
	}
	
	
	ULONG NextCore = s_LastProcessorStarted + 1;
	
	// Set a dummy restart block, as the kernel expects a pointer to one to be present.
	// Also set the processor number, as the kernel expects that too.
	static RESTART_BLOCK s_DummyRestartBlock[3] = {0};
	PKPRCB Prcb = (PKPRCB)LoaderBlock->Prcb;
	Prcb->Number = NextCore;
	Prcb->RestartBlock = &s_DummyRestartBlock[NextCore];
	
	// Ensure VI_SOLID at zero.
	MmioWriteBase32(HalpPxiRegisters, 0x24, 0);
	
	// Set the legacy blocks to use the low mapping, on non-Cafe where the EXI boot vector is used.
	ULONG AipProt = 0;
	if (!IsCafe) {
		AipProt = MmioReadBase32(HalpPxiRegisters, 0x70) & ~1;
		MmioWriteBase32(HalpPxiRegisters, 0x70, AipProt);
	}
	
	// Wake up the next core.
	ULONG SCR = __mfspr(SPR_SCR);
	SCR |= BIT(SCR_WAKE_BIT + 2 - NextCore);
	__mtspr(SPR_SCR, SCR);
	// Wait a little while for the CPU to get out of the boot vector.
	KeStallExecutionProcessor(1000);
	
	if (!IsCafe) {
		KeStallExecutionProcessor(100000);
		// Set the legacy blocks back to the high mapping.
		MmioWriteBase32(HalpPxiRegisters, 0x70, AipProt | 1);
	}
	
	if (MmioReadBase32(HalpPxiRegisters, 0x24) == 0) {
		char Buffer[128];
		_snprintf(Buffer, sizeof(Buffer), "HAL: Failed to start CPU %d\n", NextCore);
		HalDisplayString(Buffer);
		return FALSE;
	}
	MmioWriteBase32(HalpPxiRegisters, 0x24, 0);
	
	while (*(volatile ULONG*)(&s_DummyRestartBlock[NextCore].BootStatus) == 0 && *(volatile KIRQL*)(ProcessorState->ContextFrame.Gpr4 + __builtin_offsetof(KPCR, CurrentIrql)) != 2) {
		KeStallExecutionProcessor(100000);
	}
	s_LastProcessorStarted = NextCore;
	return TRUE;
}

// Determine if all processors are started.
BOOLEAN HalAllProcessorsStarted(void) {
	if (HalpSystemIsUniprocessor()) return TRUE;
	if (!HalpSystemIsCafe()) return (s_LastProcessorStarted == 1); // only use 2 cores in wiimode
	return (s_LastProcessorStarted == 2); // core2 is last.
}

// Sends an interprocessor interrupt on a set of processors.
void HalRequestIpi(ULONG Mask) {
	// Invert the mask (bit0 -> bit2, bit2 -> bit0)
	ULONG IpiMask = (Mask & BIT(1)) | ((Mask >> 2) & 1) | ((Mask & 1) << 2);
	
	// Set SCR for the mask.
	ULONG SCR = __mfspr(SPR_SCR);
	SCR |= (IpiMask << SCR_IPI_BIT);
	__mtspr(SPR_SCR, SCR);
}

// Sort partial resource descriptors.
static void HalpGetResourceSortValue (
    IN PCM_PARTIAL_RESOURCE_DESCRIPTOR  pRCurLoc,
    OUT PULONG                          sortscale,
    OUT PLARGE_INTEGER                  sortvalue
    )
{
    switch (pRCurLoc->Type) {
        case CmResourceTypeInterrupt:
            *sortscale = 0;
            sortvalue->LowPart = pRCurLoc->u.Interrupt.Level;
            sortvalue->HighPart = 0;
            break;

        case CmResourceTypePort:
            *sortscale = 1;
            *sortvalue = pRCurLoc->u.Port.Start;
            break;

        case CmResourceTypeMemory:
            *sortscale = 2;
            *sortvalue = pRCurLoc->u.Memory.Start;
            break;

        default:
            *sortscale = 4;
            sortvalue->LowPart = 0;
            sortvalue->HighPart = 0;
            break;
    }
}

void HalReportResourceUsage(void) {
	// Allocate and zero the resource lists
	PCM_RESOURCE_LIST RawResourceList = (PCM_RESOURCE_LIST)ExAllocatePool(NonPagedPool, PAGE_SIZE * 2);
	PCM_RESOURCE_LIST TranslatedResourceList = (PCM_RESOURCE_LIST)ExAllocatePool(NonPagedPool, PAGE_SIZE * 2);
	RtlZeroMemory(RawResourceList, PAGE_SIZE * 2);
	RtlZeroMemory(TranslatedResourceList, PAGE_SIZE * 2);
	
	// Initialise the lists.
	RawResourceList->List[0].InterfaceType = (INTERFACE_TYPE)-1;
	PCM_FULL_RESOURCE_DESCRIPTOR RawFullDesc = RawResourceList->List;
	PCM_FULL_RESOURCE_DESCRIPTOR TlFullDesc = NULL;
	PCM_PARTIAL_RESOURCE_DESCRIPTOR RawThis = (PCM_PARTIAL_RESOURCE_DESCRIPTOR)RawFullDesc;
	PCM_PARTIAL_RESOURCE_DESCRIPTOR TlThis = (PCM_PARTIAL_RESOURCE_DESCRIPTOR)TranslatedResourceList->List;
	PCM_PARTIAL_RESOURCE_LIST RawPartList = &RawFullDesc->PartialResourceList;
	PCM_PARTIAL_RESOURCE_LIST TlPartList = NULL;
	
	for (ULONG i = 0; i < DEVICE_VECTORS; i++) {
		if ((HalpIDTUsage[i].Flags & IDTOwned) != 0) continue;
		HalpIDTUsage[i].Flags = InternalUsage;
		HalpIDTUsage[i].BusReleativeVector = (UCHAR)i;
	}
	
	CM_PARTIAL_RESOURCE_DESCRIPTOR RawDescPart;
	CM_PARTIAL_RESOURCE_DESCRIPTOR TlDescPart;
	
	for (UCHAR pass = 0; pass < 2; pass++) {
		UCHAR ReportOn = (pass == 0 ? DeviceUsage & ~IDTOwned : InternalUsage & ~IDTOwned);
		INTERFACE_TYPE Type = Internal;
		
		ULONG CurrentIDT = 0;
		ULONG CurrentElement = 0;
		while (TRUE) {
			if (CurrentIDT <= MAXIMUM_IDTVECTOR) {
				if ((HalpIDTUsage[CurrentIDT].Flags & ReportOn) == 0) {
					// Doesn't need reporting
					CurrentIDT++;
					continue;
				}
				
				// Report CurrentIDT
				RawDescPart.Type = CmResourceTypeInterrupt;
				RawDescPart.ShareDisposition = CmResourceShareDriverExclusive;
				RawDescPart.Flags = (
					HalpIDTUsage[CurrentIDT].Flags & InterruptLatched ?
					CM_RESOURCE_INTERRUPT_LATCHED :
					CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE
				);
				RawDescPart.u.Interrupt.Vector = HalpIDTUsage[CurrentIDT].BusReleativeVector;
				RawDescPart.u.Interrupt.Level = RawDescPart.u.Interrupt.Vector;
				RawDescPart.u.Interrupt.Affinity = 0;
				RtlCopyMemory(&TlDescPart, &RawDescPart, sizeof(TlDescPart));
				TlDescPart.u.Interrupt.Vector = CurrentIDT;
				TlDescPart.u.Interrupt.Level = HalpIDTUsage[CurrentIDT].Irql;
				CurrentIDT++;
			} else {
				// TODO: report MMIO usage?
				break;
			}
			
			// Include it in the list
			if (RawFullDesc->InterfaceType != Type) {
				// Type changed, add another section
				RawResourceList->Count++;
				TranslatedResourceList->Count++;
				RawFullDesc = (PCM_FULL_RESOURCE_DESCRIPTOR)RawThis;
				TlFullDesc = (PCM_FULL_RESOURCE_DESCRIPTOR)TlThis;
				RawFullDesc->InterfaceType = Type;
				TlFullDesc->InterfaceType = Type;
				RawPartList = &RawFullDesc->PartialResourceList;
				TlPartList = &TlFullDesc->PartialResourceList;
				
				// and set the iterators
				RawThis = RawFullDesc->PartialResourceList.PartialDescriptors;
				TlThis = TlFullDesc->PartialResourceList.PartialDescriptors;
			}
			
			// Add the new descriptors to the end of the lists.
			RawPartList->Count++;
			TlPartList->Count++;
			RtlCopyMemory(RawThis, &RawDescPart, sizeof(RawDescPart));
			RtlCopyMemory(TlThis, &TlDescPart, sizeof(TlDescPart));
			RawThis++;
			TlThis++;
		}
	}
	
	ULONG ListSize = ( (ULONG)RawThis - (ULONG)RawResourceList );
	
	// Sort the lists basd on the raw resource values
	RawFullDesc = RawResourceList->List;
	TlFullDesc = TranslatedResourceList->List;
	
	for (ULONG i = 0; i < RawResourceList->Count; i++) {
		RawThis = RawFullDesc->PartialResourceList.PartialDescriptors;
		TlThis = TlFullDesc->PartialResourceList.PartialDescriptors;
		ULONG Count = RawFullDesc->PartialResourceList.Count;
		for (ULONG Part = 0; Part < Count; Part++, RawThis++, TlThis++) {
			ULONG CurScale, SortScale;
			LARGE_INTEGER CurValue, SortValue;
			HalpGetResourceSortValue(RawThis, &CurScale, &CurValue);
			PCM_PARTIAL_RESOURCE_DESCRIPTOR RawSort = RawThis;
			PCM_PARTIAL_RESOURCE_DESCRIPTOR TlSort = TlThis;
			
			for (ULONG Sort = Part + 1; Sort < Count; Sort++, RawSort++, TlSort++) {
				HalpGetResourceSortValue(RawSort, &SortScale, &SortValue);
				if (
					(SortScale < CurScale) ||
					(SortScale == CurScale && RtlLargeIntegerLessThan(SortValue, CurValue))
				) {
					// swap Raw
					RtlCopyMemory(&RawDescPart, RawThis, sizeof(RawDescPart));
					RtlCopyMemory(RawThis, RawSort, sizeof(RawDescPart));
					RtlCopyMemory(RawSort, &RawDescPart, sizeof(RawDescPart));
					// and swap Translated
					RtlCopyMemory(&TlDescPart, TlThis, sizeof(TlDescPart));
					RtlCopyMemory(TlThis, TlSort, sizeof(TlDescPart));
					RtlCopyMemory(TlSort, &TlDescPart, sizeof(TlDescPart));
					// we swapped raw with translated, as such:
					HalpGetResourceSortValue(TlThis, &CurScale, &CurValue);
				}
			}
		}
	}
	
	// Tell the kernel about the HAL's resource usage.
	IoReportHalResourceUsage((PUNICODE_STRING)&s_UsHalName, RawResourceList, TranslatedResourceList, ListSize);
	
	// Free the buffers.
	ExFreePool(RawResourceList);
	ExFreePool(TranslatedResourceList);
}
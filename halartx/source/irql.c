// Raise and lower interrupt request level

#include "halp.h"
#include "ints.h"

extern ULONG HalpIrqlToMask[];

extern __declspec(dllimport) void KiDispatchSoftwareInterrupt(void);

// Lower current IRQL to specified value
VOID KeLowerIrql(IN KIRQL NewIrql)
{
	// If new irql is equal to current, don't bother with actually changing it.
	if (NewIrql != PCR->CurrentIrql) {
		if (NewIrql > PCR->CurrentIrql) {
			KeBugCheckEx(IRQL_NOT_LESS_OR_EQUAL, NewIrql, PCR->CurrentIrql, 0, __builtin_extract_return_addr (__builtin_return_address (0)));
		}
		// Disable interrupts.
		_disable();
		
		// Switch IRQL
		KIRQL OldIrql = PCR->CurrentIrql;
		PCR->CurrentIrql = NewIrql;
		
		// Mask off the required interrupts for this IRQL.
		if (HalpPiInterruptRegs != NULL) {
			if (HalpSystemIsCafe()) MmioWriteBase32(MMIO_PILT_OFFSET(Mask), (HalpIrqlToMask[NewIrql] & HalpRegisteredInterrupts));
			else if (HALPCR->PhysicalProcessor == 0) MmioWriteBase32(MMIO_OFFSET(HalpPiInterruptRegs, Mask), (HalpIrqlToMask[NewIrql] & HalpRegisteredInterrupts));
		}
		
		// If at or above CLOCK2_LEVEL then don't enable interrupts.
		// (At or above CLOCK2_LEVEL => decremementer interrupt can't fire)
		if (NewIrql >= CLOCK2_LEVEL) return;
		
		// Enable interrupts.
		_enable();
	}
		
	// check for DPCs
	if ((NewIrql < DISPATCH_LEVEL) && PCR->SoftwareInterrupt)
		KiDispatchSoftwareInterrupt();
}

// Raise current IRQL to specified value
VOID KeRaiseIrql(IN KIRQL NewIrql, OUT PKIRQL OldIrql)
{
	// If new IRQL equal to current, nothing needs to be done.
	if (NewIrql == PCR->CurrentIrql) {
		*OldIrql = PCR->CurrentIrql;
		return;
	}
	
	if (NewIrql < PCR->CurrentIrql) {
		KeBugCheckEx(IRQL_NOT_GREATER_OR_EQUAL, NewIrql, PCR->CurrentIrql, 0, __builtin_extract_return_addr (__builtin_return_address (0)));
	}
	// Disable interrupts.
	_disable();
	
	// Switch to the new IRQL.
	*OldIrql = PCR->CurrentIrql;
	PCR->CurrentIrql = NewIrql;
	
	// Mask off the required interrupts for this IRQL.
	if (HalpPiInterruptRegs != NULL) {
		if (HalpSystemIsCafe()) MmioWriteBase32(MMIO_PILT_OFFSET(Mask), (HalpIrqlToMask[NewIrql] & HalpRegisteredInterrupts));
		else if (HALPCR->PhysicalProcessor == 0) MmioWriteBase32(MMIO_OFFSET(HalpPiInterruptRegs, Mask), (HalpIrqlToMask[NewIrql] & HalpRegisteredInterrupts));
	}
	
	// If at or above CLOCK2_LEVEL then don't reenable interrupts.
	if (NewIrql >= CLOCK2_LEVEL) return;
	
	// Enable interrupts.
	_enable();
}
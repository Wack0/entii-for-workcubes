// Implements OS timer using decrementer.

#include "halp.h"
#include "ints.h"

ULONG HalpPerformanceFrequency;
extern ULONG HalpRegisteredInterrupts;
extern ULONG HalpIrqlToMask[];
extern PPI_INTERRUPT_REGS HalpPiInterruptRegs;
extern BOOLEAN KdPollBreakIn (VOID);

ULONG HalpClockCount;
ULONG HalpFullTickClockCount;
ULONG HalpCurrentTimeIncrement;
ULONG HalpNextIntervalCount;
ULONG HalpNewTimeIncrement;

#define __SPR_TBL       268
#define __SPR_TBU       269

#define __mfdec() \
	({ ULONG result; \
	__asm__ volatile ("mfdec %0" : "=r" (result)); \
	/*return*/ result; })

#define __mtdec(val) \
	({ ULONG result = (val); \
	__asm__ volatile ("mtdec %0" : : "r" (result)); })

ULONG HalpUpdateDecrementer(ULONG value) {
	// read the decrementer to get the interrupt latency
	ULONG dec = __mfdec();
	// Add the count.
	ULONG newDec = dec + value;
	// if wrapped around, just use the count
	if (newDec < value || dec > value) newDec = value;
	// set the decrementer
	__mtdec(newDec);
	// Return old value.
	return ~dec;
}

BOOLEAN HalpHandleDecrementerInterrupt(IN PKINTERRUPT Interrupt, PVOID ServiceContext, PVOID TrapFrame) {
	// raise IRQL manually
	KIRQL OldIrql = PCR->CurrentIrql;
	PCR->CurrentIrql = CLOCK2_LEVEL;
	MmioWriteBase32(MMIO_OFFSET(HalpPiInterruptRegs, Mask), HalpIrqlToMask[CLOCK2_LEVEL] & HalpRegisteredInterrupts);
	
	// Reset the decrememnter.
	HalpUpdateDecrementer(HalpClockCount);
	
	// Update the kernel system time
	KeUpdateSystemTime(TrapFrame, HalpCurrentTimeIncrement);
	HalpCurrentTimeIncrement = HalpNewTimeIncrement;
	
	static BOOLEAN Recurse = FALSE;
	if (!Recurse) {
		// ensure KdPollBreakIn doesn't take longer than a decrementer interrupt
		Recurse = TRUE;
		if (KdDebuggerEnabled && KdPollBreakIn()) {
			_enable();
			DbgBreakPoint(); // DbgBreakPointWithStatus was added in NT4
			//DbgBreakPointWithStatus(DBG_STATUS_CONTROL_C);
			_disable();
		}
		Recurse = FALSE;
	}
	
	// Re-enable interrupts.
	PCR->CurrentIrql = OldIrql;
	MmioWriteBase32(MMIO_OFFSET(HalpPiInterruptRegs, Mask), HalpIrqlToMask[OldIrql] & HalpRegisteredInterrupts);
	return TRUE;
}

// MPNOTE: not static for MP
// not used for non-MP, we implement here anyway because it's simple enough
// Decrement interrupt handler for other CPUs
static BOOLEAN HalpHandleDecrementerInterrupt1(IN PKINTERRUPT Interrupt, PVOID ServiceContext, PVOID TrapFrame) {
	// raise IRQL manually
	KIRQL OldIrql = PCR->CurrentIrql;
	PCR->CurrentIrql = CLOCK2_LEVEL;
	// no PI interrupts taken for this CPU
	//MmioWrite32(&HalpPiInterruptRegs->Mask, HalpIrqlToMask[CLOCK2_LEVEL] & HalpRegisteredInterrupts);
	
	// Reset the decrememnter.
	HalpUpdateDecrementer(HalpFullTickClockCount);
	
	// Update the run time for this CPU
	KeUpdateRunTime(TrapFrame);
	
	// Re-enable interrupts.
	PCR->CurrentIrql = OldIrql;
	// no PI interrupts taken for this CPU
	//MmioWrite32(&HalpPiInterruptRegs->Mask, HalpIrqlToMask[OldIrql] & HalpRegisteredInterrupts);
	return TRUE;
}

// Set the clock interrupt rate.
ULONG HalSetTimeIncrement(ULONG DesiredIncrement) {
	// Raise IRQL
	KIRQL OldIrql;
	KeRaiseIrql(HIGH_LEVEL, &OldIrql);
	
	// HalpPerformanceFrequency is the number of times the decrementer ticks in 1 second.
	// MINIMUM_INCREMENT is 1 millisecond in 100ns units.
	// Thus, DesiredIncrement/MINIMUM_INCREMENT is number of milliseconds.
	// Multiply that by (decrementer ticks in 1 second)/1000 for the ticks per milliseconds.
	ULONG NextIntervalCount =
		(HalpPerformanceFrequency * (DesiredIncrement/MINIMUM_INCREMENT)) / 1000;
	
	// Calculate the number of 100ns units to report to the kernel on each decrementer int.
	ULONG NewTimeIncrement = (DesiredIncrement/MINIMUM_INCREMENT) * MINIMUM_INCREMENT;
	
	HalpClockCount = NextIntervalCount;
	HalpNewTimeIncrement = NewTimeIncrement;
	
	ULONG CurrentDecrementer = __mfdec();
	if ((CurrentDecrementer & 0x80000000) != 0) {
		__mtdec(NextIntervalCount);
	}
	
	// Lower IRQL
	KeLowerIrql(OldIrql);
	return NewTimeIncrement;
}

// Calibrate stall/decrementer
BOOLEAN HalpCalibrateStall(void) {
	PCR->StallScaleFactor = 1;
	
	// This runs on all CPUs, so only do the global init if CPU0.
	if (HALPCR->PhysicalProcessor != 0) return TRUE;
	
	HalpPerformanceFrequency = RUNTIME_BLOCK[RUNTIME_DECREMENTER_FREQUENCY];
	HalpClockCount = (HalpPerformanceFrequency * (MAXIMUM_INCREMENT/10000)) / 1000;
	HalpFullTickClockCount = HalpClockCount;
	
	return TRUE;
}
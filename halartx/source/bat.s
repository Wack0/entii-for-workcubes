// Function to set an unused BAT.

#include "kxppc.h"

// NT only allocates IBAT/DBAT for the actual MEM1 size rounded up.
// So for all of dol/rvl/cafe it would allocate 32MB cached BAT.

// However, the entire 0x8xxxxxxx address space is reserved.
// The rest of this 256MB range is unused.

// Therefore, we can use a BAT to map PA 0x0c000000-0x0e000000 (32MB MMIO) uncached,
// at 0x8C000000.

// We also need to map the EFB by BAT.

// Therefore, we can also map PA 0x08000000-0x08400000 (4MB MMIO) uncached,
// at 0x88000000.

// This function is used to set DBAT1 and DBAT2 to allow for this.

LEAF_ENTRY(HalpSetMmioDbat)
	LWI(r.7, 0x8800007E) // base at 0x88000000, size = 4MB, kernel mode only
	LWI(r.6, 0x0800002A) // phys at 0x08000000, uncached, guarded, readwrite
	LWI(r.5, 0x8C0003FE) // base at 0x8C000000, size = 32MB, kernel mode only
	LWI(r.4, 0x0C00002A) // phys at 0x0C000000, uncached, guarded, readwrite
	// set invalid first just in case
	li r.3, 0
	mtdbatu 1, r.3
	mtdbatu 2, r.3
	isync
	// set lower part first
	mtdbatl 1, r.4
	mtdbatl 2, r.6
	mtdbatu 1, r.5
	mtdbatu 2, r.7
	// barrier
	isync
LEAF_EXIT(HalpSetMmioDbat)
// Implement cache flushing on Arthur derivatives
// (Gekko, Broadway, Espresso)

#include <kxppc.h>


// Override the workaround for a different processor's errata
#undef DISABLE_INTERRUPTS
#undef ENABLE_INTERRUPTS

#define DISABLE_INTERRUPTS(p0, s0) \
        mfmsr   p0 ; \
        rlwinm  s0,p0,0,~MASK_SPR(MSR_EE,1) ; \
        mtmsr   s0 ;

#define ENABLE_INTERRUPTS(p0) \
        mtmsr     p0

        .set	HID0_ICFI, 0x0800
        .set	HID0, 1008
	.set	BLOCK_SIZE, 32
	.set	BLOCK_LOG2, 5
	.set	DCACHE_LINES, (32 * 1024) >> 5 // Data cache size in lines
        .set	BASE, 0x80000000 // valid cached virtual address

// HalSweepDcache(): flush the entire dcache
        LEAF_ENTRY(HalSweepDcache)

	li r.4, DCACHE_LINES
// Get a valid virtual address
	LWI	(r.3, BASE)

// Read memory on block sizes to make sure it all ends up in the cache
	mtctr	r.4
        DISABLE_INTERRUPTS(r.10,r.12)
        sync
        subi	r.6, r.3, BLOCK_SIZE
FillLoop:
	lbzu	r.0, BLOCK_SIZE(r.6)
	bdnz	FillLoop
        ENABLE_INTERRUPTS(r.10)

// And flush it out of dcache
	mtctr	r.4
FlushRange:
	dcbf    r.0, r.3
        addi    r.3, r.3, 0x20
	bdnz	FlushRange
	subi r.3, r.3, 0x20
	dcbf r.0, r.3
	sync
	eieio

        LEAF_EXIT(HalSweepDcache)

// HalSweepDcacheRange(PVOID address, ULONG length): flush dcache for address range
	LEAF_ENTRY(HalSweepDcacheRange)

	andi.	r.5, r.3, BLOCK_SIZE-1
	or.	r.4, r.4, r.4
	addi	r.4, r.4, BLOCK_SIZE-1
	add	r.4, r.4, r.5
	srwi	r.4, r.4, BLOCK_LOG2
// if length is zero, do nothing
	beqlr-
	mtctr r.4
	sync
	b FlushRange
	
	LEAF_EXIT(HalSweepDcacheRange)

// Invalidate dcache for given range.
// Same args as for HalSweepDcacheRange.
	LEAF_ENTRY(HalpInvalidateDcacheRange)
	
	andi.	r.5, r.3, BLOCK_SIZE-1
	or.	r.4, r.4, r.4
	addi	r.4, r.4, BLOCK_SIZE-1
	add	r.4, r.4, r.5
	srwi	r.4, r.4, BLOCK_LOG2
// if length is zero, do nothing
	beqlr-
	mtctr r.4
	sync
InvalidateRange:
	dcbi    r.0, r.3
        addi    r.3, r.3, 0x20
	bdnz	InvalidateRange
	LEAF_EXIT(HalpInvalidateDcacheRange)

// HalSweepIcache: invalidate all of icache
        LEAF_ENTRY(HalSweepIcache)

FlashInvalidateIcache:
        mfspr	r.3, HID0
        ori	r.4, r.3, HID0_ICFI
        isync
        mtspr	HID0, r.4

        LEAF_EXIT(HalSweepIcache)

// HalSweepIcacheRange(PVOID address, ULONG length):
// invalidate icache for given range
        LEAF_ENTRY(HalSweepIcacheRange)

	andi.	r.5, r.3, BLOCK_SIZE-1
	or.	r.4, r.4, r.4
	addi	r.4, r.4, BLOCK_SIZE-1
	add	r.4, r.4, r.5
	srwi	r.4, r.4, BLOCK_LOG2
// if length is zero, do nothing
	beqlr-
	mtctr	r.4
	DISABLE_INTERRUPTS(r.10,r.12)

InvalidateIcache:
	icbi    0, r.3
	sync
        addi    r.3, r.3, BLOCK_SIZE
	bdnz	InvalidateIcache
	sync
	isync
	ENABLE_INTERRUPTS(r.10)

        LEAF_EXIT(HalSweepIcacheRange)

// Flush physaddr+length to caches.
// r3 = start physical page
// r4 = start offset within page
// r5 = bytelength
// r6 = TRUE if should also flush dcache
	.set PAGE_SHIFT, 12
	LEAF_ENTRY(HalpSweepPhysicalRange)
	
	
	// Convert from page number and offset to physical address.
	rlwimi r.4, r.3, PAGE_SHIFT, 0xfffff000
	// Align to cache block.
	addi r.5, r.5, 31
	srwi r.5, r.5, 5
	// Save return address and set loop count.
	mflr r.0
	mtctr r.5
	// Disable interrupts, we need srr0 and srr1
	DISABLE_INTERRUPTS(r.12, r.11)
	// Turn off virtual memory.
	bl hspr
hspr:
	// Get physical address of hspr into a register.
	mflr r.7
	rlwinm r.7, r.7, 0, 0x7fffffff
	// Add the offset to return address (in physical memory)
	addi r.7, r.7, hspr.phys - hspr
	// Ensure everything above here is complete.
	sync
	// Far jump to physical address.
	mtsrr0 r.7
	rlwinm r.11, r.11, 0, ~0x30 // turn off MSR[IR] and MSR[DR]
	mtsrr1 r.11
	rfi

hspr.phys:
	mtsrr0 r.0 // set return address
	mtsrr1 r.12 // set old MSR
	// Do the comparison early, the cr won't change.
	cmpli 0, 0, r.6, 0

hspr.loop:
	// If caller didn't want dcache flush, branch past it.
	beq hspr.afterdcache
	dcbst 0, r.4 // flush dcache
hspr.afterdcache:
	icbi 0, r.4 // invalidate icache
	addi r.4, r.4, 32 // next block
	bdnz hspr.loop // continue loop
	
	// memory + speculation barrier
	sync
	isync
	
	// return back to caller with translation on
	rfi
	
	
	DUMMY_EXIT(HalpSweepPhysicalRange)
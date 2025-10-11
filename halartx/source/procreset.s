// Initialise other processor coming out of reset.

#include <kxppc.h>

.text
.align 2
.globl HalpProcessorReset
HalpProcessorReset:
	// Write to HW_VISOLID (a value without bit 0 set so it doesn't enable it)
	// to tell CPU 0 that this processor is running.
	lis r.6, 0x0d80
	stw r.6, 0x20(r.6) // 0x24 swizzle for 32-bit == 0x24 ^ 4 == 0x20
	sync
	
	// Set HID0
	lis r.6, 0x0011
	ori r.6, r.6, 0x0024
	mtspr 1008, r.6
	// set HID4
	lis r.6, 0xb1b0
	mtspr 1011, r.6
	sync
	// set HID5
	lis r.6, 0xE7FD
	ori r.6, r.6, 0xC000
	mtspr 944, r.6
	sync
	// enable caches
	lis r.6, 0x0011
	ori r.6, r.6, 0xC024
	mtspr 1008, r.6
	
	isync
	
	
	// Initialise unused registers. r1 to r6 all got set by the code at the boot vector.
	li r.0, 0
	li r.7, 0
	li r.8, 0
	li r.9, 0
	li r.10, 0
	li r.11, 0
	li r.12, 0
	li r.13, 0
	li r.14, 0
	li r.16, 0
	li r.17, 0
	li r.18, 0
	li r.19, 0
	li r.20, 0
	li r.21, 0
	li r.22, 0
	li r.23, 0
	li r.24, 0
	li r.25, 0
	li r.26, 0
	li r.27, 0
	li r.28, 0
	li r.29, 0
	li r.30, 0
	li r.31, 0
	
	// set MSR_ILE
	mfmsr r.6
	oris r.6, r.6, 1
	mtmsr r.6
	isync
	
	// Long jump to kernel init.
	mtsrr0 r.2
	mtsrr1 r.5
	rfi
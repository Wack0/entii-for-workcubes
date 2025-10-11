enum {
	HW_PPCIPCVAL = 0x00,
	HW_PPCIPCCTRL = 0x04,
	HW_IOPIPCCTRL = 0x0c,
	HW_TIMER = 0x10,
	HW_VISOLID = 0x24,
	HW_PPCIRQFLAG = 0x30,
	HW_PPCIRQMASK = 0x34,
	HW_IOPIRQFLAG = 0x38,
	HW_GPIO_OWNER = 0xFC,
	HW_RESETS = 0x194,
};

static inline unsigned int interrupt_status() {
	unsigned int var;
	asm volatile ("mrs %0, cpsr":"=r" (var));
	unsigned int ret = var & 0xc0;
	asm volatile("");
	return ret;
}

static inline unsigned int disable_interrupts() {
	unsigned int var;
	asm volatile ("mrs %0, cpsr":"=r" (var));
	unsigned int ret = var & 0xc0;
	var |= 0xc0;
	asm volatile ("msr cpsr_c, %0": : "r" (var));
	return ret;
}

static inline void enable_interrupts(unsigned int cookie) {
	unsigned int var;
	asm volatile ("mrs %0, cpsr":"=r" (var));
	var &= ~0xc0;
	var |= cookie;
	asm volatile ("msr cpsr_c, %0": : "r" (var));
}

static inline unsigned int read32(unsigned int offset) {
	register unsigned int MMIO_BASE = 0x0d800000;
	return *(volatile unsigned int*)(MMIO_BASE + offset);
}

static inline void write32(unsigned int offset, unsigned int value) {
	register unsigned int MMIO_BASE = 0x0d800000;
	*(volatile unsigned int*)(MMIO_BASE + offset) = value;
}

static inline unsigned int read_zero(void) {
	unsigned int value;
	asm volatile ("ldr %0, [%1]" : "=r"(value) : "r"(0));
	return value;
}

static inline void write_zero(unsigned int value) {
	asm volatile ("str %0, [%1]" : : "r"(value), "r"(0));
}

typedef void (*tfpiosNoArg)(void);
typedef void (*tfpiosSingleArg)(unsigned int arg);
typedef void (*tfpMemcpy)(void* dest, void* src, unsigned int length);

void _start(void) {
	// get current interrupt enabled state
	unsigned int interrupts = interrupt_status();
	
	
	tfpMemcpy memcpy = (tfpMemcpy)0xFFFF737C;
	tfpiosSingleArg udelay = (tfpiosSingleArg)0xffff70a1;
	while (1) {
		tfpiosNoArg iosStopPpc = (tfpiosNoArg)0xffff689d; //0xffff0e4d;
		iosStopPpc();
		
		// let PPC access the debug GPIOs
		write32(HW_GPIO_OWNER, read32(HW_GPIO_OWNER) | 0xFF0000);
		
		// copy ancast into place
		memcpy((void*)0x01330000, (void*)0x01230000, 0x3f100);
		// wipe bootrom state, we only care about the final flags
		*(volatile unsigned int*)0x016ffffc = 0;
		// set napa sync value
		write_zero(0xffffffff);
		// disable interrupts whilst flushing dcache
		disable_interrupts();
		// flush entire dcache
		__asm__ __volatile__("1: mrc p15, 0, r15, c7, c10, 3;	bne 1b" ::: "cc");
		// drain write buffer
		__asm__ __volatile__("mcr p15, 0, %0, c7, c10, 4" : : "r"((unsigned int)0));
		tfpiosSingleArg iosAhbMemInvalidate = (tfpiosSingleArg)0xffff6881;
		tfpiosSingleArg iosAhbMemFlush = (tfpiosSingleArg)0xffff67c5;
		iosAhbMemFlush(1);
		enable_interrupts(interrupts);
		
		// enable vegas IPC interrupt for PPC
		write32(HW_PPCIRQMASK, 0x40000000);
		
		// pull both hreset and sreset
		unsigned int reset = read32(HW_RESETS) & ~0x30;
		write32(HW_RESETS, reset);
		udelay(100);
		// release sreset
		reset |= 0x20;
		write32(HW_RESETS, reset);
		udelay(100);
		
		// set up for the bootrom race
		register volatile unsigned int* firstInsnPtr = (volatile unsigned int*)0x01330100;
		register unsigned int firstInsn = 0x7c9f42a6; //*firstInsnPtr;
		register unsigned int jumpInsn = 0x4bfeff00;
		register volatile unsigned int* bootromStatePtr = (volatile unsigned int*)0x016ffffc;
		register unsigned int bootromStateCacheLine = 0x016fffe0;
		// barrier before the time sensitive part
		asm volatile("");
		// disable interrupts
		disable_interrupts();
		
		// release hreset, let the bootrom start
		reset |= 0x10;
		write32(HW_RESETS, reset);
		
		while (1) {
			if (*firstInsnPtr == firstInsn) break;
			if ((*bootromStatePtr >> 24) != 0) break;
			// invalidate dcache
			__asm__ __volatile__("mcr p15, 0, %0, c7, c6, 1" : : "r"((unsigned int)firstInsnPtr));
			__asm__ __volatile__("mcr p15, 0, %0, c7, c6, 1" : : "r"(bootromStateCacheLine));
			iosAhbMemInvalidate(0);
		}
		
		// if bootrom failed, try again
		if ((*bootromStatePtr >> 24) != 0) {
			enable_interrupts(interrupts);
			continue;
		}
		
		// replace the first instruction
		*firstInsnPtr = jumpInsn;
		// flush dcache line
		__asm__ __volatile__("mcr p15, 0, %0, c7, c10, 1" : : "r"((unsigned int)firstInsnPtr));
		// drain write buffer
		__asm__ __volatile__("mcr p15, 0, %0, c7, c10, 4" : : "r"((unsigned int)0));
		iosAhbMemFlush(1);
		
		enable_interrupts(interrupts);
		
		// make sure it actually wrote out
		__asm__ __volatile__("mcr p15, 0, %0, c7, c6, 1" : : "r"((unsigned int)firstInsnPtr));
		iosAhbMemInvalidate(0);
		if (*firstInsnPtr != jumpInsn) {
			continue;
		}
		
		// race succeeded
		// wait for bootrom to finish
		while (1) {
			if ((*bootromStatePtr >> 24) != 0) break;
			// invalidate dcache
			__asm__ __volatile__("mcr p15, 0, %0, c7, c6, 1" : : "r"(bootromStateCacheLine));
			iosAhbMemInvalidate(0);
		}
		// wait up to 100ms for PPC to set low Napa back to zero
		for (int i = 0; i < 100000; i++) {
			if (read_zero() == 0) break;
			udelay(1);
		}
		//enable_interrupts(interrupts);
		// if value at low Napa not zero, then PPC didn't run our code...
		if (read_zero() != 0) {
			continue;
		}
		break;
	}
}
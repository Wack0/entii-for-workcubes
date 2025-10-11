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

static inline BOOLEAN HalpSystemIsCafe(void) {
	// Instead of using memory lookups,
	// check for CPU = espresso and BCR mask 0x08000000
	// This bit hangs the core when in wiimode.
	if (!HalpCpuIsEspresso()) return FALSE;
	return (__mfspr(SPR_BCR) & 0x08000000) != 0;
}
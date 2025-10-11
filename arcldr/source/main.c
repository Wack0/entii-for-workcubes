#include <stdio.h>
#include <stdlib.h>
#include <gccore.h>
//#include <wiiuse/wpad.h>
#include <memory.h>
#include <string.h>

#ifdef HW_RVL
#include <sdcard/wiisd_io.h>
#endif
#include <sdcard/gcsd.h>
#include <sdcard/card_cmn.h>
#include <sdcard/card_io.h>
#include <fat.h>

#include <time.h>
#include <unistd.h>
#include <ogc/lwp_watchdog.h>

#include <ogc/texconv.h>

#include "arc.h"
#include "hwdesc.h"
#include "types.h"
#include "elf_abi.h"

extern DISC_INTERFACE __io_ataa, __io_atab, __io_atac;

enum {
	PHYSADDR_LOAD = 0x400000
};

// only let the heap implementation use the first 4MB of MEM1
void* __myArena1Hi = MEM_PHYSICAL_TO_K0(PHYSADDR_LOAD);
#ifdef HW_RVL
// ...and do not touch MEM2
u32 MALLOC_MEM2 = 0;
#endif

static GXRModeObj *rmode = NULL;

// other GX stuff

#define HASPECT 			320
#define VASPECT 			240

static GXTexObj texobj;
static Mtx view;

/* New texture based scaler */
typedef struct tagcamera
{
	guVector pos;
	guVector up;
	guVector view;
}
camera;

/*** Square Matrix
     This structure controls the size of the image on the screen.
	 Think of the output as a -80 x 80 by -60 x 60 graph.
***/
static s16 square[] ARC_ALIGNED(32) =
{
  /*
   * X,   Y,  Z
   * Values set are for roughly 4:3 aspect
   */
	-HASPECT,  VASPECT, 0,	// 0
	 HASPECT,  VASPECT, 0,	// 1
	 HASPECT, -VASPECT, 0,	// 2
	-HASPECT, -VASPECT, 0	// 3
};


static camera cam = {
	{0.0F, 0.0F, 0.0F},
	{0.0F, 0.5F, 0.0F},
	{0.0F, 0.0F, -0.5F}
};

static unsigned char texturemem[640*480*4] __attribute__((aligned(32))); // GX texture

static bool fs_init_and_mount(const char* mount, const DISC_INTERFACE* di) {
	//if (!di->startup()) return false;
	bool isSd = (di == &__io_gcsda || di == &__io_gcsdb || di == &__io_gcsd2);
	#if HW_RVL
	if (!isSd) isSd = (di == &__io_wiisd);
	#endif
	printf("Trying %s: %s...", mount, isSd ? "sd" : "ide");
	bool ret = fatMount(mount, di, 0, 2, 128);
	printf("%s", ret ? "done" : "error");
	if (isSd) {
		s32 drv_no = 0;
		if (di == &__io_gcsdb) drv_no = 1;
		if (di == &__io_gcsd2) drv_no = 2;
		printf(" (%d)", sdgecko_initIO(drv_no));
	}
	printf("\n");
	return ret;
}

static inline USHORT read16(ULONG addr)
{
	USHORT x;
	__asm__ __volatile__(
		"lhz %0,0(%1) ; sync" : "=r"(x) : "b"(addr));
	return x;
}

#ifdef HW_RVL
// patch IOS to always have all access rights set
// original code from homebrew channel

enum {
	MEM2_PROT = 0xCD8B420A,
	ES_MODULE_START_ADDR = 0x939F0000
};
#define ES_MODULE_START (u16*)ES_MODULE_START_ADDR

static const u16 ticket_check[] = {
    0x685B,               // ldr r3,[r3,#4] ; get TMD pointer
    0x22EC, 0x0052,       // movls r2, 0x1D8
    0x189B,               // adds r3, r3, r2; add offset of access rights field in TMD
    0x681B,               // ldr r3, [r3]   ; load access rights (haxxme!)
    0x4698,               // mov r8, r3  ; store it for the DVD video bitcheck later
    0x07DB                // lsls r3, r3, #31; check AHBPROT bit
};

static inline ULONG read32(ULONG addr)
{
	ULONG x;
	__asm__ __volatile__(
		"lwz %0,0(%1) ; sync" : "=r"(x) : "b"(addr));
	return x;
}

static inline void write16(ULONG addr, USHORT x)
{
	__asm__ __volatile__(
		"sth %0,0(%1) ; eieio" : : "r"(x), "b"(addr));
}

static inline void write32(ULONG addr, ULONG x)
{
	__asm__ __volatile__(
		"stw %0,0(%1) ; eieio" : : "r"(x), "b"(addr));
}

static int patch_ahbprot_reset(void)
{
	u16 *patchme;

	if ((read32(0xCD800064) == 0xFFFFFFFF) ? 1 : 0) {
		write16(MEM2_PROT, 2);
		for (patchme=ES_MODULE_START; patchme < ES_MODULE_START+0x4000; ++patchme) {
			if (!memcmp(patchme, ticket_check, sizeof(ticket_check)))
			{
				// write16/uncached poke doesn't work for MEM2
				patchme[4] = 0x23FF; // li r3, 0xFF
				DCFlushRange(patchme+4, 2);
				return 0;
			}
		}
		return -1;
	} else {
		return -2;
	}
}
#endif

static void __attribute__((noreturn)) RestartSystem(void) {
	printf("Rebooting in 5 seconds.");
	for (int i = 0; i < 5; i++) {
		uint64_t ticks = gettime();
		uint64_t secs = ticks_to_secs(ticks);
		unsigned long currSecs = secs;
		while (currSecs == secs) {
			ticks = gettime();
			secs = ticks_to_secs(ticks);
		}
		printf(".");
	}
	extern void __reload(void);
	__reload();
	while (1); // should not get here...
}

static int ElfValid(void* addr) {
	Elf32_Ehdr* ehdr; /* Elf header structure pointer */

	ehdr = (Elf32_Ehdr*)addr;

	if (!IS_ELF(*ehdr))
		return 0;

	if (ehdr->e_ident[EI_CLASS] != ELFCLASS32)
		return -1;

	if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
		return -1;

	if (ehdr->e_ident[EI_VERSION] != EV_CURRENT)
		return -1;

	if (ehdr->e_type != ET_EXEC)
		return -1;

	if (ehdr->e_machine != EM_PPC)
		return -1;

	return 1;
}

static void sync_after_write(const void* pv, ULONG len)
{
	ULONG a, b;

	const void* p = (const void*)((ULONG)pv & ~0x80000000);

	a = (ULONG)p & ~0x1f;
	b = ((ULONG)p + len + 0x1f) & ~0x1f;

	for (; a < b; a += 32)
		asm("dcbst 0,%0" : : "b"(a));

	asm("sync ; isync");
}

static void sync_before_exec(const void* pv, ULONG len)
{
	ULONG a, b;

	const void* p = (const void*)((ULONG)pv & ~0x80000000);

	a = (ULONG)p & ~0x1f;
	b = ((ULONG)p + len + 0x1f) & ~0x1f;

	for (; a < b; a += 32)
		asm("dcbst 0,%0 ; sync ; icbi 0,%0" : : "b"(a));

	asm("sync ; isync");
}

static void MsrLeSwap64Single(ULONG* dest32, ULONG* src32) {
	ULONG temp = src32[1];
	dest32[1] = __builtin_bswap32(src32[0]);
	dest32[0] = __builtin_bswap32(temp);
}

static void MsrLeSwap64(void* dest, const void* src, ULONG len, ULONG memlen) {
	uint64_t* dest64 = (uint64_t*)dest;
	uint64_t* src64 = (uint64_t*)src;
	
	// align swap-len to 64 bits.
	if ((len & 7) != 0) len += 8 - (len & 7);
	for (; len != 0; dest64++, src64++, len -= sizeof(*dest64), memlen -= sizeof(*dest64)) {
		ULONG* dest32 = (ULONG*)dest64;
		if (len < sizeof(*dest64)) {
			uint64_t val64 = *src64 & ((1 << (len * 8)) - 1);
			ULONG* val32 = (ULONG*)&val64;
			MsrLeSwap64Single(dest32, val32);
			continue;
		}
		ULONG* src32 = (ULONG*)src64;
		MsrLeSwap64Single(dest32, src32);
	}
	
	if ((memlen & 7) != 0) memlen += 8 - (memlen & 7);
	for (; memlen > 0; dest64++, memlen -= sizeof(*dest64)) {
		*dest64 = 0;
	}
}

static void MsrLeMunge32(void* ptr, ULONG len) {
	ULONG* ptr32 = (ULONG*)ptr;
	
	for (; len > 0; len -= sizeof(uint64_t), ptr32 += 2) {
		ULONG temp = ptr32[0];
		ptr32[0] = ptr32[1];
		ptr32[1] = temp;
	}
}

static void MsrLeSwap64InPlace(void* ptr, ULONG len) {
	ULONG* ptr32 = (ULONG*)ptr;
	
	for (; len > 0; len -= sizeof(uint64_t), ptr32 += 2) {
		ULONG temp = __builtin_bswap32(ptr32[0]);
		ptr32[0] = __builtin_bswap32(ptr32[1]);
		ptr32[1] = temp;
	}
}

static ULONG ElfLoad(void* addr) {
	Elf32_Ehdr* ehdr;
	Elf32_Phdr* phdrs;
	UCHAR* image;
	int i;

	ehdr = (Elf32_Ehdr*)addr;

	if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) {
		//StdOutWrite("ELF has no phdrs\r\n");
		return 0;
	}

	if (ehdr->e_phentsize != sizeof(Elf32_Phdr)) {
		//StdOutWrite("Invalid ELF phdr size\r\n");
		return 0;
	}

	phdrs = (Elf32_Phdr*)(addr + ehdr->e_phoff);

	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdrs[i].p_type != PT_LOAD) {
			//print_f("skip PHDR %d of type %d\r\n", i, phdrs[i].p_type);
			continue;
		}

		// translate paddr to this BAT setup
		phdrs[i].p_paddr &= 0x3FFFFFFF;
		phdrs[i].p_paddr |= 0xC0000000;

#if 0
		print_f("PHDR %d 0x%08x [0x%x] -> 0x%08x [0x%x] <", i,
			phdrs[i].p_offset, phdrs[i].p_filesz,
			phdrs[i].p_paddr, phdrs[i].p_memsz);

		if (phdrs[i].p_flags & PF_R)
			print_f("R");
		if (phdrs[i].p_flags & PF_W)
			print_f("W");
		if (phdrs[i].p_flags & PF_X)
			print_f("X");
		print_f(">\r\n");
#endif

		if (phdrs[i].p_filesz > phdrs[i].p_memsz) {
			//print_f("-> file size > mem size\r\n");
			return 0;
		}

		if (phdrs[i].p_filesz) {
			//print_f("-> load 0x%x\r\n", phdrs[i].p_filesz);
			image = (UCHAR*)(addr + phdrs[i].p_offset);
			MsrLeSwap64(
				(void*)(phdrs[i].p_paddr),
				(const void*)image,
				phdrs[i].p_filesz,
				phdrs[i].p_memsz
			);
			memset((void*)image, 0, phdrs[i].p_filesz);

			if (phdrs[i].p_flags & PF_X)
				sync_before_exec((void*)phdrs[i].p_paddr, phdrs[i].p_memsz);
			else
				sync_after_write((void*)phdrs[i].p_paddr, phdrs[i].p_memsz);
		}
		else {
			//print_f("-> skip\r\n");
			memset((void*)phdrs[i].p_paddr + phdrs[i].p_filesz, 0, phdrs[i].p_memsz - phdrs[i].p_filesz);
		}
	}

	// fix the ELF entrypoint to physical address
	ULONG EntryPoint = ehdr->e_entry;
	EntryPoint &= 0x3fffffff;
	return EntryPoint;
}

typedef void (*ArcFirmEntry)(PHW_DESCRIPTION HwDesc);
extern void __attribute__((noreturn)) ModeSwitchEntry(ArcFirmEntry Start, PHW_DESCRIPTION HwDesc);

static void
SetupGX()
{
	Mtx44 p;
	int df = 1; // deflicker on/off

	GX_SetViewport (0, 0, 640, 480, 0, 1);
	GX_SetDispCopyYScale (1.0);
	GX_SetScissor (0, 0, 640, 480);

	GX_SetDispCopySrc (0, 0, 640, 480);
	GX_SetDispCopyDst (640, 480);
	GX_SetCopyFilter (rmode->aa, rmode->sample_pattern, (df == 1) ? GX_TRUE : GX_FALSE, rmode->vfilter);

	GX_SetFieldMode (rmode->field_rendering, GX_DISABLE);
	GX_SetPixelFmt (GX_PF_RGB8_Z24, GX_ZC_LINEAR);
	GX_SetDispCopyGamma (GX_GM_1_0);
	GX_SetCullMode (GX_CULL_NONE);
	GX_SetBlendMode(GX_BM_BLEND,GX_BL_DSTALPHA,GX_BL_INVSRCALPHA,GX_LO_CLEAR);

	GX_SetZMode (GX_TRUE, GX_LEQUAL, GX_TRUE);
	GX_SetColorUpdate (GX_TRUE);
	GX_SetNumChans(1);

	guOrtho(p, 480/2, -(480/2), -(640/2), 640/2, 100, 1000); // matrix, t, b, l, r, n, f
	GX_LoadProjectionMtx (p, GX_ORTHOGRAPHIC);
}

static inline void
draw_vert (u8 pos, u8 c, f32 s, f32 t)
{
	GX_Position1x8 (pos);
	GX_Color1x8 (c);
	GX_TexCoord2f32 (s, t);
}

static inline void
draw_square (Mtx v)
{
	Mtx m;			// model matrix.
	Mtx mv;			// modelview matrix.

	guMtxIdentity (m);
	guMtxTransApply (m, m, 0, 0, -100);
	guMtxConcat (v, m, mv);

	GX_LoadPosMtxImm (mv, GX_PNMTX0);
	GX_Begin (GX_QUADS, GX_VTXFMT0, 4);
	draw_vert (0, 0, 0.0, 0.0);
	draw_vert (1, 0, 1.0, 0.0);
	draw_vert (2, 0, 1.0, 1.0);
	draw_vert (3, 0, 0.0, 1.0);
	GX_End ();
}

#ifdef HW_RVL

#define _CPU_ISR_Enable() \
	do { \
		u32 _val = 0; \
		__asm__ __volatile__ ( \
			"mfmsr %0\n" \
			"ori %0,%0,0x8000\n" \
			"mtmsr %0" \
			: "=&r" ((_val)) : "0" ((_val)) \
			: : "memory" \
		); \
	} while (0)

#define _CPU_ISR_Disable( _isr_cookie ) \
	do { \
		u32 _disable_mask = 0; \
		_isr_cookie = 0; \
		__asm__ __volatile__ ( \
			"mfmsr %0\n" \
			"rlwinm %1,%0,0,17,15\n" \
			"mtmsr %1\n" \
			"extrwi %0,%0,1,16" \
			: "=&r" ((_isr_cookie)), "=&r" ((_disable_mask)) \
			: "0" ((_isr_cookie)), "1" ((_disable_mask)) \
			: "memory" \
		); \
	} while (0)

#define _CPU_ISR_Restore( _isr_cookie )  \
	do { \
		u32 _enable_mask = 0; \
		__asm__ __volatile__ ( \
			"cmpwi %0,0\n" \
			"beq 1f\n" \
			"mfmsr %1\n" \
			"ori %1,%1,0x8000\n" \
			"mtmsr %1\n" \
			"1:" \
			: "=r"((_isr_cookie)),"=&r" ((_enable_mask)) \
			: "0"((_isr_cookie)),"1" ((_enable_mask)) \
			: "memory" \
		); \
	} while (0)

extern void udelay(u32 us);

// encoder/i2c driver isn't exported so we need our own copy
static u32 i2cIdentFirst = 0;
static u32 i2cIdentFlag = 1;
static vu32* const _i2cReg = (u32*)0xCD800000;

static inline void __viOpenI2C(u32 channel)
{
	u32 val = ((_i2cReg[49]&~0x8000)|0x4000);
	val |= _SHIFTL(channel,15,1);
	_i2cReg[49] = val;
}

static inline u32 __viSetSCL(u32 channel)
{
	u32 val = (_i2cReg[48]&~0x4000);
	val |= _SHIFTL(channel,14,1);
	_i2cReg[48] = val;
	return 1;
}
static inline u32 __viSetSDA(u32 channel)
{
	u32 val = (_i2cReg[48]&~0x8000);
	val |= _SHIFTL(channel,15,1);
	_i2cReg[48] = val;
	return 1;
}

static inline u32 __viGetSDA(void)
{
	return _SHIFTR(_i2cReg[50],15,1);
}

static inline void __viCheckI2C(void)
{
	__viOpenI2C(0);
	udelay(4);

	i2cIdentFlag = 0;
	if(__viGetSDA()!=0) i2cIdentFlag = 1;
}

static u32 __sendSlaveAddress(u8 addr)
{
	u32 i;

	__viSetSDA(i2cIdentFlag^1);
	udelay(2);

	__viSetSCL(0);
	for(i=0;i<8;i++) {
		if(addr&0x80) __viSetSDA(i2cIdentFlag);
		else __viSetSDA(i2cIdentFlag^1);
		udelay(2);

		__viSetSCL(1);
		udelay(2);

		__viSetSCL(0);
		addr <<= 1;
	}

	__viOpenI2C(0);
	udelay(2);

	__viSetSCL(1);
	udelay(2);

	if(i2cIdentFlag==1 && __viGetSDA()!=0) return 0;

	__viSetSDA(i2cIdentFlag^1);
	__viOpenI2C(1);
	__viSetSCL(0);

	return 1;
}

static u32 __VISendI2CData(u8 addr,void *val,u32 len)
{
	u8 c;
	s32 i,j;
	u32 level,ret;

	if(i2cIdentFirst==0) {
		__viCheckI2C();
		i2cIdentFirst = 1;
	}

	_CPU_ISR_Disable(level);

	__viOpenI2C(1);
	__viSetSCL(1);

	__viSetSDA(i2cIdentFlag);
	udelay(4);

	ret = __sendSlaveAddress(addr);
	if(ret==0) {
		_CPU_ISR_Restore(level);
		return 0;
	}

	__viOpenI2C(1);
	for(i=0;i<len;i++) {
		c = ((u8*)val)[i];
		for(j=0;j<8;j++) {
			if(c&0x80) __viSetSDA(i2cIdentFlag);
			else __viSetSDA(i2cIdentFlag^1);
			udelay(2);

			__viSetSCL(1);
			udelay(2);
			__viSetSCL(0);

			c <<= 1;
		}
		__viOpenI2C(0);
		udelay(2);
		__viSetSCL(1);
		udelay(2);

		if(i2cIdentFlag==1 && __viGetSDA()!=0) {
			_CPU_ISR_Restore(level);
			return 0;
		}

		__viSetSDA(i2cIdentFlag^1);
		__viOpenI2C(1);
		__viSetSCL(0);
	}

	__viOpenI2C(1);
	__viSetSDA(i2cIdentFlag^1);
	udelay(2);
	__viSetSDA(i2cIdentFlag);

	_CPU_ISR_Restore(level);
	return 1;
}

static void __VIWriteI2CRegister8(u8 reg, u8 data)
{
	u8 buf[2];
	buf[0] = reg;
	buf[1] = data;
	__VISendI2CData(0xe0,buf,2);
	udelay(2);
}

static void __VIWriteI2CRegister16(u8 reg, u16 data)
{
	u8 buf[3];
	buf[0] = reg;
	buf[1] = data >> 8;
	buf[2] = data & 0xFF;
	__VISendI2CData(0xe0,buf,3);
	udelay(2);
}

#if 0
static void __VIWriteI2CRegister32(u8 reg, u32 data)
{
	u8 buf[5];
	buf[0] = reg;
	buf[1] = data >> 24;
	buf[2] = (data >> 16) & 0xFF;
	buf[3] = (data >> 8) & 0xFF;
	buf[4] = data & 0xFF;
	__VISendI2CData(0xe0,buf,5);
	udelay(2);
}

static void __VIWriteI2CRegisterBuf(u8 reg, int size, u8 *data)
{
	u8 buf[0x100];
	buf[0] = reg;
	memcpy(&buf[1], data, size);
	__VISendI2CData(0xe0,buf,size+1);
	udelay(2);
}
#endif


static void __VISetTiming(u8 mode)
{
	__VIWriteI2CRegister8(0x00, mode);
}

#if 0
static void __VISetOutputMode(u8 dtvstatus)
{
	switch (currTvMode)
	{
	case VI_NTSC:
	default:
		vdacFlagRegion = 0; break;
	case VI_MPAL:
		vdacFlagRegion = 1; break;
	case VI_PAL:
	case VI_EURGB60:
		vdacFlagRegion = 2; break;
	case VI_DEBUG:
	case VI_DEBUG_PAL:
		vdacFlagRegion = 3; break;
	}

	__VIWriteI2CRegister8(0x01, _SHIFTL(dtvstatus,5,3)|(vdacFlagRegion&0x1f));
}
#endif

static void __VISetVBlankData(bool cgms, bool wss, bool captions)
{
	u8 data = (captions ? 0 : 1) | (cgms ? 0 : 1) << 1 | (cgms ? 0 : 1) << 2;
	__VIWriteI2CRegister8(0x02, data);
}

#if 0
static void __VISetTrapFilter(bool enable)
{
	__VIWriteI2CRegister8(0x03, enable ? 1 : 0);
}
#endif

static void __VISetOutputEnable(bool enable)
{
	__VIWriteI2CRegister8(0x04, enable ? 1 : 0);
}

#if 0
static void __VISetCGMSData(u8 param1, u8 param2, u8 param3)
{
	__VIWriteI2CRegister16(0x05, (param1 & 3) << 8 | (param2 & 0xf) << 10 | param3);
}

static void __VIResetCGMSData(void)
{
	__VISetCGMSData(0, 0, 0);
}

static void __VISetWSSData(u8 param1, u8 param2, u8 param3, u8 param4)
{
	__VIWriteI2CRegister16(0x08, (param1 & 0xf) << 8 | (param2 & 0xf) << 12 | (param3 & 0x7) << 3 | (param4 & 0x7));
}

static void __VIResetWSSData(void)
{
	__VISetWSSData(0, 0, 0, 0);
}

static void __VISetOverDrive(bool enable, u8 level)
{
	__VIWriteI2CRegister8(0x0A, (level << 1) | (enable ? 1 : 0));
}

static void __VISetGamma(void)
{
	u8 gamma[0x21] = {
		0x10, 0x00, 0x10, 0x00, 0x10, 0x00, 0x10, 0x00,
		0x10, 0x00, 0x10, 0x00, 0x10, 0x20, 0x40, 0x60,
		0x80, 0xa0, 0xeb, 0x10, 0x00, 0x20, 0x00, 0x40,
		0x00, 0x60, 0x00, 0x80, 0x00, 0xa0, 0x00, 0xeb,
		0x00
	};
	__VIWriteI2CRegisterBuf(0x10, sizeof(gamma), gamma);
}

static void __VISetMacroVision(u8 rgb)
{
	u8 macrobuf[0x1a];

	memset(macrobuf, 0, sizeof(macrobuf));
	__VIWriteI2CRegisterBuf(0x40, sizeof(macrobuf), macrobuf);
	if (rgb) __VIWriteI2CRegister8(0x59, 1);
}

static void __VISetRGBChannelSwap(bool enable)
{
	__VIWriteI2CRegister8(0x62, enable ? 1 : 0);
}
#endif

static void __VISetOverSampling(u8 mode)
{
	__VIWriteI2CRegister8(0x65, mode);
}

static void __VISetClosedCaptionMode(u8 mode)
{
	__VIWriteI2CRegister8(0x6A, mode);
}

#if 0
static void __VISetRGBFilter(bool enable)
{
	__VIWriteI2CRegister8(0x6e, enable ? 1 : 0);
}
#endif

static void __VISetAudioVolume(u8 left_chan, u8 right_chan)
{
	u16 data = (left_chan << 8) | right_chan;
	__VIWriteI2CRegister16(0x71, data);
}

#if 0
static void __VISetClosedCaptionData(u8 param1, u8 param2, u8 param3, u8 param4)
{
	u32 data = (param1 & 0x7f) << 24 | (param2 & 0x7f) << 16 | (param3 & 0x7f) << 8 | (param4 & 0x7f);
	__VIWriteI2CRegister32(0x7A, data);
}

static void __VIResetClosedCaptionData(void)
{
	__VISetClosedCaptionData(0, 0, 0, 0);
}
#endif

static void video_encoder_init_vga(void) {
	__VISetOutputEnable(false);
	
	__VISetClosedCaptionMode(false);
	udelay(2);
	__VISetOverSampling(1);
	udelay(2);
	__VIWriteI2CRegister8(0x01, 0x23);
	udelay(2);
	
	__VISetTiming(0);
	// __VISetTrapFilter(false);
	__VISetAudioVolume(0x8e, 0x8e);
	// __VISetOverDrive(true, 0);
	__VISetVBlankData(false, false, false);
	// __VIResetCGMSData();
	// __VIResetWSSData();
	// __VIResetClosedCaptionData();
	// __VISetMacroVision(false);
	__VIWriteI2CRegister8(0x59, 0);
	
	
	udelay(2);
	VIDEO_Flush();
	VIDEO_WaitVSync();
	__VISetOutputEnable(true);
}
#endif

#ifdef HW_RVL
#define mfpvr() ({u32 _rval; \
		__asm__ __volatile__ ("mfpvr %0" : "=r"(_rval)); _rval;})

// Pwn IOS:
// - Enforce PPC access to all hardware.
// - On vWii, reboot PPC and race its bootrom to gain access to the other 2 cores.
//   Cafe OS uses core1 as main core due to its extra cache.
//   We must use core0 as main core as compat PI only allows core0 interrupts.
static void EnchantIOP(void) {
	//printf("PVR = %08x\n", mfpvr());
	if ((read32(0xCD800064) == 0xFFFFFFFF) ? 1 : 0) {
		// PPC already has access to all hardware.
		// If this isn't vWii, no need to do anything.
		if ((read32(0xCD8005A0) >> 16) != 0xCAFE) return;
		// If not in broadway compat mode, do nothing.
		if ((mfpvr() >> 16) != 8) return;
		//printf("Gaining root...\n");
	} //else printf("Gaining AHBPROT and IOS root...\n");
	
	if (IOS_GetVersion() != 58) {
		// we want IOS58.
		IOS_ReloadIOS(58);
	}
	
	// Use the /dev/sha exploit.
	// Thanks BroadOn for all the bugs :3
	static u32 stage1[] = {
		0x4903468D, // ldr r1, =0x10100000; mov sp, r1;
		0x49034788, // ldr r1, =entrypoint; blx r1;
		/* Overwrite reserved handler to loop infinitely */
		0x49036209, // ldr r1, =0xFFFF0014; str r1, [r1, #0x20];
		0x47080000, // bx r1
		0x10100000, // temporary stack
		0x41414141, // entrypoint
		0xFFFF0014, // reserved handler
	};
	
	static u32 iop_kernel_mode[] = {
		// give PPC access to all hardware
		0xe3a04536, // mov r4, #0x0D800000
		0xe3e05000, // mov r5, #0xFFFFFFFF
		0xe5845064, // str r5, [r4, #0x64]
		// set PPC uid as root
		0xe92d4003, // push {r0-r1, lr}
		0xe3a0000f, // mov r0, #15 ; PROCESS_ID_PPCIPC
		0xe3a01000, // mov r1, #0 ; USER_ID_ROOT
		0xe6000570, // syscall IOS_SetUid
		0xe8bd4003, // pop {r0-r1, lr}
		0xe3a05cff, // mov r5, #0xff00
		0xe5845024, // str r5, [r4, #0x24]
		0xe12fff1e, // bx lr
	};
	
	// We don't care about the very start of memory.
	// (Napa/Splash size is at offset 0x28, we aren't overwriting that much)
	u32* napa = (u32*)0x80000000;
	u32* ddr = (u32*)0x91000000;
	memcpy(napa, stage1, sizeof(stage1));
	napa[5] = (u32)MEM_K0_TO_PHYSICAL(iop_kernel_mode);
	DCFlushRange(napa, 0x20);
	
	int hSha = IOS_Open("/dev/sha", IPC_OPEN_NONE);
	if (hSha < 0) return;
	
	ioctlv vec[3] = {0};
	vec[1].data = (void*)0xfffe0028;
	vec[2].data = MEM_K0_TO_PHYSICAL(0x80000000);
	vec[2].len = 0x20;
	
	// broadon was cursed to never write secure code, amirite
	IOS_Ioctlv(hSha, 0, 1, 2, vec);
	// wait for context switch to idle thread
	//sleep(1);
	for (int i = 0; i < 1000000; i++) {
		if (read32(0xCD800024) == 0xFF00) break;
		udelay(1);
	}
	IOS_Close(hSha);
	
	// make sure it worked
	write32(0xCD800024, 0);
	if (read32(0xCD800064) != 0xFFFFFFFF) {
		return;
	}
	
	// do more only if in wiimode on cafe
	if ((read32(0xCD8005A0) >> 16) != 0xCAFE) {
		return;
	}
	
	// read ancast into memory.
	// 0x3f100 bytes at offset 0x500, to physaddr 0x01230000
	// arm payload will copy to 0x01330000
	const char ancast_path[] = "/title/00000001/00000200/content/00000003.app";
	int hAncast = IOS_Open(ancast_path, IPC_OPEN_READ);
	if (hAncast < 0) return;
	bool ancastSuccess = false;
	do {
		if (IOS_Seek(hAncast, 0x500, 0) < 0) break;
		if (IOS_Read(hAncast, (void*)0x81230000, 0x3f100) != 0x3f100) break;
		if (read32(0xc1230000) != 0xefa282d9) break;
		ancastSuccess = true;
	} while (0);
	IOS_Close(hAncast);
	if (!ancastSuccess) {
		return;
	}
	
	// first up, restart IOS to ensure icache + dcache are wiped
	// we lose root, but we only needed it to read the ancast image so...
	// Get IOS current version
	s32 ios = IOS_GetVersion();
	if (ios < 0) ios = IOS_GetPreferredVersion();
	if (ios >= 3) {
		// Patch to always set AHBPROT on loading TMD
		patch_ahbprot_reset();
		// reload IOS, get rid of our existing environment
		// try IOS58 first then fall back
		if (ios == 58 || IOS_ReloadIOS(58) < 0) IOS_ReloadIOS(ios);
		// and patch again, in case we reload again
		patch_ahbprot_reset();
	}
	
	// make sure ios version is correct
	if (read32(0xC0003140) != 0x3a1920) {
		return;
	}
	// get ARM kernel mode code execution again,
	// this time to race the PPC bootrom and get espresso-mode code execution
	
	static u32 iop_kernel_mode_restart_ppc[] = {
		#include "ppc_race_payload.inc"
	};

	static u32 ppc_payload_write[] = {
		0x38800000, // li r4, 0
		0x90840000, // stw r4, 0(r4)
		0x7c0420ac, // dcbf r4, r4
		0x7c0004ac, // sync
	};
	
	static u32 ppc_payload[] = {
		0x38600000 | (0x4000 - sizeof(ppc_payload_write)), // li r3, x
		0x38800000, // li r4, 0
		0x7c7a03a6, // mtsrr0 r3
		0x7c9b03a6, // mtsrr1 r4
		0x4c000064, // rfi
		0x48000000, // b .
		0x60000000, // nop
	};
	
	memcpy(ddr, iop_kernel_mode_restart_ppc, sizeof(iop_kernel_mode_restart_ppc));
	memcpy((void*)0x81320000, ppc_payload, sizeof(ppc_payload));
	memcpy((void*)(0x80004000 - sizeof(ppc_payload_write)), ppc_payload_write, sizeof(ppc_payload_write));
	memset((void*)0x816fffe0, 0, 0x20);

	memcpy(napa, stage1, sizeof(stage1));
	napa[5] = (u32)MEM_K0_TO_PHYSICAL(ddr);
	DCFlushRange(napa, 0x20);
	DCFlushRange(ddr, ((sizeof(iop_kernel_mode_restart_ppc) / 0x20) + 1) * 0x20);
	DCFlushRange((void*)0x81320000, 0x100);
	DCFlushRange((void*)0x816fffe0, 0x20);
	DCFlushRange((void*)(0x80004000 - sizeof(ppc_payload_write)), 0x20);
	
	// run exploit to reset ppc
	hSha = IOS_Open("/dev/sha", IPC_OPEN_NONE);
	if (hSha < 0) return;
	ioctlv vec2[3] = {0};
	vec2[1].data = (void*)0xfffe0028;
	vec2[2].data = MEM_K0_TO_PHYSICAL(0x80000000);
	vec2[2].len = 0x20;
	
	// wait for ios to fully come up
	//sleep(1);
	
	// close libogc IOS handles
	__IOS_ShutdownSubsystems();
	
	
	
	// bye bye
	IOS_Ioctlv(hSha, 0, 1, 2, vec2);
	// just hang until pwned IOP puts this cpu back into reset
	while (1);
}

#endif

int main(int argc, char** argv) {
	// Initialise the video system
	VIDEO_Init();
	
	// Obtain the preferred video mode from the system
	// On RVL: This will correspond to the settings in the Wii menu
	// On DOL: This will correspond to the current mode plus used cable type
	rmode = VIDEO_GetPreferredMode(NULL);
	#ifdef HW_RVL
	bool isRva = true;
	// Detect if running on RVA.
	// RVA has some custom hardware attached to EXI0:0 and EXI1:0.
	// Both of them output the same value when getting EXI ID.
	EXI_Probe(0);
	EXI_Probe(1);
	{
		u32 id0 = 0, id1 = 0;
		isRva =
			EXI_GetID(0, 0, &id0) != 0 &&
			EXI_GetID(1, 0, &id1) != 0 &&
			id0 == id1 &&
			id0 == 0xFF800000;
	}
	if (isRva) rmode = &TVNtsc480Prog;
	
	if (*(PULONG)0x80001800 == 0 && *(PULONG)0x80001804 == 'STUB') {
		// Do not try to run an IOS exploit if this isn't real hardware.
	} else {
		// Cast a spell on the IOP, we want more than what it's given us
		EnchantIOP();
	}
	#endif
	
	// Get size of Splash/Napa (MEM1), DDR (MEM2)
	ULONG SplashSize = *(PULONG)(0x80000028);
	ULONG DdrSize = 0;
	ULONG DdrIpcSize = 0; // from end of DDR
	ULONG RealDdrSize = 0;
	#ifdef HW_RVL
	DdrSize = *(PULONG)(0x80003120) - 0x90000000;
	DdrIpcSize = DdrSize - (*(PULONG)(0x80003130) - 0x90000000);
	RealDdrSize = DdrSize;
	if ((read32(0xCD800064) == 0xFFFFFFFF) ? 1 : 0) {
		// We have full hardware access.
		// Disable DDR memory protection.
		write16(MEM2_PROT, 0);
		// We now can check various registers.
		// Devkits have two ranks of DDR.
		if (read16(0xCD8B4216) == 1) {
			// This is really 128MB, if this thing is running 64MB IOS then override the size
			if (RealDdrSize <= 0x4000000) RealDdrSize = 0x8000000;
		}
		// On vWii we can modify a single register and get 256MB of DDR
		if ((read32(0xCD8005A0) >> 16) == 0xCAFE) {
			write16(0xCD8B421A, 0x3FFF);
			RealDdrSize = 0x10000000;
		}
	}
	#else
	// This is a gamecube, it might have double Splash if it's a devkit
	if (read16(0xCC004028) == 3) {
		// 48MB configuration
		if (SplashSize <= 0x1800000) SplashSize = 0x3000000;
	}
	#endif	
	
	// Get bus and cpu speed
	ULONG BusSpeed = *(PULONG)(0x800000F8);
	ULONG CpuSpeed = *(PULONG)(0x800000FC);
	
	// Get RTC counter bias
	ULONG CounterBias;
	#ifdef HW_RVL
	if (CONF_GetCounterBias(&CounterBias) < 0) CounterBias = 0;
	#else
	CounterBias = SYS_GetCounterBias();
	#endif
	
	ULONG FpFlags = 0;
	bool IsEmulator = false;
	// If the reload stub has zero at its entry point then this is dolphin
	if (*(PULONG)0x80001800 == 0 && *(PULONG)0x80001804 == 'STUB') {
		IsEmulator = true;
		FpFlags |= FPF_IN_EMULATOR;
	}
	#ifdef HW_RVL
	FpFlags |= FPF_IS_VEGAS;
	#endif
	
	// Initialise the SI sampling rate register.
	SI_SetSamplingRate(0);
	
	// Allocate XFB from end of Splash/Napa
	ULONG XfbLen = VIDEO_GetFrameBufferSize(rmode);
	ULONG XfbPhys = SplashSize - XfbLen;
	ULONG XfbVirt = (ULONG)MEM_PHYSICAL_TO_K1(XfbPhys);
	
	// Allocate 64KB from end of Splash/Napa for GX FIFO
	enum {
		GX_FIFO_SIZE = 0x10000
	};
	ULONG FifoPhys = XfbPhys - GX_FIFO_SIZE;
	// Ensure the address is 32 bytes aligned
	if ((FifoPhys & 0x1F) != 0) FifoPhys -= (FifoPhys & 0x1F);
	ULONG FifoVirt = (ULONG)MEM_PHYSICAL_TO_K1(FifoPhys);
	
	// Initialise the console
	console_init((PVOID)XfbVirt,20,20,rmode->fbWidth,rmode->xfbHeight,rmode->fbWidth*VI_DISPLAY_PIX_SZ);
	
	// Set up the video registers with the chosen mode
	VIDEO_Configure(rmode);

	// Tell the video hardware where our display memory is
	VIDEO_SetNextFramebuffer((PVOID)XfbVirt);

	// Make the display visible
	VIDEO_SetBlack(FALSE);

	// Flush the video register changes to the hardware
	VIDEO_Flush();

	// Wait for Video setup to complete
	VIDEO_WaitVSync();
	if(rmode->viTVMode&VI_NON_INTERLACE) VIDEO_WaitVSync();
	
	#ifdef HW_RVL
	// If this is RVA, set the video encoder into the correct mode
	if (isRva) video_encoder_init_vga();
	#endif
	
	// Initialise GX
	GX_Init((PVOID)FifoVirt, GX_FIFO_SIZE);
	
	// Clear the EFB.
	GXColor background = { 0, 0, 0, 255 };
	GX_SetCopyClear(background, 0x00ffffff);
	
#if 0
	// Calculate the scale factor.
	if (rmode->xfbHeight > 480) {
		f32 ScaleFactor = GX_GetYScaleFactor(480, rmode->xfbHeight);
		ULONG Scale = ((u32)(256.0f / ScaleFactor)) & 0x1ff;
		// todo: shove it somewhere?
	}
#endif
	
	// Initialise GX for later blitting a frame buffer from memory->EFB.
	SetupGX();
	GX_ClearVtxDesc ();
	GX_SetVtxDesc (GX_VA_POS, GX_INDEX8);
	GX_SetVtxDesc (GX_VA_CLR0, GX_INDEX8);
	GX_SetVtxDesc (GX_VA_TEX0, GX_DIRECT);

	GX_SetVtxAttrFmt (GX_VTXFMT0, GX_VA_POS, GX_POS_XYZ, GX_S16, 0);
	GX_SetVtxAttrFmt (GX_VTXFMT0, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA8, 0);
	GX_SetVtxAttrFmt (GX_VTXFMT0, GX_VA_TEX0, GX_TEX_ST, GX_F32, 0);

	GX_SetArray (GX_VA_POS, square, 3 * sizeof (s16));

	GX_SetNumTexGens (1);
	GX_SetNumChans (0);

	GX_SetTexCoordGen (GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY);

	GX_SetTevOp (GX_TEVSTAGE0, GX_REPLACE);
	GX_SetTevOrder (GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLORNULL);

	memset (&view, 0, sizeof (Mtx));
	guLookAt(view, &cam.pos, &cam.up, &cam.view);
	GX_LoadPosMtxImm (view, GX_PNMTX0);

	GX_InvVtxCache ();	// update vertex cache
	// init the dummy texture and load a texture object and render it
	GX_InitTexObj (&texobj, texturemem, 640, 480, GX_TF_RGBA8, GX_CLAMP, GX_CLAMP, GX_FALSE);
	GX_LoadTexObj (&texobj, GX_TEXMAP0);
	draw_square(view);
	//GX_SetColorUpdate(GX_TRUE);
	GX_DrawDone();
	
	// Everything is ready to load.
	// First 4MB of MEM1 is used by heap.
	// Last byte of MEM1 usable is (FifoPhys - 1)
	// We will load to MEM1+4MB, and reload to wherever (should be @8MB)
	PVOID Addr = (PVOID)MEM_PHYSICAL_TO_K0(PHYSADDR_LOAD);
	
	printf("\x1b[2;0H");
	printf("DOL/RVL ARC firmware loader\n");
	
	// Mount sd card.
	bool SdInitialised = false;
	#ifdef HW_RVL
	SdInitialised = fs_init_and_mount("sd", &__io_wiisd);
	#endif
	// Cannot have more than one EXI-SD device mounted at one time.
	FILE* f = NULL;
	#ifdef HW_RVL
	if (SdInitialised) f = fopen("sd:/nt/arcfw.elf", "rb");
	#endif
	
	for (u32 i = 0; i < 3 && f == NULL; i++) {
		bool inited = false;
		if (i == 0) {
			inited = fs_init_and_mount("carda", &__io_gcsda);
			if (!inited) inited = fs_init_and_mount("carda", &__io_ataa);
			if (inited) f = fopen("carda:/nt/arcfw.elf", "rb");
		} else if (i == 1) {
			inited = fs_init_and_mount("cardb", &__io_gcsdb);
			if (!inited) inited = fs_init_and_mount("cardb", &__io_atab);
			if (inited) f = fopen("cardb:/nt/arcfw.elf", "rb");
		} else if (i == 2) {
			inited = fs_init_and_mount("port2", &__io_gcsd2);
			if (!inited) inited = fs_init_and_mount("port2", &__io_atac);
			if (inited) f = fopen("port2:/nt/arcfw.elf", "rb");
		}
	}
	
	printf("Loading SD/IDE /nt/arcfw.elf...\n");
	
	if (f == NULL) {
		printf("Fatal error: Could not open SD/IDE /nt/arcfw.elf\n");
		RestartSystem();
	}
	printf("File opened...\n");
	
	fseek(f, 0, SEEK_END);
	ULONG length = ftell(f);
	fseek(f, 0, SEEK_SET);

	printf("Reading %d bytes...\n", length);
	
	int ActualLoad = fread(Addr, 1, length, f);
	fclose(f);
	
	// check for validity
	if (ActualLoad < sizeof(Elf32_Ehdr) || ElfValid(Addr) <= 0) {
		printf("Fatal error: SD/IDE /nt/arcfw.elf is not a valid ELF file\n");
		RestartSystem();
	}
	
	// load ELF
	ULONG EntryPoint = ElfLoad(Addr);
	if (EntryPoint == 0) {
		printf("Fatal error: Could not load SD/IDE /nt/arcfw.elf\n");
		RestartSystem();
	}

	// zero ELF out of memory.
	memset(Addr, 0, ActualLoad);
	
	// We now have free memory at exactly 4MB, we can use this to store our descriptor.
	PHW_DESCRIPTION Desc = (PHW_DESCRIPTION) Addr;
	Desc->MemoryLength[0] = SplashSize;
	Desc->MemoryLength[1] = RealDdrSize;
	Desc->DdrIpcBase = (DdrSize - DdrIpcSize) + 0x10000000;
	Desc->DdrIpcLength = DdrIpcSize;
	Desc->DecrementerFrequency = BusSpeed / 4;
	Desc->RtcBias = CounterBias;
	Desc->FpFlags = FpFlags;
	Desc->FrameBufferBase = XfbPhys;
	Desc->FrameBufferLength = XfbLen;
	Desc->FrameBufferWidth = rmode->fbWidth;
	Desc->FrameBufferHeight = rmode->xfbHeight - 1;
	Desc->FrameBufferStride = rmode->fbWidth * VI_DISPLAY_PIX_SZ;
	Desc->GxFifoBase = FifoPhys;
	
	// Wipe screen at this point.
	printf("\x1b[2J");
	
	// Munge descriptor so the structure looks ok when accessed with MSR_LE enabled
	MsrLeMunge32(Desc, sizeof(*Desc));
	
	#ifdef HW_RVL
	// Get IOS current version
	s32 ios = IOS_GetVersion();
	if (ios < 0) ios = IOS_GetPreferredVersion();
	if (ios >= 3) {
		// Patch to always set AHBPROT on loading TMD
		if (!IsEmulator) patch_ahbprot_reset();
		// reload IOS, get rid of our existing environment
		// try IOS58 first then fall back
		if (ios == 58 || __IOS_LaunchNewIOS(58) < 0) __IOS_LaunchNewIOS(ios);
		// wait for IOS to finish loading
		usleep(1000000);
		// and patch again, we want to reload IOS on the way in to NT
		if (!IsEmulator) patch_ahbprot_reset();
	}
	#endif
	
	// Call entrypoint through mode switch
	ModeSwitchEntry((ArcFirmEntry)EntryPoint, (PVOID)PHYSADDR_LOAD);
}

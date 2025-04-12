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

static inline USHORT read16(ULONG addr)
{
	USHORT x;
	__asm__ __volatile__(
		"lhz %0,0(%1) ; sync" : "=r"(x) : "b"(addr));
	return x;
}

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

int main(int argc, char** argv) {
	// Initialise the video system
	VIDEO_Init();
	
	// Obtain the preferred video mode from the system
	// On RVL: This will correspond to the settings in the Wii menu
	// On DOL: This will correspond to the current mode plus used cable type
	rmode = VIDEO_GetPreferredMode(NULL);
	
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

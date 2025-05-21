#pragma once

typedef enum _PXI_CONTROL {
	PXI_REQ_SEND = BIT(0), /// < Send request to IOP.
	PXI_REQ_ACK = BIT(1), /// < IOP acknowledged request. Write to clear.
	PXI_RES_SENT = BIT(2), /// < IOP responded. Write to clear.
	PXI_RES_ACK = BIT(3), /// < Acknowledge response to IOP.
	PXI_RES_SENT_INT = BIT(4), /// < Raise interrupt when IOP responds.
	PXI_REQ_ACK_INT = BIT(5), /// < Raise interrupt when IOP acks.
	
	PXI_BITS_PRESERVE = PXI_RES_SENT_INT | PXI_REQ_ACK_INT /// < Bits to preserve when clearing interrupt statuses.
} PXI_CONTROL;

typedef struct _PXI_CORE_REGISTERS {
	ULONG Message;
	ULONG Control; // PXI_CONTROL
} PXI_CORE_REGISTERS, *PPXI_CORE_REGISTERS;

typedef struct _PXI_REGISTERS {
	PXI_CORE_REGISTERS Request, Response;
	ULONG Reserved[(0x30 - 0x10) / sizeof(ULONG)];
	ULONG InterruptCause;
	ULONG InterruptMask;
} PXI_REGISTERS, *PPXI_REGISTERS;

_Static_assert(sizeof(PXI_REGISTERS) == 0x38);

typedef struct _PXI_REGISTERS_CPU {
	PXI_CORE_REGISTERS Request, Response;
} PXI_REGISTERS_CPU, *PPXI_REGISTERS_CPU;

_Static_assert(sizeof(PXI_REGISTERS_CPU) == 0x10);

typedef struct _INTERRUPT_REGISTERS_CPU {
	ULONG Cause[2];
	ULONG Mask[2];
} INTERRUPT_REGISTERS_CPU, *PINTERRUPT_REGISTERS_CPU;

_Static_assert(sizeof(INTERRUPT_REGISTERS_CPU) == 0x10);

typedef struct _PXI_REGISTERS_LATTE {
	PXI_REGISTERS Vegas;
	ULONG Reserved[(0x400 - 0x38) / sizeof(ULONG)];
	PXI_REGISTERS_CPU PerCore[3];
	ULONG Reserved2[(0x440 - 0x430) / sizeof(ULONG)];
	INTERRUPT_REGISTERS_CPU Interrupt[3];
} PXI_REGISTERS_LATTE, *PPXI_REGISTERS_LATTE;

_Static_assert(sizeof(PXI_REGISTERS_LATTE) == 0x470);

enum {
	VEGAS_INTERRUPT_GPIO = BIT(10),
	VEGAS_INTERRUPT_PXI = BIT(30)
};

enum {
	PXI_REGISTER_BASE = 0x0d800000
};

extern PPXI_REGISTERS HalpPxiRegisters;
#define HalpPxiRegistersLatte ((PPXI_REGISTERS_LATTE)HalpPxiRegisters)
//#define MMIO_INTLT_OFFSET(elem) HalpPiInterruptRegsLatte, (__builtin_offsetof(PXI_REGISTERS_LATTE, Interrupt) + (sizeof(INTERRUPT_REGISTERS_CPU) * __mfspr(SPR_PIR)) + __builtin_offsetof(INTERRUPT_REGISTERS_CPU, elem))
#define MMIO_INTLT_OFFSET(elem) HalpPiInterruptRegsLatte, (__builtin_offsetof(PXI_REGISTERS_LATTE, Interrupt) + __builtin_offsetof(INTERRUPT_REGISTERS_CPU, elem))

#define PXI_REQUEST_READ() MmioReadBase32( MMIO_OFFSET(HalpPxiRegisters, Request.Message) )
#define PXI_REQUEST_WRITE(x) MmioWriteBase32( MMIO_OFFSET(HalpPxiRegisters, Request.Message), (ULONG)((x)) )
#define PXI_CONTROL_READ() ((PXI_CONTROL) MmioReadBase32( MMIO_OFFSET(HalpPxiRegisters, Request.Control) ))
#define PXI_CONTROL_WRITE(x) MmioWriteBase32( MMIO_OFFSET(HalpPxiRegisters, Request.Control), (ULONG)((x)) )
#define PXI_CONTROL_SET(x) do { \
	PXI_CONTROL Control = PXI_CONTROL_READ() & PXI_BITS_PRESERVE; \
	Control |= (x); \
	PXI_CONTROL_WRITE(Control); \
} while (FALSE)
#define PXI_RESPONSE_READ() MmioReadBase32( MMIO_OFFSET(HalpPxiRegisters, Response.Message) )
#define VEGAS_INTERRUPT_MASK_SET(x) do { \
	MmioWriteBase32( MMIO_OFFSET(HalpPxiRegisters, InterruptMask), (ULONG)((x)) ); \
	if (HalpSystemIsCafe()) MmioWriteBase32( MMIO_INTLT_OFFSET(Mask), (ULONG)((x)) ); \
} while (0)
#define VEGAS_INTERRUPT_CLEAR(x) do { \
	MmioWriteBase32( MMIO_OFFSET(HalpPxiRegisters, InterruptCause), (ULONG)((x)) ); \
	if (HalpSystemIsCafe()) MmioWriteBase32( MMIO_INTLT_OFFSET(Cause), (ULONG)((x)) ); \
} while (0)

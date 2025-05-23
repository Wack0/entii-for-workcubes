#pragma once
#include "types.h"

// USB data structures

enum {
	USB_CLASS_HID = 3,
	USB_SUBCLASS_NONE = 0,
	USB_SUBCLASS_BOOT,
	USB_PROTOCOL_NONE = 0,
	USB_PROTOCOL_KEYBOARD,
	USB_PROTOCOL_MOUSE
};

enum {
	USB_REPTYPE_INPUT = 1,
	USB_REPTYPE_OUTPUT,
	USB_REPTYPE_FEATURE
};

// Descriptor types
enum {
	USB_DT_DEVICE = 1,
	USB_DT_CONFIG,
	USB_DT_STRING,
	USB_DT_INTERFACE,
	USB_DT_ENDPOINT,
	USB_DT_DEVICE_QUALIFIER,
	USB_DT_OTHER_SPEED_CONFIG,
	USB_DT_INTERFACE_POWER,
	USB_DT_OTG,
	USB_DT_DEBUG = 0x10,
	USB_DT_INTERFACE_ASSOCIATION,
	USB_DT_HID = 0x21,
	USB_DT_REPORT,
	USB_DT_PHYSICAL,
	USB_DT_CLASS_SPECIFIC_INTERFACE,
	USB_DT_CLASS_SPECIFIC_ENDPOINT,
	USB_DT_HUB = 0x29
};

// Standard requests
enum {
	USB_REQ_GETSTATUS = 0,
	USB_REQ_CLEARFEATURE = 1,
	USB_REQ_SETFEATURE = 3,
	USB_REQ_SETADDRESS = 5,
	USB_REQ_GETDESCRIPTOR = 6,
	USB_REQ_SETDESCRIPTOR = 7,
	USB_REQ_GETCONFIG = 8,
	USB_REQ_SETCONFIG = 9,
	USB_REQ_GETINTERFACE = 10,
	USB_REQ_SETINTERFACE = 11,
	USB_REQ_SYNCFRAME = 12,

	USB_REQ_GETREPORT = 1,
	USB_REQ_GETIDLE = 2,
	USB_REQ_GETPROTOCOL = 3,
	USB_REQ_SETREPORT = 9,
	USB_REQ_SETIDLE = 10,
	USB_REQ_SETPROTOCOL = 11
};

// Descriptor sizes
enum {
	USB_DT_DEVICE_SIZE = 18,
	USB_DT_CONFIG_SIZE = 9,
	USB_DT_INTERFACE_SIZE = 9,
	USB_DT_ENDPOINT_SIZE = 7,
	USB_DT_ENDPOINT_AUDIO_SIZE = 9,
	USB_DT_HID_SIZE = 9,
	USB_DT_MINREPORT_SIZE = 8,
	USB_DT_HUB_NONVAR_SIZE = 7,
};

// Control message request type
enum {
	USB_CTRLTYPE_DIR_HOST2DEVICE = (0 << 7), // bit 7 off
	USB_CTRLTYPE_DIR_DEVICE2HOST = (1 << 7), // bit 7 on

	USB_CTRLTYPE_TYPE_STANDARD = (0 << 5),
	USB_CTRLTYPE_TYPE_CLASS = (1 << 5),
	USB_CTRLTYPE_TYPE_VENDOR = (2 << 5),
	USB_CTRLTYPE_TYPE_RESERVED = (3 << 5),

	USB_CTRLTYPE_REC_DEVICE = 0,
	USB_CTRLTYPE_REC_INTERFACE,
	USB_CTRLTYPE_REC_ENDPOINT,
	USB_CTRLTYPE_REC_OTHER,

	USB_REQTYPE_INTERFACE_GET = (USB_CTRLTYPE_DIR_DEVICE2HOST | USB_CTRLTYPE_TYPE_CLASS | USB_CTRLTYPE_REC_INTERFACE),
	USB_REQTYPE_INTERFACE_SET = (USB_CTRLTYPE_DIR_HOST2DEVICE | USB_CTRLTYPE_TYPE_CLASS | USB_CTRLTYPE_REC_INTERFACE),
	USB_REQTYPE_ENDPOINT_GET = (USB_CTRLTYPE_DIR_DEVICE2HOST | USB_CTRLTYPE_TYPE_CLASS | USB_CTRLTYPE_REC_ENDPOINT),
	USB_REQTYPE_ENDPOINT_SET = (USB_CTRLTYPE_DIR_HOST2DEVICE | USB_CTRLTYPE_TYPE_CLASS | USB_CTRLTYPE_REC_ENDPOINT),
};

enum {
	USB_FEATURE_ENDPOINT_HALT = 0,

	USB_ENDPOINT_INTERRUPT = 0x03,
	USB_ENDPOINT_IN = 0x80,
	USB_ENDPOINT_OUT = 0x00
};

enum {
	USB_COUNT_DEVICES = 32,
	USB_COUNT_ENDPOINTS = 16,
	USB_COUNT_ENDPOINTS_HID = 2,
};

enum {
	USB_CANCEL_CONTROL,
	USB_CANCEL_INCOMING,
	USB_CANCEL_OUTGOING
};

#if 0
// 8-bit as 32-bit for uncached DDR write
typedef union _U8_AS_32 {
	struct {
		UCHAR Padding[3];
		UCHAR Char;
	};
	ULONG Long;
} U8_AS_32, * PU8_AS_32;

// Standard structures.
typedef struct ARC_ALIGNED(8) _USB_ENDPOINT {
	UCHAR bLength;
	UCHAR bDescriptorType;
	UCHAR bEndpointAddress;
	UCHAR bmAttributes;
	USHORT wMaxPacketSize;
	UCHAR bInterval;
} USB_ENDPOINT, * PUSB_ENDPOINT;
_Static_assert(sizeof(USB_ENDPOINT) == 8);

typedef struct ARC_ALIGNED(4) _USB_INTERFACE {
	UCHAR
		bLength,
		bDescriptorType,
		bInterfaceNumber,
		bAlternateSetting,
		bNumEndpoints,
		bInterfaceClass,
		bInterfaceSubClass,
		bInterfaceProtocol,
		iInterface;
} USB_INTERFACE, * PUSB_INTERFACE;
_Static_assert(sizeof(USB_INTERFACE) == 0xC);

typedef struct _USB_INTERFACE_DESC {
	USB_INTERFACE Desc; // 0
	PUSB_ENDPOINT Endpoints; // C
	PVOID Extra; // 10
	USHORT ExtraSize; // 14
} USB_INTERFACE_DESC, * PUSB_INTERFACE_DESC;

typedef struct ARC_ALIGNED(4) _USB_CONFIGURATION {
	UCHAR bLength;
	UCHAR bDescriptorType;
	USHORT bTotalLength;
	UCHAR bNumInterfaces;
	UCHAR bConfigurationValue;
	UCHAR iConfiguration;
	UCHAR bmAttributes;
	UCHAR bMaxPower;
} USB_CONFIGURATION, * PUSB_CONFIGURATION;
_Static_assert(sizeof(USB_CONFIGURATION) == 0xC);

typedef struct _USB_CONFIGURATION_DESC {
	USB_CONFIGURATION Desc;
	USB_INTERFACE_DESC Interface;
} USB_CONFIGURATION_DESC, * PUSB_CONFIGURATION_DESC;

typedef struct ARC_ALIGNED(4) _USB_DEVICE {
	UCHAR bLength;
	UCHAR bDescriptorType;
	USHORT bcdUSB;
	UCHAR bDeviceClass;
	UCHAR bDeviceSubClass;
	UCHAR bDeviceProtocol;
	UCHAR bMaxPacketSize;
	USHORT idVendor;
	USHORT idProduct;
	USHORT bcdDevice;
	UCHAR iManufacturer;
	UCHAR iProduct;
	UCHAR iSerialNumber;
	UCHAR bNumConfigurations;
} USB_DEVICE, * PUSB_DEVICE;
_Static_assert(sizeof(USB_DEVICE) == 0x14);

typedef struct _USB_DEVICE_DESC {
	USB_DEVICE Device;
	USB_CONFIGURATION Config;
	USB_INTERFACE Interface;
	USB_ENDPOINT Endpoints[USB_COUNT_ENDPOINTS];
} USB_DEVICE_DESC, * PUSB_DEVICE_DESC;

typedef struct ARC_PACKED _USB_HID_ENTRY {
	UCHAR bDescriptorType;
	USHORT wDescriptorLength;
} USB_HID_ENTRY, * PUSB_HID_ENTRY;

typedef struct ARC_PACKED _USB_HID {
	UCHAR bLength;
	UCHAR bDescriptorType;
	USHORT bcdHID;
	UCHAR bCountryCode;
	UCHAR bNumDescriptors;
	USB_HID_ENTRY Descriptors[1];
} USB_HID, * PUSB_HID;
_Static_assert(sizeof(USB_HID) == USB_DT_HID_SIZE);

// IOS-USB types.
typedef LONG IOS_USB_HANDLE, * PIOS_USB_HANDLE;

typedef struct _IOS_USB_DEVICE_ENTRY {
	IOS_USB_HANDLE DeviceHandle;
	USHORT VendorId;
	USHORT ProductId;
	ULONG Token;
} IOS_USB_DEVICE_ENTRY, * PIOS_USB_DEVICE_ENTRY;

typedef struct _IOS_USB_DEVICE_ENTRY_MAX {
	IOS_USB_DEVICE_ENTRY Entries[USB_COUNT_DEVICES];
} IOS_USB_DEVICE_ENTRY_MAX, * PIOS_USB_DEVICE_ENTRY_MAX;
#endif

// 8-bit as 32-bit for uncached DDR write
typedef union _U8_AS_32 {
	UCHAR Char;
	ULONG Long;
} U8_AS_32, * PU8_AS_32;

// Standard structures.
typedef struct ARC_BE ARC_ALIGNED(4) _USB_ENDPOINT {
	UCHAR bLength;
	UCHAR bDescriptorType;
	UCHAR bEndpointAddress;
	UCHAR bmAttributes;
	USHORT wMaxPacketSize;
	UCHAR bInterval;
} USB_ENDPOINT, * PUSB_ENDPOINT;
_Static_assert(sizeof(USB_ENDPOINT) == 8);

typedef struct ARC_BE ARC_ALIGNED(4) _USB_INTERFACE {
	UCHAR
		bLength,
		bDescriptorType,
		bInterfaceNumber,
		bAlternateSetting,
		bNumEndpoints,
		bInterfaceClass,
		bInterfaceSubClass,
		bInterfaceProtocol,
		iInterface;
} USB_INTERFACE, * PUSB_INTERFACE;
_Static_assert(sizeof(USB_INTERFACE) == 0xC);

typedef struct _USB_INTERFACE_DESC {
	USB_INTERFACE Desc;
	PUSB_ENDPOINT Endpoints;
	PVOID Extra;
	USHORT ExtraSize;
} USB_INTERFACE_DESC, * PUSB_INTERFACE_DESC;

typedef struct ARC_BE ARC_ALIGNED(4) _USB_CONFIGURATION {
	UCHAR bLength;
	UCHAR bDescriptorType;
	USHORT bTotalLength;
	UCHAR bNumInterfaces;
	UCHAR bConfigurationValue;
	UCHAR iConfiguration;
	UCHAR bmAttributes;
	UCHAR bMaxPower;
} USB_CONFIGURATION, * PUSB_CONFIGURATION;
_Static_assert(sizeof(USB_CONFIGURATION) == 0xC);

typedef struct _USB_CONFIGURATION_DESC {
	USB_CONFIGURATION Desc;
	USB_INTERFACE_DESC Interface;
} USB_CONFIGURATION_DESC, * PUSB_CONFIGURATION_DESC;

typedef struct ARC_BE ARC_ALIGNED(4) _USB_DEVICE {
	UCHAR bLength;
	UCHAR bDescriptorType;
	USHORT bcdUSB;
	UCHAR bDeviceClass;
	UCHAR bDeviceSubClass;
	UCHAR bDeviceProtocol;
	UCHAR bMaxPacketSize;
	USHORT idVendor;
	USHORT idProduct;
	USHORT bcdDevice;
	UCHAR iManufacturer;
	UCHAR iProduct;
	UCHAR iSerialNumber;
	UCHAR bNumConfigurations;
} USB_DEVICE, * PUSB_DEVICE;
_Static_assert(sizeof(USB_DEVICE) == 0x14);

typedef struct _USB_DEVICE_DESC {
	USB_DEVICE Device;
	USB_CONFIGURATION Config;
	USB_INTERFACE Interface;
	USB_ENDPOINT Endpoints[USB_COUNT_ENDPOINTS];
} USB_DEVICE_DESC, * PUSB_DEVICE_DESC;

typedef struct ARC_LE ARC_PACKED _USB_HID_ENTRY {
	UCHAR bDescriptorType;
	USHORT wDescriptorLength;
} USB_HID_ENTRY, * PUSB_HID_ENTRY;

typedef struct ARC_LE ARC_PACKED _USB_HID {
	UCHAR bLength;
	UCHAR bDescriptorType;
	USHORT bcdHID;
	UCHAR bCountryCode;
	UCHAR bNumDescriptors;
	USB_HID_ENTRY Descriptors[1];
} USB_HID, * PUSB_HID;
_Static_assert(sizeof(USB_HID) == USB_DT_HID_SIZE);

// IOS-USB types.
typedef LONG IOS_USB_HANDLE, * PIOS_USB_HANDLE;

typedef struct _IOS_USB_DEVICE_ENTRY {
	IOS_USB_HANDLE DeviceHandle;
	USHORT VendorId;
	USHORT ProductId;
	ULONG Token;
} IOS_USB_DEVICE_ENTRY, * PIOS_USB_DEVICE_ENTRY;

typedef struct _IOS_USB_DEVICE_ENTRY_MAX {
	IOS_USB_DEVICE_ENTRY Entries[USB_COUNT_DEVICES];
} IOS_USB_DEVICE_ENTRY_MAX, * PIOS_USB_DEVICE_ENTRY_MAX;

// IOS USBv5 data structures
enum {
	USB_IOCTL_GET_VERSION = 0,
	USB_IOCTL_DEVICE_CHANGE,
	USB_IOCTL_SHUTDOWN,
	USB_IOCTL_GET_DEVICE_INFO,
	USB_IOCTL_ATTACH,
	USB_IOCTL_RELEASE,
	USB_IOCTL_ATTACH_FINISH,
	USB_IOCTL_SET_ALTERNATE_SETTING,
	USB_IOCTL_RESET,
	USB_IOCTL_SUSPEND_RESUME = 0x10,
	USB_IOCTL_CANCEL_ENDPOINT,
	USB_IOCTLV_CONTROL_TRANSFER,
	USB_IOCTLV_INTERRUPT_TRANSFER,
	USB_IOCTLV_ISOCHRONOUS_TRANSFER,
	USB_IOCTLV_BULK_TRANSFER
};

enum {
	USB_BUS_OHCI = 0,
	USB_BUS_EHCI = 1,
	USB_BUS_USB1 = USB_BUS_OHCI,
	USB_BUS_USB2 = USB_BUS_EHCI
};

enum {
	USB_MAX_STRING_LENGTH = 0xFF
};

LONG UlInit(void);

void UlShutdown(void);

LONG UlOpenDevice(IOS_USB_HANDLE DeviceHandle);

LONG UlCloseDevice(IOS_USB_HANDLE DeviceHandle);

LONG UlGetDeviceDesc(IOS_USB_HANDLE DeviceHandle, PUSB_DEVICE Device);

LONG UlGetDescriptors(IOS_USB_HANDLE DeviceHandle, PUSB_DEVICE_DESC Device);

// Returns unswapped data in buffer, use bus pointers to access
LONG UlGetGenericDescriptor(
	IOS_USB_HANDLE DeviceHandle,
	UCHAR Type,
	UCHAR Index,
	UCHAR Interace,
	PVOID Data,
	ULONG Size
);

// Returns unswapped data in buffer, use bus pointers to access
LONG UlGetHidDescriptor(
	IOS_USB_HANDLE DeviceHandle,
	UCHAR Interface,
	PUSB_HID Hid,
	ULONG Size
);

LONG UlGetReportDescriptorSize(IOS_USB_HANDLE DeviceHandle, UCHAR Interface, PUSHORT Length);

// Returns unswapped data in buffer, use bus pointers to access
LONG UlGetReportDescriptor(IOS_USB_HANDLE DeviceHandle, UCHAR Interface, PVOID Data, USHORT Length);

//void UlFreeDescriptors(PUSB_DEVICE_DESC Device);

LONG UlGetAsciiString(IOS_USB_HANDLE DeviceHandle, UCHAR Index, USHORT LangID, USHORT Length, PVOID Data, PUSHORT WrittenLength);

LONG UlTransferIsoMessage(IOS_USB_HANDLE DeviceHandle, UCHAR Endpoint, UCHAR Packets, PU16BE PacketSizes, PVOID Data);
LONG UlTransferIsoMessageAsync(IOS_USB_HANDLE DeviceHandle, UCHAR Endpoint, UCHAR Packets, PU16BE PacketSizes, PVOID Data);

LONG UlTransferInterruptMessage(IOS_USB_HANDLE DeviceHandle, UCHAR Endpoint, USHORT Length, PVOID Data);
LONG UlTransferInterruptMessageAsync(IOS_USB_HANDLE DeviceHandle, UCHAR Endpoint, USHORT Length, PVOID Data);

LONG UlTransferBulkMessage(IOS_USB_HANDLE DeviceHandle, UCHAR Endpoint, USHORT Length, PVOID Data);
LONG UlTransferBulkMessageAsync(IOS_USB_HANDLE DeviceHandle, UCHAR Endpoint, USHORT Length, PVOID Data);

LONG UlTransferControlMessage(IOS_USB_HANDLE DeviceHandle, UCHAR RequestType, UCHAR Request, USHORT Value, USHORT Index, USHORT Length, PVOID Data);
LONG UlTransferControlMessageAsync(IOS_USB_HANDLE DeviceHandle, UCHAR RequestType, UCHAR Request, USHORT Value, USHORT Index, USHORT Length, PVOID Data);

void UlGetDeviceList(PIOS_USB_DEVICE_ENTRY Entry, UCHAR Count, UCHAR InterfaceClass, PUCHAR WrittenCount);

LONG UlSetConfiguration(IOS_USB_HANDLE DeviceHandle, UCHAR Configuration);

LONG UlGetConfiguration(IOS_USB_HANDLE DeviceHandle, PUCHAR Configuration);

LONG UlSetAlternativeInterface(IOS_USB_HANDLE DeviceHandle, UCHAR Interface, UCHAR AlternateSetting);

LONG UlCancelEndpoint(IOS_USB_HANDLE DeviceHandle, UCHAR Endpoint);

LONG UlClearHalt(IOS_USB_HANDLE DeviceHandle);

PVOID UlGetPassedAsyncContext(PVOID AsyncContext);
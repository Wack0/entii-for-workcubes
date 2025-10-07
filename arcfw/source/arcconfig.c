#include <stddef.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include "arc.h"
#include "arcconfig.h"
#include "arcdevice.h"
#include "arcenv.h"
#include "arcconsole.h"
#include "arcmem.h"
#include "arcio.h"
#include "arcdisk.h"
#include "runtime.h"

enum {
    MAXIMUM_DEVICE_COUNT = 256
};

// Declare stub routines
static ARC_STATUS StubOpen(PCHAR OpenPath, OPEN_MODE OpenMode, PULONG FileId) { return _ESUCCESS; }
static ARC_STATUS StubClose(ULONG FileId) {
    // TODO: set closed flag in file table
    return _ESUCCESS;
}
static ARC_STATUS StubMount(PCHAR MountPath, MOUNT_OPERATION Operation) { return _EINVAL; }
static ARC_STATUS StubSeek(ULONG FileId, PLARGE_INTEGER Offset, SEEK_MODE SeekMode) { return _ESUCCESS; }
static ARC_STATUS StubRead(ULONG FileId, PVOID Buffer, ULONG Length, PULONG Count) { return _ESUCCESS; }
static ARC_STATUS StubWrite(ULONG FileId, PVOID Buffer, ULONG Length, PULONG Count) { return _ESUCCESS; }
static ARC_STATUS StubGetReadStatus(ULONG FileId) { return _ESUCCESS; }
static ARC_STATUS StubGetFileInformation(ULONG FileId, PFILE_INFORMATION FileInfo) { return _EINVAL; }

// Declare display write routine
static char s_ConsoleBuffer[255];
static UCHAR s_ConsoleIdx;
static ARC_STATUS DisplayWrite(ULONG FileId, PVOID Buffer, ULONG Length, PULONG Count) {
    if (Length == 0) {
        *Count = 0;
        return _ESUCCESS;
    }
    // Work around a bug in MS code with ANSI escapes and multiple parameters.
    // (the console code for this ARC firmware expects to see all ansi escape data in a single buffer)
    PUCHAR Buf8 = (PUCHAR)Buffer;
    if (Buf8[0] == 0x9B && Buf8[Length - 1] == ';' && (Length <= 0x10)) {
        memcpy(s_ConsoleBuffer, Buffer, Length);
        s_ConsoleIdx = Length;
    }
    else if (s_ConsoleIdx != 0 && (Length <= 0x10)) {
        memcpy(&s_ConsoleBuffer[s_ConsoleIdx], Buffer, Length);
        *Count = ArcConsoleWrite(s_ConsoleBuffer, s_ConsoleIdx + Length);
        s_ConsoleIdx = 0;
    }
    else {
        *Count = ArcConsoleWrite((PBYTE)Buffer, Length);
    }
    return _ESUCCESS;
}

static const CHAR MonitorPath[] = "multi(0)video(0)monitor(0)";
static const CHAR s_DisplayIdentifier[] = "FLIPPER_GX";

static const DEVICE_VECTORS MonitorVectors = {
    .Open = StubOpen,
    .Close = StubClose,
    .Mount = StubMount,
    .Read = StubRead,
    .Write = DisplayWrite,
    .Seek = StubSeek,
    .GetReadStatus = StubGetReadStatus,
    .GetFileInformation = StubGetFileInformation,
    .SetFileInformation = NULL,
    .GetDirectoryEntry = NULL
};

// Let printf work.
static size_t StdoutWrite(FILE* Instance, const char* bp, size_t n) {
    return ArcConsoleWrite(bp, n);
}
static struct File_methods s_fmStdout = {
    StdoutWrite, NULL
};
static FILE s_fStdout = { &s_fmStdout };
FILE* stdout = &s_fStdout;

// Declare keyboard routines
static ARC_STATUS KeyRead(ULONG FileId, PVOID Buffer, ULONG Length, PULONG Count) {
    // Read Length chars into buffer, blocking if needed.
    PUCHAR Buffer8 = (PUCHAR)Buffer;
    ULONG RealCount = 0;
    for (; RealCount < Length; RealCount++) {
        Buffer8[RealCount] = IOSKBD_ReadChar();
    }
    *Count = Length;
    return _ESUCCESS;
}

static ARC_STATUS KeyGetReadStatus(ULONG FileId) {
    // return EAGAIN if no chars available, otherwise return ESUCCESS
    return IOSKBD_CharAvailable() ? _ESUCCESS : _EAGAIN;
}

static const CHAR KeyboardPath[] = "multi(0)keyboard(0)";

static const DEVICE_VECTORS KeyboardVectors = {
    .Open = StubOpen,
    .Close = StubClose,
    .Mount = StubMount,
    .Read = KeyRead,
    .Write = StubWrite,
    .Seek = StubSeek,
    .GetReadStatus = KeyGetReadStatus,
    .GetFileInformation = StubGetFileInformation,
    .SetFileInformation = NULL,
    .GetDirectoryEntry = NULL
};

// ARC path names.
static const PCHAR DeviceTable[] = {
    "arc",
    "cpu",
    "fpu",
    "pic",
    "pdc",
    "sic",
    "sdc",
    "sc",
    "eisa",
    "tc",
    "scsi",
    "dti",
    "multi",
    "disk",
    "tape",
    "cdrom",
    "worm",
    "serial",
    "net",
    "video",
    "par",
    "point",
    "key",
    "audio",
    "other",
    "rdisk",
    "fdisk",
    "tape",
    "modem",
    "monitor",
    "print",
    "pointer",
    "keyboard",
    "term",
    "other",
    "line",
    "network",
    "system",
    "maximum",
    "partition"
};

static DEVICE_ENTRY Root;
static DEVICE_ENTRY Cpu;
static DEVICE_ENTRY Flipper;
static DEVICE_ENTRY Vegas;
static DEVICE_ENTRY Vi;
static DEVICE_ENTRY Broadway;

// USB mass storage
static DEVICE_ENTRY UsbDisk = {
    .Component = ARC_MAKE_COMPONENT(AdapterClass, ScsiAdapter, ARC_DEVICE_INPUT | ARC_DEVICE_OUTPUT, 0, 0),
    .Parent = &Root
};

// Dummy scsi adapter so setupldr asks for mass storage drivers on flipper systems
static char s_ScsiDummyIdentifier[] = "DUMMY";
static DEVICE_ENTRY ScsiDummy = {
    .Component = ARC_MAKE_COMPONENT(AdapterClass, ScsiAdapter, ARC_DEVICE_INPUT | ARC_DEVICE_OUTPUT, 1337, 0),
    .Parent = &Root
};



// Monitor
static DEVICE_ENTRY Monitor = {
    .Component = ARC_MAKE_COMPONENT(PeripheralClass, MonitorPeripheral, ARC_DEVICE_OUTPUT | ARC_DEVICE_CONSOLE_OUT, 0, 0),
    .Parent = &Vi,
    .Vectors = &MonitorVectors
};

static const ARC_RESOURCE_LIST(ViDesc,
    ARC_RESOURCE_DESCRIPTOR_INTERRUPT(CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE, 24),
    ARC_RESOURCE_DESCRIPTOR_PORT(CM_RESOURCE_PORT_MEMORY, 0x0C002000, 0x100)
);

// Video Interface
static DEVICE_ENTRY Vi = {
    .Component = ARC_MAKE_COMPONENT(ControllerClass, DisplayController, ARC_DEVICE_OUTPUT | ARC_DEVICE_CONSOLE_OUT, 0, sizeof(ViDesc)),
    .Parent = &Flipper,
    .Child = &Monitor,
    .ConfigData = &ViDesc.Header,
};

// Keyboard (put this under Flipper despite it could be on Vegas USB too, NT doesn't care)
static DEVICE_ENTRY Keyboard = {
    .Component = ARC_MAKE_COMPONENT(PeripheralClass, KeyboardPeripheral, ARC_DEVICE_INPUT | ARC_DEVICE_CONSOLE_IN, 0, 0),
    .Parent = &Flipper,
    .Peer = &Vi,
    .Vectors = &KeyboardVectors
};

// Disk or CDROM controllers (SD/IDE on EXI bus) go directly underneath Flipper. (Same for "floppy drives" aka drivers.img on those devices)
// Format would be disk(exi_disk_index) or cdrom(exi_disk_index) followed by peripheral(image_on_disK)

// We need some valid bus for some NT driver classes to work at all.
// VME bus is allowed here, and nothing actually uses it. Perfect for us :)
static char s_FlipperBusIdentifier[] = "VME";

// Flipper components (at physical address 0C00_0000)
static DEVICE_ENTRY Flipper = {
    .Component = ARC_MAKE_COMPONENT(AdapterClass, MultiFunctionAdapter, ARC_DEVICE_NONE, 0, 0),
    .Parent = &Root,
    .Peer = &Vegas,
    .Child = &Keyboard
};

// Vegas descriptors (IPC interrupt/mem-area/mmio, etc)
static ARC_RESOURCE_LIST(VegasDesc,
    ARC_RESOURCE_DESCRIPTOR_INTERRUPT(CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE, 27), // IOP IPC interrupt
    ARC_RESOURCE_DESCRIPTOR_PORT(CM_RESOURCE_PORT_MEMORY, 0x0D000000, 0x10), // IPC memory-mapped IO
    ARC_RESOURCE_DESCRIPTOR_PORT(CM_RESOURCE_PORT_MEMORY, 0x133E0000, 0x2000), // IPC buffers. Needs patching at runtime, this is the expected area where IOS uses 12MB.
);

// Vegas components (at physical address 0D00_0000)
// This includes IOS IPC, as IOP (Starlet) is part of Vegas.
static DEVICE_ENTRY Vegas = {
    .Component = ARC_MAKE_COMPONENT(AdapterClass, MultiFunctionAdapter, ARC_DEVICE_NONE, 1, sizeof(VegasDesc)),
    .Parent = &Root,
    .Peer = &UsbDisk,
    .ConfigData = &VegasDesc.Header
};

// PPC750 caches.
// For caches, Key definition
// bit 0-15: log2(cache size in 4K pages)
// bit 16-23: log2(line size in bytes/tag)
// bit 24-31: number of cache lines transferred in a cache refill
static DEVICE_ENTRY L2Cache = {
    .Component = ARC_MAKE_COMPONENT(CacheClass, SecondaryCache, ARC_DEVICE_NONE, 0x1060006, 0),
    .Parent = &Cpu,
};
static DEVICE_ENTRY Dcache = {
    .Component = ARC_MAKE_COMPONENT(CacheClass, PrimaryDcache, ARC_DEVICE_NONE, 0x1060003, 0),
    .Parent = &Cpu,
    .Peer = &L2Cache
};
static DEVICE_ENTRY Icache = {
    .Component = ARC_MAKE_COMPONENT(CacheClass, PrimaryIcache, ARC_DEVICE_NONE, 0x1060003, 0),
    .Parent = &Cpu,
    .Peer = &Dcache
};

static const char s_GekkoIdentifier[] = "Gekko";
static const char s_BroadwayIdentifier[] = "Broadway";
static const char s_EspressoIdentifier[] = "Espresso";

// CPU
// We have to use 613 here for NT-related reasons, this is the preliminary name of the 750.
static DEVICE_ENTRY Cpu = {
    .Component = ARC_MAKE_COMPONENT(ProcessorClass, CentralProcessor, ARC_DEVICE_NONE, 613, 0),
    .Parent = &Root,
    .Child = &Icache,
    .Peer = &Flipper,
};

static const char s_RootIdentifierFlipper[] = "Nintendo GameCube";
static const char s_RootIdentifierVegas[] = "Nintendo Wii";
static const char s_RootIdentifierLatte[] = "Nintendo Wii U";

// Root
static DEVICE_ENTRY Root = {
    .Component = ARC_MAKE_COMPONENT(SystemClass, ArcSystem, ARC_DEVICE_NONE, 0, 0),
    .Child = &Cpu
};

// BUGBUG: If extra default components are added, add them to this list.
static PDEVICE_ENTRY s_DefaultComponents[] = {
    // Root
    &Root,

    // First level
    &Cpu,
    &Flipper,
    &Vegas,
    &UsbDisk,
    &ScsiDummy,

    // Cpu
    &Icache,
    &Dcache,
    &L2Cache,

    // Flipper
    &Keyboard,
    &Vi,

    // Video
    &Monitor,
    
    // Vegas
    // (nothing under vegas by default)
};

// Space for additional components.
static DEVICE_ENTRY g_AdditionalComponents[MAXIMUM_DEVICE_COUNT] = { 0 };
static BYTE g_ConfigurationDataBuffer[MAXIMUM_DEVICE_COUNT * 0x100] = {0};
static ULONG g_AdditionalComponentsCount = 0;
static ULONG g_ConfigurationDataOffset = 0;
_Static_assert(sizeof(DEVICE_ENTRY) < 0x100);

// Config functions implementation.

static bool DeviceEntryIsValidImpl(PCONFIGURATION_COMPONENT Component, PULONG Index) {
    bool ValueForDefault = true;
    if (Index != NULL) {
        *Index = -1;
        ValueForDefault = false;
    }
    if (Component == NULL) return false;
    // Must be a default component, or a used additional component.
    PDEVICE_ENTRY Entry = (PDEVICE_ENTRY)Component;
    for (ULONG def = 0; def < sizeof(s_DefaultComponents) / sizeof(s_DefaultComponents[0]); def++) {
        if (Entry == s_DefaultComponents[def]) return ValueForDefault;
    }

    for (ULONG i = 0; i < g_AdditionalComponentsCount; i++) {
        if (Entry == &g_AdditionalComponents[i]) {
            if (Index != NULL) *Index = i;
            return true;
        }
    }

    return false;
}

static bool DeviceEntryIsValid(PCONFIGURATION_COMPONENT Component) {
    return DeviceEntryIsValidImpl(Component, NULL);
}

static bool DeviceEntryIsValidForDelete(PCONFIGURATION_COMPONENT Component, PULONG Index) {
    return DeviceEntryIsValidImpl(Component, Index);
}

/// <summary>
/// Add a new component entry as a child of Component.
/// </summary>
/// <param name="Component">Parent component which will be added to.</param>
/// <param name="NewComponent">Child component to add.</param>
/// <param name="ConfigurationData">Resource list of the child component.</param>
/// <returns></returns>
static PCONFIGURATION_COMPONENT ArcAddChild(
    IN PCONFIGURATION_COMPONENT Component,
    IN PCONFIGURATION_COMPONENT NewComponent,
    IN PVOID ConfigurationData OPTIONAL
) {
    // Component must be valid.
    // Other implementations allow to replace the root component entirely.
    // We do not.
    if (Component == NULL) return NULL;
    if (!DeviceEntryIsValid(Component)) return NULL;

    // Ensure there's enough space to allocate an additional component.
    if (g_AdditionalComponentsCount >= sizeof(g_AdditionalComponents) / sizeof(g_AdditionalComponents[0])) return NULL;

    ULONG ConfigDataLength = NewComponent->ConfigurationDataLength;
    if (ConfigurationData == NULL) ConfigDataLength = 0;

    // ...and for the configuration data
    if (g_ConfigurationDataOffset + ConfigDataLength >= sizeof(g_ConfigurationDataBuffer)) return NULL;

    // Allocate the device entry.
    PDEVICE_ENTRY Entry = &g_AdditionalComponents[g_AdditionalComponentsCount];
    g_AdditionalComponentsCount++;

    // Copy the new component to the list.
    Entry->Component = *NewComponent;

    // If no config data was specified, ensure the length is zero.
    if (ConfigurationData == NULL) Entry->Component.ConfigurationDataLength = 0;

    // Set the parent.
    Entry->Parent = (PDEVICE_ENTRY)Component;

    // Copy the configuration data.
    if (ConfigDataLength != 0) {
        Entry->ConfigData = (PCM_PARTIAL_RESOURCE_LIST_HEADER)&g_ConfigurationDataBuffer[g_ConfigurationDataOffset];
        memcpy(Entry->ConfigData, ConfigurationData, ConfigDataLength);
        g_ConfigurationDataOffset += ConfigDataLength;
    }

    // Set the new entry as last child of parent.
    PDEVICE_ENTRY Parent = (PDEVICE_ENTRY)Component;
    if (Parent->Child == NULL) Parent->Child = Entry;
    else {
        PDEVICE_ENTRY This = Parent->Child;
        for (; This->Peer != NULL; This = This->Peer) {}
        This->Peer = Entry;
    }

    // All done.
    return &Entry->Component;
}

/// <summary>
/// Deletes a component entry. Can not delete an entry with children, or an entry that wasn't added by AddChild.
/// </summary>
/// <param name="Component">Component to delete</param>
/// <returns>ARC status code.</returns>
static ARC_STATUS ArcDeleteComponent(IN PCONFIGURATION_COMPONENT Component) {
    ULONG ComponentIndex;
    if (!DeviceEntryIsValidForDelete(Component, &ComponentIndex)) return _EINVAL;

    PDEVICE_ENTRY Entry = &g_AdditionalComponents[ComponentIndex];
    if (Entry->Parent == NULL) return _EINVAL;
    if (Entry->Child != NULL) return _EACCES;

    // Get the parent.
    PDEVICE_ENTRY Parent = Entry->Parent;

    // Point the child to Component's peer.
    if (Parent->Child == Entry) Parent->Child = Entry->Peer;
    else {
        PDEVICE_ENTRY This = Parent->Child;
        for (; This->Peer != Entry; This = This->Peer) {}
        This->Peer = Entry->Peer;
    }

    // Zero out the parent to remove the entry from the component hierarchy.
    Entry->Parent = NULL;

    return _ESUCCESS;
}

/// <summary>
/// Parses the next part of an ARC device path.
/// </summary>
/// <param name="pPath">Pointer to the part of the string to parse. On function success, pointer is advanced past the part that was parsed.</param>
/// <param name="ExpectedType">The device type that is expected to be parsed.</param>
/// <param name="Key">On function success, returns the parsed key from the string.</param>
/// <returns>True if parsing succeeded, false if it failed.</returns>
bool ArcDeviceParse(PCHAR* pPath, CONFIGURATION_TYPE ExpectedType, ULONG* Key) {
    PCHAR ExpectedString = DeviceTable[ExpectedType];

    // Ensure *pPath == ExpectedString (case-insensitive)
    PCHAR Path = *pPath;
    while (*ExpectedString != 0) {
        CHAR This = *Path | 0x20;
        //if (This < 'a' || This > 'z') return false;
        if (This != *ExpectedString) return false;
        ExpectedString++;
        Path++;
    }

    // Next char must be '('
    if (*Path != '(') return false;
    Path++;

    // Digits followed by ')'
    ULONG ParsedKey = 0;
    while (*Path != ')' && *Path != 0) {
        CHAR This = *Path;
        if (This < '0' || This > '9') return false;
        ParsedKey *= 10;
        ParsedKey += (This - '0');
        Path++;
    }
    if (*Path != ')') return false;
    Path++;

    // Success
    *pPath = Path;
    *Key = ParsedKey;
    return true;
}

/// <summary>
/// For an ARC device, get its ARC path.
/// </summary>
/// <param name="Component">ARC component</param>
/// <param name="Path">Buffer to write path to</param>
/// <param name="Length">Length of buffer</param>
/// <returns>Length written without null terminator</returns>
ULONG ArcDeviceGetPath(PCONFIGURATION_COMPONENT Component, PCHAR Path, ULONG Length) {
    PDEVICE_ENTRY This = (PDEVICE_ENTRY)Component;

    ULONG Offset = 0;
    // Recurse for each element.
    if (This->Parent != NULL && This->Parent != &Root) {
        Offset = ArcDeviceGetPath(&This->Parent->Component, Path, Length);
        if (Offset == 0) return 0;
    }

    if (Offset > Length) return 0;

    int Ret = snprintf(&Path[Offset], Length - Offset, "%s(%u)", DeviceTable[This->Component.Type], This->Component.Key);
    if (Ret < 0) return 0;
    if (Ret >= (Length - Offset)) return 0;
    return Offset + Ret;
}

static bool IsDevice(PDEVICE_ENTRY This, PCHAR* pPath) {
    // Initialise the key to zero.
    ULONG Key = 0;
    // Get the path string parsed in, don't update the pointer on a failure.
    PCHAR Path = *pPath;

    // Try to parse this part of the device string, by this device entry's type.
    // If it failed, this isn't the device being looked for.
    if (!ArcDeviceParse(&Path, This->Component.Type, &Key)) return false;

    // Ensure provided key matches the component's
    if (Key != This->Component.Key) return false;

    // Success
    *pPath = Path;
    return true;
}

/// <summary>
/// Obtains a component from an ARC path string. Returns the best component that can be found in the hierarchy.
/// </summary>
/// <param name="PathName">Path name to search</param>
/// <returns>Found component</returns>
static PCONFIGURATION_COMPONENT ArcGetComponent(IN PCHAR PathName) {
    // Get the root component.
    PDEVICE_ENTRY Match = &Root;

    // Keep searching until there are no more entries.
    PCHAR Pointer = PathName;
    while (*Pointer != 0) {
        // Search each child.
        PDEVICE_ENTRY This;
        for (This = Match->Child; This != NULL; This = This->Peer) {
            if (IsDevice(This, &Pointer)) {
                Match = This;
                break;
            }
        }

        if (This == NULL) break;
    }

    if (Match == &Root) {
        // The match that was found is the root.
        // Only match on that if caller really wanted it.
        Pointer = PathName;
        ULONG Key;
        if (!ArcDeviceParse(&Pointer, ArcSystem, &Key)) return NULL;
    }
    return &Match->Component;
}

/// <summary>
/// Gets the child of the current component
/// </summary>
/// <param name="Component">Component to obtain the child of. If null, obtains the root component.</param>
/// <returns>Component</returns>
static PCONFIGURATION_COMPONENT ArcGetChild(IN PCONFIGURATION_COMPONENT Component OPTIONAL) {
    if (Component == NULL) return &Root.Component;
    if (!DeviceEntryIsValid(Component)) return NULL;
    PDEVICE_ENTRY Child = ((PDEVICE_ENTRY)Component)->Child;
    if (Child == NULL) return NULL;
    return &Child->Component;
}

/// <summary>
/// Gets the parent of the current component
/// </summary>
/// <param name="Component">Component to obtain the parent of.</param>
/// <returns>Parent component</returns>
static PCONFIGURATION_COMPONENT ArcGetParent(IN PCONFIGURATION_COMPONENT Component) {
    if (Component == NULL) return NULL;
    if (!DeviceEntryIsValid(Component)) return NULL;
    PDEVICE_ENTRY Parent = ((PDEVICE_ENTRY)Component)->Parent;
    if (Parent == NULL) return NULL;
    return &Parent->Component;
}

/// <summary>
/// Gets the peer of the current component
/// </summary>
/// <param name="Component">Component to obtain the peer of.</param>
/// <returns>Peer component</returns>
static PCONFIGURATION_COMPONENT ArcGetPeer(IN PCONFIGURATION_COMPONENT Component) {
    if (Component == NULL) return NULL;
    if (!DeviceEntryIsValid(Component)) return NULL;
    PDEVICE_ENTRY Peer = ((PDEVICE_ENTRY)Component)->Peer;
    if (Peer == NULL) return NULL;
    return &Peer->Component;
}

/// <summary>
/// Gets the configuration data of the current component
/// </summary>
/// <param name="ConfigurationData">Buffer to write the configuration data into</param>
/// <param name="Component">Component to obtain the configuration data of</param>
/// <returns>ARC status value</returns>
static ARC_STATUS ArcGetData(OUT PVOID ConfigurationData, IN PCONFIGURATION_COMPONENT Component) {
    if (!DeviceEntryIsValid(Component)) return _EINVAL;

    PDEVICE_ENTRY Device = (PDEVICE_ENTRY)Component;
    memcpy(ConfigurationData, Device->ConfigData, Device->Component.ConfigurationDataLength);
    return _ESUCCESS;
}

static ARC_STATUS ArcSaveConfiguration(void) {
    // No operation.
    return _ESUCCESS;
}

static ARC_DISPLAY_STATUS s_DisplayStatus = { 0 };
static PARC_DISPLAY_STATUS ArcGetDisplayStatus(ULONG FileId) {
    ArcConsoleGetStatus(&s_DisplayStatus);
    return &s_DisplayStatus;
}

static ARC_STATUS ArcTestUnicodeCharacter(ULONG FileId, WCHAR UnicodeCharacter) {
    if ((UnicodeCharacter >= ' ') && (UnicodeCharacter <= '~')) return _ESUCCESS;
    return _EINVAL;
}

static SYSTEM_ID s_SystemId = { 0 };
static char s_VendorId[] = "ArtX";
static char s_UnknownProductIdFlipper[] = "Flipper";
static char s_UnknownProductIdVegas[] = "Vegas";
static char s_UnknownProductIdLatte[] = "Latte";
_Static_assert(sizeof(s_VendorId) <= sizeof(s_SystemId.VendorId));
static PSYSTEM_ID ArcGetSystemId(void) {
    return &s_SystemId;
}

#define CONSOLE_WRITE_CONST(str) ArcConsoleWrite((str), sizeof(str) - 1)

static ULONG s_PrintTreeCount = 0;

static void ArcPrintDevice(PDEVICE_ENTRY Device) {
    char ArcPath[1024];
    if (ArcDeviceGetPath(&Device->Component, ArcPath, sizeof(ArcPath)) == 0) {
        printf("unknown device at %08x\r\n", Device);
    }
    else {
        printf("%s\r\n", ArcPath);
    }
    if (s_PrintTreeCount != 0 && (s_PrintTreeCount & 0x1f) == 0) IOSKBD_ReadChar();
    s_PrintTreeCount++;
}

static void ArcPrintTreeImpl(PDEVICE_ENTRY Device) {
    if (Device == NULL) return;

    for (PDEVICE_ENTRY Child = (PDEVICE_ENTRY)ArcGetChild(&Device->Component); Child != NULL; Child = (PDEVICE_ENTRY)ArcGetChild(&Child->Component)) {
        ArcPrintDevice(Child);
        for (PDEVICE_ENTRY This = (PDEVICE_ENTRY)ArcGetPeer(&Child->Component); This != NULL; This = (PDEVICE_ENTRY)ArcGetPeer(&This->Component)) {
            ArcPrintDevice(This);
            if (This->Child != NULL) ArcPrintTreeImpl(This);
        }
    }
}

void ArcPrintTree(PDEVICE_ENTRY Device) {
    s_PrintTreeCount = 0;
    ArcPrintTreeImpl(Device);
}

static bool ArcConfigKeyEquals(PDEVICE_ENTRY Lhs, PDEVICE_ENTRY Rhs) {
    return (
        (Lhs->Parent == Rhs->Parent) &&
        (Lhs->Component.Type == Rhs->Component.Type) &&
        (Lhs->Component.Class == Rhs->Component.Class) &&
        (Lhs->Component.Key == Rhs->Component.Key)
        );
}

bool ArcConfigKeyExists(PDEVICE_ENTRY Device) {
    for (ULONG def = 0; def < sizeof(s_DefaultComponents) / sizeof(s_DefaultComponents[0]); def++) {
        PDEVICE_ENTRY This = s_DefaultComponents[def];
        if (This == Device) continue;
        if (!ArcConfigKeyEquals(Device, This)) continue;
        return true;
    }

    for (ULONG i = 0; i < g_AdditionalComponentsCount; i++) {
        PDEVICE_ENTRY This = &g_AdditionalComponents[i];
        if (This == Device) continue;
        if (!ArcConfigKeyEquals(Device, This)) continue;
        return true;
    }
    return false;
}

void ArcConfigInit(void) {
    // Initialise vectors.
    PVENDOR_VECTOR_TABLE Api = ARC_VENDOR_VECTORS();
    Api->AddChildRoutine = ArcAddChild;
    Api->DeleteComponentRoutine = ArcDeleteComponent;
    Api->GetComponentRoutine = ArcGetComponent;
    Api->GetChildRoutine = ArcGetChild;
    Api->GetParentRoutine = ArcGetParent;
    Api->GetPeerRoutine = ArcGetPeer;
    Api->GetDataRoutine = ArcGetData;
    Api->SaveConfigurationRoutine = ArcSaveConfiguration;
    Api->GetDisplayStatusRoutine = ArcGetDisplayStatus;
    Api->GetSystemIdRoutine = ArcGetSystemId;
    Api->TestUnicodeCharacterRoutine = ArcTestUnicodeCharacter;

    // Initialise the System ID structure.
    memset(&s_SystemId, 0, sizeof(s_SystemId));
    memcpy(&s_SystemId.VendorId, s_VendorId, sizeof(s_VendorId));
    ARTX_SYSTEM_TYPE SystemType = (ARTX_SYSTEM_TYPE)s_RuntimePointers[RUNTIME_SYSTEM_TYPE].v;
    switch (SystemType) {
    case ARTX_SYSTEM_FLIPPER:
        memcpy(&s_SystemId.ProductId, s_UnknownProductIdFlipper, sizeof(s_UnknownProductIdFlipper));
        break;
    case ARTX_SYSTEM_VEGAS:
        memcpy(&s_SystemId.ProductId, s_UnknownProductIdVegas, sizeof(s_UnknownProductIdVegas));
        break;
    case ARTX_SYSTEM_LATTE:
        memcpy(&s_SystemId.ProductId, s_UnknownProductIdLatte, sizeof(s_UnknownProductIdLatte));
        break;
    }
    

    // Initialise environment variables.
    ArcEnvSetVarInMem("CONSOLEIN", KeyboardPath);
    ArcEnvSetVarInMem("CONSOLEOUT", MonitorPath);

    // Set up the display controller identifier, used by setupldr
    Vi.Component.Identifier = (size_t)s_DisplayIdentifier;
    Vi.Component.IdentifierLength = sizeof(s_DisplayIdentifier);

    // Set up the Flipper "bus" identifier, used by NT kernel
    Flipper.Component.Identifier = (size_t)s_FlipperBusIdentifier;
    Flipper.Component.IdentifierLength = sizeof(s_FlipperBusIdentifier);

    // Set up the IOS IPC memory range.
    extern ULONG s_MacIoStart;
    VegasDesc.Descriptors[2].Memory.Start.LowPart = s_RuntimeIpc.PointerArc;
    VegasDesc.Descriptors[2].Memory.Length = s_RuntimeIpc.PointerArc;


    // Set up the CPU identifier, if this is missing smss will terminate STATUS_OBJECT_NAME_NOT_FOUND
    // Get the pvr to determine the processor.
    ULONG Pvr;
    __asm__ __volatile__ ("mfpvr %0" : "=r"(Pvr));
    ULONG PvrUpper = Pvr >> 16;
    ULONG PvrLower = Pvr & 0xFFFF;

    if (PvrUpper == 0x7001) {
        // Espresso
        Cpu.Component.Identifier = (size_t)s_EspressoIdentifier;
        Cpu.Component.IdentifierLength = sizeof(s_EspressoIdentifier);
    }
    else if (PvrUpper == 0x7000) {
        // Gekko prototypes
        Cpu.Component.Identifier = (size_t)s_GekkoIdentifier;
        Cpu.Component.IdentifierLength = sizeof(s_GekkoIdentifier);
    }
    else if (PvrUpper != 8) {
        // ??? assume this is gekko
        Cpu.Component.Identifier = (size_t)s_GekkoIdentifier;
        Cpu.Component.IdentifierLength = sizeof(s_GekkoIdentifier);
    }
    else if (PvrLower >= 0x7000) {
        // Broadway
        Cpu.Component.Identifier = (size_t)s_BroadwayIdentifier;
        Cpu.Component.IdentifierLength = sizeof(s_BroadwayIdentifier);
    }
    else {
        // Gekko
        Cpu.Component.Identifier = (size_t)s_GekkoIdentifier;
        Cpu.Component.IdentifierLength = sizeof(s_GekkoIdentifier);
    }

    // Set up the system / chipset identifier
    switch (SystemType) {
    case ARTX_SYSTEM_FLIPPER:
        Root.Component.Identifier = (size_t)s_RootIdentifierFlipper;
        Root.Component.IdentifierLength = sizeof(s_RootIdentifierFlipper);
        break;
    case ARTX_SYSTEM_VEGAS:
        Root.Component.Identifier = (size_t)s_RootIdentifierVegas;
        Root.Component.IdentifierLength = sizeof(s_RootIdentifierVegas);
        break;
    case ARTX_SYSTEM_LATTE:
        Root.Component.Identifier = (size_t)s_RootIdentifierLatte;
        Root.Component.IdentifierLength = sizeof(s_RootIdentifierLatte);
        break;
    }

    // Fix up the device tree for flipper
    if (SystemType == ARTX_SYSTEM_FLIPPER) {
        // Remove vegas from the device tree, this also cuts off usb (placed after vegas)
        // Instead, add the dummy scsi adapter
        Flipper.Peer = &ScsiDummy;
        ScsiDummy.Component.Identifier = (size_t)s_ScsiDummyIdentifier;
        ScsiDummy.Component.IdentifierLength = sizeof(s_ScsiDummyIdentifier);
    }
}

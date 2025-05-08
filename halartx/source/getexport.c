#define DEVL 1
#include <windef.h>
#include <winnt.h>

PVOID PeGetExportWithDirectory(PVOID ImageBase, PIMAGE_EXPORT_DIRECTORY Export, const char* ExportName) {
	PVOID Ret = NULL;
	
	ULONG Va = (ULONG)Export - (ULONG)ImageBase;
	
	BOOLEAN LookUpName = TRUE;
	USHORT Ordinal = 0;
	if (((ULONG)ExportName & 0xffff0000) == 0) {
		LookUpName = FALSE;
		Ordinal = (USHORT)(ULONG)ExportName;
	}
	
	if (LookUpName) {
		PULONG AddressOfNames = (PULONG)((ULONG)ImageBase + (ULONG)Export->AddressOfNames);
		PUSHORT AddressOfNameOrdinals = (PUSHORT)((ULONG)ImageBase + (ULONG)Export->AddressOfNameOrdinals);
		for (ULONG i = 0; i < Export->NumberOfNames; i++) {
			const char* Name = (const char*)((ULONG)ImageBase + AddressOfNames[i]);
			if (!strcmp(Name, ExportName)) {
				Ordinal = AddressOfNameOrdinals[i];
				LookUpName = FALSE;
				break;
			}
		}
		if (LookUpName) return NULL;
	}
	
	PULONG AddressOfFunctions = (PULONG)((ULONG)ImageBase + (ULONG)Export->AddressOfFunctions);
	return (PVOID)((ULONG)ImageBase + AddressOfFunctions[Ordinal]);
}

PVOID PeGetExport(PVOID ImageBase, const char* ExportName) {
	PIMAGE_DOS_HEADER Mz = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS Pe = (PIMAGE_NT_HEADERS)((ULONG)ImageBase + Mz->e_lfanew);
	PIMAGE_DATA_DIRECTORY ExportDir = &Pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	PIMAGE_EXPORT_DIRECTORY Export = (PIMAGE_EXPORT_DIRECTORY) ((ULONG)ImageBase + ExportDir->VirtualAddress);
	
	return PeGetExportWithDirectory(ImageBase, Export, ExportName);
}
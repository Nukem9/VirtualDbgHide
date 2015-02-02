#pragma once

ULONG_PTR GetNtoskrnlBase();
ULONG_PTR GetSSDTBase();
ULONG_PTR GetSSDTEntry(ULONG TableIndex);
NTSTATUS GetSSDTIndex(ULONG_PTR ImageBase, SIZE_T ImageSize, const char *FunctionName, PUINT32 Index);

NTSTATUS RemoveProcessFromSysProcessInfo(PVOID SystemInformation, ULONG SystemInformationLength);
NTSTATUS RemoveDriverFromSysModuleInfo(PVOID SystemInformation, ULONG SystemInformationLength, PULONG OutLength);
NTSTATUS RemoveDebugObjectInfo(PVOID ObjectInformation, ULONG ObjectInformationLength);
NTSTATUS RemoveSingleDebugObjectInfo(OBJECT_TYPE_INFORMATION *Information);
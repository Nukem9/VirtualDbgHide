#pragma once

ULONG_PTR GetNtoskrnlBase();
ULONG_PTR GetSSDTBase();
ULONG_PTR GetSSDTEntry(ULONG TableIndex);

NTSTATUS RemoveDriverFromSysModuleInfo(PVOID SystemInformation, ULONG SystemInformationLength, PULONG OutLength);
NTSTATUS RemoveDebugObjectInfo(OBJECT_TYPE_INFORMATION *Information);
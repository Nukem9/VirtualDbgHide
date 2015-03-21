#include "stdafx.h"
#include "../Misc/Pe.h"

ULONG_PTR GetNtoskrnlBase()
{
	//
	// Query the buffer size needed to list all modules
	//
	ULONG modulesSize	= 0;
	NTSTATUS status		= AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);

	if (!NT_SUCCESS(status) || modulesSize == 0)
		return 0;

	//
	// Calculate the number of modules.
	//
	ULONG numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);

	//
	// Allocate memory to receive data.
	//
	PAUX_MODULE_EXTENDED_INFO modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(
		PagedPool,
		modulesSize,
		'KLIB'
		);

	if (!modules)
		return 0;

	RtlZeroMemory(modules, modulesSize);

	//
	// Obtain the module information.
	//
	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);

	if (!NT_SUCCESS(status))
		return 0;

	//
	// Enumerate all of the entries looking for NTOS*
	//
	for (ULONG i = 0; i < numberOfModules; i++)
	{
		char *fileName = (char *)&modules[i].FullPathName[modules[i].FileNameOffset];

		if (strstr(fileName, "ntoskrnl") ||
			strstr(fileName, "ntkrnlmp") ||
			strstr(fileName, "ntkrnlpa"))
			return (ULONG_PTR)modules[i].BasicInfo.ImageBase;
	}

	return 0;
}

ULONG_PTR GetSSDTBase()
{
	//
	// The SSDT is found by using the pointer located inside of
	// KeAddSystemServiceTable, which is exported by NTOSKRNL.
	//
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"KeAddSystemServiceTable");

	PVOID KeAddSystemServiceTable = MmGetSystemRoutineAddress(&routineName);

	if (!KeAddSystemServiceTable)
		return 0;

	//
	// Get a copy of the function's code
	//
	UCHAR functionData[1024];
	ULONG functionSize = 0;
	RtlCopyMemory(functionData, KeAddSystemServiceTable, sizeof(functionData));

	for (ULONG i = 0; i < sizeof(functionData); i++)
	{
		if (functionData[i] == 0xC3)
		{
			functionSize = i + 1;
			break;
		}
	}

	//
	// Will fail if 0xC3 (RETN) is never found
	//
	if (functionSize <= 0)
		return 0;

	//
	// Determine the SSDT RVA with a byte scan
	//
	ULONG rva = 0;

	for (ULONG i = 0; i < functionSize; i++)
	{
		//
		// 48 83 BC 18 80 4A 35 00 00       cmp qword ptr [rax+rbx+354A80h], 0
		//
		if (memcmp(&functionData[i], "\x48\x83\xBC", 3) == 0)
		{
			//
			// Verify the zero
			//
			if (functionData[i + 8] == 0x00)
			{
				rva = *(ULONG *)&functionData[i + 4];
				break;
			}
		}
	}

	//
	// NtosnkrlBase + RVA = SSDT address
	//
	ULONG_PTR ssdtAddress = NtKernelBase + rva;

	//
	// Also check validity
	//
	if (!MmIsAddressValid((PVOID)ssdtAddress))
		return 0;

	return ssdtAddress;
}

ULONG_PTR GetSSDTEntry(ULONG TableIndex)
{
	PKSERVICE_TABLE_DESCRIPTOR ssdt = (PKSERVICE_TABLE_DESCRIPTOR)NtKernelSSDT;

#ifdef _WIN64
	// SSDT pointers are relative to the base in X64
	ULONG_PTR entry = (ULONG_PTR)ssdt->ServiceTable + (ssdt->ServiceTable[TableIndex] >> 4);
#else
	// Otherwise it's 32-bit and a direct pointer
	ULONG_PTR entry = (ULONG_PTR)ssdt->ServiceTable[TableIndex];
#endif

	//
	// Verify address
	//
	if (!MmIsAddressValid((PVOID)entry))
	{
		DbgPrint("FAILED INDEX IN GetSSDTEntry: 0x%X - 0x%p\n", TableIndex, entry);
		return 0;
	}

	return entry;
}

NTSTATUS GetSSDTIndex(ULONG_PTR ImageBase, SIZE_T ImageSize, const char *FunctionName, PUINT32 Index)
{
	//
	// First get the exported function in the module
	//
	ULONG_PTR function = PeGetExportOffset(ImageBase, ImageSize, FunctionName);

	if (function == PE_ERROR_VALUE)
		return STATUS_NOT_FOUND;

	//
	// Trace the assembly
	// 8B XX XX XX XX		MOV EAX, XXXXXXXX
	// 0F 05				SYSCALL
	// 0F 34				SYSENTER
	// C2/C3				RET(N)
	//
	for (PUCHAR i = (PUCHAR)function; i < (PUCHAR)(function + 32); i++)
	{
		switch (i[0])
		{
		//
		// MOV EAX -> hit, copy the next 4 bytes
		//
		case 0xB8:
			*Index = (*(UINT32 *)&i[1]);
			return STATUS_SUCCESS;

		//
		// SYS* -> error, exit function
		//
		case 0x0F:
			if (i[1] == 0x05 || i[1] == 0x34)
				return STATUS_NOT_FOUND;
			continue;

		//
		// RET(N) -> error, exit function
		//
		case 0xC2:
		case 0xC3:
			return STATUS_NOT_FOUND;
		}
	}

	return STATUS_NOT_FOUND;
}

#define IS_IN_BOUNDS(var, start, size) (((ULONG_PTR)(var)) < ((ULONG_PTR)start + (size)))

NTSTATUS RemoveProcessFromSysProcessInfo(PVOID SystemInformation, ULONG SystemInformationLength)
{
	//
	// Check the size of the base container
	//
	if (SystemInformationLength < sizeof(SYSTEM_PROCESS_INFORMATION))
		return STATUS_INFO_LENGTH_MISMATCH;

	//
	// Get a pointer to the modules and loop each index
	//
	PSYSTEM_PROCESS_INFORMATION moduleInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

	PSYSTEM_PROCESS_INFORMATION prevPointer = NULL;
	PSYSTEM_PROCESS_INFORMATION currPointer = NULL;
	PSYSTEM_PROCESS_INFORMATION nextPointer = NULL;

	for (;;)
	{
		//
		// Does this process match?
		//
		if (moduleInfo->ProcessId == (HANDLE)3108)
			currPointer = moduleInfo;

		//
		// Validate pointer
		//
		if (moduleInfo->NextEntryOffset == 0)
			break;

		ULONG_PTR nextIndex = (ULONG_PTR)moduleInfo + moduleInfo->NextEntryOffset;
		ULONG_PTR maxOffset = (ULONG_PTR)FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION, ParentProcessId);

		if (!IS_IN_BOUNDS(nextIndex + maxOffset, SystemInformation, SystemInformationLength))
			break;

		//
		// If this flag was set, get the next pointer in the list and exit
		//
		if (currPointer)
		{
			nextPointer = (PSYSTEM_PROCESS_INFORMATION)nextIndex;
			break;
		}

		//
		// Move to next index
		//
		prevPointer = moduleInfo;
		moduleInfo	= (PSYSTEM_PROCESS_INFORMATION)nextIndex;
	}

	if (!currPointer)
		return STATUS_NOT_FOUND;

	//
	// Was there a previous pointer?
	//
	if (prevPointer)
	{
		//
		// Link it to the next, or set it to 0
		//
		if (nextPointer)
			prevPointer->NextEntryOffset = (ULONG)((ULONG_PTR)nextPointer - (ULONG_PTR)prevPointer);
		else
			prevPointer->NextEntryOffset = 0;
	}

	//
	// Calculate the size of the target entry and zero it
	//
	SIZE_T zeroLength = 0;

	if (nextPointer)
	{
		//
		// There was another entry after this, so determine
		// the delta between them
		//
		zeroLength = (ULONG_PTR)nextPointer - (ULONG_PTR)currPointer;
	}
	else
	{
		//
		// Data is from 'currPointer' to SystemInformation buffer end
		//
		zeroLength = ((ULONG_PTR)SystemInformation + SystemInformationLength) - (ULONG_PTR)currPointer;
	}

	RtlSecureZeroMemory(currPointer, zeroLength);
	return STATUS_SUCCESS;
}

NTSTATUS RemoveDriverFromSysModuleInfo(PVOID SystemInformation, ULONG SystemInformationLength, PULONG OutLength)
{
	//
	// Subtract the size of the base container
	//
	if (SystemInformationLength <= sizeof(SYSTEM_MODULE_INFORMATION))
		return STATUS_INFO_LENGTH_MISMATCH;

	SystemInformationLength -= sizeof(SYSTEM_MODULE_INFORMATION);

	//
	// Determine the SYSTEM_MODULE count
	//
	ULONG entryCount = SystemInformationLength / sizeof(SYSTEM_MODULE);

	//
	// Get a pointer to the modules and loop each index
	//
	PSYSTEM_MODULE_INFORMATION moduleInfo = (PSYSTEM_MODULE_INFORMATION)SystemInformation;

	PSYSTEM_MODULE startPointer = NULL;
	PSYSTEM_MODULE copyPointer	= NULL;
	ULONG remainderBytes		= 0;

	for (ULONG i = 0; i < entryCount; i++)
	{
		if (moduleInfo->Modules[i].ImageBase == (PVOID)0xfffff80010834000) // FIXME
		{
			startPointer	= &moduleInfo->Modules[i];
			copyPointer		= &moduleInfo->Modules[i + 1];
			remainderBytes	= (entryCount - (i + 1)) * sizeof(SYSTEM_MODULE);

			break;
		}
	}

	if (!startPointer || !copyPointer)
		return STATUS_NOT_FOUND;

	//
	// Overwrite the data for this driver and fix up variables
	//
	ULONG modifiedLength = (SystemInformationLength - sizeof(SYSTEM_MODULE));

	if (remainderBytes > 0)
		RtlMoveMemory(startPointer, copyPointer, remainderBytes);

	//
	// Zero the end to prevent leaking any data
	//
	RtlSecureZeroMemory((PUCHAR)SystemInformation + modifiedLength, sizeof(SYSTEM_MODULE));

	//
	// Fix the output parameter and internal struct counter
	//
	if (OutLength)
		*OutLength = modifiedLength;

	moduleInfo->ModulesCount -= 1;
	return STATUS_SUCCESS;
}

NTSTATUS RemoveDebugObjectInfo(PVOID ObjectInformation, ULONG ObjectInformationLength)
{
	//
	// Validate the size of the base container
	//
	if (ObjectInformationLength < (sizeof(OBJECT_ALL_TYPES_INFORMATION) + sizeof(OBJECT_TYPE_INFORMATION)))
		return STATUS_INFO_LENGTH_MISMATCH;

	//
	// Enumerate all entries
	//
	POBJECT_ALL_TYPES_INFORMATION typesInfo = (POBJECT_ALL_TYPES_INFORMATION)ObjectInformation;
	POBJECT_TYPE_INFORMATION typeInfo		= typesInfo->TypeInformation;

	for (ULONG i = 0; i < typesInfo->NumberOfTypes; i++)
	{
		//
		// Should this entry be faked?
		//
		if (NT_SUCCESS(RemoveSingleDebugObjectInfo(typeInfo)))
			return STATUS_SUCCESS;

		//
		// Validate the pointer first (Aligned to 0x4)
		//
		ULONG_PTR nextType = ((ULONG_PTR)typeInfo->Name.Buffer + typeInfo->Name.Length) & 0xFFFFFFFC;

		if (nextType >= ((ULONG_PTR)ObjectInformation + ObjectInformationLength))
			break;

		//
		// Increment the loop
		//
		typeInfo = (POBJECT_TYPE_INFORMATION)nextType;
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS RemoveSingleDebugObjectInfo(OBJECT_TYPE_INFORMATION *Information)
{
	//
	// Does the object type information name match "DebugObject"?
	//
	if (RtlEqualUnicodeString(&Information->Name, &Nt::DebugObjectName, FALSE))
	{
		Information->TotalNumberOfObjects = 0;
		Information->TotalNumberOfHandles = 0;

		return STATUS_SUCCESS;
	}

	return STATUS_NOT_FOUND;
}
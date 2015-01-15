#include "stdafx.h"

//
// Every function in this file is called from usermode because of
// SYSCALL/SYSENTER. Zw* functions never reach here.
//

NTSTATUS(NTAPI * NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
NTSTATUS(NTAPI * NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

volatile ULONG64 numCalls = 0;

NTSTATUS NTAPI hk_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
{
	numCalls++;

	//	if (numCalls % 1000 == 0)
	//		DbgLog("NtReadVirtualMemory - 0x%p 0x%p 0x%p 0x%p 0x%p\n", ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);

	return NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}

NTSTATUS NTAPI hk_NtClose(HANDLE Handle)
{
	PVOID object = NULL;
	NTSTATUS status = ObReferenceObjectByHandle(Handle, 0, NULL, UserMode, &object, NULL);

	//
	// This will fail with an invalid handle
	//
	if (!NT_SUCCESS(status))
		return STATUS_INVALID_HANDLE;

	//
	// Continue execution normally
	//
	ObDereferenceObject(object);
	return NtClose(Handle);
}

NTSTATUS NTAPI RemoveDriverFromList(PVOID SystemInformation, ULONG SystemInformationLength, PULONG OutLength)
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
	PSYSTEM_MODULE copyPointer = NULL;
	ULONG remainderBytes = 0;

	for (ULONG i = 0; i < entryCount; i++)
	{
		if (moduleInfo->Modules[i].ImageBase == (PVOID)0xfffff80010834000) // FIXME
		{
			startPointer = &moduleInfo->Modules[i];
			copyPointer = &moduleInfo->Modules[i + 1];
			remainderBytes = (entryCount - (i + 1)) * sizeof(SYSTEM_MODULE);

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
	RtlZeroMemory((PUCHAR)SystemInformation + modifiedLength, sizeof(SYSTEM_MODULE));

	//
	// Fix the output parameter and internal struct counter
	//
	if (OutLength)
		*OutLength = modifiedLength;

	moduleInfo->ModulesCount -= 1;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI hk_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS status = NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	//
	// Special case for SystemModuleInformation (11)
	//
	if (SystemInformationClass == SystemModuleInformation)
	{
		if (SystemInformation)
			RemoveDriverFromList(SystemInformation, SystemInformationLength, ReturnLength);

		//
		// ALWAYS subtract one SYSTEM_MODULE from the return length
		// if it is not null and SystemInformation is null
		//	
		if (!SystemInformation && ReturnLength && *ReturnLength >= sizeof(SYSTEM_MODULE))
			ReturnLength -= sizeof(SYSTEM_MODULE);
	}

	//
	// Did the first call succeed?
	//
	if (!NT_SUCCESS(status))
		return status;

	//
	// It did, so now modify any return values
	//
	if (SystemInformation && SystemInformationLength > 0)
	{
		if (SystemInformationClass == SystemKernelDebuggerInformation)
		{
			PSYSTEM_KERNEL_DEBUGGER_INFORMATION debugInfo = (PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation;

			debugInfo->DebuggerEnabled = FALSE;
			debugInfo->DebuggerNotPresent = TRUE;
		}
		else if (SystemInformationClass == SystemKernelDebuggerInformationEx)
		{
			PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX debugInfoEx = (PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation;

			debugInfoEx->BootedDebug = FALSE;
			debugInfoEx->DebuggerEnabled = FALSE;
			debugInfoEx->DebuggerPresent = FALSE;
		}
	}

	return status;
}
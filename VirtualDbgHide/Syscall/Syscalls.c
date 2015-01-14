#include "stdafx.h"

//
// Every function in this file is called from usermode because of
// SYSCALL/SYSENTER. Zw* functions never reach here.
//

NTSTATUS (NTAPI * NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
NTSTATUS (NTAPI * NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

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
	PVOID object	= NULL;
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

NTSTATUS NTAPI hk_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS status = NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	//
	// Did the first call succeed?
	//
	if (!NT_SUCCESS(status))
		return status;

	//
	// It did, so now modify any return values
	//
	if (SystemInformation)
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
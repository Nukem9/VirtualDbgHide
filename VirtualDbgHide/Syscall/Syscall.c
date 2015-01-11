#include "Driver.h"

ULONG64 NtSyscallHandler;
ULONG64 NtKernelBase;
ULONG64 GuestSyscallHandler;

// 1 = Hook, 0 = Disabled
CHAR SyscallHookEnabled[4096];
CHAR SyscallParamTable[4096];
PVOID SyscallPointerTable[4096];

#define IMAGE_DOS_SIGNATURE 0x5a4d

ULONG_PTR FindNtoskrnlBase(ULONG_PTR Addr)
{
	// Scan down from a given symbol’s address
	Addr = (Addr & ~0xfff);

	__try
	{
		while ((*(USHORT *)Addr != IMAGE_DOS_SIGNATURE))
			Addr -= PAGE_SIZE;

		return Addr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return 0;
}

NTSTATUS (NTAPI * NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);

volatile ULONG64 numCalls = 0;

DECLSPEC_NOINLINE NTSTATUS NTAPI hk_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
{
	numCalls++;

	if (numCalls % 1000 == 0)
		DbgLog("NtReadVirtualMemory - 0x%p 0x%p 0x%p 0x%p 0x%p\n", ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);

	return NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}

VOID SyscallEntryPoint();

NTSTATUS AddNtServiceCallHook(ULONG Index, UCHAR ParameterCount, PVOID Function)
{
	if (Index >= ARRAYSIZE(SyscallHookEnabled))
		return STATUS_INVALID_PARAMETER_1;

	if (ParameterCount > 15)
		return STATUS_INVALID_PARAMETER_2;

	//
	// If the syscall hook is enabled, disable it immediately
	//
	InterlockedExchange8(&SyscallHookEnabled[Index], FALSE);

	SyscallParamTable[Index]	= ParameterCount;
	SyscallPointerTable[Index]	= Function;

	//
	// If the function is valid, re-enable it
	//
	if (Function)
		InterlockedExchange8(&SyscallHookEnabled[Index], TRUE);

	return STATUS_SUCCESS;
}

VOID QueryNtServiceCall()
{
	NtSyscallHandler	= (ULONG64)__readmsr(MSR_LSTAR);
	GuestSyscallHandler = (ULONG64)&SyscallEntryPoint;

	NtKernelBase = FindNtoskrnlBase(NtSyscallHandler);
	DbgLog("NtOSBase: 0x%llx\n", NtKernelBase);

	*(ULONG_PTR *)&NtReadVirtualMemory = (ULONG_PTR)NtKernelBase + 0x3D0AF4;

	RtlSecureZeroMemory(SyscallHookEnabled, sizeof(SyscallHookEnabled));
	RtlSecureZeroMemory(SyscallParamTable, sizeof(SyscallParamTable));
	RtlSecureZeroMemory(SyscallPointerTable, sizeof(SyscallPointerTable));

	AddNtServiceCallHook(0x3E, 5, (PVOID)&hk_NtReadVirtualMemory);
}
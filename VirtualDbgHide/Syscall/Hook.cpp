#include "Driver.h"

extern "C"
{
	ULONG64 NtSyscallHandler;
	ULONG64 GuestSyscallHandler;

	ULONG64 NtKernelBase;
	ULONG64 NtKernelSSDT;

	CHAR SyscallHookEnabled[4096];
	CHAR SyscallParamTable[4096];
	PVOID SyscallPointerTable[4096];

	VOID SyscallEntryPoint();
}

NTSTATUS AddServiceCallHook(ULONG Index, UCHAR ParameterCount, PVOID Function)
{
	if (Index >= ARRAYSIZE(SyscallHookEnabled))
		return STATUS_INVALID_PARAMETER_1;

	if (ParameterCount > 15)
		return STATUS_INVALID_PARAMETER_2;

	//
	// Ensure this function isn't interrupted
	//
	KIRQL irql = KeGetCurrentIrql();

	if (irql < DISPATCH_LEVEL)
		irql = KeRaiseIrqlToDpcLevel();

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

	//
	// Reset IRQL
	//
	if (KeGetCurrentIrql() > irql)
		KeLowerIrql(irql);

	return STATUS_SUCCESS;
}

NTSTATUS RemoveServiceCallHook(ULONG Index)
{
	return AddServiceCallHook(Index, 0, NULL);
}

NTSTATUS ServiceCallInitialize()
{
	//
	// Initialize the kernel library
	//
	NTSTATUS status = AuxKlibInitialize();

	if (!NT_SUCCESS(status))
		return status;

	//
	// Query NTOSKRNL base offsets
	//
	NtKernelBase = GetNtoskrnlBase();
	NtKernelSSDT = GetSSDTBase();

	DbgLog("NtOSBase: 0x%llx\n", NtKernelBase);
	DbgLog("NtSSDT: 0x%llx\n", NtKernelSSDT);

	if (!NtKernelBase || !NtKernelSSDT)
		return STATUS_UNSUCCESSFUL;

	//
	// System call handler
	//
	NtSyscallHandler	= (ULONG64)__readmsr(MSR_LSTAR);
	GuestSyscallHandler = (ULONG64)&SyscallEntryPoint;

	//
	// Zero out information tables
	//
	RtlSecureZeroMemory(SyscallHookEnabled, sizeof(SyscallHookEnabled));
	RtlSecureZeroMemory(SyscallParamTable, sizeof(SyscallParamTable));
	RtlSecureZeroMemory(SyscallPointerTable, sizeof(SyscallPointerTable));

	//
	// Init the function pointers
	//
	status = Nt::Initialize();

	if (!NT_SUCCESS(status))
		return status;

//	AddServiceCallHook(0xE, 1, (PVOID)&hk_NtClose);
	AddServiceCallHook(0x3E, 5, (PVOID)&hk_NtReadVirtualMemory);
//	AddServiceCallHook(0x35, 4, (PVOID)&hk_NtQuerySystemInformation);
	return STATUS_SUCCESS;
}
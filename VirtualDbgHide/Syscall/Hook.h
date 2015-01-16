#pragma once

#define SYSCALL_NO_HOOK (-1)

typedef struct _SYSCALL_HOOK_INFO
{
	ULONG TargetProcessId;

	USHORT IdNtQueryInformationProcess;
	USHORT IdNtQueryObject;
	USHORT IdNtQuerySystemInformation;
	USHORT IdNtClose;
	USHORT IdNtSetInformationThread;
	USHORT IdNtSetContextThread;
} SYSCALL_HOOK_INFO, * PSYSCALL_HOOK_INFO;

#ifdef __cplusplus
extern "C"
{
#endif
	extern ULONG64 NtSyscallHandler;
	extern ULONG64 GuestSyscallHandler;

	extern ULONG64 NtKernelBase;
	extern ULONG64 NtKernelSSDT;
#ifdef __cplusplus
}
#endif

VOID QueryNtServiceCall();
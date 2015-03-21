#pragma once

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

NTSTATUS ServiceCallInitialize();
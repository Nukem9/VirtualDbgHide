#include "stdafx.h"

namespace Nt
{
	UNICODE_STRING DebugObjectName;

	NTSTATUS (NTAPI * pNtClose)(HANDLE Handle);
	NTSTATUS (NTAPI * pNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	NTSTATUS (NTAPI * pNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
	NTSTATUS (NTAPI * pNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	NTSTATUS (NTAPI * pNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
	NTSTATUS (NTAPI * pNtSetInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
	NTSTATUS (NTAPI * pNtSystemDebugControl)(DEBUG_CONTROL_CODE ControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);

	NTSTATUS Initialize()
	{
		RtlInitUnicodeString(&DebugObjectName, L"DebugObject");

		*(ULONG_PTR *)&pNtClose						= GetSSDTEntry(0);
		*(ULONG_PTR *)&pNtQueryInformationProcess	= GetSSDTEntry(0);
		*(ULONG_PTR *)&pNtQueryObject				= GetSSDTEntry(0);
		*(ULONG_PTR *)&pNtQuerySystemInformation	= GetSSDTEntry(0);
		*(ULONG_PTR *)&pNtReadVirtualMemory			= GetSSDTEntry(0);
		*(ULONG_PTR *)&pNtSetInformationThread		= GetSSDTEntry(0);
		*(ULONG_PTR *)&pNtSystemDebugControl		= GetSSDTEntry(0);

		if (!pNtClose ||
			!pNtQueryInformationProcess ||
			!pNtQueryObject ||
			!pNtQuerySystemInformation ||
			!pNtReadVirtualMemory ||
			!pNtSetInformationThread ||
			!pNtSystemDebugControl)
			return STATUS_UNSUCCESSFUL;

		return STATUS_SUCCESS;
	}

	NTSTATUS NTAPI NtClose(HANDLE Handle)
	{
		return pNtClose(Handle);
	}

	NTSTATUS NTAPI NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
	{
		return pNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	}

	NTSTATUS NTAPI NtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength)
	{
		return pNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
	}

	NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
	{
		return pNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	}

	NTSTATUS NTAPI NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
	{
		return pNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
	}

	NTSTATUS NTAPI NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
	{
		return pNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
	}

	NTSTATUS NTAPI NtSystemDebugControl(DEBUG_CONTROL_CODE ControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength)
	{
		return pNtSystemDebugControl(ControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
	}
}
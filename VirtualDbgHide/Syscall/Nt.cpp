#include "stdafx.h"

namespace Nt
{
#define DECL_NT(Name, ...) NTSTATUS (NTAPI * p##Name)(__VA_ARGS__); \
	UINT32 Id##Name;

	DECL_NT(NtClose, HANDLE Handle);
	DECL_NT(NtQueryInformationProcess, HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	DECL_NT(NtQueryObject, HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
	DECL_NT(NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	DECL_NT(NtReadVirtualMemory, HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
	DECL_NT(NtSetInformationThread, HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
	DECL_NT(NtSystemDebugControl, DEBUG_CONTROL_CODE ControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);

	UNICODE_STRING DebugObjectName;

	NTSTATUS Initialize()
	{
		RtlInitUnicodeString(&DebugObjectName, L"DebugObject");

		//
		// Determine the function pointer indexes
		//
		if (!NT_SUCCESS(QuerySyscallIndexes()))
			return STATUS_UNSUCCESSFUL;

		//
		// Get the actual function pointers now
		//
		*(ULONG_PTR *)&pNtClose						= GetSSDTEntry(IdNtClose);
		*(ULONG_PTR *)&pNtQueryInformationProcess	= GetSSDTEntry(IdNtQueryInformationProcess);
		*(ULONG_PTR *)&pNtQueryObject				= GetSSDTEntry(IdNtQueryObject);
		*(ULONG_PTR *)&pNtQuerySystemInformation	= GetSSDTEntry(IdNtQuerySystemInformation);
		*(ULONG_PTR *)&pNtReadVirtualMemory			= GetSSDTEntry(IdNtReadVirtualMemory);
		*(ULONG_PTR *)&pNtSetInformationThread		= GetSSDTEntry(IdNtSetInformationThread);
		*(ULONG_PTR *)&pNtSystemDebugControl		= GetSSDTEntry(IdNtSystemDebugControl);

		*(ULONG_PTR *)&pNtQuerySystemInformation = NtKernelBase + 0x3D1EA8;
		*(ULONG_PTR *)&pNtReadVirtualMemory = NtKernelBase + 0x3D0AF4;

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

	NTSTATUS QuerySyscallIndexes()
	{
		//
		// Open a handle to NTDLL from the system root
		//
		UNICODE_STRING fileName;
		RtlInitUnicodeString(&fileName, L"\\SystemRoot\\system32\\ntdll.dll");

		OBJECT_ATTRIBUTES objectAttributes;
		InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		HANDLE fileHandle;
		IO_STATUS_BLOCK ioStatusBlock;
		NTSTATUS status = ZwCreateFile(&fileHandle,
			GENERIC_READ,
			&objectAttributes,
			&ioStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL, 0);

		if (!NT_SUCCESS(status))
			return status;

		//
		// Query the file size
		//
		FILE_STANDARD_INFORMATION fileInformation;

		status = ZwQueryInformationFile(fileHandle,
			&ioStatusBlock,
			&fileInformation,
			sizeof(FILE_STANDARD_INFORMATION),
			FileStandardInformation);

		if (!NT_SUCCESS(status))
			return status;

		//
		// Allocate a data buffer
		//
		ULONG fileSize	= fileInformation.EndOfFile.LowPart;
		PVOID memory	= ExAllocatePoolWithTag(NonPagedPool, fileSize, 'NTDL');

		if (!memory)
		{
			status = STATUS_NO_MEMORY;
			goto __cleanup;
		}

		status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, memory, fileSize, NULL, NULL);

		if (!NT_SUCCESS(status))
			goto __cleanup;

		//
		// Parse all of the exports
		//
		status = STATUS_SUCCESS;
		status |= GetSSDTIndex((ULONG_PTR)memory, fileSize, "NtClose", &IdNtClose);
		status |= GetSSDTIndex((ULONG_PTR)memory, fileSize, "NtQueryInformationProcess", &IdNtQueryInformationProcess);
		status |= GetSSDTIndex((ULONG_PTR)memory, fileSize, "NtQueryObject", &IdNtQueryObject);
		status |= GetSSDTIndex((ULONG_PTR)memory, fileSize, "NtQuerySystemInformation", &IdNtQuerySystemInformation);
		status |= GetSSDTIndex((ULONG_PTR)memory, fileSize, "NtReadVirtualMemory", &IdNtReadVirtualMemory);
		status |= GetSSDTIndex((ULONG_PTR)memory, fileSize, "NtSetInformationThread", &IdNtSetInformationThread);
		status |= GetSSDTIndex((ULONG_PTR)memory, fileSize, "NtSystemDebugControl", &IdNtSystemDebugControl);

	__cleanup:
		if (memory)
			ExFreePoolWithTag(memory, 'NTDL');

		ZwClose(fileHandle);
		return status;
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
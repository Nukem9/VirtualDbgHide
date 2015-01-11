#include "Driver.h"

#define WINNT_DEVICE_NAME L"\\Device\\VirtualDbgHide"
#define MSDOS_DEVICE_NAME L"\\DosDevices\\VirtualDbgHide"

UNICODE_STRING usDriverName;
UNICODE_STRING usDosDeviceName;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	//
	// Set up major function pointers
	//
	//DriverObject->MajorFunction[IRP_MJ_CREATE]			= DispatchCreateClose;
	//DriverObject->MajorFunction[IRP_MJ_CLOSE]			= DispatchCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;
	DriverObject->DriverUnload = DriverUnload;

	//
	// Initialize unicode driver device names
	//
	RtlInitUnicodeString(&usDriverName, WINNT_DEVICE_NAME);
	RtlInitUnicodeString(&usDosDeviceName, MSDOS_DEVICE_NAME);

	//
	// Create the I/O manager instance
	//
	PDEVICE_OBJECT deviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);

	if (!NT_SUCCESS(status))
		return status;

	//
	// Symbolic link to DOS path
	//
	IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);

	QueryNtServiceCall();

	HANDLE thread;
	status = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, VmStart, NULL);

	if (!NT_SUCCESS(status))
		return status;

	ZwClose(thread);

	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	IoDeleteSymbolicLink(&usDosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);
}
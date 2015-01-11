#include "Driver.h"

#define VM_DETOUR_SYSCALLS		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VM_BEGIN_VIRTUALIZATION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS DispatchIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);

	//
	// Check if MajorFunction was for DeviceIoControl
	//
	if (ioStack->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		ULONG controlCode = ioStack->Parameters.DeviceIoControl.IoControlCode;

		switch (controlCode)
		{
		case VM_DETOUR_SYSCALLS:
			break;

		case VM_BEGIN_VIRTUALIZATION:
			break;
		}
	}

	//
	// Complete the request, but don't boost priority
	//
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}
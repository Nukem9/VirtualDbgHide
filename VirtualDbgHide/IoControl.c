#include "Driver.h"

#define VM_DETOUR_SYSCALLS		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VM_BEGIN_VIRTUALIZATION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VM_STOP_VIRTUALIZATION	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define VM_QUERY_RUNNING		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
		ULONG controlCode	= ioStack->Parameters.DeviceIoControl.IoControlCode;
		ULONG inputLength	= ioStack->Parameters.DeviceIoControl.InputBufferLength;
		ULONG outputLength	= ioStack->Parameters.DeviceIoControl.OutputBufferLength;

		switch (controlCode)
		{
		case VM_DETOUR_SYSCALLS:
		{
			//
			// Information length check
			//
			if (inputLength != sizeof(SYSCALL_HOOK_INFO))
			{
				status = STATUS_INFO_LENGTH_MISMATCH;
				break;
			}

			PSYSCALL_HOOK_INFO info = Irp->AssociatedIrp.SystemBuffer;
		}
		break;

		case VM_BEGIN_VIRTUALIZATION:
		{
			//
			// Start the virtual machine initialization thread
			//
			HANDLE threadHandle;
			status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, VmStart, NULL);

			if (NT_SUCCESS(status))
				NtClose(threadHandle);
		}
		break;

		case VM_STOP_VIRTUALIZATION:
		{
			status = STATUS_NOT_IMPLEMENTED;
		}
		break;

		case VM_QUERY_RUNNING:
		{
			//
			// Output buffer size is expected to be a CHAR
			//
			if (outputLength != sizeof(CHAR))
			{
				status = STATUS_INFO_LENGTH_MISMATCH;
				break;
			}

			*(CHAR *)Irp->AssociatedIrp.SystemBuffer	= VmIsActive();
			Irp->IoStatus.Information					= sizeof(CHAR);
		}
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
#include "stdafx.h"

VOID VmStart(PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);

	//
	// Does the hardware allow it in the first place?
	//
	NTSTATUS status = VTxHardwareStatus();

	if (!NT_SUCCESS(status))
	{
		DbgLog("Intel VT-x is not supported (0x%X)\n", status);
		return;
	}

	//
	// Enable VMX on each processor/core
	//
	status = VTxEnableProcessors(KeNumberProcessors);

	if (!NT_SUCCESS(status))
	{
		DbgLog("Unable to prepare processors for virtualization (0x%X)\n", status);
		return;
	}

	//
	// Synchronize
	//
	KMUTEX mutex;

	KeInitializeMutex(&mutex, 0);
	KeWaitForSingleObject(&mutex, Executive, KernelMode, FALSE, NULL);

	//
	// Control area for saving states and VM information
	//
	status = ControlAreaInitialize(KeNumberProcessors);

	if (!NT_SUCCESS(status))
	{
		DbgLog("Unable to initialize control area (0x%X)\n", status);
		return;
	}

	//
	// Start virtualization
	//
	DbgLog("Virtualizing %d processors...\n", KeNumberProcessors);

	for (LONG i = 0; i < KeNumberProcessors; i++) 
	{
		KAFFINITY oldAffinity	= KeSetSystemAffinityThreadEx((KAFFINITY)(1 << i));
		KIRQL oldIrql			= KeRaiseIrqlToDpcLevel();

		_StartVirtualization();

		KeLowerIrql(oldIrql);
		KeRevertToUserAffinityThreadEx(oldAffinity);
	}

	DbgLog("Done\n");

	KeReleaseMutex(&mutex, FALSE);
}

CHAR VmIsActive()
{
	__try
	{
		return _QueryVirtualization();
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return FALSE;
}

NTSTATUS StartVirtualization(PVOID GuestRsp)
{
	ULONG processorId	= KeGetCurrentProcessorNumber();
	NTSTATUS status		= ControlAreaInitializeProcessor(processorId);
	PVIRT_CPU cpu		= CpuControlArea[processorId];

	if (!NT_SUCCESS(status))
	{
		DbgLog("Failed ControlAreaInitializeProcessor 0x%x\n", status);
		return status;
	}

	CpuSetupVMCS(cpu, GuestRsp);

	status = Virtualize(cpu);

	if (!NT_SUCCESS(status))
	{
		DbgLog("Failed Virtualize\n");
		return status;
	}

	return STATUS_SUCCESS;
}
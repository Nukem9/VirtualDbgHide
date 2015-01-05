#include "Driver.h"

NTSTATUS VTxEnableProcessors(LONG ProcessorCount)
{
	NTSTATUS status			= STATUS_SUCCESS;
	LONG processorIndex		= 0;

	for (; processorIndex < ProcessorCount; processorIndex++)
	{
		KAFFINITY oldAffinity	= KeSetSystemAffinityThreadEx((KAFFINITY)(1 << processorIndex));
		KIRQL oldIrql			= KeRaiseIrqlToDpcLevel();

		// Enable if possible
		status = VTxSoftwareStatus();

		KeLowerIrql(oldIrql);
		KeRevertToUserAffinityThreadEx(oldAffinity);

		// If it failed, exit
		if (!NT_SUCCESS(status))
			break;
	}

	if (!NT_SUCCESS(status) || processorIndex != ProcessorCount)
	{
		DbgLog("Error: Unable to enable virtualization on all processors\n");
		return status;
	}

	return STATUS_SUCCESS;
}

NTSTATUS VTxHardwareStatus()
{
	//
	// Use CPUID first to determine if the hardware supports it
	//
	int cpuInfo[4];
	__cpuid(cpuInfo, 0);

	//
	// Are newer feature levels supported?
	//
	if (cpuInfo[0] < 1)
	{
		DbgLog("Error: extended CPUID functions not implemented\n");
		return STATUS_NOT_SUPPORTED;
	}

	//
	// GenuineIntel check
	//
	if (cpuInfo[1] != 'uneG' ||
		cpuInfo[2] != 'letn' ||
		cpuInfo[3] != 'Ieni')
	{
		DbgLog("Error: Processor is not 'GenuineIntel':\n");

		int buffer[4];
		buffer[0] = cpuInfo[1];
		buffer[1] = cpuInfo[3];
		buffer[2] = cpuInfo[2];
		buffer[3] = 0;
		DbgPrint("%s\n", &buffer);

		return STATUS_NOT_SUPPORTED;
	}

	//
	// Check CPUID values to see if virtualization is supported
	//
	__cpuid(cpuInfo, 1);

	//
	// BIT #5 VMX
	//
	if ((cpuInfo[2] & (1 << 5)) == 0)
	{
		DbgLog("Error: VMX not supported\n");
		return STATUS_NOT_SUPPORTED;
	}

	return STATUS_SUCCESS;
}

NTSTATUS VTxSoftwareStatus()
{
	//
	// Check the feature control bit MSR
	//
	IA32_FEATURE_CONTROL_MSR msr;
	TO_ULL(msr) = __readmsr(MSR_IA32_FEATURE_CONTROL);

	if (msr.Lock == 1)
	{
		// If the MSR is locked, it can't be modified
		// If 'EnableVmxon' is unset, virtualization is not possible
		if (msr.EnableVmxon == 0)
		{
			DbgLog("VMX is disabled in bios: MSR_IA32_FEATURE_CONTROL is 0x%llx\n", msr);
			return STATUS_NOT_SUPPORTED;
		}
	}
	else
	{
		// Force the lock to be on and enable VMXON
		msr.Lock		= 1;
		msr.VmxonInSmx	= 1;
		msr.EnableVmxon = 1;

		__writemsr(MSR_IA32_FEATURE_CONTROL, TO_ULL(msr));
	}

	//
	// Setup CR0 correctly (Protected mode and paging must be enabled)
	//
	CR0_REG cr0;
	TO_ULL(cr0) = __readcr0();

	if (cr0.PE == 0 || cr0.PG == 0)
	{
		DbgLog("Error: Protected mode or paging is not set in CR0\n");
		return STATUS_NOT_SUPPORTED;
	}
	else
	{
		// Required by first processors that supported VMX
		cr0.NE = 1;
	}

	__writecr0(TO_ULL(cr0));

	//
	// Virtual Machine eXtensions Enable in CR4
	// BIT #13 VMXE
	//
	__try
	{
		__writecr4(__readcr4() | (1 << 13));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// Possible 'Privileged Instruction Exception' with CR4 bits
		return GetExceptionCode();
	}

	return STATUS_SUCCESS;
}
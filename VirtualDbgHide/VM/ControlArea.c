#include "stdafx.h"

LONG		CpuControlAreaCount;
LONG		CpuControlAreaSize;
PVIRT_CPU	*CpuControlArea;

NTSTATUS ControlAreaInitialize(LONG ProcessorCount)
{
	//
	// Allocate the CPU data array
	//
	CpuControlAreaCount = ProcessorCount;
	CpuControlAreaSize	= ROUND_TO_PAGES(sizeof(PVIRT_CPU) * CpuControlAreaCount);
	CpuControlArea		= ExAllocatePoolWithTag(NonPagedPool, CpuControlAreaSize, 'CCTL');

	if (!CpuControlArea)
		return STATUS_NO_MEMORY;

	//
	// Clear invalid memory
	//
	RtlSecureZeroMemory(CpuControlArea, CpuControlAreaSize);

	return STATUS_SUCCESS;
}

NTSTATUS ControlAreaInitializeProcessor(LONG ProcessorNumber)
{
	//
	// Allocate host stack region
	// 16 pages available for use
	//
	SIZE_T stackSize = 16 * PAGE_SIZE;
	PUCHAR stackBase = ExAllocatePoolWithTag(NonPagedPool, stackSize, 'KSTK');

	if (!stackBase)
		return STATUS_NO_MEMORY;

	RtlSecureZeroMemory((PVOID)stackBase, stackSize);

	//
	// Set up CPU control structure
	//
	PVIRT_CPU cpu		= (PVIRT_CPU)(stackBase + stackSize - 8 - sizeof(VIRT_CPU));
	cpu->HostStackBase	= stackBase;
	cpu->Self			= cpu;

	CpuControlArea[ProcessorNumber] = cpu;

	//
	// Allocate all VMX regions
	//
	if (!NT_SUCCESS(AllocateVmxProcessorData(&cpu->VmxonVa, &cpu->VmxonPa, &cpu->VmxonSize)))
		return STATUS_NO_MEMORY;

	if (!NT_SUCCESS(AllocateVmxProcessorData(&cpu->VmcsVa, &cpu->VmcsPa, &cpu->VmcsSize)))
		return STATUS_NO_MEMORY;

	if (!NT_SUCCESS(AllocateVmxProcessorData(&cpu->MSRBitmapVa, &cpu->MSRBitmapPa, &cpu->MSRBitmapSize)))
		return STATUS_NO_MEMORY;

	// Bitmap needs to be zeroed
	RtlSecureZeroMemory(cpu->MSRBitmapVa, cpu->MSRBitmapSize);

	__try
	{
		if (__vmx_on(PA_PTR_INT64(cpu->VmxonPa)) > 0)
			return STATUS_UNSUCCESSFUL;

		if (__vmx_vmclear(PA_PTR_INT64(cpu->VmcsPa)) > 0)
			return STATUS_UNSUCCESSFUL;

		if (__vmx_vmptrld(PA_PTR_INT64(cpu->VmcsPa)) > 0)
			return STATUS_UNSUCCESSFUL;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// Rare case (or if physical address is invalid)
		return GetExceptionCode();
	}

	return STATUS_SUCCESS;
}

NTSTATUS AllocateVmxProcessorData(PVOID *VirtualAddress, PHYSICAL_ADDRESS *PhysicalAddress, SIZE_T *Size)
{
	if (!VirtualAddress || !PhysicalAddress || !Size)
		return STATUS_INVALID_PARAMETER;

	//
	// Read the MSR information to get the base size
	// Default to 4096 bytes
	//
	VMX_BASIC_MSR msr;
	TO_ULL(msr) = __readmsr(MSR_IA32_VMX_BASIC);

	if (*Size <= 0)
	{
		// In rare cases this isn't set (*COUGH* *VMWARE*)
		if (msr.szVmxOnRegion > 0)
			*Size = msr.szVmxOnRegion;
		else
			*Size = 0x1000;

		*Size = ROUND_TO_PAGES(*Size);
	}

	//
	// Allocate CONTIGUOUS physical memory
	// MmCached = Stored in CPU L1/L2/L3 cache if possible 
	//
	PHYSICAL_ADDRESS l1, l2, l3;

	l1.QuadPart = 0;
	l2.QuadPart = -1;
	l3.QuadPart = 0x200000;

	PVOID address = MmAllocateContiguousMemorySpecifyCache(*Size, l1, l2, l3, MmCached);

	if (!address)
		return STATUS_NO_MEMORY;

	RtlSecureZeroMemory(address, *Size);

	//
	// Set the revision id
	//
	*(ULONG *)address = msr.RevId;

	//
	// Done
	//
	*VirtualAddress	 = address;
	*PhysicalAddress = MmGetPhysicalAddress(address);

	return STATUS_SUCCESS;
}

NTSTATUS FreeVmxProcessorData(PVOID VirtualAddress)
{
	if (!VirtualAddress)
		return STATUS_INVALID_PARAMETER;

	MmFreeContiguousMemory(VirtualAddress);
	return STATUS_SUCCESS;
}
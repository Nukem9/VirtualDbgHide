#pragma once

extern LONG			CpuControlAreaCount;
extern LONG			CpuControlAreaSize;
extern PVIRT_CPU	*CpuControlArea;

NTSTATUS ControlAreaInitialize(LONG ProcessorCount);
NTSTATUS ControlAreaInitializeProcessor(LONG ProcessorNumber);

NTSTATUS AllocateVmxProcessorData(PVOID *VirtualAddress, PHYSICAL_ADDRESS *PhysicalAddress, SIZE_T *Size);
NTSTATUS FreeVmxProcessorData(PVOID VirtualAddress);
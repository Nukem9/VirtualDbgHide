#pragma once

NTSTATUS NTAPI HandleUnimplemented(PVIRT_CPU Cpu, ULONG InstructionLength);
NTSTATUS NTAPI HandleCpuid(PVIRT_CPU Cpu, ULONG InstructionLength);
NTSTATUS NTAPI HandleException(PVIRT_CPU Cpu, ULONG InstructionLength);
NTSTATUS NTAPI HandleInvd(PVIRT_CPU Cpu, ULONG InstructionLength);
NTSTATUS NTAPI HandleRdpmc(PVIRT_CPU Cpu, ULONG InstructionLength);
NTSTATUS NTAPI HandleRdtsc(PVIRT_CPU Cpu, ULONG InstructionLength);
NTSTATUS NTAPI HandleVmCall(PVIRT_CPU Cpu, ULONG InstructionLength);
NTSTATUS NTAPI HandleVmInstruction(PVIRT_CPU Cpu, ULONG InstructionLength);
NTSTATUS NTAPI HandleCrAccess(PVIRT_CPU Cpu, ULONG InstructionLength);
NTSTATUS NTAPI HandleDrAccess(PVIRT_CPU Cpu, ULONG InstructionLength);
NTSTATUS NTAPI HandleMsrRead(PVIRT_CPU Cpu, ULONG InstructionLength);
NTSTATUS NTAPI HandleMsrWrite(PVIRT_CPU Cpu, ULONG InstructionLength);
NTSTATUS NTAPI HandleRdtscp(PVIRT_CPU Cpu, ULONG InstructionLength);
NTSTATUS NTAPI HandleXsetbv(PVIRT_CPU Cpu, ULONG InstructionLength);
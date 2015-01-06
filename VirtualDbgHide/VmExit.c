#include "Driver.h"

VmExitCallback VmExitCallbacks[VMX_MAX_GUEST_VMEXIT] =
{
	HandleException,			// 0  EXIT_REASON_EXCEPTION_NMI
	HandleUnimplemented,		// 1  EXIT_REASON_EXTERNAL_INTERRUPT
	HandleUnimplemented,		// 2  EXIT_REASON_TRIPLE_FAULT
	HandleUnimplemented,		// 3  EXIT_REASON_INIT
	HandleUnimplemented,		// 4  EXIT_REASON_SIPI
	HandleUnimplemented,		// 5  EXIT_REASON_IO_SMI
	HandleUnimplemented,		// 6  EXIT_REASON_OTHER_SMI
	HandleUnimplemented,		// 7  EXIT_REASON_PENDING_VIRT_INTR
	HandleUnimplemented,		// 8  EXIT_REASON_PENDING_VIRT_NMI
	HandleUnimplemented,		// 9  EXIT_REASON_TASK_SWITCH
	HandleCpuid,				// 10 EXIT_REASON_CPUID
	HandleUnimplemented,		// 11 EXIT_REASON_GETSEC
	HandleUnimplemented,		// 12 EXIT_REASON_HLT
	HandleInvd,					// 13 EXIT_REASON_INVD
	HandleUnimplemented,		// 14 EXIT_REASON_INVLPG
	HandleUnimplemented,		// 15 EXIT_REASON_RDPMC
	HandleRdtsc,				// 16 EXIT_REASON_RDTSC
	HandleUnimplemented,		// 17 EXIT_REASON_RSM
	HandleVmCall,				// 18 EXIT_REASON_VMCALL
	HandleVmInstruction,		// 19 EXIT_REASON_VMCLEAR
	HandleVmInstruction,		// 20 EXIT_REASON_VMLAUNCH
	HandleVmInstruction,		// 21 EXIT_REASON_VMPTRLD
	HandleVmInstruction,		// 22 EXIT_REASON_VMPTRST
	HandleVmInstruction,		// 23 EXIT_REASON_VMREAD
	HandleVmInstruction,		// 24 EXIT_REASON_VMRESUME
	HandleVmInstruction,		// 25 EXIT_REASON_VMWRITE
	HandleVmInstruction,		// 26 EXIT_REASON_VMXOFF
	HandleVmInstruction,		// 27 EXIT_REASON_VMXON
	HandleCrAccess,				// 28 EXIT_REASON_CR_ACCESS
	HandleDrAccess,				// 29 EXIT_REASON_DR_ACCESS
	HandleUnimplemented,		// 30 EXIT_REASON_IO_INSTRUCTION
	HandleMsrRead,				// 31 EXIT_REASON_MSR_READ
	HandleMsrWrite,				// 32 EXIT_REASON_MSR_WRITE
	HandleUnimplemented,		// 33 EXIT_REASON_INVALID_GUEST_STATE
	HandleUnimplemented,		// 34 EXIT_REASON_MSR_LOADING
	HandleUnimplemented,		// 35 ?
	HandleUnimplemented,		// 36 EXIT_REASON_MWAIT_INSTRUCTION
	HandleUnimplemented,		// 37 EXIT_REASON_MONITOR_TRAP_FLAG
	HandleUnimplemented,		// 38 ?
	HandleUnimplemented,		// 39 EXIT_REASON_MONITOR_INSTRUCTION
	HandleUnimplemented,		// 40 EXIT_REASON_PAUSE_INSTRUCTION
	HandleUnimplemented,		// 41 EXIT_REASON_MACHINE_CHECK
	HandleUnimplemented,		// 42 ?
	HandleUnimplemented,		// 43 EXIT_REASON_TPR_BELOW_THRESHOLD
	HandleUnimplemented,		// 44 EXIT_REASON_APIC_ACCESS
	HandleUnimplemented,		// 45 EXIT_REASON_EOI_INDUCED
	HandleUnimplemented,		// 46 EXIT_REASON_GIDTR_ACCESS
	HandleUnimplemented,		// 47 EXIT_REASON_LDTR_ACCESS
	HandleUnimplemented,		// 48 EXIT_REASON_EPT_VIOLATION
	HandleUnimplemented,		// 49 EXIT_REASON_EPT_MISCONFIG
	HandleUnimplemented,		// 50 EXIT_REASON_INVEPT
	HandleRdtscp,				// 51 EXIT_REASON_RDTSCP
	HandleUnimplemented,		// 52 EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED
	HandleUnimplemented,		// 53 EXIT_REASON_INVVPID
	HandleUnimplemented,		// 54 EXIT_REASON_WBINVD
	HandleXsetbv,				// 55 EXIT_REASON_XSETBV
	HandleUnimplemented,		// 56 EXIT_REASON_APIC_WRITE
	HandleUnimplemented,		// 57 EXIT_REASON_RDRAND
	HandleUnimplemented,		// 58 EXIT_REASON_INVPCID
	HandleUnimplemented,		// 59 EXIT_REASON_VMFUNC
	HandleUnimplemented,		// 60 ?
	HandleUnimplemented,		// 61 EXIT_REASON_RDSEED
	HandleUnimplemented,		// 62 ?
	HandleUnimplemented,		// 63 EXIT_REASON_XSAVES
	HandleUnimplemented,		// 64 EXIT_REASON_XRSTORS
};

VOID HandleVmExit(PVIRT_CPU Cpu, PGUEST_REGS GuestRegs)
{
	//
	// Read guest state registers and adjust IRQL
	//
	CpuPrepareExit(Cpu);
	CpuUpdateState(Cpu, GuestRegs);

	//
	// Exit information
	//
	__vmx_vmread(VM_EXIT_REASON, &Cpu->ExitReason);
	Cpu->ExitReason &= ~VMX_EXIT_REASONS_FAILED_VMENTRY;

	SIZE_T instructionLen = 0;
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &instructionLen);

	VmExitCallbacks[Cpu->ExitReason](Cpu, (ULONG)instructionLen);

	//
	// Set registers and return to VM execution
	//
	CpuSyncState(Cpu, GuestRegs);
	CpuPrepareEntry(Cpu);
}
#include "stdafx.h"

VOID CpuDumpRegisters(PVIRT_CPU Cpu)
{
	DbgPrint("rip    = 0x%llx\n", Cpu->rip);
	DbgPrint("rflags = 0x%llx\n", Cpu->rflags);
	DbgPrint("rax    = 0x%llx\n", Cpu->rax);
	DbgPrint("rbx    = 0x%llx\n", Cpu->rbx);
	DbgPrint("rcx    = 0x%llx\n", Cpu->rcx);
	DbgPrint("rdx    = 0x%llx\n", Cpu->rdx);
	DbgPrint("rbp    = 0x%llx\n", Cpu->rbp);
	DbgPrint("rsp    = 0x%llx\n", Cpu->rsp);
	DbgPrint("rdi    = 0x%llx\n", Cpu->rdi);
	DbgPrint("rsi    = 0x%llx\n", Cpu->rsi);
	DbgPrint("r8     = 0x%llx\n", Cpu->r8);
	DbgPrint("r9     = 0x%llx\n", Cpu->r9);
	DbgPrint("r10    = 0x%llx\n", Cpu->r10);
	DbgPrint("r11    = 0x%llx\n", Cpu->r11);
	DbgPrint("r12    = 0x%llx\n", Cpu->r12);
	DbgPrint("r13    = 0x%llx\n", Cpu->r13);
	DbgPrint("r14    = 0x%llx\n", Cpu->r14);
	DbgPrint("r15    = 0x%llx\n", Cpu->r15);
}

VOID CpuPrepareExit(PVIRT_CPU Cpu)
{
	//
	// High IRQL so this is not interrupted
	//
	Cpu->ExitIRQL = KeGetCurrentIrql();

	if (Cpu->ExitIRQL < DISPATCH_LEVEL)
		Cpu->PreviousIRQL = KeRaiseIrqlToDpcLevel();
}

VOID CpuPrepareEntry(PVIRT_CPU Cpu)
{
	//
	// Accommodate for ExitIRQL changing
	//
	if (Cpu->ExitIRQL < DISPATCH_LEVEL)
	{
		// GUEST has a lower IRQL
		KeLowerIrql(Cpu->PreviousIRQL);
	}
	else if (Cpu->ExitIRQL > DISPATCH_LEVEL)
	{
		// GUEST now has a higher IRQL
		KeRaiseIrql(Cpu->ExitIRQL, &Cpu->PreviousIRQL);
	}
}

VOID CpuUpdateState(PVIRT_CPU Cpu, PGUEST_REGS GuestRegisters)
{
	static_assert(sizeof(Cpu->Registers) == sizeof(GUEST_REGS), "sizeof(Cpu->Registers) != sizeof(GUEST_REGS)");

	RtlCopyMemory(Cpu->Registers, GuestRegisters, sizeof(GUEST_REGS));

	__vmx_vmread(GUEST_RSP, &Cpu->rsp);
	__vmx_vmread(GUEST_RIP, &Cpu->rip);
	__vmx_vmread(GUEST_RFLAGS, &Cpu->rflags);
}

VOID CpuSyncState(PVIRT_CPU Cpu, PGUEST_REGS GuestRegisters)
{
	static_assert(sizeof(Cpu->Registers) == sizeof(GUEST_REGS), "sizeof(Cpu->Registers) != sizeof(GUEST_REGS)");

	RtlCopyMemory(GuestRegisters, Cpu->Registers, sizeof(GUEST_REGS));

	__vmx_vmwrite(GUEST_RSP, Cpu->rsp);
	__vmx_vmwrite(GUEST_RIP, Cpu->rip);
	__vmx_vmwrite(GUEST_RFLAGS, Cpu->rflags);
}

VOID CpuSetupVMCS(PVIRT_CPU Cpu, PVOID GuestRsp)
{
	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());
	__vmx_vmwrite(GUEST_DR7, __readdr(7));
	__vmx_vmwrite(GUEST_RSP, (SIZE_T)GuestRsp);
	__vmx_vmwrite(GUEST_RIP, (SIZE_T)_GuestEntryPoint);
	__vmx_vmwrite(GUEST_RFLAGS, _Rflags());

	PVOID GdtBase = (PVOID)_GdtBase();
	FillGuestSelectorData(GdtBase, ES, _Es());
	FillGuestSelectorData(GdtBase, CS, _Cs());
	FillGuestSelectorData(GdtBase, SS, _Ss());
	FillGuestSelectorData(GdtBase, DS, _Ds());
	FillGuestSelectorData(GdtBase, FS, _Fs());
	FillGuestSelectorData(GdtBase, GS, _Gs());
	FillGuestSelectorData(GdtBase, LDTR, _Ldtr());
	FillGuestSelectorData(GdtBase, TR, _TrSelector());
	__vmx_vmwrite(GUEST_ES_BASE, 0);
	__vmx_vmwrite(GUEST_CS_BASE, 0);
	__vmx_vmwrite(GUEST_SS_BASE, 0);
	__vmx_vmwrite(GUEST_DS_BASE, 0);
	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));
	__vmx_vmwrite(GUEST_GDTR_BASE, (SIZE_T)GdtBase);
	__vmx_vmwrite(GUEST_IDTR_BASE, _IdtBase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, _GdtLimit());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, _IdtLimit());

	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xffffffff);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);
	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

	// Guest non register state
	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);
	__vmx_vmwrite(VMCS_LINK_POINTER, 0xffffffff);
	__vmx_vmwrite(VMCS_LINK_POINTER_HIGH, 0xffffffff);

	// Host state area
	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());
	__vmx_vmwrite(HOST_RSP, (SIZE_T)Cpu);
	__vmx_vmwrite(HOST_RIP, (SIZE_T)_ExitHandler);

	__vmx_vmwrite(HOST_ES_SELECTOR, KGDT64_R0_DATA);
	__vmx_vmwrite(HOST_CS_SELECTOR, KGDT64_R0_CODE);
	__vmx_vmwrite(HOST_SS_SELECTOR, KGDT64_R0_DATA);
	__vmx_vmwrite(HOST_DS_SELECTOR, KGDT64_R0_DATA);
	__vmx_vmwrite(HOST_FS_SELECTOR, (_Fs() & 0xf8));
	__vmx_vmwrite(HOST_GS_SELECTOR, (_Gs() & 0xf8));
	__vmx_vmwrite(HOST_TR_SELECTOR, (_TrSelector() & 0xf8));
	__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

	SEGMENT_SELECTOR segmentSelector;
	InitializeSegmentSelector(&segmentSelector, _TrSelector(), (PUCHAR)_GdtBase());

	__vmx_vmwrite(HOST_TR_BASE, segmentSelector.base);

	__vmx_vmwrite(HOST_GDTR_BASE, _GdtBase());
	__vmx_vmwrite(HOST_IDTR_BASE, _IdtBase());

	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

	//
	// PIN based control fields
	//
	{
		ULONG PinExecControl = 0;

		__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(PinExecControl, MSR_IA32_VMX_PINBASED_CTLS));
	}

	//
	// CPU based primary controls
	//
	{
		ULONG VmExecControl = 0;
		//VmExecControl |= CPU_BASED_ACTIVATE_MSR_BITMAP;
		VmExecControl |= CPU_BASED_RDTSC_EXITING;
		VmExecControl |= CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;

		__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(VmExecControl, MSR_IA32_VMX_PROCBASED_CTLS));
	}

	//
	// CPU based secondary controls
	//
	{
		ULONG VmExecControlSecondary = 0;
		VmExecControlSecondary |= SECONDARY_EXEC_RDTSCP;

		__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(VmExecControlSecondary, MSR_IA32_VMX_PROCBASED_CTLS2));
	}
	
	//
	// VM entry controls
	//
	{
		ULONG EntryControl = 0;
		EntryControl |= VM_ENTRY_IA32E_MODE;

		__vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(EntryControl, MSR_IA32_VMX_ENTRY_CTLS));
	}
	
	//
	// VM exit controls
	//
	{
		ULONG ExitControl = 0;
		ExitControl |= VM_EXIT_IA32E_MODE;
		ExitControl |= VM_EXIT_ACK_INTR_ON_EXIT;

		__vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(ExitControl, MSR_IA32_VMX_EXIT_CTLS));
	}

	//
	// Exception bitmap
	//
	{
		ULONG ExceptionBitmap = 0;
		//ExceptionBitmap |= 1 << VECTOR_DEBUG_EXCEPTION;
		//ExceptionBitmap |= 1 << VECTOR_BREAKPOINT_EXCEPTION;
		//ExceptionBitmap |= 1 << VECTOR_INVALID_OPCODE_EXCEPTION;
		//ExceptionBitmap |= 1 << PAGE_FAULT_EXCEPTION;

		__vmx_vmwrite(EXCEPTION_BITMAP, ExceptionBitmap);
	}

	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	__vmx_vmwrite(IO_BITMAP_A, 0);
	__vmx_vmwrite(IO_BITMAP_A_HIGH, 0);
	__vmx_vmwrite(IO_BITMAP_B, 0);
	__vmx_vmwrite(IO_BITMAP_B_HIGH, 0);
	__vmx_vmwrite(TSC_OFFSET, 0);
	__vmx_vmwrite(TSC_OFFSET_HIGH, 0);
	__vmx_vmwrite(MSR_BITMAP, Cpu->MSRBitmapPa.LowPart);
	__vmx_vmwrite(MSR_BITMAP_HIGH, Cpu->MSRBitmapPa.HighPart);

	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

	__vmx_vmwrite(CR0_GUEST_HOST_MASK, X86_CR0_PG);
	__vmx_vmwrite(CR0_READ_SHADOW, (__readcr0() & X86_CR0_PG) | X86_CR0_PG);

	__vmx_vmwrite(CR4_GUEST_HOST_MASK, X86_CR4_VMXE);
	__vmx_vmwrite(CR4_READ_SHADOW, 0);

	__vmx_vmwrite(CR3_TARGET_COUNT, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE0, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE1, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE2, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE3, 0);
}

extern ULONG64 GuestSyscallHandler;
NTSTATUS Virtualize(PVIRT_CPU pCpu)
{
	DbgLog("CPU: 0x%p\n", pCpu);
	DbgLog("RSP: 0x%p\n", _Rsp());

	__writemsr(MSR_LSTAR, GuestSyscallHandler);

	switch (__vmx_vmlaunch())
	{
	case 0:
		// The operation succeeded. Never reaches this.
		__debugbreak();
		break;

	case 1:
		// The operation failed with extended status available.
		DbgLog("VMLaunch failed: 0x%llX\n", __readvmx(VM_INSTRUCTION_ERROR));
		return STATUS_UNSUCCESSFUL;

	case 2:
		// The operation failed without status available.
		DbgLog("VMLaunch failed: No error available\n");
		return STATUS_UNSUCCESSFUL;
	}

	// Execution will never reach here
	__assume(0);
}
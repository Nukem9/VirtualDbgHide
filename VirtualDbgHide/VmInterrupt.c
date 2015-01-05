#include "Driver.h"

VOID VmInjectInterrupt(ULONG InterruptType, ULONG Vector, ULONG WriteLength)
{
	ULONG InjectEvent = 0;
	PINTERRUPT_INJECT_INFO_FIELD pInjectEvent = (PINTERRUPT_INJECT_INFO_FIELD)&InjectEvent;

	pInjectEvent->Vector			= Vector;
	pInjectEvent->InterruptionType	= InterruptType;
	pInjectEvent->DeliverErrorCode	= 0;
	pInjectEvent->Valid				= 1;

	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, InjectEvent);

	if (WriteLength > 0)
		__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, WriteLength);
}
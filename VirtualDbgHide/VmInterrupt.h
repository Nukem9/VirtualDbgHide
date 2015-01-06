#pragma once

typedef struct _INTERRUPT_INFO_FIELD
{
	unsigned Vector : 8;
	unsigned InterruptionType : 3;
	unsigned ErrorCodeValid : 1;
	unsigned NMIUnblocking : 1;
	unsigned Reserved : 18;
	unsigned Valid : 1;
} INTERRUPT_INFO_FIELD, *PINTERRUPT_INFO_FIELD;

typedef struct _INTERRUPT_INJECT_INFO_FIELD
{
	unsigned Vector : 8;
	unsigned InterruptionType : 3;
	unsigned DeliverErrorCode : 1;
	unsigned Reserved : 19;
	unsigned Valid : 1;
} INTERRUPT_INJECT_INFO_FIELD, *PINTERRUPT_INJECT_INFO_FIELD;

/*
 * Interrupt Descriptor Table entries
 * http://www.acm.uiuc.edu/sigops/roll_your_own/i386/idt.html
 */
#define VECTOR_DIVIDE_ERROR_EXCEPTION			0
#define VECTOR_DEBUG_EXCEPTION					1
#define VECTOR_NMI_INTERRUPT					2
#define VECTOR_BREAKPOINT_EXCEPTION				3
#define VECTOR_OVERFLOW_EXCEPTION				4
#define VECTOR_BOUND_EXCEPTION					5
#define VECTOR_INVALID_OPCODE_EXCEPTION			6
#define VECTOR_DEVICE_NOT_AVAILABLE_EXCEPTION	7
#define VECTOR_DOUBLE_FAULT_EXCEPTION			8
#define VECTOR_COPROCESSOR_SEGMENT_OVERRUN		9
#define VECTOR_INVALID_TSS_EXCEPTION			10
#define VECTOR_SEGMENT_NOT_PRESENT				11
#define VECTOR_STACK_FAULT_EXCEPTION			12
#define VECTOR_GENERAL_PROTECTION_EXCEPTION		13
#define VECTOR_PAGE_FAULT_EXCEPTION				14
#define VECTOR_X87_FLOATING_POINT_ERROR			16
#define VECTOR_ALIGNMENT_CHECK_EXCEPTION		17
#define VECTOR_MACHINE_CHECK_EXCEPTION			18
#define VECTOR_SIMD_FLOATING_POINT_EXCEPTION	19
#define VECTOR_VIRTUALIZATION_EXCEPTION			20

/*
 * Event injection interrupt types
 */
#define INTERRUPT_EXTERNAL							0
#define INTERRUPT_RESERVED							1
#define INTERRUPT_NMI								2
#define INTERRUPT_HARDWARE_EXCEPTION				3
#define INTERRUPT_SOFTWARE							4
#define INTERRUPT_PRIVILEGED_SOFTWARE_EXCEPTION		5
#define INTERRUPT_SOFTWARE_EXCEPTION				6
#define INTERRUPT_OTHER_EVENT						7

VOID VmInjectInterrupt(ULONG InterruptType, ULONG Vector, ULONG WriteLength);
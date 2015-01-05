#pragma once

#define DbgLog(Format, ...) DbgPrint("virtdbg[#%d][IRQL=0x%x](%s): " Format, KeGetCurrentProcessorNumber(), KeGetCurrentIrql(), __FUNCTION__, __VA_ARGS__);

NTSTATUS InitializeSegmentSelector(PSEGMENT_SELECTOR SegmentSelector, USHORT Selector, PUCHAR GdtBase);
ULONG AdjustControls(ULONG Ctl, ULONG Msr);
NTSTATUS FillGuestSelectorData(PVOID GdtBase, ULONG Segreg, USHORT Selector);
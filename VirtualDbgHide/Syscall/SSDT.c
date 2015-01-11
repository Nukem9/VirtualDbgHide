#include "stdafx.h"

ULONG_PTR GetNtoskrnlBase()
{
	#define IMAGE_DOS_SIGNATURE 0x5a4d

	//
	// Scan down from a given symbol’s address.
	// Align to PAGE_SIZE first.
	//
	ULONG_PTR addr	= (ULONG_PTR)&MmGetSystemRoutineAddress;
	addr			= (addr & ~0xfff);

	__try
	{
		while ((*(USHORT *)addr != IMAGE_DOS_SIGNATURE))
			addr -= PAGE_SIZE;

		return addr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return 0;
}

ULONG_PTR GetSSDTBase()
{
	//
	// The SSDT is found by using the pointer located inside of
	// KeAddSystemServiceTable, which is exported by NTOSKRNL.
	//
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"KeAddSystemServiceTable");

	PVOID KeAddSystemServiceTable = MmGetSystemRoutineAddress(&routineName);

	if (!KeAddSystemServiceTable)
		return 0;

	//
	// Get a copy of the function's code
	//
	UCHAR functionData[1024];
	ULONG functionSize = 0;
	RtlCopyMemory(functionData, KeAddSystemServiceTable, sizeof(functionData));

	for (ULONG i = 0; i < sizeof(functionData); i++)
	{
		if (functionData[i] == 0xC3)
		{
			functionSize = i + 1;
			break;
		}
	}

	//
	// Will fail if 0xC3 (RETN) is never found
	//
	if (functionSize <= 0)
		return 0;

	//
	// Determine the SSDT RVA with a byte scan
	//
	ULONG rva = 0;

	for (ULONG i = 0; i < functionSize; i++)
	{
		//
		// 48 83 BC 18 80 4A 35 00 00       cmp qword ptr [rax+rbx+354A80h], 0
		//
		if (memcmp(&functionData[i], "\x48\x83\xBC", 3) == 0)
		{
			//
			// Verify the zero
			//
			if (functionData[i + 8] == 0x00)
			{
				rva = *(ULONG *)&functionData[i + 4];
				break;
			}
		}
	}

	//
	// NtosnkrlBase + RVA = SSDT address
	//
	ULONG_PTR ssdtAddress = NtKernelBase + rva;

	//
	// Also check validity
	//
	if (!MmIsAddressValid((PVOID)ssdtAddress))
		return 0;

	return ssdtAddress;
}

ULONG_PTR GetSSDTEntry(ULONG TableIndex)
{
	ULONG_PTR entry = 0;

#ifdef _WIN64
	// SSDT pointers are relative to the base in X64
	entry = NtKernelSSDT + (*((ULONG *)NtKernelSSDT + TableIndex) >> 4);
#else
	// Otherwise it's 32-bit and a direct pointer
	entry = *(ULONG *)(NtKernelSSDT + (4 * TableIndex));
#endif

	//
	// Verify address
	//
	if (!MmIsAddressValid((PVOID)entry))
		return 0;

	return entry;
}
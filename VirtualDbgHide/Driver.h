#pragma once

#define TO_ULL(x)		(*(ULONGLONG *)(&x))
#define PA_PTR_INT64(x) (UINT64 *)(&((x).QuadPart))

//#include <ntddk.h>
#include <ntifs.h>
#include <intrin.h>

#include "vmx.h"
#include "Misc.h"
#include "virtdbg.h"

#include "Cpu.h"
#include "ControlArea.h"

#include "VTx.h"

#include "VmInterrupt.h"
#include "VmExitHandlers.h"
#include "VmExit.h"

#include "Syscall.h"
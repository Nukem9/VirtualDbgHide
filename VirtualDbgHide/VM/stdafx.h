#pragma once

#include <ntifs.h>
#include <intrin.h>

#define TO_ULL(x)		(*(ULONGLONG *)(&x))
#define PA_PTR_INT64(x) (UINT64 *)(&((x).QuadPart))

#include "amd64.h"
#include "vmx.h"
#include "Misc.h"

#include "Cpu.h"
#include "ControlArea.h"

#include "VTx.h"

#include "Vm.h"
#include "VmInterrupt.h"
#include "VmExitHandlers.h"
#include "VmExit.h"
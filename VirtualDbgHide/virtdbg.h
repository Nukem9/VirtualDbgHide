#pragma once

#include <ntddk.h>
#include "amd64.h"
#include "vmx.h"
#include "misc.h"

VOID VirtDbgStart(PVOID StartContext);
NTSTATUS StartVirtualization(PVOID GuestRsp);

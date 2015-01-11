#pragma once

VOID VmStart(PVOID StartContext);
CHAR VmIsActive();

NTSTATUS StartVirtualization(PVOID GuestRsp);

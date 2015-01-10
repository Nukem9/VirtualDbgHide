#pragma once

#include <ntifs.h>
#include "VM/stdafx.h"
#include "Syscall/stdafx.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DispatchIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
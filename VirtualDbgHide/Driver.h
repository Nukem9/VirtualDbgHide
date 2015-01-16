#pragma once

#include <ntifs.h>
#include "VM/stdafx.h"
#include "Syscall/stdafx.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
extern "C" VOID DriverUnload(PDRIVER_OBJECT DriverObject);

NTSTATUS DispatchIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
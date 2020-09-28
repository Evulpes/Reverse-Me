// ReverseMe-x64.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <psapi.h>

const int MESSAGE_LENGTH = 14;
const int CODECAVE_OFFSET = 0x2905;
const int CODECAVE_STORAGE_SIZE = 0x3;

//Add ?ts=4 to the end of the URL in GitHub for this .cpp file.

class AssemblyCode
{
	public:
		byte codeCave[80] =
		{
			0x49, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		//mov r10, 0x0				-- Move the address of memory we’ve reserved (codeCaveStorageAddr) in our application to R10
			0x41, 0xc6, 0x02, 0x00,											//mov [r10], 0x0			-- Set the first byte of our memory (codeCaveStorageAddr) to non-signalled
			0x44, 0x8a, 0x1a,												//mov r11b, [rdx]			-- Move the lower part of RDX, which contains the packet index, into R11B	
			0x45, 0x88, 0x5A, 0x1,											//mov [r10+1], r11b			-- Move R11B to the second byte of our memory					
			0x44, 0x8a, 0x5a, 0x01,											//mov r11b, [rdx+1]			-- Move the second byte of RDX, which contains the character, into R11B			
			0x45, 0x88, 0x5a, 0x02,											//mov [r10+2], r11b			-- Move R11B to the third byte of our memory					
			0x41, 0xc6, 0x02, 0x01,											//mov [r10], 0x1			-- Set the first byte of our memory (signalByte) to signalled								
			0x41, 0x80, 0x3a, 0x00,											//cmp [r10], 0x0			-- Wait for our application to finish reading the memory, at which point it set the byte (signalByte) to non-signalled		
			0x75, 0xfa,														//jne 0xfffffffffffffffc	-- While the byte is signalled, jump to the previous step
			#pragma region Predetermined Assembly
			0x48, 0x89, 0x54, 0x24, 0x10,									//mov [rsp+10], rdx
			0x48, 0x89, 0x4C, 0x24, 0x08,									//mov [rsp+8], rcx
			0x48, 0x8B, 0x44, 0x24, 0x08,									//mov rax, [rsp+0x8]
			0x48, 0x8B, 0x4C, 0x24, 0x10,									//mov rcx, [rsp+0xa]
			0x48, 0x89, 0x08,												//mov [rax], rcx
			0x48, 0x8B, 0x44, 0x24, 0x08,									//mov rax, [rsp+8]
			#pragma endregion
			0x49, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		//mov r10, 0x0				-- Move the address that we jumped from initially, +1, to R10	
			0x41, 0xff, 0xe2,												//jmp r10					-- Jump to R10			
		};
		byte call[23] =
		{
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		//mov rax, 0x0				-- Move codecave address to rax
			0xff, 0xe0,														//jmp rax
			0x90, 0x90, 0x90,0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90	//nop padding 				-- Overwrite with NOPS to codecave required replacements
		};
};
class UndocumentedInternals
{
	typedef LONG(NTAPI* _NtSuspendProcess)(IN HANDLE hProcess);
	typedef LONG(NTAPI* _NtResumeProcess)(IN HANDLE hProcess);

	public:
		_NtSuspendProcess NtSuspendProcess;
		_NtResumeProcess NtResumeProcess;
		UndocumentedInternals()
		{
			NtSuspendProcess = (_NtSuspendProcess)GetProcAddress(GetModuleHandle(L"ntdll"), "NtSuspendProcess");
			NtResumeProcess = (_NtResumeProcess)GetProcAddress(GetModuleHandle(L"ntdll"), "NtResumeProcess");
		}
};


int main()
{
	STARTUPINFO startupInfo = { sizeof(startupInfo) };
	PROCESS_INFORMATION processInformation;
	UndocumentedInternals nativeMethods;
	AssemblyCode assemblyCode;
	memset(&startupInfo, 0, sizeof(startupInfo));
	memset(&processInformation, 0, sizeof(processInformation));

	//Start the process in a suspended state so that changes to memory can be made prior to runtime
	bool ntStatus = CreateProcess(L"ReverseMe.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInformation);
	if (ntStatus != TRUE)
	{
		printf("Error: %d \n", GetLastError());
		system("pause");
		exit(0);
	};

	HMODULE modules[1024]{};
	DWORD cbNeeded;

	/*Temporarily resume to aquire the executable base module and address.
	Initially, the executable is discovered second, and stored in index 1, but is swapped to 0 upon discovery.
	*/
	nativeMethods.NtResumeProcess(processInformation.hProcess);
	while (!modules[1])
		EnumProcessModules(processInformation.hProcess, modules, sizeof(modules), &cbNeeded);
	
	//Resuspend the process after the first 2 modules are found
	nativeMethods.NtSuspendProcess(processInformation.hProcess);

	//The address at where to start the codeCave
	DWORD_PTR jmpFromAddr = (DWORD_PTR)modules[0] + CODECAVE_OFFSET;
	INT64 codeCaveAddr = (DWORD_PTR)VirtualAllocEx(processInformation.hProcess, NULL, sizeof(assemblyCode.codeCave), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	INT64 codeCaveStorageAddr = (DWORD_PTR)VirtualAllocEx(processInformation.hProcess, NULL, CODECAVE_STORAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	//Update the codeCave bytecode with the newly allocated codeCaveStorageAddr
	byte* codeCaveStoragePtr = (byte*)&codeCaveStorageAddr;
	for (int i = 2; i < 10; i++)
	{
		assemblyCode.codeCave[i] = *codeCaveStoragePtr;
		codeCaveStoragePtr++;
	}

	//Likewise with the call bytecode for the codeCaveAddr
	byte* codeCaveAddrPtr = (byte*)&codeCaveAddr;
	for (int i = 2; i < 10; i++)
	{
		assemblyCode.call[i] = *codeCaveAddrPtr;
		codeCaveAddrPtr++;
	}

	//Update the codeCave bytecode with the return jmp address
	byte* jmpFromAddrPtr = (byte*)&jmpFromAddr;
	for (int i = 69; i < 77; i++)
	{
		assemblyCode.codeCave[i] = *jmpFromAddrPtr;
		jmpFromAddrPtr++;

		if (i == 69) 
			assemblyCode.codeCave[i] += 0xc;
	}

	SIZE_T bytes;
	if (!WriteProcessMemory(processInformation.hProcess, (LPVOID)jmpFromAddr, assemblyCode.call, sizeof(assemblyCode.call)/sizeof(assemblyCode.call[0]), &bytes))
	{
		printf("Error writing the calling assembly: LastError: %d \n", GetLastError());
		system("pause");
		exit(0);
	};
	if (!WriteProcessMemory(processInformation.hProcess, (LPVOID)codeCaveAddr, assemblyCode.codeCave, sizeof(assemblyCode.codeCave)/sizeof(assemblyCode.codeCave[0]), &bytes))
	{
		printf("Error writing the codecave assembly: LastError: %d \n", GetLastError());
		system("pause");
		exit(0);
	};


	//Begin runtime
	nativeMethods.NtResumeProcess(processInformation.hProcess);

	byte codeCaveStorage[CODECAVE_STORAGE_SIZE] = {};
	byte signalByte[1] = { 0 };
	byte socketMessage[MESSAGE_LENGTH] = {};
	int charCounter = 0;


	while (true) 
	{
		if(!ReadProcessMemory(processInformation.hProcess, (LPVOID)codeCaveStorageAddr, codeCaveStorage, 0x3, &bytes))
		{
			printf("Error reading from the codecave storage, will print what was hooked and exit. LastError: %d \n", GetLastError());
			break;
		};

		//Check if the first byte in the codeCaveStorage is signalled
		if (codeCaveStorage[0] == 1)
		{
			//Move the character, at codeCaveStorage[2] into the socketMessageArray, checking the (zero-based [1]-1) index against the codeCaveStorage[1]
			socketMessage[codeCaveStorage[1]-1] = codeCaveStorage[2];

			charCounter++;
			
			//Set the signalByte (codeCaveStorage[0] / x64 [r10]) back to non signalled
			if (!WriteProcessMemory(processInformation.hProcess, (LPVOID)codeCaveStorageAddr, (LPCVOID)signalByte, 0x1, &bytes))
			{
				printf("Error writing to the signalByte [r10], will print what was hooked and exit. LastError: %d \n", GetLastError());
				break;
			};

			//If 14 true loops have been accumulated, the full message has been stored
			if (charCounter == MESSAGE_LENGTH)
				break;
		}
	}

	
	for (int i = 0; i < MESSAGE_LENGTH; i++)
		printf("%c", (char)socketMessage[i]);

	printf("\n");


	//Cleanup
	TerminateProcess(processInformation.hProcess, 0);
	CloseHandle(processInformation.hThread);
	CloseHandle(processInformation.hProcess);
	system("pause");
}






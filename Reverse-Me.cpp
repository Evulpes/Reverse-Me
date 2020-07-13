// ReverseMe-x64.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <psapi.h>

class AssemblyCode
{
public:
	byte codeCave[85] =
	{
		0x49, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		//mov r10, 0x0				-- Mov storage address to R15	
		0x41, 0xc6, 0x02, 0x00,											//mov [r10], 0x0			-- Set the busy byte to 0x00	
		#pragma region Predeterminded Assembly
		0x90, 0x90, 0x90, 0x90, 0x90,
		0x48, 0x89, 0x54, 0x24, 0x10,									//mov [rsp+10], rdx
		#pragma endregion
		0x44, 0x8a, 0x1a,												//mov r11b, [rdx]			-- Mov the lower part of RDX, which stores the packet index, into r14b		
		0x45, 0x88, 0x5A, 0x1,											//mov [r10+1], r11b			-- Mov r14b to the second byte of the allocated storage						
		0x44, 0x8a, 0x5a, 0x01,											//mov r11b, [rdx+1]			-- Mov the second byte of RDX, the character, into r14b				
		0x45, 0x88, 0x5a, 0x02,											//mov [r10+2], r11b			-- Mov r14b into the second byte of reserved memory							

		0x41, 0xc6, 0x02, 0x01,											//mov [r10], 0x1			-- Signal the busy byte as work complete									
		0x41, 0x80, 0x3a, 0x00,											//cmp [r10], 0x0			-- Wait for software to finish reading, byte will be updated to 0x00		
		0x75, 0xfa,														//jne 0xfffffffffffffffc	-- While software is busy, loop
		#pragma region Predeterminded Assembly
		0x48, 0x89, 0x4C, 0x24, 0x08,									//mov [rsp+8], rcx
		0x48, 0x8B, 0x44, 0x24, 0x08,									//mov rax, [rsp+0x8]
		0x48, 0x8B, 0x4C, 0x24, 0x10,									//mov rcx, [rsp+0xa]
		0x48, 0x89, 0x08,												//mov [rax], rcx
		0x48, 0x8B, 0x44, 0x24, 0x08,									//mov rax, [rsp+8]
		#pragma endregion
		0x49, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		//mov r10, 0x0				-- Mov the exit address to r15		
		0x41, 0xff, 0xe2,												//jmp r10					-- Jmp to the exit address			
	};
	byte call[23] =
	{
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		//mov rax, 0x0 				-- Move codecave address to rax
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

	bool ntStatus = CreateProcess(L"ReverseMe.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInformation);
	if (ntStatus != TRUE)
	{
		printf("Error: %d \n", GetLastError());
		system("pause");
		exit(0);
	};

	HMODULE modules[1024]{};
	DWORD cbNeeded;


	nativeMethods.NtResumeProcess(processInformation.hProcess);
	while (!modules[1])
	{
		EnumProcessModules(processInformation.hProcess, modules, sizeof(modules), &cbNeeded);
	};
	nativeMethods.NtSuspendProcess(processInformation.hProcess);


	DWORD_PTR writeAddr = (DWORD_PTR)modules[0] + 0x2905;
	INT64 codeCaveAddr = (DWORD_PTR)VirtualAllocEx(processInformation.hProcess, NULL, sizeof(assemblyCode.codeCave), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	INT64 busyCheckAddr = (DWORD_PTR)VirtualAllocEx(processInformation.hProcess, NULL, 0x3, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	//Convert the busy storage address into bytecode using a ptr, and then populate the bytes with the correct address
	byte* busyCheckAddrPtr = (byte*)&busyCheckAddr;
	for (int i = 2; i < 10; i++)
	{
		assemblyCode.codeCave[i] = *busyCheckAddrPtr;
		busyCheckAddrPtr++;
	}

	//Convert the codecave address into bytecode using a ptr, and then populate the bytes with the correct address
	byte* codeCaveAddrPtr = (byte*)&codeCaveAddr;
	for (int i = 2; i < 10; i++)
	{
		assemblyCode.call[i] = *codeCaveAddrPtr;
		codeCaveAddrPtr++;
	}

	byte* writeAddrPtr = (byte*)&writeAddr;
	for (int i = 74; i < 82; i++)
	{

		assemblyCode.codeCave[i] = *writeAddrPtr;
		writeAddrPtr++;
		if (i == 74) 
		{
			assemblyCode.codeCave[i] += 0xc;
		}
	}

	SIZE_T bytes;
	if (!WriteProcessMemory(processInformation.hProcess, (LPVOID)writeAddr, assemblyCode.call, 23, &bytes))
	{
		printf("Error: %d \n", GetLastError());
		system("pause");
		exit(0);
	};
	if (!WriteProcessMemory(processInformation.hProcess, (LPVOID)codeCaveAddr, assemblyCode.codeCave, sizeof(assemblyCode.codeCave) / sizeof(assemblyCode.codeCave[0]), &bytes))
	{
		printf("Error: %d \n", GetLastError());
		system("pause");
		exit(0);
	};




	nativeMethods.NtResumeProcess(processInformation.hProcess);

	byte busyByte[3] = {};
	byte byteOne[1] = { 0 };
	byte socketMessage[14] = {};
	int counter = 0;

	while (true) 
	{
		ReadProcessMemory(processInformation.hProcess, (LPVOID)busyCheckAddr, busyByte, 0x3, &bytes);

		if (busyByte[0] == 1)
		{
			socketMessage[busyByte[1]-1] = busyByte[2];
			counter++;

			
			WriteProcessMemory(processInformation.hProcess, (LPVOID)busyCheckAddr, (LPCVOID)byteOne, 0x1, &bytes);


			if (counter == 14)
			{
				break;
			}
		}
	}

	for (size_t i = 0; i < 14; i++)
	{
		printf("%c", (char)socketMessage[i]);
	}
	printf("\n");

	TerminateProcess(processInformation.hProcess, 0);
	CloseHandle(processInformation.hThread);
	CloseHandle(processInformation.hProcess);
	system("pause");
}






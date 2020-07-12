// ReverseMe-x64.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <psapi.h>

class AssemblyCode
{
public:
	byte codeCave[33] =
	{
		0x4C, 0x89, 0x44, 0x24, 0x12,	//mov [rsp+0x12], r8
		0x48, 0x89, 0x54, 0x24, 0x0A,	//mov [rsp+0xa], rdx
		0x48, 0x89, 0x4C, 0x24, 0x08,	//mov [rsp+0x8], rcx
		0x48, 0x8B, 0x44, 0x24, 0x08,	//mov rax, [rsp+0x8]
		0x48, 0x8B, 0x4C, 0x24, 0x0A,   //mov rcx, [rsp+0xa]
		0x48, 0x89, 0x08,				//mov [rax], rcx
		0x48, 0x8B, 0x44, 0x24, 0x08    //mov rax, [rsp+0x8]
	};
	byte call[23] =
	{
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,			//mov rax, 0x0
		0xff, 0xe0,															//jmp rax
		0x90, 0x90, 0x90,0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90		//nop padding
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
	byte* ptr = (byte*)&codeCaveAddr;


	for (int i = 2; i < 10; i++)
	{
		assemblyCode.call[i] = *ptr;
		ptr++;
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
	TerminateProcess(processInformation.hProcess, 0);
	CloseHandle(processInformation.hThread);
	CloseHandle(processInformation.hProcess);
}






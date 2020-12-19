#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <fstream>
#include <thread>

#include <windows.h>
#include <shlwapi.h>
#include <Tlhelp32.h>



DWORD GetPIDForProcess(wchar_t* Str)
{
	BOOL            working = 0;
	PROCESSENTRY32 lppe = { 0 };
	DWORD            targetPid = 0;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot)
	{
		lppe.dwSize = sizeof(lppe);
		working = Process32First(hSnapshot, &lppe);
		while (working)
		{
			if (std::wstring(lppe.szExeFile) == Str)
			{
				targetPid = lppe.th32ProcessID;
				break;
			}
			working = Process32Next(hSnapshot, &lppe);
		}
	}
	CloseHandle(hSnapshot);
	return targetPid;
}


int main()
{
	//getchar();
	//ReadProcessMemory(nullptr, nullptr, nullptr, 0, 0);
	//MessageBoxA(NULL, NULL, NULL, NULL);
	LoadLibraryA("AADebug.dll");

	//__debugbreak();

	//ULONG_PTR Addr = 0xff6a0000;//0x7ff606730000;// 
	//ULONG_PTR p = 0;
	//HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetPIDForProcess(L"calc.exe"));
	////std::cout << GetPIDForProcess(L"notepad.exe");
	////HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetPIDForProcess(L"notepad.exe")); 
	//ReadProcessMemory(handle, (LPCVOID)Addr, &p, 8, 0);
	//std::cout << std::hex << p << std::endl;
	//DWORD lpflOldProtect = 0;
	//VirtualProtectEx(handle, (LPVOID)Addr, 8, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
	//int a = GetLastError();
	//p = 0;
	//WriteProcessMemory(handle, (LPVOID)Addr, &p, 8, 0);
	//ReadProcessMemory(handle, (LPCVOID)Addr, &p, 8, 0);
	//std::cout << std::hex << p << std::endl;
	
	STARTUPINFOA startupinfo;
	PROCESS_INFORMATION processinformation;
	RtlZeroMemory(&startupinfo, sizeof(STARTUPINFO));
	RtlZeroMemory(&processinformation, sizeof(PROCESS_INFORMATION));

	/*if (!CreateProcessA("C:\\Windows\\System32\\calc.exe", nullptr, nullptr, nullptr,
		false, DEBUG_PROCESS, nullptr, nullptr, &startupinfo, &processinformation))*/

	/*if (!CreateProcessA("F:\\Project\\AADebug\\x64\\Debug\\al-khaser.exe", nullptr, nullptr, nullptr,
		false, DEBUG_ONLY_THIS_PROCESS|DEBUG_PROCESS, nullptr, nullptr, &startupinfo, &processinformation))*/

		/*if (!CreateProcessA("F:\\Project\\AADebug\\x64\\Debug\\AADebugBeDebuger.exe", nullptr, nullptr, nullptr,
			false, 0, nullptr, nullptr, &startupinfo, &processinformation))*/

	if (!CreateProcessA("C:\\Users\\Administrator\\Desktop\\al-khaser.exe", nullptr, nullptr, nullptr,
		false, 0, nullptr, nullptr, &startupinfo, &processinformation))
	{
		std::cout << "error1:"<<GetLastError() << std::endl;
		getchar();
		return 0;
	}

	if (!DebugActiveProcess(processinformation.dwProcessId))
	{
		getchar();
		return 0;
		std::cout << "error2:" << GetLastError() << std::endl;
	}

	DEBUG_EVENT debugevent;
	while (WaitForDebugEvent(&debugevent,INFINITE))
	{
		if (debugevent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
		{
			std::cout << "catch int 3" << std::endl;
		}

		switch (debugevent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
		{
			std::cout << "CreateProcessInfoStartAddress:";
			std::cout << std::hex << (ULONG_PTR)debugevent.u.CreateProcessInfo.lpBaseOfImage << std::endl;
		}
		case CREATE_THREAD_DEBUG_EVENT:
		{
			std::cout << "StartAddress:";
			std::cout << std::hex << (ULONG_PTR)debugevent.u.CreateThread.lpStartAddress << std::endl;
		}
		case LOAD_DLL_DEBUG_EVENT:
		{
			std::cout << "ModleBase:";
			std::cout << std::hex << (ULONG_PTR)debugevent.u.LoadDll.lpBaseOfDll << std::endl;
			//std::cout << (char*)debugevent.u.LoadDll.lpImageName << std::endl;
		}
		case EXIT_PROCESS_DEBUG_EVENT:
			break;
		default:
			break;
		}

		bool tempb= ContinueDebugEvent(debugevent.dwProcessId,debugevent.dwThreadId,DBG_CONTINUE);
		if (tempb == false)
		{
		}
	}

	getchar();
	return 0;
}
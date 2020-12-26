#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <fstream>

#include <windows.h>

#include "wow64ext/wow64ext.h"


using namespace std;


typedef struct _UNICODE_STRING { // UNICODE_STRING structure
	USHORT Length;
	USHORT MaximumLength;
	//PWSTR  Buffer;
	ULONG Reserve;//wow64¶ÔÆë
	ULONG64 Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;


typedef NTSTATUS(WINAPI *_LdrLoadDll) //LdrLoadDll function prototype
(
	IN PWCHAR PathToFile OPTIONAL,
	IN ULONG Flags OPTIONAL,
	IN PUNICODE_STRING ModuleFileName,
	OUT PHANDLE ModuleHandle
);

void test()
{
	UNICODE_STRING a;
	RtlZeroMemory(&a, sizeof(UNICODE_STRING));
	wchar_t c[] = L"C:\\Users\\Administrator\\Desktop\\TEST_DLL.dll";
	//wchar_t c[] = L"F:\\Project\\Test\\TEST_DLL\\x64\\Debug\\TEST_DLL.dll";
	a.Length = sizeof(c) - 2;
	a.MaximumLength = sizeof(c);
	a.Buffer = (ULONG64)&c;
	
	ULONG64 b = 0;
	ULONG64 modle_addr = GetModuleHandle64(L"ntdll.dll");
	ULONG64 func = GetProcAddress64(modle_addr, "LdrLoadDll");;

	X64Call(func, 4, (ULONG64)0, (ULONG64)0, (ULONG64)&a, (ULONG64)&b);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		Wow64ExtInit();
		test();
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

#include "AADebug.h"
#include "DetoursHook.h"
#include "HookFunc.h"

HookFunc *_HookFunc = nullptr;

bool AADebug::Init()
{
	HANDLE device = CreateFileA("\\\\.\\AADebug", GENERIC_READ | GENERIC_WRITE, 0,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (device == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "CreateFileA", NULL, NULL);
		return false;
	}
	_HookFunc = new HookFunc(device);
	if (!_HookFunc)
	{
		MessageBoxA(NULL, "HookFunc", NULL, NULL);
		return false;
	}

	return true;
}

bool AADebug::StartHook()
{
	ULONG ret = DetourTransactionBegin();
	if (ret != NO_ERROR)
	{
		return false;
	}

	ret = DetourUpdateThread(GetCurrentThread());
	if (ret != NO_ERROR)
	{
		return false;
	}
	
	_Original_ReadVirtualMemory = DetoursHook("Ntdll.dll", "NtReadVirtualMemory", HookFunc::NewNtReadVirtualMemory);
	if (!_Original_ReadVirtualMemory)
	{
		return false;
	}

	_Original_WriteVirtualMemory = DetoursHook("Ntdll.dll", "NtWriteVirtualMemory", HookFunc::NewNtWriteVirtualMemory);
	if (!_Original_WriteVirtualMemory)
	{
		return false;
	}

	/*_Original_ProtectVirtualMemory = DetoursHook("Ntdll.dll", "NtProtectVirtualMemory", HookFunc::NewNtProtectVirtualMemory);
	if (!_Original_ProtectVirtualMemory)
	{
		return false;
	}*/

	_Original_NtOpenProcess = DetoursHook("Ntdll.dll", "NtOpenProcess", HookFunc::NewNtOpenProcess);
	if (!_Original_NtOpenProcess)
	{
		return false;
	}

	_Original_DebugActiveProcess = DetoursHook("Kernel32.dll", "DebugActiveProcess", HookFunc::NewDebugActiveProcess);
	if (!_Original_DebugActiveProcess)
	{
		return false;
	}

	_Original_NtCreateDebugObject = DetoursHook("Ntdll.dll", "NtCreateDebugObject", HookFunc::NewNtCreateDebugObject);
	if (!_Original_NtCreateDebugObject)
	{
		return false;
	}

	_Original_NtDebugActiveProcess = DetoursHook("Ntdll.dll", "NtDebugActiveProcess", HookFunc::NewNtDebugActiveProcess);
	if (!_Original_NtDebugActiveProcess)
	{
		return false;
	}

	/*_Original_NtRemoveProcessDebug = DetoursHook("Ntdll.dll", "NtRemoveProcessDebug", HookFunc::NewNtRemoveProcessDebug);
	if (!_Original_NtRemoveProcessDebug)
	{
		return false;
	}*/

	_Original_DbgUiWaitStateChange = DetoursHook("Ntdll.dll", "DbgUiWaitStateChange", HookFunc::NewDbgUiWaitStateChange);
	if (!_Original_DbgUiWaitStateChange)
	{
		return false;
	}

	_Original_DbgUiContinue = DetoursHook("Ntdll.dll", "DbgUiContinue", HookFunc::NewDbgUiContinue);
	if (!_Original_DbgUiContinue)
	{
		return false;
	}

	_Original_DbgUiGetThreadDebugObject = DetoursHook("Ntdll.dll", "DbgUiGetThreadDebugObject", HookFunc::NewDbgUiGetThreadDebugObject);
	if (!_Original_DbgUiGetThreadDebugObject)
	{
		return false;
	}

	_Original_DbgUiConnectToDbg = DetoursHook("Ntdll.dll", "DbgUiConnectToDbg", HookFunc::NewDbgUiConnectToDbg);
	if (!_Original_DbgUiConnectToDbg)
	{
		return false;
	}

	_Original_DbgUiDebugActiveProcess = DetoursHook("Ntdll.dll", "DbgUiDebugActiveProcess", HookFunc::NewDbgUiDebugActiveProcess);
	if (!_Original_DbgUiDebugActiveProcess)
	{
		return false;
	}

	ret = DetourTransactionCommit();
	if (ret != NO_ERROR)
	{
		return false;
	}

	return true;
}


bool AADebug::Test()
{
	/*_Original_NtOpenProcess = DetoursHook("Ntdll.dll", "NtCreateDebugObject", NtCreateDebugObject);
	if (!_Original_NtOpenProcess)
	{
		return false;
	}*/

	return StartHook();
	return true;
}
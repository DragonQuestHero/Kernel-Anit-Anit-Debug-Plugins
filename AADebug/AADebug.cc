#include "AADebug.h"
#include "DetoursHook.h"
#include "HookFunc.h"

#include "FindSymbl/FindAddress.h"

HookFunc *_HookFunc = nullptr;

bool AADebug::Init()
{
	CFindAddress *FindAddr = new CFindAddress();

	DbgkpWakeTarget = FindAddr->FindSymAddress("DbgkpWakeTarget");
	if (DbgkpWakeTarget == 0)
	{
		return false;
	}

	PsResumeThread = FindAddr->FindSymAddress("PsResumeThread");
	if (PsResumeThread == 0)
	{
		return false;
	}

	PsSuspendThread = FindAddr->FindSymAddress("PsSuspendThread");
	if (PsSuspendThread == 0)
	{
		return false;
	}

	PsGetNextProcessThread = FindAddr->FindSymAddress("PsGetNextProcessThread");
	if (PsGetNextProcessThread == 0)
	{
		return false;
	}

	DbgkpSectionToFileHandle = FindAddr->FindSymAddress("DbgkpSectionToFileHandle");
	if (DbgkpSectionToFileHandle == 0)
	{
		return false;
	}

	MmGetFileNameForAddress = FindAddr->FindSymAddress("MmGetFileNameForAddress");
	if (MmGetFileNameForAddress == 0)
	{
		return false;
	}

	KiDispatchException = FindAddr->FindSymAddress("KiDispatchException");
	if (KiDispatchException == 0)
	{
		return false;
	}

	DbgkForwardException = FindAddr->FindSymAddress("DbgkForwardException");
	if (DbgkForwardException == 0)
	{
		return false;
	}

	DbgkpSuspendProcess = FindAddr->FindSymAddress("DbgkpSuspendProcess");
	if (DbgkpSuspendProcess == 0)
	{
		return false;
	}

	KeThawAllThreads = FindAddr->FindSymAddress("KeThawAllThreads");
	if (KeThawAllThreads == 0)
	{
		return false;
	}

	DbgkDebugObjectType = FindAddr->FindSymAddress("DbgkDebugObjectType");
	if (DbgkDebugObjectType == 0)
	{
		return false;
	}

	//return true;//test

	HANDLE device = CreateFileA("\\\\.\\AADebug", GENERIC_READ | GENERIC_WRITE, 0,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (device == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	_HookFunc = new HookFunc(device);
	if (!_HookFunc)
	{
		return false;
	}

	Message_Init temp_message;
	temp_message.DbgkpWakeTarget = DbgkpWakeTarget;
	temp_message.PsResumeThread = PsResumeThread;
	temp_message.PsSuspendThread = PsSuspendThread;
	temp_message.PsGetNextProcessThread = PsGetNextProcessThread;
	temp_message.DbgkpSectionToFileHandle = DbgkpSectionToFileHandle;
	temp_message.MmGetFileNameForAddress = MmGetFileNameForAddress;
	temp_message.KiDispatchException = KiDispatchException;
	temp_message.DbgkForwardException = DbgkForwardException;
	temp_message.DbgkpSuspendProcess = DbgkpSuspendProcess;
	temp_message.KeThawAllThreads = KeThawAllThreads;
	temp_message.DbgkDebugObjectType = DbgkDebugObjectType;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	NTSTATUS status = ZwDeviceIoControlFile(device, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_Init,
		&temp_message, sizeof(Message_Init),
		&temp_message, sizeof(Message_Init));
	if (NT_SUCCESS(status))
	{
		return true;
	}

	MessageBoxA(NULL, NULL, NULL, NULL);
	return false;
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

	_Original_ProtectVirtualMemory = DetoursHook("Ntdll.dll", "NtProtectVirtualMemory", HookFunc::NewNtProtectVirtualMemory);
	if (!_Original_ProtectVirtualMemory)
	{
		return false;
	}

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

	_Original_NtRemoveProcessDebug = DetoursHook("Ntdll.dll", "NtRemoveProcessDebug", HookFunc::NewNtRemoveProcessDebug);
	if (!_Original_NtRemoveProcessDebug)
	{
		return false;
	}
	
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
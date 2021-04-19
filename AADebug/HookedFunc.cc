#include "HookFunc.h"
//#include "ntdll.h"
//#include "ntstatus.h"

//#include "wow64ext/wow64ext.h"

HANDLE HookFunc::_Io_Handle = nullptr;
HANDLE HookFunc::_DebugObjectHandle = nullptr;


NTSTATUS NTAPI HookFunc::NewNtWriteVirtualMemory(
	IN  HANDLE ProcessHandle,
	OUT PVOID BaseAddress,
	IN  PVOID Buffer,
	IN  SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL)
{
	Message_NtReadWriteVirtualMemory temp_message = { 0 };
	temp_message.ProcessId = (HANDLE)GetProcessId(ProcessHandle);
	temp_message.BaseAddress = BaseAddress;
	temp_message.Buffer = Buffer;
	temp_message.BufferBytes = BufferSize;
	temp_message.ReturnBytes = NumberOfBytesWritten;
	temp_message.Read = false;
	return NewNtReadWriteVirtualMemory(&temp_message);
}

NTSTATUS NTAPI HookFunc::NewNtReadVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_bytecap_(BufferBytes) PVOID Buffer,
	_In_ SIZE_T BufferBytes,
	_Out_opt_ PSIZE_T ReturnBytes)
{
	Message_NtReadWriteVirtualMemory temp_message = { 0 };
	temp_message.ProcessId = (HANDLE)GetProcessId(ProcessHandle);
	temp_message.BaseAddress = BaseAddress;
	temp_message.Buffer = Buffer;
	temp_message.BufferBytes = BufferBytes;
	temp_message.ReturnBytes = ReturnBytes;
	temp_message.Read = true;
	return NewNtReadWriteVirtualMemory(&temp_message);
}

NTSTATUS NTAPI HookFunc::NewNtReadWriteVirtualMemory(Message_NtReadWriteVirtualMemory *temp_message)
{
	NTSTATUS status = 0;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtReadWriteVirtualMemory,
		temp_message, sizeof(Message_NtReadWriteVirtualMemory),
		temp_message, sizeof(Message_NtReadWriteVirtualMemory));
	return status;
}

NTSTATUS NTAPI HookFunc::NewNtProtectVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtect,
	_Out_ PULONG OldProtect)
{
	NTSTATUS status = 0;
	Message_NtProtectVirtualMemory temp_message = { 0 };
	temp_message.ProcessHandle = ProcessHandle;
	temp_message.BaseAddress = BaseAddress;
	temp_message.RegionSize = RegionSize;
	temp_message.NewProtect = NewProtect;
	temp_message.OldProtect = OldProtect;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtProtectVirtualMemory,
		&temp_message, sizeof(Message_NtProtectVirtualMemory),
		&temp_message, sizeof(Message_NtProtectVirtualMemory));
	return status;
}

NTSTATUS NTAPI HookFunc::NewNtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN OPTIONAL PCLIENT_ID ClientId)
{
	NTSTATUS status = 0;
	Message_NewNtOpenProcess temp_message = { 0 };
	temp_message.ProcessHandle = ProcessHandle;
	temp_message.DesiredAccess = DesiredAccess;
	temp_message.ObjectAttributes = ObjectAttributes;
	temp_message.ClientId = ClientId;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtOpenProcess,
		&temp_message, sizeof(Message_NewNtOpenProcess),
		&temp_message, sizeof(Message_NewNtOpenProcess));
	return status;
}

BOOL NTAPI HookFunc::NewDebugActiveProcess(DWORD dwProcessId)
{
	HANDLE Process;
	NTSTATUS Status;

	Status = NewDbgUiConnectToDbg();
	if (!NT_SUCCESS(Status)) 
	{
		return FALSE;
	}
	
	Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (Process == NULL) 
	{
		return FALSE;
	}

	Status = NewDbgUiDebugActiveProcess(Process);
	if (!NT_SUCCESS(Status)) 
	{
		NtClose(Process);
		return FALSE;
	}

	NtClose(Process);
	return TRUE;
}

NTSTATUS NTAPI HookFunc::NewNtDebugActiveProcess(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle)
{
	NTSTATUS status = 0;
#ifdef _AMD64_
	Message_NewNtDebugActiveProcess temp_message = { 0 };
	temp_message.ProcessId = (HANDLE)GetProcessId(ProcessHandle);//DebugObjectHandle就是目标进程ID
	temp_message.ProcessHandle = ProcessHandle;
	temp_message.DebugObjectHandle = DebugObjectHandle;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtDebugActiveProcess,
		&temp_message, sizeof(Message_NewNtDebugActiveProcess),
		&temp_message, sizeof(Message_NewNtDebugActiveProcess));
#else
	Message_NewNtDebugActiveProcess64 temp_message = { 0 };
	temp_message.ProcessId = (ULONG64)GetProcessId(ProcessHandle);//DebugObjectHandle就是目标进程ID
	temp_message.ProcessHandle = (ULONG64)ProcessHandle;
	temp_message.DebugObjectHandle = (ULONG64)DebugObjectHandle;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtDebugActiveProcess,
		&temp_message, sizeof(Message_NewNtDebugActiveProcess),
		&temp_message, sizeof(Message_NewNtDebugActiveProcess));
#endif // _AMD64_
	return status;
}

NTSTATUS NTAPI HookFunc::NewNtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags)
{
	NTSTATUS status = 0;
#ifdef _AMD64_
	Message_NewNtCreateDebugObject temp_message = { 0 };
	temp_message.DebugObjectHandle = DebugObjectHandle;
	temp_message.DesiredAccess = DesiredAccess;
	temp_message.ObjectAttributes = ObjectAttributes;
	temp_message.Flags = Flags;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtCreateDebugObject,
		&temp_message, sizeof(Message_NewNtCreateDebugObject),
		&temp_message, sizeof(Message_NewNtCreateDebugObject));
#else
	UNICODE_STRING64 temp_str = { 0 };//本就未初始化
	

	//Wow64ExtInit();
	//ULONG64 addr64 = VirtualAllocEx64(GetCurrentProcess(), NULL, sizeof(OBJECT_ATTRIBUTES64), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//if (addr64 == 0)
	//{
	//	//MessageBoxA(NULL, NULL, NULL, NULL);
	//}

	OBJECT_ATTRIBUTES64 temp_obj = { 0 };
	temp_obj.Length = sizeof(OBJECT_ATTRIBUTES64);
	temp_obj.ObjectName = (ULONG64)ObjectAttributes->ObjectName;
	/*OBJECT_ATTRIBUTES64 *temp_obj = new OBJECT_ATTRIBUTES64();
	temp_obj->Length = sizeof(OBJECT_ATTRIBUTES64);*/
	

	Message_NewNtCreateDebugObject64 temp_message = { 0 };
	temp_message.DebugObjectHandle = (ULONG64)DebugObjectHandle;
	temp_message.DesiredAccess = DesiredAccess;
	temp_message.ObjectAttributes = (ULONG64)&temp_obj;
	temp_message.Flags = Flags;


	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtCreateDebugObject,
		&temp_message, sizeof(Message_NewNtCreateDebugObject64),
		&temp_message, sizeof(Message_NewNtCreateDebugObject64));


	ObjectAttributes->Attributes = temp_obj.Attributes;
	ObjectAttributes->Length = 0x18;
	ObjectAttributes->RootDirectory = (HANDLE)temp_obj.RootDirectory;
	ObjectAttributes->SecurityDescriptor = (PVOID)temp_obj.SecurityDescriptor;
	ObjectAttributes->SecurityQualityOfService = (PVOID)temp_obj.SecurityQualityOfService;
	/*if (temp_str.Buffer != 0)//未初始化
	{
		ObjectAttributes->ObjectName->Buffer = (PWSTR)temp_str.Buffer;
	}
	ObjectAttributes->ObjectName->Length = temp_str.Length;
	ObjectAttributes->ObjectName->MaximumLength = temp_str.MaximumLength;*/
	

#endif // _AMD64_

	
	return status;
}

NTSTATUS NTAPI HookFunc::NewNtRemoveProcessDebug(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle)
{
	NTSTATUS status = 0;
#ifdef _AMD64_
	Message_NewNtRemoveProcessDebug temp_message = { 0 };
	temp_message.ProcessId = (HANDLE)GetProcessId(ProcessHandle);//同NewNtDebugActiveProcess
	temp_message.ProcessHandle = ProcessHandle;
	temp_message.DebugObjectHandle = DebugObjectHandle;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtRemoveProcessDebug,
		&temp_message, sizeof(Message_NewNtRemoveProcessDebug),
		&temp_message, sizeof(Message_NewNtRemoveProcessDebug));
#else
	Message_NewNtRemoveProcessDebug temp_message = { 0 };
	temp_message.ProcessId = (HANDLE)GetProcessId(ProcessHandle);//同NewNtDebugActiveProcess
	temp_message.ProcessHandle = ProcessHandle;
	temp_message.DebugObjectHandle = DebugObjectHandle;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtRemoveProcessDebug,
		&temp_message, sizeof(Message_NewNtRemoveProcessDebug),
		&temp_message, sizeof(Message_NewNtRemoveProcessDebug));
#endif // _AMD64_
	return status;
}





int WINAPI TestMessageBoxA(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType)
{
	MessageBoxW(NULL, L"1", L"2", NULL);
	return 0;
}

NTSTATUS WINAPI HookFunc::NewDbgUiConnectToDbg(VOID)
{
	NTSTATUS Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES oa;
	if (_DebugObjectHandle == nullptr)
	{
		InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
		Status = NewNtCreateDebugObject(&_DebugObjectHandle, DEBUG_ALL_ACCESS, &oa, DEBUG_KILL_ON_CLOSE);
	}
	return Status;
}

NTSTATUS NTAPI HookFunc::NewDbgUiDebugActiveProcess(IN HANDLE Process)
{
	NTSTATUS Status;
	Status = NewNtDebugActiveProcess(Process, _DebugObjectHandle);
	if (NT_SUCCESS(Status)) 
	{
		Status = DbgUiIssueRemoteBreakin(Process);
		if (!NT_SUCCESS(Status)) 
		{
			Status = NewNtRemoveProcessDebug(Process, _DebugObjectHandle);//Status = DbgUiStopDebugging(Process);
		}
	}
	return Status;
}

NTSTATUS NTAPI HookFunc::NewDbgUiWaitStateChange(
	OUT PDBGUI_WAIT_STATE_CHANGE StateChange,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	return NtWaitForDebugEvent(_DebugObjectHandle, TRUE, Timeout, StateChange);
}

NTSTATUS NTAPI HookFunc::NewDbgUiContinue(
	IN PCLIENT_ID AppClientId,
	IN NTSTATUS ContinueStatus)
{
	 return NtDebugContinue(_DebugObjectHandle, AppClientId, ContinueStatus);
}

HANDLE NTAPI HookFunc::NewDbgUiGetThreadDebugObject()
{
	return _DebugObjectHandle;
}
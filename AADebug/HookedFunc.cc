#include "HookFunc.h"
//#include "ntdll.h"
//#include "ntstatus.h"

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
		&temp_message, sizeof(Message_NtReadWriteVirtualMemory),
		&temp_message, sizeof(Message_NtReadWriteVirtualMemory));
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
		&temp_message, sizeof(Message_NtReadWriteVirtualMemory),
		&temp_message, sizeof(Message_NtReadWriteVirtualMemory));
	return status;
}

BOOL NTAPI HookFunc::NewDebugActiveProcess(DWORD dwProcessId)
{
	HANDLE Process;
	NTSTATUS Status;

	Status = PrivateDbgUiConnectToDbg();
	if (!NT_SUCCESS(Status)) 
	{
		return FALSE;
	}
	
	Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (Process == NULL) 
	{
		return FALSE;
	}

	Status = PrivateDbgUiDebugActiveProcess(Process);
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
	Message_NewNtDebugActiveProcess temp_message = { 0 };
	temp_message.ProcessId = (HANDLE)GetProcessId(ProcessHandle);//DebugObjectHandle就是目标进程ID
	temp_message.ProcessHandle = ProcessHandle;
	temp_message.DebugObjectHandle = DebugObjectHandle;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtDebugActiveProcess,
		&temp_message, sizeof(Message_NtReadWriteVirtualMemory),
		&temp_message, sizeof(Message_NtReadWriteVirtualMemory));
	return status;
}

NTSTATUS NTAPI HookFunc::NewNtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags)
{
	NTSTATUS status = 0;
	Message_NewNtCreateDebugObject temp_message = { 0 };
	temp_message.DebugObjectHandle = DebugObjectHandle;
	temp_message.DesiredAccess = DesiredAccess;
	temp_message.ObjectAttributes = ObjectAttributes;
	temp_message.Flags = Flags;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtCreateDebugObject,
		&temp_message, sizeof(Message_NtReadWriteVirtualMemory),
		&temp_message, sizeof(Message_NtReadWriteVirtualMemory));
	return status;
}

NTSTATUS NTAPI HookFunc::NewNtRemoveProcessDebug(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle)
{
	NTSTATUS status = 0;
	Message_NewNtRemoveProcessDebug temp_message = { 0 };
	temp_message.ProcessId = (HANDLE)GetProcessId(ProcessHandle);//同NewNtDebugActiveProcess
	temp_message.ProcessHandle = ProcessHandle;
	temp_message.DebugObjectHandle = DebugObjectHandle;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	status = ZwDeviceIoControlFile(_Io_Handle, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_NtRemoveProcessDebug,
		&temp_message, sizeof(Message_NtReadWriteVirtualMemory),
		&temp_message, sizeof(Message_NtReadWriteVirtualMemory));
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

NTSTATUS WINAPI HookFunc::PrivateDbgUiConnectToDbg(VOID)
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

NTSTATUS NTAPI HookFunc::PrivateDbgUiDebugActiveProcess(IN HANDLE Process)
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
	 NTSTATUS s = NtDebugContinue(_DebugObjectHandle, AppClientId, ContinueStatus);
	 return s;
}
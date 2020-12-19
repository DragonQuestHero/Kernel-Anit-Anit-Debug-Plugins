#pragma once
#include <windows.h>
#include "ntdll.h"

#include "..\AADebugKernel\NativeMessage.h"



class HookFunc
{
public:
	HookFunc(HANDLE handle)
	{
		_Io_Handle = handle;
	}
	~HookFunc() = default;
public:
	static NTSTATUS NTAPI NewNtWriteVirtualMemory(
		IN  HANDLE ProcessHandle,
		OUT PVOID BaseAddress,
		IN  PVOID Buffer,
		IN  SIZE_T BufferSize,
		OUT PSIZE_T NumberOfBytesWritten OPTIONAL);
	static NTSTATUS NTAPI NewNtReadVirtualMemory(
		_In_ HANDLE  ProcessHandle,
		_In_opt_ PVOID BaseAddress,
		_Out_bytecap_(BufferBytes) PVOID Buffer,
		_In_ SIZE_T BufferBytes,
		_Out_opt_ PSIZE_T ReturnBytes);
	static NTSTATUS NTAPI NewNtReadWriteVirtualMemory(Message_NtReadWriteVirtualMemory *temp_message);
	static NTSTATUS NTAPI NewNtProtectVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID *BaseAddress,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG NewProtect,
		_Out_ PULONG OldProtect);
	static NTSTATUS NTAPI NewNtOpenProcess(
		OUT PHANDLE ProcessHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN OPTIONAL PCLIENT_ID ClientId);
public:
	static BOOL NTAPI NewDebugActiveProcess(DWORD dwProcessId);
	static NTSTATUS NTAPI NewNtDebugActiveProcess(
		IN HANDLE ProcessHandle,
		IN HANDLE DebugObjectHandle);
public:
	static NTSTATUS NTAPI NewNtCreateDebugObject(
		OUT PHANDLE DebugObjectHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN ULONG Flags);
	static NTSTATUS NTAPI NewNtRemoveProcessDebug(
		IN HANDLE ProcessHandle,
		IN HANDLE DebugObjectHandle);
public:
	static NTSTATUS NTAPI NewDbgUiWaitStateChange(
		OUT PDBGUI_WAIT_STATE_CHANGE StateChange,
		IN PLARGE_INTEGER Timeout OPTIONAL);
	static NTSTATUS NTAPI NewDbgUiContinue(
		IN PCLIENT_ID AppClientId,
		IN NTSTATUS ContinueStatus);
public:
	static int WINAPI TestMessageBoxA(
		_In_opt_ HWND hWnd,
		_In_opt_ LPCSTR lpText,
		_In_opt_ LPCSTR lpCaption,
		_In_ UINT uType);
private:
	static NTSTATUS WINAPI PrivateDbgUiConnectToDbg(VOID);
	static NTSTATUS NTAPI PrivateDbgUiDebugActiveProcess(IN HANDLE Process);
private:
	static HANDLE _Io_Handle;
	static HANDLE _DebugObjectHandle;
};


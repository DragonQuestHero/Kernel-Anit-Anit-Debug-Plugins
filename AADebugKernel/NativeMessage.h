#pragma once


#if _KERNEL_MODE
#include "CRT/NtSysAPI_Func.hpp"
#else
#include <windows.h>
#endif

struct Message_Init
{
	ULONG_PTR DbgkpWakeTarget = 0;
	ULONG_PTR PsResumeThread = 0;
	ULONG_PTR PsSuspendThread = 0;
	ULONG_PTR PsGetNextProcessThread = 0;
	ULONG_PTR DbgkpSectionToFileHandle = 0;
	ULONG_PTR MmGetFileNameForAddress = 0;
	ULONG_PTR KiDispatchException = 0;
	ULONG_PTR DbgkForwardException = 0;
	ULONG_PTR DbgkpSuspendProcess = 0;
	ULONG_PTR KeThawAllThreads = 0;

	ULONG_PTR DbgkDebugObjectType = 0;
};

struct Message_NtReadWriteVirtualMemory
{
	HANDLE ProcessId;
	HANDLE ProcessHandle;
	PVOID BaseAddress;
	PVOID Buffer;
	SIZE_T BufferBytes;
	PSIZE_T ReturnBytes;
	bool Read;
};

struct Message_NtProtectVirtualMemory
{
	HANDLE ProcessHandle;
	PVOID *BaseAddress;
	PSIZE_T RegionSize;
	ULONG NewProtect;
	PULONG OldProtect;
};

struct Message_NewNtOpenProcess
{
	PHANDLE ProcessHandle;
	ACCESS_MASK DesiredAccess;
	POBJECT_ATTRIBUTES ObjectAttributes;
	PCLIENT_ID ClientId;
};

struct Message_NewNtDebugActiveProcess
{
	HANDLE ProcessId;
	HANDLE ProcessHandle;
	HANDLE DebugObjectHandle;
};

struct Message_NewNtCreateDebugObject
{
	HANDLE ProcessId;
	PHANDLE DebugObjectHandle;
	ACCESS_MASK DesiredAccess;
	POBJECT_ATTRIBUTES ObjectAttributes;
	ULONG Flags;
};

struct Message_NewNtRemoveProcessDebug
{
	HANDLE ProcessId;
	HANDLE ProcessHandle;
	HANDLE DebugObjectHandle;
};


struct Message_NewNtWaitForDebugEvent
{
	HANDLE DebugObjectHandle;
	BOOLEAN Alertable;
	PLARGE_INTEGER Timeout;
	void *WaitStateChange;
	//PDBGUI_WAIT_STATE_CHANGE WaitStateChange;
};



#if _KERNEL_MODE	
#endif

#define IO_Init CTL_CODE(FILE_DEVICE_UNKNOWN,0x7100,METHOD_BUFFERED ,FILE_ANY_ACCESS)

#define IO_NtReadWriteVirtualMemory CTL_CODE(FILE_DEVICE_UNKNOWN,0x7101,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define IO_NtProtectVirtualMemory CTL_CODE(FILE_DEVICE_UNKNOWN,0x7102,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define IO_NtOpenProcess CTL_CODE(FILE_DEVICE_UNKNOWN,0x7103,METHOD_BUFFERED ,FILE_ANY_ACCESS)


#define IO_NtCreateDebugObject CTL_CODE(FILE_DEVICE_UNKNOWN,0x7104,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define IO_NtDebugActiveProcess CTL_CODE(FILE_DEVICE_UNKNOWN,0x7105,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define IO_NtRemoveProcessDebug CTL_CODE(FILE_DEVICE_UNKNOWN,0x7106,METHOD_BUFFERED ,FILE_ANY_ACCESS)

#define TEST_2 CTL_CODE(FILE_DEVICE_UNKNOWN,0x8101,METHOD_BUFFERED ,FILE_ANY_ACCESS)




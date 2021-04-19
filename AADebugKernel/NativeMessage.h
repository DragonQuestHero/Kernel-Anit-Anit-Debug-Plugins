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
	ULONG_PTR DbgkCreateThread = 0;
	ULONG_PTR DbgkMapViewOfSection = 0;
	ULONG_PTR DbgkUnMapViewOfSection = 0;
	ULONG_PTR NtCreateUserProcess = 0;
	ULONG_PTR DbgkpMarkProcessPeb = 0;
	ULONG_PTR DbgkpSuppressDbgMsg = 0;

	ULONG_PTR DbgkDebugObjectType = 0;
	ULONG_PTR PsSystemDllBase = 0;
};









#ifdef _AMD64_
#else
typedef struct _UNICODE_STRING64
{
	USHORT Length;
	USHORT MaximumLength;
	ULONG Resave;//wow64¶ÔÆë
	ULONG64 Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;
#pragma pack(1)
typedef struct _OBJECT_ATTRIBUTES64
{
	ULONG Length;
	ULONG Resave1;//wow64¶ÔÆë
	ULONG64 RootDirectory;//HANDLE RootDirectory;
	ULONG64 ObjectName;//PUNICODE_STRING ObjectName;
	ULONG Attributes;
	ULONG Resave2;//wow64¶ÔÆë
	ULONG64 SecurityDescriptor;//PVOID SecurityDescriptor;        // SECURITY_DESCRIPTOR
	ULONG64 SecurityQualityOfService;//PVOID SecurityQualityOfService;  // SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES64;
typedef OBJECT_ATTRIBUTES64 *POBJECT_ATTRIBUTES64;

#pragma pack(1)
struct Message_NewNtCreateDebugObject64
{
	ULONG64 DebugObjectHandle;
	ACCESS_MASK DesiredAccess;
	ULONG64 ObjectAttributes;//POBJECT_ATTRIBUTES64 ObjectAttributes;
	ULONG Flags;
};

#pragma pack(1)
struct Message_NewNtDebugActiveProcess64
{
	ULONG64 ProcessId;
	ULONG64 ProcessHandle;
	ULONG64 DebugObjectHandle;
};


#pragma pack(1)
struct Message_NewNtWaitForDebugEvent64
{
	ULONG64 DebugObjectHandle;
	BOOLEAN Alertable;
	ULONG64 Timeout;//PLARGE_INTEGER Timeout;
	ULONG64 WaitStateChange;	//PDBGUI_WAIT_STATE_CHANGE WaitStateChange;
};
#endif // _AMD64_













#pragma pack(1)
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

#pragma pack(1)
struct Message_NtProtectVirtualMemory
{
	HANDLE ProcessHandle;
	PVOID *BaseAddress;
	PSIZE_T RegionSize;
	ULONG NewProtect;
	PULONG OldProtect;
};

#pragma pack(1)
struct Message_NewNtOpenProcess
{
	PHANDLE ProcessHandle;
	ACCESS_MASK DesiredAccess;
	POBJECT_ATTRIBUTES ObjectAttributes;
	PCLIENT_ID ClientId;
};

#pragma pack(1)
struct Message_NewNtDebugActiveProcess
{
	HANDLE ProcessId;
	HANDLE ProcessHandle;
	HANDLE DebugObjectHandle;
};


#pragma pack(1)
struct Message_NewNtCreateDebugObject
{
	PHANDLE DebugObjectHandle;
	ACCESS_MASK DesiredAccess;
	POBJECT_ATTRIBUTES ObjectAttributes;
	ULONG Flags;
};

#pragma pack(1)
struct Message_NewNtRemoveProcessDebug
{
	HANDLE ProcessId;
	HANDLE ProcessHandle;
	HANDLE DebugObjectHandle;
};

//#pragma pack(1)
//struct Message_NewNtWaitForDebugEvent
//{
//	HANDLE DebugObjectHandle;
//	BOOLEAN Alertable;
//	PLARGE_INTEGER Timeout;
//	void *WaitStateChange;
//	//PDBGUI_WAIT_STATE_CHANGE WaitStateChange;
//};



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




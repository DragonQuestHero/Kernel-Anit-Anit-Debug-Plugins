#pragma once
#include "CRT/NtSysAPI_Func.hpp"

#undef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#include <vector>
#include <map>


#include "NtHookEngine/x64detour.h"
#include "NativeMessage.h"

struct DebugInfomation
{
	HANDLE SourceProcessId;
	HANDLE TargetProcessId;
	HANDLE DebugObjectHandle;
	DEBUG_OBJECT *DebugObject;
};

class NewFunc
{
public:
	NewFunc()
	{
		_This = this;
	}
	~NewFunc() = default;
public:
	bool Init(Message_Init *message);
public://应用层实现函数
	NTSTATUS NTAPI NewNtReadWriteVirtualMemory(Message_NtReadWriteVirtualMemory *message);
	NTSTATUS NTAPI NewNtProtectVirtualMemory(Message_NtProtectVirtualMemory *message);
	NTSTATUS NTAPI NewNtOpenProcess(Message_NewNtOpenProcess *message);
public:
	NTSTATUS NTAPI NewNtCreateDebugObject(Message_NewNtCreateDebugObject *message);
	NTSTATUS NTAPI NewNtDebugActiveProcess(Message_NewNtDebugActiveProcess *message);
	NTSTATUS NTAPI NewNtRemoveProcessDebug(Message_NewNtRemoveProcessDebug *message);
	//NTSTATUS NTAPI NewNtWaitForDebugEvent(Message_NewNtWaitForDebugEvent *message);暂时不用实现
private://私有实现函数
	NTSTATUS NTAPI PrivateDbgkpPostFakeProcessCreateMessages(
		IN PEPROCESS Process,
		IN PDEBUG_OBJECT DebugObject,
		IN PETHREAD *pLastThread);
	NTSTATUS NTAPI PrivateDbgkpPostFakeThreadMessages(
			IN PEPROCESS Process,
			IN PDEBUG_OBJECT DebugObject,
			IN PETHREAD StartThread,
			OUT PETHREAD *pFirstThread,
			OUT PETHREAD *pLastThread);
	NTSTATUS NTAPI PrivateDbgkpQueueMessage(
		IN PEPROCESS Process,
		IN PETHREAD Thread,
		IN OUT PDBGKM_APIMSG ApiMsg,
		IN ULONG Flags,
		IN PDEBUG_OBJECT TargetDebugObject);
	NTSTATUS NTAPI PrivateDbgkpPostFakeModuleMessages(
		IN PEPROCESS Process,
		IN PETHREAD Thread,
		IN PDEBUG_OBJECT DebugObject);
	NTSTATUS NTAPI PrivateDbgkpSetProcessDebugObject(
		IN PEPROCESS Process,
		IN PDEBUG_OBJECT DebugObject,
		IN NTSTATUS MsgStatus,
		IN PETHREAD LastThread);
	NTSTATUS NTAPI PrivateDbgkpSendApiMessage(
		IN OUT PDBGKM_APIMSG ApiMsg,
		IN BOOLEAN SuspendProcess);
public://HOOK函数
#ifdef _AMD64_
	static VOID NTAPI NewKiDispatchException(
		IN PEXCEPTION_RECORD ExceptionRecord,
		IN PKEXCEPTION_FRAME ExceptionFrame,
		IN PKTRAP_FRAME TrapFrame,
		IN KPROCESSOR_MODE PreviousMode,
		IN BOOLEAN FirstChance);
#else
	static VOID NTAPI NewKiDispatchException(
		IN PEXCEPTION_RECORD ExceptionRecord,
		IN void *ExceptionFrame,
		IN void *TrapFrame,
		IN KPROCESSOR_MODE PreviousMode,
		IN BOOLEAN FirstChance);
#endif // _AMD64_

	
	static BOOLEAN NTAPI NewDbgkForwardException(
		IN PEXCEPTION_RECORD ExceptionRecord,
		IN BOOLEAN DebugException,
		IN BOOLEAN SecondChance);
	static VOID NTAPI NewDbgkCreateThread(PETHREAD Thread, PVOID StartAddress);
#ifdef _AMD64_
	static VOID NTAPI NewDbgkMapViewOfSection(
		PEPROCESS Process,
		void *SectionObject,
		void *BaseAddress,
		unsigned int SectionOffset,
		unsigned __int64 ViewSize);
#else
	static VOID NTAPI NewDbgkMapViewOfSection(
		IN HANDLE SectionHandle,
		IN PVOID BaseAddress,
		IN ULONG SectionOffset,
		IN ULONG_PTR ViewSize);
#endif // _AMD64_
	static VOID NTAPI NewDbgkUnMapViewOfSection(IN PVOID BaseAddress);
	/*static NTSTATUS NTAPI NewPspCreateProcess(
		OUT PHANDLE ProcessHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN HANDLE ParentProcess OPTIONAL,
		IN ULONG Flags,
		IN HANDLE SectionHandle OPTIONAL,
		IN HANDLE DebugPort OPTIONAL,
		IN HANDLE ExceptionPort OPTIONAL,
		IN ULONG JobMemberLevel);*/
	static NTSTATUS NTAPI NewNtCreateUserProcess(
		PHANDLE ProcessHandle,
		PETHREAD ThreadHandle,
		ACCESS_MASK ProcessDesiredAccess,
		ACCESS_MASK ThreadDesiredAccess,
		_OBJECT_ATTRIBUTES *ProcessObjectAttributes,
		_OBJECT_ATTRIBUTES *ThreadObjectAttributes,
		ULONG ProcessFlags,
		ULONG ThreadFlags,
		_RTL_USER_PROCESS_PARAMETERS *ProcessParameters,
		void *CreateInfo,
		void *AttributeList);
private:
	HOOK_INFO NewKiDispatchExceptionHookInfo = { 0 };
	HOOK_INFO NewDbgkForwardExceptionHookInfo = { 0 };
	HOOK_INFO NewDbgkCreateThreadHookInfo = { 0 };
	HOOK_INFO NewDbgkMapViewOfSectionHookInfo = { 0 };
	HOOK_INFO NewDbgkUnMapViewOfSectionHookInfo = { 0 };
	HOOK_INFO NewNtCreateUserProcessHookInfo = { 0 };
public:
	static NewFunc *_This;
private:
	bool IS_SYSTEM_THREAD(PETHREAD Thread)
	{
		return ((*(ULONG*)((char*)Thread + NtSysAPI_ETHREAD_CrossThreadFlags_X64_Win7) & PS_CROSS_THREAD_FLAGS_SYSTEM) != 0);
	}
	ULONG PrivateGetThreadCrossThreadFlags(PETHREAD Thread)
	{
		return *(ULONG*)((char*)Thread + NtSysAPI_ETHREAD_CrossThreadFlags_X64_Win7);
	}
	ULONG* PrivateGetThreadCrossThreadFlagsPoint(PETHREAD Thread)
	{
		return (ULONG*)((char*)Thread + NtSysAPI_ETHREAD_CrossThreadFlags_X64_Win7);
	}
	void* PrivateGetThreadStartAddress(PETHREAD Thread)
	{
		return (void*)((char*)Thread + NtSysAPI_ETHREAD_StartAddress_X64_Win7);
	}
	PEX_RUNDOWN_REF PrivateGetThreadRundownProtect(PETHREAD Thread)
	{
		return (PEX_RUNDOWN_REF)((char*)Thread + NtSysAPI_ETHREAD_RundownProtect_X64_Win7);
	}
	PKTIMER PrivateGetThreadTimer(PETHREAD Thread)
	{
		return (PKTIMER)((char*)Thread + NtSysAPI_KTHREAD_Timer_X64_Win7);
	}
private:
	ULONG* PrivateGetProcessFlags(PEPROCESS Process)
	{
		return (ULONG*)((char*)Process + NtSysAPI_EPROCESS_Flags_X64_Win7);
	}
	PWOW64_PROCESS PrivateGetProcessWow64Process(PEPROCESS Process)
	{
		return (PWOW64_PROCESS)((char*)Process + NtSysAPI_EPROCESS_Wow64Process_X64_Win7);
	}
	void* PrivateGetProcessSectionObject(PEPROCESS Process)
	{
		return (void*)((char*)Process + NtSysAPI_EPROCESS_SectionObject_X64_Win7);
	}
	void* PrivateGetProcessSectionBaseAddress(PEPROCESS Process)
	{
		return (void*)((char*)Process + NtSysAPI_EPROCESS_SectionBaseAddress_X64_Win7);
	}
	PEX_RUNDOWN_REF PrivateGetProcessRundownProtect(PEPROCESS Process)
	{
		return (PEX_RUNDOWN_REF)((char*)Process + NtSysAPI_EPROCESS_RundownProtect_X64_Win7);
	}
	ULONG PrivateGetProcessUserTime(PEPROCESS Process)
	{
		return *(ULONG*)((char*)Process + NtSysAPI_KPROCESS_UserTime_X64_Win7);
	}
	ULONG_PTR* PrivateGetProcessDebugPort(PEPROCESS Process)
	{
		return (ULONG_PTR*)((char*)Process + NtSysAPI_EPROCESS_DebugPort_X64_Win7);
	}
private:
	_NtProtectVirtualMemory NtProtectVirtualMemory = nullptr;
	_DbgkpWakeTarget DbgkpWakeTarget = nullptr;
	_PsResumeThread PsResumeThread = nullptr;
	_PsSuspendThread PsSuspendThread = nullptr;
	//_NtCreateDebugObject NtCreateDebugObject = nullptr;
	_PsGetNextProcessThread PsGetNextProcessThread = nullptr;
	//_PsQuitNextProcessThread PsQuitNextProcessThread = nullptr;
	_DbgkpSectionToFileHandle DbgkpSectionToFileHandle = nullptr;
	_MmGetFileNameForAddress MmGetFileNameForAddress = nullptr;
	_KiDispatchException KiDispatchException = nullptr;
	_DbgkForwardException DbgkForwardException = nullptr;
	_DbgkpSuspendProcess DbgkpSuspendProcess = nullptr;//不需要实现 没有什么特殊的地方
	_KeThawAllThreads KeThawAllThreads = nullptr;
	_DbgkCreateThread DbgkCreateThread = nullptr;
	_DbgkMapViewOfSection DbgkMapViewOfSection = nullptr;
	_DbgkUnMapViewOfSection DbgkUnMapViewOfSection = nullptr;
	//_PspCreateProcess PspCreateProcess = nullptr;废案
	_NtCreateUserProcess NtCreateUserProcess = nullptr;
	_DbgkpMarkProcessPeb DbgkpMarkProcessPeb = nullptr;
	_DbgkpSuppressDbgMsg DbgkpSuppressDbgMsg = nullptr;
private:
	POBJECT_TYPE *_DbgkDebugObjectType = nullptr;
	PVOID _PsSystemDllBase = nullptr;
private:
	std::vector<DebugInfomation*> _DebugInfomationVector;
	HANDLE _Io_Handle;
	bool _Init = false;
};

#define ProbeForWriteHandle(Address) {                                       \
    if ((Address) >= (HANDLE * const)MM_USER_PROBE_ADDRESS) {                \
        *(volatile HANDLE * const)MM_USER_PROBE_ADDRESS = 0;                 \
    }                                                                        \
                                                                             \
    *(volatile HANDLE *)(Address) = *(volatile HANDLE *)(Address);           \
}

#define PS_SET_BITS(Flags, Flag) \
    RtlInterlockedSetBitsDiscardReturn (Flags, Flag)

#define PS_TEST_SET_BITS(Flags, Flag) \
    RtlInterlockedSetBits (Flags, Flag)

#define ProbeForReadSmallStructure ProbeForRead

#define DBGKM_MSG_OVERHEAD 8

#define DBGKM_API_MSG_LENGTH(TypeSize) \
            sizeof(DBGKM_APIMSG)<<16 | (DBGKM_MSG_OVERHEAD + (TypeSize))

#define DBGKM_FORMAT_API_MSG(m,Number,TypeSize)             \
    (m).h.u1.Length = DBGKM_API_MSG_LENGTH((TypeSize));     \
    (m).h.u2.ZeroInit = LPC_DEBUG_EVENT;                    \
    (m).ApiNumber = (Number)

#define NTDLL_PATH_NAME L"\\SystemRoot\\System32\\ntdll.dll"
const UNICODE_STRING PsNtDllPathName = {
	sizeof(NTDLL_PATH_NAME) - sizeof(UNICODE_NULL),
	sizeof(NTDLL_PATH_NAME),
	NTDLL_PATH_NAME
};


#define DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(hdrs,field) \
            ((hdrs)->OptionalHeader.##field)
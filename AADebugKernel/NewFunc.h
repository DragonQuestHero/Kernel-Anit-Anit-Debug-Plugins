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
	static VOID NTAPI NewKiDispatchException(
		IN PEXCEPTION_RECORD ExceptionRecord,
		IN PKEXCEPTION_FRAME ExceptionFrame,
		IN PKTRAP_FRAME TrapFrame,
		IN KPROCESSOR_MODE PreviousMode,
		IN BOOLEAN FirstChance);
	static BOOLEAN NTAPI NewDbgkForwardException(
		IN PEXCEPTION_RECORD ExceptionRecord,
		IN BOOLEAN DebugException,
		IN BOOLEAN SecondChance);
private:
	HOOK_INFO NewKiDispatchExceptionHookInfo = { 0 };
	HOOK_INFO NewDbgkForwardExceptionHookInfo = { 0 };
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
	PEX_RUNDOWN_REF PrivateGetProcessRundownProtect(PEPROCESS Process)
	{
		return (PEX_RUNDOWN_REF)((char*)Process + NtSysAPI_EPROCESS_RundownProtect_X64_Win7);
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
private:
	POBJECT_TYPE *_DbgkDebugObjectType = nullptr;
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

#define ProbeForReadSmallStructure ProbeForRead

#define DBGKM_MSG_OVERHEAD 8

#define DBGKM_API_MSG_LENGTH(TypeSize) \
            sizeof(DBGKM_APIMSG)<<16 | (DBGKM_MSG_OVERHEAD + (TypeSize))

#define DBGKM_FORMAT_API_MSG(m,Number,TypeSize)             \
    (m).h.u1.Length = DBGKM_API_MSG_LENGTH((TypeSize));     \
    (m).h.u2.ZeroInit = LPC_DEBUG_EVENT;                    \
    (m).ApiNumber = (Number)
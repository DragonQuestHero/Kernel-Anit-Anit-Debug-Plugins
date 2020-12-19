#pragma once
#include <windows.h>




class AADebug
{
public:
	AADebug() = default;
	~AADebug() = default;
public:
	bool Init();
	bool StartHook();
	bool Test();
private:
	ULONG_PTR DbgkpWakeTarget = 0;
	ULONG_PTR PsResumeThread = 0;
	ULONG_PTR PsSuspendThread = 0;
	//_NtCreateDebugObject NtCreateDebugObject = nullptr;
	ULONG_PTR PsGetNextProcessThread = 0;
	ULONG_PTR DbgkpSectionToFileHandle = 0;
	ULONG_PTR MmGetFileNameForAddress = 0;
	ULONG_PTR DbgkDebugObjectType = 0;
	ULONG_PTR KiDispatchException = 0;
	ULONG_PTR DbgkForwardException = 0;
	ULONG_PTR DbgkpSuspendProcess = 0;
	ULONG_PTR KeThawAllThreads = 0;
private:
	void *_Original_ReadVirtualMemory = nullptr;
	void *_Original_WriteVirtualMemory = nullptr;
	void *_Original_ProtectVirtualMemory = nullptr;
	void *_Original_NtOpenProcess = nullptr;
	void *_Original_DebugActiveProcess = nullptr;
	void *_Original_NtCreateDebugObject = nullptr;
	void *_Original_NtDebugActiveProcess = nullptr;
	void *_Original_NtRemoveProcessDebug = nullptr;
	void *_Original_DbgUiWaitStateChange = nullptr;
	void *_Original_DbgUiContinue = nullptr;
};


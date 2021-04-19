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
	void *_Original_DbgUiGetThreadDebugObject = nullptr;
	void *_Original_DbgUiConnectToDbg = nullptr;
	void *_Original_DbgUiDebugActiveProcess = nullptr;
};


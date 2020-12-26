#include <windows.h>

#include <string>
#include <iostream>

#include "ntdll.h"

#include "FindSymbl/FindAddress.h"


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
ULONG_PTR DbgkCreateThread = 0;
ULONG_PTR DbgkMapViewOfSection = 0;
ULONG_PTR DbgkUnMapViewOfSection = 0;
ULONG_PTR NtCreateUserProcess = 0;
ULONG_PTR DbgkpMarkProcessPeb = 0;
ULONG_PTR DbgkpSuppressDbgMsg = 0;


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

#define IO_Init CTL_CODE(FILE_DEVICE_UNKNOWN,0x7100,METHOD_BUFFERED ,FILE_ANY_ACCESS)


int main()
{

#ifdef _AMD64_
	CFindAddress *FindAddr = new CFindAddress();

	DbgkpWakeTarget = FindAddr->FindSymAddress("DbgkpWakeTarget");
	if (DbgkpWakeTarget == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	PsResumeThread = FindAddr->FindSymAddress("PsResumeThread");//x86-KeResumeThread
	if (PsResumeThread == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	PsSuspendThread = FindAddr->FindSymAddress("PsSuspendThread");
	if (PsSuspendThread == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	PsGetNextProcessThread = FindAddr->FindSymAddress("PsGetNextProcessThread");
	if (PsGetNextProcessThread == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	DbgkpSectionToFileHandle = FindAddr->FindSymAddress("DbgkpSectionToFileHandle");
	if (DbgkpSectionToFileHandle == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	MmGetFileNameForAddress = FindAddr->FindSymAddress("MmGetFileNameForAddress");
	if (MmGetFileNameForAddress == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	KiDispatchException = FindAddr->FindSymAddress("KiDispatchException");
	if (KiDispatchException == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	DbgkForwardException = FindAddr->FindSymAddress("DbgkForwardException");
	if (DbgkForwardException == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	DbgkpSuspendProcess = FindAddr->FindSymAddress("DbgkpSuspendProcess");
	if (DbgkpSuspendProcess == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	KeThawAllThreads = FindAddr->FindSymAddress("KeThawAllThreads");
	if (KeThawAllThreads == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	DbgkCreateThread = FindAddr->FindSymAddress("DbgkCreateThread");
	if (DbgkCreateThread == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	DbgkMapViewOfSection = FindAddr->FindSymAddress("DbgkMapViewOfSection");
	if (DbgkMapViewOfSection == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	DbgkUnMapViewOfSection = FindAddr->FindSymAddress("DbgkUnMapViewOfSection");
	if (DbgkUnMapViewOfSection == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	NtCreateUserProcess = FindAddr->FindSymAddress("NtCreateUserProcess");
	if (NtCreateUserProcess == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	DbgkpMarkProcessPeb = FindAddr->FindSymAddress("DbgkpMarkProcessPeb");
	if (DbgkpMarkProcessPeb == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}

	DbgkpSuppressDbgMsg = FindAddr->FindSymAddress("DbgkpSuppressDbgMsg");
	if (DbgkpSuppressDbgMsg == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}



	DbgkDebugObjectType = FindAddr->FindSymAddress("DbgkDebugObjectType");
	if (DbgkDebugObjectType == 0)
	{
		std::cout << "FindSymAddress error";
		getchar();
	}
#else
	DbgkpWakeTarget = 0x840fd922;
	PsResumeThread = 0x83ef1a91;
	PsSuspendThread = 0x840e5efd;
	PsGetNextProcessThread = 0x840841e8;
	DbgkpSectionToFileHandle = 0x840ff617;
	MmGetFileNameForAddress = 0x8411d5ec;
	KiDispatchException = 0x83f03ee0;
	DbgkForwardException = 0x84058888;
	DbgkpSuspendProcess = 0x840ff5e9;
	KeThawAllThreads = 0x83f2d29f;
	DbgkCreateThread = 0x840a92a1;
	DbgkMapViewOfSection = 0x840a633e;
	DbgkUnMapViewOfSection = 0x840a648f;
	NtCreateUserProcess = 0x840bf056;
	DbgkpMarkProcessPeb = 0x840fd7eb;
	DbgkDebugObjectType = 0x83f87dac;
	DbgkpSuppressDbgMsg = 0x840ff792;

#endif // _AMD64_

	HANDLE device = CreateFileA("\\\\.\\AADebug", GENERIC_READ | GENERIC_WRITE, 0,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (device == INVALID_HANDLE_VALUE)
	{
		std::cout << "CreateFileA error";
		getchar();
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
	temp_message.DbgkCreateThread = DbgkCreateThread;
	temp_message.DbgkMapViewOfSection = DbgkMapViewOfSection;
	temp_message.DbgkUnMapViewOfSection = DbgkUnMapViewOfSection;
	temp_message.NtCreateUserProcess = NtCreateUserProcess;
	temp_message.DbgkpMarkProcessPeb = DbgkpMarkProcessPeb;
	temp_message.DbgkpSuppressDbgMsg = DbgkpSuppressDbgMsg;

	temp_message.DbgkDebugObjectType = DbgkDebugObjectType;
	temp_message.PsSystemDllBase = (ULONG64)GetModuleHandleA("NTDLL.DLL");

	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	NTSTATUS status = ZwDeviceIoControlFile(device, nullptr, nullptr, nullptr,
		&IoStatusBlock, IO_Init,
		&temp_message, sizeof(Message_Init),
		&temp_message, sizeof(Message_Init));
	if (!NT_SUCCESS(status))
	{
		std::cout << "ZwDeviceIoControlFile error";
		getchar();
	}
}
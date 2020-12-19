#include "CRT/Ntddk.hpp"
#undef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#include <string>
#include <vector>
#include <algorithm>
#include <map>

#include "IO_Control.h"

IO_Control *_IO_Control = nullptr;

void DriverUnload(PDRIVER_OBJECT drive_object)
{
	DbgBreakPoint();
	DbgPrint("Unload Over!\n");
	_IO_Control->Delete_IO_Control();
	delete _IO_Control;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drive_object, PUNICODE_STRING path)
{
	drive_object->DriverUnload = DriverUnload;


	_IO_Control = new IO_Control(drive_object);
	_IO_Control->Create_IO_Control();


	return STATUS_SUCCESS;
}
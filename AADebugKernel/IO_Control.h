#pragma once
#include "CRT/Ntddk.hpp"
#include "NewFunc.h"


class IO_Control
{
public:
	IO_Control(PDRIVER_OBJECT drive_object)
	{
		_This = this;
		Driver_Object = drive_object;
		_NewFunc = new NewFunc();
	}
	~IO_Control()
	{
		if (_NewFunc)
		{
			delete _NewFunc;
		}
	}
public:
	NTSTATUS Create_IO_Control();
	NTSTATUS Delete_IO_Control();
private:
	static NTSTATUS IO_Default(PDEVICE_OBJECT  DeviceObject, PIRP  pIrp);
	static NTSTATUS Code_Control_Center(PDEVICE_OBJECT  DeviceObject, PIRP  pIrp);
private:
	static IO_Control *_This;
private:
	DRIVER_OBJECT *Driver_Object = nullptr;
	DEVICE_OBJECT *Device_Object = nullptr;
	UNICODE_STRING Device_Name;
	UNICODE_STRING Link_Name;
	NewFunc *_NewFunc = nullptr;
	bool InitFlag = false;
};


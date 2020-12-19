#include "IO_Control.h"
#include "CRT/NtSysAPI_Func.hpp"

#define DEVICE_NAME L"\\Device\\AADebug"
#define LINK_NAME L"\\??\\AADebug"


IO_Control *IO_Control::_This = nullptr;


NTSTATUS IO_Control::Create_IO_Control()
{
	NTSTATUS status = 0;
	RtlInitUnicodeString(&Device_Name, DEVICE_NAME);
	status = IoCreateDevice(Driver_Object, 0, &Device_Name, FILE_DEVICE_UNKNOWN, 0, FALSE, &Device_Object);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Create Device error!\n");
		return status;
	}

	Device_Object->Flags |= DO_BUFFERED_IO;
	RtlInitUnicodeString(&Link_Name, LINK_NAME);
	status = IoCreateSymbolicLink(&Link_Name, &Device_Name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(Device_Object);
		DbgPrint("Create Link error!\n");
		return status;
	}

	//DbgPrint("Create Device and Link SUCCESS!\n");

	Driver_Object->MajorFunction[IRP_MJ_CREATE] = IO_Control::IO_Default;
	Driver_Object->MajorFunction[IRP_MJ_CLOSE] = IO_Control::IO_Default;
	Driver_Object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IO_Control::Code_Control_Center;

	return STATUS_SUCCESS;
}

NTSTATUS IO_Control::Delete_IO_Control()
{
	IoDeleteSymbolicLink(&Link_Name);
	IoDeleteDevice(Device_Object);
	DbgPrint("Link_Unload\n");
	return STATUS_SUCCESS;
}

NTSTATUS IO_Control::IO_Default(PDEVICE_OBJECT  DeviceObject, PIRP  pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS IO_Control::Code_Control_Center(PDEVICE_OBJECT  DeviceObject, PIRP pIrp)
{
	PIO_STACK_LOCATION irp = IoGetCurrentIrpStackLocation(pIrp);
	ULONG Io_Control_Code = irp->Parameters.DeviceIoControl.IoControlCode;
	ULONG Input_Lenght = irp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG Output_Lenght = irp->Parameters.DeviceIoControl.OutputBufferLength;
	void *Input_Output_Buffer = (void*)pIrp->AssociatedIrp.SystemBuffer;

	NTSTATUS status = 0;
	
	do 
	{
		if (Io_Control_Code == IO_NtReadWriteVirtualMemory)
		{
			if (Input_Output_Buffer != nullptr && Input_Lenght != 0 && Output_Lenght != 0)
			{
				status = _This->_NewFunc->NewNtReadWriteVirtualMemory((Message_NtReadWriteVirtualMemory*)Input_Output_Buffer);
			}
			else
			{
				status = STATUS_UNSUCCESSFUL;
			}
			pIrp->IoStatus.Status = status;
			pIrp->IoStatus.Information = sizeof(Message_NtReadWriteVirtualMemory);
			break;
		}


		if (Io_Control_Code == IO_NtProtectVirtualMemory)
		{
			if (Input_Output_Buffer != nullptr && Input_Lenght != 0 && Output_Lenght != 0)
			{
				status = _This->_NewFunc->NewNtProtectVirtualMemory((Message_NtProtectVirtualMemory*)Input_Output_Buffer);
			}
			else
			{
				status = STATUS_UNSUCCESSFUL;
			}
			pIrp->IoStatus.Status = status;
			pIrp->IoStatus.Information = sizeof(Message_NtReadWriteVirtualMemory);
			break;
		}

		if (Io_Control_Code == IO_NtOpenProcess)
		{
			if (Input_Output_Buffer != nullptr && Input_Lenght != 0 && Output_Lenght != 0)
			{
				status = _This->_NewFunc->NewNtOpenProcess((Message_NewNtOpenProcess*)Input_Output_Buffer);
			}
			else
			{
				status = STATUS_UNSUCCESSFUL;
			}
			
			pIrp->IoStatus.Status = status;
			pIrp->IoStatus.Information = sizeof(Message_NewNtOpenProcess);
			break;
		}


		if (Io_Control_Code == IO_Init)
		{
			if (Input_Output_Buffer != nullptr && Input_Lenght != 0 && Output_Lenght != 0)
			{
				DbgBreakPoint();
				if (_This->_NewFunc->Init((Message_Init*)Input_Output_Buffer))
				{
					_This->InitFlag = true;
				}
			}
			break;
		}

		if (_This->InitFlag == false)
		{
			break;
		}

		if (Io_Control_Code == IO_NtCreateDebugObject)
		{
			if (Input_Output_Buffer != nullptr && Input_Lenght != 0 && Output_Lenght != 0)
			{
				status = _This->_NewFunc->NewNtCreateDebugObject((Message_NewNtCreateDebugObject*)Input_Output_Buffer);
			}
			else
			{
				status = STATUS_UNSUCCESSFUL;
			}
			pIrp->IoStatus.Status = status;
			pIrp->IoStatus.Information = sizeof(Message_NewNtCreateDebugObject);
			break;
		}

		DbgBreakPoint();
		if (Io_Control_Code == IO_NtDebugActiveProcess)
		{
			if (Input_Output_Buffer != nullptr && Input_Lenght != 0 && Output_Lenght != 0)
			{
				status = _This->_NewFunc->NewNtDebugActiveProcess((Message_NewNtDebugActiveProcess*)Input_Output_Buffer);
			}
			else
			{
				status = STATUS_UNSUCCESSFUL;
			}
			pIrp->IoStatus.Status = status;
			pIrp->IoStatus.Information = sizeof(Message_NewNtDebugActiveProcess);
			break;
		}

		if (Io_Control_Code == IO_NtRemoveProcessDebug)
		{
			if (Input_Output_Buffer != nullptr && Input_Lenght != 0 && Output_Lenght != 0)
			{
				status = _This->_NewFunc->NewNtRemoveProcessDebug((Message_NewNtRemoveProcessDebug*)Input_Output_Buffer);
			}
			else
			{
				status = STATUS_UNSUCCESSFUL;
			}
			pIrp->IoStatus.Status = status;
			pIrp->IoStatus.Information = sizeof(Message_NewNtRemoveProcessDebug);
			break;
		}
		

	} while (false);
	

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}
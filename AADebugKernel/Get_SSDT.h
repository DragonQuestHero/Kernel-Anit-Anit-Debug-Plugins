#pragma once
#include "CRT/Ntddk.hpp"
#include "CRT/NtSysAPI_Func.hpp"


static PSYSTEM_SERVICE_TABLE GetKeServiceDescriptorTableAddrX64()
{
	PUCHAR StartSearchAddress = NULL;
	PUCHAR EndSearchAddress = NULL;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	LONG templong = 0;
	ULONG_PTR addr = 0;
	RTL_OSVERSIONINFOW Version = { 0 };
	Version.dwOSVersionInfoSize = sizeof(Version);
	RtlGetVersion(&Version);
	if (Version.dwBuildNumber > 17763)
	{
		StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
		for (i = StartSearchAddress; i < StartSearchAddress + 0x500; i++)
		{
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 5))
			{
				b1 = *i;
				b2 = *(i + 5);
				if (b1 == 0xe9 && b2 == 0xc3)
				{
					memcpy(&templong, i + 1, 4);
					StartSearchAddress = i + 5 + templong;
					break;
				}
			}
		}
	}
	else
	{
		StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	}
	EndSearchAddress = StartSearchAddress + 0x500;
	for (i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *(i);
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)
			{
				memcpy(&templong, i + 3, 4);
				//核心部分  
				//kd> db fffff800`03e8b772  
				//fffff800`03e8b772  4c 8d 15 c7 20 23 00 4c-8d 1d 00 21 23 00 f7 83  L... #.L...!#...  
				//templong = 002320c7 ,i = 03e8b772, 7为指令长度  
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				break;
			}
		}
	}
	return (PSYSTEM_SERVICE_TABLE)addr;
}

static ULONG_PTR GetSSDTFuncCurAddrByIndex(ULONG index)
{
	LONG dwtmp = 0;
	ULONG_PTR addr = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)GetKeServiceDescriptorTableAddrX64()->ServiceTableBase;
	dwtmp = ServiceTableBase[index];
	dwtmp = dwtmp >> 4;
	addr = ((ULONG_PTR)dwtmp + (ULONG_PTR)ServiceTableBase);//&0xFFFFFFF0;
	return addr;
}
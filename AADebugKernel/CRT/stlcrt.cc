// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// 
// CoreSTL
// 
// Copyright (C) MeeSong. All rights reserved.
// 	    Author : MeeSong 
//	    Email  : meesong@live.cn
// 	    Github : https://github.com/meesong
//      License: GNU Library General Public License(LGPL) - Version 3
#include "Ntddk.hpp"
#include "stlcrt.h"

extern "C"
{

	void __cdecl CoreSTLRaiseException(unsigned long _code, size_t _arg1, size_t _arg2, size_t _arg3, size_t _arg4)
       
    {
        KdBreakPoint();
        KeBugCheckEx(_code, _arg1, _arg2, _arg3, _arg4);
    }

	void __cdecl _invalid_parameter_noinfo_noreturn()
	{
		CoreSTLRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
	}

}

namespace std
{

	void __cdecl _Xbad_alloc()
    {
        CoreSTLRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
    }

	void __cdecl _Xinvalid_argument(const char * _msg)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, _msg);
        CoreSTLRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
    }

	void __cdecl _Xlength_error(const char * _msg)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, _msg);
        CoreSTLRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
    }

	void __cdecl _Xout_of_range(const char * _msg)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, _msg);
        CoreSTLRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
    }

	void __cdecl _Xoverflow_error(const char * _msg)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, _msg);
        CoreSTLRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
    }

	void __cdecl _Xruntime_error(const char * _msg)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, _msg);
        CoreSTLRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
    }

	char const* __cdecl _Syserror_map( int)
	{
		__debugbreak();
		return nullptr;
	}

	char const*
		__cdecl
		_Winerror_map(
		 int
		)
	{
		__debugbreak();
		return nullptr;
	}
}
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// 
// CoreSTL
// 
// Copyright (C) MeeSong. All rights reserved.
// 	    Author : MeeSong 
//	    Email  : meesong@live.cn
// 	    Github : https://github.com/meesong
//      License: GNU Library General Public License(LGPL) - Version 3
// 
// This file is part of Idea
// 
// Idea is free software; you can redistribute it and/or modify
// it under the terms of the GNU Library General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Idea is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Library General Public License for more details.
//
// You should have received a copy of the GNU Library General Public License
// along with Idea.  If not, see <http://www.gnu.org/licenses/>.
//
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

#pragma once

extern "C"
{

	void __cdecl CoreSTLRaiseException(
        unsigned long   _code,
		size_t   _arg1 = 0,
		size_t   _arg2 = 0,
		size_t   _arg3 = 0,
		size_t   _arg4 = 0);

	//void __cdecl _invalid_parameter_noinfo_noreturn();

}

namespace std
{

	void __cdecl _Xbad_alloc();

	void __cdecl _Xinvalid_argument(const char* _msg);

	void __cdecl _Xlength_error(const char* _msg);

	void __cdecl _Xout_of_range(const char* _msg);

	void __cdecl _Xoverflow_error(const char* _msg);

	void __cdecl _Xruntime_error(const char* _msg);
    
	char const* __cdecl _Syserror_map( int);

	char const*
		__cdecl
		_Winerror_map(
		 int
		);

}
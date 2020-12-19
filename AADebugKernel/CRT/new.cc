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

#include "Ntddk.hpp"
#include "new.h"



void __cdecl CoreSTLRaiseException(
    unsigned long   _code,
    size_t   _arg1,
    size_t   _arg2,
    size_t   _arg3,
    size_t   _arg4);

namespace std
{
	void __cdecl _Xbad_alloc();
}



// replaceable usual deallocation functions
void* __cdecl operator new(size_t _size)
{
    if (0 == _size) _size = 1;

    if (auto ptr = __core_allocator(_size, NonPagedPool, DefaultPoolTag))
    {
        return ptr;
    }

    std::_Xbad_alloc();
}

void __cdecl operator delete(void * _ptr)
{
    if (nullptr == _ptr) return;

    return __core_deletor(_ptr, NonPagedPool, DefaultPoolTag);
}

void* __cdecl operator new(size_t _size, POOL_TYPE _pool_type)
{
    if (0 == _size) _size = 1;

    if (auto ptr = __core_allocator(_size, _pool_type, DefaultPoolTag))
    {
        return ptr;
    }

    std::_Xbad_alloc();
}

void* __cdecl operator new(size_t _size, POOL_TYPE _pool_type, unsigned long _tag)
{
    if (0 == _size) _size = 1;

    if (auto ptr = __core_allocator(_size, _pool_type, _tag))
    {
        return ptr;
    }

    std::_Xbad_alloc();
}

void __cdecl operator delete(void * _ptr, POOL_TYPE _pool_type)
{
    if (nullptr == _ptr) return;

    return __core_deletor(_ptr, _pool_type, DefaultPoolTag);
}

void __cdecl operator delete(void * _ptr, POOL_TYPE _pool_type, unsigned long _tag)
{
    if (nullptr == _ptr) return;

    return __core_deletor(_ptr, _pool_type, _tag);
}

void* __cdecl operator new[](size_t _size)
{
    if (0 == _size) _size = 1;

    if (auto ptr = __core_allocator(_size, NonPagedPool, DefaultPoolTag))
    {
        return ptr;
    }

    std::_Xbad_alloc();
}

void __cdecl operator delete[](void * _ptr)
{
    if (nullptr == _ptr) return;

    return __core_deletor(_ptr, NonPagedPool, DefaultPoolTag);
}

void* __cdecl operator new[](size_t _size, POOL_TYPE _pool_type)
{
    if (0 == _size) _size = 1;

    if (auto ptr = __core_allocator(_size, _pool_type, DefaultPoolTag))
    {
        return ptr;
    }

    std::_Xbad_alloc();
}

void* __cdecl operator new[](size_t _size, POOL_TYPE _pool_type, unsigned long _tag)
{
    if (0 == _size) _size = 1;

    if (auto ptr = __core_allocator(_size, _pool_type, _tag))
    {
        return ptr;
    }

    std::_Xbad_alloc();
}

void __cdecl operator delete[](void * _ptr, POOL_TYPE _pool_type)
{
    if (nullptr == _ptr) return;

    return __core_deletor(_ptr, _pool_type, DefaultPoolTag);
}

void __cdecl operator delete[](void * _ptr, POOL_TYPE _pool_type, unsigned long _tag)
{
    if (nullptr == _ptr) return;

    return __core_deletor(_ptr, _pool_type, _tag);
}

void __cdecl operator delete  (void*, void*)
{
    return ;
}

void __cdecl operator delete[](void*, void*)
{
    return ;
}

// sized class - specific deallocation functions
void __cdecl operator delete  (void* _ptr, size_t /*_size*/)
{
    if (nullptr == _ptr) return;

    return __core_deletor(_ptr, NonPagedPool, DefaultPoolTag);
}

void __cdecl operator delete[](void* _ptr, size_t /*_size*/)
{
    if (nullptr == _ptr) return;

    return __core_deletor(_ptr, NonPagedPool, DefaultPoolTag);
}
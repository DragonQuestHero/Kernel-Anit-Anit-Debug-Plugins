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
#include "c_alloc.h"


// replaceable usual deallocation functions
void* __cdecl operator new     (size_t _size);
void __cdecl operator delete  (void *_ptr);

void* __cdecl operator new     (size_t _size, POOL_TYPE _pool_type);
void* __cdecl operator new     (size_t _size, POOL_TYPE _pool_type, unsigned long _tag);
void __cdecl operator delete  (void *_ptr, POOL_TYPE _pool_type);
void __cdecl operator delete  (void *_ptr, POOL_TYPE _pool_type, unsigned long _tag);

void* __cdecl operator new[](size_t _size);
void __cdecl operator delete[](void* _ptr);

void* __cdecl operator new[](size_t _size, POOL_TYPE _pool_type);
void* __cdecl operator new[](size_t _size, POOL_TYPE _pool_type, unsigned long _tag);
void __cdecl operator delete[](void *_ptr, POOL_TYPE _pool_type);
void __cdecl operator delete[](void *_ptr, POOL_TYPE _pool_type, unsigned long _tag);

// replaceable placement deallocation functions
void* __cdecl operator new   (size_t _size, void* _ptr);
void* __cdecl operator new[](size_t _size, void* _ptr);

// T::~T()
void __cdecl operator delete  (void*, void*);
void __cdecl operator delete[](void*, void*);

// sized class - specific deallocation functions
void __cdecl operator delete  (void* _ptr, size_t _size);
void __cdecl operator delete[](void* _ptr, size_t _size);

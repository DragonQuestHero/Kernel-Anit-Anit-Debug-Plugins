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
#include "corecrt.h"


// Need to put the following marker variables into the .CRT section.
// The .CRT section contains arrays of function pointers.
// The compiler creates functions and adds pointers to this section
// for things like C++ global constructors.
//
// The XIA, XCA etc are group names with in the section.
// The compiler sorts the contributions by the group name.
// For example, .CRT$XCA followed by .CRT$XCB, ... .CRT$XCZ.
// The marker variables below let us get pointers
// to the beginning/end of the arrays of function pointers.
//
// For example, standard groups are
//  XCA used here, for begin marker
//  XCC "compiler" inits
//  XCL "library" inits
//  XCU "user" inits
//  XCZ used here, for end marker
//

#define _CRTAlloc$(x) __declspec(allocate(x))

#pragma section(".CRT$XIA", long, read)      // C Initializer
#pragma section(".CRT$XIZ", long, read)

#pragma section(".CRT$XCA", long, read)      // C++ Initializer
#pragma section(".CRT$XCZ", long, read)

#pragma section(".CRT$XPA", long, read)      // C pre-terminators
#pragma section(".CRT$XPZ", long, read)

#pragma section(".CRT$XTA", long, read)      // C terminators
#pragma section(".CRT$XTZ", long, read)

extern "C" _CRTAlloc$(".CRT$XIA") _PIFV __xi_a[] = { nullptr };
extern "C" _CRTAlloc$(".CRT$XIZ") _PIFV __xi_z[] = { nullptr };
extern "C" _CRTAlloc$(".CRT$XCA") _PVFV __xc_a[] = { nullptr };
extern "C" _CRTAlloc$(".CRT$XCZ") _PVFV __xc_z[] = { nullptr };
extern "C" _CRTAlloc$(".CRT$XPA") _PVFV __xp_a[] = { nullptr };
extern "C" _CRTAlloc$(".CRT$XPZ") _PVFV __xp_z[] = { nullptr };
extern "C" _CRTAlloc$(".CRT$XTA") _PVFV __xt_a[] = { nullptr };
extern "C" _CRTAlloc$(".CRT$XTZ") _PVFV __xt_z[] = { nullptr };

#pragma comment(linker, "/merge:.CRT=.rdata")


// Calls each function in [first, last).  [first, last) must be a valid range of
// function pointers.  Each function is called, in order.
extern "C" static void __cdecl _initterm(_PVFV* const first, _PVFV* const last)
{
    for (_PVFV* it = first; it != last; ++it)
    {
        if (*it == nullptr)
            continue;

        (**it)();
    }
}

// Calls each function in [first, last).  [first, last) must be a valid range of
// function pointers.  Each function must return zero on success, nonzero on
// failure.  If any function returns nonzero, iteration stops immediately and
// the nonzero value is returned.  Otherwise all functions are called and zero
// is returned.
//
// If a nonzero value is returned, it is expected to be one of the runtime error
// values (_RT_{NAME}, defined in the internal header files).
extern "C" static int __cdecl _initterm_e(_PIFV* const first, _PIFV* const last)
{
    for (_PIFV* it = first; it != last; ++it)
    {
        if (*it == nullptr)
            continue;

        int const result = (**it)();
        if (result != 0)
            return result;
    }

    return 0;
}

using $onexit = _PVFV;

struct onexit_entry
{
    onexit_entry*   _next       = nullptr;
    $onexit         _destructor = nullptr;

    onexit_entry(onexit_entry* next, $onexit destructor)
        : _next         { next }
        , _destructor   { destructor }
    { }

    ~onexit_entry()
    {
        _destructor();
    }
};
static onexit_entry* s_onexit_table = nullptr;

static int __cdecl register_onexit(onexit_entry* table, $onexit const function)
{
    const auto entry = new onexit_entry(table, function);
    if (nullptr == entry)
    {
        return -1;
    }
    s_onexit_table = entry;

    return 0;
}

static int __cdecl execute_onexit(onexit_entry* table)
{
    for (auto entry = table; entry;)
    {
        const auto next = entry->_next;
        delete entry;
        entry = next;
    }

    return 0;
}

extern "C" int __cdecl atexit(_PVFV const function)
{
    return register_onexit(s_onexit_table, reinterpret_cast<$onexit const>(function));
}

// This function executes a table of atexit() functions.  The Terminators 
// are executed in reverse order, to give the required LIFO execution order.  
// If the table is uninitialized, this function has no effect.  
// After executing the terminators, this function resets the table
// so that it is uninitialized.  Returns 0 on success; -1 on failure.
extern "C" int __cdecl onexit()
{
    return execute_onexit(s_onexit_table);
}

extern "C" auto __cdecl _initalloc()
-> void;

// Call all of the C++ static constructors.
extern "C" int __cdecl doinit(void)
{
    // do allocator initializions
    _initalloc();

    // do C initializations
    _initterm_e(__xi_a, __xi_z);

    // do C++ initializations
    _initterm(__xc_a, __xc_z);
    return 0;
}

extern "C" int __cdecl doexit(void)
{
    // do exit() of atexit()
    onexit();

    // do C initializations
    _initterm(__xp_a, __xp_z);

    // do C++ terminations
    _initterm(__xt_a, __xt_z);
    return 0;
}

#pragma once
#include "Ntddk.hpp"


extern unsigned long const  DefaultPoolTag;
extern POOL_TYPE     DefaultPOOL_TYPE;
extern unsigned long        DefaultMdlProtection;


void* __cdecl __core_allocator(size_t _size, POOL_TYPE _pool_type, unsigned long _tag);

void __cdecl __core_deletor(void* _ptr, POOL_TYPE _pool_type, unsigned long _tag);


extern "C"
{
    #pragma warning(suppress: 4565)
	__declspec(restrict) void* __cdecl malloc(size_t _size);

    #pragma warning(suppress: 4565)
	void __cdecl free(void * _ptr);
}

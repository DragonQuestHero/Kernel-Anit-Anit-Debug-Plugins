#include "Ntddk.hpp"
#include "c_alloc.h"
#include "macro.h"


extern unsigned long const DefaultPoolTag  = ByteSwap32$('ccrt');
extern POOL_TYPE DefaultPOOL_TYPE = NonPagedPool;
extern unsigned long DefaultMdlProtection = MdlMappingNoExecute;
#define memory_targe 'ock'


extern "C" void __cdecl _initalloc()
{
    RTL_OSVERSIONINFOW ver_info{};

    auto status = RtlGetVersion(&ver_info);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    if ((ver_info.dwMajorVersion <  6) ||
        (ver_info.dwMajorVersion == 6 && ver_info.dwMinorVersion < 2))
    {
        DefaultPOOL_TYPE = POOL_TYPE::NonPagedPool;
        DefaultMdlProtection = 0;
    }
}

void* __cdecl __core_allocator(size_t _size, POOL_TYPE _pool_type, unsigned long _tag)
{
    return ExAllocatePoolWithTag(_pool_type, _size, _tag);
}

void __cdecl __core_deletor(void * _ptr, POOL_TYPE /*_pool_type*/, unsigned long _tag)
{
    return ExFreePoolWithTag(_ptr, _tag);
}

extern "C"
{
    __declspec(restrict) auto __cdecl malloc(size_t _size) -> void *
    {
		return __core_allocator(_size, POOL_TYPE::PagedPool, memory_targe);
    }

    auto __cdecl free(void * _ptr) -> void
    {
		return __core_deletor(_ptr, POOL_TYPE::PagedPool, memory_targe);
    }
}

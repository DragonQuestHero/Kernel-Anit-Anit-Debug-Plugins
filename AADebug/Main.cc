#include <windows.h>
#include "AADebug.h"


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		AADebug aadebug;
		if (!aadebug.Init())
		{
			MessageBoxA(NULL, "Init", NULL, NULL);
		}
		if (!aadebug.Test())
		{
			MessageBoxA(NULL, "Test", NULL, NULL);
		}
		//aadebug.StartHook();
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}


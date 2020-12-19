#include "DetoursHook.h"

void *DetoursHook(const char * DllName, const char * FuncName, void * NewFunc)
{
	void *original_func = nullptr;
	ULONG ret = 0;

	original_func = DetourFindFunction(DllName, FuncName);

	/*ret = DetourTransactionBegin();
	if (ret != NO_ERROR)
	{
		return nullptr;
	}

	ret = DetourUpdateThread(GetCurrentThread());
	if (ret != NO_ERROR)
	{
		return nullptr;
	}*/

	ret = DetourAttach(&original_func, NewFunc);
	if (ret != NO_ERROR)
	{
		return nullptr;
	}

	/*ret = DetourTransactionCommit();
	if (ret != NO_ERROR)
	{
		return nullptr;
	}*/

	return original_func;
}

bool DetoursUnHook(void *OriginalFunc, void * NewFunc)
{
	ULONG ret = 0;

	ret = DetourTransactionBegin();
	if (ret != NO_ERROR)
	{
		return false;
	}

	ret = DetourUpdateThread(GetCurrentThread());
	if (ret != NO_ERROR)
	{
		return false;
	}

	ret = DetourDetach(&OriginalFunc, NewFunc);
	if (ret != NO_ERROR)
	{
		return false;
	}

	ret = DetourTransactionCommit();
	if (ret != NO_ERROR)
	{
		return false;
	}
	return true;
}
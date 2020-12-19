#pragma once
#include <Windows.h>

#include "Detours/detours.h"

void *DetoursHook(const char * DllName, const char * FuncName, void * NewFunc);
bool DetoursUnHook(void *OriginalFunc, void * NewFunc);
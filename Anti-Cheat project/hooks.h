#ifndef HOOKS_H
#define HOOKS_H

#include "common.h"

BOOL CheckIATHooks(DWORD targetPID);
BOOL CheckEATHooksForModule(HANDLE hProcess, const char* moduleName);
BOOL CheckThreadStack(HANDLE hThread, CONTEXT* ctx); // checks if stack of a thread is clean
BOOL isBackedByModuleRemote(PVOID address);
#endif
#ifndef PROCESS_UTILS_H
#define PROCESS_UTILS_H

#include "common.h"

DWORD GetPIDByName(const char* processName);
BOOL GetRemoteModuleBounds(HANDLE hProcess, const char* moduleName, uintptr_t* start, DWORD* size);
BOOL IsInsideModule(DWORD_PTR address, DWORD_PTR modStart, DWORD modSize);

#endif
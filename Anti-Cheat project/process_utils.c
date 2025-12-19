#define _CRT_SECURE_NO_WARNINGS
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h> // include only if required by public API
BOOL IsInsideModule(DWORD_PTR address, DWORD_PTR modStart, DWORD modSize);
BOOL GetRemoteModuleBounds(HANDLE hProcess, const char* moduleName, uintptr_t* start, DWORD* size);
DWORD GetPIDByName(const char* processName);

#ifdef __cplusplus
}
#endif

#include "common.h"
#include "process_utils.h"
pNtQuerySystemInformation NtQuerySystemInformation = NULL;

BOOL InitializeNtApi() {
    if (NtQuerySystemInformation != NULL) return TRUE;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;

    NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    return NtQuerySystemInformation != NULL;
}
// check wether an address is within a valid module
BOOL IsInsideModule(DWORD_PTR address, DWORD_PTR modStart, DWORD modSize) {
    if (modStart == 0 || modSize == 0) return FALSE;
    return (address >= modStart && address <= (modStart + modSize));
}



BOOL isBackedByModuleRemote(PVOID address) {
    HMODULE lphModule[256] = { 0 };
    DWORD lpcbNeeded;
    MODULEINFO lpmodinfo;
    DWORD64 i = 0;
       if (!EnumProcessModules(hProcess, lphModule, sizeof(lphModule), &lpcbNeeded)) { printf("[-] EnumProcessModules failed\n "); exit(1); }
       while(lphModule[i] != NULL){
           GetModuleInformation(hProcess, lphModule[i], &lpmodinfo, sizeof(MODULEINFO));
           if (IsInsideModule((DWORD_PTR)address, lphModule[i], lpmodinfo.SizeOfImage)) {      
               return TRUE;
           }
           i++;
       }
       return FALSE;

}


BOOL ShouldSkipStackValue(DWORD64 addr, MEMORY_BASIC_INFORMATION* stackMbi,
    MEMORY_BASIC_INFORMATION* outAddrMbi) {
    // Filter 1: Invalid user-mode range
    if (addr < 0x10000 || addr > 0x00007FFFFFFFFFFF) {
        return TRUE;
    }

    // Filter 2: On stack
    if (addr >= (DWORD64)stackMbi->BaseAddress &&
        addr < (DWORD64)((PBYTE)stackMbi->BaseAddress + stackMbi->RegionSize)) {
        return TRUE;
    }

    // Query memory at this address
    if (!VirtualQueryEx(hProcess, (PVOID)addr, outAddrMbi, sizeof(*outAddrMbi))) {
        return TRUE;  // Can't query = skip
    }

    // Filter 3: Not executable
    if (!(outAddrMbi->Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
        return TRUE;
    }

    return FALSE;  // Don't skip - check this address
}




// Helper to get the bounds of a module in the remote process
BOOL GetRemoteModuleBounds(HANDLE hProcess, const char* moduleName, uintptr_t* start, DWORD* size) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
                if (_stricmp(szModName, moduleName) == 0) {
                    MODULEINFO modInfo;
                    GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo));
                    *start = (uintptr_t)modInfo.lpBaseOfDll;
                    *size = modInfo.SizeOfImage;
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

DWORD GetPIDByName(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"dummy-game.exe") == 0) {  // Compare wide strings
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}



    BOOL GetNameByPID(DWORD pid, char* processName, size_t bufferSize) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hSnapshot, &pe32)) {
            CloseHandle(hSnapshot);
            return FALSE;
        }

        do {
            if (pe32.th32ProcessID == pid) {
                // Convert wchar_t to char
                wcstombs(processName, pe32.szExeFile, bufferSize);
                CloseHandle(hSnapshot);
                return TRUE;
            }
        } while (Process32Next(hSnapshot, &pe32));

        CloseHandle(hSnapshot);
        return FALSE;
    }
    PVOID GetProcessObject(DWORD targetPID) {
        // Open handle to target process
        HANDLE hTarget = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPID);
        if (!hTarget) {
            printf("Failed to open target process. Error: %d\n", GetLastError());
            return NULL;
        }

        // Get system handle information
        ULONG size = 0x100000;
        PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(size);
        if (!handleInfo) {
            CloseHandle(hTarget);
            return NULL;
        }

        NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, size, &size);
        if (status == 0xC0000004) {
            free(handleInfo);
            handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(size);
            status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, size, &size);
        }

        PVOID pProcessObject = NULL;
        if (status == 0) {
            DWORD myPID = GetCurrentProcessId();

            // Find our handle to the target process
            for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
                if (handleInfo->Handles[i].UniqueProcessId == myPID &&
                    handleInfo->Handles[i].ObjectTypeIndex == 7) {

                    // Check if this handle matches our opened handle
                    if ((HANDLE)(ULONG_PTR)handleInfo->Handles[i].HandleValue == hTarget) {
                        pProcessObject = handleInfo->Handles[i].Object;
                        printf("Found process object: %p\n", pProcessObject);
                        break;
                    }
                }
            }
        }

        free(handleInfo);
        CloseHandle(hTarget);
        return pProcessObject;
    }
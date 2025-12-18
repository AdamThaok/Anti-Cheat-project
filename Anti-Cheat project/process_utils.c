
#include "common.h"



 // check wether an address is within a valid module
BOOL IsInsideModule(DWORD_PTR address, DWORD_PTR modStart, DWORD modSize) {
    if (modStart == 0 || modSize == 0) return FALSE;
    return (address >= modStart && address <= (modStart + modSize));
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
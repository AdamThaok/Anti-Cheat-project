#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>

#include <Windows.h>

#include <psapi.h> 
#include <tlhelp32.h>
//Sus process detection
static DWORD crc32_table[256];

void InitCRC32Table() {
    for (DWORD i = 0; i < 256; i++) {
        DWORD crc = i;
        for (DWORD j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
        }
        crc32_table[i] = crc;
    }
}

DWORD GetPIDByName(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;  // Not found
}
BOOL CheckIATHooks(DWORD targetPID) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, targetPID);
    if (!hProcess) return FALSE;

    // Get dummy-game's base address
    HMODULE hMods[1024];
    DWORD cbNeeded;
    EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded);
    HMODULE targetModule = hMods[0];  // Main module

    // Read DOS header
    IMAGE_DOS_HEADER dosHeader;
    ReadProcessMemory(hProcess, targetModule, &dosHeader, sizeof(dosHeader), NULL);

    // Read NT headers
    IMAGE_NT_HEADERS ntHeaders;
    ReadProcessMemory(hProcess, (PBYTE)targetModule + dosHeader.e_lfanew,
        &ntHeaders, sizeof(ntHeaders), NULL);

    // Read Import Directory
    DWORD importRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR importDesc;
    PBYTE importAddr = (PBYTE)targetModule + importRVA;

    do {
        ReadProcessMemory(hProcess, importAddr, &importDesc, sizeof(importDesc), NULL);
        if (!importDesc.Name) break;

        // Read DLL name
        char dllName[256];
        ReadProcessMemory(hProcess, (PBYTE)targetModule + importDesc.Name, dllName, 256, NULL);

        // Check each IAT entry...
        // (Similar logic, but using ReadProcessMemory for everything)

        importAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    } while (importDesc.Name);

    CloseHandle(hProcess);
    return FALSE;
}
int main() {
    InitCRC32Table();  // ADD THIS

    char exePath[MAX_PATH];
    //GetModuleFileNameA(NULL, exePath, MAX_PATH);  // ADD THIS
    strcpy(exePath, "C:\\Users\\x\\source\\repos\\Anti-Cheat project\\x64\\Debug\\dummy-game.exe");

    // 1 Check running processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Snapshot failed\n");
        return 1;
    }
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            wprintf(L"PID: %lu - %ls\n", pe32.th32ProcessID, pe32.szExeFile);
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);

    // 2  Text Patching detection
    HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file\n");
        return 0;
    }

    DWORD crc = 0xFFFFFFFF;
    BYTE buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hFile, buffer, 4096, &bytesRead, NULL) && bytesRead > 0) {
        for (DWORD i = 0; i < bytesRead; i++) {
            crc = (crc >> 8) ^ crc32_table[(crc ^ buffer[i]) & 0xFF];
        }
    }
    crc = ~crc;
    CloseHandle(hFile);

    printf("File CRC32: 0x%08X\n", crc);

    DWORD expectedCRC = 0xAC6EBFB3;  // Store this from clean build
    if (crc != expectedCRC) {
        printf("[!] File integrity violation!\n");
    }



    // 3 IAT Hook detection
    DWORD pid = GetPIDByName("dummy-game.exe");
    if (!CheckIATHooks(pid)) {
        printf("IAT Hook Detected!\n");
    }







    return 0;
}

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>

#include <Windows.h>

#include <psapi.h> 
#include <tlhelp32.h>
#include <stddef.h>
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





BOOL CheckThreadStack(HANDLE hThread, CONTEXT* ctx) {

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
            // wprintf(L"PID: %lu - %ls\n", pe32.th32ProcessID, pe32.szExeFile);
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
    if (CheckIATHooks(pid)) {
        printf("IAT Hook Detected!\n");
    }





    // 4 Eat detection 
    //Find kernel32 base
    // find export table
    //iterate for each function number

    HMODULE kernel32Base = GetModuleHandleA("kernel32.dll");

    //fine eat
// 4. EAT Detection (Remote Process)

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        printf("[!] Failed to open process. Error: %lu\n", GetLastError());
        return 1;
    }

    // Alternative: Check only important DLLs
    const char* criticalDLLs[] = {
        "kernel32.dll",
        "kernelbase.dll",
        "ntdll.dll",
        "user32.dll",
        "gdi32.dll",
        "d3d9.dll",
        "d3d11.dll",
        "dxgi.dll"
    };

    for (int i = 0; i < sizeof(criticalDLLs) / sizeof(criticalDLLs[0]); i++) {
        CheckEATHooksForModule(hProcess, criticalDLLs[i]);
    }
    printf("[+] Scan complete. No EAT hooks found.\n");








    // stack detection



	THREADENTRY32 te32;
	HANDLE ThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    CONTEXT ctx;
    Thread32First(ThreadSnap, &te32);

    do {
        if (te32.th32OwnerProcessID == pid) {
            //check if stack has legit values
            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, te32.th32ThreadID);
            if (!hThread) { printf("[-] Got an invalid thread handle, exiting..."); exit(1); }
            SuspendThread(hThread);
            ctx.ContextFlags = CONTEXT_FULL;
            GetThreadContext(hThread, &ctx);
            
            CheckThreadStack(hThread, &ctx);

            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    } while (Thread32Next(ThreadSnap, &te32));
       



    





    return 0;
}
#define _CRT_SECURE_NO_WARNINGS

#include "winternl.h"
#include "common.h"
#include "process_utils.h"
#include "hooks.h"
//Sus process detection
static DWORD crc32_table[256];
HANDLE hProcess;

// Global variables requested (do not change program logic)
// These mirror the variables used later in main() so they are available globally.

ULONG size = 0;
NTSTATUS status = 0;

void InitCRC32Table() {
    for (DWORD i = 0; i < 256; i++) {
        DWORD crc = i;
        for (DWORD j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
        }
        crc32_table[i] = crc;
    }
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

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
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
    te32.dwSize = sizeof(THREADENTRY32);
    HANDLE ThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    if (!ThreadSnap) { printf("[-]Invalid threadsnap handle"); }
    CONTEXT ctx;
    Thread32First(ThreadSnap, &te32);
    BOOL DbgClean = TRUE;
    do {
        if (te32.th32OwnerProcessID == pid) {
            //check if stack has legit values
            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, te32.th32ThreadID);
            if (!hThread) { printf("[-] Got an invalid thread handle, exiting..."); exit(1); }
            SuspendThread(hThread);
            ctx.ContextFlags = CONTEXT_ALL;
            GetThreadContext(hThread, &ctx);


            // stack detection
            CheckThreadStack(hThread, &ctx);

            // Debugger register check
            if (ctx.Dr7 != 0) {
                printf("[!] Hardware breakpoint detected!\n");
                BOOL DbgClean = 0;
            }

            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    } while (Thread32Next(ThreadSnap, &te32));

    printf("[+] Debug registers clean!\n");
    printf("[+] Stack  detected! is clean\n");

    if (!InitializeNtApi()) {
        printf("Failed to initialize NT API\n");
        return;
    }
    size = 0x100000; // 1MB 1fb
    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(size);
    status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, size, &size);
    if (status == 0xC0000004) {
        free(handleInfo);
        handleInfo = malloc(size); // Reallocate with correct size
        status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, size, &size);
    }



    // Check who has open handle to game
    if (handleInfo == NULL) exit(1);
    char pname[MAX_PATH] = { 0 };
    PVOID pProcessObject = NULL;
    PVOID pTargetProcessObj = GetProcessObject(pid); 
    // Find the process object by looking for ANY handle with type 7 that another process has to target
    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        if (handleInfo->Handles[i].ObjectTypeIndex == 7 && handleInfo->Handles[i].Object == pTargetProcessObj) {
            GetNameByPID(handleInfo->Handles[i].UniqueProcessId, pname, MAX_PATH);
            printf("ppid %d with name %s has open handle to target process\n", handleInfo->Handles[i].UniqueProcessId, pname);
        }
    }

    return 0;
}

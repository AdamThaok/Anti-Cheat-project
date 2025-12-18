#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>

#include <Windows.h>





BOOL CheckIATHooks(DWORD targetPID) {
    printf("[-] Attaching to PID: %lu\n", targetPID);
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, targetPID);
    if (!hProcess) {
        printf("[!] Failed to open process. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // 1. Get Base Address of the main module (the .exe)
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        printf("[!] Failed to enumerate modules.\n");
        CloseHandle(hProcess); return FALSE;
    }
    HMODULE hMainModule = hMods[0];

    // 2. Pre-calculate bounds for common "Safe" forwarding targets
    DWORD_PTR ntdllStart = 0; DWORD ntdllSize = 0;
    GetRemoteModuleBounds(hProcess, "ntdll.dll", &ntdllStart, &ntdllSize);

    DWORD_PTR kbaseStart = 0; DWORD kbaseSize = 0;
    GetRemoteModuleBounds(hProcess, "KernelBase.dll", &kbaseStart, &kbaseSize);

    DWORD_PTR win32uStart = 0; DWORD win32uSize = 0;
    GetRemoteModuleBounds(hProcess, "win32u.dll", &win32uStart, &win32uSize);

    // 3. Read Headers to find Import Directory
    IMAGE_DOS_HEADER dosHeader;
    ReadProcessMemory(hProcess, hMainModule, &dosHeader, sizeof(dosHeader), NULL);

    IMAGE_NT_HEADERS ntHeaders;
    ReadProcessMemory(hProcess, (PBYTE)hMainModule + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), NULL);

    DWORD importRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) {
        printf("[!] No Import Table found.\n");
        CloseHandle(hProcess); return FALSE;
    }

    IMAGE_IMPORT_DESCRIPTOR importDesc;
    PBYTE importDescAddr = (PBYTE)hMainModule + importRVA;

    int hookCount = 0;

    // --- OUTER LOOP: Iterate over Imported DLLs ---
    while (TRUE) {
        if (!ReadProcessMemory(hProcess, importDescAddr, &importDesc, sizeof(importDesc), NULL)) break;
        if (importDesc.Name == 0) break; // End of imports

        char dllName[256];
        ReadProcessMemory(hProcess, (PBYTE)hMainModule + importDesc.Name, dllName, sizeof(dllName), NULL);

        // Get valid bounds for this specific DLL (e.g. KERNEL32.DLL)
        DWORD_PTR modStart = 0;
        DWORD modSize = 0;
        BOOL foundModule = GetRemoteModuleBounds(hProcess, dllName, &modStart, &modSize);

        if (foundModule) {
            // IAT (FirstThunk) = The Addresses (What we check)
            // INT (OriginalFirstThunk) = The Names (What we print)
            DWORD_PTR thunkRef = importDesc.FirstThunk;
            DWORD_PTR funcNameRef = importDesc.OriginalFirstThunk;

            // If OriginalFirstThunk is 0, fall back to FirstThunk (rare, but happens)
            if (funcNameRef == 0) funcNameRef = thunkRef;

            PBYTE thunkAddr = (PBYTE)hMainModule + thunkRef;
            PBYTE thunkOrgAddr = (PBYTE)hMainModule + funcNameRef;

            // --- INNER LOOP: Iterate over Functions ---
            while (TRUE) {
                IMAGE_THUNK_DATA thunkData;    // Holds Address
                IMAGE_THUNK_DATA thunkOrgData; // Holds Name Info

                if (!ReadProcessMemory(hProcess, thunkAddr, &thunkData, sizeof(thunkData), NULL)) break;
                if (!ReadProcessMemory(hProcess, thunkOrgAddr, &thunkOrgData, sizeof(thunkOrgData), NULL)) break;

                // End of IAT
                if (thunkData.u1.Function == 0) break;

                DWORD_PTR funcAddr = thunkData.u1.Function;

                // --- RESOLVE FUNCTION NAME ---
                char funcName[256] = "Unknown";

                // Check if imported by Ordinal (High bit set)
                // On x64, IMAGE_ORDINAL_FLAG is extremely large, so we check the high bit.
                if (thunkOrgData.u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    sprintf_s(funcName, sizeof(funcName), "Ordinal_%llu", thunkOrgData.u1.Ordinal & 0xFFFF);
                }
                else {
                    // Imported by Name: Follow RVA to IMAGE_IMPORT_BY_NAME
                    DWORD_PTR nameRVA = thunkOrgData.u1.AddressOfData;
                    // Skip 2 bytes (Hint) to get the string
                    ReadProcessMemory(hProcess, (PBYTE)hMainModule + nameRVA + 2, funcName, sizeof(funcName), NULL);
                }

                // --- HOOK CHECKING ---
                // 1. Is it inside the DLL it claims to be from?
                BOOL isSafe = IsInsideModule(funcAddr, modStart, modSize);

                // 2. If not, is it inside a known safe Forwarder?
                if (!isSafe) {
                    if (IsInsideModule(funcAddr, ntdllStart, ntdllSize) ||
                        IsInsideModule(funcAddr, kbaseStart, kbaseSize) ||
                        IsInsideModule(funcAddr, win32uStart, win32uSize)) {
                        isSafe = TRUE;
                    }
                }

                if (!isSafe) {
                    printf("[HOOK DETECTED] !!! \n");
                    printf("  Function:   %s\n", funcName);
                    printf("  Import DLL: %s\n", dllName);
                    printf("  IAT Ptr:    0x%p\n", thunkAddr);
                    printf("  Jump To:    0x%p (OUTSIDE VALID MODULES)\n\n", (void*)funcAddr);
                    hookCount++;
                }

                // Move to next entry (8 bytes on x64, 4 on x86)
                thunkAddr += sizeof(IMAGE_THUNK_DATA);
                thunkOrgAddr += sizeof(IMAGE_THUNK_DATA);
            }
        }
        importDescAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    CloseHandle(hProcess);

    if (hookCount == 0) {
        printf("[-] Scan complete. No hooks found.\n");
        return FALSE;
    }
    else {
        printf("[!] Scan complete. Found %d hooks.\n", hookCount);
        return TRUE;
    }
}
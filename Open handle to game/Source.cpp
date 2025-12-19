#include <windows.h>
#include <stdio.h>

int main() {
    DWORD targetPID = 7000;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);

    if (hProcess) {
        printf("Successfully opened handle to PID %d\n", targetPID);
        printf("Handle value: %p\n", hProcess);
        printf("Press Enter to close handle...\n");
        getchar();
        CloseHandle(hProcess);
        printf("Handle closed\n");
    }
    else {
        printf("Failed to open handle to PID %d. Error: %d\n", targetPID, GetLastError());
    }

    return 0;
}
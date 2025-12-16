#include <stdio.h>
#include <Windows.h>

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

int main() {
    InitCRC32Table();

    char exePath[] = "C:\\Users\\x\\source\\repos\\Anti-Cheat project\\x64\\Debug\\dummy-game.exe";

    HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file\n");
        return 1;
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

    printf("dummy-game.exe CRC32: 0x%08X\n", crc);
    getchar();
    return 0;
}
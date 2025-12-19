#ifndef PROCESS_UTILS_H
#define PROCESS_UTILS_H
#include "common.h"

#define SystemHandleInformation 0x10

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

extern pNtQuerySystemInformation NtQuerySystemInformation;
BOOL GetNameByPID(DWORD pid, char* processName, size_t bufferSize);
BOOL DetectSuspiciousHandles(DWORD targetPID);
DWORD GetPIDByName(const char* processName);
BOOL GetRemoteModuleBounds(HANDLE hProcess, const char* moduleName, uintptr_t* start, DWORD* size);
BOOL IsInsideModule(DWORD_PTR address, DWORD_PTR modStart, DWORD modSize);
BOOL isBackedByModuleRemote(PVOID address);
BOOL ShouldSkipStackValue(DWORD64 addr, MEMORY_BASIC_INFORMATION* stackMbi,
    MEMORY_BASIC_INFORMATION* outAddrMbi);
BOOL InitializeNtApi();
PVOID GetProcessObject(DWORD targetPID);
#endif
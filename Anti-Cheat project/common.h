#ifndef COMMON_H
#define COMMON_H

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <psapi.h> 
#include <tlhelp32.h>
#include <stddef.h>
extern DWORD PID;
extern HANDLE hProcess;

// Shared table used by the integrity checker
extern DWORD crc32_table[256];

#endif
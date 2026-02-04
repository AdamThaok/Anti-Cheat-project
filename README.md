# Usermode Anti-Cheat System

A Windows usermode anti-cheat implementation demonstrating various detection techniques used to identify game manipulation, debugging, and code injection attempts.

## Overview

This project implements multiple layers of protection commonly found in commercial anti-cheat solutions, focusing on usermode detection mechanisms. It serves as an educational resource for understanding how anti-cheat systems detect malicious activity.

## Detection Techniques

### 1. Process Enumeration
Scans running processes using `CreateToolhelp32Snapshot` to identify known cheat tools, debuggers, or suspicious applications running alongside the protected game.

### 2. File Integrity Verification (CRC32)
Computes a CRC32 checksum of the game executable and compares it against a known-good value. Detects:
- Static binary patching
- Modified game files
- Tampered executables

### 3. IAT Hook Detection
Scans the Import Address Table of the target process to detect function redirection. Identifies when imported functions have been hooked to intercept API calls.

### 4. EAT Hook Detection
Examines the Export Address Table of critical system DLLs for modifications:
- `kernel32.dll`
- `kernelbase.dll`
- `ntdll.dll`
- `user32.dll`
- `gdi32.dll`
- `d3d9.dll` / `d3d11.dll` / `dxgi.dll`

### 5. Stack Analysis
Analyzes thread call stacks to detect:
- Return addresses pointing outside legitimate modules
- Stack-based code execution
- Injected shellcode

### 6. Hardware Breakpoint Detection
Inspects debug registers (DR0-DR7) across all threads to detect:
- Hardware breakpoints set by debuggers
- Anti-anti-debug bypass attempts

### 7. Handle Enumeration
Uses `NtQuerySystemInformation` with `SystemHandleInformation` to identify external processes holding handles to the protected game, detecting:
- Memory reading/writing tools
- External cheat software
- Process manipulation attempts

## Project Structure

```
├── main.c              # Main detection loop
├── common.h            # Common definitions and includes
├── winternl.h          # NT API structures and definitions
├── process_utils.h/.c  # Process enumeration utilities
├── hooks.h/.c          # Hook detection implementations
└── dummy-game.exe      # Test target application
```

## Building

### Requirements
- Visual Studio 2019/2022
- Windows SDK
- x64 architecture target

### Compilation
1. Open the solution in Visual Studio
2. Set configuration to `x64 Debug` or `x64 Release`
3. Build the solution

## Usage

```bash
# Run the anti-cheat scanner
Anti-Cheat.exe
```

The scanner will output detection results for each check:
```
File CRC32: 0xAC6EBFB3
[+] Scan complete. No EAT hooks found.
[+] Debug registers clean!
[+] Stack detected! is clean
ppid 1234 with name cheatengine-x86_64.exe has open handle to target process
```

## Configuration

Update the following values for your target:

```c
// Path to protected executable
strcpy(exePath, "C:\\Path\\To\\Your\\Game.exe");

// Expected CRC32 of clean build
DWORD expectedCRC = 0xAC6EBFB3;

// Target process name
DWORD pid = GetPIDByName("your-game.exe");
```

## Limitations

This is a **usermode-only** implementation with inherent limitations:
- Can be bypassed by kernel-level cheats
- Susceptible to usermode unhooking techniques
- Detection signatures can be fingerprinted and evaded
- No hypervisor-level protection

For production use, consider combining with kernel-mode drivers and additional obfuscation.

## Educational Purpose

This project is intended for **educational purposes only** to understand:
- Windows process internals
- Memory protection mechanisms
- Common hooking techniques
- Anti-cheat architecture design

## Dependencies

- Windows API (kernel32, ntdll)
- Tool Help Library (tlhelp32.h)
- Native API (NtQuerySystemInformation)

## License

This project is provided for educational and research purposes.

## Disclaimer

This software is provided as-is for learning purposes. Do not use these techniques to circumvent legitimate software protections or violate terms of service of any application.

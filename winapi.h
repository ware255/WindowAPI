#pragma once

#include <windows.h>
#include <winternl.h>

#define STATUS_SUCCESS    0x00000000
#define SYSCALL_STUB_SIZE 21

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

extern MyNtOpenProcess NtOpenProcess;
extern char OpenProcStub[SYSCALL_STUB_SIZE];

extern MyNtAllocateVirtualMemory NtAllocateVirtualMemory;
extern char AllocStub[SYSCALL_STUB_SIZE];

extern MyNtWriteVirtualMemory NtWriteVirtualMemory;
extern char WVMStub[SYSCALL_STUB_SIZE];

extern MyNtProtectVirtualMemory NtProtectVirtualMemory;
extern char ProtectStub[SYSCALL_STUB_SIZE];

enum find_call {
    Find_OpenProcess = 1,
    Find_VirtualAlloc,
    Find_WriteVirtualMemory,
    Find_ProtectVirtualMemory
};

/*******************************************
 STANDARD LIBRARIES
*******************************************/
const wchar_t* MyWcsString(const wchar_t *Str, const wchar_t *_Str);
errno_t MyStringCopy_Safe(wchar_t *dest, rsize_t dest_size, const wchar_t *src);
errno_t MyWcsLower_Safe(wchar_t *Str, size_t SizeInWords);
PVOID CCopyMemory(PVOID Destination, const PVOID Source, SIZE_T Length);
SIZE_T StringLengthW(LPCWSTR String);
int MyStringComparison(const char *s1, const char *s2);

/*******************************************
 LIBRARY LOADING
*******************************************/
HMODULE MyGetModuleHandle(LPCWSTR lModuleName);
FARPROC MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
HMODULE MyLoadLibrary(LPCWSTR lpFileName);

/*******************************************
 PROCESS CREATION
*******************************************/
HANDLE MyOpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
LPVOID MyVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBOOL MyWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
BOOL MyVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

/*******************************************
 OTHER
*******************************************/
VOID RtlInitUnicodeString_(PUNICODE_STRING DestinationString, PCWSTR SourceString);

/*******************************************
 HELLS GATE POC
*******************************************/
BOOL EstablishSyscalls(enum find_call fc);

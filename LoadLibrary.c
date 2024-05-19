#include "winapi.h"

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

#include "winapi.h"

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

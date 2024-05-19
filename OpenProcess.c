#include "winapi.h"

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

#include "winapi.h"

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

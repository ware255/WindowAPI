#include "winapi.h"

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

#include "winapi.h"

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

#include "winapi.h"

PVOID CCopyMemory(PVOID Destination, const PVOID Source, SIZE_T Length) {
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;
    while (Length--) *D++ = *S++;
    return Destination;
}

#include "winapi.h"

VOID RtlInitUnicodeString_(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
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

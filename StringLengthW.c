#include "winapi.h"

SIZE_T StringLengthW(LPCWSTR String) {
    static LPCWSTR String2;
    for (String2 = String; *String2; ++String2);
    return (String2 - String);
}

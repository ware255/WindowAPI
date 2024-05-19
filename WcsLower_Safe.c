#include "winapi.h"

errno_t MyWcsLower_Safe(wchar_t *Str, size_t SizeInWords) {
    if (Str == NULL) {
        abort();
        return EINVAL;
    }

    static size_t len = 0;
    while (Str[len] != '\0') len++;

    if (len > SizeInWords) {
        abort();
        return ERANGE;
    }

    for (size_t i = 0; i < len; i++)
        if ((Str[i] >= 'A') && (Str[i] <= 'Z')) Str[i] += 0x20;

    return 0;
}

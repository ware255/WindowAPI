#include "winapi.h"

errno_t MyStringCopy_Safe(wchar_t *dest, rsize_t dest_size, const wchar_t *src) {
    if (dest == NULL) {
        abort();
        return EINVAL;
    }
    else if (src == NULL) {
        dest[0] = '\0';
        abort();
        return EINVAL;
    }

    static size_t len = 0;
    while (src[len] != '\0') len++;

    if (dest_size <= len) {
        dest[0] = '\0';
        abort();
        return ERANGE;
    }

    wchar_t *tmp = dest;
    while ((*dest++ = *src++));
    dest = tmp;

    return 0;
}

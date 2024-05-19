#include "winapi.h"

const wchar_t* MyWcsString(const wchar_t *Str, const wchar_t *_Str) {
    static int ret, t = 0;
    while (*Str != '\0') {
        const wchar_t *t1 = Str;
        const wchar_t *t2 = _Str;
        while (*t1 && *t2) {
            if (*t1 != *t2) {
                t = 1;
                break;
            }
            t1++; t2++;
        }
        ret = t ? 0 : (*t2 == '\0');
        if ((*Str == *_Str) && ret) return Str;
        Str++; t = 0;
    }
    return NULL;
}

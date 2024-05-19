#include "winapi.h"

int MyStringComparison(const char *s1, const char *s2) {
    static int res;
    while (1) if ((res = *s1 - *s2++) != 0 || !*s1++) break;
    return res;
}

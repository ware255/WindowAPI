#include <cstdio>
#include "winapi.c"

typedef int(WINAPI *MesBox)(HWND, LPCWSTR, LPCWSTR, UINT);

int main() {
    MesBox func = 0;

    HMODULE hMod = MyLoadLibrary(L"user32.dll");

    if (hMod == NULL) return 1;

    func = (MesBox)MyGetProcAddress(hMod, "MessageBoxW");

    if (func) (*func)(0, L"Meow-meow!", L"=^..^=", MB_OK);
    FreeLibrary(hMod);

    return 0;
}

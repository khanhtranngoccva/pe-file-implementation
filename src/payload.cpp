#include <windows.h>
#include "peb-lookup.h"

// It's worth noting that strings can be defined nside the .text section:
#pragma code_seg(".text")

wchar_t kernel32_str[] = L"kernel32.dll";
char load_lib_str[] = "LoadLibraryA";

int main() {
    // Stack based strings for libraries and functions the shellcode needs
    wchar_t kernel32_dll_name[] = L"kernel32.dll";
    char load_lib_name[] = "LoadLibraryA";
    char get_proc_name[] = "GetProcAddress";
    char user32_dll_name[] = "user32.dll";
    char message_box_name[] = "MessageBoxW";

    // stack based strings to be passed to the messagebox win api
    wchar_t msg_content[] = L"attempt 1?";
    wchar_t msg_title[] = L"demonstration";

    // resolve kernel32 image base
    void *base = get_module_by_name(kernel32_dll_name);
    if (!base) {
        return 1;
    }

    // resolve loadlibraryA() address
    void *load_lib = get_func_by_name(base, load_lib_name);
    if (!load_lib) {
        return 2;
    }

    // resolve getprocaddress() address
    void *get_proc = get_func_by_name(base, get_proc_name);
    if (!get_proc) {
        return 3;
    }

    // loadlibrarya and getprocaddress function definitions
    const auto $LoadLibraryA = reinterpret_cast<HMODULE(WINAPI*)(LPCSTR)>(load_lib);
    const auto $GetProcAddress = reinterpret_cast<FARPROC(WINAPI*)(HMODULE, LPCSTR)>(get_proc);

    // load user32.dll
    const auto u32_dll = $LoadLibraryA(user32_dll_name);

    // messageboxw function definition
    const auto $MessageBoxW = reinterpret_cast<
        int(WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT)
    >($GetProcAddress(u32_dll, message_box_name));

    if ($MessageBoxW == nullptr) return 4;
    $MessageBoxW(nullptr, msg_content, msg_title, MB_OK);

    return 0;
}
#include "peb-lookup.h"
#include "../dist/oep-stager-header.h"

// It's worth noting that strings can be defined inside the .text section:
#pragma code_seg(".text")

int main() {
    char create_thread_name[] = {'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0};
    char get_exit_code_thread_name[] = {'G', 'e', 't', 'E', 'x', 'i', 't', 'C', 'o', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0};
    char wait_for_single_object_name[] = {'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', 0};
    char message_box_name[] = {'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'W', 0};
    char kernel32_dll_name_a[] = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0};
    wchar_t kernel32_dll_name[] = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0};
    char load_lib_name[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0};
    char get_proc_name[] = {'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0};
    char user32_dll_name[] = {'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0};
    wchar_t msg_content[] = {'T', 'h', 'i', 's', ' ', 'w', 'o', 'r', 'k', 's', 0};
    wchar_t msg_title[] = {'T', 'h', 'i', 's', ' ', 'w', 'o', 'r', 'k', 's', 0};

    LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!base) {
        return 1;
    }
    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)load_lib_name);
    if (!load_lib) {
        return 2;
    }
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)get_proc_name);
    if (!get_proc) {
        return 3;
    }

    // loadlibrarya and getprocaddress function definitions
    const auto $LoadLibraryA = reinterpret_cast<HMODULE(WINAPI *)(LPCSTR)>(load_lib);
    const auto $GetProcAddress = reinterpret_cast<FARPROC(WINAPI *)(HMODULE, LPCSTR)>(get_proc);

    // load user32.dll
    const auto u32_dll = $LoadLibraryA(user32_dll_name);
//    const auto kernel32_dll = $LoadLibraryA(kernel32_dll_name_a);

    if (!u32_dll) {
        return 4;
    }

//    if (!kernel32_dll) {
//        return 5;
//    }

//     resolve createthread() address
//    auto create_thread = $GetProcAddress(kernel32_dll, create_thread_name);
//    if (!create_thread) {
//        return 6;
//    }
//
//     resolve waitforsingleobject() address
//    auto wait_for_single_object = $GetProcAddress(kernel32_dll, wait_for_single_object_name);
//    if (!wait_for_single_object) {
//        return 7;
//    }

//    const auto $CreateThread = reinterpret_cast<HANDLE(WINAPI *)(
//            _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
//            _In_ SIZE_T dwStackSize,
//            _In_ LPTHREAD_START_ROUTINE lpStartAddress,
//            _In_opt_ __drv_aliasesMem LPVOID lpParameter,
//            _In_ DWORD dwCreationFlags,
//            _Out_opt_ LPDWORD lpThreadId
//    )>(create_thread);
//    const auto $WaitForSingleObject = reinterpret_cast<DWORD(WINAPI *)(
//            _In_ HANDLE hHandle,
//            _In_ DWORD dwMilliseconds
//    )>(wait_for_single_object);

    // messageboxw function definition
    const auto $MessageBoxW = reinterpret_cast<
            int (WINAPI *)(HWND, LPCWSTR, LPCWSTR, UINT)
            >($GetProcAddress(u32_dll, message_box_name));


    if ($MessageBoxW == nullptr) return 101;
//    const auto $GetExitCodeThread = reinterpret_cast<BOOL(WINAPI*)(
//            _In_ HANDLE hThread,
//            _Out_ LPDWORD lpExitCode
//    )>($GetProcAddress(kernel32_dll, get_exit_code_thread_name));
//
//    if ($GetExitCodeThread == nullptr) return 102;
    $MessageBoxW(nullptr, msg_content, msg_title, MB_OK);

//    unsigned long long resume = RESUME_POINT;

//    auto newThread = $CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(resume), nullptr, 0,
//                                   nullptr);
//    $WaitForSingleObject(newThread, INFINITE);

//    return 0;
//    DWORD exitCode;
//    auto exitRes = $GetExitCodeThread(newThread, &exitCode);
//    if (exitRes) {
//        return exitCode;
//    } else {
//        return 10;
//    }
}
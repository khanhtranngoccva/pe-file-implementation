#include "peb-lookup.h"
#include "oep-stager-header.h"

// It's worth noting that strings can be defined inside the .text section:
#pragma code_seg(".text")

__declspec(allocate(".text"))
char create_thread_name[] = "CreateThread";
__declspec(allocate(".text"))
char get_exit_code_thread_name[] = "GetExitCodeThread";
__declspec(allocate(".text"))
char wait_for_single_object_name[] = "WaitForSingleObject";
__declspec(allocate(".text"))
char message_box_name[] = "MessageBoxW";
__declspec(allocate(".text"))
wchar_t kernel32_dll_name[] = L"kernel32.dll";
__declspec(allocate(".text"))
char load_lib_name[] = "LoadLibraryA";
__declspec(allocate(".text"))
char get_proc_name[] = "GetProcAddress";
__declspec(allocate(".text"))
char user32_dll_name[] = "user32.dll";

__declspec(allocate(".text"))
wchar_t msg_content[] = L"attempt 1?";
__declspec(allocate(".text"))
wchar_t msg_title[] = L"demonstration";


int main() {
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

    // resolve createthread() address
    void *create_thread = get_func_by_name(base, create_thread_name);
    if (!create_thread) {
        return 4;
    }

    // resolve waitforsingleobject() address
    void *wait_for_single_object = get_func_by_name(base, wait_for_single_object_name);
    if (!wait_for_single_object) {
        return 5;
    }

    // resolve getexitcodethread() address
    void *get_exit_code_thread = get_func_by_name(base, get_exit_code_thread_name);
    if (!get_exit_code_thread) {
        return 5;
    }

    // loadlibrarya and getprocaddress function definitions
    const auto $LoadLibraryA = reinterpret_cast<HMODULE(WINAPI *)(LPCSTR)>(load_lib);
    const auto $GetProcAddress = reinterpret_cast<FARPROC(WINAPI *)(HMODULE, LPCSTR)>(get_proc);
    const auto $CreateThread = reinterpret_cast<HANDLE(WINAPI *)(
            _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
            _In_ SIZE_T dwStackSize,
            _In_ LPTHREAD_START_ROUTINE lpStartAddress,
            _In_opt_ __drv_aliasesMem LPVOID lpParameter,
            _In_ DWORD dwCreationFlags,
            _Out_opt_ LPDWORD lpThreadId
    )>(create_thread);
    const auto $WaitForSingleObject = reinterpret_cast<DWORD(WINAPI *)(
            _In_ HANDLE hHandle,
            _In_ DWORD dwMilliseconds
    )>(wait_for_single_object);
    const auto $GetExitCodeThread = reinterpret_cast<BOOL(WINAPI*)(
            _In_ HANDLE hThread,
            _Out_ LPDWORD lpExitCode
    )>(get_exit_code_thread);

    // load user32.dll
    const auto u32_dll = $LoadLibraryA(user32_dll_name);

    // messageboxw function definition
    const auto $MessageBoxW = reinterpret_cast<
            int (WINAPI *)(HWND, LPCWSTR, LPCWSTR, UINT)
            >($GetProcAddress(u32_dll, message_box_name));

    if ($MessageBoxW == nullptr) return 4;
    $MessageBoxW(nullptr, msg_content, msg_title, MB_OK);

    auto newThread = $CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(ORIGINAl_FILE_OEP), nullptr, 0,
                                   nullptr);
    $WaitForSingleObject(newThread, INFINITE);

    DWORD exitCode;
    auto exitRes = $GetExitCodeThread(newThread, &exitCode);
    if (exitRes) {
        return exitCode;
    } else {
        return 10;
    }
}
/* SPDX-License-Identifier: MIT
 * Original Pear translated worker/TLS/normal-return fixture. Each failure has a
 * distinct process exit code; no forced target-thread termination is used.
 */
#include <windows.h>
#include <stdint.h>
__declspec(dllimport) LONG NtTerminateProcess(HANDLE, LONG);
static DWORD slot, main_id;
static volatile DWORD worker_id;
static DWORD WINAPI worker(void *parameter) {
    if (parameter != &worker_id || GetCurrentThreadId() == main_id || TlsGetValue(slot)) return 101;
    worker_id = GetCurrentThreadId();
    if (!TlsSetValue(slot, (void *)(uintptr_t)0x76540) || TlsGetValue(slot) != (void *)(uintptr_t)0x76540) return 102;
    return 6*7;
}
static LONG exercise(void) {
    main_id = GetCurrentThreadId();
    slot = TlsAlloc();
    if (slot == TLS_OUT_OF_INDEXES || !TlsSetValue(slot, (void *)(uintptr_t)0x12340)) return 103;
    DWORD id = 0, exit_code = 0;
    HANDLE thread = CreateThread(0, 1048576, worker, (void *)&worker_id, 0, &id);
    if (!thread || !id || id == main_id) return 104;
    if (WaitForSingleObject(thread, 5000) != WAIT_OBJECT_0) return 105;
    if (!GetExitCodeThread(thread, &exit_code) || exit_code != 42 || worker_id != id) return 106;
    if (TlsGetValue(slot) != (void *)(uintptr_t)0x12340) return 107;
    if (!CloseHandle(thread) || !TlsFree(slot)) return 108;
    return 42;
}
void pear_first_dispatch(void) {
    NtTerminateProcess((HANDLE)(intptr_t)-1, exercise());
    for (;;) {}
}

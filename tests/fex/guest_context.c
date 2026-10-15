/* SPDX-License-Identifier: MIT
 * Original Pear translated worker suspend/context-edit/resume fixture.
 */
#include <windows.h>
#include <stdint.h>
__declspec(dllimport) LONG NtTerminateProcess(HANDLE, LONG);
static volatile LONG stop, ticks;
static CONTEXT context;
extern DWORD pear_guest_spin(volatile LONG *,volatile LONG *);
__asm__(".text\n.global pear_guest_spin\npear_guest_spin:\npush %r12\nmov $17,%r12d\n1: incl (%rdx)\ncmpl $0,(%rcx)\nje 1b\nmov %r12d,%eax\npop %r12\nret\n");
static DWORD WINAPI worker(void *unused) {
    (void)unused;
    return pear_guest_spin(&stop,&ticks);
}
static LONG exercise(void) {
    HANDLE thread=CreateThread(0,1048576,worker,0,0,0);
    if (!thread) return 131;
    while (!ticks) Sleep(0);
    if (SuspendThread(thread)!=(DWORD)0) return 132;
    context.ContextFlags=CONTEXT_INTEGER|CONTEXT_CONTROL;
    if (!GetThreadContext(thread,&context) || context.R12!=17) return 133;
    context.R12=42;
    if (!SetThreadContext(thread,&context)) return 134;
    if (ResumeThread(thread)!=(DWORD)1) return 135;
    stop=1;
    DWORD result;
    if (WaitForSingleObject(thread,10000)!=WAIT_OBJECT_0 || !GetExitCodeThread(thread,&result) || result!=42) return 136;
    if (!CloseHandle(thread)) return 137;
    return 42;
}
void pear_first_dispatch(void) {
    NtTerminateProcess((HANDLE)(intptr_t)-1,exercise());
    for (;;) {}
}

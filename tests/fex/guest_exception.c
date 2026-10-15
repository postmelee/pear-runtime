/* SPDX-License-Identifier: MIT
 * Original Pear handled x64 exception, context edit and ordinary data guard test.
 * All deliberate faults are caught by the guest handler; no native fatal test.
 */
#include <windows.h>
#include <stdint.h>
__declspec(dllimport) LONG NtTerminateProcess(HANDLE, LONG);
__declspec(dllimport) LONG NtQuerySystemTime(int64_t *);
extern int pear_guest_ud2(void);
__asm__(".text\n.global pear_guest_ud2\npear_guest_ud2:\nud2\nret\n");
static volatile LONG illegal_count, guard_count, callback_failure;
static volatile unsigned char *guard_page;
static LONG CALLBACK handle(EXCEPTION_POINTERS *p) {
    if (p->ExceptionRecord->ExceptionCode==EXCEPTION_ILLEGAL_INSTRUCTION &&
        p->ExceptionRecord->ExceptionAddress==(void *)pear_guest_ud2 &&
        p->ContextRecord->Rip==(DWORD64)(uintptr_t)pear_guest_ud2) {
        int64_t now=0;
        if (NtQuerySystemTime(&now) || now<=0) callback_failure=1;
        ++illegal_count;
        p->ContextRecord->Rip+=2;
        p->ContextRecord->Rax=42;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (p->ExceptionRecord->ExceptionCode==STATUS_GUARD_PAGE_VIOLATION &&
        p->ExceptionRecord->NumberParameters>=2 &&
        p->ExceptionRecord->ExceptionInformation[1]==(ULONG_PTR)guard_page) {
        ++guard_count;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static LONG exercise(void) {
    void *handler=AddVectoredExceptionHandler(1,handle);
    if (!handler) return 121;
    if (pear_guest_ud2()!=42 || illegal_count!=1 || callback_failure) return 122;
    guard_page=VirtualAlloc(0,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!guard_page) return 123;
    *guard_page=42;
    DWORD old;
    if (!VirtualProtect((void *)guard_page,4096,PAGE_READWRITE|PAGE_GUARD,&old)) return 124;
    if (*guard_page!=42 || guard_count!=1) return 125;
    if (*guard_page!=42 || guard_count!=1) return 126;
    if (!VirtualFree((void *)guard_page,0,MEM_RELEASE)) return 127;
    if (!RemoveVectoredExceptionHandler(handler)) return 128;
    return 42;
}
void pear_first_dispatch(void) {
    NtTerminateProcess((HANDLE)(intptr_t)-1,exercise());
    for (;;) {}
}

/* SPDX-License-Identifier: MIT
 * Original guest table-based x64 SEH/unwind fixture. No native fatal fault.
 */
#include <windows.h>
#include <stdint.h>
__declspec(dllimport) LONG NtTerminateProcess(HANDLE,LONG);
static volatile unsigned trace, filtered, finalized, handled;
uint64_t pear_before[2][28], pear_after[2][28], pear_alignment[2];
extern void pear_abi_outer(void);
static LONG result;
static LONG filter(EXCEPTION_POINTERS *p) {
    if (p->ExceptionRecord->ExceptionCode!=0xe0420006 ||
        p->ExceptionRecord->NumberParameters!=1 ||
        p->ExceptionRecord->ExceptionInformation[0]!=0x12345678) return EXCEPTION_CONTINUE_SEARCH;
    trace=trace*10+2; ++filtered;
    return EXCEPTION_EXECUTE_HANDLER;
}
__attribute__((noinline)) static void inner(void) {
    ULONG_PTR parameter=0x12345678;
    __try {
        trace=1;
        RaiseException(0xe0420006,0,1,&parameter);
        trace=99;
    } __finally {
        if (AbnormalTermination()) { trace=trace*10+3; ++finalized; }
    }
}
__attribute__((noinline)) static LONG exercise(void) {
    /* Volatile stack locals survive the inner frame's unwind and handler. */
    volatile uint64_t before=0x123456789abcdef0ULL;
    __try { inner(); }
    __except(filter(GetExceptionInformation())) { trace=trace*10+4; ++handled; }
    return trace==1234 && filtered==1 && finalized==1 && handled==1 &&
        before==0x123456789abcdef0ULL ? 42 : 94;
}
void pear_native_outer(void) { result=exercise(); }
void pear_first_dispatch(void) {
    pear_abi_outer();
    if (pear_alignment[0]!=8) result=95;
    for (unsigned i=0;i<28;++i) if (pear_before[0][i]!=pear_after[0][i]) result=96;
    NtTerminateProcess((HANDLE)(intptr_t)-1,result);
    for (;;) {}
}

/* SPDX-License-Identifier: MIT
 * Original finite Windows x64 ABI fixture. Deliberate guest SEH is separate.
 */
#include <windows.h>
#include <stdint.h>
__declspec(dllimport) LONG NtTerminateProcess(HANDLE,LONG);
__declspec(dllimport) LONG NtQuerySystemTime(int64_t *);
__declspec(dllimport) LONG RtlRunOnceExecuteOnce(void *,void *,void *,void **);
extern void pear_abi_outer(void), pear_abi_inner(void);
extern BOOL CALLBACK pear_callback(void *,void *,void **);
uint64_t pear_before[2][28], pear_after[2][28], pear_alignment[2], pear_callback_alignment;
static unsigned calls, failures;
static uintptr_t once;
static int64_t now;
static int same(unsigned slot) {
    for (unsigned i=0;i<28;++i) if (pear_before[slot][i]!=pear_after[slot][i]) return 0;
    return pear_alignment[slot]==8;
}
void pear_native_inner(void) {
    if (NtQuerySystemTime(&now) || now<=0) ++failures;
}
BOOL CALLBACK pear_callback_body(void *run_once,void *parameter,void **context) {
    if (run_once!=&once || parameter!=&calls || !context || pear_callback_alignment!=8) ++failures;
    ++calls;
    pear_abi_inner();
    if (!same(1)) ++failures;
    *context=(void *)(uintptr_t)0x12340;
    return TRUE;
}
void pear_native_outer(void) {
    void *context=0;
    if (RtlRunOnceExecuteOnce(&once,(void *)pear_callback,&calls,&context) || context!=(void *)(uintptr_t)0x12340) ++failures;
}
static void emit(void) {
    /* Fixed-size binary-free hexadecimal state, stable across the two hosts. */
    const char *alphabet="0123456789abcdef";
    static char line[4096]; unsigned n=0; DWORD written=0;
    const char *prefix="{\"event\":\"abi_state\",\"values\":[";
    while (*prefix) line[n++]=*prefix++;
    for (unsigned slot=0;slot<2;++slot) for (unsigned side=0;side<2;++side) for (unsigned i=0;i<28;++i) {
        uint64_t v=side?pear_after[slot][i]:pear_before[slot][i];
        if (slot || side || i) line[n++]=',';
        line[n++]='"'; line[n++]='0'; line[n++]='x';
        for (int j=15;j>=0;--j) line[n++]=alphabet[(v>>(4*j))&15];
        line[n++]='"';
    }
    line[n++]=']';line[n++]='}';line[n++]='\n';
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),line,n,&written,0) || written!=n) ++failures;
}
void pear_first_dispatch(void) {
    pear_abi_outer();
    if (!same(0) || calls!=1) ++failures;
    emit();
    NtTerminateProcess((HANDLE)(intptr_t)-1,failures?93:42);
    for (;;) {}
}

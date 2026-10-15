/* SPDX-License-Identifier: MIT
 * Original Pear x64 code mutation and cross-thread cache invalidation fixture.
 * The role-aware Wine PE mapping keeps these guest bytes native NX throughout.
 */
#include <windows.h>
#include <stdint.h>
__declspec(dllimport) LONG NtTerminateProcess(HANDLE, LONG);
extern int pear_mutable_guest(void);
__asm__(".section .pearcode,\"xr\"\n.balign 4096\n.global pear_mutable_guest\npear_mutable_guest:\n.byte 0xb8,41,0,0,0,0xc3\n.space 4090,0x90\n.text\n");
static HANDLE ready, resume;
static DWORD WINAPI worker(void *unused) {
    (void)unused;
    if (pear_mutable_guest()!=41) return 111;
    if (!SetEvent(ready) || WaitForSingleObject(resume,10000)!=WAIT_OBJECT_0) return 112;
    return pear_mutable_guest();
}
static LONG exercise(void) {
    if (pear_mutable_guest()!=41) return 113;
    ready=CreateEventW(0,TRUE,FALSE,0); resume=CreateEventW(0,TRUE,FALSE,0);
    if (!ready || !resume) return 114;
    HANDLE thread=CreateThread(0,1048576,worker,0,0,0);
    if (!thread || WaitForSingleObject(ready,10000)!=WAIT_OBJECT_0) return 114;
    /* Failed removal must not discard the live image's execution metadata. */
    if (VirtualFree((void *)pear_mutable_guest,1,MEM_RELEASE)) return 121;
    if (pear_mutable_guest()!=41) return 122;
    DWORD old=0, temporary=0, result=0;
    if (!VirtualProtect((void *)pear_mutable_guest,4096,PAGE_READWRITE,&old)) return 115;
    ((volatile unsigned char *)pear_mutable_guest)[1]=42;
    if (!VirtualProtect((void *)pear_mutable_guest,4096,old,&temporary)) return 116;
    if (!FlushInstructionCache(GetCurrentProcess(),(void *)pear_mutable_guest,6)) return 117;
    if (pear_mutable_guest()!=42 || !SetEvent(resume)) return 118;
    if (WaitForSingleObject(thread,10000)!=WAIT_OBJECT_0 || !GetExitCodeThread(thread,&result) || result!=42) return 119;
    if (!CloseHandle(thread) || !CloseHandle(ready) || !CloseHandle(resume)) return 120;
    return 42;
}
void pear_first_dispatch(void) {
    NtTerminateProcess((HANDLE)(intptr_t)-1,exercise());
    for (;;) {}
}

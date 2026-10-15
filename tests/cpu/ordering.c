/* SPDX-License-Identifier: MIT
 * Original finite x64 ordering fixture. Thread/TLS/join handling adapts Pear's
 * guest_thread.c. Epoch acquire/release occurs outside the measured assembly.
 * Only assembly accesses measured shared cells concurrently; reset happens
 * after both workers publish completion and before the next released epoch.
 */
#include <windows.h>
#include <stdint.h>
#ifndef PEAR_ITERATIONS
#define PEAR_ITERATIONS 64
#endif
#ifndef PEAR_ROUNDS
#define PEAR_ROUNDS 2
#endif
__declspec(dllimport) LONG NtTerminateProcess(HANDLE, LONG);
extern unsigned pear_locked(unsigned *, unsigned *), pear_publish(unsigned *, unsigned *);
extern unsigned pear_observe(unsigned *, unsigned *), pear_buffer(unsigned *, unsigned *);
extern unsigned pear_fenced(unsigned *, unsigned *);
struct __attribute__((aligned(128))) cell { unsigned value; char pad[124]; };
static struct cell x, y, epoch, done[2], aborted;
static unsigned results[2], worker_ids[2], main_id, slot;
static ULONGLONG deadline;
static int await(unsigned *p, unsigned value) {
    unsigned spins=0;
    while (__atomic_load_n(p,__ATOMIC_ACQUIRE)!=value) {
        __builtin_ia32_pause();
        /* Three participants must also progress on a two-vCPU reference host.
         * Yield only while awaiting an epoch/completion, outside measured ASM. */
        if (!(spins & 1023)) SwitchToThread();
        if (__atomic_load_n(&aborted.value,__ATOMIC_ACQUIRE)) return 0;
        if (!(++spins & 65535) && GetTickCount64()>deadline) {
            __atomic_store_n(&aborted.value,1,__ATOMIC_RELEASE); return 0;
        }
    }
    return 1;
}
static DWORD WINAPI worker(void *arg) {
    unsigned id=(unsigned)(uintptr_t)arg;
    worker_ids[id]=GetCurrentThreadId();
    if (worker_ids[id]==main_id || TlsGetValue(slot) ||
        !TlsSetValue(slot,(void *)(uintptr_t)(id+1))) {
        __atomic_store_n(&aborted.value,1,__ATOMIC_RELEASE); return 101;
    }
    unsigned serial=0;
    for (unsigned mode=0;mode<4;++mode) for (unsigned i=0;i<PEAR_ITERATIONS;++i) {
        if (!await(&epoch.value,++serial)) return 102;
        unsigned value;
        if (mode==0) value=pear_locked(&x.value,&y.value);
        else if (mode==1) value=id ? pear_observe(&x.value,&y.value) : pear_publish(&x.value,&y.value);
        else if (mode==2) value=id ? pear_buffer(&y.value,&x.value) : pear_buffer(&x.value,&y.value);
        else value=id ? pear_fenced(&y.value,&x.value) : pear_fenced(&x.value,&y.value);
        results[id]=value;
        __atomic_store_n(&done[id].value,serial,__ATOMIC_RELEASE);
    }
    return TlsGetValue(slot)==(void *)(uintptr_t)(id+1) ? 42 : 103;
}
static char output[1024]; static unsigned used;
static void text(const char *p) { while (*p) output[used++]=*p++; }
static void number(unsigned n) {
    char b[16]; unsigned k=0;
    do { b[k++]=(char)('0'+n%10); n/=10; } while(n);
    while(k) output[used++]=b[--k];
}
static int emit(void) {
    DWORD written=0; output[used++]='\n';
    int ok=WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),output,used,&written,0) && written==used;
    used=0; return ok;
}
static LONG exercise(void) {
    main_id=GetCurrentThreadId(); slot=TlsAlloc();
    if(slot==TLS_OUT_OF_INDEXES || !TlsSetValue(slot,(void *)(uintptr_t)0x12340)) return 104;
    for(unsigned round=0;round<PEAR_ROUNDS;++round) {
        HANDLE threads[2]; DWORD ids[2]; unsigned counts[4][4]={{0}}, serial=0;
        epoch.value=done[0].value=done[1].value=aborted.value=0;
        deadline=GetTickCount64()+45000;
        for(unsigned id=0;id<2;++id) {
            threads[id]=CreateThread(0,1048576,worker,(void *)(uintptr_t)id,0,&ids[id]);
            if(!threads[id]) return 105;
        }
        for(unsigned mode=0;mode<4;++mode) for(unsigned i=0;i<PEAR_ITERATIONS;++i) {
            x.value=y.value=0;
            __atomic_store_n(&epoch.value,++serial,__ATOMIC_RELEASE);
            if(!await(&done[0].value,serial) || !await(&done[1].value,serial)) {
                text("{\"event\":\"ordering_wait_failed\",\"round\":");number(round);
                text(",\"serial\":");number(serial);
                text(",\"done\":[");number(__atomic_load_n(&done[0].value,__ATOMIC_ACQUIRE));
                text(",");number(__atomic_load_n(&done[1].value,__ATOMIC_ACQUIRE));text("]}");
                emit();return 106;
            }
            unsigned bucket;
            if(mode==0) {
                if(x.value!=2 || results[0]>1 || results[1]>1 || results[0]==results[1]) return 107;
                bucket=results[0];
            } else if(mode==1) {
                bucket=results[1]; if(bucket>3 || bucket==2) return 108;
            } else {
                if(results[0]>1 || results[1]>1) return 109;
                bucket=2*results[0]+results[1];
                if(mode==3 && bucket==0) return 110;
            }
            ++counts[mode][bucket];
        }
        for(unsigned id=0;id<2;++id) {
            DWORD code=0;
            if(WaitForSingleObject(threads[id],5000)!=WAIT_OBJECT_0 ||
               !GetExitCodeThread(threads[id],&code) || code!=42 ||
               worker_ids[id]!=ids[id] || !CloseHandle(threads[id])) return 111;
        }
        if(ids[0]==ids[1] || TlsGetValue(slot)!=(void *)(uintptr_t)0x12340) return 112;
        text("{\"event\":\"ordering_round\",\"round\":");number(round);
        text(",\"coordinator\":");number(main_id);text(",\"workers\":[");number(ids[0]);text(",");number(ids[1]);
        text("],\"iterations\":");number(PEAR_ITERATIONS);text(",\"joined\":2,\"tls_ok\":true,\"counts\":[");
        for(unsigned mode=0;mode<4;++mode) {
            if(mode) text(",");text("[");
            for(unsigned j=0;j<4;++j) { if(j) text(",");number(counts[mode][j]); }
            text("]");
        }
        text("]}");if(!emit()) return 113;
    }
    if(!TlsFree(slot)) return 114;
    text("{\"event\":\"ordering_complete\",\"rounds\":");number(PEAR_ROUNDS);
    text(",\"iterations\":");number(PEAR_ITERATIONS);text("}");
    return emit()?42:115;
}
void pear_first_dispatch(void) {
    NtTerminateProcess((HANDLE)(intptr_t)-1,exercise()); for(;;) {}
}

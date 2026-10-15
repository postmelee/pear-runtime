/* SPDX-License-Identifier: MIT
 * Ordinary ARM64 diagnostic-selection controls. No FEX or guest init. */
#include "wine/pear_fex_memory.h"
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
typedef uint32_t (WINAPI *memory_call_fn)(const struct pear_fex_memory_request *, struct pear_fex_memory_response *);
static int actual_owner_pid(uint64_t *owner_pid)
{
    char value[32] = {0};
    DWORD length = GetEnvironmentVariableA("PEAR_FEX_MEMORY_OWNER_PID", value, sizeof(value));
    if (!length || length >= sizeof(value) || value[0] == '0') return -1;
    uint64_t parsed = 0;
    for (DWORD i = 0; i < length; ++i)
    {
        unsigned char digit = (unsigned char)value[i];
        if (digit < '0' || digit > '9' || parsed > (UINT64_MAX-(digit-'0'))/10) return -1;
        parsed = parsed*10+(digit-'0');
    }
    if (!parsed || parsed > INT32_MAX) return -1;
    *owner_pid = parsed; return 0;
}

int main(void) {
    if(setvbuf(stdout,NULL,_IONBF,0))return 90;
    char mode[16]={0}; DWORD length=GetEnvironmentVariableA("PEAR_FEX_BITMAP_DIAGNOSTICS",mode,sizeof(mode));
    int malformed=!strcmp(mode,"invalid");
    if(!length||length>=sizeof(mode)||(!malformed&&strcmp(mode,"0")))return 65;
    uint64_t pid=0;if(actual_owner_pid(&pid))return 66;
    memory_call_fn call=(memory_call_fn)(uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),"__wine_pear_fex_memory");
    if(!call)return 67;
    struct pear_fex_memory_request q={0};struct pear_fex_memory_response r={0},allocated={0};
    q.version=PEAR_FEX_MEMORY_VERSION;q.size=sizeof(q);q.owner_pid=pid;q.ec_role=PEAR_FEX_ROLE_NATIVE;q.opcode=PEAR_FEX_EXECUTOR_REGISTER;
    uint32_t registered=call(&q,&r);
    if(registered||r.status||!r.executor_id||r.owner_pid!=pid||r.flags!=PEAR_FEX_NATIVE_IDLE)return 69;
    uint64_t executor=r.executor_id;
    q.opcode=PEAR_FEX_RESERVE;q.executor_id=executor;q.allocation_class=PEAR_FEX_CLASS_SHARED;q.extent_size=16u*1024u*1024u;
    uint32_t reserve=call(&q,&allocated),retire=PEAR_FEX_UNAVAILABLE;int retired=0;
    int valid=reserve==allocated.status && (malformed ? reserve==PEAR_FEX_NATIVE_FAILURE && !allocated.allocation_id :
        !reserve&&allocated.allocation_id&&allocated.generation&&allocated.extent_size==q.extent_size&&
        allocated.lifecycle_state==PEAR_FEX_RESERVED_NONE&&allocated.effective_protection==PEAR_FEX_PROTECTION_NONE);
    if(!reserve&&allocated.allocation_id) {
        q.opcode=PEAR_FEX_RETIRE;q.allocation_id=allocated.allocation_id;q.generation=allocated.generation;
        q.extent_offset=allocated.extent_offset;q.extent_size=allocated.extent_size;q.write_epoch=allocated.write_epoch;
        q.expected_state=allocated.lifecycle_state;
        retire=call(&q,&r);retired=!retire&&!r.status&&r.lifecycle_state==PEAR_FEX_RETIRED_NONE&&r.effective_protection==PEAR_FEX_PROTECTION_NONE;
    }
    memset(&q,0,sizeof(q));q.version=PEAR_FEX_MEMORY_VERSION;q.size=sizeof(q);q.owner_pid=pid;q.executor_id=executor;q.opcode=PEAR_FEX_EXECUTOR_UNREGISTER;
    uint32_t cleanup=call(&q,&r);
    int passed=valid&&(malformed?!allocated.allocation_id:retired)&&!cleanup&&!r.status&&r.flags==PEAR_FEX_UNREGISTERED;
    printf("{\"record_kind\":\"pear_bitmap_selection\",\"mode\":\"%s\",\"passed\":%s,\"reserve_status\":%u,\"reserve_error_domain\":%u,\"reserve_error_code\":%d,\"retire_attempted\":%s,\"retire_status\":%u,\"unregister_status\":%u,\"FEX_initialization\":false}\n",mode,passed?"true":"false",reserve,allocated.native_error_domain,allocated.native_error_code,allocated.allocation_id?"true":"false",retire,cleanup);
    return passed?0:70;
}

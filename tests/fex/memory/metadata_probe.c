/* SPDX-License-Identifier: MIT
 * Ordinary ARM64 observation of the paired Wine owner. No FEX or guest init. */
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
    uint64_t pid=0;if(actual_owner_pid(&pid))return 66;
    HMODULE ntdll=GetModuleHandleA("ntdll.dll");
    memory_call_fn call=(memory_call_fn)(uintptr_t)GetProcAddress(ntdll,"__wine_pear_fex_memory");
    if(!call)return 67;
    struct pear_fex_memory_request q={0};struct pear_fex_memory_response r={0};
    q.version=PEAR_FEX_MEMORY_VERSION;q.size=128;q.owner_pid=pid;q.ec_role=PEAR_FEX_ROLE_NATIVE;
    q.opcode=PEAR_FEX_OBSERVE_METADATA;
    uint32_t first=call(&q,&r);
    if(first!=PEAR_FEX_UNAVAILABLE||r.status!=first)return 68;
    q.opcode=PEAR_FEX_EXECUTOR_REGISTER;
    uint32_t registered=call(&q,&r);
    if(registered||r.status||!r.executor_id||r.owner_pid!=pid||r.flags!=PEAR_FEX_NATIVE_IDLE)return 69;
    uint64_t executor=r.executor_id;
    q.opcode=PEAR_FEX_OBSERVE_METADATA;
    uint32_t status=call(&q,&r);struct pear_fex_memory_metadata m;memcpy(&m,&r,sizeof(m));
    q.opcode=PEAR_FEX_EXECUTOR_UNREGISTER;q.ec_role=0;q.executor_id=executor;
    uint32_t cleanup=call(&q,&r);
    int passed=!status&&!m.status&&m.version==PEAR_FEX_MEMORY_VERSION&&m.size==128&&
        m.owner_pid==pid&&!m.reserved0&&!m.reserved1&&!m.native_error_domain&&!m.native_error_code&&
        !cleanup&&!r.status&&r.executor_id==executor&&r.flags==PEAR_FEX_UNREGISTERED;
    printf("{\"record_kind\":\"pear_metadata_observation\",\"passed\":%s,\"wire_version\":%u,"
        "\"status\":%u,\"native_error_domain\":%u,\"native_error_code\":%d,\"cleanup_status\":%u,"
        "\"mapping_bytes\":%" PRIu64 ",\"baseline_mapping_bytes\":%" PRIu64 ",\"page_bytes\":%" PRIu64 ","
        "\"leaf_coverage_bytes\":%" PRIu64 ",\"leaf_backing_bytes\":%" PRIu64 ",\"baseline_leaves\":%" PRIu64 ","
        "\"additional_leaves\":%" PRIu64 ",\"view_block_bytes\":%" PRIu64 ",\"view_record_bytes\":%" PRIu64 ","
        "\"available_view_slots\":%" PRIu64 ",\"fixed_native_bytes\":%" PRIu64 ",\"FEX_initialization\":false}\n",
        passed?"true":"false",m.version,status,m.native_error_domain,m.native_error_code,cleanup,
        m.mapping_bytes,m.baseline_mapping_bytes,m.page_bytes,m.leaf_coverage_bytes,m.leaf_backing_bytes,
        m.baseline_leaves,m.additional_leaves,m.view_block_bytes,m.view_record_bytes,m.available_view_slots,m.fixed_native_bytes);
    return passed?0:70;
}

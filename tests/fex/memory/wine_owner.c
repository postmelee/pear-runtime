/* Original Pear ordinary ARM64 PE fixture. MIT-licensed.
 * Calls the actual private ntdll export; no FEX initialization, x64 guest,
 * raw asynchronous handler or intentionally fatal native control is used. */
#include "fixture_suite.h"
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

typedef uint32_t (WINAPI *memory_call_fn)(const struct pear_fex_memory_request *,
                                         struct pear_fex_memory_response *);
static memory_call_fn owner_call;
static unsigned int queried_pages;
static uint32_t dispatch(const struct pear_fex_memory_request *request,
                         struct pear_fex_memory_response *response)
{
    return owner_call(request, response);
}
static int observe(uint64_t address, uint64_t bytes, uint32_t protection)
{
    DWORD wanted = protection == PEAR_FEX_PROTECTION_NONE ? PAGE_NOACCESS :
        protection == PEAR_FEX_PROTECTION_RW_NX ? PAGE_READWRITE :
        protection == PEAR_FEX_PROTECTION_RX ? PAGE_EXECUTE_READ : 0;
    if (!wanted || !bytes || address > UINT64_MAX - bytes) return -1;
    uint64_t cursor = address, end = address + bytes;
    while (cursor < end)
    {
        MEMORY_BASIC_INFORMATION info = {0};
        SIZE_T got = VirtualQuery((void *)(uintptr_t)cursor, &info, sizeof(info));
        uint64_t base = (uint64_t)(uintptr_t)info.BaseAddress;
        uint64_t size = (uint64_t)info.RegionSize;
        if (got != sizeof(info) || base > cursor || !size || base > UINT64_MAX - size ||
            base + size <= cursor) return -1;
        /* The selected owner source stores vprot0 for NONE; Wine reports its
         * still-owned noncommitted view as MEM_RESERVE with Protect0. Commit/RX
         * or other inaccessible aliases are not equivalent to that contract. */
        if (protection == PEAR_FEX_PROTECTION_NONE)
        {
            if (info.State != MEM_RESERVE || info.Protect != 0) return -1;
        }
        else if (info.State != MEM_COMMIT || info.Protect != wanted) return -1;
        ++queried_pages;
        cursor = base + size < end ? base + size : end;
    }
    return 0;
}
static int execute(uint64_t address, unsigned int expected)
{
    if (observe(address & ~UINT64_C(4095), 4096, PEAR_FEX_PROTECTION_RX)) return -1;
    unsigned int (*volatile leaf)(void) = (unsigned int (*)(void))(uintptr_t)address;
    return leaf() == expected ? 0 : -1;
}
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
static int readiness_call(const char *control, struct pear_fex_memory_request *request,
                          struct pear_fex_memory_response *response)
{
    uint32_t status = owner_call(request, response);
    printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_wine\",\"event\":\"readiness_call\","
           "\"control\":\"%s\",\"opcode\":%u,\"returned_status\":%u,\"status\":%u,"
           "\"native_error_domain\":%u,\"native_error_code\":%d}\n", control, request->opcode, status,
           response->status, response->native_error_domain, response->native_error_code);
    return status != PEAR_FEX_OK || response->status != PEAR_FEX_OK || response->version != PEAR_FEX_MEMORY_VERSION ||
        response->size != 128 || response->reserved0 || response->native_error_domain || response->native_error_code;
}
int main(void)
{
    if (setvbuf(stdout, NULL, _IONBF, 0) || setvbuf(stderr, NULL, _IONBF, 0)) return 90;
    SYSTEM_INFO info = {0}; GetSystemInfo(&info);
    if (info.dwPageSize != 4096) return 65;
    uint64_t owner_pid = 0;
    if (actual_owner_pid(&owner_pid)) return 66;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 66;
    owner_call = (memory_call_fn)(uintptr_t)GetProcAddress(ntdll, "__wine_pear_fex_memory");
    if (!owner_call) return 67;
    /* The exact paired export supplies actual owner admission. This ordinary
     * native ARM64 module does not impersonate the ARM64EC FEX module or request
     * an EC role. A checked bitmap capability, if observed, remains distinct
     * from performing source-qualified EC registration. */
    struct pear_fex_memory_request request = {0};
    request.version = PEAR_FEX_MEMORY_VERSION; request.size = 128; request.opcode = PEAR_FEX_EXECUTOR_REGISTER;
    request.owner_pid = owner_pid; request.ec_role = PEAR_FEX_ROLE_NATIVE;
    struct pear_fex_memory_response response = {0};
    /* The selected export initializes only through admitted native REGISTER or
     * RESERVE. A QUERY cannot bootstrap a restricted owner or select EC. */
    if (readiness_call("register_readiness_native_executor", &request, &response) ||
        !response.executor_id || response.flags != PEAR_FEX_NATIVE_IDLE || response.owner_pid != owner_pid) return 68;
    uint64_t executor_id = response.executor_id;
    request.opcode = PEAR_FEX_QUERY; request.ec_role = 0; request.executor_id = executor_id;
    if (readiness_call("query_readiness_native_owner", &request, &response) ||
        response.executor_id != executor_id || response.owner_pid != owner_pid || response.flags != PEAR_FEX_NATIVE_IDLE ||
        (response.capabilities & (PEAR_FEX_SINGLE_MAP_JIT | PEAR_FEX_OBSERVED_4K | PEAR_FEX_GLOBAL_GATE)) !=
            (PEAR_FEX_SINGLE_MAP_JIT | PEAR_FEX_OBSERVED_4K | PEAR_FEX_GLOBAL_GATE) ||
        (response.capabilities & ~PEAR_FEX_CAPABILITIES_MASK)) return 68;
    request.opcode = PEAR_FEX_EXECUTOR_UNREGISTER;
    if (readiness_call("unregister_readiness_native_executor", &request, &response) ||
        response.executor_id != executor_id || response.flags != PEAR_FEX_UNREGISTERED || response.owner_pid != owner_pid) return 68;
    const struct pear_memory_fixture_platform platform = {
        .scope = "wine_owner", .owner_pid = owner_pid, .checked_ec = 0,
        .role = PEAR_FEX_ROLE_NATIVE, .call = dispatch, .poll = NULL,
        .observe = observe, .execute = execute
    };
    int result = pear_memory_fixture_suite(&platform);
    printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_wine\",\"event\":\"finish\","
           "\"native_arm64_pe_execution\":true,\"virtual_query_observations\":%u,"
           "\"checked_ec\":false,\"ec_registration_exercised\":false,\"wine_view_registration\":true,\"fex_initialization\":false,"
           "\"translated_guest_execution\":false,\"game_execution\":false,\"exit_code\":%d}\n",
           queried_pages, result);
    return result;
}

/* Original Pear finite native owner adapter. MIT-licensed.
 * Admission/signatures are checked by the directly owned supervisor before
 * the pipe release. This fixture uses the actual selected Wine owner/backing,
 * never a second MAP_JIT arena or a fabricated EC bitmap. */
#include "fixture_suite.h"
#include "pear_fex_memory_private.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

#if !defined(__APPLE__) || !defined(__aarch64__)
#error This fixture requires actual native ARM64 macOS.
#endif
extern const struct mach_header_64 _mh_execute_header;
static _Atomic unsigned int observed_regions, executed_leaves;

static int observed_protection(uint64_t pointer, uint64_t bytes, uint32_t protection)
{
    int expected = protection == PEAR_FEX_PROTECTION_NONE ? VM_PROT_NONE :
        protection == PEAR_FEX_PROTECTION_RW_NX ? VM_PROT_READ | VM_PROT_WRITE :
        protection == PEAR_FEX_PROTECTION_RX ? VM_PROT_READ | VM_PROT_EXECUTE : -1;
    if (expected < 0 || !bytes || pointer > UINT64_MAX - bytes) return -1;
    mach_vm_address_t cursor = pointer, end = pointer + bytes;
    while (cursor < end)
    {
        mach_vm_address_t address = cursor;
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info = {0};
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        kern_return_t result = mach_vm_region(mach_task_self(), &address, &size,
            VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
        kern_return_t released = object == MACH_PORT_NULL ? KERN_SUCCESS :
            mach_port_deallocate(mach_task_self(), object);
        if (result != KERN_SUCCESS || released != KERN_SUCCESS || count != VM_REGION_BASIC_INFO_COUNT_64 ||
            address > cursor || !size || address > UINT64_MAX - size || address + size <= cursor ||
            info.protection != expected || (info.max_protection & expected) != expected) return -1;
        ++observed_regions;
        cursor = address + size < end ? address + size : end;
    }
    return 0;
}
static int execute_owned(uint64_t address, unsigned int expected)
{
    if (observed_protection(address & ~UINT64_C(4095), 4096, PEAR_FEX_PROTECTION_RX)) return -1;
    unsigned int (*volatile leaf)(void) = (unsigned int (*)(void))(uintptr_t)address;
    unsigned int answer = leaf();
    ++executed_leaves;
    return answer == expected ? 0 : -1;
}
static int native_role(uint32_t role) { return role == PEAR_FEX_ROLE_NATIVE; }
static int native_entry(uint64_t extent_offset, uint64_t usable_extent, uint64_t entry_offset,
                        uint32_t cls, uint32_t role)
{
    return role == PEAR_FEX_ROLE_NATIVE &&
        (cls == PEAR_FEX_CLASS_SHARED || cls == PEAR_FEX_CLASS_DISPATCHER) &&
        !(extent_offset & (cls == PEAR_FEX_CLASS_SHARED ? 65535 : 16383)) && usable_extent >= 8192 &&
        (entry_offset == 0 || entry_offset == 4096);
}
static int native_view(uint64_t offset, uint64_t size, uint64_t allocation_id, uint64_t generation,
                       uint32_t cls, uint32_t role, int add, struct pear_fex_memory_error *error)
{
    (void)offset; (void)add;
    /* This scope has an actual native owner but no Wine file_view/PEB. It
     * explicitly cannot qualify registration or call classification. */
    if (role != PEAR_FEX_ROLE_NATIVE || !size || !allocation_id || !generation ||
        (cls != PEAR_FEX_CLASS_SHARED && cls != PEAR_FEX_CLASS_DISPATCHER))
    { error->domain = PEAR_FEX_ERROR_ERRNO; error->code = EINVAL; return -1; }
    return 0;
}
static int admission(void)
{
    const char *nonce = getenv("PEAR_FEX_MEMORY_NONCE");
    const char *control = getenv("PEAR_FEX_MEMORY_CONTROL_FD");
    if (!nonce || strlen(nonce) != 32 || !control || !*control) return -1;
    for (unsigned int index = 0; index < 32; ++index)
        if (!((nonce[index] >= '0' && nonce[index] <= '9') ||
              (nonce[index] >= 'a' && nonce[index] <= 'f'))) return -1;
    for (const char *at = control; *at; ++at) if (*at < '0' || *at > '9') return -1;
    errno = 0; char *end = NULL; long parsed = strtol(control, &end, 10);
    if (errno || *end || parsed < 3 || parsed > 1048575) return -1;
    int descriptor = (int)parsed;
    struct stat stat = {0};
    if (fstat(descriptor, &stat) || !S_ISFIFO(stat.st_mode)) return -1;
    struct proc_bsdinfo identity = {0};
    if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &identity, sizeof(identity)) != sizeof(identity) ||
        identity.pbi_pid != (uint32_t)getpid() || !identity.pbi_start_tvsec ||
        identity.pbi_start_tvusec >= 1000000) { close(descriptor); return -1; }
    int translated = -1; size_t translation_size = sizeof(translated);
    errno = 0; int query = sysctlbyname("sysctl.proc_translated", &translated, &translation_size, NULL, 0);
    int query_error = query ? errno : 0;
    errno = 0; long user = sysconf(_SC_PAGESIZE); int user_error = user < 0 ? errno : 0;
    vm_size_t kernel = 0; mach_port_t host = mach_host_self();
    kern_return_t kernel_result = host_page_size(host, &kernel);
    kern_return_t port_result = mach_port_deallocate(mach_task_self(), host);
    int jit_supported = pthread_jit_write_protect_supported_np();
    int geometry = !query && !query_error && translation_size == sizeof(translated) && translated == 0 &&
        !user_error && user == 4096 && vm_page_size == 4096 && kernel == 16384 &&
        kernel_result == KERN_SUCCESS && port_result == KERN_SUCCESS &&
        _mh_execute_header.cputype == CPU_TYPE_ARM64 && jit_supported == 1;
    printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_admission\",\"event\":\"ready\","
           "\"pid\":%u,\"parent_pid\":%u,\"start_seconds\":%llu,\"start_microseconds\":%llu,"
           "\"nonce\":\"%s\",\"user_page\":%ld,\"vm_page\":%lu,\"kernel_page\":%lu,"
           "\"translation_result\":%d,\"translation_errno\":%d,\"translation_value\":%d,"
           "\"translation_size\":%zu,\"user_page_errno\":%d,\"kernel_page_result\":%d,"
           "\"host_port_release_result\":%d,\"cpu_type\":%d,\"jit_supported\":%d,"
           "\"geometry_accepted\":%s,\"restricted_operations_started\":false,"
           "\"checked_ec\":false,\"wine_view_registration\":false}\n", identity.pbi_pid, identity.pbi_ppid,
           (unsigned long long)identity.pbi_start_tvsec, (unsigned long long)identity.pbi_start_tvusec,
           nonce, user, (unsigned long)vm_page_size, (unsigned long)kernel,
           query, query_error, translated, translation_size, user_error,
           kernel_result, port_result, _mh_execute_header.cputype, jit_supported,
           geometry ? "true" : "false");
    if (!geometry) { close(descriptor); return -1; }
    struct pollfd pipe = {.fd = descriptor, .events = POLLIN};
    int polled = poll(&pipe, 1, 10000); char command = 0;
    ssize_t bytes = polled == 1 && (pipe.revents & POLLIN) ? read(descriptor, &command, 1) : -1;
    int closed = close(descriptor);
    if (polled != 1 || bytes != 1 || command != 'G' || closed) return -1;
    return 0;
}
#ifndef PEAR_MEMORY_FIXTURE_NO_MAIN
int main(void)
{
    if (setvbuf(stdout, NULL, _IONBF, 0) || setvbuf(stderr, NULL, _IONBF, 0)) return 90;
    if (admission()) return 65;
    const struct pear_fex_memory_backend backend = {
        .initialize = pear_fex_backing_initialize, .query = pear_fex_backing_query,
        .protect = pear_fex_backing_protect, .ec_register = NULL,
        .view = native_view, .role = native_role, .entry = native_entry
    };
    struct pear_fex_memory_error error = {0};
    uint32_t initialized = pear_fex_memory_initialize(&backend, &error);
    printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_admission\",\"event\":\"initialize\","
           "\"status\":%u,\"native_error_domain\":%u,\"native_error_code\":%" PRId32 ","
           "\"checked_ec\":false,\"wine_view_registration\":false}\n",
           initialized, error.domain, error.code);
    if (initialized != PEAR_FEX_OK) return 66;
    const struct pear_memory_fixture_platform platform = {
        .scope = "native_owner", .owner_pid = (uint64_t)getpid(), .checked_ec = 0,
        .role = PEAR_FEX_ROLE_NATIVE, .call = pear_fex_memory_dispatch, .poll = pear_fex_memory_poll,
        .observe = observed_protection, .execute = execute_owned
    };
    int result = pear_memory_fixture_suite(&platform);
    printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_admission\",\"event\":\"finish\","
           "\"observed_regions\":%u,\"native_owned_code_execution\":%s,"
           "\"native_arm64_pe_execution\":false,\"checked_ec\":false,\"wine_view_registration\":false,"
           "\"fex_initialization\":false,\"translated_guest_execution\":false,"
           "\"game_execution\":false,\"exit_code\":%d}\n", observed_regions,
           executed_leaves ? "true" : "false", result);
    return result;
}
#endif

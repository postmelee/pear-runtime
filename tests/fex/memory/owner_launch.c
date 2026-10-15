/* Original Pear finite memory-owner launcher. MIT-licensed.
 * Reuses the observed identity and 4 KiB SETEXEC pattern from the original
 * tests/wine/fixtures/api_launch.c; that historical helper remains unchanged.
 * This helper establishes no permission, Wine/EC support or game qualification.
 */
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

#if !defined(__APPLE__) || !defined(__aarch64__)
#error Native ARM64 macOS is required.
#endif
extern char **environ;
extern const struct mach_header_64 _mh_execute_header;

static int failure(const char *operation, unsigned int domain, int original, int cleanup)
{
    fprintf(stderr, "{\"version\":1,\"record_kind\":\"pear_fex_memory_launch_failure\","
            "\"operation\":\"%s\",\"native_error_domain\":%u,\"native_error_code\":%d,"
            "\"attribute_cleanup_code\":%d,\"passed\":false}\n",
            operation, domain, original, cleanup);
    return 67;
}
static int observe(void)
{
    struct proc_bsdinfo info = {0};
    int translated = -1, query_error = 0;
    size_t size = sizeof(translated);
    errno = 0;
    int query_result = sysctlbyname("sysctl.proc_translated", &translated, &size, NULL, 0);
    if (query_result) query_error = errno;
    else if (size != sizeof(translated)) query_error = EIO;
    errno = 0;
    long user_page = sysconf(_SC_PAGESIZE);
    int page_error = errno;
    vm_size_t kernel_page = 0;
    mach_port_t host = mach_host_self();
    kern_return_t kernel_error = host_page_size(host, &kernel_page);
    kern_return_t release_error = mach_port_deallocate(mach_task_self(), host);
    errno = 0;
    int identity_result = proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    int identity_error = errno;
    if (identity_result != (int)sizeof(info))
        return failure("proc_pidinfo", 1, identity_error ? identity_error : EIO, 0);
    if (printf("{\"version\":1,\"record_kind\":\"pear_bootstrap_helper\",\"pid\":%d,"
               "\"ppid\":%d,\"start_sec\":%" PRIu64 ",\"start_usec\":%" PRIu64 ",\"cpu_type\":%u,"
               "\"translation_value\":%d,\"query_errno\":%d,\"user_page\":%ld,"
               "\"vm_page\":%lu,\"kernel_page\":%lu,\"kernel_error\":%d}\n",
               getpid(), getppid(), (uint64_t)info.pbi_start_tvsec, (uint64_t)info.pbi_start_tvusec,
               (unsigned int)_mh_execute_header.cputype, translated, query_error, user_page,
               (unsigned long)vm_page_size, (unsigned long)kernel_page, kernel_error) < 0 || fflush(stdout))
        return failure("helper_observation_output", 1, errno ? errno : EIO, 0);
    if (query_error) return failure("sysctl_proc_translated", 1, query_error, 0);
    if (page_error || user_page <= 0) return failure("sysconf_pagesize", 1, page_error ? page_error : EIO, 0);
    if (kernel_error) return failure("host_page_size", 3, kernel_error, 0);
    if (release_error) return failure("mach_port_deallocate", 3, release_error, 0);
    if (translated || _mh_execute_header.cputype != CPU_TYPE_ARM64 || kernel_page != 16384 ||
        (user_page != 4096 && user_page != 16384) || user_page != (long)vm_page_size ||
        !info.pbi_start_tvsec || info.pbi_start_tvusec >= 1000000 || info.pbi_ppid != (uint32_t)getppid())
        return failure("observed_native_identity_and_geometry", 1, EINVAL, 0);
    return 0;
}
int main(int argc, char **argv)
{
    typedef int (*set_page_mode_fn)(const posix_spawnattr_t *);
    if (argc == 2 && !strcmp(argv[1], "--observe")) return observe();
    if (argc < 3 || strcmp(argv[1], "--exec-4k") || argv[2][0] != '/') return 64;
    struct stat target;
    errno = 0;
    if (lstat(argv[2], &target)) return failure("lstat_target", 1, errno, 0);
    if (!S_ISREG(target.st_mode)) return failure("regular_target_required", 1, EINVAL, 0);
    int observed = observe();
    if (observed) return observed;
    set_page_mode_fn setter = (set_page_mode_fn)dlsym(RTLD_DEFAULT, "posix_spawnattr_set_4k_page_size_np");
    if (!setter) return failure("four_k_spawn_attribute_unavailable", 1, ENOSYS, 0);
    posix_spawnattr_t attributes;
    int result = posix_spawnattr_init(&attributes);
    if (result) return failure("posix_spawnattr_init", 1, result, 0);
    const char *operation = "posix_spawnattr_set_4k_page_size_np";
    result = setter(&attributes);
    if (!result)
    {
        operation = "posix_spawnattr_setflags_setexec";
        result = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETEXEC);
    }
    if (!result)
    {
        char owner_pid[32];
        int length = snprintf(owner_pid, sizeof(owner_pid), "%jd", (intmax_t)getpid());
        operation = "actual_host_pid_environment";
        if (length <= 0 || (size_t)length >= sizeof(owner_pid)) result = EOVERFLOW;
        else if (setenv("PEAR_FEX_MEMORY_OWNER_PID", owner_pid, 1)) result = errno;
    }
    if (!result)
    {
        /* Replace the directly owned helper while preserving PID, parent and
         * start identity. Wine's Win32 process ID is not the Unix owner PID.
         * Only the supervisor's bounded environment and owned FDs are inherited.
         */
        pid_t unused = 0;
        operation = "posix_spawn_setexec";
        result = posix_spawn(&unused, argv[2], NULL, &attributes, argv + 2, environ);
        if (!result) result = EIO; /* Successful SETEXEC cannot return here. */
    }
    int cleanup = posix_spawnattr_destroy(&attributes);
    return failure(operation, 1, result, cleanup);
}

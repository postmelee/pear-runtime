/* Original Pear four-worker cooperative owner fixture. MIT-licensed.
 * Includes the original admitted native adapter and finite token helpers;
 * authoritative owner/backing implementation comes from the selected Wine
 * supplement. No guest, raw handler, artificial fault or FEX initialization. */
#define PEAR_MEMORY_FIXTURE_NO_MAIN
#include "native_owner.c"
#include "fixture_suite.c"
#include <sched.h>
#include <time.h>

struct cooperative {
    pthread_mutex_t mutex, trace_mutex;
    pthread_cond_t condition;
    unsigned int phase, registered, readers_ready, reader_pins, finished;
    int writer_started, writer_done, release, stop, failed;
    struct token token;
    unsigned int answer, schedules, timeout_controls, writes, handoffs, leaf_calls;
    uint64_t trace_sequence, wire_poll_calls;
};
struct worker { struct cooperative *shared; unsigned int actor; uint64_t executor; };
static int timed_wait(struct cooperative *shared)
{
    struct timespec duration = {.tv_sec = 10, .tv_nsec = 0};
    int result = pthread_cond_timedwait_relative_np(&shared->condition, &shared->mutex, &duration);
    if (result) { shared->failed = 1; shared->stop = 1; pthread_cond_broadcast(&shared->condition); }
    return result;
}
static void fail_worker(struct worker *worker, const char *reason)
{
    struct cooperative *shared = worker->shared;
    pthread_mutex_lock(&shared->trace_mutex);
    printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_cooperative\",\"event\":\"failure\","
           "\"sequence\":%" PRIu64 ",\"actor\":%u,\"reason\":\"%s\"}\n",
           ++shared->trace_sequence, worker->actor, reason);
    pthread_mutex_unlock(&shared->trace_mutex);
    pthread_mutex_lock(&shared->mutex); shared->failed = 1; shared->stop = 1;
    pthread_cond_broadcast(&shared->condition); pthread_mutex_unlock(&shared->mutex);
}
static int worker_call(struct worker *worker, const char *control,
                       const struct pear_fex_memory_request *value,
                       struct pear_fex_memory_response *response, uint32_t expected)
{
    memset(response, 0xa5, sizeof(*response));
    uint32_t status = pear_fex_memory_dispatch(value, response);
    struct cooperative *shared = worker->shared;
    pthread_mutex_lock(&shared->trace_mutex);
    printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_cooperative\",\"event\":\"owner_call\","
           "\"sequence\":%" PRIu64 ",\"actor\":%u,\"control\":\"%s\",\"opcode\":%u,"
           "\"returned_status\":%u,\"status\":%u,\"executor_id\":%" PRIu64 ","
           "\"continuation_id\":%" PRIu64 ",\"executor_state\":%u,\"write_epoch\":%" PRIu64 ","
           "\"native_error_domain\":%u,\"native_error_code\":%" PRId32 "}\n",
           ++shared->trace_sequence, worker->actor, control, value->opcode, status, response->status,
           response->executor_id, response->continuation_id, response->flags, response->write_epoch,
           response->native_error_domain, response->native_error_code);
    pthread_mutex_unlock(&shared->trace_mutex);
    int valid = status == expected && response->status == expected && response->version == PEAR_FEX_MEMORY_VERSION &&
        response->size == 128 && !response->reserved0 && response->native_error_domain <= PEAR_FEX_ERROR_MACH &&
        (response->native_error_domain || !response->native_error_code);
    if (status)
    {
        struct pear_fex_memory_response zero = {0};
        zero.version = PEAR_FEX_MEMORY_VERSION; zero.size = 128; zero.status = status;
        zero.native_error_domain = response->native_error_domain; zero.native_error_code = response->native_error_code;
        valid = valid && !memcmp(&zero, response, sizeof(zero));
    }
    if (!valid) { fail_worker(worker, control); return -1; }
    return 0;
}
static struct pear_fex_memory_request worker_request(struct worker *worker, uint32_t opcode)
{
    struct pear_fex_memory_request value = {0};
    value.version = PEAR_FEX_MEMORY_VERSION; value.size = 128; value.opcode = opcode;
    value.owner_pid = (uint64_t)getpid(); value.executor_id = worker->executor;
    return value;
}
static int reader_schedule(struct worker *worker, struct token token, unsigned int phase, unsigned int answer)
{
    struct cooperative *shared = worker->shared;
    struct pear_fex_memory_request value = worker_request(worker, PEAR_FEX_EXECUTOR_ENTRY);
    identity(&value, &token); value.write_epoch = token.facts.write_epoch;
    value.expected_state = PEAR_FEX_PUBLISHED_RX;
    value.operation_offset = worker->actor & 1 ? 4096 : 0; value.operation_size = 4;
    struct pear_fex_memory_response response;
    if (worker_call(worker, "enter_source_leaf", &value, &response, PEAR_FEX_OK)) return -1;
    if (response.flags != PEAR_FEX_MANAGED_ACTIVE || execute_owned(token.code + value.operation_offset, answer))
    { fail_worker(worker, "reader_leaf_result"); return -1; }
    pthread_mutex_lock(&shared->mutex); ++shared->leaf_calls; ++shared->readers_ready;
    pthread_cond_broadcast(&shared->condition);
    if (phase != 2)
        while (!shared->release && !shared->stop) if (timed_wait(shared)) break;
    int stopped = shared->stop;
    pthread_mutex_unlock(&shared->mutex);
    if (stopped) return -1;
    uint64_t original_epoch = value.write_epoch;
    value.opcode = PEAR_FEX_EXECUTOR_HANDOFF;
    if (worker_call(worker, "handoff_to_compiled_native_gate", &value, &response, PEAR_FEX_OK)) return -1;
    uint64_t continuation = response.continuation_id;
    if (!continuation || response.flags != PEAR_FEX_NATIVE_PINNED)
    { fail_worker(worker, "handoff_keeps_generation"); return -1; }
    pthread_mutex_lock(&shared->mutex); ++shared->handoffs; ++shared->reader_pins;
    pthread_cond_broadcast(&shared->condition);
    if (phase == 2)
        while (!shared->release && !shared->stop) if (timed_wait(shared)) break;
    stopped = shared->stop;
    pthread_mutex_unlock(&shared->mutex);
    if (stopped) return -1;
    /* Open polling preserves native-pinned state; only a completed native
     * parking acknowledgement under the closed writer can admit that writer.
     * The source poll observes its current closed epoch. No forced suspension. */
    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline))
    { fail_worker(worker, "native_poll_clock_error"); return -1; }
    deadline.tv_sec += 3;
    unsigned int poll_attempts = 0;
    value.operation_size = 0; value.continuation_id = continuation;
    value.write_epoch = original_epoch;
    for (;;)
    {
        if (++poll_attempts > 32) { fail_worker(worker, "bounded_wire_poll_calls"); return -1; }
        if (worker_call(worker, "poll_existing_source_descriptor", &value, &response, PEAR_FEX_OK)) return -1;
        if (response.flags != PEAR_FEX_NATIVE_PINNED || response.continuation_id != continuation)
        { fail_worker(worker, "wire_poll_preserves_original_pin"); return -1; }
        pthread_mutex_lock(&shared->mutex); ++shared->wire_poll_calls; pthread_mutex_unlock(&shared->mutex);
        pthread_mutex_lock(&shared->mutex); int done = shared->writer_done, stop = shared->stop;
        pthread_mutex_unlock(&shared->mutex);
        if (stop) return -1;
        if (done) break;
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now))
        { fail_worker(worker, "native_poll_clock_error"); return -1; }
        if (now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec))
        { fail_worker(worker, "bounded_native_poll_progress"); return -1; }
        const struct timespec yield = {.tv_sec = 0, .tv_nsec = 1000000};
        if (nanosleep(&yield, NULL)) { fail_worker(worker, "poll_yield_error"); return -1; }
    }
    value = worker_request(worker, PEAR_FEX_CONTINUATION_UNPIN); identity(&value, &token);
    value.continuation_id = continuation; value.write_epoch = original_epoch;
    value.expected_state = PEAR_FEX_PUBLISHED_RX;
    if (worker_call(worker, "discard_saved_resume_original_epoch", &value, &response, PEAR_FEX_OK)) return -1;
    if (response.flags != PEAR_FEX_NATIVE_IDLE) { fail_worker(worker, "reader_returns_native_idle"); return -1; }
    return 0;
}
static int writer_schedule(struct worker *worker, struct token token, unsigned int phase)
{
    struct cooperative *shared = worker->shared;
    pthread_mutex_lock(&shared->mutex);
    while ((shared->readers_ready < 3 || (phase == 2 && shared->reader_pins < 3)) && !shared->stop)
        if (timed_wait(shared)) break;
    shared->writer_started = 1; pthread_cond_broadcast(&shared->condition);
    int stopped = shared->stop; pthread_mutex_unlock(&shared->mutex);
    if (stopped) return -1;
    struct pear_fex_memory_request value = worker_request(worker, PEAR_FEX_BEGIN_WRITE);
    identity(&value, &token); value.write_epoch = token.facts.write_epoch;
    value.expected_state = PEAR_FEX_PUBLISHED_RX; value.operation_size = 8192;
    struct pear_fex_memory_response response;
    uint32_t expected = phase <= 2 ? PEAR_FEX_QUIESCENCE_TIMEOUT : PEAR_FEX_OK;
    if (worker_call(worker, phase == 1 ? "active_participant_timeout" :
                    phase == 2 ? "native_pin_without_park_timeout" : "cooperative_writer_admission",
                    &value, &response, expected)) return -1;
    if (phase <= 2)
    {
        if (observed_protection(token.code, 8192, PEAR_FEX_PROTECTION_RX))
        { fail_worker(worker, "timeout_preserves_rx"); return -1; }
        pthread_mutex_lock(&shared->mutex); ++shared->timeout_controls;
        shared->writer_done = 1; pthread_cond_broadcast(&shared->condition);
        pthread_mutex_unlock(&shared->mutex);
        return 0;
    }
    if (response.lifecycle_state != PEAR_FEX_WRITING_RW_NX ||
        response.private_write_base != token.code || observed_protection(token.code, 8192, PEAR_FEX_PROTECTION_RW_NX))
    { fail_worker(worker, "writer_has_exact_rw_nx_window"); return -1; }
    unsigned int answer = phase & 1 ? 84 : 42;
    const uint32_t *code = answer == 42 ? leaf42 : leaf84;
    memcpy((void *)(uintptr_t)token.code, code, sizeof(leaf42));
    memcpy((void *)(uintptr_t)(token.code + 4096), code, sizeof(leaf42));
    token.facts = response;
    value = worker_request(worker, PEAR_FEX_PUBLISH); identity(&value, &token);
    value.write_epoch = token.facts.write_epoch; value.expected_state = PEAR_FEX_WRITING_RW_NX;
    if (worker_call(worker, "publish_after_native_park_ack", &value, &response, PEAR_FEX_OK)) return -1;
    if (response.lifecycle_state != PEAR_FEX_PUBLISHED_RX ||
        observed_protection(token.code, 8192, PEAR_FEX_PROTECTION_RX))
    { fail_worker(worker, "writer_publish_rx"); return -1; }
    token.facts = response;
    pthread_mutex_lock(&shared->mutex); shared->token = token; shared->answer = answer;
    ++shared->writes; shared->writer_done = 1; pthread_cond_broadcast(&shared->condition);
    pthread_mutex_unlock(&shared->mutex);
    return 0;
}
static void *worker_main(void *opaque)
{
    struct worker *worker = opaque; struct cooperative *shared = worker->shared;
    struct pear_fex_memory_request value = worker_request(worker, PEAR_FEX_EXECUTOR_REGISTER);
    value.executor_id = 0; value.ec_role = PEAR_FEX_ROLE_NATIVE;
    struct pear_fex_memory_response response;
    if (worker_call(worker, "register_owned_worker", &value, &response, PEAR_FEX_OK)) return NULL;
    worker->executor = response.executor_id;
    pthread_mutex_lock(&shared->mutex); ++shared->registered; pthread_cond_broadcast(&shared->condition);
    unsigned int previous = 0;
    while (!shared->stop)
    {
        while (shared->phase <= previous && !shared->stop) if (timed_wait(shared)) break;
        if (shared->stop) break;
        unsigned int phase = shared->phase, answer = shared->answer;
        struct token token = shared->token;
        pthread_mutex_unlock(&shared->mutex);
        int failed = worker->actor == 3 ? writer_schedule(worker, token, phase) : reader_schedule(worker, token, phase, answer);
        pthread_mutex_lock(&shared->mutex);
        if (failed) { shared->failed = 1; shared->stop = 1; pthread_cond_broadcast(&shared->condition); break; }
        previous = phase; ++shared->finished; pthread_cond_broadcast(&shared->condition);
    }
    pthread_mutex_unlock(&shared->mutex);
    value = worker_request(worker, PEAR_FEX_EXECUTOR_UNREGISTER);
    (void)worker_call(worker, "unregister_owned_worker", &value, &response, PEAR_FEX_OK);
    return NULL;
}
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
    if (pear_fex_memory_initialize(&backend, &error) != PEAR_FEX_OK) return 66;
    const struct pear_memory_fixture_platform platform = {
        .scope = "native_owner", .owner_pid = (uint64_t)getpid(), .checked_ec = 0,
        .role = PEAR_FEX_ROLE_NATIVE, .call = pear_fex_memory_dispatch,
        .poll = pear_fex_memory_poll, .observe = observed_protection, .execute = execute_owned
    };
    struct fixture setup = {0}; setup.platform = &platform;
    struct pear_fex_memory_request value = request(&setup, PEAR_FEX_EXECUTOR_REGISTER);
    value.ec_role = PEAR_FEX_ROLE_NATIVE;
    struct pear_fex_memory_response response;
    if (success(&setup, "setup_register", value, &response)) return 67;
    setup.executor = response.executor_id;
    struct cooperative shared = {.mutex = PTHREAD_MUTEX_INITIALIZER, .trace_mutex = PTHREAD_MUTEX_INITIALIZER,
        .condition = PTHREAD_COND_INITIALIZER, .answer = 42};
    if (reserve(&setup, &shared.token, PEAR_FEX_CLASS_SHARED, SHARED_UNIT) || emit_code(&setup, &shared.token, 42)) return 68;
    value = request(&setup, PEAR_FEX_EXECUTOR_UNREGISTER); value.executor_id = setup.executor;
    if (success(&setup, "setup_unregister", value, &response)) return 69;
    pthread_t threads[4]; struct worker workers[4]; unsigned int spawned = 0, joined = 0;
    for (unsigned int actor = 0; actor < 4; ++actor)
    {
        workers[actor] = (struct worker){.shared = &shared, .actor = actor};
        int created = pthread_create(&threads[actor], NULL, worker_main, &workers[actor]);
        pthread_mutex_lock(&shared.trace_mutex);
        printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_cooperative\",\"event\":\"thread_create\","
               "\"sequence\":%" PRIu64 ",\"actor\":%u,\"native_error_code\":%d}\n",
               ++shared.trace_sequence, actor, created);
        pthread_mutex_unlock(&shared.trace_mutex);
        if (created) { pthread_mutex_lock(&shared.mutex); shared.failed = 1;
            pthread_mutex_unlock(&shared.mutex); break; }
        ++spawned;
    }
    pthread_mutex_lock(&shared.mutex);
    while (shared.registered < spawned && !shared.stop) if (timed_wait(&shared)) break;
    if (spawned != 4) shared.stop = 1;
    for (unsigned int phase = 1; phase <= 32 && !shared.stop; ++phase)
    {
        shared.phase = phase; shared.readers_ready = shared.reader_pins = shared.finished = 0;
        shared.writer_started = shared.writer_done = shared.release = 0;
        pthread_cond_broadcast(&shared.condition);
        while (!shared.writer_started && !shared.stop) if (timed_wait(&shared)) break;
        if (phase <= 2)
            while (!shared.writer_done && !shared.stop) if (timed_wait(&shared)) break;
        shared.release = 1; pthread_cond_broadcast(&shared.condition);
        while (shared.finished < 4 && !shared.stop) if (timed_wait(&shared)) break;
        if (!shared.stop) ++shared.schedules;
    }
    shared.stop = 1; pthread_cond_broadcast(&shared.condition); pthread_mutex_unlock(&shared.mutex);
    for (unsigned int actor = 0; actor < spawned; ++actor)
    {
        int code = pthread_join(threads[actor], NULL);
        if (!code) ++joined;
        pthread_mutex_lock(&shared.trace_mutex);
        printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_cooperative\",\"event\":\"thread_join\","
               "\"sequence\":%" PRIu64 ",\"actor\":%u,\"native_error_code\":%d}\n",
               ++shared.trace_sequence, actor, code);
        pthread_mutex_unlock(&shared.trace_mutex);
    }
    if (joined != spawned)
    {
        /* A failed join does not establish ownership drainage. The supervisor
         * records/reaps the failed child; do not destroy a possibly live lock. */
        printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_cooperative\",\"event\":\"join_incomplete\","
               "\"passed\":false,\"owned_workers\":%u,\"workers_joined\":%u}\n", spawned, joined);
        return 71;
    }
    int result = shared.failed || spawned != 4 || joined != 4 || shared.schedules != 32 ||
        shared.timeout_controls != 2 || shared.writes != 30 || shared.handoffs != 96 || shared.leaf_calls != 96 ||
        shared.wire_poll_calls < 96 || shared.wire_poll_calls > 3072;
    if (!result)
    {
        value = request(&setup, PEAR_FEX_EXECUTOR_REGISTER); value.ec_role = PEAR_FEX_ROLE_NATIVE;
        if (success(&setup, "cleanup_register_after_worker_join", value, &response)) result = 1;
        else
        {
            setup.executor = response.executor_id;
            if (retire(&setup, &shared.token)) result = 1;
            value = request(&setup, PEAR_FEX_EXECUTOR_UNREGISTER); value.executor_id = setup.executor;
            if (success(&setup, "cleanup_unregister_after_retirement", value, &response)) result = 1;
        }
    }
    int condition_cleanup = pthread_cond_destroy(&shared.condition);
    int mutex_cleanup = pthread_mutex_destroy(&shared.mutex);
    int trace_cleanup = pthread_mutex_destroy(&shared.trace_mutex);
    if (condition_cleanup || mutex_cleanup || trace_cleanup) result = 1;
    printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_cooperative\",\"event\":\"complete\","
           "\"sequence\":%" PRIu64 ",\"passed\":%s,\"owned_workers\":%u,\"workers_joined\":%u,"
           "\"schedules\":%u,\"timeout_controls\":%u,\"writes\":%u,\"handoffs\":%u,"
           "\"owned_leaf_calls\":%u,\"wire_poll_calls\":%" PRIu64 ",\"condition_cleanup\":%d,\"mutex_cleanup\":%d,\"trace_cleanup\":%d,"
           "\"checked_ec\":false,\"wine_view_registration\":false,"
           "\"fex_initialization\":false,\"translated_guest_execution\":false,\"game_execution\":false}\n",
           ++shared.trace_sequence, result ? "false" : "true", spawned, joined, shared.schedules,
           shared.timeout_controls, shared.writes, shared.handoffs, shared.leaf_calls, shared.wire_poll_calls,
           condition_cleanup, mutex_cleanup, trace_cleanup);
    return result ? 1 : 0;
}

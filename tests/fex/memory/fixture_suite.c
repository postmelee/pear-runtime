/* Original Pear finite source-bound owner fixture. MIT-licensed.
 * Native and Wine ARM64 adapters call the same actual owner; no shadow bitmap
 * or model substitutes for a successful EC observation. */
#include "fixture_suite.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define SHARED_UNIT UINT64_C(16777216)
#define SCHEDULES 32u
struct fixture {
    const struct pear_memory_fixture_platform *platform;
    uint64_t sequence, executor;
    unsigned int calls, refusals, executable_calls, protection_observations;
    unsigned int allocations, retirements, publications, fragmentation_controls;
    unsigned int patch_rounds, continuation_controls;
    int failed;
};
struct token {
    struct pear_fex_memory_response facts;
    uint64_t code;
};
static const uint32_t leaf42[] = {UINT32_C(0x52800540), UINT32_C(0xd65f03c0)};
static const uint32_t leaf84[] = {UINT32_C(0x52800a80), UINT32_C(0xd65f03c0)};

static int check(struct fixture *fixture, int condition, const char *control)
{
    if (condition) return 0;
    fixture->failed = 1;
    printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_fixture\","
           "\"scope\":\"%s\",\"sequence\":%" PRIu64 ",\"event\":\"failed_control\","
           "\"control\":\"%s\"}\n", fixture->platform->scope, ++fixture->sequence, control);
    return -1;
}
#define CHECK(fixture, condition, label) do { if (check(fixture, condition, label)) return -1; } while (0)

static struct pear_fex_memory_request request(struct fixture *fixture, uint32_t opcode)
{
    struct pear_fex_memory_request value = {0};
    value.version = PEAR_FEX_MEMORY_VERSION;
    value.size = sizeof(value);
    value.opcode = opcode;
    value.owner_pid = fixture->platform->owner_pid;
    return value;
}
static void identity(struct pear_fex_memory_request *value, const struct token *token)
{
    value->allocation_id = token->facts.allocation_id;
    value->generation = token->facts.generation;
    value->extent_offset = token->facts.extent_offset;
    value->extent_size = token->facts.extent_size;
    value->allocation_class = token->facts.allocation_class;
    value->ec_role = token->facts.ec_role;
}
static int call(struct fixture *fixture, const char *control,
                const struct pear_fex_memory_request *value, struct pear_fex_memory_response *response)
{
    memset(response, 0xa5, sizeof(*response));
    uint32_t status = fixture->platform->call(value, response);
    ++fixture->calls;
    printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_fixture\","
           "\"scope\":\"%s\",\"sequence\":%" PRIu64 ",\"event\":\"owner_call\","
           "\"control\":\"%s\",\"opcode\":%u,\"returned_status\":%u,\"status\":%u,"
           "\"requested_state\":%u,\"operation_offset\":\"%016" PRIx64 "\",\"operation_size\":\"%016" PRIx64 "\","
           "\"allocation_id\":%" PRIu64 ",\"generation\":%" PRIu64 ",\"extent_offset\":%" PRIu64 ","
           "\"extent_size\":%" PRIu64 ",\"write_epoch\":%" PRIu64 ",\"executor_id\":%" PRIu64 ","
           "\"continuation_id\":%" PRIu64 ",\"executor_state\":%u,\"lifecycle\":%u,"
           "\"protection\":%u,\"capabilities\":%" PRIu64 ",\"native_error_domain\":%u,"
           "\"native_error_code\":%" PRId32 "}\n", fixture->platform->scope, ++fixture->sequence,
           control, value->opcode, status, response->status, value->expected_state,
           value->operation_offset, value->operation_size, response->allocation_id,
           response->generation, response->extent_offset, response->extent_size,
           response->write_epoch, response->executor_id, response->continuation_id,
           response->flags, response->lifecycle_state, response->effective_protection,
           response->capabilities, response->native_error_domain, response->native_error_code);
    CHECK(fixture, response->version == PEAR_FEX_MEMORY_VERSION && response->size == 128 &&
          status == response->status && status <= PEAR_FEX_QUARANTINED && !response->reserved0,
          "exact_response_header");
    CHECK(fixture, response->native_error_domain <= PEAR_FEX_ERROR_MACH &&
          (response->native_error_domain || !response->native_error_code), "exact_error_domain");
    if (status)
    {
        struct pear_fex_memory_response empty = {0};
        empty.version = PEAR_FEX_MEMORY_VERSION; empty.size = 128; empty.status = status;
        empty.native_error_domain = response->native_error_domain;
        empty.native_error_code = response->native_error_code;
        CHECK(fixture, !memcmp(&empty, response, sizeof(empty)), "refusal_zero_facts");
        ++fixture->refusals;
    }
    else CHECK(fixture, !response->native_error_domain && !response->native_error_code &&
               !(response->capabilities & ~PEAR_FEX_CAPABILITIES_MASK), "success_has_no_error");
    return 0;
}
static int success(struct fixture *fixture, const char *control,
                   struct pear_fex_memory_request value, struct pear_fex_memory_response *response)
{
    if (call(fixture, control, &value, response)) return -1;
    CHECK(fixture, response->status == PEAR_FEX_OK, control);
    return 0;
}
static int refusal(struct fixture *fixture, const char *control, struct pear_fex_memory_request value)
{
    struct pear_fex_memory_response response;
    if (call(fixture, control, &value, &response)) return -1;
    CHECK(fixture, response.status != PEAR_FEX_OK, control);
    return 0;
}
static int refresh(struct fixture *fixture, struct token *token)
{
    struct pear_fex_memory_request value = request(fixture, PEAR_FEX_QUERY);
    identity(&value, token); value.executor_id = fixture->executor;
    struct pear_fex_memory_response response;
    int mixed = token->code && token->facts.lifecycle_state == PEAR_FEX_PUBLISHED_RX;
    if (call(fixture, mixed ? "mixed_extent_query_unavailable" : "query_current_token", &value, &response)) return -1;
    if (mixed)
    {
        CHECK(fixture, response.status == PEAR_FEX_UNAVAILABLE, "mixed_extent_is_not_uniform_rx");
        /* Retain the exact successful publication token. Its protection fact
         * describes the stored 8 KiB window; the remaining extent/guard is NONE.
         * A refused whole-extent query supplies no replacement facts. */
        return 0;
    }
    CHECK(fixture, response.status == PEAR_FEX_OK, "query_current_token");
    token->facts = response;
    return 0;
}
static int reserve(struct fixture *fixture, struct token *token, uint32_t cls, uint64_t bytes)
{
    struct pear_fex_memory_request value = request(fixture, PEAR_FEX_RESERVE);
    value.allocation_class = cls; value.ec_role = fixture->platform->role;
    value.extent_size = bytes; value.executor_id = fixture->executor;
    if (success(fixture, "reserve_extent", value, &token->facts)) return -1;
    CHECK(fixture, token->facts.lifecycle_state == PEAR_FEX_RESERVED_NONE &&
          token->facts.effective_protection == PEAR_FEX_PROTECTION_NONE &&
          token->facts.allocation_id && token->facts.generation &&
          token->facts.extent_size == bytes && !(token->facts.extent_offset & 16383), "reserve_identity_geometry");
    ++fixture->allocations;
    token->code = 0;
    return 0;
}
static int retire(struct fixture *fixture, struct token *token)
{
    if (refresh(fixture, token)) return -1;
    struct pear_fex_memory_request value = request(fixture, PEAR_FEX_RETIRE);
    identity(&value, token); value.executor_id = fixture->executor;
    value.write_epoch = token->facts.write_epoch; value.expected_state = token->facts.lifecycle_state;
    if (success(fixture, "retire_extent", value, &token->facts)) return -1;
    CHECK(fixture, token->facts.lifecycle_state == PEAR_FEX_RETIRED_NONE &&
          token->facts.effective_protection == PEAR_FEX_PROTECTION_NONE, "retire_none");
    ++fixture->retirements;
    return 0;
}
static int emit_code(struct fixture *fixture, struct token *token, unsigned int expected)
{
    if (refresh(fixture, token)) return -1;
    struct pear_fex_memory_request value = request(fixture, PEAR_FEX_BEGIN_WRITE);
    identity(&value, token); value.executor_id = fixture->executor;
    value.write_epoch = token->facts.write_epoch; value.expected_state = token->facts.lifecycle_state;
    value.operation_offset = 0; value.operation_size = 8192;
    if (success(fixture, "begin_two_page_write", value, &token->facts)) return -1;
    CHECK(fixture, token->facts.lifecycle_state == PEAR_FEX_WRITING_RW_NX &&
          token->facts.effective_protection == PEAR_FEX_PROTECTION_RW_NX &&
          token->facts.private_write_base && token->facts.write_epoch, "write_window_lease");
    token->code = token->facts.private_write_base;
    CHECK(fixture, fixture->platform->observe(token->code, 8192, PEAR_FEX_PROTECTION_RW_NX) == 0,
          "observe_two_pages_rw_nx");
    ++fixture->protection_observations;
    /* Fixed original instructions with two adjacent published blocks. The
     * native platform independently observes pages; no copy happens in RX. */
    const uint32_t *code = expected == 42 ? leaf42 : leaf84;
    memcpy((void *)(uintptr_t)token->code, code, sizeof(leaf42));
    memcpy((void *)(uintptr_t)(token->code + 4096), code, sizeof(leaf42));
    value = request(fixture, PEAR_FEX_PUBLISH); identity(&value, token);
    value.executor_id = fixture->executor; value.write_epoch = token->facts.write_epoch;
    value.expected_state = PEAR_FEX_WRITING_RW_NX;
    if (success(fixture, "publish_two_pages", value, &token->facts)) return -1;
    CHECK(fixture, token->facts.lifecycle_state == PEAR_FEX_PUBLISHED_RX &&
          token->facts.effective_protection == PEAR_FEX_PROTECTION_RX &&
          !token->facts.private_write_base, "publish_rx_no_writer_address");
    CHECK(fixture, fixture->platform->observe(token->code, 8192, PEAR_FEX_PROTECTION_RX) == 0,
          "observe_two_pages_rx");
    ++fixture->protection_observations; ++fixture->publications;
    return 0;
}
static int execute_code(struct fixture *fixture, struct token *token, unsigned int expected, uint64_t offset)
{
    if (refresh(fixture, token)) return -1;
    struct pear_fex_memory_request value = request(fixture, PEAR_FEX_EXECUTOR_ENTRY);
    identity(&value, token); value.executor_id = fixture->executor;
    value.write_epoch = token->facts.write_epoch; value.expected_state = PEAR_FEX_PUBLISHED_RX;
    value.operation_offset = offset; value.operation_size = 4;
    struct pear_fex_memory_response response;
    if (success(fixture, "enter_owned_leaf", value, &response)) return -1;
    CHECK(fixture, response.flags == PEAR_FEX_MANAGED_ACTIVE &&
          fixture->platform->execute(token->code + offset, expected) == 0, "owned_leaf_result");
    ++fixture->executable_calls;
    value = request(fixture, PEAR_FEX_EXECUTOR_EXIT); identity(&value, token);
    value.executor_id = fixture->executor; value.write_epoch = response.write_epoch;
    value.expected_state = PEAR_FEX_PUBLISHED_RX;
    if (success(fixture, "exit_to_native_gate", value, &response)) return -1;
    CHECK(fixture, response.flags == PEAR_FEX_NATIVE_IDLE, "native_gate_idle");
    return 0;
}
static int malformed_controls(struct fixture *fixture, const struct token *token)
{
    struct pear_fex_memory_request value = request(fixture, PEAR_FEX_QUERY);
    value.version = 1;
    if (refusal(fixture, "version_mismatch", value)) return -1;
    value = request(fixture, PEAR_FEX_QUERY); value.size = 127;
    if (refusal(fixture, "record_size_mismatch", value)) return -1;
#if PEAR_FEX_MEMORY_VERSION >= 3
    value = request(fixture, 16);
#else
    value = request(fixture, 15);
#endif
    if (refusal(fixture, "unknown_opcode", value)) return -1;
    value = request(fixture, PEAR_FEX_QUERY); value.flags = 1;
    if (refusal(fixture, "unknown_flags", value)) return -1;
    value = request(fixture, PEAR_FEX_QUERY); value.reserved0 = 1;
    if (refusal(fixture, "reserved_word", value)) return -1;
    value = request(fixture, PEAR_FEX_QUERY); value.reserved1 = 1;
    if (refusal(fixture, "reserved_word64", value)) return -1;
    value = request(fixture, PEAR_FEX_QUERY); value.owner_pid++;
    if (refusal(fixture, "foreign_owner", value)) return -1;
    value = request(fixture, PEAR_FEX_QUERY); identity(&value, token); value.generation++;
    if (refusal(fixture, "stale_generation", value)) return -1;
    value = request(fixture, PEAR_FEX_QUERY); identity(&value, token); value.allocation_id = UINT64_MAX;
    if (refusal(fixture, "foreign_allocation", value)) return -1;
    value = request(fixture, PEAR_FEX_QUERY); identity(&value, token); value.extent_offset++;
    if (refusal(fixture, "offset_alias", value)) return -1;
    value = request(fixture, PEAR_FEX_QUERY); identity(&value, token); value.extent_size += 4096;
    if (refusal(fixture, "extent_alias", value)) return -1;
    value = request(fixture, PEAR_FEX_QUERY); identity(&value, token); value.ec_role = 3;
    if (refusal(fixture, "unselected_role", value)) return -1;
    value = request(fixture, PEAR_FEX_EXECUTOR_REGISTER); value.ec_role = PEAR_FEX_ROLE_ARM64EC;
    if (refusal(fixture, "native_fixture_cannot_select_arm64ec_role", value)) return -1;
    value = request(fixture, PEAR_FEX_BEGIN_WRITE); identity(&value, token);
    value.executor_id = fixture->executor; value.write_epoch = token->facts.write_epoch;
    value.expected_state = token->facts.lifecycle_state; value.operation_offset = UINT64_MAX;
    value.operation_size = 8;
    if (refusal(fixture, "wrapped_write_range", value)) return -1;
    value.operation_offset = token->facts.extent_size - 4096; value.operation_size = 4;
    if (refusal(fixture, "source_guard_write", value)) return -1;
    value.operation_offset = 0; value.operation_size = 0;
    if (refusal(fixture, "empty_write", value)) return -1;
    return 0;
}
static int cross_page_control(struct fixture *fixture, struct token *token)
{
    struct pear_fex_memory_request value = request(fixture, PEAR_FEX_BEGIN_WRITE);
    identity(&value, token); value.executor_id = fixture->executor;
    value.write_epoch = token->facts.write_epoch; value.expected_state = PEAR_FEX_PUBLISHED_RX;
    value.operation_offset = 4092; value.operation_size = 8;
    struct pear_fex_memory_response response;
    if (success(fixture, "begin_cross_page_instruction_pair", value, &response)) return -1;
    CHECK(fixture, response.private_write_base == token->code + 4092 &&
          fixture->platform->observe(token->code, 8192, PEAR_FEX_PROTECTION_RW_NX) == 0,
          "cross_page_window_covers_both_live_blocks");
    const uint32_t pair[] = {UINT32_C(0xd503201f), UINT32_C(0x52800a80)};
    memcpy((void *)(uintptr_t)response.private_write_base, pair, sizeof(pair));
    token->facts = response;
    value = request(fixture, PEAR_FEX_PUBLISH); identity(&value, token);
    value.executor_id = fixture->executor; value.write_epoch = token->facts.write_epoch;
    value.expected_state = PEAR_FEX_WRITING_RW_NX;
    if (success(fixture, "publish_cross_page_instruction_pair", value, &token->facts)) return -1;
    CHECK(fixture, fixture->platform->observe(token->code, 8192, PEAR_FEX_PROTECTION_RX) == 0,
          "cross_page_blocks_both_rx");
    fixture->protection_observations += 2; ++fixture->publications;
    if (execute_code(fixture, token, 42, 0) || execute_code(fixture, token, 84, 4096) ||
        emit_code(fixture, token, 42)) return -1;
    return 0;
}
static int continuation_controls(struct fixture *fixture, struct token *token)
{
    struct pear_fex_memory_request value = request(fixture, PEAR_FEX_EXECUTOR_ENTRY);
    identity(&value, token); value.executor_id = fixture->executor;
    value.write_epoch = token->facts.write_epoch; value.expected_state = PEAR_FEX_PUBLISHED_RX;
    value.operation_size = 4;
    struct pear_fex_memory_response response;
    if (success(fixture, "enter_before_source_continuation", value, &response)) return -1;
    if (fixture->platform->poll)
        CHECK(fixture, fixture->platform->poll(fixture->executor) == PEAR_FEX_INVALID_REQUEST,
              "poll_does_not_drop_active_lease");
    value.opcode = PEAR_FEX_CONTINUATION_PIN;
    if (success(fixture, "pin_saved_source_resume", value, &response)) return -1;
    uint64_t continuations[128] = {response.continuation_id};
    uint64_t epochs[128] = {value.write_epoch};
    CHECK(fixture, continuations[0] && response.flags == PEAR_FEX_MANAGED_ACTIVE, "pin_before_active_drop");
    value = request(fixture, PEAR_FEX_EXECUTOR_EXIT); identity(&value, token);
    value.executor_id = fixture->executor; value.write_epoch = token->facts.write_epoch;
    value.expected_state = PEAR_FEX_PUBLISHED_RX;
    if (refusal(fixture, "ordinary_exit_cannot_drop_saved_resume", value)) return -1;
    value = request(fixture, PEAR_FEX_EXECUTOR_HANDOFF); identity(&value, token);
    value.executor_id = fixture->executor; value.continuation_id = continuations[0];
    value.write_epoch = token->facts.write_epoch; value.expected_state = PEAR_FEX_PUBLISHED_RX;
    value.operation_size = 4;
    if (success(fixture, "direct_owned_handoff_to_native", value, &response)) return -1;
    CHECK(fixture, response.flags == PEAR_FEX_NATIVE_PINNED &&
          response.continuation_id == continuations[0], "handoff_keeps_source_pin");
    if (refusal(fixture, "nested_handoff_refused", value)) return -1;
    value.operation_size = 0;
    if (success(fixture, "poll_existing_owned_handoff", value, &response)) return -1;
    CHECK(fixture, response.flags == PEAR_FEX_NATIVE_PINNED &&
          response.continuation_id == continuations[0], "poll_keeps_exact_original_pin");
    ++value.write_epoch;
    if (refusal(fixture, "poll_requires_original_pin_epoch", value)) return -1;
    --value.write_epoch;
    value.operation_offset = 4;
    if (refusal(fixture, "poll_requires_exact_resume_offset", value)) return -1;
    value.operation_offset = 0;
    value.continuation_id = 0;
    if (refusal(fixture, "poll_requires_existing_continuation", value)) return -1;
    value = request(fixture, PEAR_FEX_EXECUTOR_UNREGISTER); value.executor_id = fixture->executor;
    if (refusal(fixture, "unregister_cannot_drop_saved_resume", value)) return -1;
    value = request(fixture, PEAR_FEX_RETIRE); identity(&value, token);
    value.executor_id = fixture->executor; value.write_epoch = token->facts.write_epoch;
    value.expected_state = PEAR_FEX_PUBLISHED_RX;
    if (refusal(fixture, "retirement_keeps_saved_generation", value)) return -1;
    CHECK(fixture, fixture->platform->observe(token->code, 8192, PEAR_FEX_PROTECTION_RX) == 0,
          "held_pin_refusal_preserves_rx");
    ++fixture->protection_observations;
    /* Distinct original finite saved-resume records share the same source
     * leaf offset. This checks the 128-record admission, not 128 live workers. */
    value = request(fixture, PEAR_FEX_CONTINUATION_PIN); identity(&value, token);
    value.executor_id = fixture->executor; value.write_epoch = token->facts.write_epoch;
    value.expected_state = PEAR_FEX_PUBLISHED_RX; value.operation_size = 4;
    for (unsigned int index = 1; index < 128; ++index)
    {
        if (success(fixture, "admit_finite_saved_resume", value, &response)) return -1;
        continuations[index] = response.continuation_id; epochs[index] = value.write_epoch;
        CHECK(fixture, continuations[index] && continuations[index] != continuations[index - 1],
              "fresh_continuation_identity");
    }
    if (refusal(fixture, "continuation_capacity_preserves_old_pins", value)) return -1;
    for (unsigned int index = 128; index-- > 1;)
    {
        value = request(fixture, PEAR_FEX_CONTINUATION_UNPIN); identity(&value, token);
        value.executor_id = fixture->executor; value.continuation_id = continuations[index];
        value.write_epoch = epochs[index]; value.expected_state = PEAR_FEX_PUBLISHED_RX;
        if (success(fixture, "discard_owned_saved_resume", value, &response)) return -1;
    }
    /* An actual source owner rewrite advances the allocation's epoch while
     * the original saved generation remains pinned outside managed code. */
    if (emit_code(fixture, token, 84)) return -1;
    CHECK(fixture, token->facts.write_epoch != epochs[0], "writer_advances_epoch_with_saved_pin");
    value = request(fixture, PEAR_FEX_CONTINUATION_UNPIN); identity(&value, token);
    value.executor_id = fixture->executor; value.continuation_id = continuations[0];
    value.write_epoch = token->facts.write_epoch; value.expected_state = PEAR_FEX_PUBLISHED_RX;
    if (refusal(fixture, "new_epoch_cannot_release_original_pin", value)) return -1;
    value.write_epoch = epochs[0];
    if (success(fixture, "release_original_pin_epoch", value, &response)) return -1;
    CHECK(fixture, response.flags == PEAR_FEX_NATIVE_IDLE && !response.continuation_id,
          "source_continuations_drained");
    ++fixture->continuation_controls;
    return 0;
}
static int abort_controls(struct fixture *fixture)
{
    struct token token = {0};
    if (reserve(fixture, &token, PEAR_FEX_CLASS_SHARED, SHARED_UNIT)) return -1;
    struct pear_fex_memory_request value = request(fixture, PEAR_FEX_BEGIN_WRITE);
    identity(&value, &token); value.executor_id = fixture->executor;
    value.write_epoch = token.facts.write_epoch; value.expected_state = PEAR_FEX_RESERVED_NONE;
    value.operation_size = 4096;
    if (success(fixture, "begin_unpublished_abort_control", value, &token.facts)) return -1;
    uint64_t saved_window = token.facts.private_write_base;
    CHECK(fixture, saved_window && fixture->platform->observe(saved_window, 4096,
          PEAR_FEX_PROTECTION_RW_NX) == 0, "abort_window_rw_nx");
    memcpy((void *)(uintptr_t)saved_window, leaf42, sizeof(leaf42));
    value = request(fixture, PEAR_FEX_ABORT_WRITE); identity(&value, &token);
    value.executor_id = fixture->executor; value.write_epoch = token.facts.write_epoch;
    value.expected_state = PEAR_FEX_WRITING_RW_NX;
    if (success(fixture, "abort_unpublished_window", value, &token.facts)) return -1;
    CHECK(fixture, token.facts.lifecycle_state == PEAR_FEX_RESERVED_NONE &&
          !token.facts.private_write_base && token.facts.effective_protection == PEAR_FEX_PROTECTION_NONE &&
          fixture->platform->observe(saved_window, 4096, PEAR_FEX_PROTECTION_NONE) == 0,
          "aborted_candidate_never_executable");
    fixture->protection_observations += 2;
    if (emit_code(fixture, &token, 42) || execute_code(fixture, &token, 42, 0) || retire(fixture, &token)) return -1;
    return 0;
}
/* Actual owner operations on a real published dispatcher extent. These
 * finite API controls do not initialize FEX or qualify source object lifetime. */
static int atomic_resume_controls(struct fixture *fixture, struct token *token)
{
    struct pear_fex_memory_request value = request(fixture, PEAR_FEX_EXECUTOR_ENTRY);
    struct pear_fex_memory_response response;
    identity(&value, token); value.executor_id = fixture->executor;
    value.write_epoch = token->facts.write_epoch; value.expected_state = PEAR_FEX_PUBLISHED_RX;
    value.operation_size = 4;
    if (success(fixture, "atomic_enter_dispatcher", value, &response)) return -1;
    value.opcode = PEAR_FEX_EXECUTOR_HANDOFF;
    if (success(fixture, "atomic_handoff_dispatcher", value, &response)) return -1;
    const uint64_t original_continuation = response.continuation_id;
    const uint64_t original_epoch = value.write_epoch;
    CHECK(fixture, original_continuation && response.flags == PEAR_FEX_NATIVE_PINNED,
          "atomic_original_dispatcher_pin");
    const char *labels[] = {"atomic_wrong_size", "atomic_wrong_offset", "atomic_wrong_continuation",
                           "atomic_missing_continuation", "atomic_stale_current_epoch", "atomic_old_wire_version",
                           "atomic_wrong_generation", "atomic_wrong_executor", "atomic_wrong_role"};
    for (unsigned int control = 0; control < 9; ++control)
    {
        struct pear_fex_memory_request resume = value;
        resume.opcode = PEAR_FEX_EXECUTOR_RESUME; resume.continuation_id = original_continuation;
        if (control == 0) resume.operation_size = 0;
        else if (control == 1) resume.operation_offset = 4;
        else if (control == 2) ++resume.continuation_id;
        else if (control == 3) resume.continuation_id = 0;
        else if (control == 4) ++resume.write_epoch;
        else if (control == 5) resume.version = 1;
        else if (control == 6) ++resume.generation;
        else if (control == 7) ++resume.executor_id;
        else resume.ec_role = fixture->platform->role == PEAR_FEX_ROLE_NATIVE ?
                                  PEAR_FEX_ROLE_ARM64EC : PEAR_FEX_ROLE_NATIVE;
        if (refusal(fixture, labels[control], resume)) return -1;
        struct pear_fex_memory_request poll = value;
        poll.continuation_id = original_continuation; poll.operation_size = 0;
        if (success(fixture, "atomic_refusal_preserves_original_pin", poll, &response)) return -1;
        CHECK(fixture, response.continuation_id == original_continuation &&
              response.flags == PEAR_FEX_NATIVE_PINNED, "atomic_refusal_keeps_actual_pin");
    }
    value.opcode = PEAR_FEX_RETIRE; value.continuation_id = 0; value.operation_size = 0;
    if (refusal(fixture, "atomic_retirement_preserves_original_pin", value)) return -1;
    /* A real owner write advances the current epoch while the original
     * descriptor/continuation remains pinned. The original instruction stays42. */
    if (emit_code(fixture, token, 42)) return -1;
    CHECK(fixture, token->facts.write_epoch > original_epoch, "atomic_real_epoch_advance");
    value = request(fixture, PEAR_FEX_EXECUTOR_RESUME); identity(&value, token);
    value.executor_id = fixture->executor; value.continuation_id = original_continuation;
    value.write_epoch = original_epoch; value.expected_state = PEAR_FEX_PUBLISHED_RX;
    value.operation_size = 4;
    if (refusal(fixture, "atomic_original_epoch_requires_retry", value)) return -1;
    value.write_epoch = token->facts.write_epoch;
    if (success(fixture, "atomic_consume_original_pin_on_current_epoch", value, &response)) return -1;
    CHECK(fixture, response.flags == PEAR_FEX_MANAGED_ACTIVE && !response.continuation_id &&
          response.write_epoch == token->facts.write_epoch &&
          response.lifecycle_state == PEAR_FEX_PUBLISHED_RX &&
          response.effective_protection == PEAR_FEX_PROTECTION_RX,
          "atomic_resume_active_without_continuation");
    if (refusal(fixture, "atomic_consumed_continuation_cannot_repeat", value)) return -1;
    value = request(fixture, PEAR_FEX_EXECUTOR_EXIT); identity(&value, token);
    value.executor_id = fixture->executor; value.write_epoch = token->facts.write_epoch;
    value.expected_state = PEAR_FEX_PUBLISHED_RX;
    if (success(fixture, "atomic_exit_consumed_continuation", value, &response)) return -1;
    CHECK(fixture, response.flags == PEAR_FEX_NATIVE_IDLE && !response.continuation_id,
          "atomic_resume_checked_native_exit");
    ++fixture->continuation_controls;
    return 0;
}
static int dispatcher_controls(struct fixture *fixture)
{
    struct token token = {0};
    if (reserve(fixture, &token, PEAR_FEX_CLASS_DISPATCHER, 16384) ||
        emit_code(fixture, &token, 42) || atomic_resume_controls(fixture, &token) ||
        execute_code(fixture, &token, 42, 0) ||
        execute_code(fixture, &token, 42, 4096) || emit_code(fixture, &token, 84) ||
        execute_code(fixture, &token, 84, 0) || retire(fixture, &token)) return -1;
    return 0;
}
static int capacity_controls(struct fixture *fixture)
{
    struct token units[32] = {0};
    for (unsigned int index = 0; index < 32; ++index)
        if (reserve(fixture, &units[index], PEAR_FEX_CLASS_SHARED, SHARED_UNIT)) return -1;
    struct pear_fex_memory_request value = request(fixture, PEAR_FEX_RESERVE);
    value.executor_id = fixture->executor; value.allocation_class = PEAR_FEX_CLASS_SHARED;
    value.ec_role = fixture->platform->role; value.extent_size = SHARED_UNIT;
    if (refusal(fixture, "shared_capacity_exhausted", value)) return -1;
    for (unsigned int index = 0; index < 32; index += 2)
        if (retire(fixture, &units[index])) return -1;
    value.extent_size = 2 * SHARED_UNIT;
    if (refusal(fixture, "fragmented_free_bytes_refused", value)) return -1;
    ++fixture->fragmentation_controls;
    for (unsigned int index = 1; index < 32; index += 2)
        if (retire(fixture, &units[index])) return -1;
    for (unsigned int index = 0; index < 4; ++index)
    {
        struct token large = {0};
        if (reserve(fixture, &large, PEAR_FEX_CLASS_SHARED, SHARED_UNIT << index)) return -1;
        if (retire(fixture, &large)) return -1;
    }
    struct token dispatchers[64] = {0};
    for (unsigned int index = 0; index < 64; ++index)
        if (reserve(fixture, &dispatchers[index], PEAR_FEX_CLASS_DISPATCHER, 16384)) return -1;
    value.allocation_class = PEAR_FEX_CLASS_DISPATCHER; value.extent_size = 16384;
    if (refusal(fixture, "dispatcher_capacity_exhausted", value)) return -1;
    for (unsigned int index = 0; index < 64; ++index)
        if (retire(fixture, &dispatchers[index])) return -1;
    return 0;
}
int pear_memory_fixture_suite(const struct pear_memory_fixture_platform *platform)
{
    struct fixture fixture = {0}; fixture.platform = platform;
    if (!platform || !platform->owner_pid || !platform->call || !platform->observe || !platform->execute)
        return 64;
    struct pear_fex_memory_request value = request(&fixture, PEAR_FEX_EXECUTOR_REGISTER);
    value.ec_role = platform->role;
    struct pear_fex_memory_response response;
    if (success(&fixture, "register_actual_native_executor", value, &response)) goto failed;
    fixture.executor = response.executor_id;
    if (check(&fixture, fixture.executor && response.flags == PEAR_FEX_NATIVE_IDLE,
              "executor_registration")) goto failed;
    struct token token = {0};
    if (reserve(&fixture, &token, PEAR_FEX_CLASS_SHARED, SHARED_UNIT) ||
        malformed_controls(&fixture, &token) || emit_code(&fixture, &token, 42) ||
        execute_code(&fixture, &token, 42, 0) || execute_code(&fixture, &token, 42, 4096)) goto failed;
    for (unsigned int round = 0; round < SCHEDULES; ++round)
    {
        unsigned int answer = round & 1 ? 42 : 84;
        if (emit_code(&fixture, &token, answer) || execute_code(&fixture, &token, answer, 0) ||
            execute_code(&fixture, &token, answer, 4096)) goto failed;
        ++fixture.patch_rounds;
    }
    if (cross_page_control(&fixture, &token) || continuation_controls(&fixture, &token) || execute_code(&fixture, &token, 84, 0) ||
        retire(&fixture, &token)) goto failed;
    value = request(&fixture, PEAR_FEX_RETIRE); identity(&value, &token);
    value.executor_id = fixture.executor; value.write_epoch = token.facts.write_epoch;
    value.expected_state = PEAR_FEX_RETIRED_NONE;
    if (refusal(&fixture, "duplicate_retirement", value) || abort_controls(&fixture) ||
        dispatcher_controls(&fixture) || capacity_controls(&fixture)) goto failed;
    value = request(&fixture, PEAR_FEX_EXECUTOR_UNREGISTER); value.executor_id = fixture.executor;
    if (success(&fixture, "unregister_actual_native_executor", value, &response)) goto failed;
    if (check(&fixture, response.flags == PEAR_FEX_UNREGISTERED, "executor_unregistered")) goto failed;
    printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_fixture\",\"scope\":\"%s\","
           "\"sequence\":%" PRIu64 ",\"event\":\"suite_complete\",\"passed\":true,"
           "\"checked_ec\":%s,\"owner_calls\":%u,\"refusals\":%u,\"allocations\":%u,"
           "\"retirements\":%u,\"publications\":%u,\"owned_code_calls\":%u,"
           "\"protection_observations\":%u,\"patch_rounds\":%u,\"fragmentation_controls\":%u,\"continuation_controls\":%u,"
           "\"fex_initialization\":false,\"translated_guest_execution\":false,\"game_execution\":false}\n",
           platform->scope, ++fixture.sequence, platform->checked_ec ? "true" : "false",
           fixture.calls, fixture.refusals, fixture.allocations, fixture.retirements,
           fixture.publications, fixture.executable_calls, fixture.protection_observations,
           fixture.patch_rounds, fixture.fragmentation_controls, fixture.continuation_controls);
    return 0;
failed:
    printf("{\"version\":1,\"record_kind\":\"pear_fex_memory_fixture\",\"scope\":\"%s\","
           "\"sequence\":%" PRIu64 ",\"event\":\"suite_complete\",\"passed\":false,"
           "\"checked_ec\":%s,\"owner_calls\":%u,\"fex_initialization\":false,"
           "\"translated_guest_execution\":false,\"game_execution\":false}\n",
           platform->scope, ++fixture.sequence, platform->checked_ec ? "true" : "false", fixture.calls);
    return 1;
}

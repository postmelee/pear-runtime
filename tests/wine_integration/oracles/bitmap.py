# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Finite Wine bitmap diagnostic policy; pure parsing, never native admission.

Every returned row remains a diagnostic observation. Paired producer/current
source/raw-stream closure and execution supervision belong to the parent.
"""
import hashlib
import json

PREFIX = b'PEAR_FEX_BITMAP_DIAGNOSTIC '
MAX_ROW = 4096
BITMAP_PREFIX = b'PEAR_FEX_BITMAP '
MAX_STREAM = 2 * 1024**2
# Selected public SDK vm_region.h uses pack(4), five initial 32-bit fields,
# one 64-bit offset, one 32-bit behavior and a 16-bit wired count: 36 / 4.
# This source-derived value is not a new paired-target sizeof observation.
VM_BASIC_COUNT = 9
VM_KEYS = {'mode', 'performed', 'calls', 'expected', 'region_code', 'port_release_performed',
           'port_release_code', 'count', 'protection', 'maximum', 'predicate_failed'}
BOOL_KEYS = {'created_bitmap', 'bitmap_prepared', 'page_count_performed', 'force_exec_prot',
             'original_bitmap_present', 'original_peb_bitmap_present', 'first_page_performed',
             'set_vprot_performed', 'set_vprot_succeeded', 'release_performed',
             'release_classification_performed', 'release_arena_check_performed', 'release_arena_overlap',
             'release_native_performed', 'release_native_succeeded', 'final_bitmap_equal', 'final_peb_equal',
             'fex_initialization', 'translated_guest_execution', 'game_execution'}
UINT_KEYS = {'failure_predicates', 'page_count', 'first_page', 'previous_vprot', 'current_vprot',
             'release_method', 'native_error_domain'}
KEYS = BOOL_KEYS | UINT_KEYS | {'schema_version', 'record_kind', 'scope', 'release_reserved',
                              'native_error_code', 'cleanup_vm', 'page_vm', 'release_vm'}
BITMAP_KEYS = {'set_observed', 'clear_observed', 'restoration_observed', 'none_before', 'none_after',
               'actual_peb_bitmap', 'restoration_attempted', 'hybrid_classification', 'error_domain', 'error_code'}


class Refused(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def vm(value):
    need(type(value) is dict and set(value) == VM_KEYS, 'vm_shape')
    for name in ('performed', 'port_release_performed', 'predicate_failed'):
        need(type(value[name]) is bool, 'vm_boolean')
    for name in ('calls', 'count', 'protection', 'maximum'):
        need(integer(value[name], 0, 2**32-1), 'vm_unsigned')
    for name in ('region_code', 'port_release_code'):
        need(integer(value[name], -2**31, 2**31-1), 'vm_native_code')
    need(integer(value['mode'], 0, 2) and integer(value['expected'], 0, 7), 'vm_mode')
    if value['mode'] == 0:
        need(value == dict.fromkeys(VM_KEYS, 0) | {
            'performed': False, 'port_release_performed': False, 'predicate_failed': False}, 'vm_unperformed')
    if not value['performed']:
        need(value['calls'] == 0 and value['region_code'] == 0 and value['count'] == 0
             and value['protection'] == 0 and value['maximum'] == 0
             and not value['port_release_performed'], 'vm_fabricated_observation')
    else:
        need(value['mode'] != 0 and value['calls'] > 0, 'vm_missing_call')
    if not value['port_release_performed']:
        need(value['port_release_code'] == 0, 'vm_fabricated_port_error')
    else:
        need(value['performed'], 'vm_fabricated_port_release')
    if value['mode'] == 2:
        need(value['expected'] == 0 and (not value['performed'] or value['calls'] == 1),
             'hole_call_identity')
    return value


def vm_outcome(value):
    """Return disclosed source predicate outcome, never a native error guess.

    Geometry details remain undisclosed. A true predicate_failed can reflect
    those details even when protection/count match. Primary error is independent
    of this latest observer because earlier errors are deliberately preserved.
    """
    vm(value)
    if value['mode'] == 0:
        return None
    if not value['performed']:
        need(value['predicate_failed'], 'observer_unperformed_predicate')
        return False
    effective = value['region_code']
    if not effective and value['port_release_performed']:
        effective = value['port_release_code']
    if value['mode'] == 2 and effective == 1:
        need(not value['predicate_failed'], 'hole_invalid_address_predicate')
        return True
    if effective:
        need(not value['predicate_failed'], 'native_error_precedes_predicate')
        return False
    if value['count'] != VM_BASIC_COUNT or (value['mode'] == 1 and
        (value['protection'] != value['expected'] or value['maximum'] & value['expected'] != value['expected'])):
        need(value['predicate_failed'], 'observer_unmarked_predicate')
    return not value['predicate_failed']


def known_native_failure(value):
    if not value['performed']:
        return False
    effective = value['region_code']
    if not effective and value['port_release_performed']:
        effective = value['port_release_code']
    return bool(effective) and not (value['mode'] == 2 and effective == 1)


def unix_protection(vprot):
    """Exact selected Wine get_unix_prot byte mapping; no VM operation."""
    result = 0
    if vprot & 0x20 and not vprot & 0x10:
        if vprot & 0x01:
            result |= 1
        if vprot & (0x02 | 0x08):
            result |= 3
        if vprot & 0x04:
            result |= 5
        if vprot & 0x40:
            result &= ~2
    return result


def validate(value, bitmap=None):
    need(type(value) is dict and set(value) == KEYS, 'row_shape')
    need(type(value['schema_version']) is int and value['schema_version'] == 1
         and value['record_kind'] == 'pear_fex_bitmap_diagnostic'
         and value['scope'] == 'finite_wine_owner_bitmap_restoration', 'row_scope')
    for name in BOOL_KEYS:
        need(type(value[name]) is bool, 'row_boolean')
    for name in UINT_KEYS:
        need(integer(value[name], 0, 2**32-1), 'row_unsigned')
    need(integer(value['native_error_code'], -2**31, 2**31-1)
         and integer(value['release_reserved'], -1, 1), 'row_signed')
    need(value['native_error_domain'] <= 3 and (value['native_error_domain'] or not value['native_error_code']),
         'row_native_error')
    need(value['failure_predicates'] & ~8191 == 0 and value['release_method'] <= 2,
         'row_closed_mask')
    need(all(value[name] is False for name in ('fex_initialization', 'translated_guest_execution', 'game_execution')),
         'row_unqualified_scope')
    for name in ('cleanup_vm', 'page_vm', 'release_vm'):
        vm_outcome(value[name])
    mask = value['failure_predicates']
    need(value['created_bitmap'] is not value['original_bitmap_present'], 'created_bitmap_complement')
    if not value['page_count_performed']:
        need(value['page_count'] == 0, 'page_count_fabricated')
    if value['bitmap_prepared']:
        need(value['page_count_performed'] and 1 <= value['page_count'] <= 32,
             'prepared_page_count')
        need(not value['original_bitmap_present'] or value['original_peb_bitmap_present'],
             'prepared_existing_peb_presence')
        cleanup = value['cleanup_vm']
        need(cleanup['mode'] == 1 and cleanup['performed'] and cleanup['expected'] == 3
             and 1 <= cleanup['calls'] <= value['page_count'], 'cleanup_observer_identity')
        need(bool(mask & 1) is (vm_outcome(cleanup) is False), 'cleanup_failure_mask')
    else:
        need(value['cleanup_vm']['mode'] == 0 and not mask & 31,
             'unprepared_restore_observation')
    need(value['first_page_performed'] is bool(mask & 6), 'first_page_mask_presence')
    if value['first_page_performed']:
        need(value['bitmap_prepared'] and value['page_count_performed'] and 0 < value['page_count'] <= 32
             and value['first_page'] < value['page_count'] and value['set_vprot_performed']
             and value['failure_predicates'] & 6, 'first_page_identity')
        need(value['previous_vprot'] <= 255 and value['current_vprot'] <= 255, 'page_vprot')
        page = value['page_vm']
        need(page['mode'] == 1 and page['performed'] and page['calls'] == 1
             and page['expected'] == unix_protection(value['previous_vprot']), 'first_page_missing_observation')
        set_failed = not value['set_vprot_succeeded']
        observed_failed = vm_outcome(page) is False
        need(set_failed or observed_failed, 'first_page_success_snapshot')
        need(not set_failed or mask & 2, 'first_page_set_mask')
        need(not observed_failed or mask & 4, 'first_page_observer_mask')
        if value['first_page'] == value['page_count'] - 1:
            need(bool(mask & 2) is set_failed and bool(mask & 4) is observed_failed,
                 'last_first_page_exact_mask')
    else:
        need(all(value[name] == 0 for name in ('first_page', 'previous_vprot', 'current_vprot'))
             and not value['set_vprot_performed'] and not value['set_vprot_succeeded']
             and value['page_vm']['mode'] == 0, 'first_page_fabricated')
    if not value['release_performed']:
        need(not value['release_classification_performed'] and value['release_reserved'] == 0
             and not value['release_arena_check_performed'] and not value['release_arena_overlap']
             and value['release_method'] == 0 and not value['release_native_performed']
             and not value['release_native_succeeded'] and value['release_vm']['mode'] == 0,
             'release_fabricated')
        need(not mask & 2016, 'release_unperformed_mask')
    else:
        need(value['created_bitmap'] and value['release_classification_performed'], 'release_identity')
        if value['release_reserved'] < 0:
            need(not value['release_arena_check_performed'] and not value['release_arena_overlap']
                 and value['failure_predicates'] & 32 and value['release_method'] == 0
                 and not value['release_native_performed'],
                 'partial_reserved_branch')
            need(mask & 2016 == 32, 'partial_reserved_exact_mask')
        else:
            need(value['release_arena_check_performed'], 'arena_check_missing')
            if value['release_arena_overlap']:
                need(value['failure_predicates'] & 64 and value['release_method'] == 0
                     and not value['release_native_performed'], 'arena_overlap_branch')
                need(mask & 2016 == 64, 'arena_overlap_exact_mask')
            else:
                need(value['release_method'] == (1 if value['release_reserved'] else 2)
                     and value['release_native_performed'], 'release_method_identity')
                failure_bit = 128 if value['release_method'] == 1 else 512
                observer_bit = 256 if value['release_method'] == 1 else 1024
                if not value['release_native_succeeded']:
                    need(mask & 2016 == failure_bit, 'release_native_failure_mask')
                else:
                    need(value['release_vm']['mode'] == value['release_method']
                         and value['release_vm']['performed'] and value['release_vm']['expected'] == 0,
                         'release_observer_identity')
                    expected_mask = observer_bit if vm_outcome(value['release_vm']) is False else 0
                    need(mask & 2016 == expected_mask, 'release_observer_failure_mask')
        release_succeeded = (value['release_reserved'] >= 0 and not value['release_arena_overlap']
            and value['release_native_succeeded'] and vm_outcome(value['release_vm']) is True)
        need(value['final_bitmap_equal'] is release_succeeded, 'created_release_final_bitmap')
        need(not release_succeeded or value['final_peb_equal'], 'created_release_final_peb')
    if not value['release_native_performed']:
        need(not value['release_native_succeeded'] and value['release_vm']['mode'] == 0,
             'release_native_fabricated')
    if value['release_native_succeeded']:
        need(value['release_vm']['performed'] and value['release_vm']['mode'] == value['release_method'],
             'release_observation_missing')
    need(bool(mask & 2048) is not value['final_bitmap_equal'], 'bitmap_identity_contradiction')
    need(bool(mask & 4096) is not value['final_peb_equal'], 'peb_identity_contradiction')
    need(not (mask & 8 and mask & 16), 'view_identity_branch_order')
    if any(known_native_failure(value[name]) for name in ('cleanup_vm', 'page_vm', 'release_vm')) or (
        value['release_native_performed'] and not value['release_native_succeeded']):
        need(value['native_error_domain'] != 0, 'native_failure_primary_domain_missing')
    if bitmap is not None:
        need(type(bitmap) is dict and set(bitmap) == BITMAP_KEYS, 'bitmap_shape')
        for name in BITMAP_KEYS - {'error_domain', 'error_code'}:
            need(type(bitmap[name]) is bool, 'bitmap_boolean')
        need(integer(bitmap['error_domain'], 0, 3) and integer(bitmap['error_code'], -2**31, 2**31-1)
             and bitmap['hybrid_classification'] is False, 'bitmap_scope')
        need((value['native_error_domain'], value['native_error_code']) == (bitmap['error_domain'], bitmap['error_code']),
             'primary_error_changed')
        need(bitmap['restoration_attempted'] is (value['bitmap_prepared'] or value['release_performed']),
             'restoration_attempted_identity')
        if value['page_count_performed'] or value['bitmap_prepared']:
            need(bitmap['actual_peb_bitmap'] and bitmap['none_before'], 'prepared_primary_identity')
        if not value['bitmap_prepared']:
            need(not any(bitmap[name] for name in ('set_observed', 'clear_observed', 'none_after',
                     'restoration_observed')), 'unprepared_primary_observation')
        if mask & (8 | 16):
            need(bitmap['none_after'], 'view_identity_primary_branch')
        if value['failure_predicates']:
            need(bitmap['restoration_observed'] is False, 'failed_predicate_promoted')
        if bitmap['restoration_observed']:
            need(value['failure_predicates'] == 0 and value['final_bitmap_equal'] and value['final_peb_equal'],
                 'restoration_identity_missing')
            need(value['bitmap_prepared'] and value['page_count_performed'] and 1 <= value['page_count'] <= 32
                 and bitmap['restoration_attempted'] and bitmap['none_before'] and bitmap['none_after']
                 and bitmap['actual_peb_bitmap'] and vm_outcome(value['cleanup_vm']) is True,
                 'restoration_positive_prerequisites')
            if value['created_bitmap']:
                need(value['release_performed'] and value['release_native_succeeded']
                     and vm_outcome(value['release_vm']) is True, 'created_restoration_release')
    return value


def json_row(raw, prefix, bound):
    need(type(raw) is bytes and len(raw) <= bound and raw.startswith(prefix)
         and raw.endswith(b'\n') and raw.count(b'\n') == 1, 'row_bytes')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate_key')
            result[key] = value
        return result
    try:
        value = json.loads(raw[len(prefix):-1].decode('ascii'), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused('nonfinite')))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise Refused('invalid_json') from None
    return value


def parse_row(raw, bitmap=None):
    return validate(json_row(raw, PREFIX, MAX_ROW), bitmap)


def paired_prefix(raw, required, complete):
    """Closed original-row/diagnostic pairing with independent required count.

    The parent must still apply its original primary-record success predicate,
    command/source identity closure and finite native execution assessment.
    Other stderr remains byte-for-byte private diagnostics, not accepted warnings.
    """
    need(type(raw) is bytes and len(raw) <= MAX_STREAM
         and integer(required, 1, 128) and type(complete) is bool, 'stream_bound')
    rows = []
    other = bytearray()
    pending = None
    for line in raw.splitlines(keepends=True):
        # This exact branch precedes the original unknown-bitmap fallback.
        if line.startswith(PREFIX):
            need(pending is None, 'diagnostic_duplicate')
            pending = parse_row(line)
        elif line.startswith(BITMAP_PREFIX):
            need(pending is not None, 'diagnostic_missing')
            primary = json_row(line, BITMAP_PREFIX, 2048)
            validate(pending, primary)
            rows.append({'diagnostic': pending, 'bitmap': primary})
            pending = None
            need(len(rows) <= required, 'diagnostic_count')
        else:
            need(b'PEAR_FEX_BITMAP' not in line, 'bitmap_unrecognized')
            need(pending is None, 'diagnostic_not_adjacent')
            other.extend(line)
    need(pending is None, 'diagnostic_orphan')
    if complete:
        need(len(rows) == required, 'diagnostic_count')
    return rows, bytes(other)


def parse_stream(raw, expected):
    """Completed-count pairing; original native success gate remains separate."""
    return paired_prefix(raw, expected, True)


def parse_failed_prefix(raw, required):
    """Separate failed-run observations; observed count never replaces required.

    The caller binds required to the selected fixture's complete count. A
    malformed or unpaired row refuses rather than substituting another count;
    caller preserves raw bytes and its original process/source failure.
    """
    rows, other = paired_prefix(raw, required, False)
    return {'scope':'failed_partial_bitmap_diagnostics', 'required_self_tests':required,
            'observed_self_tests':len(rows), 'observations':rows,
            'completed_self_test_count_verified':False, 'runtime_qualification':'unperformed'}, other


def observe_failed_prefix(raw):
    """Retain only strict adjacent pairs before a refusal, with raw-byte spans.

    No expected count is accepted, no completed-run parser is called and no
    process/native error is inferred. The caller preserves the original error
    and complete private stream separately.
    """
    result = {'scope': 'partial_bitmap_diagnostics', 'completed_count_qualified': False,
              'observations': [], 'parse_error': None}
    pending = None
    offset = 0
    try:
        need(type(raw) is bytes and len(raw) <= MAX_STREAM, 'stream_bound')
        for line in raw.splitlines(keepends=True):
            if line.startswith(PREFIX):
                need(pending is None, 'diagnostic_duplicate')
                pending = (parse_row(line), offset)
            elif line.startswith(BITMAP_PREFIX):
                need(pending is not None, 'diagnostic_missing')
                primary = json_row(line, BITMAP_PREFIX, 2048)
                validate(pending[0], primary)
                need(len(result['observations']) < 128, 'diagnostic_count')
                start = pending[1]
                span = raw[start:offset+len(line)]
                result['observations'].append({'diagnostic': pending[0], 'bitmap': primary,
                    'raw_offset_bytes': start, 'raw_size_bytes': len(span),
                    'raw_sha256': hashlib.sha256(span).hexdigest()})
                pending = None
            else:
                need(b'PEAR_FEX_BITMAP' not in line, 'bitmap_unrecognized')
                need(pending is None, 'diagnostic_not_adjacent')
            offset += len(line)
        need(pending is None, 'diagnostic_orphan')
    except Refused as exc:
        result['parse_error'] = {'code': 'bitmap_diagnostic_prefix_refused',
                                 'reason': str(exc), 'raw_offset_bytes': offset}
    return result

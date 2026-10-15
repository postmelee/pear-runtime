"""Independent finite fixture wire reader for the approved private owner ABI.

This is test code, not an owner, platform backend or permission validator. The
native fixture includes Wine's authoritative header; these independently
encoded records check little-endian wire bytes and refusal observations.
"""
from __future__ import annotations

import struct

VERSION = 2

REQUEST_NAMES = ('version', 'size', 'opcode', 'flags', 'owner_pid',
    'allocation_id', 'generation', 'write_epoch', 'executor_id', 'continuation_id',
    'extent_offset', 'extent_size', 'operation_offset', 'operation_size',
    'allocation_class', 'ec_role', 'expected_state', 'reserved0', 'reserved1', 'reserved2')
RESPONSE_NAMES = ('version', 'size', 'status', 'flags', 'native_error_domain',
    'native_error_code', 'allocation_class', 'ec_role', 'owner_pid', 'allocation_id',
    'generation', 'write_epoch', 'executor_id', 'continuation_id', 'extent_offset',
    'extent_size', 'private_write_base', 'lifecycle_state', 'effective_protection',
    'capabilities', 'reserved0')
REQUEST = struct.Struct('<4I10Q4I2Q')
RESPONSE = struct.Struct('<5Ii2I9Q2I2Q')
assert REQUEST.size == RESPONSE.size == 128


class ProtocolError(ValueError):
    """A record violates the reviewed finite fixture boundary."""


def request(**fields):
    """Encode an original request, including malformed controls when requested."""
    unknown = set(fields) - set(REQUEST_NAMES)
    if unknown:
        raise ProtocolError('unknown_request_field')
    value = dict.fromkeys(REQUEST_NAMES, 0)
    value.update(version=VERSION, size=128)
    value.update(fields)
    if any(type(v) is not int for v in value.values()):
        raise ProtocolError('non_integer_request_field')
    try:
        return REQUEST.pack(*(value[name] for name in REQUEST_NAMES))
    except struct.error:
        raise ProtocolError('request_field_range') from None


def response(raw):
    """Read exact response bytes without interpreting a refusal as safe memory."""
    if not isinstance(raw, bytes) or len(raw) != RESPONSE.size:
        raise ProtocolError('response_size')
    value = dict(zip(RESPONSE_NAMES, RESPONSE.unpack(raw)))
    if value['version'] != VERSION or value['size'] != 128:
        raise ProtocolError('response_header')
    if value['status'] not in range(9) or value['native_error_domain'] not in range(4):
        raise ProtocolError('response_status_domain')
    if value['reserved0'] or value['flags'] & ~7 or value['flags'] > 5:
        raise ProtocolError('response_reserved_or_executor_state')
    if value['native_error_domain'] == 0 and value['native_error_code']:
        raise ProtocolError('response_error_domain_missing')
    if value['status']:
        # Zeroing is a refusal contract, not an observation of PROT_NONE.
        keep = {'version', 'size', 'status', 'native_error_domain', 'native_error_code'}
        if any(number for name, number in value.items() if name not in keep):
            raise ProtocolError('refusal_exposes_success_facts')
        return value
    if value['native_error_domain'] or value['native_error_code']:
        raise ProtocolError('success_preserves_failure_error')
    if (value['allocation_class'] not in range(3) or value['ec_role'] not in range(3)
            or value['lifecycle_state'] not in range(6)
            or value['effective_protection'] not in range(3)
            or value['capabilities'] & ~15):
        raise ProtocolError('response_unknown_success_enum')
    if value['private_write_base'] and not (
        value['lifecycle_state'] == 2 and value['effective_protection'] == 1
        and value['owner_pid'] and value['allocation_id'] and value['generation']
        and value['write_epoch'] and value['executor_id'] and value['extent_size']):
        raise ProtocolError('response_write_address_without_lease')
    if value['lifecycle_state'] and not (
        value['owner_pid'] and value['allocation_id'] and value['generation']
        and value['extent_size'] and value['allocation_class'] and value['ec_role']):
        raise ProtocolError('response_incomplete_allocation_identity')
    if value['flags'] and not (value['owner_pid'] and value['executor_id']):
        raise ProtocolError('response_incomplete_executor_identity')
    return value


def publication(value, *, ec_required):
    """Check observed RX/cache/EC facts before a fixture calls owned code."""
    expected = {'state', 'effective_protection', 'pages_observed',
                'cache_primitive_performed', 'checked_ec', 'ec_registered',
                'writer_closed', 'raw_signal_handoff'}
    if not isinstance(value, dict) or set(value) != expected:
        raise ProtocolError('publication_observation_fields')
    if (value['state'] != 'published_rx' or value['effective_protection'] != 'rx'
            or type(value['pages_observed']) is not int or value['pages_observed'] < 1
            or value['cache_primitive_performed'] is not True
            or value['writer_closed'] is not True or value['raw_signal_handoff'] is not False):
        raise ProtocolError('publication_not_observed')
    if type(value['checked_ec']) is not bool or type(value['ec_registered']) is not bool:
        raise ProtocolError('publication_ec_fact_type')
    if ec_required and not (value['checked_ec'] and value['ec_registered']):
        raise ProtocolError('publication_ec_unqualified')
    if value['ec_registered'] and not value['checked_ec']:
        raise ProtocolError('publication_shadow_ec_claim')
    return value

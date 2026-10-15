"""Bounded data and exact-byte helpers for Wine component preparation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

REPO = Path(__file__).resolve().parents[2]
MAX_JSON = 8 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024 * 1024
MAX_NODES = 250000
MAX_DEPTH = 48
MAX_STRING = 262144
HEX256 = re.compile(r'[0-9a-f]{64}\Z')


class Error(Exception):
    """A stable public error code, without raw paths or subprocess diagnostics."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise Error(code)


def relative(value):
    need(isinstance(value, str) and 0 < len(value.encode('utf-8', 'surrogatepass')) <= 4096,
         'unsafe_path')
    need(not value.startswith(('/', '~')) and not any(c in value for c in ('\\', ':', '%'))
         and all(ord(c) >= 32 and ord(c) != 127 and not 0xD800 <= ord(c) <= 0xDFFF for c in value),
         'unsafe_path')
    parts = tuple(value.split('/'))
    need(len(parts) <= 64 and all(p not in ('', '.', '..') and len(p.encode('utf-8')) <= 255 for p in parts),
         'unsafe_path')
    return parts


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def open_relative(root, value, directory=False):
    """Read descriptor-relative paths without following any relative component."""
    parts = relative(value)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(parts):
            is_dir = index < len(parts) - 1 or directory
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if is_dir:
                flags |= os.O_DIRECTORY
            new = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = new
            mode = os.fstat(fd).st_mode
            need(stat.S_ISDIR(mode) if is_dir else stat.S_ISREG(mode), 'nonregular_input')
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_relative(root, value, limit=MAX_JSON):
    with os.fdopen(open_relative(root, value), 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(before.st_size <= limit, 'input_size_limit')
        data = stream.read(limit + 1)
        need(len(data) <= limit, 'input_size_limit')
        need(_identity(before) == _identity(os.fstat(stream.fileno())), 'input_changed')
        return data


def sha256(path):
    """Hash an ordinary file, refusing symlink leaves, special files and changes."""
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode), 'nonregular_input')
        need(before.st_size <= MAX_FILE, 'input_size_limit')
        digest, size = hashlib.sha256(), 0
        while block := stream.read(1024 * 1024):
            size += len(block)
            need(size <= MAX_FILE, 'input_size_limit')
            digest.update(block)
        need(_identity(before) == _identity(os.fstat(stream.fileno())) and size == before.st_size,
             'input_changed')
        return digest.hexdigest()


# The preflight counts every container, key and scalar before json.loads can
# allocate an object graph. The strict JSON parser still validates the grammar.
_JSON_GAP = re.compile(r'[ \t\r\n,:]+')
_JSON_STRING_MARK = re.compile(r'["\\\x00-\x1f]')
_JSON_ATOM = re.compile(r'(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null|NaN|-?Infinity)')
_JSON_HEX = re.compile(r'[0-9a-fA-F]{4}\Z')


def _json_preflight(text, max_nodes):
    position, count, containers = 0, 0, []
    while position < len(text):
        char = text[position]
        if char in ' \t\r\n,:':
            position = _JSON_GAP.match(text, position).end()
            continue
        if char in ']}':
            need(containers and containers.pop() == ('[' if char == ']' else '{'), 'invalid_json')
            position += 1
            continue
        count += 1
        need(count <= max_nodes and len(containers) <= MAX_DEPTH, 'json_structure_limit')
        if char in '[{':
            containers.append(char)
            position += 1
        elif char == '"':
            position += 1
            while True:
                mark = _JSON_STRING_MARK.search(text, position)
                need(mark is not None, 'invalid_json')
                position = mark.start()
                if text[position] == '"':
                    position += 1
                    break
                need(text[position] == '\\' and position + 1 < len(text), 'invalid_json')
                escape = text[position + 1]
                if escape == 'u':
                    need(_JSON_HEX.fullmatch(text[position + 2:position + 6]) is not None, 'invalid_json')
                    position += 6
                else:
                    need(escape in '"\\/bfnrt', 'invalid_json')
                    position += 2
        else:
            atom = _JSON_ATOM.match(text, position)
            need(atom is not None, 'invalid_json')
            position = atom.end()
    need(not containers, 'invalid_json')


def _json_children(item, depth):
    if isinstance(item, dict):
        for key, value in item.items():
            need(len(key) <= 256, 'json_key_limit')
            yield key, depth
            yield value, depth
    else:
        for value in item:
            yield value, depth


def decode_json(data, max_bytes=MAX_JSON, *, max_nodes=MAX_NODES):
    need(type(max_bytes) is int and max_bytes > 0 and type(max_nodes) is int and max_nodes > 0,
         'invalid_json_budget')
    need(isinstance(data, bytes) and len(data) <= max_bytes, 'input_size_limit')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    def forbidden(_):
        raise Error('noninteger_json_number')
    try:
        text = data.decode('utf-8')
        _json_preflight(text, max_nodes)
        value = json.loads(text, object_pairs_hook=pairs,
                           parse_constant=forbidden, parse_float=forbidden)
    except (UnicodeError, ValueError, RecursionError):
        raise Error('invalid_json') from None
    # Iterators keep the validation stack proportional to depth, not the number
    # of siblings in a large event array. Keys count as nodes in both passes.
    pending, count = [iter(((value, 0),))], 0
    while pending:
        try:
            item, depth = next(pending[-1])
        except StopIteration:
            pending.pop()
            continue
        count += 1
        need(count <= max_nodes and depth <= MAX_DEPTH, 'json_structure_limit')
        if isinstance(item, (dict, list)):
            pending.append(_json_children(item, depth + 1))
        elif isinstance(item, str):
            need(len(item) <= MAX_STRING and all((ord(c) >= 32 or c in '\n\r\t') and ord(c) != 127
                 and not 0xD800 <= ord(c) <= 0xDFFF for c in item), 'json_string_limit')
        elif type(item) is int:
            need(abs(item) <= 2**53 - 1, 'json_integer_limit')
    need(isinstance(value, dict), 'invalid_document_shape')
    return value


def load_json(path, max_bytes=MAX_JSON):
    path = Path(path)
    return decode_json(read_relative(path.parent, path.name, max_bytes), max_bytes)


def record(value, kind):
    need(isinstance(value, dict), 'invalid_document_shape')
    need(type(value.get('schema_version')) is int and value['schema_version'] == 1,
         'unsupported_record_version')
    need(value.get('record_kind') == kind, 'unexpected_record_kind')
    return value


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('utf-8')

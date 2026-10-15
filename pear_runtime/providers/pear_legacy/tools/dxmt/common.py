"""DXMT-scoped bounded readers; no build or guest-execution functionality."""
from __future__ import annotations
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import struct
import subprocess
import time

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('_pear_dxmt_bounded_common', REPO / 'tools/wine/common.py')
_wine = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_wine)
# Reuse only these reviewed general readers, not Wine/task4 entrypoints.
Error, need, relative = _wine.Error, _wine.need, _wine.relative
read_relative, open_relative = _wine.read_relative, _wine.open_relative
decode_json, load_json, encoded, record = _wine.decode_json, _wine.load_json, _wine.encoded, _wine.record
sha256 = _wine.sha256
_audit_spec = importlib.util.spec_from_file_location('_pear_dxmt_source_audit', REPO / 'tools/sources/validate_inventory.py')
_audit = importlib.util.module_from_spec(_audit_spec)
_audit_spec.loader.exec_module(_audit)
MAX_LISTING = 32 * 1024 * 1024
MAX_BLOB = 32 * 1024 * 1024
MAX_SOURCE = 256 * 1024 * 1024
MAX_ENTRIES = 250000
MACH_ARM64 = 0x100000c


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hex_digest(value, length=64):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{' + str(length) + '}', value) is not None


def fields(value, names, kind=None):
    need(isinstance(value, dict) and set(value) == set(names), 'record_fields')
    if kind:
        record(value, kind)


def real_directory(value):
    path = Path(value).absolute()
    need('..' not in path.parts, 'unsafe_root')
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        need(not cursor.is_symlink() and cursor.is_dir(), 'unsafe_root')
    return path


def output_directory(value, repo=REPO):
    root = real_directory(repo)
    path = Path(value)
    path = path if path.is_absolute() else root / path
    need('..' not in path.parts and path.parent == root / '.build/task7'
         and re.fullmatch('[a-z0-9][a-z0-9_-]{0,95}', path.name), 'output_scope')
    for item in [root / '.build', root / '.build/task7', path]:
        need(not item.is_symlink(), 'symlink_output')
        need(not item.exists() or item.is_dir(), 'output_not_directory')
    need(not path.exists(), 'destination_exists')
    path.mkdir(parents=True, mode=0o755)
    return path


def owned_directory(value, repo=REPO):
    root = real_directory(repo)
    path = real_directory(value)
    need(path.parent == root / '.build/task7' and re.fullmatch('[a-z0-9][a-z0-9_-]{0,95}', path.name),
         'output_scope')
    return path


def write_new(path, value):
    path = Path(path)
    need(not path.is_symlink() and not path.exists(), 'destination_exists')
    with path.open('xb') as out:
        out.write(encoded(value))


def producer_hashes(repo=REPO):
    root = Path(repo)
    paths = ['tools/dxmt/' + n for n in ['common.py', 'prepare.py', 'check.py', 'verify.py']]
    paths += ['tools/wine/common.py', 'tools/sources/validate_inventory.py']
    return {name: digest(read_relative(root, name, MAX_BLOB)) for name in paths}


def clean_env():
    return {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'LANG': 'C',
            'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0', 'GIT_LFS_SKIP_SMUDGE': '1'}


def run_bounded(argv, *, cwd=None, timeout=60, limit=MAX_LISTING, env=None, log_directory=None):
    """Read-only developer-tool calls with bounded pipes and owned cleanup."""
    need(isinstance(argv, list) and argv and all(isinstance(a, str) and '\0' not in a for a in argv), 'command_arguments')
    started = time.monotonic_ns()
    proc = subprocess.Popen(argv, cwd=cwd, env=clean_env() if env is None else env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    sel, chunks = selectors.DefaultSelector(), {'stdout': bytearray(), 'stderr': bytearray()}
    for stream, label in [(proc.stdout, 'stdout'), (proc.stderr, 'stderr')]:
        os.set_blocking(stream.fileno(), False)
        sel.register(stream, selectors.EVENT_READ, label)
    timed_out = limited = False
    try:
        while sel.get_map():
            if time.monotonic_ns() - started > timeout * 1_000_000_000:
                timed_out = True
                break
            for key, _ in sel.select(0.1):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    sel.unregister(key.fileobj)
                else:
                    chunks[key.data].extend(data)
                    if sum(len(v) for v in chunks.values()) > limit:
                        limited = True
                        break
            if limited:
                break
        if timed_out or limited:
            os.killpg(proc.pid, signal.SIGKILL)
        code = proc.wait(timeout=5)
    finally:
        sel.close()
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)
        proc.stdout.close()
        proc.stderr.close()
    result = {'argv': argv, 'exit_code': code, 'timed_out': timed_out, 'output_limit': limited,
              'elapsed_ms': (time.monotonic_ns() - started) // 1_000_000,
              'stdout': bytes(chunks['stdout']), 'stderr': bytes(chunks['stderr'])}
    if log_directory is not None:
        directory = Path(log_directory)
        need(directory.is_dir() and not directory.is_symlink(), 'command_log_directory')
        for stream in ['stdout', 'stderr']:
            with (directory / stream).open('xb') as output:
                output.write(result[stream])
    if timed_out or limited:
        error = Error('command_bound')
        # Failure-only finite facts: consumers must not infer the observed bound
        # from output length or fabricate an exit code when the call raises.
        error.bound_outcome = {key: result[key] for key in ['timed_out', 'output_limit', 'elapsed_ms']}
        raise error
    return result


def validate_bare_repo(cache, path):
    try:
        return _audit.Audit({}, REPO, Path(cache)).validate_repo(path)
    except _audit.Invalid as error:
        raise Error(error.code) from None


def git(repo, *args):
    allowed = {'rev-parse', 'cat-file', 'ls-tree', 'show', 'fsck'}
    need(args and args[0] in allowed, 'git_operation')
    repository = real_directory(repo)
    need(not (repository / 'objects/info/alternates').exists(), 'git_alternates')
    # No ambient configuration, checkout, fetch, hooks, aliases or replacement objects.
    command = ['/usr/bin/git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null',
               '-c', 'protocol.allow=never', '-c', 'submodule.recurse=false',
               '-c', 'gc.auto=0', '--git-dir=' + str(repository), *args]
    result = run_bounded(command)
    need(result['exit_code'] == 0, 'git_read_failed')
    return result['stdout']


def source_tree_name(value):
    """Literal read-only Git names; percent is punctuation, never URL-decoded.

    LLVM includes IR-symbol filenames containing '%'. Such names are accounted
    for only in nonmaterialized trees. Output paths still use strict relative().
    """
    need(isinstance(value, str), 'source_tree_path')
    relative(value.replace('%', '_'))
    return tuple(value.split('/'))


def tree_entries(data, metadata_only=False):
    need(isinstance(data, bytes) and len(data) <= MAX_LISTING and data.endswith(b'\0'), 'listing_shape')
    rows, seen = [], set()
    for item in data[:-1].split(b'\0'):
        try:
            metadata, rawpath = item.split(b'\t', 1)
            mode, kind, blob = metadata.decode('ascii').split(' ')
            path = rawpath.decode('utf-8')
        except (ValueError, UnicodeError):
            raise Error('listing_shape') from None
        source_tree_name(path) if metadata_only else relative(path)
        need(path not in seen and len(seen) < MAX_ENTRIES, 'listing_duplicate_or_limit')
        need((mode in ['100644', '100755'] and kind == 'blob') or (mode == '160000' and kind == 'commit')
             or (metadata_only and mode == '120000' and kind == 'blob'),
             'unsupported_tree_entry')
        need(hex_digest(blob, 40), 'git_object_identity')
        seen.add(path)
        rows.append({'path': path, 'mode': mode, 'kind': kind, 'git_object': blob})
    return rows


def resolve_contained(root, value):
    """Allow pinned tool symlinks only inside the explicitly selected cache root."""
    root = real_directory(root)
    relative(value)
    path = root / value
    need(path.exists() and path.resolve().is_relative_to(root), 'tool_link_escape_or_missing')
    resolved = path.resolve()
    need(resolved.is_file(), 'tool_not_file')
    return resolved


def macho_slices(path):
    """Header-only actual host-slice inventory, never an execution claim."""
    with Path(path).open('rb') as stream:
        data = stream.read(4096)
    need(len(data) >= 8, 'macho_header')
    if data[:4] == b'\xcf\xfa\xed\xfe':
        need(len(data) >= 32, 'macho_header')
        return [struct.unpack_from('<I', data, 4)[0]]
    need(data[:4] in [b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'], 'macho_header')
    stride = 32 if data[3] == 0xbf else 20
    count = struct.unpack_from('>I', data, 4)[0]
    need(0 < count <= 32 and 8 + count * stride <= len(data), 'macho_fat_header')
    size = Path(path).stat().st_size
    slices = []
    for n in range(count):
        at = 8 + stride * n
        cpu = struct.unpack_from('>I', data, at)[0]
        start, length = struct.unpack_from('>QQ' if stride == 32 else '>II', data, at + 8)
        need(start >= 8 + count * stride and length >= 32 and start + length <= size, 'macho_slice_bounds')
        with Path(path).open('rb') as stream:
            stream.seek(start)
            header = stream.read(32)
        need(header[:4] == b'\xcf\xfa\xed\xfe' and struct.unpack_from('<I', header, 4)[0] == cpu,
             'macho_slice_header')
        slices.append(cpu)
    need(len(set(slices)) == len(slices), 'macho_duplicate_slice')
    return slices


def validate_ec_archive_index(entries):
    """Validate LLVM's /<ECSYMBOLS>/ index as metadata, never a COFF object.

    Reuse decision: bounded byte-format interpretation of pinned LLVM23
    ArchiveWriter.cpp writeECSymbols and Archive.cpp ec_symbols/getMember.
    Indices are 1-based into the second COFF linker member's offset table.
    """
    ec = [body for _,name,body in entries if name=='/<ECSYMBOLS>/']
    if not ec:
        return None
    symbols = [body for _,name,body in entries if name=='/']
    need(len(ec)==1 and len(symbols)==2, 'ec_index_linker_members')
    second = symbols[1]
    need(len(second)>=8, 'ec_linker_table_bounds')
    count = struct.unpack_from('<I',second)[0]
    end = 4+count*4
    need(0<count<=65535 and end+4<=len(second), 'ec_linker_table_bounds')
    offsets = struct.unpack_from('<'+'I'*count,second,4)
    regular = {offset for offset,name,_ in entries if name not in ('/','//','/SYM64/','/<ECSYMBOLS>/')}
    need(len(set(offsets))==count and all(offset in regular for offset in offsets), 'ec_linker_member_reference')
    def names_and_indices(body,start,number):
        end = start+number*2
        need(0<number<=1000000 and end<=len(body), 'ec_symbol_index_bounds')
        indices = struct.unpack_from('<'+'H'*number,body,start)
        need(all(1<=index<=count for index in indices), 'ec_symbol_member_reference')
        cursor = end; names = []
        for _ in range(number):
            nul = body.find(b'\0',cursor)
            need(nul>cursor, 'ec_symbol_string_bounds')
            names.append(body[cursor:nul]);cursor=nul+1
        need(body[cursor:] in (b'',b'\0') and names==sorted(set(names)), 'ec_symbol_string_table')
        return number
    number=struct.unpack_from('<I',second,end)[0]
    names_and_indices(second,end+4,number)
    need(len(ec[0])>=4, 'ec_symbol_index_bounds')
    ec_count=struct.unpack_from('<I',ec[0])[0]
    names_and_indices(ec[0],4,ec_count)
    return {'symbol_count':ec_count,'indexed_members':count}


def archive_machines(data):
    """Inspect COFF archive members/import headers without a linker or guest load."""
    need(data[:8] == b'!<arch>\n' and len(data) <= 64 * 1024 * 1024, 'coff_archive')
    at, machines, count, entries = 8, set(), 0, []
    while at < len(data):
        need(at + 60 <= len(data) and data[at + 58:at + 60] == b'`\n', 'archive_header')
        name = data[at:at + 16].decode('ascii').strip()
        try:
            size = int(data[at + 48:at + 58].decode('ascii').strip())
        except ValueError:
            raise Error('archive_member_size') from None
        start = at + 60
        need(0 <= size <= len(data) - start and count < 65536, 'archive_member_bounds')
        body = data[start:start + size]
        entries.append((at,name,body))
        if name not in ['/', '//', '/SYM64/','/<ECSYMBOLS>/']:
            if body[:4] == b'\0\0\xff\xff':
                need(len(body) >= 20, 'coff_import_header')
                machine = struct.unpack_from('<H', body, 6)[0]
            else:
                need(len(body) >= 20, 'coff_header')
                machine = struct.unpack_from('<H', body)[0]
            need(machine in [0xaa64, 0xa641, 0x8664, 0x14c], 'coff_machine')
            machines.add(machine)
        at = start + size + (size & 1)
        count += 1
    need(at == len(data) and machines, 'archive_empty_or_truncated')
    validate_ec_archive_index(entries)
    return sorted(machines)

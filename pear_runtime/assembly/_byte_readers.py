# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Original ARM64 Mach-O reader with selected-profile dependency path admission."""
from pathlib import Path
import struct
import unicodedata
from ._common import need, sha256
MACH_ARM64 = 0x100000C

def inspect_macho(path):
    """Read the ARM64 slice and its load commands without executing the file."""
    path = Path(path)
    need(path.stat().st_size <= 1024**3, "macho_size_limit")
    data = path.read_bytes()
    need(len(data) >= 8, "truncated_macho")
    offset = 0
    size = len(data)
    architectures = []
    magic = data[:4]
    if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        count = struct.unpack_from(">I", data, 4)[0]
        stride = 32 if magic[-1] == 0xBF else 20
        need(0 < count <= 32 and 8 + count * stride <= len(data), "invalid_fat_header")
        selected = None
        for index in range(count):
            at = 8 + index * stride
            cpu = struct.unpack_from(">I", data, at)[0]
            if stride == 32:
                start, length = struct.unpack_from(">QQ", data, at + 8)
            else:
                start, length = struct.unpack_from(">II", data, at + 8)
            need(start >= 8 + count * stride and start + length <= len(data), "invalid_fat_slice")
            architectures.append(cpu)
            if cpu == MACH_ARM64:
                need(selected is None, "ambiguous_arm64_slice")
                selected = (start, length)
        need(selected is not None, "missing_arm64_slice")
        offset, size = selected
    else:
        need(magic == b"\xcf\xfa\xed\xfe", "not_macho64")
        architectures.append(struct.unpack_from("<I", data, 4)[0])
    need(size >= 32 and data[offset:offset + 4] == b"\xcf\xfa\xed\xfe", "not_arm64_macho64")
    cpu, subtype, filetype, count, command_bytes = struct.unpack_from("<IIIII", data, offset + 4)
    need(cpu == MACH_ARM64 and count <= 65536 and 32 + command_bytes <= size, "invalid_arm64_commands")
    dependencies, rpaths = [], []
    at = offset + 32
    end = at + command_bytes
    for _ in range(count):
        need(at + 8 <= end, "truncated_load_command")
        cmd, length = struct.unpack_from("<II", data, at)
        need(length >= 8 and at + length <= end, "invalid_load_command")
        if cmd in (0xC, 0x18, 0x80000018, 0x1F, 0x8000001F, 0x20, 0x23, 0x80000023, 0x8000001C):
            need(length >= 12, "invalid_load_string")
            start = struct.unpack_from("<I", data, at + 8)[0]
            need(12 <= start < length, "invalid_load_string")
            raw = data[at + start:at + length]
            need(b"\0" in raw, "unterminated_load_string")
            text = raw.split(b"\0", 1)[0].decode("utf-8", errors="strict")
            (rpaths if cmd == 0x8000001C else dependencies).append(text)
        at += length
    need(at == end, "load_command_size_mismatch")
    return {"architectures": architectures, "selected_cpu": cpu, "subtype": subtype,
            "filetype": filetype, "dependencies": dependencies, "rpaths": rpaths}


def _raw_path_parts(value, *, rpath=False):
    """Admit raw components before normalization or system classification."""
    need(type(value) is str and value and "\\" not in value and
         not any(unicodedata.category(c) == "Cc" for c in value) and
         not value.startswith("//"), "macho_raw_path")
    # One trailing separator and bounded anchored parents preserve selected Wine.
    text = value[:-1] if rpath and value.endswith("/") else value
    absolute = text.startswith("/")
    parts = text[1:].split("/") if absolute else text.split("/")
    need(parts and all(p not in ("", ".") for p in parts), "macho_raw_components")
    anchors = ("@loader_path", "@executable_path")
    tokens = (*anchors, "@rpath")
    if absolute:
        need(".." not in parts and not any(token in p for p in parts for token in tokens),
             "macho_absolute_components")
    else:
        need(parts[0] in (anchors if rpath else tokens), "macho_leading_anchor")
        need(not any(token in p for p in parts[1:] for token in tokens), "macho_mid_token")
        if not rpath:
            need(".." not in parts, "macho_load_components")
    return absolute, parts


def _anchor_base(token, current, executable):
    return current.parent if token == "@loader_path" else executable.parent


def _bounded_native_path(path, bundle, *, directory=False):
    # Existing in-bundle aliases are bound separately by the complete inventory.
    # Broken aliases are failures, including when another rpath has a valid file.
    path = Path(path)
    need(path.exists(), "macho_path_missing")
    target = path.resolve(strict=True)
    need(target.is_relative_to(bundle), "macho_path_outside_bundle")
    need(target.is_dir() if directory else target.is_file(), "macho_path_kind")
    return target


def _admit_rpath(value, current, executable, bundle):
    absolute, parts = _raw_path_parts(value, rpath=True)
    candidate = (Path(value[:-1] if value.endswith("/") else value) if absolute else
                 _anchor_base(parts[0], current, executable).joinpath(*parts[1:]))
    # The selected profile requires existing directories, even for unused paths.
    return _bounded_native_path(candidate, bundle, directory=True)


def _admit_load(value, current, executable, bundle, paths):
    absolute, parts = _raw_path_parts(value)
    if absolute and value.startswith(("/usr/lib/", "/System/Library/")):
        return {"name": value, "kind": "macos_system_dependency"}, None
    if absolute:
        candidates = [Path(value)]
    elif parts[0] == "@rpath":
        need(len(parts) > 1, "macho_load_suffix")
        candidates = [p.joinpath(*parts[1:]) for p in paths]
    else:
        need(len(parts) > 1, "macho_load_suffix")
        candidates = [_anchor_base(parts[0], current, executable).joinpath(*parts[1:])]
    hits = set()
    for candidate in candidates:
        # A missing leaf must not hide a broken/external intermediate alias.
        need(candidate.resolve().is_relative_to(bundle), "macho_path_outside_bundle")
        for component in (candidate, *candidate.parents):
            if component.is_symlink():
                need(component.exists(), "macho_path_missing")
                need(component.resolve(strict=True).is_relative_to(bundle),
                     "macho_path_outside_bundle")
        if candidate.exists():
            hits.add(_bounded_native_path(candidate, bundle))
    need(len(hits) == 1, "unresolved_or_ambiguous_dependency")
    target = hits.pop()
    return {"name": value, "kind": "bundled", "path": str(target)}, target


def inspect_closure(path, root):
    """Resolve admitted bundled paths; canonical OS names remain external."""
    root, executable = Path(root).resolve(), Path(path).resolve()
    need(executable.is_relative_to(root), "tool_outside_bundle")
    found, pending = {}, [(executable, [])]
    while pending:
        current, inherited_rpaths = pending.pop()
        if str(current) in found:
            continue
        need(current.is_relative_to(root), "dependency_outside_bundle")
        info = inspect_macho(current)
        expanded = [_admit_rpath(item, current, executable, root) for item in info["rpaths"]]
        paths = expanded + inherited_rpaths
        resolved = []
        for dep in info["dependencies"]:
            row, target = _admit_load(dep, current, executable, root, paths)
            resolved.append(row)
            if target is not None:
                pending.append((target, paths))
        found[str(current)] = {"path": str(current), "sha256": sha256(current),
                               **info, "resolved_dependencies": resolved}
    return list(found.values())

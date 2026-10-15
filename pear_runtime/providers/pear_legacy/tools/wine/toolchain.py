#!/usr/bin/env python3
"""Prepare and qualify bounded native/PE build tools, never a Wine runtime."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import time

from common import Error, encoded, load_json, need, record, relative, sha256
from prepare import verify_prepared

REPO = Path(__file__).resolve().parents[2]
MACH_ARM64 = 0x100000C
MAX_ARCHIVE_MTIME = (2**63 - 1) // 1_000_000_000
TARGETS = {"aarch64": ("arm64", 0xAA64), "arm64ec": ("arm64ec", 0xA641),
           "x86_64": ("x64", 0x8664), "i686": ("x86", 0x14C)}
FRAMEWORKS = ["AppKit", "Carbon", "Foundation", "IOKit", "Metal", "OpenGL",
              "QuartzCore", "Security", "CoreText", "CoreFoundation", "CoreServices",
              "DiskArbitration", "SystemConfiguration", "ApplicationServices"]


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(encoded(value))


def task_path(path):
    path = Path(path).absolute()
    root = (REPO / ".build/task4").resolve()
    need(path.resolve().is_relative_to(root), "outside_task_root")
    return path


def empty_directory(path):
    path = task_path(path)
    need(not path.exists() and not path.is_symlink(), "destination_exists")
    path.mkdir(parents=True)
    return path


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


def inspect_closure(path, root):
    """Resolve bundled libraries; OS shared-cache dependencies are explicit inputs."""
    root, executable = Path(root).resolve(), Path(path).resolve()
    need(executable.is_relative_to(root), "tool_outside_bundle")
    found, pending = {}, [(executable, [])]
    while pending:
        current, inherited_rpaths = pending.pop()
        if str(current) in found:
            continue
        need(current.is_relative_to(root), "dependency_outside_bundle")
        info = inspect_macho(current)
        expanded = []
        for item in info["rpaths"]:
            expanded.append(item.replace("@loader_path", str(current.parent)).replace(
                "@executable_path", str(executable.parent)))
        paths = expanded + inherited_rpaths
        resolved = []
        for dep in info["dependencies"]:
            if dep.startswith(("/usr/lib/", "/System/Library/")):
                resolved.append({"name": dep, "kind": "macos_system_dependency"})
                continue
            name = dep.replace("@loader_path", str(current.parent)).replace(
                "@executable_path", str(executable.parent))
            candidates = [Path(name)]
            if name.startswith("@rpath/"):
                candidates = [Path(base) / name[7:] for base in paths]
            hits = {p.resolve() for p in candidates if p.is_file()}
            need(len(hits) == 1, "unresolved_or_ambiguous_dependency")
            target = hits.pop()
            need(target.is_relative_to(root), "dependency_outside_bundle")
            resolved.append({"name": dep, "kind": "bundled", "path": str(target)})
            pending.append((target, paths))
        found[str(current)] = {"path": str(current), "sha256": sha256(current),
                               **info, "resolved_dependencies": resolved}
    return list(found.values())


def archive_members(archive, expected_root, max_bytes):
    """Validate the complete member graph before writing any extracted member."""
    need(isinstance(max_bytes, int) and 0 < max_bytes <= 4 * 1024**3, "invalid_archive_budget")
    result, names, links, total = [], set(), {}, 0
    for member in archive.getmembers():
        name = member.name.rstrip("/")
        parts = relative(name)
        need(parts[0] == expected_root, "archive_root_mismatch")
        if len(parts) == 1:
            need(member.isdir(), "invalid_archive_root")
            continue
        rel = "/".join(parts[1:])
        need(rel not in names, "duplicate_archive_member")
        names.add(rel)
        need(member.isfile() or member.isdir() or member.issym() or member.islnk(), "special_archive_member")
        if member.isfile():
            # The locked releases use whole seconds; bound signed-64-bit nanoseconds.
            need(type(member.mtime) is int and 0 <= member.mtime <= MAX_ARCHIVE_MTIME,
                 "invalid_archive_mtime")
            total += member.size
            need(member.size >= 0 and total <= max_bytes, "archive_expansion_limit")
        if member.issym():
            target = member.linkname
            need(target and not target.startswith("/") and "\\" not in target, "unsafe_archive_link")
            dest = posixpath.normpath(posixpath.join(posixpath.dirname(rel), target))
            relative(dest)
            links[rel] = dest
        elif member.islnk():
            target_parts = relative(member.linkname)
            need(target_parts[0] == expected_root and len(target_parts) > 1, "unsafe_archive_hardlink")
            links[rel] = "/".join(target_parts[1:])
        result.append((member, rel))
    for _, rel in result:
        for parent in PurePosixPath(rel).parents:
            need(str(parent) not in links, "archive_link_parent")
    for origin, target in links.items():
        visited = {origin}
        while target in links:
            need(target not in visited, "archive_link_cycle")
            visited.add(target)
            target = links[target]
        need(target in names, "archive_dangling_link")
    return result, total


def extract_verified(spec, destination):
    source = REPO.joinpath(*relative(spec["download_path"]))
    need(source.resolve().is_relative_to((REPO / ".build/task4").resolve()), "download_outside_task")
    need(source.is_file() and source.stat().st_size == spec["size_bytes"], "artifact_size_mismatch")
    need(sha256(source) == spec["sha256"], "artifact_digest_mismatch")
    need(spec["format"] in ("tar.xz", "tar.gz"), "unsupported_archive")
    need(not destination.exists() and not destination.is_symlink(), "destination_exists")
    with tarfile.open(source, "r:*") as archive:
        members, total = archive_members(archive, spec["archive_root"], spec["max_unpacked_bytes"])
        need(shutil.disk_usage(destination.parent).free >= total + 512 * 1024**2, "insufficient_extraction_space")
        destination.mkdir()
        files = []
        for member, rel in members:
            path = destination.joinpath(*relative(rel))
            path.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                path.mkdir(exist_ok=True)
            elif member.isfile():
                with archive.extractfile(member) as inp, path.open("xb") as out:
                    shutil.copyfileobj(inp, out, 1024 * 1024)
                path.chmod(0o755 if member.mode & 0o111 else 0o644)
                # Preserve release ordering instead of triggering maintainer regeneration.
                stamp = member.mtime * 1_000_000_000
                os.utime(path, ns=(stamp, stamp), follow_symlinks=False)
                need(path.stat().st_mtime_ns == stamp, "archive_mtime_not_preserved")
                files.append({"path": rel, "sha256": sha256(path), "size_bytes": member.size})
        for member, rel in members:
            path = destination.joinpath(*relative(rel))
            if member.issym():
                path.symlink_to(member.linkname)
                files.append({"path": rel, "symlink": member.linkname})
            elif member.islnk():
                target = destination.joinpath(*relative(member.linkname)[1:])
                need(target.is_file() and not target.is_symlink(), "invalid_hardlink_target")
                os.link(target, path)
                files.append({"path": rel, "sha256": sha256(path), "size_bytes": path.stat().st_size})
    notices = []
    for notice in spec.get("notice_files", []):
        path = destination.joinpath(*relative(notice["path"]))
        need(path.stat().st_size == notice["size_bytes"] and sha256(path) == notice["sha256"], "notice_identity_mismatch")
        notices.append({"path": str(path), **notice})
    manifest = destination.parent / (spec["id"] + "-files.json")
    write_new(manifest, {"schema_version": 1, "record_kind": "wine_tool_files", "files": files})
    return {"id": spec["id"], "archive_sha256": spec["sha256"], "members": len(members),
            "unpacked_regular_bytes": total, "path": str(destination), "notices": notices,
            "files_manifest": {"path": str(manifest), "sha256": sha256(manifest)}}


def alias_directory(target):
    target = task_path(target).resolve()
    holder = Path(tempfile.mkdtemp(prefix="pear-task4-", dir="/private/tmp"))
    alias = holder / "workspace"
    alias.symlink_to(target, target_is_directory=True)
    need(holder.stat().st_uid == os.getuid() and alias.resolve() == target, "invalid_owned_alias")
    return alias


def verify_extracted(spec, artifact, tools):
    """Bind mutable extraction evidence to the locked archive before execution."""
    root = Path(artifact["path"])
    need(root == tools / spec["install_subdir"] and not root.is_symlink(), "prepared_tool_root_mismatch")
    source = REPO.joinpath(*relative(spec["download_path"]))
    need(source.stat().st_size == spec["size_bytes"] and sha256(source) == spec["sha256"], "artifact_identity_mismatch")
    expected = set()
    with tarfile.open(source, "r:*") as archive:
        members, _ = archive_members(archive, spec["archive_root"], spec["max_unpacked_bytes"])
        for member, rel in members:
            path = root.joinpath(*relative(rel))
            if member.isdir():
                need(path.is_dir() and not path.is_symlink(), "prepared_tool_directory_changed")
                continue
            expected.add(rel)
            if member.issym():
                need(path.is_symlink() and os.readlink(path) == member.linkname, "prepared_tool_link_changed")
            else:
                digest = hashlib.sha256()
                with archive.extractfile(member) as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                need(path.is_file() and not path.is_symlink() and sha256(path) == digest.hexdigest(), "prepared_tool_archive_mismatch")
    observed = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in files + [name for name in dirs if (Path(directory) / name).is_symlink()]:
            observed.add((Path(directory) / name).relative_to(root).as_posix())
    need(observed == expected, "prepared_tool_inventory_mismatch")


def base_env(sdk, extra_path=()):
    env = {key: os.environ[key] for key in ("HOME", "USER", "LOGNAME", "TMPDIR") if key in os.environ}
    env.update({"PATH": os.pathsep.join([*(str(p) for p in extra_path), "/usr/bin", "/bin", "/usr/sbin", "/sbin"]),
                "LC_ALL": "C", "LANG": "C", "SDKROOT": str(sdk),
                "PKG_CONFIG_PATH": "", "PKG_CONFIG_LIBDIR": "/nonexistent/pear-task4"})
    return env


def verify_prepared_tools(lock, tools):
    """Revalidate source archives, extracted inventory, and local build evidence."""
    tools = task_path(tools).resolve()
    prepared = record(load_json(tools / "prepared.json"), "wine_toolchain_prepared")
    need(prepared["passed"] is True, "prepared_tools_failed")
    need(len(prepared["artifacts"]) == len(lock["artifacts"]), "prepared_artifact_count_mismatch")
    need(len({item["id"] for item in prepared["artifacts"]}) == len(lock["artifacts"]), "duplicate_prepared_artifact")
    for artifact in prepared["artifacts"]:
        specs = [spec for spec in lock["artifacts"] if spec["id"] == artifact["id"]]
        need(len(specs) == 1, "prepared_artifact_identity_mismatch")
        verify_extracted(specs[0], artifact, tools)
        manifest = Path(artifact["files_manifest"]["path"])
        need(manifest.resolve().is_relative_to(tools) and sha256(manifest) == artifact["files_manifest"]["sha256"], "prepared_tool_manifest_mismatch")
        rows = record(load_json(manifest), "wine_tool_files")["files"]
        for row in rows:
            path = Path(artifact["path"]).joinpath(*relative(row["path"]))
            if "symlink" in row:
                need(path.is_symlink() and os.readlink(path) == row["symlink"], "prepared_tool_link_changed")
            else:
                need(path.stat().st_size == row["size_bytes"] and sha256(path) == row["sha256"], "prepared_tool_file_changed")
    bison = tools / "bison/bin/bison"
    need(prepared["bison"]["sha256"] == sha256(bison), "derived_bison_digest_mismatch")
    need(inspect_macho(bison)["architectures"] == [MACH_ARM64], "bison_not_native_arm64")
    for command in prepared["commands"]:
        need(command["exit_code"] == 0 and not command["timed_out"] and not command["output_limit"], "bison_build_not_passed")
        for stream in ("stdout_log", "stderr_log"):
            log = Path(command[stream]["path"])
            need(log.resolve().is_relative_to(tools) and sha256(log.resolve()) == command[stream]["sha256"], "bison_log_mismatch")
    return prepared


def run_command(commands, ident, argv, cwd, env, timeout=120):
    """Bound output on disk and stop only the newly owned process group."""
    argv = [str(x) for x in argv]
    if sys.platform == "darwin":
        with Path(argv[0]).open("rb") as executable:
            is_script = executable.read(2) == b"#!"
        if is_script:
            argv = ["/bin/sh", *argv]
        argv = ["/usr/bin/arch", "-arm64", *argv]
    entry = {"id": ident, "argv": argv, "cwd": str(cwd)}
    commands.append(entry)
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        started = time.monotonic()
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err, start_new_session=True)
        timed_out = output_limit = False
        while process.poll() is None:
            timed_out = time.monotonic() - started > timeout
            output_limit = max(os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size) > 256 * 1024
            if timed_out or output_limit:
                os.killpg(process.pid, signal.SIGKILL)
                break
            time.sleep(0.05)
        code = process.wait(timeout=5)
        output_limit = output_limit or max(os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size) > 256 * 1024
        out.seek(0)
        err.seek(0)
        entry.update(exit_code=code, timed_out=timed_out, output_limit=output_limit,
                     elapsed_ms=round((time.monotonic() - started) * 1000))
        logs = Path(cwd) / ".pear-command-logs"
        logs.mkdir(exist_ok=True)
        for name, stream in (("stdout", out), ("stderr", err)):
            data = stream.read(256 * 1024)
            log = logs / (ident + "." + name)
            with log.open("xb") as target:
                target.write(data)
            entry[name] = data[:16000].decode("utf-8", errors="replace")
            entry[name + "_preview_truncated"] = len(data) > 16000
            entry[name + "_log"] = {"path": str(log), "sha256": sha256(log), "size_bytes": len(data)}
    need(code == 0 and not timed_out and not output_limit, "command_failed:" + ident)
    return entry


def native_tool(lock, ident):
    rows = [x for x in lock["native_tools"] if x["id"] == ident]
    need(len(rows) == 1, "missing_or_duplicate_native_tool:" + ident)
    path = Path(rows[0]["path"])
    need(path.is_absolute() and path.is_file(), "missing_native_tool:" + ident)
    need(sha256(path.resolve()) == rows[0]["sha256"], "native_tool_digest_mismatch:" + ident)
    inspect_macho(path)
    return path


def inspect_sdk(lock):
    path = Path(lock["sdk"]["path"])
    need(path.is_absolute() and path.is_dir(), "missing_sdk")
    settings = path.resolve() / "SDKSettings.json"
    data = load_json(settings)
    need(data["Version"] == lock["sdk"]["version"], "sdk_version_mismatch")
    need(data["CanonicalName"] == "macosx" + data["Version"], "sdk_platform_mismatch")
    return {"path": str(path), "resolved_path": str(path.resolve()),
            "settings_sha256": sha256(settings), "version": data["Version"],
            "canonical_name": data["CanonicalName"]}


def prepare(lock_path, output):
    lock = record(load_json(lock_path), "wine_toolchain")
    output = empty_directory(output)
    data = {"schema_version": 1, "record_kind": "wine_toolchain_prepared",
            "lock_sha256": sha256(lock_path), "artifacts": [], "commands": []}
    try:
        for spec in lock["artifacts"]:
            subdir = relative(spec["install_subdir"])
            need(len(subdir) == 1, "invalid_install_subdir")
            data["artifacts"].append(extract_verified(spec, output / subdir[0]))
        data["notices"] = []
        for artifact in data["artifacts"]:
            for path in sorted(Path(artifact["path"]).iterdir()):
                if path.is_file() and (path.name.upper().startswith(("COPYING", "LICENSE", "NOTICE")) or path.name == "versions.txt"):
                    data["notices"].append({"artifact": artifact["id"], "path": str(path), "sha256": sha256(path), "size_bytes": path.stat().st_size})
        bison = [x for x in lock["artifacts"] if x["id"] == "bison-source"]
        if bison:
            need(len(bison) == 1, "duplicate_bison_recipe")
            need(bison[0].get("recipe") == "gnu-bison-3.8.2-v1" and bison[0]["sha256"] == "9bba0214ccf7f1079c5d59210045227bcf619519840ebfa80cd3849cff5a5bf2", "unreviewed_bison_recipe")
            alias = alias_directory(output)
            data["alias"] = {"invoked": str(alias), "resolved": str(output.resolve())}
            build = output / "bison-build"
            build.mkdir()
            sdk = lock["sdk"]["path"]
            cc, make, m4 = (native_tool(lock, x) for x in ("clang", "make", "m4"))
            source = alias / bison[0]["install_subdir"]
            env = base_env(sdk)
            env.update(CC=str(cc), M4=str(m4), CFLAGS="-arch arm64 -isysroot " + str(sdk),
                       PWD=str(alias / "bison-build"))
            argv = [source / "configure", "--prefix=" + str(alias / "bison"), "--disable-nls", "--enable-relocatable"]
            run_command(data["commands"], "bison.configure", argv, alias / "bison-build", env, 240)
            run_command(data["commands"], "bison.build", [make, "-j4"], alias / "bison-build", env, 600)
            run_command(data["commands"], "bison.install", [make, "install"], alias / "bison-build", env, 120)
            executable = output / "bison/bin/bison"
            data["bison"] = {"path": str(executable), "sha256": sha256(executable), **inspect_macho(executable)}
        data["passed"] = True
        write_new(output / "prepared.json", data)
        return 0
    except (Error, OSError, ValueError, KeyError) as exc:
        data.update(passed=False, error=getattr(exc, "code", type(exc).__name__ + ":" + str(exc)))
        write_new(output / "prepare-failed.json", data)
        raise


def coff_machine(path):
    data = Path(path).read_bytes()
    need(len(data) >= 20, "truncated_coff")
    at = 0
    if data[:2] == b"MZ":
        need(len(data) >= 64, "truncated_dos_header")
        at = struct.unpack_from("<I", data, 60)[0]
        need(at + 24 <= len(data) and data[at:at + 4] == b"PE\0\0", "invalid_pe_header")
        at += 4
    return struct.unpack_from("<H", data, at)[0]


def inspect_host(output):
    result = {"schema_version": 1, "record_kind": "wine_toolchain_inspection", "tools": []}
    for ident in ("clang", "clang++", "make", "bison", "flex", "m4", "autoconf", "pkg-config", "cmake", "ninja", "lld", "llvm-dlltool"):
        path = shutil.which(ident)
        result["tools"].append({"id": ident, "path": path,
                                "sha256": sha256(Path(path).resolve()) if path else None,
                                "status": "found_unqualified" if path else "not_found_on_path"})
    write_new(task_path(output), result)
    return 0


def check(lock_path, tools, fixtures, output, inputs=None, config_path=None):
    lock = record(load_json(lock_path), "wine_toolchain")
    tools = task_path(tools).resolve()
    output = task_path(output)
    need(not output.exists(), "destination_exists")
    prepared = record(load_json(tools / "prepared.json"), "wine_toolchain_prepared")
    need(prepared["passed"] is True and prepared["lock_sha256"] == sha256(lock_path), "prepared_identity_mismatch")
    work = empty_directory(output.with_suffix(".work"))
    fixtures = Path(fixtures).resolve()
    config = load_json(config_path) if config_path else None
    result = {"schema_version": 1, "record_kind": "wine_toolchain_check", "lock_sha256": sha256(lock_path),
              "producer_sha256": {name: sha256(Path(__file__).parent / name) for name in ("toolchain.py", "common.py", "prepare.py")},
              "prepared_sha256": sha256(tools / "prepared.json"),
              "config_sha256": sha256(config_path) if config_path else None,
              "fixture_hashes": {p.name: sha256(p) for p in sorted(fixtures.iterdir()) if p.is_file()},
              "tools": [], "checks": [], "commands": [], "pe_execution": False, "wine_runtime_execution": False}
    commands = result["commands"]
    tc = tools / "llvm-mingw"
    try:
        need(set(lock["fixture_targets"]) == set(TARGETS), "incomplete_target_matrix")
        verify_prepared_tools(lock, tools)
        need(config is not None and inputs is not None, "missing_source_configuration")
        input_root = Path(inputs).resolve()
        source_prepared = verify_prepared(input_root)
        inputs_ref = source_prepared["inputs_ref"]
        component = source_prepared["components"][0]
        source = input_root.joinpath(*relative(component["source_path"]))
        manifest_path = input_root.joinpath(*relative(component["files_manifest"]["path"]))
        result.update(source_prepared_sha256=sha256(input_root / "prepared.json"),
                      source_prepared_path=str(input_root / "prepared.json"), inputs_sha256=inputs_ref["sha256"],
                      source_manifest_sha256=sha256(manifest_path))
        for name in ("clang", "lld-link", "llvm-readobj", "llvm-rc", "llvm-dlltool"):
            invoked = tc / "bin" / name
            result["tools"].append({"id": name, "path": str(invoked), "resolved_path": str(invoked.resolve()),
                                    "sha256": sha256(invoked.resolve()), "closure": inspect_closure(invoked, tc)})
        cc = native_tool(lock, "clang")
        sdk = lock["sdk"]["path"]
        result["sdk"] = inspect_sdk(lock)
        need(config["sdk_version"] == result["sdk"]["version"], "config_sdk_mismatch")
        env = base_env(sdk, [tc / "bin", tools / "bison/bin"])
        if config:
            env["MACOSX_DEPLOYMENT_TARGET"] = config["deployment_target"]
        env["PWD"] = str(work)
        def command(ident, args, timeout=120):
            return run_command(commands, ident, args, work, env, timeout)
        def passed(ident, **details):
            details.setdefault("command_ids", [x["id"] for x in commands if x["id"] == ident or x["id"].startswith(ident + ".")])
            result["checks"].append({"id": ident, "status": "passed", "details": details})
        def artifact(path):
            return {"path": str(path), "sha256": sha256(path), "size_bytes": path.stat().st_size}
        version = command("compiler.version", [tc / "bin/clang", "--version"])
        need(re.search(r"\bclang version 23\.1\.1\b", version["stdout"]) is not None, "compiler_baseline_mismatch")
        result["compiler_version"] = version["stdout"].splitlines()[0]
        native = work / "native"
        command("native.compile", [cc, "-arch", "arm64", "-isysroot", sdk, "-std=c11", "-Wall", "-Wextra", "-Werror", fixtures / "toolchain_native.c", "-o", native])
        info = inspect_macho(native)
        need(info["architectures"] == [MACH_ARM64], "native_not_arm64_only")
        ran = command("native.run", [native])
        need(ran["stdout"] == '{"fixture":"pear-toolchain-native-v1","value":42}\n', "native_fixture_mismatch")
        passed("native", artifact=artifact(native), stdout=ran["stdout"], **info)
        framework_binary = work / "frameworks"
        args = [cc, "-arch", "arm64", "-isysroot", sdk, "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations", fixtures / "toolchain_frameworks.m", "-o", framework_binary]
        frameworks = config["frameworks"] if config else FRAMEWORKS
        for framework in frameworks:
            args += ["-framework", framework]
        command("frameworks.link", args)
        info = inspect_macho(framework_binary)
        for framework in frameworks:
            need(any('/' + framework + '.framework/' in p for p in info["dependencies"]), "framework_dependency_missing:" + framework)
        passed("frameworks", artifact=artifact(framework_binary), executed=False, **info)
        clang, link, readobj = (tc / "bin" / n for n in ("clang", "lld-link", "llvm-readobj"))
        for target, (machine, object_machine) in TARGETS.items():
            out = work / target
            out.mkdir()
            target_args = ["--target=" + target + "-w64-windows-gnu", "-ffreestanding", "-fno-stack-protector"]
            support = []
            if target == "arm64ec":
                support = [tc / "aarch64-w64-mingw32/lib/libmingwex.a"]
            for fixture_source, name, language in [("toolchain_pe.c", "main.obj", "c11"), ("toolchain_dll.c", "dll.obj", "c11"), ("toolchain_cpp.cpp", "cpp.obj", "c++17")]:
                command(target + "." + name, [clang, *target_args, "-std=" + language, "-c", fixtures / fixture_source, "-o", out / name])
                need(coff_machine(out / name) == object_machine, "coff_machine_mismatch:" + target)
            passed(target + ".compile", machine=object_machine, artifacts=[artifact(out / "main.obj"), artifact(out / "dll.obj")], command_ids=[target + ".main.obj", target + ".dll.obj"])
            passed(target + ".cxx", artifact=artifact(out / "cpp.obj"), command_ids=[target + ".cpp.obj"])
            command(target + ".assemble", [clang, *target_args, "-c", fixtures / "toolchain_seh.S", "-o", out / "seh.obj"])
            need(coff_machine(out / "seh.obj") == object_machine, "assembly_machine_mismatch")
            unwind = command(target + ".unwind.inspect", [readobj, "--unwind", out / "seh.obj"])
            if target != "i686":
                need("RuntimeFunction" in unwind["stdout"], "missing_unwind_records:" + target)
            passed(target + (".assembly" if target == "i686" else ".unwind"), artifact=artifact(out / "seh.obj"), output=unwind["stdout"], command_ids=[target + ".assemble", target + ".unwind.inspect"])
            resource = out / "fixture.res"
            command(target + ".resource.compile", [tc / "bin/llvm-rc", "/FO" + str(resource), "--", fixtures / "toolchain_resource.rc"])
            need(resource.stat().st_size > 32, "resource_empty")
            link_mode = ["/lldmingw"] if target == "i686" else []
            command(target + ".dll.link", [link, *link_mode, "/machine:" + machine, "/dll", "/noentry", "/nodefaultlib", "/out:" + str(out / "pear-toolchain.dll"), "/implib:" + str(out / "automatic.lib"), out / "dll.obj", *support])
            dlltool_machine = {"i686": "i386", "x86_64": "i386:x86-64", "aarch64": "arm64", "arm64ec": "arm64ec"}[target]
            command(target + ".importlib", [tc / "bin/llvm-dlltool", "-m", dlltool_machine, "-d", fixtures / "toolchain_dll.def", "-l", out / "fixture.lib"])
            command(target + ".exe.link", [link, *link_mode, "/machine:" + machine, "/entry:pear_toolchain_entry", "/subsystem:console", "/nodefaultlib", "/out:" + str(out / "fixture.exe"), out / "main.obj", out / "fixture.lib", resource, *support])
            expected_pe = 0x8664 if target == "arm64ec" else object_machine
            for name in ("fixture.exe", "pear-toolchain.dll"):
                need(coff_machine(out / name) == expected_pe, "pe_machine_mismatch:" + target)
            passed(target + ".link", pe_machine=expected_pe, artifacts=[artifact(out / "fixture.exe"), artifact(out / "pear-toolchain.dll")], executed=False, command_ids=[target + ".dll.link", target + ".exe.link"])
            if target == "arm64ec":
                metadata = command("arm64ec.support.inspect", [readobj, "--coff-load-config", out / "fixture.exe", out / "pear-toolchain.dll"])
                pointers = re.findall(r"CHPEMetadataPointer: 0x([0-9A-Fa-f]+)", metadata["stdout"])
                need(len(pointers) == 2 and all(int(p, 16) for p in pointers), "missing_arm64ec_load_config")
                passed("arm64ec.support", archive={"path": "aarch64-w64-mingw32/lib/libmingwex.a", "sha256": sha256(support[0]), "size_bytes": support[0].stat().st_size},
                       output=metadata["stdout"], metadata_scope="linked upstream CRT metadata; no guest execution")
            imports = command(target + ".imports.inspect", [readobj, "--coff-imports", out / "fixture.exe"])
            need("pear-toolchain.dll" in imports["stdout"] and "pear_toolchain_add" in imports["stdout"], "missing_fixture_import")
            passed(target + ".imports", artifact=artifact(out / "fixture.lib"), output=imports["stdout"], command_ids=[target + ".importlib", target + ".imports.inspect"])
            exports = command(target + ".exports.inspect", [readobj, "--coff-exports", out / "pear-toolchain.dll"])
            need("pear_toolchain_add" in exports["stdout"], "missing_fixture_export")
            passed(target + ".exports", output=exports["stdout"])
            resources = command(target + ".resources.inspect", [readobj, "--coff-resources", out / "fixture.exe"])
            need("101" in resources["stdout"] and "504541522A00" in "".join(resources["stdout"].upper().split()), "missing_fixture_resource")
            passed(target + ".resources", artifact=artifact(resource), output=resources["stdout"], command_ids=[target + ".resource.compile", target + ".resources.inspect"])
        bison = tools / "bison/bin/bison"
        need(prepared["bison"]["sha256"] == sha256(bison), "derived_bison_digest_mismatch")
        version = command("bison.version", [bison, "--version"])
        need(re.search(r"\b3\.8\.2\b", version["stdout"]) is not None, "unexpected_bison_version")
        passed("bison", sha256=sha256(bison), version=version["stdout"].splitlines()[0])
        if config is not None and inputs is not None:
            need((source / "configure").is_file(), "missing_wine_configure")
            alias = alias_directory(REPO / ".build/task4")
            result["path_alias"] = {"invoked": str(alias), "resolved": str(alias.resolve())}
            def logical(path):
                # Preserve invocation basenames: clang/clang-23 select different configure paths.
                return alias / Path(path).absolute().relative_to(alias.resolve())
            for variant in config["variants"]:
                ident = variant["id"]
                need(ident in ("arm64", "arm64ec-build"), "unsupported_configure_variant")
                build = work / ("configure-" + ident)
                build.mkdir()
                invocation = logical(build)
                configure_env = base_env(sdk, [logical(tc / "bin"), logical(tools / "bison/bin")])
                configure_env.update(CC=str(cc), CXX=str(native_tool(lock, "clang++")),
                                     BISON=str(logical(bison)), FLEX=str(native_tool(lock, "flex")),
                                     CFLAGS="-arch arm64 -isysroot " + sdk,
                                     CXXFLAGS="-arch arm64 -isysroot " + sdk, PWD=str(invocation),
                                     MACOSX_DEPLOYMENT_TARGET=config["deployment_target"])
                args = [logical(source / "configure"), "--prefix=" + str(logical(build / "install")),
                        "--with-mingw=" + str(logical(tc / "bin/clang")), *variant["configure_args"]]
                configured = run_command(commands, "configure." + ident, args, invocation, configure_env, 300)
                need((build / "Makefile").is_file() and (build / "config.log").is_file(), "configure_outputs_missing")
                makefile = (build / "Makefile").read_text()
                observed = {}
                for name in ("HOST_ARCH", "PE_ARCHS", "aarch64_CC", "aarch64_TARGET", "arm64ec_CC", "arm64ec_TARGET", "x86_64_CC", "x86_64_TARGET", "FREETYPE_LIBS", "FONTCONFIG_LIBS", "CORETEXT_LIBS", "APPKIT_LIBS", "COREAUDIO_LIBS"):
                    values = re.findall(r"^" + name + r" = (.*)$", makefile, re.MULTILINE)
                    need(len(values) == 1, "missing_configure_observation:" + name)
                    observed[name] = values[0].strip()
                need(observed["HOST_ARCH"] == "aarch64" and observed["PE_ARCHS"].split() == variant["pe_archs"], "configure_architecture_mismatch")
                need(not observed["FREETYPE_LIBS"] and not observed["FONTCONFIG_LIBS"] and not observed["COREAUDIO_LIBS"], "unexpected_optional_dependency")
                need(observed["APPKIT_LIBS"] == "-framework AppKit" and observed["CORETEXT_LIBS"] == "-framework CoreText", "missing_mac_driver_framework")
                need("dlls/winemac.drv/cocoa_app.o:" in makefile, "missing_mac_driver_rules")
                if ident == "arm64ec-build":
                    need(observed["x86_64_TARGET"] == "x86_64-windows", "missing_arm64ec_auxiliary_compiler")
                # Query make's generated graph, without building any runtime target.
                run_command(commands, "configure." + ident + ".make-query", [native_tool(lock, "make"), "-n", "tools/winebuild/winebuild"], invocation, configure_env, 60)
                diagnostic = Path(configured["stdout_log"]["path"]).read_text()
                passed("configure." + ident, makefile_sha256=sha256(build / "Makefile"), config_log_sha256=sha256(build / "config.log"),
                       observed=observed, notices=[line for line in diagnostic.splitlines() if line.startswith("configure:")],
                       deployment_target=config["deployment_target"], wine_runtime_built=False)
        result["passed"] = True
    except (Error, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        result["passed"] = False
        result["error"] = getattr(exc, "code", type(exc).__name__ + ":" + str(exc))
        result["checks"].append({"id": "failure", "status": "failed", "details": {"error": result["error"]}})
    write_new(output, result)
    return 0 if result["passed"] else 3


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("--output", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--lock", required=True)
    prep.add_argument("--output", required=True)
    prep.add_argument("--require-empty", action="store_true")
    chk = sub.add_parser("check")
    for name in ("lock", "tools", "fixtures", "output", "inputs", "config"):
        chk.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            return inspect_host(args.output)
        if args.command == "prepare":
            return prepare(args.lock, args.output)
        return check(args.lock, args.tools, args.fixtures, args.output, args.inputs, args.config)
    except (Error, OSError, ValueError, KeyError, tarfile.TarError) as exc:
        print(json.dumps({"error": getattr(exc, "code", type(exc).__name__ + ":" + str(exc))}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

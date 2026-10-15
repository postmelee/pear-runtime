#!/usr/bin/env python3
"""Read-only validation of Pear source-audit records and already acquired inputs.

This is an audit consistency/content checker, not a runtime or trust authority.
Only the installed Git executable is invoked; no recorded command is executed.
A cache must not be concurrently mutated during verification. Git's own reads
cannot provide an atomic snapshot of a directory controlled by another writer.
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tarfile
import time
from urllib.parse import urlsplit

MAX_JSON = 8 * 1024 * 1024
MAX_DOCUMENTS = 16
MAX_DEPTH = 48
MAX_NODES = 250000
MAX_COMPONENTS = 256
MAX_FILE = 512 * 1024 * 1024
MAX_GIT_OUTPUT = 128 * 1024 * 1024
MAX_GIT_COMMANDS = 4096
GIT_TIMEOUT = 120
MAX_MEMBERS = 100000
MAX_ARCHIVE_CONTENT = 2 * 1024 * 1024 * 1024
ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,95}\Z")
HEX = {"sha1": re.compile(r"[0-9a-f]{40}\Z"), "sha256": re.compile(r"[0-9a-f]{64}\Z")}
SCOPES = {"git_tree_listing_bytes", "downloaded_archive_bytes", "archive_member_metadata_json_bytes",
          "git_blob_bytes", "patch_file_bytes", "archive_member_bytes", "installed_metadata_bytes"}
TOP_FIELDS = {"schema_version", "record_kind", "issue", "stage", "audit_date", "scope", "audit_complete",
              "decision", "source_ready", "qualification", "input_root", "evidence_document", "identity_rules",
              "proposed_target_roles", "components", "dependencies", "vendored_path_inventory",
              "observed_build_requirements", "unresolved_inputs", "requirements", "handoff", "evidence_documents",
              "evidence_reference_resolution", "source_requirements", "patch_inventory", "candidate_toolchain"}


class Invalid(Exception):
    def __init__(self, code):
        self.code = code


def need(condition, code):
    if not condition:
        raise Invalid(code)


def ident(value):
    need(isinstance(value, str) and ID.fullmatch(value), "invalid_id")
    return value


def oid(value, fmt="sha1"):
    need(fmt in HEX and isinstance(value, str) and HEX[fmt].fullmatch(value), "invalid_object_identity")
    return value


def relative(value):
    need(isinstance(value, str) and 0 < len(value) <= 4096 and "\\" not in value and "\x00" not in value,
         "unsafe_path")
    parts = value.split("/")
    need(not value.startswith("/") and all(p not in ("", ".", "..") for p in parts), "unsafe_path")
    return parts


def public_url(value):
    need(isinstance(value, str), "invalid_source_url")
    u = urlsplit(value)
    need(u.scheme == "https" and u.hostname and not u.username and not u.password
         and not u.query and not u.fragment, "invalid_source_url")


def open_relative(root, value, directory=False):
    """Traverse each component with openat/O_NOFOLLOW; refuse FIFO/device files."""
    parts = relative(value)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for i, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            is_dir = i < len(parts) - 1 or directory
            if is_dir:
                flags |= os.O_DIRECTORY
            new = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = new
            need(stat.S_ISDIR(os.fstat(fd).st_mode) if is_dir else stat.S_ISREG(os.fstat(fd).st_mode),
                 "nonregular_input")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_relative(root, value, limit=MAX_JSON):
    fd = open_relative(root, value)
    with os.fdopen(fd, "rb") as f:
        need(os.fstat(f.fileno()).st_size <= limit, "input_size_limit")
        data = f.read(limit + 1)
        need(len(data) <= limit, "input_size_limit")
        return data


def digest_relative(root, value):
    fd = open_relative(root, value)
    digest, size = hashlib.sha256(), 0
    with os.fdopen(fd, "rb") as f:
        need(os.fstat(f.fileno()).st_size <= MAX_FILE, "input_size_limit")
        while block := f.read(1024 * 1024):
            size += len(block)
            need(size <= MAX_FILE, "input_size_limit")
            digest.update(block)
    return digest.hexdigest(), size


def walk(value):
    pending = [(value, 0)]
    count = 0
    while pending:
        x, depth = pending.pop()
        count += 1
        need(depth <= MAX_DEPTH and count <= MAX_NODES, "json_structure_limit")
        need(not isinstance(x, float) or math.isfinite(x), "nonfinite_json")
        yield x
        if isinstance(x, dict):
            pending.extend((v, depth + 1) for v in x.values())
        elif isinstance(x, list):
            pending.extend((v, depth + 1) for v in x)


def decode_json(data):
    def pairs(items):
        out = {}
        for k, v in items:
            need(k not in out, "duplicate_json_key")
            out[k] = v
        return out
    def nonfinite(_):
        raise Invalid("nonfinite_json")
    need(len(data) <= MAX_JSON, "input_size_limit")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite)
    except (UnicodeError, ValueError, RecursionError):
        raise Invalid("invalid_json") from None
    list(walk(value))
    need(isinstance(value, dict), "invalid_document_shape")
    return value


def check_digest(record, expected_scope=None):
    need(isinstance(record, dict) and record.get("algorithm") == "sha256", "invalid_digest")
    oid(record.get("value"), "sha256")
    need(record.get("scope") in SCOPES, "invalid_digest_scope")
    if expected_scope:
        need(record["scope"] == expected_scope, "invalid_digest_scope")


def bounded_git(git_executable, repo, args):
    """No inherited Git overrides, prompts, helpers, hooks or network fetching."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "DYLD_", "LD_"))}
    env.update({"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
                "GIT_OPTIONAL_LOCKS": "0", "GIT_ATTR_NOSYSTEM": "1", "LC_ALL": "C"})
    argv = [git_executable, "--no-pager", "--no-optional-locks", "-C", str(repo),
            "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
            "-c", "protocol.allow=never", "-c", "submodule.recurse=false", "-c", "gc.auto=0", *args]
    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env=env, start_new_session=True) as child:
        output, deadline = bytearray(), time.monotonic() + GIT_TIMEOUT
        with selectors.DefaultSelector() as sel:
            sel.register(child.stdout, selectors.EVENT_READ)
            try:
                while sel.get_map():
                    need(time.monotonic() < deadline, "git_timeout")
                    for key, _ in sel.select(min(0.25, max(0, deadline - time.monotonic()))):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            sel.unregister(key.fileobj)
                        else:
                            output.extend(chunk)
                            need(len(output) <= MAX_GIT_OUTPUT, "git_output_limit")
                code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
                need(code == 0, "git_verification_failed")
            except BaseException:
                if child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except (PermissionError, ProcessLookupError):
                        # Some macOS sandboxes permit signaling the owned child
                        # but deny group signaling. Reap that child explicitly.
                        try:
                            child.kill()
                        except ProcessLookupError:
                            pass
                child.wait()
                raise
    return bytes(output)


class Audit:
    def __init__(self, manifest, repo_root, cache_root):
        self.m, self.repo_root, self.cache = manifest, repo_root, cache_root
        self.components, self.evidence, self.documents, self.git_repos, self.trees = {}, {}, [], {}, {}
        self.git_executable = shutil.which("git")
        self.active = None
        self.checks = {"components": 0, "acquired_git": 0, "acquired_archives": 0, "content_digests": 0,
                       "source_blobs": 0, "archive_members": 0, "gitlinks": 0, "patches": 0,
                       "evidence_definitions": 0, "git_commands": 0}

    def git(self, cid, *args):
        self.checks["git_commands"] += 1
        need(self.checks["git_commands"] <= MAX_GIT_COMMANDS, "git_command_limit")
        return bounded_git(self.git_executable, self.git_repos[cid], args)

    def register_ids(self, rows, key):
        need(isinstance(rows, list) and len(rows) <= MAX_NODES, "invalid_record_list")
        found = {}
        for row in rows:
            need(isinstance(row, dict), "invalid_record_shape")
            name = ident(row.get(key))
            need(name not in found, "duplicate_id")
            found[name] = row
        return found

    def references(self):
        docs = self.m.get("evidence_documents")
        need(isinstance(docs, list) and 0 < len(docs) <= MAX_DOCUMENTS and len(docs) == len(set(docs)),
             "invalid_evidence_documents")
        need(self.m.get("evidence_document") in docs, "missing_primary_evidence")
        legacy = set()
        for name in docs:
            doc = decode_json(read_relative(self.repo_root, name))
            self.documents.append(doc)
            need(type(doc.get("schema_version")) is int and doc["schema_version"] == 1
                 and type(doc.get("issue")) is int and doc["issue"] == self.m["issue"], "evidence_identity_mismatch")
            if name == self.m["evidence_document"]:
                legacy = set(doc)
            for row in walk(doc):
                if isinstance(row, dict) and "evidence_id" in row and set(row) - {"evidence_id", "lines"}:
                    key = ident(row["evidence_id"])
                    need(key not in self.evidence, "duplicate_evidence_id")
                    self.evidence[key] = row
        need(not (legacy & set(self.evidence)), "ambiguous_evidence_id")
        for root in [self.m, *self.documents]:
            for row in walk(root):
                if not isinstance(row, dict):
                    continue
                for field in ("size_bytes", "line_count", "tracked_entries", "order", "check_exit_code", "exit_code"):
                    if field in row:
                        value = row[field]
                        if value is None and field == "exit_code":
                            continue
                        need(type(value) is int and (field == "exit_code" or value >= 0), "invalid_integer_field")
                if "evidence_refs" in row:
                    need(isinstance(row["evidence_refs"], list), "invalid_reference")
                    for ref in row["evidence_refs"]:
                        need(isinstance(ref, str) and ref in self.evidence.keys() | legacy, "broken_evidence_reference")
                if "evidence_id" in row and not set(row) - {"evidence_id", "lines"}:
                    need(row["evidence_id"] in self.evidence, "broken_evidence_reference")
                    lines = row.get("lines")
                    if lines:
                        need(isinstance(lines, list) and len(lines) == 2 and all(type(n) is int for n in lines)
                             and 1 <= lines[0] <= lines[1], "invalid_line_reference")
                        total = self.evidence[row["evidence_id"]].get("line_count")
                        need(total is None or lines[1] <= total, "invalid_line_reference")
                if row.get("algorithm") == "sha256" and "scope" in row:
                    check_digest(row)
        self.checks["evidence_definitions"] = len(self.evidence)

    def validate_repo(self, path):
        fd = open_relative(self.cache, path, directory=True)
        os.close(fd)
        repo = self.cache.joinpath(*relative(path))
        # Reject external object stores and repo configs which could cause implicit reads/fetches.
        visited = 0
        for base, dirs, files in os.walk(repo, followlinks=False):
            for item in dirs + files:
                visited += 1
                need(visited <= 1000000, "git_repository_limit")
                mode = os.lstat(Path(base) / item).st_mode
                need(not stat.S_ISLNK(mode) and (stat.S_ISREG(mode) or stat.S_ISDIR(mode)), "unsafe_git_repository")
        for bad in ["commondir", "objects/info/alternates", "objects/info/http-alternates", "info/grafts"]:
            need(not (repo / bad).exists(), "external_git_storage")
        need(not list((repo / "objects/pack").glob("*.promisor")), "partial_git_repository")
        raw = read_relative(repo, "config", 128 * 1024).decode("utf-8")
        parser = configparser.RawConfigParser(strict=True)
        parser.read_string(raw)
        for section in parser.sections():
            lowered = section.lower()
            # A narrow allowlist avoids options such as fsck.skipList or include
            # causing reads outside the caller's source cache.
            need(lowered in {"core", "extensions"}, "unsafe_git_config")
            allowed = ({"repositoryformatversion", "filemode", "bare", "ignorecase", "precomposeunicode",
                        "logallrefupdates"} if lowered == "core" else {"objectformat"})
            need(set(parser[section]) <= allowed, "unsafe_git_config")
        need(parser.get("core", "bare", fallback="").lower() == "true", "unsafe_git_config")
        need(parser.get("extensions", "objectformat", fallback="sha1") in HEX, "unsafe_git_config")
        return repo

    def content(self):
        rows = self.m.get("components")
        need(isinstance(rows, list) and 0 < len(rows) <= MAX_COMPONENTS, "invalid_components")
        self.components = self.register_ids(rows, "component_id")
        for cid, c in self.components.items():
            self.active = cid
            self.checks["components"] += 1
            need(isinstance(c.get("role"), str) and c["role"], "missing_component_role")
            source, acquisition = c.get("source", {}), c.get("acquisition", {})
            need(isinstance(source, dict) and isinstance(acquisition, dict), "invalid_component_shape")
            kind, acquired = source.get("kind"), acquisition.get("status") == "acquired"
            need(kind in {"git", "archive"}, "invalid_source_kind")
            public_url(source.get("url"))
            need(acquisition.get("status") in {"acquired", "not_acquired", "unavailable"}, "invalid_acquisition_status")
            if kind == "git":
                fmt = source.get("object_format")
                if acquired or source.get("commit_object_id") is not None:
                    oid(source.get("commit_object_id"), fmt)
                else:
                    need(fmt in HEX, "invalid_object_identity")
                if acquired:
                    oid(source.get("tree_object_id"), fmt)
            if not acquired:
                need(acquisition.get("cache_path") is None and isinstance(acquisition.get("reason"), str)
                     and acquisition["reason"], "unaccounted_missing_input")
                need(not c.get("content_digests"), "unacquired_verified_digest")
                continue
            digests = c.get("content_digests")
            need(isinstance(digests, list) and digests, "missing_content_digest")
            by_scope = {}
            for digest in digests:
                check_digest(digest)
                scope = digest["scope"]
                need(scope not in by_scope, "duplicate_digest_scope")
                allowed = {"git_tree_listing_bytes"} if kind == "git" else {"downloaded_archive_bytes", "archive_member_metadata_json_bytes"}
                need(scope in allowed, "invalid_digest_scope")
                actual, size = digest_relative(self.cache, digest.get("cache_path"))
                need(actual == digest["value"] and ("size_bytes" not in digest or digest["size_bytes"] == size),
                     "content_digest_mismatch")
                by_scope[scope] = digest
                self.checks["content_digests"] += 1
            if kind == "git":
                need(self.git_executable, "git_unavailable")
                self.git_repos[cid] = self.validate_repo(acquisition.get("cache_path"))
                commit, tree = source["commit_object_id"], source["tree_object_id"]
                for args, expected in [(("rev-parse", "--show-object-format"), fmt),
                                       (("rev-parse", "--verify", commit + "^{commit}"), commit),
                                       (("rev-parse", "--verify", commit + "^{tree}"), tree)]:
                    need(self.git(cid, *args).decode().strip() == expected, "git_identity_mismatch")
                self.git(cid, "fsck", "--full", "--no-reflogs")
                listing = self.git(cid, "ls-tree", "-r", "-z", "--full-tree", commit)
                need("git_tree_listing_bytes" in by_scope and hashlib.sha256(listing).hexdigest()
                     == by_scope["git_tree_listing_bytes"]["value"], "git_listing_mismatch")
                entries = {}
                for entry in listing.split(b"\0"):
                    if not entry:
                        continue
                    meta, name = entry.split(b"\t", 1)
                    mode, objtype, obj = meta.decode("ascii").split()
                    name = name.decode("utf-8")
                    relative(name)
                    entries[name] = (mode, objtype, obj)
                need(c.get("tracked_entries", len(entries)) == len(entries), "git_entry_count_mismatch")
                self.trees[cid] = entries
                self.checks["acquired_git"] += 1
            else:
                need(source.get("archive_format") in {"tar+gzip", "tar", "tar+xz"}, "unsupported_archive")
                need("downloaded_archive_bytes" in by_scope and acquisition.get("cache_path")
                     == by_scope["downloaded_archive_bytes"]["cache_path"], "archive_identity_mismatch")
                self.checks["acquired_archives"] += 1
        self.active = None

    def dependencies(self):
        deps = self.m.get("dependencies")
        need(isinstance(deps, list), "invalid_dependencies")
        links = {}
        for dep in deps:
            need(isinstance(dep, dict), "invalid_dependency")
            parent, child = dep.get("parent"), dep.get("dependency")
            need(parent in self.components and child in self.components, "broken_component_reference")
            need(dep.get("acquisition_status") == self.components[child]["acquisition"]["status"],
                 "dependency_status_mismatch")
            if dep.get("relationship") != "git_submodule":
                need(dep.get("relationship") == "build_definition_reference", "invalid_dependency_kind")
                continue
            relative(dep.get("path"))
            key = (parent, dep["path"])
            need(key not in links, "duplicate_gitlink")
            links[key] = child
            child_source = self.components[child]["source"]
            expected = oid(dep.get("declared_commit_object_id"), child_source["object_format"])
            need(expected == child_source.get("commit_object_id") and dep.get("declared_url") == child_source.get("url"),
                 "gitlink_identity_mismatch")
            need(parent in self.trees and self.trees[parent].get(dep["path"]) == ("160000", "commit", expected),
                 "gitlink_content_mismatch")
            self.checks["gitlinks"] += 1
        for parent, entries in self.trees.items():
            for path, (mode, _, _) in entries.items():
                if mode == "160000":
                    need((parent, path) in links, "unrecorded_gitlink")
        for cid, component in self.components.items():
            if component["role"] == "unselected-gitlink-input":
                need(cid in links.values() and component["acquisition"]["status"] == "not_acquired",
                     "unaccounted_excluded_component")
        for row in self.m.get("vendored_path_inventory", []):
            cid = row.get("parent")
            need(cid in self.git_repos, "broken_component_reference")
            relative(row.get("path"))
            oid(row.get("object_id"), row.get("object_format"))
            need(self.git(cid, "rev-parse", "--verify", self.components[cid]["source"]["commit_object_id"]
                          + ":" + row["path"]).decode().strip() == row["object_id"], "vendored_identity_mismatch")

    def source_evidence(self):
        seen = set()
        for row in self.evidence.values():
            cid = row.get("component_id")
            if cid is not None:
                need(cid in self.components, "broken_component_reference")
            if "blob_object_id" not in row:
                if cid in self.components and "commit_object_id" in row:
                    selected = self.components[cid]["source"]
                    for field in ("commit_object_id", "tree_object_id", "object_format"):
                        if field in row:
                            need(row[field] == selected.get(field), "evidence_source_mismatch")
                continue
            self.active = cid
            need(cid in self.git_repos, "unavailable_evidence_source")
            s = self.components[cid]["source"]
            need(row.get("commit_object_id") == s["commit_object_id"], "evidence_source_mismatch")
            path = row.get("path")
            relative(path)
            oid(row.get("blob_object_id"), s["object_format"])
            entry = self.trees[cid].get(path)
            need(entry and entry[1:] == ("blob", row["blob_object_id"]) and entry[0] != "120000",
                 "evidence_blob_mismatch")
            check_digest(row.get("digest"), "git_blob_bytes")
            key = (cid, path, row["digest"]["value"], row.get("size_bytes"), row.get("line_count"))
            if key not in seen:
                data = self.git(cid, "cat-file", "blob", row["blob_object_id"])
                need(hashlib.sha256(data).hexdigest() == row["digest"]["value"]
                     and len(data) == row.get("size_bytes"), "evidence_digest_mismatch")
                if "line_count" in row:
                    need(len(data.splitlines()) == row["line_count"], "evidence_line_mismatch")
                seen.add(key)
                self.checks["source_blobs"] += 1
        self.active = None
        for doc in self.documents:
            vendor = doc.get("vendor_archive_audit")
            if not vendor:
                continue
            cid = vendor.get("component_id")
            need(cid in self.components and self.components[cid]["source"]["kind"] == "archive",
                 "broken_component_reference")
            c = self.components[cid]
            dig = next(d for d in c["content_digests"] if d["scope"] == "downloaded_archive_bytes")
            need(vendor.get("archive_sha256") == dig["value"] and vendor.get("archive_url") == c["source"]["url"],
                 "archive_evidence_identity_mismatch")
            selected = vendor["inspection_scope"]["selected_members"]
            wanted = {}
            for member in selected:
                relative(member.get("path"))
                need(member.get("scope") == "archive_member_bytes", "invalid_digest_scope")
                oid(member.get("sha256"), "sha256")
                need(member["path"] not in wanted, "duplicate_archive_evidence")
                wanted[member["path"]] = member
            fd = open_relative(self.cache, c["acquisition"]["cache_path"])
            observed, names, expanded = set(), set(), 0
            with os.fdopen(fd, "rb") as raw, tarfile.open(fileobj=raw, mode="r|*") as archive:
                for member in archive:
                    relative(member.name.rstrip("/"))
                    need(member.name not in names, "duplicate_archive_member")
                    names.add(member.name)
                    expanded += member.size
                    need(len(names) <= MAX_MEMBERS and expanded <= MAX_ARCHIVE_CONTENT
                         and member.size <= MAX_FILE, "archive_size_limit")
                    if member.name not in wanted:
                        continue
                    record = wanted[member.name]
                    need(member.isfile(), "nonregular_archive_evidence")
                    with archive.extractfile(member) as stream:
                        digest = hashlib.file_digest(stream, "sha256").hexdigest()
                    need(digest == record["sha256"] and member.size == record.get("size_bytes"),
                         "archive_member_mismatch")
                    observed.add(member.name)
                    self.checks["archive_members"] += 1
            need(observed == set(wanted), "missing_archive_evidence")

    def patches(self):
        patches = self.register_ids(self.m.get("patch_inventory", []), "patch_id")
        for pid, patch in patches.items():
            cid = patch.get("component_id")
            need(cid in self.git_repos, "broken_patch_component")
            self.active = cid
            public_url(patch.get("source_url"))
            oid(patch.get("original_base_commit"), self.components[cid]["source"]["object_format"])
            need(type(patch.get("order")) is int and patch["order"] >= 1 and patch.get("evidence_refs"),
                 "missing_patch_provenance")
            check_digest(patch.get("digest"), "patch_file_bytes")
            value, size = digest_relative(self.cache, patch.get("cache_path"))
            need(value == patch["digest"]["value"] and size == patch.get("size_bytes"), "patch_digest_mismatch")
            evidence = [self.evidence[ref] for ref in patch["evidence_refs"] if ref in self.evidence]
            origins = [r for r in evidence if r.get("patch_id") == pid and "origin" in r]
            need(len(origins) == 1, "missing_patch_provenance")
            origin = origins[0]
            selected = patch.get("applied_to_runtime_candidate", False)
            need(type(selected) is bool and (not selected or origin.get("selected_runtime_series") is True),
                 "patch_selection_mismatch")
            if "patch_path_relative_to_inputs" in origin:
                need(origin["patch_path_relative_to_inputs"] == patch["cache_path"], "patch_provenance_mismatch")
            need(origin.get("terms_scope") and origin.get("digest") == patch["digest"]
                 and origin.get("order") == patch["order"] and origin.get("patch_url") == patch["source_url"]
                 and origin["origin"].get("parent") == patch["original_base_commit"]
                 and origin["origin"].get("commit") == self.components[cid]["source"]["commit_object_id"],
                 "patch_provenance_mismatch")
            actual_parent = self.git(cid, "rev-parse", "--verify", origin["origin"]["commit"] + "^").decode().strip()
            need(actual_parent == patch["original_base_commit"], "patch_base_mismatch")
            need(patch.get("applicability") == origin.get("applicability"), "patch_applicability_mismatch")
            for result in patch["applicability"]:
                oid(result.get("base_commit"))
                passed = result.get("status") == "applies"
                need(result.get("status") in {"applies", "does_not_apply"}
                     and result.get("check_exit_code") == (0 if passed else 1)
                     and (not result.get("applied") or passed), "patch_applicability_mismatch")
                if result.get("applied"):
                    oid(result.get("result_tree"))
                    if result.get("target") == "original-parent":
                        need(result["result_tree"] == self.components[cid]["source"]["tree_object_id"],
                             "patch_result_mismatch")
                if result.get("target") in self.components:
                    need(result["base_commit"] == self.components[result["target"]]["source"]["commit_object_id"],
                         "patch_base_mismatch")
            self.checks["patches"] += 1
        for cid, component in self.components.items():
            for series in ("ordered_series", "candidate_series"):
                rows = component.get("patches", {}).get(series)
                if rows is None:
                    continue
                need(isinstance(rows, list), "invalid_patch_series")
                seen = set()
                for index, row in enumerate(rows, 1):
                    need(isinstance(row, dict) and row.get("patch_id") in patches and row.get("order") == index,
                         "invalid_patch_series")
                    need(row["patch_id"] not in seen, "invalid_patch_series")
                    seen.add(row["patch_id"])
                    p = patches[row["patch_id"]]
                    if "target_base_commit" in row:
                        need(row["target_base_commit"] == component["source"]["commit_object_id"]
                             and row.get("original_base_commit") == p["original_base_commit"], "patch_base_mismatch")
                        matches = [r for r in p["applicability"] if r.get("target") == cid]
                        need(len(matches) == 1 and row.get("applicability") == matches[0]["status"]
                             and row.get("check_exit_code") == matches[0]["check_exit_code"], "patch_applicability_mismatch")
                    if series == "ordered_series":
                        need(any(r.get("target") == cid and r.get("status") == "applies" for r in p["applicability"]),
                             "unverified_applied_patch")
        self.active = None

    def decision(self):
        m = self.m
        complete, decision, ready = m.get("audit_complete"), m.get("decision"), m.get("source_ready")
        need(type(complete) is bool and type(ready) is bool and decision in {"unassessed", "go", "needs-port", "blocked"},
             "invalid_decision")
        need(not complete or decision != "unassessed", "contradictory_decision")
        need(ready == (complete and decision == "go"), "contradictory_readiness")
        need(isinstance(m.get("qualification"), dict) and m["qualification"] ==
             {"runtime": "unassessed", "game": "unassessed", "distribution": "unassessed"}, "runtime_claim_forbidden")
        requirements = self.register_ids(m.get("requirements", []), "requirement_id")
        source_requirements = self.register_ids(m.get("source_requirements", []), "requirement_id")
        need(requirements, "missing_requirements")
        allowed = {"unassessed", "partial", "present-unverified", "needs-port", "blocked", "verified", "not-applicable"}
        for row in [*requirements.values(), *source_requirements.values()]:
            need(row.get("status") in allowed, "invalid_requirement_status")
            need(row.get("evidence_refs") or row.get("sources"), "missing_requirement_evidence")
            if row["status"] != "verified":
                need(row.get("remaining") or row.get("remaining_work") or row.get("reason"), "unaccounted_requirement")
            if complete:
                need(row["status"] not in {"unassessed", "partial"}, "incomplete_requirement_accounting")
        unresolved = self.register_ids(m.get("unresolved_inputs", []), "input_id")
        for row in unresolved.values():
            need(isinstance(row.get("reason"), str) and row["reason"] and row.get("status")
                 and row.get("role"), "unaccounted_missing_input")
        tools = m.get("candidate_toolchain", [])
        self.register_ids(tools, "tool_id")
        for row in tools:
            need(row.get("status") in {"metadata_observed", "not_found", "unavailable", "source_candidate"},
                 "invalid_tool_status")
            need(row.get("role") and row.get("evidence_refs") and row.get("compatibility") in {"unverified", "conflict", "verified"},
                 "invalid_tool_evidence")
            if row["status"] in {"metadata_observed", "source_candidate"}:
                need(isinstance(row.get("version"), str) and row["version"], "missing_tool_version")
                if row["status"] == "metadata_observed":
                    matches = [self.evidence[ref] for ref in row["evidence_refs"]
                               if ref in self.evidence and "observed_version" in self.evidence[ref]]
                    need(len(matches) == 1 and matches[0]["observed_version"] == row["version"]
                         and matches[0].get("exit_code") == 0, "tool_metadata_mismatch")
            else:
                need(row.get("version") is None and row.get("reason"), "unaccounted_missing_tool")
        if decision == "go":
            need(complete, "contradictory_decision")
            need(not m.get("unresolved_inputs"), "unresolved_source_prerequisites")
            need(all(r["status"] in {"verified", "not-applicable"} for r in [*requirements.values(), *source_requirements.values()]),
                 "unresolved_source_prerequisites")
            for c in self.components.values():
                if c["role"] == "unselected-gitlink-input":
                    need(c["acquisition"].get("reason"), "unaccounted_missing_input")
                    continue
                need(c["acquisition"]["status"] == "acquired" and c.get("readiness") == "verified"
                     and c.get("terms", {}).get("status") == "reviewed"
                     and c.get("patches", {}).get("ordered_series") is not None, "unready_component")
            need(tools and all(t["compatibility"] == "verified" and t["status"] == "metadata_observed" for t in tools),
                 "unready_toolchain")

    def run(self):
        m = self.m
        need(set(m) <= TOP_FIELDS and type(m.get("schema_version")) is int and m["schema_version"] == 1
             and m.get("record_kind") == "source_audit"
             and type(m.get("issue")) is int and m["issue"] > 0, "invalid_manifest_shape")
        self.references()
        self.content()
        self.dependencies()
        self.source_evidence()
        self.patches()
        self.decision()


def validate_inventory(manifest_path, cache_root, require_complete=False, require_source_ready=False):
    result = {"record_valid": False, "audit_complete": False, "decision": "invalid", "source_ready": False,
              "checks": {}, "errors": []}
    audit = None
    try:
        path = Path(manifest_path).absolute()
        # CLI paths are explicit caller inputs. Record references remain rooted at the repository.
        root = path.parent.parent.parent
        need(path.parent.name == "sources" and path.parent.parent.name == "runtime", "manifest_location")
        manifest = decode_json(read_relative(root, "runtime/sources/" + path.name))
        cache = Path(cache_root).absolute()
        need(cache.is_dir() and not cache.is_symlink(), "invalid_cache_root")
        audit = Audit(manifest, root, cache)
        audit.run()
        result.update(record_valid=True, audit_complete=manifest["audit_complete"], decision=manifest["decision"],
                      source_ready=manifest["source_ready"], checks=audit.checks)
        refused = (require_complete and not result["audit_complete"]) or (require_source_ready and not result["source_ready"])
        if refused:
            result["errors"] = [{"code": "requested_gate_not_met"}]
        return result, 3 if refused else 0
    except (Invalid, OSError, ValueError, TypeError, KeyError, configparser.Error, tarfile.TarError,
            subprocess.SubprocessError, UnicodeError, OverflowError, AttributeError, RecursionError) as exc:
        entry = {"code": exc.code if isinstance(exc, Invalid) else "unreadable_or_malformed_input"}
        if audit:
            result["checks"] = audit.checks
            if audit.active and ID.fullmatch(audit.active):
                entry["component_id"] = audit.active
        result["errors"] = [entry]
        return result, 1


class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error embeds user-supplied paths/options.
        print(json.dumps({"record_valid": False, "audit_complete": False, "decision": "invalid",
                          "source_ready": False, "checks": {}, "errors": [{"code": "cli_usage"}]}))
        raise SystemExit(2)


def main(argv=None):
    parser = PrivateParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--cache-root", required=True)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--require-complete", action="store_true")
    group.add_argument("--require-source-ready", action="store_true")
    args = parser.parse_args(argv)
    result, code = validate_inventory(args.manifest, args.cache_root, args.require_complete, args.require_source_ready)
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())

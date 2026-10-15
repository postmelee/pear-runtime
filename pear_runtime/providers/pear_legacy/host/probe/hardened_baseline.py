"""Run local Developer ID Hardened Runtime controls on existing probe binaries.

This developer tool neither builds a runtime nor requests restricted capabilities.
Generated bundles stay in ignored .build/ for inspection; they are not releases.
Identity metadata and command diagnostics are consumed locally, never published.
"""

import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from xml.parsers.expat import ExpatError


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / ".build/host-probe"
ALLOW_JIT = "com.apple.security.cs.allow-jit"
QUALIFICATION = {"runtime": "not_assessed", "rosetta_free_game": "not_assessed",
                 "distribution": "not_assessed"}
STEP_NAMES = {
    "memory": ("allocate", "write_read", "protect_read", "restore_write",
               "rewrite_read", "release"),
    "protection": ("allocate", "write_read", "protect_read", "unexpected_write",
                   "unused", "release"),
    "low-address": ("allocate", "write_read", "release"),
    "jit": ("allocate", "write", "publish", "icache_sync", "execute", "release"),
}


class ControlError(Exception):
    """A stable, non-sensitive failure code suitable for the public record."""

    def __init__(self, code, stage=None):
        super().__init__(code)
        self.code = code
        self.stage = stage


def select_identity(output, override=None):
    """Select only an available Developer ID Application identity by fingerprint."""
    identities = {}
    pattern = r'^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"(Developer ID Application: [^"\r\n]+)"\s*$'
    for line in output.splitlines():
        match = re.fullmatch(pattern, line)
        if match:
            identities[match[1].upper()] = match[2]
    if override is not None:
        matches = [fingerprint for fingerprint, name in identities.items()
                   if override.upper() == fingerprint or override == name]
        if len(matches) != 1:
            raise ControlError("identity_override_unavailable")
        return matches[0]
    if len(identities) != 1:
        raise ControlError("identity_unavailable" if not identities else "identity_ambiguous")
    return next(iter(identities))


def check_signature(metadata, entitlements, positive):
    """Validate effective claims without returning private certificate metadata."""
    matches = re.findall(r'^CodeDirectory\b[^\r\n]*?\bflags=0x([0-9a-fA-F]+)(?:\(|\s|$)',
                         metadata, re.M)
    if len(matches) != 1:
        raise ControlError("signature_flags_missing")
    flags = int(matches[0], 16)
    if not flags & 0x10000 or flags & 0x2:
        raise ControlError("signature_not_hardened_signed")
    if not re.search(r'^Authority=Developer ID Application: [^\r\n]+$', metadata, re.M):
        raise ControlError("signature_wrong_category")
    if not re.search(r'^TeamIdentifier=[A-Z0-9]+$', metadata, re.M):
        raise ControlError("signature_team_unavailable")
    try:
        claims = plistlib.loads(entitlements) if entitlements.strip() else {}
    except (ValueError, TypeError, ExpatError, plistlib.InvalidFileException):
        raise ControlError("entitlements_invalid") from None
    expected = {ALLOW_JIT: True} if positive else {}
    if not isinstance(claims, dict) or claims != expected:
        raise ControlError("entitlements_unexpected")
    if positive and claims.get(ALLOW_JIT) is not True:
        raise ControlError("entitlements_unexpected")
    return {"category": "developer_id_application", "flags": flags,
            "hardened_runtime": True, "ad_hoc": False,
            "entitlements": expected}


def _observed(observation, expected):
    return (isinstance(observation, dict) and observation.get("status") == "observed"
            and type(observation.get("value")) is type(expected)
            and observation.get("value") == expected and observation.get("error") is None)


def _integer(value):
    return type(value) is int


def _step(step, status, value=None, error=None):
    return (isinstance(step, dict) and step.get("status") == status
            and type(step.get("value")) is type(value) and step.get("value") == value
            and step.get("error") == error)


def _allocation(step):
    return (isinstance(step, dict) and _integer(step.get("value"))
            and step["value"] > 0 and _step(step, "passed", step["value"]))


def assess_result(record, positive, paired_positive=False):
    """Require actual expected behavior; a crash is never a negative JIT pass."""
    def failed(reason):
        return {"status": "failed", "reason": reason}

    if not isinstance(record, dict) or type(record.get("schema_version")) is not int:
        return failed("invalid_record")
    if (record["schema_version"] != 1 or record.get("record_kind") != "baseline_execution"
            or record.get("scope") != "owned_test_children"
            or record.get("qualification") != QUALIFICATION):
        return failed("invalid_record")
    parent = record.get("parent_observations")
    if not isinstance(parent, dict) or parent.get("qualification") != QUALIFICATION:
        return failed("invalid_parent_observations")
    process = parent.get("process", {})
    signature = parent.get("signature", {})
    if (not isinstance(process, dict) or not isinstance(signature, dict)
            or not _observed(process.get("architecture"), "arm64")
            or not _observed(process.get("translated"), False)
            or not _observed(signature.get("category"), "signed")):
        return failed("native_signed_parent_unconfirmed")
    items = record.get("probes")
    if not isinstance(items, list) or len(items) != 4:
        return failed("invalid_probe_set")
    probes = {}
    for item in items:
        if (not isinstance(item, dict) or not isinstance(item.get("name"), str)
                or item["name"] not in STEP_NAMES):
            return failed("invalid_probe_set")
        if item["name"] in probes:
            return failed("invalid_probe_set")
        probes[item["name"]] = item
    paired_rejection = False
    for name, probe in probes.items():
        execution = probe.get("execution")
        steps = probe.get("steps")
        if (not isinstance(execution, dict) or not isinstance(steps, dict)
                or set(steps) != set(STEP_NAMES[name])):
            return failed("invalid_probe_record")
        if (execution.get("packet_valid") is not True
                or execution.get("child_reaped") is not True
                or not _integer(execution.get("error_code")) or execution["error_code"] != 0
                or not _integer(execution.get("stdout_bytes")) or execution["stdout_bytes"] != 160
                or not _integer(execution.get("stderr_bytes")) or execution["stderr_bytes"] != 0
                or not _integer(execution.get("elapsed_ms")) or execution["elapsed_ms"] < 0):
            return failed("invalid_child_execution")
        if name == "protection":
            if (probe.get("status") != "passed"
                    or probe.get("expected_fault_observed") is not True
                    or execution.get("outcome") != "signaled"
                    or execution.get("exit_code") is not None
                    or not _integer(execution.get("signal"))
                    or execution["signal"] not in (signal.SIGBUS, signal.SIGSEGV)
                    or not _allocation(steps["allocate"])
                    or not _step(steps["write_read"], "passed", 42)
                    or not _step(steps["protect_read"], "passed", 0)
                    or any(not _step(steps[key], "not_run")
                           for key in ("unexpected_write", "unused", "release"))):
                return failed("protection_control_failed")
            continue
        if (execution.get("outcome") != "exited"
                or not _integer(execution.get("exit_code")) or execution["exit_code"] != 0
                or execution.get("signal") is not None
                or probe.get("expected_fault_observed") is not False):
            return failed("unexpected_child_termination")
        if name == "memory":
            expected = {"write_read": 42, "protect_read": 0, "restore_write": 0,
                        "rewrite_read": 84, "release": 0}
            if (probe.get("status") != "passed" or not _allocation(steps["allocate"])
                    or any(not _step(steps[key], "passed", value)
                           for key, value in expected.items())):
                return failed("memory_control_failed")
        elif name == "low-address":
            if probe.get("status") == "passed":
                if any(not _step(steps[key], "passed", value) for key, value in
                       (("allocate", 0x20000000), ("write_read", 42), ("release", 0))):
                    return failed("low_address_control_failed")
            elif probe.get("status") == "unavailable":
                allocation = steps["allocate"]
                error = allocation.get("error") if isinstance(allocation, dict) else None
                if (not isinstance(error, dict) or error.get("domain") != "mach"
                        or not _integer(error.get("code")) or error["code"] not in (1, 2, 3)
                        or not _step(allocation, "unavailable", 0, error)
                        or any(not _step(steps[key], "not_run") for key in ("write_read", "release"))):
                    return failed("low_address_control_failed")
            else:
                return failed("low_address_control_failed")
        elif positive:
            expected = {"write": 8, "publish": 0, "icache_sync": 8,
                        "execute": 42, "release": 0}
            if (probe.get("status") != "passed" or not _allocation(steps["allocate"])
                    or any(not _step(steps[key], "passed", value)
                           for key, value in expected.items())):
                return failed("positive_jit_control_failed")
        else:
            allocation = steps["allocate"]
            error = allocation.get("error") if isinstance(allocation, dict) else None
            if (not isinstance(error, dict) or error.get("domain") != "errno"
                    or not _integer(error.get("code"))
                    or any(not _step(steps[key], "not_run") for key in STEP_NAMES["jit"][1:])):
                return failed("negative_jit_control_failed")
            permission_denied = (probe.get("status") == "unavailable"
                                 and error["code"] in (errno.EPERM, errno.EACCES)
                                 and _step(allocation, "unavailable", 0, error))
            # EINVAL has several mmap causes. Interpret it only in this matched
            # experiment after the same input passed with allow-jit enabled;
            # retain the native failed/EINVAL result rather than reclassifying it.
            paired_rejection = (paired_positive is True and probe.get("status") == "failed"
                                and error["code"] == errno.EINVAL
                                and _step(allocation, "failed", 0, error))
            if not permission_denied and not paired_rejection:
                return failed("negative_jit_control_failed")
    return {"status": "passed", "reason": "expected_paired_jit_rejection_observed"
            if paired_rejection else "expected_control_observed"}


def paired_positive_matches(report, negative):
    """Only verified successful control copies from identical inputs form a pair."""
    if not isinstance(report, dict) or not isinstance(negative, dict):
        return False
    inputs = report.get("input_binary_sha256")
    if (not isinstance(inputs, dict) or set(inputs) != {"pear-baseline-probe", "pear-probe-child"}
            or negative.get("name") != "negative" or negative.get("input_copy_sha256") != inputs
            or not isinstance(report.get("controls"), list)):
        return False
    positives = [item for item in report.get("controls", [])
                 if isinstance(item, dict) and item.get("name") == "positive"]
    return (len(positives) == 1 and positives[0].get("status") == "passed"
            and positives[0].get("input_copy_sha256") == inputs)


def sanitized_result(record):
    """Retain numeric observations and known labels, never arbitrary child strings."""
    if not isinstance(record, dict):
        return None
    def observation(value, accepts):
        if not isinstance(value, dict):
            return {"status": "invalid", "value": None, "error": None}
        status = value.get("status")
        actual = value.get("value")
        error = value.get("error")
        clean_error = None
        if (isinstance(error, dict) and error.get("domain") in ("errno", "osstatus", "internal")
                and _integer(error.get("code"))):
            clean_error = {"domain": error["domain"], "code": error["code"]}
        return {"status": status if status in ("observed", "unavailable", "failed") else "invalid",
                "value": actual if accepts(actual) else None, "error": clean_error}

    result = {"probes": []}
    parent = record.get("parent_observations")
    if isinstance(parent, dict):
        clean_parent = {}
        process = parent.get("process")
        if isinstance(process, dict):
            clean_parent["process"] = {
                "architecture": observation(process.get("architecture"),
                                            lambda value: value in ("arm64", "x86_64")),
                "translated": observation(process.get("translated"), lambda value: type(value) is bool),
            }
        signature = parent.get("signature")
        if isinstance(signature, dict):
            clean_parent["signature"] = {
                "category": observation(signature.get("category"),
                                        lambda value: value in ("signed", "ad_hoc", "unsigned")),
            }
        host = parent.get("host")
        if isinstance(host, dict):
            clean_parent["host"] = {
                "os_version": observation(host.get("os_version"), lambda value: isinstance(value, str)
                                          and re.fullmatch(r"[0-9]{1,4}(?:\.[0-9]{1,4}){0,3}", value) is not None),
                "os_build": observation(host.get("os_build"), lambda value: isinstance(value, str)
                                        and re.fullmatch(r"[0-9]{1,4}[A-Z][0-9]{1,6}[a-z]?", value) is not None),
                "page_size_bytes": observation(host.get("page_size_bytes"),
                                               lambda value: _integer(value) and value > 0),
            }
        result["parent_observations"] = clean_parent
    items = record.get("probes", [])
    if not isinstance(items, list):
        return result
    for item in items[:4]:
        if (not isinstance(item, dict) or not isinstance(item.get("name"), str)
                or item["name"] not in STEP_NAMES):
            continue
        clean = {"name": item["name"], "status": item.get("status")
                 if item.get("status") in ("passed", "unavailable", "failed") else "invalid"}
        execution = item.get("execution", {})
        clean["execution"] = {}
        if isinstance(execution, dict):
            for key in ("exit_code", "signal", "error_code", "elapsed_ms", "stdout_bytes",
                        "stderr_bytes", "packet_valid", "child_reaped"):
                value = execution.get(key)
                clean["execution"][key] = value if type(value) in (int, bool, type(None)) else None
            outcome = execution.get("outcome")
            clean["execution"]["outcome"] = outcome if outcome in (
                "exited", "signaled", "timed_out", "output_limit", "spawn_error", "io_error",
                "invalid_output") else "invalid"
        clean["expected_fault_observed"] = item.get("expected_fault_observed") is True
        clean["steps"] = {}
        steps = item.get("steps", {})
        for name in STEP_NAMES[item["name"]]:
            step = steps.get(name) if isinstance(steps, dict) else None
            if not isinstance(step, dict):
                continue
            status = step.get("status")
            error = step.get("error")
            clean_error = None
            if (isinstance(error, dict) and error.get("domain") in ("errno", "mach", "internal")
                    and _integer(error.get("code"))):
                clean_error = {"domain": error["domain"], "code": error["code"]}
            clean["steps"][name] = {
                "status": status if status in ("passed", "unavailable", "failed", "not_run") else "invalid",
                "value": step.get("value") if _integer(step.get("value")) else None,
                "error": clean_error,
            }
        result["probes"].append(clean)
    return result


def _hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _command(arguments, stage, events, *, timeout=20, require_success=True):
    event = {"stage": stage}
    events.append(event)
    try:
        result = subprocess.run(arguments, capture_output=True, timeout=timeout,
                                stdin=subprocess.DEVNULL, close_fds=True)
    except subprocess.TimeoutExpired:
        event["status"] = "timed_out"
        raise ControlError("command_timed_out", stage) from None
    except OSError as error:
        event.update(status="unavailable", error_code=error.errno)
        raise ControlError("command_unavailable", stage) from None
    event.update(status="completed", exit_code=result.returncode,
                 stdout_bytes=len(result.stdout), stderr_bytes=len(result.stderr))
    if require_success and result.returncode != 0:
        raise ControlError("command_failed", stage)
    return result


def _verify(target, positive, label, events):
    _command(["/usr/bin/codesign", "--verify", "--strict", str(target)],
             label + ".verify", events)
    metadata = _command(["/usr/bin/codesign", "--display", "--verbose=4", str(target)],
                        label + ".metadata", events)
    claims = _command(["/usr/bin/codesign", "--display", "--entitlements", ":-", str(target)],
                      label + ".entitlements", events)
    try:
        result = check_signature(metadata.stderr.decode("utf-8", errors="strict"), claims.stdout, positive)
    except UnicodeError:
        raise ControlError("signature_metadata_invalid", label) from None
    except ControlError as error:
        error.stage = label
        raise
    return {"strict_verification": "passed", **result}


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _control(directory, sources, identity, positive, report):
    label = "positive" if positive else "negative"
    identifier = "io.github.postmelee.pear.host-probe.baseline." + label
    bundle = directory / (label + ".app")
    executables = bundle / "Contents/MacOS"
    executables.mkdir(parents=True)
    control = {"name": label, "status": "failed", "bundle": bundle.relative_to(ROOT).as_posix(),
               "embedded_profile": False, "signatures": {}, "signed_binary_sha256": {},
               "input_copy_sha256": {}}
    report["controls"].append(control)
    with (bundle / "Contents/Info.plist").open("wb") as stream:
        plistlib.dump({"CFBundleIdentifier": identifier, "CFBundleExecutable": "pear-baseline-probe",
                      "CFBundleName": "Pear Host Probe", "CFBundlePackageType": "APPL",
                      "CFBundleVersion": "1", "CFBundleShortVersionString": "0.1",
                      "LSMinimumSystemVersion": "13.0"}, stream, sort_keys=True)
    for name, source in sources.items():
        target = executables / name
        shutil.copy2(source, target)
        control["input_copy_sha256"][name] = _hash(target)
        if control["input_copy_sha256"][name] != report["input_binary_sha256"][name]:
            raise ControlError("input_changed", label + ".copy")
    child = executables / "pear-probe-child"
    parent = executables / "pear-baseline-probe"
    sign = ["/usr/bin/codesign", "--force", "--sign", identity,
            "--options", "runtime", "--timestamp=none"]
    child_sign = [*sign, "--identifier", identifier + ".child"]
    if positive:
        entitlement_file = directory / "allow-jit.plist"
        with entitlement_file.open("wb") as stream:
            plistlib.dump({ALLOW_JIT: True}, stream)
        child_sign.extend(["--entitlements", str(entitlement_file)])
    _command([*child_sign, str(child)], label + ".sign_child", report["commands"])
    _command([*sign, "--identifier", identifier, str(bundle)], label + ".sign_bundle", report["commands"])
    for name, target, allow_jit in (("child", child, positive), ("parent", parent, False),
                                   ("bundle", bundle, False)):
        control["signatures"][name] = _verify(target, allow_jit, label + "." + name, report["commands"])
    control["signed_binary_sha256"] = {name: _hash(executables / name) for name in sources}
    result = _command([str(parent)], label + ".execute", report["commands"],
                      timeout=20, require_success=False)
    control["execution"] = {"exit_code": result.returncode, "stderr_bytes": len(result.stderr)}
    if len(result.stdout) > 65536:
        raise ControlError("baseline_output_limit", label + ".execute")
    try:
        record = json.loads(result.stdout, object_pairs_hook=_json_object)
    except (ValueError, UnicodeError):
        raise ControlError("baseline_json_invalid", label + ".execute") from None
    control["baseline"] = sanitized_result(record)
    paired_positive = not positive and paired_positive_matches(report, control)
    control["paired_positive_verified"] = paired_positive
    control["assessment"] = assess_result(record, positive, paired_positive=paired_positive)
    paired_rejection = (control["assessment"]["status"] == "passed"
                        and control["assessment"]["reason"] == "expected_paired_jit_rejection_observed")
    expected_exit = 1 if paired_rejection else 0
    if result.returncode != expected_exit or result.stderr:
        raise ControlError("baseline_execution_failed", label + ".execute")
    if control["assessment"]["status"] != "passed":
        raise ControlError(control["assessment"]["reason"], label + ".assess")
    if not positive:
        control["interpretation"] = "expected_jit_rejection"
    control["status"] = "passed"


def main():
    report = {"schema_version": 1, "record_kind": "hardened_baseline_control",
              "scope": "local_signed_test_bundles", "status": "failed",
              "identity_category": "developer_id_application", "identity_selection": "not_run",
              "timestamp": "none", "notarization": "not_assessed",
              "restricted_capabilities": "not_run", "qualification": dict(QUALIFICATION),
              "input_binary_sha256": {}, "controls": [], "commands": []}
    directory = None
    stage = "prepare"
    try:
        if len(sys.argv) != 1:
            raise ControlError("unexpected_arguments", stage)
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            raise ControlError("native_apple_silicon_required", stage)
        sources = {name: BUILD / name for name in ("pear-baseline-probe", "pear-probe-child")}
        for name, source in sources.items():
            if not source.is_file() or not os.access(source, os.X_OK):
                raise ControlError("build_required", stage)
            report["input_binary_sha256"][name] = _hash(source)
            architectures = _command(["/usr/bin/lipo", "-archs", str(source)],
                                     "input_architecture." + name, report["commands"])
            if architectures.stdout.strip() != b"arm64":
                raise ControlError("arm64_only_binary_required", stage)
        stage = "identity_selection"
        identities = _command(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"],
                              stage, report["commands"])
        try:
            identity = select_identity(identities.stdout.decode("utf-8", errors="strict"),
                                       os.environ.get("PEAR_SIGNING_IDENTITY"))
        except UnicodeError:
            raise ControlError("identity_output_invalid", stage) from None
        report["identity_selection"] = "matched_available_identity"
        stage = "bundle_preparation"
        directory = Path(tempfile.mkdtemp(prefix="hardened-control-", dir=BUILD))
        report["output_directory"] = directory.relative_to(ROOT).as_posix()
        for positive in (True, False):
            stage = "positive" if positive else "negative"
            _control(directory, sources, identity, positive, report)
        for name, source in sources.items():
            if _hash(source) != report["input_binary_sha256"][name]:
                raise ControlError("source_binary_changed", "final_input_check")
        report["status"] = "passed"
    except ControlError as error:
        report["error"] = {"stage": error.stage or stage, "code": error.code}
    except OSError as error:
        report["error"] = {"stage": stage, "code": "filesystem_error", "error_code": error.errno}
    except KeyboardInterrupt:
        report["error"] = {"stage": stage, "code": "interrupted"}
    except Exception:
        # A traceback could contain an identity, private path, or captured stderr.
        report["error"] = {"stage": stage, "code": "unexpected_tool_error"}
    if directory is not None:
        try:
            (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        except OSError as error:
            report["status"] = "failed"
            report["error"] = {"stage": "save_report", "code": "filesystem_error", "error_code": error.errno}
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())

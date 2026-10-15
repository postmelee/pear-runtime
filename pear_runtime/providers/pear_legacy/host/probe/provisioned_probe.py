"""Validate a genuine development profile and run local signed process probes.

Profiles, identities and device identifiers are consumed locally. Reports contain
checks, known labels and hashes, never profile contents or private identifiers.
This tool does not acquire entitlements, build probes or produce release bundles.
"""

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import signal
import sys
import tempfile
from xml.parsers.expat import ExpatError


_SPEC = importlib.util.spec_from_file_location(
    "pear_hardened_helpers", Path(__file__).with_name("hardened_baseline.py"))
BASELINE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(BASELINE)
ControlError = BASELINE.ControlError
ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / ".build/host-probe"
DEFAULT_BUNDLE_ID = "io.github.postmelee.pear.host-probe"
CROSS_KEYS = ("com.apple.developer.cross-architecture-support",
              "com.apple.developer.cross-architecture-support-unmanaged")
APP_ID = "com.apple.application-identifier"
TEAM_ID = "com.apple.developer.team-identifier"
ABI_STEP_NAMES = {
    "x18-roundtrip": ("host_entry", "foreign_entry", "guest_before", "guest_after_getter",
                      "host_exit", "completed_roundtrips"),
    "x18-callbacks": ("host_entry", "host_callbacks", "nested_guest_returns",
                      "outer_guest_restores", "injected_error_returns", "host_exit"),
    "x18-signals": ("symbols_resolved", "host_handler_entry", "foreign_handler_entry",
                    "host_handler_body_calls", "resumed_guest_preserved", "host_exit"),
    "thread-policy": ("api_resolved", "created_threads", "initialized_threads",
                      "enabled_threads", "restored_threads", "joined_threads"),
    "thread-litmus": ("initialized_workers", "baseline_trials", "baseline_forbidden",
                      "enabled_trials", "enabled_forbidden", "restored_and_joined_workers"),
}
ABI_VALUES = {
    "x18-roundtrip": (0, 1, 0x11223344, 0x11223344, 0, 64),
    "x18-callbacks": (0, 32, 32, 32, 16, 0),
    "x18-signals": (2, 0, 1, 2, 1, 0),
    "thread-policy": (1, 2, 2, 2, 2, 2),
    "thread-litmus": (2, 10000, None, 10000, 0, 2),
}
STEP_NAMES = {
    **BASELINE.STEP_NAMES,
    **ABI_STEP_NAMES,
    "geometry": ("user_page_size", "vm_page_size", "kernel_page_size"),
    "subpage": ("allocate", "initial_sentinels", "protect_middle", "restore_middle",
                "verify_neighbors", "release"),
    "subpage-fault": ("allocate", "initial_sentinels", "protect_middle", "restore_middle",
                      "verify_neighbors", "release"),
    "recommit": ("allocate", "initial_sentinels", "replace_middle", "verify_neighbors",
                 "recommit_zero_and_write", "release"),
    "recommit-fault": ("allocate", "initial_sentinels", "replace_middle", "verify_neighbors",
                       "recommit_zero_and_write", "release"),
}


def validate_profile(profile, identity_output, provisioning_udid, bundle_id, now=None):
    """Return private signing inputs separately from public consistency checks."""
    if not isinstance(profile, dict):
        raise ControlError("profile_invalid")
    now = now or datetime.now(timezone.utc)
    expiration = profile.get("ExpirationDate")
    if not isinstance(expiration, datetime):
        raise ControlError("profile_expiration_missing")
    if expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if expiration <= now:
        raise ControlError("profile_expired")
    platforms = profile.get("Platform")
    if not isinstance(platforms, list) or "OSX" not in platforms:
        raise ControlError("profile_not_macos")
    claims = profile.get("Entitlements")
    teams = profile.get("TeamIdentifier")
    prefixes = profile.get("ApplicationIdentifierPrefix")
    if (not isinstance(claims, dict) or not isinstance(teams, list) or len(teams) != 1
            or not isinstance(teams[0], str) or not teams[0]
            or claims.get(TEAM_ID) != teams[0]
            or not isinstance(prefixes, list) or not prefixes
            or any(not isinstance(prefix, str) or not prefix or "*" in prefix for prefix in prefixes)):
        raise ControlError("profile_identity_inconsistent")
    application_id = claims.get(APP_ID)
    if (not isinstance(application_id, str) or "*" in application_id
            or sum(application_id == prefix + "." + bundle_id for prefix in prefixes) != 1):
        raise ControlError("profile_application_mismatch")
    granted = [key for key in CROSS_KEYS if claims.get(key) is True]
    if len(granted) != 1:
        raise ControlError("profile_cross_architecture_grant_missing_or_ambiguous")
    devices = profile.get("ProvisionedDevices")
    if (not isinstance(provisioning_udid, str) or not provisioning_udid
            or not isinstance(devices, list)
            or not any(isinstance(device, str) and device.casefold() == provisioning_udid.casefold()
                       for device in devices)):
        raise ControlError("profile_device_mismatch")
    certificates = profile.get("DeveloperCertificates")
    if (not isinstance(certificates, list) or not certificates
            or any(not isinstance(certificate, bytes) or not certificate for certificate in certificates)):
        raise ControlError("profile_certificates_invalid")
    fingerprints = {hashlib.sha1(certificate).hexdigest().upper() for certificate in certificates}
    identities = set()
    pattern = r'^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"Apple Development: [^"\r\n]+"\s*$'
    for line in identity_output.splitlines():
        match = re.fullmatch(pattern, line)
        if match and match[1].upper() in fingerprints:
            identities.add(match[1].upper())
    if len(identities) != 1:
        raise ControlError("profile_signing_identity_missing_or_ambiguous")
    signed_claims = {APP_ID: application_id, TEAM_ID: teams[0], granted[0]: True,
                     BASELINE.ALLOW_JIT: True}
    return {
        "identity": next(iter(identities)), "claims": signed_claims,
        "checks": {"unexpired": True, "macos_platform": True, "explicit_application_match": True,
                   "team_and_prefix_consistent": True, "single_cross_architecture_grant": True,
                   "current_provisioning_device_match": True, "available_development_certificate_match": True},
        "granted_cross_architecture_key": granted[0],
    }


def check_signature(metadata, entitlements, expected_claims):
    """Check effective code claims while withholding profile-bound identifiers."""
    matches = re.findall(r'^CodeDirectory\b[^\r\n]*?\bflags=0x([0-9a-fA-F]+)(?:\(|\s|$)',
                         metadata, re.M)
    if len(matches) != 1:
        raise ControlError("signature_flags_missing")
    flags = int(matches[0], 16)
    if not flags & 0x10000 or flags & 0x2:
        raise ControlError("signature_not_hardened_signed")
    if not re.search(r'^Authority=Apple Development: [^\r\n]+$', metadata, re.M):
        raise ControlError("signature_wrong_category")
    teams = re.findall(r'^TeamIdentifier=([^\r\n]+)$', metadata, re.M)
    if teams != [expected_claims[TEAM_ID]]:
        raise ControlError("signature_team_mismatch")
    try:
        actual = plistlib.loads(entitlements)
    except (ValueError, TypeError, ExpatError, plistlib.InvalidFileException):
        raise ControlError("entitlements_invalid") from None
    if (not isinstance(actual, dict) or actual != expected_claims
            or any(type(actual[key]) is not type(value) for key, value in expected_claims.items())):
        raise ControlError("entitlements_unexpected")
    return {"category": "apple_development", "flags": flags, "hardened_runtime": True,
            "ad_hoc": False, "profile_claims_match": True, "claim_keys": sorted(expected_claims)}


def assess_result(record, mode, layout):
    """Assess observed process and memory semantics independently of CLI exit zero."""
    def failed(reason):
        return {"status": "failed", "reason": reason}

    if (not isinstance(record, dict) or type(record.get("schema_version")) is not int
            or record["schema_version"] != 1 or record.get("record_kind") != "process_capabilities"
            or record.get("requested_mode") != mode or mode not in ("default", "4k")
            or record.get("qualification") != BASELINE.QUALIFICATION):
        return failed("invalid_process_record")
    parent = record.get("parent_observations")
    if not isinstance(parent, dict) or parent.get("qualification") != BASELINE.QUALIFICATION:
        return failed("invalid_parent_observations")
    process = parent.get("process", {})
    signature = parent.get("signature", {})
    if (not isinstance(process, dict) or not isinstance(signature, dict)
            or not BASELINE._observed(process.get("architecture"), "arm64")
            or not BASELINE._observed(process.get("translated"), False)
            or not BASELINE._observed(signature.get("category"), "signed")):
        return failed("native_signed_parent_unconfirmed")
    expected = set(BASELINE.STEP_NAMES) | {"geometry"}
    if mode == "4k":
        expected |= {"subpage", "subpage-fault", "recommit", "recommit-fault"}
    items = record.get("probes")
    if not isinstance(items, list) or len(items) != len(expected):
        return failed("invalid_probe_set")
    probes = {}
    for item in items:
        if (not isinstance(item, dict) or not isinstance(item.get("name"), str)
                or item["name"] not in expected or item["name"] in probes):
            return failed("invalid_probe_set")
        probes[item["name"]] = item
        execution = item.get("execution")
        if (not isinstance(execution, dict)
                or execution.get("page_attribute_called") is not (mode == "4k")
                or type(execution.get("page_attribute_error")) is not int
                or execution["page_attribute_error"] != 0):
            return failed("page_attribute_unconfirmed")
    ordinary = {"schema_version": 1, "record_kind": "baseline_execution",
                "scope": "owned_test_children", "parent_observations": parent,
                "qualification": record["qualification"],
                "probes": [probes[name] for name in BASELINE.STEP_NAMES]}
    assessment = BASELINE.assess_result(ordinary, True)
    if assessment["status"] != "passed":
        return assessment
    if layout and probes["low-address"].get("status") != "passed":
        return failed("layout_low_address_unavailable")
    for name in expected - set(BASELINE.STEP_NAMES):
        probe = probes[name]
        execution = probe["execution"]
        steps = probe.get("steps")
        if (probe.get("status") != "passed" or not isinstance(steps, dict)
                or set(steps) != set(STEP_NAMES[name])
                or execution.get("packet_valid") is not True or execution.get("child_reaped") is not True
                or type(execution.get("error_code")) is not int or execution["error_code"] != 0
                or type(execution.get("stdout_bytes")) is not int or execution["stdout_bytes"] != 160
                or type(execution.get("stderr_bytes")) is not int or execution["stderr_bytes"] != 0
                or type(execution.get("elapsed_ms")) is not int or execution["elapsed_ms"] < 0):
            return failed("invalid_process_probe")
        fault = name.endswith("-fault")
        if fault:
            if (execution.get("outcome") != "signaled" or execution.get("exit_code") is not None
                    or type(execution.get("signal")) is not int
                    or execution["signal"] not in (signal.SIGBUS, signal.SIGSEGV)
                    or probe.get("expected_fault_observed") is not True):
                return failed("process_fault_unconfirmed")
            values = (12288, 7, 0, None, None, None)
            if any(not BASELINE._step(steps[key], "not_run" if value is None else "passed", value)
                   for key, value in zip(STEP_NAMES[name], values)):
                return failed("process_fault_setup_invalid")
            continue
        if (execution.get("outcome") != "exited" or type(execution.get("exit_code")) is not int
                or execution["exit_code"] != 0 or execution.get("signal") is not None
                or probe.get("expected_fault_observed") is not False):
            return failed("unexpected_child_termination")
        if name == "geometry":
            page_size = 4096 if mode == "4k" else 16384
            if (not BASELINE._step(steps["user_page_size"], "passed", page_size)
                    or not BASELINE._step(steps["vm_page_size"], "passed", page_size)
                    or not BASELINE._allocation(steps["kernel_page_size"])):
                return failed("process_page_geometry_mismatch")
        else:
            values = ((12288, 7, 0, 84, 3, 0) if name == "subpage" else
                      (12288, 7, 0, 3, 42, 0))
            if any(not BASELINE._step(steps[key], "passed", value)
                   for key, value in zip(STEP_NAMES[name], values)):
                return failed("process_memory_semantics_mismatch")
    return {"status": "passed", "reason": "expected_process_capabilities_observed"}


def assess_abi_result(record, mode):
    """Require finite ABI/thread evidence without implying runtime qualification."""
    def failed(reason):
        return {"status": "failed", "reason": reason}

    if (not isinstance(record, dict) or type(record.get("schema_version")) is not int
            or record["schema_version"] != 1 or record.get("record_kind") != "abi_capabilities"
            or record.get("scope") != "owned_test_children" or record.get("requested_mode") != mode
            or mode not in ("default", "4k") or record.get("qualification") != BASELINE.QUALIFICATION):
        return failed("invalid_abi_record")
    parent = record.get("parent_observations")
    if not isinstance(parent, dict) or parent.get("qualification") != BASELINE.QUALIFICATION:
        return failed("invalid_parent_observations")
    process, signature = parent.get("process", {}), parent.get("signature", {})
    if (not isinstance(process, dict) or not isinstance(signature, dict)
            or not BASELINE._observed(process.get("architecture"), "arm64")
            or not BASELINE._observed(process.get("translated"), False)
            or not BASELINE._observed(signature.get("category"), "signed")):
        return failed("native_signed_parent_unconfirmed")
    expected = set(ABI_STEP_NAMES) | {"geometry"}
    probes = record.get("probes")
    if not isinstance(probes, list) or len(probes) != len(expected):
        return failed("invalid_abi_probe_set")
    seen = set()
    for probe in probes:
        if (not isinstance(probe, dict) or not isinstance(probe.get("name"), str)
                or probe["name"] not in expected or probe["name"] in seen):
            return failed("invalid_abi_probe_set")
        name = probe["name"]
        seen.add(name)
        execution, steps = probe.get("execution"), probe.get("steps")
        if (probe.get("status") != "passed" or probe.get("expected_fault_observed") is not False
                or not isinstance(execution, dict) or not isinstance(steps, dict)
                or set(steps) != set(STEP_NAMES[name])
                or execution.get("outcome") != "exited" or execution.get("signal") is not None
                or execution.get("packet_valid") is not True or execution.get("child_reaped") is not True
                or execution.get("page_attribute_called") is not (mode == "4k")):
            return failed("invalid_abi_execution")
        for key, wanted in (("exit_code", 0), ("error_code", 0), ("stdout_bytes", 160),
                            ("stderr_bytes", 0), ("page_attribute_error", 0)):
            if type(execution.get(key)) is not int or execution[key] != wanted:
                return failed("invalid_abi_execution")
        if type(execution.get("elapsed_ms")) is not int or execution["elapsed_ms"] < 0:
            return failed("invalid_abi_execution")
        if name == "geometry":
            page = 4096 if mode == "4k" else 16384
            if (not BASELINE._step(steps["user_page_size"], "passed", page)
                    or not BASELINE._step(steps["vm_page_size"], "passed", page)
                    or not BASELINE._allocation(steps["kernel_page_size"])):
                return failed("abi_page_geometry_mismatch")
            continue
        for key, value in zip(ABI_STEP_NAMES[name], ABI_VALUES[name]):
            if value is None:
                observed = steps[key].get("value") if isinstance(steps[key], dict) else None
                if type(observed) is not int or not 0 <= observed <= 10000:
                    return failed("abi_semantics_mismatch")
                value = observed
            if not BASELINE._step(steps[key], "passed", value):
                return failed("abi_semantics_mismatch")
    return {"status": "passed", "reason": "finite_abi_thread_cases_observed"}


def sanitized_result(record):
    """Extend the existing numeric/enum sanitizer to the process-specific names."""
    clean = BASELINE.sanitized_result(record)
    if clean is None or not isinstance(record.get("probes"), list):
        return clean
    clean["requested_mode"] = record.get("requested_mode") if record.get("requested_mode") in ("default", "4k") else "invalid"
    clean["probes"] = []
    for item in record["probes"][:9]:
        if (not isinstance(item, dict) or not isinstance(item.get("name"), str)
                or item["name"] not in STEP_NAMES):
            continue
        # Reuse the trusted base sanitizer for fixed execution fields. The local
        # memory alias never changes the source record or the meaning assessed.
        proxy = {**item, "name": "memory", "steps": {}}
        sanitized = BASELINE.sanitized_result({"probes": [proxy]})["probes"][0]
        sanitized["name"] = item["name"]
        execution = item.get("execution", {})
        if isinstance(execution, dict):
            for key in ("page_attribute_called", "page_attribute_error"):
                value = execution.get(key)
                sanitized["execution"][key] = value if type(value) in (bool, int) else None
        steps = item.get("steps", {})
        for name in STEP_NAMES[item["name"]]:
            value = steps.get(name) if isinstance(steps, dict) else None
            if not isinstance(value, dict):
                continue
            proxy["steps"] = {"allocate": value}
            filtered = BASELINE.sanitized_result({"probes": [proxy]})["probes"][0]["steps"]
            sanitized["steps"][name] = filtered["allocate"]
        clean["probes"].append(sanitized)
    return clean


def _parse_arguments(arguments):
    values = {"--bundle-id": DEFAULT_BUNDLE_ID, "--suite": "process"}
    seen = set()
    if len(arguments) not in (2, 4, 6):
        raise ControlError("expected_profile_argument", "arguments")
    for index in range(0, len(arguments), 2):
        key, value = arguments[index:index + 2]
        if key not in ("--profile", "--bundle-id", "--suite") or key in seen:
            raise ControlError("invalid_arguments", "arguments")
        seen.add(key)
        values[key] = value
    if ("--profile" not in values or values["--suite"] not in ("process", "abi")
            or re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", values["--bundle-id"]) is None):
        raise ControlError("invalid_arguments", "arguments")
    return Path(values["--profile"]).expanduser(), values["--bundle-id"], values["--suite"]


def _provisioning_udid(report):
    result = BASELINE._command(["/usr/sbin/system_profiler", "-json", "SPHardwareDataType"],
                               "device_match", report["commands"], timeout=30)
    try:
        hardware = json.loads(result.stdout, object_pairs_hook=BASELINE._json_object)["SPHardwareDataType"]
        if not isinstance(hardware, list) or not hardware or not isinstance(hardware[0], dict):
            raise ValueError
        values = [value for key, value in hardware[0].items() if "provision" in key.casefold()]
        if len(values) != 1 or not isinstance(values[0], str) or not values[0]:
            raise ValueError
        return values[0]
    except (ValueError, KeyError, TypeError):
        raise ControlError("provisioning_device_unavailable", "device_match") from None


def _verify(target, claims, label, report):
    BASELINE._command(["/usr/bin/codesign", "--verify", "--strict", str(target)],
                      label + ".verify", report["commands"])
    metadata = BASELINE._command(["/usr/bin/codesign", "--display", "--verbose=4", str(target)],
                                 label + ".metadata", report["commands"])
    entitlements = BASELINE._command(["/usr/bin/codesign", "--display", "--entitlements", ":-", str(target)],
                                     label + ".entitlements", report["commands"])
    try:
        result = check_signature(metadata.stderr.decode("utf-8", errors="strict"), entitlements.stdout, claims)
    except UnicodeError:
        raise ControlError("signature_metadata_invalid", label) from None
    return {"strict_verification": "passed", **result}


def _variant(directory, source, label, bundle_id, private, profile_copy, report, suite="process"):
    bundle = directory / (label + ".app")
    executable = bundle / "Contents/MacOS/pear-process-probe"
    executable.parent.mkdir(parents=True)
    control = {"variant": label, "status": "failed", "bundle": bundle.relative_to(ROOT).as_posix(),
               "signatures": {}, "runs": []}
    report["controls"].append(control)
    shutil.copy2(source, executable)
    if BASELINE._hash(executable) != report["input_binary_sha256"][label]:
        raise ControlError("input_changed", label + ".copy")
    embedded = bundle / "Contents/embedded.provisionprofile"
    shutil.copyfile(profile_copy, embedded)
    with (bundle / "Contents/Info.plist").open("wb") as stream:
        plistlib.dump({"CFBundleIdentifier": bundle_id, "CFBundleExecutable": "pear-process-probe",
                      "CFBundleName": "Pear Process Probe", "CFBundlePackageType": "APPL",
                      "CFBundleVersion": "1", "CFBundleShortVersionString": "0.1",
                      "LSMinimumSystemVersion": "26.5"}, stream)
    entitlements = directory / "process-entitlements.plist"
    if not entitlements.exists():
        with entitlements.open("wb") as stream:
            plistlib.dump(private["claims"], stream)
    BASELINE._command(["/usr/bin/codesign", "--force", "--sign", private["identity"],
                       "--options", "runtime", "--timestamp=none", "--entitlements", str(entitlements),
                       "--identifier", bundle_id, str(bundle)], label + ".sign", report["commands"])
    for name, target in (("executable", executable), ("bundle", bundle)):
        control["signatures"][name] = _verify(target, private["claims"], label + "." + name, report)
    if BASELINE._hash(embedded) != report["profile_sha256"]:
        raise ControlError("embedded_profile_changed", label + ".verify_profile")
    control["embedded_profile_matches_validated_copy"] = True
    control["signed_binary_sha256"] = BASELINE._hash(executable)
    for mode in ("default", "4k"):
        arguments = [str(executable), "--mode", mode]
        if suite == "abi":
            arguments += ["--suite", "abi"]
        result = BASELINE._command(arguments, label + ".execute." + mode,
                                   report["commands"], timeout=70 if suite == "abi" else 45 if mode == "4k" else 25,
                                   require_success=False)
        run = {"mode": mode, "status": "failed", "exit_code": result.returncode,
               "stderr_bytes": len(result.stderr)}
        control["runs"].append(run)
        if len(result.stdout) > 131072:
            raise ControlError("process_output_limit", label + ".execute." + mode)
        try:
            record = json.loads(result.stdout, object_pairs_hook=BASELINE._json_object)
        except (ValueError, UnicodeError):
            raise ControlError("process_json_invalid", label + ".execute." + mode) from None
        run["observations"] = sanitized_result(record)
        run["assessment"] = assess_abi_result(record, mode) if suite == "abi" else assess_result(record, mode, label == "layout")
        if result.returncode != 0 or result.stderr:
            raise ControlError("process_execution_failed", label + ".execute." + mode)
        if run["assessment"]["status"] != "passed":
            raise ControlError(run["assessment"]["reason"], label + ".assess." + mode)
        run["status"] = "passed"
    control["status"] = "passed"


def main():
    report = {"schema_version": 1, "record_kind": "provisioned_process_control",
              "scope": "local_signed_test_bundles", "status": "failed",
              "identity_category": "apple_development", "timestamp": "none",
              "notarization": "not_assessed", "qualification": dict(BASELINE.QUALIFICATION),
              "profile_checks": {}, "input_binary_sha256": {}, "controls": [], "commands": []}
    directory = None
    stage = "arguments"
    try:
        profile_path, bundle_id, suite = _parse_arguments(sys.argv[1:])
        if suite == "abi":
            report["record_kind"] = "provisioned_abi_control"
        stage = "prepare"
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            raise ControlError("native_apple_silicon_required", stage)
        sources = {"standard": BUILD / "pear-process-probe", "layout": BUILD / "pear-process-probe-layout"}
        for label, source in sources.items():
            if not source.is_file() or not os.access(source, os.X_OK):
                raise ControlError("build_required", stage)
            report["input_binary_sha256"][label] = BASELINE._hash(source)
            architectures = BASELINE._command(["/usr/bin/lipo", "-archs", str(source)],
                                               "input_architecture." + label, report["commands"])
            if architectures.stdout.strip() != b"arm64":
                raise ControlError("arm64_only_binary_required", stage)
        directory = Path(tempfile.mkdtemp(prefix="provisioned-control-", dir=BUILD))
        report["output_directory"] = directory.relative_to(ROOT).as_posix()
        stage = "profile_decode"
        profile_copy = directory / "validated.provisionprofile"
        shutil.copyfile(profile_path, profile_copy)
        report["profile_sha256"] = BASELINE._hash(profile_copy)
        decoded = BASELINE._command(["/usr/bin/security", "cms", "-D", "-i", str(profile_copy)],
                                    stage, report["commands"])
        try:
            profile = plistlib.loads(decoded.stdout)
        except (ValueError, TypeError, ExpatError, plistlib.InvalidFileException):
            raise ControlError("profile_plist_invalid", stage) from None
        report["profile_checks"]["cms_decode_succeeded"] = True
        stage = "profile_match"
        identities = BASELINE._command(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"],
                                       "identity_match", report["commands"])
        try:
            private = validate_profile(profile, identities.stdout.decode("utf-8", errors="strict"),
                                       _provisioning_udid(report), bundle_id)
        except UnicodeError:
            raise ControlError("identity_output_invalid", stage) from None
        report["profile_checks"].update(private["checks"])
        report["granted_cross_architecture_key"] = private["granted_cross_architecture_key"]
        report["effective_claim_keys"] = sorted(private["claims"])
        for label, source in sources.items():
            stage = label
            _variant(directory, source, label, bundle_id, private, profile_copy, report, suite)
        for label, source in sources.items():
            if BASELINE._hash(source) != report["input_binary_sha256"][label]:
                raise ControlError("source_binary_changed", "final_input_check")
        report["status"] = "passed"
    except ControlError as error:
        report["error"] = {"stage": error.stage or stage, "code": error.code}
    except OSError as error:
        report["error"] = {"stage": stage, "code": "filesystem_error", "error_code": error.errno}
    except KeyboardInterrupt:
        report["error"] = {"stage": stage, "code": "interrupted"}
    except Exception:
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

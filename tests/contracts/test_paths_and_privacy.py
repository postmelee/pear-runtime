"""Independent path and disclosure checks for the public contract interface."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TEST_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = TEST_ROOT.parents[1]
VALIDATOR = TEST_ROOT / "validate.py"
RESEARCH_EXAMPLE = REPOSITORY_ROOT / "runtime/contracts/examples/research-lock.json"
SECRET = "PRIVATE_MARKER_DO_NOT_DISCLOSE_7b9676"


class PathAndPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pear-contract-private-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.bundle = self.base / "bundle"
        self.bundle.mkdir()
        self.entry = "record.json"
        self.example = RESEARCH_EXAMPLE.read_bytes()
        (self.bundle / self.entry).write_bytes(self.example)

    def command(self, *, entry=None, root=None, extra=()):
        return [sys.executable, str(VALIDATOR), "--bundle-root",
                str(self.bundle if root is None else root), "--entry",
                self.entry if entry is None else entry, "--context", "research",
                "--purpose", "inspect", *extra]

    def invoke(self, *, entry=None, root=None, extra=()):
        result = subprocess.run(self.command(entry=entry, root=root, extra=extra),
                                capture_output=True, timeout=5, check=False)
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 8192)
        self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)
        self.assertNotIn(str(self.base).encode(), result.stdout + result.stderr)
        self.assertNotIn(b"Traceback", result.stdout + result.stderr)
        self.assertEqual(result.stderr, b"")
        report = json.loads(result.stdout)
        self.assertIs(report["evaluation_only"], True)
        self.assertIsInstance(report["outcome_codes"], list)
        self.assertEqual(report["outcome_codes"], sorted(set(report["outcome_codes"])))
        return result.returncode, report

    def assert_rejected(self, expected_code, **kwargs):
        code, report = self.invoke(**kwargs)
        self.assertEqual(code, 1)
        self.assertIs(report["record_valid"], False)
        self.assertIs(report["eligible"], False)
        self.assertEqual(report["outcome_codes"], [expected_code])

    def test_control_research_inspection_is_valid(self):
        code, report = self.invoke()
        self.assertEqual(code, 0)
        self.assertIs(report["record_valid"], True)

    def test_entry_path_has_no_ambient_filesystem_interpretation(self):
        outside = self.base / (SECRET + ".json")
        outside.write_bytes(self.example)
        cases = [str(outside), "../" + outside.name,
                 "sub/../../" + outside.name, "./record.json",
                 "sub/../record.json", "sub//record.json",
                 "C:\\" + SECRET + ".json", "\\\\server\\" + SECRET,
                 "https://example.invalid/" + SECRET]
        for entry in cases:
            with self.subTest(entry_kind=cases.index(entry)):
                self.assert_rejected("invalid_path", entry=entry)

    def test_entry_symlink_to_external_file_is_rejected(self):
        outside = self.base / (SECRET + ".json")
        outside.write_bytes(self.example)
        (self.bundle / "linked.json").symlink_to(outside)
        self.assert_rejected("unsafe_or_missing_path", entry="linked.json")

    def test_entry_symlink_to_internal_file_is_rejected(self):
        (self.bundle / "linked.json").symlink_to(self.entry)
        self.assert_rejected("unsafe_or_missing_path", entry="linked.json")

    def test_intermediate_directory_symlink_is_rejected(self):
        internal = self.bundle / "real"
        internal.mkdir()
        (internal / self.entry).write_bytes(self.example)
        (self.bundle / "alias").symlink_to(internal, target_is_directory=True)
        self.assert_rejected("unsafe_or_missing_path", entry="alias/record.json")

    def test_symlink_loop_is_bounded_and_rejected(self):
        (self.bundle / "loop.json").symlink_to("loop.json")
        self.assert_rejected("unsafe_or_missing_path", entry="loop.json")

    def test_directory_entry_is_rejected(self):
        (self.bundle / "directory.json").mkdir()
        self.assert_rejected("not_regular_file", entry="directory.json")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Requires a POSIX FIFO")
    def test_fifo_entry_is_rejected_without_waiting_for_a_writer(self):
        os.mkfifo(self.bundle / "pipe.json")
        self.assert_rejected("not_regular_file", entry="pipe.json")

    def test_parser_failures_do_not_echo_private_values(self):
        cases = [
            ('{"' + SECRET + '":').encode(),
            ('{"record_id":"' + SECRET + '","record_id":"duplicate"}').encode(),
            b'{"value":"' + SECRET.encode() + b'\xff"}',
            ('{"value":"' + SECRET + '","number":NaN}').encode(),
            ('{"value":"' + SECRET + '","number":1e9999}').encode(),
            ("[" * 34 + '"' + SECRET + '"' + "]" * 34).encode(),
            b'\xef\xbb\xbf' + self.example,
            b'{"record_id":"\\ud800"}',
            b'{"record_id":"\\udfff"}',
            ('{"value":"' + SECRET + '","number":-Infinity}').encode(),
            ('{"value":"' + SECRET + '","number":' + '9' * 5000 + '}').encode(),
        ]
        for surrogate in ("\ud800", "\udfff"):
            record = json.loads(self.example)
            record["compatibility_family"]["reason"] = surrogate
            cases.append(json.dumps(record).encode("utf-8"))
        codes = ["invalid_json", "duplicate_key", "invalid_utf8",
                 "unsupported_number", "unsupported_number", "json_depth_limit",
                 "invalid_json", "invalid_string", "invalid_string",
                 "unsupported_number", "unsupported_number", "invalid_string",
                 "invalid_string"]
        self.assertEqual(len(cases), len(codes))
        for index, (raw, code) in enumerate(zip(cases, codes, strict=True)):
            with self.subTest(case=index):
                (self.bundle / self.entry).write_bytes(raw)
                self.assert_rejected(code)

    def test_schema_failures_do_not_echo_private_values(self):
        record = json.loads(self.example)
        record[SECRET] = {"raw_environment": {"STEAM_PASSWORD": SECRET}}
        (self.bundle / self.entry).write_text(json.dumps(record), encoding="utf-8")
        self.assert_rejected("schema_invalid")

    def test_oversize_file_does_not_echo_its_content(self):
        (self.bundle / self.entry).write_bytes(SECRET.encode() + b" " * 262145)
        self.assert_rejected("json_size_limit")

    def test_embedded_policy_cannot_silently_authorize_input(self):
        record = json.loads(self.example)
        record["policy"] = {"trusted_reviewers": [SECRET], "supported": True}
        (self.bundle / self.entry).write_text(json.dumps(record), encoding="utf-8")
        self.assert_rejected("schema_invalid")

    def test_cli_misuse_does_not_echo_private_arguments(self):
        for extra in [("--context", SECRET), ("--" + SECRET,)]:
            with self.subTest(case=len(extra)):
                result = subprocess.run(self.command(extra=extra), capture_output=True,
                                        timeout=5, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertLessEqual(len(result.stdout) + len(result.stderr), 8192)
                self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)
                self.assertNotIn(str(self.base).encode(), result.stdout + result.stderr)
                self.assertNotIn(b"Traceback", result.stdout + result.stderr)

    def test_inspection_leaves_bundle_and_unrelated_sentinel_unchanged(self):
        sentinel = self.base / "unrelated-sentinel"
        sentinel.write_bytes(SECRET.encode())
        before = {p.relative_to(self.bundle): p.read_bytes()
                  for p in self.bundle.rglob("*") if p.is_file()}
        self.invoke()
        after = {p.relative_to(self.bundle): p.read_bytes()
                 for p in self.bundle.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(sentinel.read_bytes(), SECRET.encode())


class FixturePathAndPrivacyTests(unittest.TestCase):
    """Exercise ownership rules on an internally consistent synthetic record DAG."""

    def setUp(self):
        from fixture_factory import build_fixture
        self.temporary = tempfile.TemporaryDirectory(prefix="pear-contract-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.bundle = self.base / "bundle"
        self.fixture = build_fixture(self.bundle)

    def evaluate(self, name="request", purpose="fixture_launch"):
        from validate import validate_bundle
        report = validate_bundle(self.bundle, self.fixture["paths"][name],
                                 context="fixture", purpose=purpose,
                                 policy=self.fixture["policy"])
        encoded = json.dumps(report).encode()
        self.assertLessEqual(len(encoded), 8192)
        self.assertNotIn(SECRET.encode(), encoded)
        self.assertNotIn(str(self.base).encode(), encoded)
        self.assertIs(report["evaluation_only"], True)
        return report

    def change(self, name, mutate, *, refresh_cache=True):
        from fixture_factory import rewrite
        rewrite(self.bundle, self.fixture, name, mutate)
        if refresh_cache and name in {"lock", "artifact", "profile"}:
            def synchronize(request):
                for field in ("lock", "artifact", "profile"):
                    request["cache_identity"][field + "_digest"] = self.fixture["refs"][field]["digest"]["value"]
            rewrite(self.bundle, self.fixture, "request", synchronize)

    def denied(self, expected_code, **kwargs):
        report = self.evaluate(**kwargs)
        self.assertIs(report["eligible"], False)
        self.assertIn(expected_code, report["outcome_codes"])
        self.assertNotIn("validation_error", report["outcome_codes"])
        return report

    def test_positive_fixture_control(self):
        report = self.evaluate()
        self.assertIs(report["record_valid"], True)
        self.assertIs(report["eligible"], True)

    def test_mutable_root_cannot_equal_immutable_runtime_root(self):
        self.change("request", lambda r: r["roots"].update(prefix=r["roots"]["runtime"]))
        self.denied("overlapping_roots")

    def test_mutable_root_cannot_be_inside_immutable_runtime(self):
        self.change("request", lambda r: r["roots"].update(cache=r["roots"]["runtime"] + "/cache"))
        self.denied("overlapping_roots")

    def test_mutable_root_cannot_contain_immutable_runtime(self):
        self.change("request", lambda r: r["roots"].update(prefix="state"))
        self.denied("overlapping_roots")

    def test_mutable_prefix_cannot_cover_an_immutable_payload(self):
        self.change("profile", lambda r: r["operations"][0].update(path="payload.txt"))
        self.change("request", lambda r: r["roots"].update(prefix="blobs"))
        self.denied("immutable_path_overlap")

    def test_mutable_logs_cannot_cover_immutable_contract_records(self):
        self.change("request", lambda r: r["roots"].update(logs="records"))
        self.denied("immutable_path_overlap")

    def test_case_alias_cannot_expose_an_immutable_payload_to_prefix_writes(self):
        if not (self.bundle / "BLOBS").is_dir():
            self.skipTest("Filesystem does not expose the tested case alias")
        self.change("profile", lambda r: r["operations"][0].update(path="payload.txt"))
        self.change("request", lambda r: r["roots"].update(prefix="BLOBS"))
        self.denied("immutable_path_overlap")

    def test_existing_mutable_hardlink_cannot_alias_immutable_payload(self):
        target = self.bundle / "state/prefix/config/options.json"
        target.parent.mkdir(parents=True)
        os.link(self.bundle / self.fixture["payload"]["path"], target)
        self.denied("immutable_path_overlap")

    def test_prefix_family_mismatch_cannot_be_repaired_by_matching_bytes(self):
        self.change("request", lambda r: r.update(prefix_family="unrelated-family"))
        self.denied("incompatible_family")

    def test_cache_cannot_reuse_a_different_translator(self):
        self.change("request", lambda r: r["cache_identity"].update(translator_component="unrelated-translator"))
        self.denied("cache_identity_mismatch")

    def test_cache_cannot_reuse_a_different_abi(self):
        self.change("request", lambda r: r["cache_identity"].update(abi="unrelated-abi"))
        self.denied("cache_identity_mismatch")

    def test_cache_cannot_reuse_a_different_cpu_feature_set(self):
        self.change("request", lambda r: r["cache_identity"].update(cpu_features=["unrelated-cpu-feature"]))
        self.denied("cache_identity_mismatch")

    def test_blob_symlink_cannot_substitute_identical_bytes(self):
        payload = self.bundle / self.fixture["payload"]["path"]
        outside = self.base / (SECRET + ".txt")
        outside.write_bytes(payload.read_bytes())
        payload.unlink()
        payload.symlink_to(outside)
        self.denied("unsafe_or_missing_path")

    def test_record_symlink_cannot_substitute_identical_bytes(self):
        profile = self.bundle / self.fixture["paths"]["profile"]
        outside = self.base / (SECRET + ".json")
        outside.write_bytes(profile.read_bytes())
        profile.unlink()
        profile.symlink_to(outside)
        self.denied("unsafe_or_missing_path")

    def test_guest_drive_path_is_not_a_host_relative_path(self):
        self.change("profile", lambda r: r["executable"].update(path="C:\\" + SECRET + ".exe"))
        self.denied("invalid_path")

    def test_guest_drive_relative_path_is_rejected(self):
        self.change("profile", lambda r: r["executable"].update(path="C:" + SECRET + ".exe"))
        self.denied("invalid_path")

    def test_setting_cannot_escape_prefix(self):
        self.change("profile", lambda r: r["operations"][0].update(path="../" + SECRET))
        self.denied("invalid_path")

    def test_setting_cannot_target_immutable_root(self):
        self.change("profile", lambda r: r["operations"][0].update(root="runtime"))
        self.denied("schema_invalid")

    def test_profile_cannot_supply_an_arbitrary_command(self):
        self.change("profile", lambda r: r["operations"].append({"operation": "shell", "command": SECRET}))
        self.denied("schema_invalid")

    def test_environment_cannot_override_dynamic_loader(self):
        self.change("profile", lambda r: r["environment"].append({"key": "DYLD_INSERT_LIBRARIES", "value": SECRET}))
        self.denied("schema_invalid")

    def test_environment_cannot_have_duplicate_allowed_keys(self):
        self.change("profile", lambda r: r["environment"].extend([
            {"key": "PEAR_FIXTURE_VALUE", "value": "first"},
            {"key": "PEAR_FIXTURE_VALUE", "value": SECRET}]))
        self.denied("duplicate_identity")

    def test_arguments_cannot_contain_nul(self):
        self.change("profile", lambda r: r["arguments"].append("\x00" + SECRET))
        self.denied("invalid_string")

    def test_environment_values_cannot_contain_nul(self):
        self.change("profile", lambda r: r["environment"].append({"key": "PEAR_FIXTURE_VALUE", "value": "\x00" + SECRET}))
        self.denied("invalid_string")

    def test_public_partial_record_cannot_enable_fixture_launch(self):
        self.change("request", lambda r: r.update(disclosure={"mode": "public_partial", "withheld": ["private_configuration"], "origin_token": "private-original"}))
        self.denied("partial_bundle")

    def test_direct_api_nul_entry_is_bounded(self):
        from validate import validate_bundle
        report = validate_bundle(self.bundle, "bad\x00" + SECRET, context="fixture", purpose="inspect")
        self.assertIs(report["record_valid"], False)
        self.assertIs(report["eligible"], False)
        self.assertEqual(report["outcome_codes"], ["invalid_path"])
        self.assertNotIn(SECRET, json.dumps(report))


if __name__ == "__main__":
    unittest.main()

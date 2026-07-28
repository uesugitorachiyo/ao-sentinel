#!/usr/bin/env python3
"""Regression coverage for the Sentinel release rehearsal verifier."""

import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts" / "release-rehearsal-verify.py"
SOURCE = "0123456789abcdef0123456789abcdef01234567"


class ReleaseVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.candidates = self.root / "candidates"
        self.candidates.mkdir()
        self.manifest = self.root / "manifest.json"
        self.out = self.root / "out"
        self._write_manifest()
        for label, extension, binary, binary_format in (
            ("linux-x86_64", "tar.gz", "ao-sentinel", "elf"),
            ("macos-aarch64", "tar.gz", "ao-sentinel", "macho"),
            ("windows-x86_64", "zip", "ao-sentinel.exe", "pe"),
        ):
            self._write_candidate(label, extension, binary, binary_format)

    def tearDown(self):
        self.temp.cleanup()

    def _write_manifest(self):
        document = {
            "schema_version": "ao.sentinel.release-manifest.v0.1",
            "repository": "ao-sentinel",
            "version": "0.1.0",
            "tag": "v0.1.0",
            "source_commit": SOURCE,
            "release_notes_path": "docs/release/V0.1.0-OPERATOR-CLOSEOUT.md",
            "release_notes_sha256": "a" * 64,
            "targets": [
                {"target_label": "linux-x86_64", "archive": "ao-sentinel-0.1.0-linux-x86_64.tar.gz", "binary": "ao-sentinel", "binary_format": "elf", "goos": "linux", "goarch": "amd64"},
                {"target_label": "macos-aarch64", "archive": "ao-sentinel-0.1.0-macos-aarch64.tar.gz", "binary": "ao-sentinel", "binary_format": "macho", "goos": "darwin", "goarch": "arm64"},
                {"target_label": "windows-x86_64", "archive": "ao-sentinel-0.1.0-windows-x86_64.zip", "binary": "ao-sentinel.exe", "binary_format": "pe", "goos": "windows", "goarch": "amd64"},
            ],
        }
        self.manifest.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")

    def _write_candidate(self, label, extension, binary, binary_format):
        directory = self.candidates / label
        directory.mkdir()
        archive = f"ao-sentinel-0.1.0-{label}.{extension}"
        version = json.dumps({"schema_version": "ao.sentinel.version.v0.1", "version": "0.1.0", "source_commit": SOURCE, "provider_calls": False}, sort_keys=True).encode()
        provenance = json.dumps({"schema_version": "ao.sentinel.release-candidate-provenance.v0.1", "repository": "ao-sentinel", "version": "0.1.0", "source_commit": SOURCE, "target_label": label, "binary_format": binary_format, "provider_calls": False, "workflow_identity": ".github/workflows/release-rehearsal.yml@" + SOURCE}, sort_keys=True).encode()
        smoke = json.dumps({"schema_version": "ao.sentinel.release-functional-smoke.v0.1", "command": "target validate", "status": "passed", "provider_calls": False}, sort_keys=True).encode()
        binary_bytes = {
            "elf": b"\x7fELF\x02\x01" + b"\0" * 12 + b"\x3e\0",
            "macho": b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01",
            "pe": b"MZ" + b"\0" * 58 + b"\x80\0\0\0" + b"\0" * 64 + b"PE\0\0\x64\x86",
        }[binary_format]
        files = {binary: binary_bytes, "LICENSE": b"license", "NOTICE": b"notice", "version-readback.json": version, "provenance.json": provenance, "functional-smoke.json": smoke, "sbom.json": b"{}"}
        archive_path = directory / archive
        if extension == "zip":
            with zipfile.ZipFile(archive_path, "w") as bundle:
                for name, data in files.items():
                    bundle.writestr(name, data)
        else:
            with tarfile.open(archive_path, "w:gz") as bundle:
                for name, data in files.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    bundle.addfile(info, io.BytesIO(data))
        archive_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        summary = {"schema_version": "ao.sentinel.release-candidate.v0.1", "target_label": label, "archive": archive, "archive_sha256": archive_hash, "binary": binary, "binary_format": binary_format, "goos": "windows" if binary_format == "pe" else ("darwin" if binary_format == "macho" else "linux"), "goarch": "arm64" if binary_format == "macho" else "amd64", "repository": "ao-sentinel", "version": "0.1.0", "tag": "v0.1.0", "source_commit": SOURCE}
        (directory / "candidate.json").write_text(json.dumps(summary, sort_keys=True), encoding="utf-8")

    def run_verify(self, *extra):
        return subprocess.run(["python3", str(VERIFY), "assemble", "--manifest", str(self.manifest), "--candidates", str(self.candidates), "--out", str(self.out), "--dry-run", "true", *extra], text=True, capture_output=True)

    def test_assemble_valid_candidates_and_dry_run_boundary(self):
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        boundary = json.loads((self.out / "dry-run-boundary.json").read_text())
        self.assertEqual(boundary, {"publication_status": "not_attempted", "public_upload_attempted": False, "release_creation_attempted": False, "tag_creation_attempted": False})

    def test_rejects_altered_archive_digest(self):
        summary_path = self.candidates / "linux-x86_64" / "candidate.json"
        summary = json.loads(summary_path.read_text())
        summary["archive_sha256"] = "0" * 64
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
        result = self.run_verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive SHA-256 mismatch", result.stderr)

    def test_live_verification_accepts_exact_prior_dry_run_plan(self):
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = self.out / "immutable-promotion-plan.json"
        digest = hashlib.sha256(plan.read_bytes()).hexdigest()
        verify = subprocess.run([
            "python3", str(VERIFY), "verify", "--manifest", str(self.manifest),
            "--candidates", str(self.candidates), "--plan", str(plan),
            "--dry-run", "false", "--expected-plan-digest", digest,
        ], text=True, capture_output=True)
        self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_rejects_missing_candidate(self):
        for path in (self.candidates / "windows-x86_64").iterdir():
            path.unlink()
        (self.candidates / "windows-x86_64").rmdir()
        result = self.run_verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("candidate target set", result.stderr)

    def test_rejects_wrong_source_version_and_duplicate_manifest_key(self):
        original = json.loads(self.manifest.read_text())
        for field, value in (("source_commit", "f" * 40), ("version", "0.1.1")):
            mutated = deepcopy(original)
            mutated[field] = value
            self.manifest.write_text(json.dumps(mutated), encoding="utf-8")
            result = self.run_verify()
            self.assertNotEqual(result.returncode, 0, field)
        self.manifest.write_text(
            '{"schema_version":"ao.sentinel.release-manifest.v0.1",'
            '"schema_version":"ao.sentinel.release-manifest.v0.1"}',
            encoding="utf-8",
        )
        result = self.run_verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate JSON key", result.stderr)

    def test_rejects_wrong_binary_format_and_unexpected_archive_member(self):
        summary_path = self.candidates / "linux-x86_64" / "candidate.json"
        summary = json.loads(summary_path.read_text())
        archive_path = summary_path.parent / summary["archive"]
        with tarfile.open(archive_path, "r:gz") as bundle:
            files = {
                member.name: bundle.extractfile(member).read()
                for member in bundle.getmembers()
            }
        files["ao-sentinel"] = b"not-elf"
        files["unexpected.txt"] = b"unexpected"
        with tarfile.open(archive_path, "w:gz") as bundle:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                bundle.addfile(info, io.BytesIO(data))
        summary["archive_sha256"] = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
        result = self.run_verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive file inventory mismatch", result.stderr)

    def test_rejects_wrong_binary_format_with_exact_archive_inventory(self):
        summary_path = self.candidates / "linux-x86_64" / "candidate.json"
        summary = json.loads(summary_path.read_text())
        archive_path = summary_path.parent / summary["archive"]
        with tarfile.open(archive_path, "r:gz") as bundle:
            files = {
                member.name: bundle.extractfile(member).read()
                for member in bundle.getmembers()
            }
        files["ao-sentinel"] = b"not-elf"
        with tarfile.open(archive_path, "w:gz") as bundle:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                bundle.addfile(info, io.BytesIO(data))
        summary["archive_sha256"] = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
        result = self.run_verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("candidate binary is not ELF x86_64", result.stderr)

    def test_rejects_incomplete_or_altered_provenance(self):
        summary_path = self.candidates / "linux-x86_64" / "candidate.json"
        summary = json.loads(summary_path.read_text())
        archive_path = summary_path.parent / summary["archive"]
        with tarfile.open(archive_path, "r:gz") as bundle:
            files = {
                member.name: bundle.extractfile(member).read()
                for member in bundle.getmembers()
            }
        provenance = json.loads(files["provenance.json"])
        provenance.pop("schema_version")
        provenance["workflow_identity"] = ".github/workflows/release-rehearsal.yml@" + ("f" * 40)
        files["provenance.json"] = json.dumps(provenance, sort_keys=True).encode()
        with tarfile.open(archive_path, "w:gz") as bundle:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                bundle.addfile(info, io.BytesIO(data))
        summary["archive_sha256"] = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
        result = self.run_verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("candidate provenance binding mismatch", result.stderr)

    def test_rejects_altered_plan_even_with_matching_expected_digest(self):
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = self.out / "immutable-promotion-plan.json"
        altered = json.loads(plan.read_text())
        altered["source_commit"] = "f" * 40
        plan.write_text(json.dumps(altered, sort_keys=True, separators=(",", ":")) + "\n")
        digest = hashlib.sha256(plan.read_bytes()).hexdigest()
        verify = subprocess.run([
            "python3", str(VERIFY), "verify", "--manifest", str(self.manifest),
            "--candidates", str(self.candidates), "--plan", str(plan),
            "--dry-run", "false", "--expected-plan-digest", digest,
        ], text=True, capture_output=True)
        self.assertNotEqual(verify.returncode, 0)
        self.assertIn("promotion plan binding mismatch", verify.stderr)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Strict offline verifier for AO Sentinel release-rehearsal candidates."""

import argparse
import hashlib
import json
import struct
import sys
import tarfile
import zipfile
from pathlib import Path


MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MANIFEST_KEYS = {
    "schema_version", "repository", "version", "tag", "source_commit",
    "release_notes_path", "release_notes_sha256", "targets",
}
CANDIDATE_KEYS = {
    "schema_version", "target_label", "archive", "archive_sha256", "binary",
    "binary_format", "goos", "goarch", "repository", "version", "tag", "source_commit",
}
TARGETS = {
    "linux-x86_64": ("ao-sentinel-{version}-linux-x86_64.tar.gz", "ao-sentinel", "elf", "linux", "amd64"),
    "macos-aarch64": ("ao-sentinel-{version}-macos-aarch64.tar.gz", "ao-sentinel", "macho", "darwin", "arm64"),
    "windows-x86_64": ("ao-sentinel-{version}-windows-x86_64.zip", "ao-sentinel.exe", "pe", "windows", "amd64"),
}


class VerificationError(Exception):
    pass


def fail(message):
    raise VerificationError(message)


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path, label):
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            value = json.load(handle, object_pairs_hook=strict_object)
    except (OSError, json.JSONDecodeError, VerificationError) as error:
        fail(f"invalid {label}: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_keys(value, expected, label):
    if set(value) != set(expected):
        fail(f"{label} keys mismatch: expected {sorted(expected)}, got {sorted(value)}")


def require_sha256(value, label):
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        fail(f"{label} must be a lowercase SHA-256")


def validate_manifest(manifest):
    require_keys(manifest, MANIFEST_KEYS, "manifest")
    if manifest["schema_version"] != "ao.sentinel.release-manifest.v0.1":
        fail("manifest schema_version mismatch")
    if manifest["repository"] != "ao-sentinel":
        fail("manifest repository mismatch")
    version, tag, source = manifest["version"], manifest["tag"], manifest["source_commit"]
    if not isinstance(version, str) or not version or tag != "v" + version:
        fail("manifest version/tag mismatch")
    if not isinstance(source, str) or len(source) != 40 or any(ch not in "0123456789abcdef" for ch in source):
        fail("manifest source_commit must be a lowercase 40-character SHA")
    if manifest["release_notes_path"] != f"docs/release/V{version}-OPERATOR-CLOSEOUT.md":
        fail("manifest release notes path mismatch")
    require_sha256(manifest["release_notes_sha256"], "manifest release_notes_sha256")
    targets = manifest["targets"]
    if not isinstance(targets, list) or len(targets) != 3:
        fail("manifest must contain exactly three targets")
    actual = set()
    for target in targets:
        if not isinstance(target, dict) or set(target) != {"target_label", "archive", "binary", "binary_format", "goos", "goarch"}:
            fail("manifest target fields mismatch")
        label = target["target_label"]
        if label not in TARGETS or label in actual:
            fail("manifest target labels must be unique and exact")
        archive, binary, binary_format, goos, goarch = TARGETS[label]
        expected = {"target_label": label, "archive": archive.format(version=version), "binary": binary, "binary_format": binary_format, "goos": goos, "goarch": goarch}
        if target != expected:
            fail(f"manifest target {label} mismatch")
        actual.add(label)
    if actual != set(TARGETS):
        fail("manifest target set mismatch")
    return {target["target_label"]: target for target in targets}


def read_archive(path, extension):
    files = {}
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        fail("archive exceeds size limit")
    try:
        if extension == "zip":
            with zipfile.ZipFile(path) as archive:
                members = archive.infolist()
                for member in members:
                    if member.is_dir() or member.filename in files or "/" in member.filename or "\\" in member.filename or member.filename.startswith("."):
                        fail("unsafe or duplicate zip member")
                    data = archive.read(member)
                    if len(data) > MAX_MEMBER_BYTES:
                        fail("archive member exceeds size limit")
                    files[member.filename] = data
        else:
            with tarfile.open(path, "r:gz") as archive:
                for member in archive.getmembers():
                    if not member.isfile() or member.name in files or "/" in member.name or "\\" in member.name or member.name.startswith("."):
                        fail("unsafe or duplicate tar member")
                    if member.size > MAX_MEMBER_BYTES:
                        fail("archive member exceeds size limit")
                    handle = archive.extractfile(member)
                    if handle is None:
                        fail("tar member cannot be read")
                    data = handle.read(MAX_MEMBER_BYTES + 1)
                    if len(data) != member.size:
                        fail("tar member size mismatch")
                    files[member.name] = data
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        fail(f"invalid candidate archive: {error}")
    return files


def load_json_bytes(raw, label):
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, VerificationError) as error:
        fail(f"invalid {label}: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def verify_binary(raw, binary_format):
    if binary_format == "elf":
        if len(raw) < 20 or raw[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", raw, 18)[0] != 0x3E:
            fail("candidate binary is not ELF x86_64")
    elif binary_format == "macho":
        if len(raw) < 8 or struct.unpack_from("<I", raw, 0)[0] != 0xFEEDFACF or struct.unpack_from("<I", raw, 4)[0] != 0x0100000C:
            fail("candidate binary is not Mach-O arm64")
    elif binary_format == "pe":
        if len(raw) < 0x46 or raw[:2] != b"MZ":
            fail("candidate binary is not PE x86_64")
        offset = struct.unpack_from("<I", raw, 0x3C)[0]
        if offset + 6 > len(raw) or raw[offset:offset + 4] != b"PE\0\0" or struct.unpack_from("<H", raw, offset + 4)[0] != 0x8664:
            fail("candidate binary is not PE x86_64")
    else:
        fail("unknown candidate binary format")


def validate_candidate(summary_path, target, manifest):
    summary = load_json(summary_path, "candidate summary")
    require_keys(summary, CANDIDATE_KEYS, "candidate summary")
    if summary["schema_version"] != "ao.sentinel.release-candidate.v0.1":
        fail("candidate schema mismatch")
    for key in ("target_label", "archive", "binary", "binary_format", "goos", "goarch"):
        if summary[key] != target[key]:
            fail(f"candidate {key} mismatch")
    for key in ("repository", "version", "tag", "source_commit"):
        if summary[key] != manifest[key]:
            fail(f"candidate {key} binding mismatch")
    require_sha256(summary["archive_sha256"], "candidate archive_sha256")
    archive_path = summary_path.parent / summary["archive"]
    if not archive_path.is_file():
        fail("candidate archive missing")
    if sha256_file(archive_path) != summary["archive_sha256"]:
        fail("archive SHA-256 mismatch")
    files = read_archive(archive_path, "zip" if summary["archive"].endswith(".zip") else "tar.gz")
    expected = {summary["binary"], "LICENSE", "NOTICE", "version-readback.json", "provenance.json", "functional-smoke.json", "sbom.json"}
    if set(files) != expected:
        fail("candidate archive file inventory mismatch")
    verify_binary(files[summary["binary"]], summary["binary_format"])
    version = load_json_bytes(files["version-readback.json"], "version readback")
    if version != {"schema_version": "ao.sentinel.version.v0.1", "version": manifest["version"], "source_commit": manifest["source_commit"], "provider_calls": False}:
        fail("embedded version identity mismatch")
    smoke = load_json_bytes(files["functional-smoke.json"], "functional smoke")
    if smoke != {"schema_version": "ao.sentinel.release-functional-smoke.v0.1", "command": "target validate", "status": "passed", "provider_calls": False}:
        fail("functional smoke mismatch")
    provenance = load_json_bytes(files["provenance.json"], "provenance")
    expected_provenance = {
        "schema_version": "ao.sentinel.release-candidate-provenance.v0.1",
        "repository": manifest["repository"],
        "version": manifest["version"],
        "source_commit": manifest["source_commit"],
        "target_label": target["target_label"],
        "binary_format": target["binary_format"],
        "provider_calls": False,
        "workflow_identity": ".github/workflows/release-rehearsal.yml@" + manifest["source_commit"],
    }
    if provenance != expected_provenance:
        fail("candidate provenance binding mismatch")
    return summary


def discover_candidates(root):
    found = list(Path(root).rglob("candidate.json"))
    if len(found) > 3:
        fail("too many candidate summaries")
    return found


def plan_document(manifest, manifest_digest, candidates):
    return {
        "schema_version": "ao.sentinel.release-rehearsal-plan.v0.1",
        "repository": manifest["repository"], "version": manifest["version"], "tag": manifest["tag"],
        "source_commit": manifest["source_commit"], "approved_manifest_sha256": manifest_digest,
        "candidates": sorted(candidates, key=lambda candidate: candidate["target_label"]),
    }


def validate_all(manifest_path, candidates_root):
    manifest = load_json(manifest_path, "manifest")
    targets = validate_manifest(manifest)
    found = discover_candidates(candidates_root)
    candidates = []
    seen = set()
    for path in found:
        label = load_json(path, "candidate summary").get("target_label")
        if label not in targets or label in seen:
            fail("candidate target set mismatch")
        candidates.append(validate_candidate(path, targets[label], manifest))
        seen.add(label)
    if seen != set(targets):
        fail("candidate target set mismatch")
    return manifest, candidates


def command_assemble(args):
    manifest, candidates = validate_all(args.manifest, args.candidates)
    manifest_digest = sha256_file(args.manifest)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    plan = plan_document(manifest, manifest_digest, candidates)
    plan_bytes = (json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    digest = hashlib.sha256(plan_bytes).hexdigest()
    if args.expected_plan_digest and args.expected_plan_digest != digest:
        fail("expected plan digest mismatch")
    (out / "immutable-promotion-plan.json").write_bytes(plan_bytes)
    (out / "immutable-promotion-plan.sha256").write_text(f"{digest}  immutable-promotion-plan.json\n", encoding="ascii")
    checksums = "".join(f"{candidate['archive_sha256']}  {candidate['archive']}\n" for candidate in sorted(candidates, key=lambda candidate: candidate["archive"]))
    (out / "SHA256SUMS").write_text(checksums, encoding="ascii")
    boundary = {"publication_status": "not_attempted", "public_upload_attempted": False, "release_creation_attempted": False, "tag_creation_attempted": False}
    (out / "dry-run-boundary.json").write_text(json.dumps(boundary, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def command_verify(args):
    manifest, candidates = validate_all(args.manifest, args.candidates)
    plan = load_json(args.plan, "promotion plan")
    expected = plan_document(manifest, sha256_file(args.manifest), candidates)
    if plan != expected:
        fail("promotion plan binding mismatch")
    if args.expected_plan_digest and sha256_file(args.plan) != args.expected_plan_digest:
        fail("promotion plan SHA-256 mismatch")


def main(argv):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("assemble", "verify"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--manifest", required=True)
        sub.add_argument("--candidates", required=True)
        sub.add_argument("--dry-run", choices=("true", "false"), required=True)
        sub.add_argument("--expected-plan-digest", default="")
        if name == "assemble":
            sub.add_argument("--out", required=True)
        else:
            sub.add_argument("--plan", required=True)
    validate = subparsers.add_parser("validate-manifest")
    validate.add_argument("--manifest", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "assemble":
            command_assemble(args)
        elif args.command == "verify":
            command_verify(args)
        else:
            validate_manifest(load_json(args.manifest, "manifest"))
    except VerificationError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

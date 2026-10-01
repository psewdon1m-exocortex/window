#!/usr/bin/env python3
"""Bind a Window release to an immutable catalog and verify its exact assets."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TAG = re.compile(r"window-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
ID = re.compile(r"^\| \*\*([A-Z]+-[0-9]+)\*\* \| (.+) \| (.+) \|\s*$")
ASSETS = (
    "window-linux-amd64",
    "window-linux-arm64",
    "window.service",
    "updater-bootstrap.sh",
    "window-release-linux-amd64.json",
    "window-release-linux-amd64.json.sig.json",
    "window-release-linux-arm64.json",
    "window-release-linux-arm64.json.sig.json",
    "window.pem",
    "window-bootstrap.sh",
)


def fail(message: str) -> None:
    raise SystemExit(message)


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def check_catalog(policy: dict, docs: pathlib.Path) -> list[str]:
    revision = policy.get("catalog_revision", "")
    if not COMMIT.fullmatch(revision):
        fail("Catalog revision must be an immutable full commit SHA")
    actual = subprocess.check_output(["git", "-C", str(docs), "rev-parse", "HEAD"], text=True).strip()
    if actual != revision:
        fail("Checked-out central documentation revision differs from release policy")
    catalog = docs / policy.get("catalog_path", "")
    if not catalog.is_file() or digest(catalog) != policy.get("catalog_sha256"):
        fail("Part 12 catalog bytes differ from the pinned SHA-256")
    entries: dict[str, tuple[str, str]] = {}
    for line in catalog.read_text(encoding="utf-8").splitlines():
        if not re.match(r"^\| \*\*[A-Z]+-[0-9]+\*\* \|", line):
            continue
        match = ID.fullmatch(line)
        if not match:
            fail("Malformed Part 12 problem row")
        problem_id, problem, solution = match.groups()
        if problem_id in entries or not problem.strip() or not solution.strip():
            fail(f"Duplicate or empty Part 12 entry: {problem_id}")
        entries[problem_id] = (problem, solution)
    if not entries:
        fail("Part 12 catalog contains no active problem IDs")
    ids = sorted(entries)
    ids_hash = hashlib.sha256(("\n".join(ids) + "\n").encode()).hexdigest()
    if ids_hash != policy.get("catalog_ids_sha256"):
        fail("Part 12 ID set changed without an explicit Window policy review")
    for target in re.findall(r"\]\(([^)]+)\)", catalog.read_text(encoding="utf-8")):
        if target.startswith(("https://", "http://", "mailto:", "#")):
            continue
        relative = target.split("#", 1)[0]
        if relative and not (catalog.parent / relative).resolve().is_file():
            fail(f"Broken local Part 12 link: {relative}")
    return ids


def classifications(policy: dict, ids: list[str], phase: str, run_url: str) -> list[dict]:
    values: dict[str, dict] = {}
    for name, group in policy.get("not_applicable", {}).items():
        reason = group.get("reason", "").strip()
        if len(reason) < 50:
            fail(f"{name}: N/A needs a checked, concrete reason")
        for problem_id in group.get("ids", []):
            if problem_id in values:
                fail(f"Duplicate classification: {problem_id}")
            values[problem_id] = {"id": problem_id, "status": "N/A", "evidence": [], "reason": reason}
    for name, group in policy.get("applicable", {}).items():
        evidence = group.get("evidence", [])
        if not isinstance(evidence, list) or not evidence:
            fail(f"{name}: PASS needs reproducible evidence")
        for problem_id in group.get("ids", []):
            if problem_id in values:
                fail(f"Duplicate classification: {problem_id}")
            status = "PENDING_FINAL" if name == "signed_artifact_and_publication" and phase == "pre" else "PASS"
            values[problem_id] = {
                "id": problem_id,
                "status": status,
                "evidence": evidence + ([run_url] if run_url else []),
                "reason": None,
            }
    if set(values) != set(ids):
        fail(f"Unclassified or unknown Part 12 IDs: missing={sorted(set(ids)-set(values))}, extra={sorted(set(values)-set(ids))}")
    return [values[problem_id] for problem_id in ids]


def check_identity(tag: str, revision: str, main_revision: str) -> str:
    match = TAG.fullmatch(tag)
    if not match or tag == "window-v0.0.0":
        fail("Release tag must be exactly window-vMAJOR.MINOR.PATCH")
    if not COMMIT.fullmatch(revision) or revision != main_revision:
        fail("Release tag must point at the exact current main commit")
    return tag.removeprefix("window-v")


def check_updater(policy: dict, updater: pathlib.Path) -> None:
    for name, pinned in (
        ("updater-bootstrap.sh", policy.get("updater_bootstrap_sha256", "")),
        ("updater-install.tar.gz", policy.get("updater_install_sha256", "")),
    ):
        if not SHA.fullmatch(pinned) or digest(updater / name) != pinned:
            fail(f"Pinned Updater dependency does not match: {name}")
    expected = policy.get("window_public_key_sha256", "")
    if not SHA.fullmatch(expected):
        fail("Window release public key fingerprint is missing")
    with tarfile.open(updater / "updater-install.tar.gz", "r:gz") as archive:
        member = archive.extractfile("updater/release-trust/window.pem")
        if member is None or hashlib.sha256(member.read()).hexdigest() != expected:
            fail("Published Updater does not pin this Window release key")
    bootstrap = (updater / "updater-bootstrap.sh").read_text(encoding="utf-8")
    if f'version="{policy["updater_version"]}"' not in bootstrap:
        fail("Published Updater bootstrap does not select its pinned exact version")


def check_manifest_set(artifacts: pathlib.Path, version: str, policy: dict) -> None:
    minimum = policy["updater_version"]
    for arch in ("amd64", "arm64"):
        name = f"window-release-linux-{arch}.json"
        data = read_json(artifacts / name)
        if data != {
            "schema": "exocortex.window.release.v1",
            "product": "window-linux",
            "version": version,
            "runtime": f"linux-{arch}",
            "minimum_updater": minimum,
            "binary_sha256": digest(artifacts / f"window-linux-{arch}"),
            "unit_sha256": digest(artifacts / "window.service"),
            "updater_bootstrap_sha256": digest(artifacts / "updater-bootstrap.sh"),
        }:
            fail(f"Window {arch} manifest does not describe the exact release assets")
    if digest(artifacts / "updater-bootstrap.sh") != policy["updater_bootstrap_sha256"]:
        fail("Embedded Updater bootstrap differs from the pinned dependency")
    binary = artifacts / "window-linux-amd64"
    reported = subprocess.check_output([str(binary), "version"], text=True).strip()
    if reported != version:
        fail("Built Window runtime version differs from release tag")
    for arch, machine in (("amd64", 62), ("arm64", 183)):
        header = (artifacts / f"window-linux-{arch}").read_bytes()[:20]
        if len(header) != 20 or header[:4] != b"\x7fELF" or int.from_bytes(header[18:20], "little") != machine:
            fail(f"Window {arch} binary has the wrong ELF target")


def check_signature(artifacts: pathlib.Path, manifest: pathlib.Path) -> None:
    public = artifacts / "window.pem"
    envelope = read_json(pathlib.Path(str(manifest) + ".sig.json"))
    der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", str(public), "-outform", "DER"])
    if envelope.get("schema") != "exocortex.release-signature.v1" or envelope.get("algorithm") != "RSA-PSS-SHA256":
        fail("Window signature envelope has the wrong contract")
    if envelope.get("key_id") != hashlib.sha256(der).hexdigest():
        fail("Window signature key ID does not match its public key")
    signature = base64.b64decode(envelope.get("signature", ""), validate=True)
    with tempfile.NamedTemporaryFile() as temporary:
        temporary.write(signature)
        temporary.flush()
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(public), "-signature", temporary.name,
             "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", str(manifest)],
            capture_output=True,
        )
        if result.returncode:
            fail(f"Window manifest signature failed verification: {manifest.name}")


def check_assets(artifacts: pathlib.Path, version: str, policy: dict, candidate_hashes: pathlib.Path) -> None:
    for name in ASSETS:
        if not (artifacts / name).is_file() or (artifacts / name).stat().st_size == 0:
            fail(f"Required Window release asset is missing or empty: {name}")
    if digest(artifacts / "window.pem") != policy["window_public_key_sha256"]:
        fail("Release signer differs from the key pinned by Updater")
    check_manifest_set(artifacts, version, policy)
    for arch in ("amd64", "arm64"):
        check_signature(artifacts, artifacts / f"window-release-linux-{arch}.json")
    bootstrap = (artifacts / "window-bootstrap.sh").read_text(encoding="utf-8")
    public = (artifacts / "window.pem").read_bytes()
    repository = os.getenv("GITHUB_REPOSITORY", "psewdon1m-exocortex/window")
    for expected in (f'version="{version}"', f'repository="{repository}"', base64.b64encode(public).decode()):
        if expected not in bootstrap:
            fail("Window bootstrap is not bound to the signed release")
    if "__WINDOW_" in bootstrap or "PRIVATE KEY" in bootstrap:
        fail("Window bootstrap contains an unresolved placeholder or private key")
    for line in candidate_hashes.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([a-z0-9.-]+)", line)
        if not match or match.group(2) not in ASSETS:
            fail("Malformed candidate checksum record")
        if digest(artifacts / match.group(2)) != match.group(1):
            fail(f"Published binary or dependency differs from the pre-signing candidate: {match.group(2)}")
    checksum = artifacts / "checksums.txt"
    lines = checksum.read_text(encoding="utf-8").splitlines()
    expected = {f"{digest(artifacts / name)}  {name}" for name in ASSETS}
    if set(lines) != expected or len(lines) != len(expected):
        fail("Release checksum list does not exactly cover the required assets")
    for name in ASSETS:
        if b"-----BEGIN PRIVATE KEY-----" in (artifacts / name).read_bytes():
            fail(f"Private key material found in release asset: {name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("lint", "pre", "verify", "final"))
    parser.add_argument("--policy", type=pathlib.Path, default=ROOT / ".github/release-policy.json")
    parser.add_argument("--docs", type=pathlib.Path, required=True)
    parser.add_argument("--tag", default=os.getenv("GITHUB_REF_NAME", ""))
    parser.add_argument("--revision", default=os.getenv("GITHUB_SHA", ""))
    parser.add_argument("--main-revision", default="")
    parser.add_argument("--updater-dir", type=pathlib.Path)
    parser.add_argument("--artifacts", type=pathlib.Path)
    parser.add_argument("--candidate-hashes", type=pathlib.Path)
    parser.add_argument("--pre-report", type=pathlib.Path)
    parser.add_argument("--published-dir", type=pathlib.Path)
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args()
    policy = read_json(args.policy)
    if policy.get("schema") != "exocortex.window.release-policy.v1":
        fail("Unsupported Window release policy schema")
    ids = check_catalog(policy, args.docs)
    run_url = f"https://github.com/{os.getenv('GITHUB_REPOSITORY', 'psewdon1m-exocortex/window')}/actions/runs/{os.getenv('GITHUB_RUN_ID')}" if os.getenv("GITHUB_RUN_ID") else ""
    classifications(policy, ids, "final", run_url)
    if args.phase == "lint":
        print(f"Pinned Part 12 catalog lint passed: {len(ids)} active IDs, all classified")
        return
    version = check_identity(args.tag, args.revision, args.main_revision or args.revision)
    if args.phase == "pre":
        if not args.updater_dir or not args.artifacts or not args.report:
            fail("Pre-signing gate needs pinned Updater assets, candidate and output report")
        check_updater(policy, args.updater_dir)
        check_manifest_set(args.artifacts, version, policy)
        report = {
            "schema_version": 1,
            "service": "window",
            "revision": args.revision,
            "release_tag": args.tag,
            "catalog_repository": policy["catalog_repository"],
            "catalog_revision": policy["catalog_revision"],
            "catalog_path": policy["catalog_path"],
            "catalog_sha256": policy["catalog_sha256"],
            "checks": classifications(policy, ids, "pre", run_url),
        }
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Pre-signing Part 12 gate passed for {args.tag}; final signature checks remain pending")
        return
    if not args.artifacts or not args.candidate_hashes or not args.pre_report:
        fail("Signed-asset verification needs artifacts, candidate hashes and pre-signing report")
    previous = read_json(args.pre_report)
    if previous.get("release_tag") != args.tag or previous.get("revision") != args.revision or previous.get("catalog_sha256") != policy["catalog_sha256"]:
        fail("Pre-signing report is stale or belongs to another revision")
    if previous.get("checks") != classifications(policy, ids, "pre", run_url):
        fail("Pre-signing classifications differ from the pinned policy")
    check_assets(args.artifacts, version, policy, args.candidate_hashes)
    if args.phase == "verify":
        print("Signed Window artifacts, dependencies and candidate digests verified")
        return
    if not args.published_dir or not args.report:
        fail("Final gate needs anonymous download of the published assets")
    for name in (*ASSETS, "checksums.txt"):
        if digest(args.artifacts / name) != digest(args.published_dir / name):
            fail(f"Public release asset differs from verified candidate: {name}")
    report = dict(previous)
    report["checks"] = classifications(policy, ids, "final", run_url)
    report["published_asset_sha256"] = {name: digest(args.artifacts / name) for name in (*ASSETS, "checksums.txt")}
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Final Part 12 gate passed for {args.tag}: {len(ids)} classified IDs and anonymous assets verified")


if __name__ == "__main__":
    main()

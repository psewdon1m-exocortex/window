#!/usr/bin/env python3
"""Fail-closed seven-area CI gate shared by every service repository."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

PROFILES = (
    "backup_restore",
    "service_update",
    "internal_documentation",
    "technical_documentation",
    "security",
    "public_seo_geo",
    "private_concealed",
)
EXPOSURE_MODES = {
    "public/indexable",
    "public/non-indexable",
    "private",
    "concealed",
}
LINK_RE = re.compile(r"\[[^\]]+\]\((?:<([^>]+)>|((?:[^()]|\([^()]*\))+))\)")
SECRET_PATTERNS = (
    (
        "private key material",
        re.compile(
            rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s*\r?\n"
            rb"[A-Za-z0-9+/=\r\n]{32,}"
        ),
    ),
    ("GitHub token", re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("AWS access key", re.compile(rb"AKIA[0-9A-Z]{16}")),
)
HIGH_RISK_NAMES = {
    ".env",
    "id_rsa",
    "id_ed25519",
}
HIGH_RISK_SUFFIXES = {
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
}


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def commit_exists(value: str) -> bool:
    if not value or set(value) == {"0"}:
        return False
    return git("cat-file", "-e", f"{value}^{{commit}}", check=False).returncode == 0


def choose_base(explicit: str | None, head: str) -> str | None:
    candidates = (
        explicit,
        os.getenv("GATE_BASE_SHA"),
        os.getenv("GITHUB_EVENT_BEFORE"),
        f"{head}^",
    )
    for candidate in candidates:
        if candidate and commit_exists(candidate):
            return candidate
    return None


def changed_files(base: str | None, head: str) -> list[str]:
    if base:
        result = git("diff", "--name-only", "--diff-filter=ACMR", base, head)
    else:
        result = git("ls-files")
    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})


def validate_markdown_links(path: Path, errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    for match in LINK_RE.finditer(text):
        target = (match.group(1) or match.group(2) or "").strip()
        if not target or target.startswith(("http://", "https://", "mailto:", "#", "/")):
            continue
        if " \"" in target:
            target = target.split(" \"", 1)[0]
        target = unquote(target.split("#", 1)[0].split("?", 1)[0])
        if not target:
            continue
        resolved = (path.parent / target).resolve()
        if not resolved.exists():
            errors.append(f"{path}: broken local link: {target}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", default=".github/pre-push-gate.json")
    parser.add_argument("--base")
    parser.add_argument("--worktree", action="store_true", help="Include unstaged, staged and untracked non-ignored files")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--upstream-result", default="success")
    parser.add_argument("--report", default=".pre-push-gate-report.json")
    args = parser.parse_args()

    root = Path.cwd().resolve()
    errors: list[str] = []
    checks: list[str] = []

    policy_path = root / args.policy
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        policy = {}
        errors.append(f"cannot read policy {args.policy}: {exc}")

    service = str(policy.get("service", "")).strip()
    modes = set(policy.get("exposure_modes", []))
    profiles = policy.get("profiles", {})

    if policy.get("version") != 1:
        errors.append("policy version must be 1")
    if not service:
        errors.append("policy must name the service")
    if not modes or not modes.issubset(EXPOSURE_MODES):
        errors.append(f"invalid or empty exposure_modes: {sorted(modes)}")
    if set(profiles) != set(PROFILES):
        errors.append("policy must define exactly the seven required profiles")
    if profiles.get("security", {}).get("applicable") is not True:
        errors.append("security profile is always applicable")
    if ("public/indexable" in modes) != bool(
        profiles.get("public_seo_geo", {}).get("applicable")
    ):
        errors.append("public/indexable exposure must match public_seo_geo applicability")
    if bool(modes & {"private", "concealed"}) != bool(
        profiles.get("private_concealed", {}).get("applicable")
    ):
        errors.append("private/concealed exposure must match profile applicability")

    evidence_paths: set[Path] = set()
    statuses: dict[str, dict[str, object]] = {}
    for name in PROFILES:
        entry = profiles.get(name, {})
        applicable = entry.get("applicable")
        evidence = entry.get("evidence", [])
        reason = str(entry.get("reason", "")).strip()
        if not isinstance(applicable, bool):
            errors.append(f"{name}: applicable must be boolean")
            applicable = False
        if applicable:
            if not isinstance(evidence, list) or not evidence:
                errors.append(f"{name}: applicable profile needs evidence paths")
                evidence = []
            for raw in evidence:
                candidate = root / str(raw)
                if not candidate.is_file() or candidate.stat().st_size == 0:
                    errors.append(f"{name}: missing or empty evidence: {raw}")
                else:
                    evidence_paths.add(candidate)
            statuses[name] = {"status": "PASS", "evidence": evidence}
        else:
            if len(reason) < 12:
                errors.append(f"{name}: N/A requires a concrete reason")
            statuses[name] = {"status": "N/A", "reason": reason}

    if args.upstream_result != "success":
        errors.append(f"native verification result is {args.upstream_result}, not success")
    else:
        checks.append("native verification succeeded")

    head = git("rev-parse", args.head).stdout.strip()
    base = choose_base(args.base, head)
    changed = changed_files(base, head)
    if args.worktree:
        changed = sorted(set(git("diff", "--name-only", "--diff-filter=ACMR", "HEAD").stdout.splitlines()) | set(git("ls-files", "--others", "--exclude-standard").stdout.splitlines()))

    diff_args = ("diff", "--check", base, head) if base else ("diff", "--check")
    if args.worktree:
        diff_args = ("diff", "--check", "HEAD")
    diff_check = git(*diff_args, check=False)
    if diff_check.returncode:
        errors.append(f"git diff --check failed:\n{diff_check.stdout}{diff_check.stderr}")
    else:
        checks.append("diff whitespace check passed")

    for path in sorted(evidence_paths):
        if path.suffix.lower() == ".md":
            try:
                validate_markdown_links(path, errors)
            except UnicodeDecodeError:
                errors.append(f"{path}: documentation is not valid UTF-8")
    checks.append(f"validated {len(evidence_paths)} evidence files")

    for raw in changed:
        path = root / raw
        lowered = path.name.lower()
        if lowered in HIGH_RISK_NAMES or path.suffix.lower() in HIGH_RISK_SUFFIXES:
            errors.append(f"high-risk tracked file in outgoing diff: {raw}")
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(data):
                errors.append(f"possible {label} in outgoing diff: {raw}")
    checks.append(f"scanned {len(changed)} outgoing text/file paths")

    report = {
        "schema": "exocortex.pre-push-gate.v1",
        "working_tree": args.worktree,
        "service": service,
        "head": head,
        "base": base,
        "exposure_modes": sorted(modes),
        "changed_files": changed,
        "profiles": statuses,
        "checks": checks,
        "errors": errors,
        "result": "FAIL" if errors else "PASS",
    }
    Path(args.report).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    summary = os.getenv("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as handle:
            handle.write(f"## Seven-area pre-push gate: {report['result']}\n\n")
            handle.write(f"Service: `{service}` | head: `{head}`\n\n")
            handle.write("| Area | Status | Evidence / reason |\n| --- | --- | --- |\n")
            for name in PROFILES:
                value = statuses.get(name, {"status": "FAIL"})
                detail = value.get("evidence") or value.get("reason") or ""
                if isinstance(detail, list):
                    detail = ", ".join(str(item) for item in detail)
                handle.write(f"| {name} | {value['status']} | {detail} |\n")
            if errors:
                handle.write("\n### Blocking findings\n\n")
                for error in errors:
                    handle.write(f"- {error}\n")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Seven-area pre-push gate passed for {service} at {head}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env bash
set -euo pipefail

output="${1:?output directory required}"
policy="${2:-.github/release-policy.json}"
readarray -t pinned < <(python3 - "$policy" <<'PY'
import json, re, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
version = data.get("updater_version", "")
bootstrap = data.get("updater_bootstrap_sha256", "")
installer = data.get("updater_install_sha256", "")
if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
    raise SystemExit("Invalid pinned Updater version")
if not all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in (bootstrap, installer)):
    raise SystemExit("Updater asset SHA-256 values must be pinned before a Window release")
print(version, bootstrap, installer, sep="\n")
PY
)
version="${pinned[0]}"
mkdir -p "$output"
base="https://github.com/psewdon1m-exocortex/updater/releases/download/updater-v${version}"
curl -fLSs --proto '=https' --proto-redir '=https' --retry 3 --retry-all-errors \
  --connect-timeout 10 --max-time 180 --max-filesize 1048576 \
  "$base/bootstrap.sh" -o "$output/updater-bootstrap.sh"
curl -fLSs --proto '=https' --proto-redir '=https' --retry 3 --retry-all-errors \
  --connect-timeout 10 --max-time 300 --max-filesize 104857600 \
  "$base/updater-${version}-install.tar.gz" -o "$output/updater-install.tar.gz"
printf '%s  %s\n' "${pinned[1]}" "$output/updater-bootstrap.sh" \
  "${pinned[2]}" "$output/updater-install.tar.gz" | sha256sum --check --status
grep -Fxq "version=\"$version\"" "$output/updater-bootstrap.sh" || {
  echo 'Pinned Updater bootstrap version mismatch' >&2
  exit 1
}
printf 'Verified Updater %s bootstrap and install archive against pinned SHA-256.\n' "$version"

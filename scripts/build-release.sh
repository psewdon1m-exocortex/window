#!/usr/bin/env bash
set -euo pipefail

version="${1:?exact stable version required}"
output="${2:-release-artifacts}"
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || { echo 'Use a stable version' >&2; exit 2; }
[[ "${WINDOW_MIN_UPDATER_VERSION:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Set WINDOW_MIN_UPDATER_VERSION' >&2; exit 2; }
[[ "$(printf '%s\n%s\n' 0.6.8 "$WINDOW_MIN_UPDATER_VERSION" | sort -V | head -1)" = 0.6.8 ]] || { echo 'Window requires Updater 0.6.8 or newer' >&2; exit 2; }
[[ "${GITHUB_REPOSITORY:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'Set GITHUB_REPOSITORY=owner/repo' >&2; exit 2; }
: "${WINDOW_RELEASE_SIGNING_KEY_FILE:?Set the protected Window release signing key file}"
: "${WINDOW_UPDATER_BOOTSTRAP_FILE:?Set the exact signed Updater bootstrap file}"
[[ -f "$WINDOW_UPDATER_BOOTSTRAP_FILE" && ! -L "$WINDOW_UPDATER_BOOTSTRAP_FILE" ]] || { echo 'Updater bootstrap must be a regular file' >&2; exit 2; }
bootstrap_version="$(sed -n 's/^version="\([0-9][0-9.]*\)"$/\1/p' "$WINDOW_UPDATER_BOOTSTRAP_FILE" | head -1)"
[[ "$bootstrap_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Updater bootstrap has no pinned exact version' >&2; exit 2; }
[[ "$(printf '%s\n%s\n' "$WINDOW_MIN_UPDATER_VERSION" "$bootstrap_version" | sort -V | head -1)" = "$WINDOW_MIN_UPDATER_VERSION" ]] || { echo 'Pinned Updater bootstrap is too old' >&2; exit 2; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
cp "$root/systemd/window.service" "$output/window.service"
cp "$WINDOW_UPDATER_BOOTSTRAP_FILE" "$output/updater-bootstrap.sh"
updater_bootstrap_sha="$(sha256sum "$output/updater-bootstrap.sh" | cut -d' ' -f1)"
unit_sha="$(sha256sum "$output/window.service" | cut -d' ' -f1)"
for arch in amd64 arm64; do
  binary="$output/window-linux-$arch"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$binary" ./cmd/window)
  binary_sha="$(sha256sum "$binary" | cut -d' ' -f1)"
  manifest="$output/window-release-linux-$arch.json"
  cat > "$manifest" <<EOF
{
  "schema": "exocortex.window.release.v1",
  "product": "window-linux",
  "version": "$version",
  "runtime": "linux-$arch",
  "minimum_updater": "$WINDOW_MIN_UPDATER_VERSION",
  "binary_sha256": "$binary_sha",
  "unit_sha256": "$unit_sha",
  "updater_bootstrap_sha256": "$updater_bootstrap_sha"
}
EOF
  node "$root/scripts/sign-release.mjs" "$manifest" "$output/window.pem"
done
node "$root/scripts/build-bootstrap.mjs" "$root/bootstrap.sh" "$output/window.pem" "$output/window-bootstrap.sh" "$version" "$GITHUB_REPOSITORY"
printf 'Window %s release artifacts built in %s\n' "$version" "$output"

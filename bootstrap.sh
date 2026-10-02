#!/usr/bin/env sh
set -eu
umask 077

version="__WINDOW_VERSION__"
repository="__WINDOW_REPOSITORY__"
public_key_b64="__WINDOW_PUBLIC_KEY_BASE64__"
[ "$(id -u)" -eq 0 ] || { echo 'Run Window bootstrap as root' >&2; exit 1; }
case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) echo 'Unsupported Window architecture' >&2; exit 1 ;; esac
if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl openssl python3 sudo
fi
for command in curl openssl python3 visudo; do command -v "$command" >/dev/null 2>&1 || { echo "$command is required" >&2; exit 1; }; done
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT HUP INT TERM
printf '%s' "$public_key_b64" | openssl base64 -d -A > "$work/window.pem"
base="https://github.com/$repository/releases/download/window-v$version"
manifest="$work/window-release-linux-$arch.json"
curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 --connect-timeout 10 --max-time 120 --max-filesize 65536 "$base/window-release-linux-$arch.json" -o "$manifest"
curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 --connect-timeout 10 --max-time 120 --max-filesize 16384 "$base/window-release-linux-$arch.json.sig.json" -o "$manifest.sig.json"
python3 - "$manifest" "$manifest.sig.json" "$work/window.pem" "$version" "$arch" <<'PYVERIFY'
import base64, hashlib, json, pathlib, re, subprocess, sys, tempfile
manifest, envelope, trust = map(pathlib.Path, sys.argv[1:4])
version, arch = sys.argv[4:]
raw = manifest.read_bytes()
data = json.loads(raw)
signed = json.loads(envelope.read_bytes())
if data.get("schema") != "exocortex.window.release.v1" or data.get("product") != "window-linux" or data.get("version") != version or data.get("runtime") != f"linux-{arch}":
    raise SystemExit("Window release identity mismatch")
if signed.get("schema") != "exocortex.release-signature.v1" or signed.get("algorithm") != "RSA-PSS-SHA256":
    raise SystemExit("Window signature envelope is invalid")
public = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(trust), "-outform", "DER"], check=True, capture_output=True).stdout
if hashlib.sha256(public).hexdigest() != signed.get("key_id"):
    raise SystemExit("Window release signer is not trusted")
for name in ("binary_sha256", "unit_sha256", "updater_bootstrap_sha256"):
    if not re.fullmatch(r"[a-f0-9]{64}", str(data.get(name,""))):
        raise SystemExit("Window release digest is invalid")
if not re.fullmatch(r"\d+\.\d+\.\d+", str(data.get("minimum_updater",""))):
    raise SystemExit("Window minimum Updater version is invalid")
with tempfile.TemporaryDirectory() as directory:
    signature = pathlib.Path(directory) / "signature.bin"
    signature.write_bytes(base64.b64decode(signed.get("signature", ""), validate=True))
    subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(trust), "-signature", str(signature), "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", str(manifest)], check=True, capture_output=True)
PYVERIFY

if [ ! -x /usr/bin/updater ]; then
  curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 --connect-timeout 10 --max-time 120 --max-filesize 1048576 "$base/updater-bootstrap.sh" -o "$work/updater-bootstrap.sh"
  expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["updater_bootstrap_sha256"])' "$manifest")"
  actual="$(openssl dgst -sha256 "$work/updater-bootstrap.sh" | awk '{print $NF}')"
  [ "$actual" = "$expected" ] || { echo 'Pinned Updater bootstrap digest mismatch' >&2; exit 1; }
  sh "$work/updater-bootstrap.sh"
fi
trust=/etc/exocortex/release-trust/window.pem
[ -f "$trust" ] && [ ! -L "$trust" ] && cmp -s "$trust" "$work/window.pem" || { echo 'Updater has no matching pinned Window release key' >&2; exit 1; }
minimum="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["minimum_updater"])' "$manifest")"
dpkg --compare-versions "$(/usr/bin/updater version)" ge "$minimum" || { echo 'Updater is too old for this Window release' >&2; exit 1; }
/usr/bin/updater tui --help 2>&1 | grep -Fq -- '-window-only' || { echo 'Updater does not support the restricted Window operator TUI; upgrade Updater first' >&2; exit 1; }
id windowops >/dev/null 2>&1 || useradd --create-home --user-group --shell /bin/bash --password '!' windowops
[ "$(getent passwd windowops | cut -d: -f6-7)" = '/home/windowops:/bin/bash' ] || { echo 'Window operator account must use /home/windowops and /bin/bash.' >&2; exit 1; }
[ "$(id -gn windowops)" = windowops ] || { echo 'Window operator primary group must be windowops.' >&2; exit 1; }
[ "$(id -u windowops)" -ne 0 ] || { echo 'Window operator account must not be root.' >&2; exit 1; }
for privileged_group in root sudo wheel docker lxd updater window; do
  case " $(id -nG windowops) " in *" $privileged_group "*) echo "Remove windowops from privileged group $privileged_group." >&2; exit 1 ;; esac
done
[ ! -L /home/windowops ] || { echo 'Window operator home must not be a symlink.' >&2; exit 1; }
install -d -o windowops -g windowops -m 0700 /home/windowops
install -d -o root -g root -m 0755 /etc/sudoers.d
[ ! -L /etc/sudoers.d/windowops ] || { echo 'Window operator sudoers file must not be a symlink.' >&2; exit 1; }
windowops_sudoers="$(mktemp /etc/sudoers.d/.windowops.XXXXXX)"
printf '%s\n' 'windowops ALL=(root) NOPASSWD: /usr/bin/updater tui --window-only, /usr/bin/updater window pair --key-base64 *, /usr/local/bin/window capture-test *' > "$windowops_sudoers"
chmod 0440 "$windowops_sudoers"
visudo -cf "$windowops_sudoers" >/dev/null || { rm -f "$windowops_sudoers"; exit 1; }
mv -f "$windowops_sudoers" /etc/sudoers.d/windowops
visudo -c >/dev/null
/usr/bin/updater host seed-source window "https://github.com/$repository"
/usr/bin/updater window install --version "$version"
printf '%s\n' "Window $version installed with access closed. Log in as windowops and run sudo /usr/bin/updater tui --window-only."
printf '%s\n' 'For a new windowops account, set its login password with passwd windowops or install an SSH public key.'

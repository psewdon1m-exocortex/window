# Window deployment readiness

The immutable release workflow verifies source, signatures, Updater dependency,
artifact digests and anonymous downloads. A production host rehearsal is still
`NOT_RUN` until an operator performs the checks below on the intended server.
Do not treat a green release as proof that a particular host is configured.

## Before installation

On the intended Linux host, record the actual host and installed Updater version:

```sh
hostname -f
pwd
/usr/bin/updater version
sudo systemctl status updater --no-pager
```

Confirm that DNS and outbound HTTPS can reach the exact Window and Updater
release URLs. A firewall or proxy failure here blocks installation; retry only
after the network path is fixed. Use a release-specific `window-bootstrap.sh`
asset, never a file from `main` or `latest`.

The host must run published Updater 0.6.12 or newer with the matching Window
public release key pinned under `/etc/exocortex/release-trust/window.pem`.
Window's release policy pins the verified Updater 0.6.12 bootstrap and install
archive. If an older Updater
is installed, update it through its own verified release path first. Do not copy
a Window key directly into the host trust directory as a workaround.

On a first Window installation, use an interactive root terminal to set the
`windowops` password when prompted. If `windowops` already has a password or
an SSH public key, the bootstrap preserves it and does not prompt. An
unattended first installation without either credential stops before Window
is installed. The Updater installer may have already created the account with
a locked password; Window's bootstrap still prompts in that case.

## After installation

```sh
/usr/bin/updater version
sudo systemctl status window --no-pager
sudo systemctl show window -p MainPID -p ActiveState -p SubState
sudo /usr/local/bin/window version
sudo journalctl -u window -n 50 --no-pager -o short-iso
```

`systemctl restart` alone is not readiness evidence. Check the running version,
process state and Updater TUI Window status after activation. Verify that an
unpaired or closed grant denies data reads. Pair the development PC through
`scripts/setup-codex.ps1`, then log in as `windowops` and open a short grant in
`sudo /usr/bin/updater tui -window`. Exercise `window_sources` and
`window_updater_jobs` from Codex. Revoke it in the
TUI and verify the next read is denied. No Codex agent runs on the host.

For a failed install or update, inspect the specific Updater job and Window
journal with timestamps, preserve the original error, then use TUI Repair. Do
not erase the transaction journal or blindly rerun install. Recheck the running
binary, unit, trust key, socket and version after repair. Record the exact
release tag, checksums, commands and observed result in the deployment record.

Do not paste raw log lines, passwords, private keys or credential-bearing
commands into an issue. Window filtering is heuristic; review excerpts before
sharing them beyond the paired development PC. Any temporary workaround needs
an issue and a regression check before the incident is considered resolved.

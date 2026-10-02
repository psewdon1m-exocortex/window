# Window

Window is a shared Linux host diagnostic agent managed by Updater. This source
requires Updater 0.6.12 or newer for its restricted operator TUI.
It has no application-service consumer edges. Codex runs only on the
development PC and connects through the host's existing SSH port. Window
does not listen on a TCP port and gives the SSH account no Docker socket.
The [design and applicability record](docs/design.md) maps Window to the
central `.docs` rules and records the staged producer-redaction decision.

## Operator flow

The root installer creates `windowops` for the interactive SSH session and a
restricted sudoers rule for Window controls. On the first Window installation,
if `windowops` has neither a password nor an SSH public key, the bootstrap asks
for a password through `passwd` on the operator's terminal. It never receives
or stores the password itself. An unattended first installation without either
credential stops before installing Window; add a public key first or run the
bootstrap from an interactive terminal. Existing credentials survive updates.
For key login, put the operator's public key in
`/home/windowops/.ssh/authorized_keys` with `windowops` ownership and mode
`0600` (directory mode `0700`). Log in through Termius as `windowops` and run
`sudo /usr/bin/updater tui -window`. The technical `window` account remains
separate and accepts only the paired MCP key.

1. On the development PC, verify the production SSH host-key fingerprint out
   of band and add it to `known_hosts`. Run `scripts/setup-codex.ps1 -HostName
   HOST` on Windows. Choose either a one-time password login as an existing
   server operator with sudo rights, or paste the printed `ssh-ed25519` public
   key into `sudo /usr/bin/updater tui -window` → Pair development PC. The password
   method runs `sudo updater window pair` over the existing SSH port; neither
   the SSH nor sudo password is stored. Codex always uses the dedicated key
   for later read-only connections.

   For a non-interactive choice of setup method, use
   `scripts/setup-codex.ps1 -HostName HOST -PairingMethod Password -OperatorUser windowops`
   or `-PairingMethod Tui`. If the server disables SSH password login, use the
   TUI method. The dedicated `window` SSH account remains key-only.
2. In the same TUI, choose Open read-only grant and a duration of 1–120
   minutes. The TUI sends a heartbeat every three seconds. Codex can now call
   Window's five read-only MCP tools over its **own** SSH connection.
3. Choose Start observed operator shell to mirror echoed commands and output.
   The agent polls `window_live_events` during an active Codex turn; it cannot
   type into the shell. Exit the shell to stop the live feed.
4. Run `sudo window capture-test smoke -- COMMAND [ARG...]` from that shell to
   save a bounded result under Window's test sources. The command executes as
   the original, unprivileged sudo user. Window does not run tests on an MCP
   request.
5. Choose Revoke access now to deny new reads. Closing the Updater TUI stops
   heartbeats. In a normal Termius SSH session, its loss also exits the TUI;
   data reads fail within 12 seconds even if Codex's separate SSH process
   remains open. If the TUI is deliberately kept alive in `tmux` or `screen`,
   closing Termius alone does not close the grant: revoke it or exit the TUI.

The Termius session is the operator control session, not Codex's data
connection. The SSH host key trusted by Termius is not automatically trusted
by the development PC's OpenSSH client. Window access starts closed after
daemon restart and after each new TUI session until explicitly opened.

If **Check for releases** reports Kernel HTTP 403, verify that Updater's host
machine principal in Kernel is allowed to resolve `repositories.window.url`.
The saved Window repository in TUI is a fallback for an unavailable Kernel;
an explicit authorization denial requires correcting the Kernel principal.

## Read boundary

`window_sources` lists a fixed set of systemd units, containers whose names
start with `exocortex-`, and up to 20 retained test results. `window_logs`
reads one bounded source. `window_updater_jobs` reads the existing sanitized
Updater operator summary. `window_live_events` reads up to 100 buffered events
per call. `window_storage` reports root filesystem space, the current syslog
file size, and a cached Docker `system df` summary. The first request may say
`pending` while Docker computes usage; ask again later. The summary refreshes
after five minutes and may say `unavailable` if Docker cannot answer. No MCP
tool accepts a shell command, path, Docker API request or
source outside this inventory. Each log request is limited to 200 lines,
64 KiB of returned text, a 24-hour lookback and a six-second read timeout.
Test output is limited to 128 KiB at capture and 64 KiB after filtering;
the most recent 20 results are kept for at most seven days. The audit stores
only route, status and byte count and rotates at 512 KiB.

Window drops whole lines containing common secret indicators and strips
terminal control sequences. This is **heuristic**: unknown secret formats in
existing producer logs or live shell output can still be exposed while the
grant is open. Treat an active grant as permission to read all registered
diagnostic sources. Avoid entering credentials in the observed shell.

## Release and installation

GitHub Actions runs verification on pushes to `main`, pull requests and plain
`vVERSION` validation tags. The same checks can be started manually. CI vets
and tests the Go code, checks shell and JavaScript syntax, builds both Linux
targets, lints the pinned Part 12 catalog, checks all seven pre-push areas and
tests the Windows Codex pairing flow. It does not receive release signing keys
or publish artifacts. An exact `window-vVERSION` tag starts the separate
release workflow only after the same CI passes. That workflow checks the
published Updater dependency, builds a candidate, completes the Part 12 gate,
signs inside the restricted `release` environment, compares the signed build
against the candidate, and anonymously downloads every published asset before
attaching the final evidence report. See [deployment readiness](DEPLOYMENT_READINESS.md)
for the separate production-host rehearsal.

Window uses its own RSA-PSS release key, `window-vVERSION` tags and signed
`window-release-linux-{amd64,arm64}.json` manifests. Updater pins the Window
public key in its own signed installer, then verifies the exact manifest,
asset digests, minimum Updater version and running Window health before
accepting installation or update. Failed activation restores the previous
binary and unit. If an update is interrupted, TUI Repair restores the prior
version from `.previous`. Pairing survives a successful update; a grant does not.

For a local rehearsal, supply a protected RSA key outside the repository and
the exact, previously published Updater bootstrap. The release workflow uses
the same builder with its protected GitHub environment key:

```sh
WINDOW_RELEASE_SIGNING_KEY_FILE=/protected/window.private.pem \
WINDOW_UPDATER_BOOTSTRAP_FILE=/protected/updater-bootstrap.sh \
WINDOW_MIN_UPDATER_VERSION="$PUBLISHED_UPDATER_VERSION" \
GITHUB_REPOSITORY=OWNER/window \
bash scripts/build-release.sh 0.0.1 release-artifacts
```

The workflow publishes all generated assets under the immutable tag and keeps
that release out of `latest` discovery. Distribute `window-bootstrap.sh` from
that exact release URL. On a clean host it verifies
Window's exact signed manifest, downloads the pinned Updater bootstrap if
needed, checks the Updater-installed Window key and asks Updater to install
the exact Window version. Normal host operations use Updater TUI.

Production release qualification still needs a host rehearsal with real
systemd, OpenSSH, Docker and a paired development PC. Workspace tests exercise
the grant and peer boundaries, source restrictions, MCP client, release
signatures and Updater integration without changing the production host.

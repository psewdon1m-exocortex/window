# Window v0.0.1 design and applicability

Window is a single shared Linux host agent. It is installed and operated by
Updater and has no application-service consumers. The development PC is its one
explicitly paired read-only client. Neither Codex nor a public Window listener
runs on the production host.

## Authority and applicability

| Part | Applicability | Window decision |
| --- | --- | --- |
| [00](https://github.com/psewdon1m-exocortex/general/blob/65b2f5461a4499243024f4125fb7d4db3df89ad6/PART_00_SYSTEM_UNIFICATION_SPECIFICATION.md) | Applicable | Separate component, explicit trust boundaries and cross-layer tests. |
| 01 | N/A | No application web UI. The operator uses the existing Updater TUI. |
| [02](https://github.com/psewdon1m-exocortex/general/blob/65b2f5461a4499243024f4125fb7d4db3df89ad6/PART_02_OBSERVABILITY_AUDIT_AND_LOG_EXPORT.md) | Applicable | Bounded log reads, central output filtering and bounded access audit. Existing producer logs are not claimed to be secret-free. |
| [03](https://github.com/psewdon1m-exocortex/general/blob/65b2f5461a4499243024f4125fb7d4db3df89ad6/PART_03_BACKUP_AND_RECOVERY.md) | Applicable | Pairing identity is recovery data. Ephemeral leases and live output are deliberately not restored. |
| [04](https://github.com/psewdon1m-exocortex/general/blob/65b2f5461a4499243024f4125fb7d4db3df89ad6/PART_04_BOOTSTRAP_AND_DEPLOYMENT.md)–[05](https://github.com/psewdon1m-exocortex/general/blob/65b2f5461a4499243024f4125fb7d4db3df89ad6/PART_05_CI_RELEASES_AND_LOCAL_UPDATES.md) | Applicable | Own bootstrap, signed release and verified Updater lifecycle are required before production installation. |
| [06](https://github.com/psewdon1m-exocortex/general/blob/65b2f5461a4499243024f4125fb7d4db3df89ad6/PART_06_UNIFIED_ACCEPTANCE_CHECKLIST.md)–[07](https://github.com/psewdon1m-exocortex/general/blob/65b2f5461a4499243024f4125fb7d4db3df89ad6/PART_07_SECURITY_AND_EXPOSURE_CONTROL.md) | Applicable | Pre-push and private exposure checks; no network listener and no arbitrary command/data path. |
| 08 | N/A | No public or indexable surface. |
| [09](https://github.com/psewdon1m-exocortex/general/blob/65b2f5461a4499243024f4125fb7d4db3df89ad6/PART_09_SERVICE_AGENTS_DEPLOYMENT_AND_LIFECYCLE.md)–[10](https://github.com/psewdon1m-exocortex/general/blob/65b2f5461a4499243024f4125fb7d4db3df89ad6/PART_10_SERVICE_AGENTS_UI_AND_OPERATOR_WORKFLOWS.md) | Applicable | Shared host agent and Updater TUI operator workflow. |
| [11](https://github.com/psewdon1m-exocortex/general/blob/65b2f5461a4499243024f4125fb7d4db3df89ad6/PART_11_INITIAL_MULTI_SERVICE_DEPLOYMENT.md)–[12](https://github.com/psewdon1m-exocortex/general/blob/65b2f5461a4499243024f4125fb7d4db3df89ad6/PART_12_KNOWN_DEPLOYMENT_AND_OPERATIONS_PROBLEMS.md) | Applicable at release | Deployment acceptance and known-problem evidence must be bound to an exact candidate. |
| [13](https://github.com/psewdon1m-exocortex/general/blob/65b2f5461a4499243024f4125fb7d4db3df89ad6/PART_13_HOST_DEPENDENCIES_AND_EXTENSION_GUIDE.md) | Applicable | One host singleton, own signing trust and Updater dependency; zero application consumer edges initially. |

## Boundary

```text
Termius -> root Updater TUI -> root Updater operator socket -> Window admin socket
Codex on paired PC -> dedicated SSH key -> forced `window mcp` -> Window reader socket
Window -> fixed journal units / Exocortex Docker containers / test results / sanitized Updater jobs
```

Initial pairing has two operator paths: paste the public key in the root TUI,
or use an existing operator's password-authenticated SSH session to run the
root Updater pairing command once. The setup helper never reads or stores that
password; OpenSSH and, if required, sudo prompt for it. Both paths install the
same dedicated public key in Window. Subsequent Codex MCP reads use that key,
and the dedicated `window` account never permits password login.

An open grant requires a paired key, a live TUI heartbeat, an unexpired
operator-selected duration and no revocation. It is checked on each read. An
open SSH transport alone grants nothing. The default and daemon-restart state
is closed. Emergency revocation denies new reads after the revoke response;
an in-flight response is bounded by the local HTTP write timeout. A lost TUI
heartbeat closes the grant within 12 seconds. Duration is 1–120 minutes.

No user-controlled path, unit name, container ID, Docker API method, shell
command, environment variable or filename reaches a reader. Sources are
discovered from a fixed unit list and Docker container names with the exact
`exocortex-` prefix. The reader invokes only `journalctl` and `docker logs` with
fixed argument positions, bounded output, tail, lookback and timeout. Window
never passes Docker's socket to the paired SSH process. An audit records request
metadata and byte counts, never full returned log lines. Every output line is
filtered and control characters are removed before MCP serialization. Unknown
secret formats may remain; this is a documented residual risk until producers
meet Part 02 source-redaction requirements.

Updater job summaries use a typed read-only view over its local operator API.
The Window client never receives Updater's operator socket. Live observation
starts only from the Window section of the TUI and mirrors a newly launched
operator shell's output. The MCP inventory exposes no input or execution tool.
The live feed is bounded and volatile; it ends with the observed shell or grant.
Codex sees new events only when it calls the polling tool during an active turn.
The operator's Termius SSH session and Codex's independent SSH process are
different transports; a lost TUI closes the *data grant*, not necessarily
Codex's already-open transport. A TUI kept alive by `tmux` or `screen` remains
a live grant owner even after its original Termius transport disconnects.

## Material divergence: producer redaction is deferred

Applicable guide: [Part 02, §10.2](https://github.com/psewdon1m-exocortex/general/blob/65b2f5461a4499243024f4125fb7d4db3df89ad6/PART_02_OBSERVABILITY_AUDIT_AND_LOG_EXPORT.md)
requires central recursive inspection of structured values and known credential
patterns before logs reach any sink, and forbids secrets in logs. Part 00 §1
requires an operator decision for a material difference.

Observed implementation: existing services may already write unknown secret
formats into journal or container output. Window drops lines with common
credential markers and applies the same filter to captured tests and observed
shell output, but it cannot prove that every existing log is secret-free.

Difference and impact: an operator-granted reader may receive an unknown
credential while the grant is open. The exposure is limited to the paired PC,
the chosen duration and the connected TUI heartbeat, but disclosure cannot be
undone by revoking a grant. Existing logs remain on the host after revocation.

Operator decision: the operator explicitly deferred changes to all producer
services and chose one grant covering the registered sources. This selects a
staged compatibility path. Window makes that risk visible in its README and
keeps filtering centralized; it does not claim full Part 02 compliance.

Convergence: add structured redaction at each producer's serialization
boundary in later service work, then test representative journal, Docker,
test-result and live outputs against known credential formats. Until then,
avoid entering credentials in the observed shell and treat the paired agent as
authorized to see potentially sensitive diagnostics. Rollback is immediate
grant revocation followed by disabling the Window unit if needed; neither can
recall data already read.

## Acceptance

- Closed, expired, lost-heartbeat and revoked grants deny all data reads.
- A paired SSH key alone cannot read data or start a shell.
- A connected reader is cut off on revoke and duration expiry.
- Invalid source names, paths, excessive limits and malformed MCP calls fail.
- Container and journal reads are bounded; Docker socket is not exposed.
- Jobs contain only the existing sanitized operator fields.
- Live observation is explicit, read-only, bounded, and never captures raw
  keyboard input.
- Signed install/update restores the prior binary and unit on failed health.
- TUI repair recovers the prior binary and unit after an interrupted update.
- An actual MCP client is used in workspace tests. Linux/systemd/sshd and
  Docker behavior need final qualification on a representative host.

No production host was changed by this workspace implementation.

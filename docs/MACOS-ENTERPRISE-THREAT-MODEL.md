# macOS managed-enterprise threat model

This is the macOS part of the [enterprise threat model](ENTERPRISE-THREAT-MODEL.md),
which defines the enterprise profiles, the trust zones Z0–Z5 and the
cross-platform boundary table.

macOS runs either profile:

- `secure_client` (the default when no profile is set) is installed by Cisco
  Secure Client through `packaging/macos/install.sh`, runs its gateway,
  guardian and enumerator as root under `com.cisco.secureclient.defenseclaw.*`
  in `/opt/cisco/secureclient/defenseclaw`, and is in production. The
  standalone work does not change its scripts, plists or behavior.
- `standalone` is installed by any MDM or an administrator through
  `defenseclaw-gateway enterprise macos …` or the standalone `.pkg`.

The rows below cover the standalone profile. They are numbered `M-01`…; the
second column names the matching Windows row.

<!-- verify-after-merge: M2 M4 M5 — this model describes the macOS standalone lifecycle, LaunchDaemons, enrollment worker and machine policy being merged (the hook transport and peer checks are merged) into the enterprise-hardening branch. Re-check every path and plist key against the merged tree before removing this comment. -->

## Review scope

- Primary paths:
  - `internal/enterpriseunix/` (lifecycle, shared with Linux; `launchd` platform)
  - `internal/cli/enterprise_unix*.go` (`defenseclaw-gateway enterprise macos …`)
  - `packaging/launchd-standalone/` (LaunchDaemons `com.cisco.defenseclaw.*`)
  - `scripts/build-macos-enterprise-pkg.sh` (standalone `.pkg`)
  - `internal/gateway/api_uds_unix.go`, `internal/gateway/managed_hook_peer.go`
  - `internal/gateway/connector/hookexec/managed_standalone_transport.go`
  - `internal/peercred/peercred_darwin.go`
  - `internal/unixidentity/platform_darwin.go`, `internal/cli/enterprise_hooks_worker_darwin.go`
  - `internal/enterprisepolicy/` (`*_darwin.go` sources)
- Out of scope: the Secure Client packaging under `packaging/macos/` and
  `packaging/launchd/`.

## Security objectives

1. A standard user cannot unload, edit or replace any DefenseClaw
   LaunchDaemon, binary, config, policy, secret, manifest, ledger or runtime
   descriptor.
2. The gateway runs as the hidden `_defenseclaw` user and can write only its
   runtime state and its log directory.
3. A hook sends no request byte until `LOCAL_PEERCRED` proves the hook
   socket's listener is root or `_defenseclaw`.
4. The gateway authorizes every hook caller by kernel uid against the root
   guardian's ledger.
5. The root guardian never touches a user home itself; a per-user worker does
   it as that user.
6. Vendor machine policy is merged, never replaced.
7. A normal user cannot disable DefenseClaw's hooks through vendor settings,
   and a foreign hook cannot rewrite a tool call DefenseClaw inspected.

## Zones on macOS (standalone)

| Zone | What runs or lives there | Identity | Protected by |
| --- | --- | --- | --- |
| Z0 | launchd, root, the MDM agent, the `.pkg` postinstall, `defenseclaw-gateway enterprise macos` | root | Trusted by assumption |
| Z1 | `com.cisco.defenseclaw.hook-guardian` (watch, one-minute reconcile) | root | Root-owned plist in `/Library/LaunchDaemons`; `KeepAlive` |
| Z1 | `com.cisco.defenseclaw.hook-enumerator` (five-minute cycle) | root | Same |
| Z1 | Per-user `enterprise hooks apply-target` worker | the target's uid and primary gid | New session; the guardian's timeout kills its process group; cross-user task ports are denied by the OS |
| Z1 | `com.cisco.defenseclaw.sensor-helper` | root | Fixed request protocol; homes from the manifest |
| Z1 | `com.cisco.defenseclaw.apply` (`WatchPaths` on config, secrets, policies → `ensure`), `com.cisco.defenseclaw.verify` (daily) | root | Root-owned plists |
| Z2 | `com.cisco.defenseclaw.gateway` | `_defenseclaw` (`UserName`/`GroupName`), `Umask` 077 | Read-only config, policy and ledger; writes `/opt/cisco/defenseclaw/runtime` and `/Library/Logs/Cisco/DefenseClaw/gateway` |
| Z2 endpoints | `127.0.0.1:18970` and `/opt/cisco/defenseclaw/run/hook.sock`, bound by the gateway | `_defenseclaw` | The lifecycle creates `/opt/cisco/defenseclaw/run` for `_defenseclaw` inside the root-owned install tree; it survives reboot and no other user can create a file there |
| Z3 | `/opt/cisco/defenseclaw/{bin,etc,etc/policies,etc/secrets,etc/hook-guardian,lifecycle,hook-guardian-state}` (the `run/` socket directory belongs to `_defenseclaw`), `/Library/Application Support/{ClaudeCode,Cursor,opencode}`, `/etc/codex`, `/etc/github-copilot/policy.d` | root (secrets `root:_defenseclaw 0640`) | Administrator-only write |
| Z4 | The AI agent and `/opt/cisco/defenseclaw/bin/defenseclaw-hook` as the user | the user | Peer verification, repair, foreign-hook guard |

launchd hands sockets to a daemon only through `launch_activate_socket(3)`,
which needs cgo; release builds are `CGO_ENABLED=0`, so the macOS gateway
binds its own listeners. The protected socket directory, not socket
activation, is what prevents squatting on the hook socket. `/var/run` is
not used: macOS clears it at boot and `_defenseclaw` cannot write it.
<!-- verify-after-merge: M2 — the lifecycle creates /opt/cisco/defenseclaw/run and no longer ships a boot-time prepare daemon -->

## Data flows

### Install and lifecycle

1. The MDM installs the standalone `.pkg` (or stages a payload) and runs
   `defenseclaw-gateway enterprise macos ensure` as root. The postinstall
   calls the same lifecycle.
2. The lifecycle creates the hidden `_defenseclaw` user and group with
   `dscl` if needed, lays out `/opt/cisco/defenseclaw` from
   `managed.StandaloneLayoutFor("darwin")`, writes the LaunchDaemons, and
   runs the same locked, snapshotted, verified transaction as on Linux. It
   refuses when a Secure Client deployment is present.
3. Exit codes are `0`, `1`, `2` and `75`.

### Hook request

1. The agent runs the admin-owned hook as the user.
2. The hook reads the socket path and the `_defenseclaw` uid from the
   root-owned descriptor `/opt/cisco/defenseclaw/etc/managed-runtime.json`.
3. It resolves the socket directory through platform symlinks, requires it
   to be owned by root or the service account and writable by no one else,
   connects to `/opt/cisco/defenseclaw/run/hook.sock`, and requires the
   `LOCAL_PEERCRED` uid to be 0 or the service uid before sending.
4. There is no TCP fallback on macOS: an unprivileged process cannot learn the
   owner of another process's TCP socket without parsing private kernel
   structures, so the hook fails closed instead.

### Enrollment

Accounts resolve through `os/user`, which on macOS goes through libSystem
and Open Directory, so directory-bound and mobile accounts resolve; `dscl .
-list /Users` lists local accounts. Directory accounts are found through
logged-in sessions, home owners under `/Users` and
`enrollment.include_users`. As on Linux, a lookup error is never a deletion.

## Threat analysis

| ID | Windows | Threat | Control | Evidence |
| --- | --- | --- | --- | --- |
| M-01 | W-01 | A user unloads, disables or edits a LaunchDaemon (`launchctl bootout`, `disable`, plist edit) | System-domain daemons require root; plists are `root:wheel 0644`; `KeepAlive` restarts a killed daemon | `launchctl` attempts as each test user |
| M-02 | W-02 | A user replaces a binary, config, policy, secret, manifest, ledger or descriptor | Root ownership of every file and ancestor under `/opt/cisco/defenseclaw`; trusted-path checks on read | Write and swap attempts; `verify` |
| M-03 | W-04 | A user downgrades the mode or profile | Mode and profile pinned in each plist's `EnvironmentVariables`; config must agree | Config and profile tests |
| M-04 | W-05 | A compromised gateway edits policy or the ledger | `_defenseclaw` has no write access to `etc/`, `hook-guardian-state/` or `bin/` | File-mode verification |
| M-05 | W-25 | A user wins the gateway's endpoint during a restart | The hook uses only the socket, in a directory no other user can write, and verifies the peer uid before sending | `managed_standalone_transport_test.go`, `api_uds_unix_test.go`; squat-and-restart race on a host |
| M-06 | — | A user pre-creates the socket or its directory, or the directory disappears at boot | The directory is `/opt/cisco/defenseclaw/run`, created by the lifecycle for `_defenseclaw` inside the root-owned install tree, so it persists across reboot and no other user can create entries; the gateway refuses a directory with any other owner or a group/other write bit and replaces only a stale socket it owns | `internal/gateway/api_uds_unix_test.go`; reboot test on a host |
| M-07 | W-28 | An unenrolled uid uses a per-user connector's hook | Hook-socket authorization against the ledger (as L-08) | `managed_hook_peer_test.go` |
| M-08 | W-06 | Root follows a user symlink inside a home | The root guardian refuses in-process home access; the worker acts as the user | Worker and standalone tests |
| M-09 | — | TCC blocks the worker from reading the agent's configuration | Agent configs live in dotdirs in the home, which TCC does not protect; an optional PPPC profile granting Full Disk Access to the hook guardian is documented for sites that relocate them | Host run with each connector <!-- verify-after-merge: M10 --> |
| M-10 | W-26, W-49 | A user disables Codex or Claude Code hooks | `/etc/codex/requirements.toml` with `allow_managed_hooks_only` and `[features] hooks = true`; `/Library/Application Support/ClaudeCode/managed-settings.d/90-defenseclaw.json` with `allowManagedHooksOnly` | Machine-policy tests; `enterprise policy verify --live` |
| M-11 | W-51 | A higher-precedence source shadows DefenseClaw's policy: the Codex MDM preference `com.openai.codex` `requirements_toml_base64` outranks `/etc/codex`, and Claude Code managed preferences outrank the file drop-in | Detect the preference; report it as higher precedence; `enterprise policy export` produces the plist or TOML block the MDM should carry; `higher_precedence_sources: fail` (default) or `warn` | `codex_sources_darwin.go`, `claude_sources_darwin.go` tests |
| M-12 | W-50 | A user or project hook rewrites a tool call (Cursor, Copilot, Devin, OpenCode, Amp) | Foreign-hook guard | `guard_test.go` |
| M-13 | W-48 | A user reads the AI Defense key | `root:_defenseclaw 0640` in a `0750` directory; the reader requires root ownership, a single link and no access for others | Credential tests |
| M-14 | W-52 | A per-user install competes with the managed deployment | `scripts/install.sh` and the per-user gateway refuse while the descriptor exists | Refusal tests |
| M-15 | W-15 | A failed upgrade leaves mixed state | Transaction snapshot and rollback | Lifecycle tests |
| M-16 | — | The standalone and Secure Client profiles are installed together | The standalone lifecycle refuses when a Secure Client deployment is present | `secureClientPresent` tests |

## Residual risks

1. Per-user registrations are user-owned and repaired within one reconcile
   interval, as on the other platforms.
2. Without socket activation, a hook that runs while the gateway restarts
   fails closed rather than queuing.
3. The Codex and Claude Code MDM preference layers can override local files;
   they belong to whoever manages those preferences.
4. Unsigned (hash-pinned) builds do not satisfy Gatekeeper or notarization
   requirements; sign with a Developer ID and notarize, or re-sign.
5. The vendor residuals in the
   [enterprise threat model](ENTERPRISE-THREAT-MODEL.md#residual-risks) apply.

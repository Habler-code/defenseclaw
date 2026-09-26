# Linux managed-enterprise threat model

This is the Linux part of the [enterprise threat model](ENTERPRISE-THREAT-MODEL.md),
which defines the enterprise profiles, the trust zones Z0–Z5 and the
cross-platform boundary table. Linux supports only the `standalone` profile;
the loader rejects `secure_client` on Linux.

Rows are numbered `L-01`…. Where a row mirrors a Windows row, the Windows ID
is given in the second column so reviewers can compare the two platforms.

<!-- verify-after-merge: M2 M4 M5 — this model describes the Linux lifecycle, units, enrollment worker and machine policy that are being merged (the hook transport and peer checks are merged) into the enterprise-hardening branch. Re-check every path and unit property against the merged tree before removing this comment. -->

## Review scope

- Repository: `defenseclaw`; a certification record names the exact tree hash.
- Primary paths:
  - `internal/enterpriseunix/` (lifecycle transaction)
  - `internal/cli/enterprise_unix*.go` (`defenseclaw-gateway enterprise linux …`, `enterprise secret …`)
  - `packaging/systemd/` (units, sockets, path unit, timer, sysusers)
  - `packaging/linux/` (`.deb` / `.rpm` maintainer scripts)
  - `internal/gateway/api_uds_unix.go`, `internal/gateway/managed_hook_peer.go`
  - `internal/gateway/connector/hookexec/managed_standalone_transport.go`, `tcp_owner_linux.go`
  - `internal/peercred/`, `internal/systemd/`
  - `internal/unixidentity/`, `internal/enterprisehooks/enumerator_unix.go`,
    `internal/cli/enterprise_hooks_worker_*.go`
  - `internal/enterprisepolicy/`
  - `internal/managed/credentials_unix.go`, `internal/managed/runtime_descriptor.go`
- Supported hosts: systemd 239 or later as PID 1. Containers and WSL without
  systemd are refused (`systemd is not the running init system`).

## Security objectives

1. A standard user cannot stop, disable, mask, reconfigure or replace any
   DefenseClaw unit, binary, config, policy, secret, manifest, ledger or
   runtime descriptor.
2. The gateway runs as the `defenseclaw` system user with an empty capability
   set inside a systemd sandbox, and can write only its state, runtime and log
   directories.
3. A hook sends no request byte until the kernel proves the listener is root
   (PID 1 holding an activated socket) or the gateway's service uid.
4. The gateway authorizes each hook caller by kernel uid against the
   guardian's root-owned authorization ledger.
5. The root guardian never reads, writes, removes or changes permissions
   inside a user home itself; a per-user worker does it with that user's uid
   and gid.
6. Directory-backed users (LDAP, SSSD, AD, NIS, systemd-userdb) are enrolled;
   a directory outage never revokes anyone.
7. Vendor machine policy is merged, never replaced; administrator entries
   survive install, repair and uninstall byte for byte.
8. A normal user cannot disable DefenseClaw's hooks through vendor settings,
   and a foreign hook cannot rewrite a tool call DefenseClaw inspected.
9. Every lifecycle action is a transaction that commits fully or rolls back.

## Zones on Linux

| Zone | What runs or lives there | Identity | Protected by |
| --- | --- | --- | --- |
| Z0 | systemd (PID 1), root, `apt`/`dnf`, `defenseclaw-gateway enterprise linux` run by an MDM script or an administrator | root | Trusted by assumption |
| Z1 | `defenseclaw-hook-guardian.service` | root; `CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_KILL CAP_SETGID CAP_SETUID`; `NoNewPrivileges=true` | Root-owned unit; `ProtectSystem=strict`; writes only homes (through the worker) and the guardian state |
| Z1 | `defenseclaw-hook-enumerator.service` | root; `CAP_DAC_READ_SEARCH CAP_KILL CAP_SETGID CAP_SETUID`; `ProtectHome=read-only` | Writes only `/etc/defenseclaw/hook-guardian` |
| Z1 | Per-user `enterprise hooks apply-target` worker | the target user's uid and primary gid | New session, parent-death signal, non-dumpable, rlimits, timeout, minimal environment |
| Z1 | `defenseclaw-sensor-helper.service` | root with acquisition capabilities (`CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, `CAP_CHOWN`, `CAP_FOWNER`) | Own `RuntimeDirectory=defenseclaw-sensor`; fixed fieldless request protocol; homes from the manifest |
| Z2 | `defenseclaw-gateway.service` (`Type=notify`, watchdog) | `defenseclaw:defenseclaw`, `CapabilityBoundingSet=` (empty) | `ProtectSystem=strict`, `ProtectHome=true`, `PrivateDevices`, `PrivateTmp`, `ProtectProc=invisible`, `@system-service` syscall filter, `MemoryDenyWriteExecute`, `RestrictNamespaces`; read-only `/etc/defenseclaw`, `/opt/defenseclaw` and the ledger |
| Z2 endpoints | `defenseclaw-gateway-api.socket` (`127.0.0.1:18970`) and `defenseclaw-gateway-hook.socket` (`/run/defenseclaw-hook/hook.sock`) | bound by PID 1 | Held across gateway restarts; socket directory created by PID 1 (`DirectoryMode=0755`, root-owned) |
| Z3 | `/opt/defenseclaw` (binaries), `/etc/defenseclaw` (config, `policies/`, `secrets/`, `hook-guardian/targets.yaml`, `managed-runtime.json`, `machine-policy.json`), `/var/lib/defenseclaw-hook-guardian` (ledger), `/var/lib/defenseclaw-enterprise` (lifecycle), `/etc/{codex,claude-code,cursor,github-copilot,opencode}` | root | Administrator-only write; secrets root-only |
| Z4 | The AI agent and `/opt/defenseclaw/bin/defenseclaw-hook` running as the user; the user's vendor config | the user | Peer verification, guardian repair, foreign-hook guard |

Supporting units: `defenseclaw-enterprise-apply.path` watches the config,
secrets and policies and runs `ensure`; `defenseclaw-enterprise-verify.timer`
runs `verify` daily; `defenseclaw.sysusers` creates the service account. The
racing oneshot guardian timer and the template unit from earlier layouts are
removed.

## Data flows

### Install, upgrade, ensure, uninstall

1. An administrator, package script or MDM runs
   `defenseclaw-gateway enterprise linux <action>` as root. Paths come from
   `managed.StandaloneLayoutFor("linux")`; the environment is not consulted.
2. The lifecycle takes the lock in `/var/lib/defenseclaw-enterprise`, rolls
   back any interrupted transaction, records an intent, snapshots every file
   it will touch, and stages replacements in the destination directory.
3. It stops the services, applies files, owners and modes, reloads systemd,
   and starts the sensor helper, the gateway (waiting for `READY=1` and
   `/health`), the guardian (waiting for a fresh ledger) and the enumerator.
4. It verifies every file, mode, unit property and readiness check, then
   commits the deployment record or restores the snapshot and the previously
   running services. `ensure` is a no-op when nothing changed. Exit codes are
   `0`, `1` (rolled back), `2` (invalid arguments) and `75` (lock busy).
5. On SELinux hosts the lifecycle relabels the install and config trees and
   reports a warning if relabeling fails.

### Secrets

`defenseclaw-gateway enterprise secret set --name <name> --from-stdin` stores
a value in `/etc/defenseclaw/secrets/<name>`. With systemd 247 or later the
file is `root:root 0600` and reaches the gateway only through
`LoadCredential=` under `/run/credentials/`; with older systemd it is
`root:defenseclaw 0640`. The gateway reads it through
`managed.ResolveServiceCredential`, which requires the credentials directory
under `/run/credentials/` or a root-owned, single-link file with no other
access. Status shows presence, modification time and a digest prefix only.

### Hook request

1. The agent runs `/opt/defenseclaw/bin/defenseclaw-hook --connector <c>
   --enterprise-managed` as the user.
2. The hook reads the gateway address, hook socket and gateway service uid
   only from the root-owned runtime descriptor
   (`/etc/defenseclaw/managed-runtime.json`). Inherited gateway tokens and
   addresses cannot loosen it.
3. It connects to `/run/defenseclaw-hook/hook.sock`, checks the socket
   directory is owned by root or the service account and writable by no one
   else, and requires the peer's `SO_PEERCRED` uid to be 0 or the service uid.
   Only then does it send the request. If no socket is configured, it uses
   `127.0.0.1:18970` and resolves the owner uid of the server side of that
   exact connection through `NETLINK_SOCK_DIAG` (falling back to a bounded
   `/proc/net/tcp` read).
4. The gateway reads the caller's uid from the socket and checks the
   authorization ledger (L-08).

### Enrollment and repair

1. The enumerator lists candidates from NSS (`getent passwd` through the
   root-owned binary, so LDAP, SSSD, AD, NIS and systemd-userdb accounts are
   visible to the `CGO_ENABLED=0` build), logged-in sessions, home owners and
   `enrollment.include_users`, then applies uid, shell, group, home-root and
   exclusion filters.
2. Agent versions are discovered by the per-user worker as that user, never
   as root.
3. The manifest is published atomically. Existing `enabled`, `deferred` and
   version state is kept; a row is revoked only after several consecutive
   definitive not-found answers; a changed uid or home inode is a new
   identity.
4. The guardian spawns one worker per target. The worker installs or repairs
   the registration, removes foreign hooks, and reports back; the guardian
   mints tokens, writes the ledger and watches files.

## Threat analysis

| ID | Windows | Threat | Control | Evidence |
| --- | --- | --- | --- | --- |
| L-01 | W-01 | A user stops, disables, masks, edits or deletes a unit | Units live in root-owned systemd directories; `systemctl` mutations need root or polkit authorization that standard users lack; `Restart=always`, `StartLimitIntervalSec=0` | `systemctl stop/disable/mask` as each test user; unit files unchanged |
| L-02 | W-02 | A user replaces a binary, config, policy, secret, manifest, ledger or descriptor | Root ownership of every file and ancestor; the loader rejects untrusted config and policy inputs; the descriptor parser is strict and bounded | Write, rename, symlink-swap attempts; `verify` detects drift |
| L-03 | W-04 | A user downgrades `managed_enterprise` or the profile through config or environment | `DEFENSECLAW_DEPLOYMENT_MODE` and `DEFENSECLAW_ENTERPRISE_PROFILE` pinned in every unit; config must agree; reload refuses a profile change | `internal/config/enterprise_test.go`, `internal/managed/profile_test.go` |
| L-04 | W-05 | A compromised gateway edits policy or the ledger | `ReadOnlyPaths=/etc/defenseclaw /opt/defenseclaw -/var/lib/defenseclaw-hook-guardian`; empty capabilities; `ProtectHome=true` | `systemctl show` properties; write attempts from the service identity |
| L-05 | W-25 | A user binds `127.0.0.1:18970` or the hook socket during a restart and returns an allow | PID 1 binds both sockets before any user process and holds them across restarts; the hook verifies the listener uid (socket: `SO_PEERCRED`; TCP: sock_diag owner of the exact 4-tuple) before writing | `internal/gateway/connector/hookexec/managed_standalone_transport_test.go`, `tcp_owner_linux_test.go`, `internal/systemd/systemd_test.go`; a squat-and-restart race on a host |
| L-06 | — | A user pre-creates `/run/defenseclaw-hook/hook.sock` or its directory | The directory is created by PID 1 (root-owned, `0755`); the gateway's own bind (without activation) refuses a directory that is not owned by root or the service account or is writable by others, and replaces only a stale socket it owns | `internal/gateway/api_uds_unix_test.go` |
| L-07 | W-14 | A user reads another user's hook token or the service's runtime state | `StateDirectoryMode=0750`, `RuntimeDirectoryMode=0750`, `UMask=0077`; tokens under each user's home with owner-only modes | Cross-user read attempts |
| L-08 | W-28 | An unenrolled uid uses a per-user connector's hook route | Hook socket authorization: per-user connectors require a ledger row for that uid and connector; machine-policy connectors inspect every user unless `enrollment.unenrolled_users: deny`; uid 0 follows `enrollment.root`; `exempt_users` are inspected and logged | `internal/gateway/managed_hook_peer_test.go` |
| L-09 | W-06 | The root guardian follows a user-planted symlink or races a check-then-act inside a home | The root guardian refuses in-process home access in the standalone profile; the per-user worker operates with the user's own kernel permissions, so a race gains nothing the user did not already have | `internal/enterprisehooks/standalone_unix_test.go`, worker tests |
| L-10 | W-08 | A credential drop leaks into other goroutines | No `Seteuid` in the guardian process; the worker is a separate process started with the target credentials (`SysProcAttr.Credential`) | Worker tests |
| L-11 | — | A home under a world-writable ancestor (for example `/tmp`) is swapped by another user | Refused with a reason before any mutation | `internal/enterprisehooks/home_unix.go` tests |
| L-12 | — | An NFS `root_squash`, autofs, ecryptfs-locked or homed home breaks repair or is treated as deleted | The worker reads as the user; an unavailable home is `deferred`, not failed or revoked | `pendingErrno` tests |
| L-13 | W-42 | A directory outage or uid reuse revokes or mis-enrolls users | NSS lookups; only a definitive not-found counts; several misses before revocation; uid and home-inode identity | `internal/unixidentity/identity_test.go`, `internal/enterprisehooks/enumerator_unix_test.go` |
| L-14 | W-09 | A user deletes or edits a per-user registration | File watching plus a one-minute reconcile repairs through the worker | Tamper-and-measure runs per connector |
| L-15 | W-26, W-49 | A user disables Codex or Claude Code hooks (`[features] hooks = false`, `-c`, `disableAllHooks`, `CODEX_HOME`, `CLAUDE_CONFIG_DIR`) | Machine policy in `/etc/codex/requirements.toml` (with `allow_managed_hooks_only` and a mandatory `[features] hooks = true` pin) and `/etc/claude-code/managed-settings.d/90-defenseclaw.json` (with `allowManagedHooksOnly`) | `internal/enterprisepolicy/codex_test.go`, `claude_test.go`; `enterprise policy verify --live --user <user>` |
| L-16 | W-50 | A user or project hook rewrites a tool call (Cursor, Copilot, Devin, OpenCode, Amp) | Foreign-hook guard: guardian removal from user config through the worker, hook-time project check, allowlist by hash | `internal/enterprisepolicy/guard_test.go` |
| L-17 | W-30 | Uninstall deletes an administrator's vendor policy | Ownership records and preimages; remove only DefenseClaw-owned entries; restore preimages | Install over existing admin policy; uninstall; byte compare |
| L-18 | W-15 | A failed upgrade leaves mixed state | Transaction snapshot, rollback and crash recovery on the next run | `internal/enterpriseunix/lifecycle_test.go` failure injection |
| L-19 | W-46 | Concurrent MDM runs collide | Lifecycle lock; exit `75` while busy | Lifecycle tests |
| L-20 | W-48 | A user reads the AI Defense key | `LoadCredential=` with a root-only file (systemd 247 or later), else `root:defenseclaw 0640`; the reader rejects any other owner, mode or link count | `internal/managed/credentials_test.go`, `internal/enterpriseunix/lifecycle_test.go` |
| L-21 | W-52 | A per-user install competes with the managed deployment | `scripts/install.sh`, `scripts/defenseclaw-upgrade.sh`, `defenseclaw upgrade` and the per-user gateway refuse while `/etc/defenseclaw/managed-runtime.json` exists; `--adopt-existing` backs up and takes over an older unmanaged layout | `cli/tests/test_managed_host_refusal.py`, `internal/cli/managed_host_guard_test.go` |
| L-22 | W-13 | A removed user or connector stays authorized | The ledger is rebuilt from the current manifest; removed or disabled rows are revoked | Enumerator and guardian tests |
| L-23 | — | SELinux, fapolicyd or AppArmor silently blocks a service | Relabel after install; lifecycle warnings; certification on RHEL 9 with SELinux enforcing | Host certification record |
| L-24 | W-21 | The gateway hangs without exiting | `WatchdogSec=60s` with `Type=notify`; systemd restarts it | SIGSTOP drill |

## Invariants

- The Linux profile is always `standalone`.
- PID 1 owns the gateway's listening sockets; the gateway only inherits them.
- The gateway has no capabilities and cannot write outside its own
  directories.
- The root guardian does not touch user homes itself.
- A hook trusts only uid 0 or the service uid read from the root-owned
  descriptor.
- A lookup error is "unknown", never "deleted".

## Residual risks

1. Per-user registrations are user-owned. A user can remove them until the
   next repair (seconds with the watcher, at most one reconcile interval
   otherwise). Machine-policy connectors do not have this window.
2. The TCP fallback depends on `NETLINK_SOCK_DIAG` or `/proc/net/tcp` being
   readable; hosts that hide them (for example `hidepid` with a restrictive
   group) force the hook onto the socket or fail closed.
3. A user can hold the TCP port while the gateway is stopped by an
   administrator (socket activation keeps it bound otherwise). The hook fails
   closed; this is an availability issue only.
4. The sensor helper and guardian run as root with capabilities. A compromise
   of either collapses into the trusted-administrator assumption.
5. The vendor residuals in the
   [enterprise threat model](ENTERPRISE-THREAT-MODEL.md#residual-risks) apply.
6. Confined SELinux users (`user_u`) and fapolicyd rules may block the hook
   binary or agent CLIs; the lifecycle reports but does not rewrite host
   policy.

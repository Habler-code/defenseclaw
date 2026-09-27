# Secure Client golden fixtures

Production Cisco Secure Client deployments ship the DefenseClaw
`managed_enterprise` lifecycle for native Windows and macOS from the release
branch `release-defenseclaw-enterprise-26.8.4`. These fixtures pin what that
lifecycle produces today so that adding other deployment profiles (for
example a standalone, MDM-deployed profile) cannot silently change it.

A config with `deployment_mode: managed_enterprise` and **no `enterprise:`
block** is the Secure Client shape. Every Go golden constructs exactly that
in memory; an implementation must keep treating an unset in-memory profile as
Secure Client (the config loader is the place that applies any
per-OS default).

## What is pinned

| Fixture | Produced by | Pins |
| --- | --- | --- |
| `go/config_posture.json` (darwin, windows) | `internal/config` | managed-mode constants and env names; IPC enablement and peer-auth kind per deployment mode; the Secure Client GUI codesign allowlist; managed AI Defense log-sink predicate; loopback listener rules; Windows IPC allowlist rejection; `env_config.json` path and endpoint validation; guardrail runtime-migration gate |
| `go/config_mode_pin.json` (darwin, windows) | `internal/config` | `DEFENSECLAW_DEPLOYMENT_MODE` service pin: fills, matches, conflicts, invalid |
| `go/gateway_posture.json` | `internal/gateway` | AI Defense-only decisions (local detectors, CodeGuard, and regex bypassed), fail-open when AI Defense has no verdict or is unwired, managed inspector requires a registered cloud provider and an endpoint, multi-connector refusal without a provider, no OS toasts, runtime config PATCH denied, events without an identity never attributed to the gateway's service account |
| `go/cli_posture.json` | `internal/cli` | the per-user gateway guard never refuses on a host without a trusted standalone deployment record, and a record a standard user could have planted does not count; a standard user whose vendor directory keeps the ProgramData Users grant is refused only when the administrator-registered gateway service runs the standalone gateway executable, never for the Secure Client gateway |
| `go/ipc_socket.json` (darwin, windows) | `internal/ipc` | Secure Client GUI IPC socket path, env-override immunity (socket override, and `DEFENSECLAW_ENTERPRISE_PROFILE` unset, `secure_client` or invalid), socket-mode ceilings |
| `go/cli_dotenv_profile_pin.json` | `internal/cli` | a data-directory `.env` cannot supply `DEFENSECLAW_ENTERPRISE_PROFILE`, so the Secure Client shape still resolves `secure_client` on darwin and windows |
| `go/sensor_socket.json` (darwin, windows) | `internal/sensor/acquire` | managed sensor-helper socket path and env-override immunity (socket override, and `DEFENSECLAW_ENTERPRISE_PROFILE` unset, `secure_client` or invalid) |
| `windows/codex_requirements_*.toml`, `windows/codex_requirements_contract.json` | `internal/gateway/connector` | bytes of `%ProgramData%\OpenAI\Codex\requirements.toml` after reconcile (including today's re-marshal that drops administrator comments), refusals, hook groups, managed hook command, report |
| `windows/claude_managed_policy_*.json` | `internal/gateway/connector` (Windows only) | bytes of `C:\Program Files\ClaudeCode\managed-settings.d\90-defenseclaw.json` |
| `windows/lifecycle.json` | `packaging/windows/tests/secure-client-golden.ps1` | managed layout; the five SCM service specifications Verify enforces (image, account, SID type, privileges, dependencies, environment, start mode) for installed, pending, servicing, any-start-mode, and attested deployments; service SDDL, description, registry-key SDDL, failure actions, drain interval; canonical ACL per managed path kind; the path-to-kind ACL plan; the required-rights matrix; the Secure Client values of the profile helpers (per-profile roots including certification and lifecycle roots, broker gate, gateway dependencies, Claude floor, attestation schema); the `sc.exe` argument lists `Set-DefenseClawManagedServices` issues at install (create and reconfigure, automatic and deferred start, with and without the sensor helper), recorded through stubs and identical to the f05a9d3c module; `-Mode`/`-Connector` config.yaml and targets.yaml rendering; connector allow-lists and version placeholders; read-only Status keys; cross-profile record decisions (a standalone deployment record a standard user could plant, as a file or a folder, does not block a Secure Client install; one an administrator wrote does); the `deployment.json` document `New-DefenseClawDeploymentMetadata` writes for an installed Secure Client deployment and for a tombstone, and what `Get-DefenseClawDeploymentMetadata` reads back from Secure Client records (identical to the f05a9d3c module; a record naming the standalone profile is refused) |
| `go/setup_command_line.json` | `cmd/defenseclaw-enterprise-setup` | Secure Client Setup (`DefenseClawSetup-Enterprise-x64.exe`) usage text, the options each accepted command line parses to, and the exact refusal text (plain and `--json`) for every rejected one, including the standalone-only `ensure` action and `--allowed-signers` flag; generated from the pre-standalone Setup |
| `windows/lifecycle_profile_resolution.json` | `internal/cli` (Windows only) | the profile `defenseclaw enterprise windows <action>` resolves for Secure Client Setup inputs (no `--profile`, a config without an `enterprise:` block, `--broker-binary`) on a host with no record, a Secure Client record, an unreadable one, or a Secure Client tombstone, in certification scope, and the refusals of standalone-only inputs; and, against records on disk judged by the production record inspector and validator, a standalone record a standard user planted as a file or a folder (ignored, for an administrator and for a standard user) and one an administrator wrote (refused) |
| `windows/setup_lifecycle_arguments.json` | `cmd/defenseclaw-enterprise-setup` (Windows only) | the `defenseclaw enterprise windows ...` argument vector the Secure Client Setup passes the lifecycle for each accepted command line |
| `macos/*` | `packaging/macos/tests/test_secure_client_golden.sh` | `render_config`, `render_targets_manifest`, AI Defense endpoint selection, supported connectors |
| `source_tripwire.json` | `scripts/secure_client_golden.py` | SHA-256 of git-tracked Secure Client sources (macOS and launchd packaging, the AVC build kit, CMID/cloudreg/broker code, the Secure Client IPC contract and the managed local IPC server, listener, ACL, peer-auth and path code) and of the Secure Client-defining functions and constants in `packaging/windows/DefenseClawEnterprise.psm1` and `install-enterprise.ps1`, including every profile helper they call for their Secure Client branch, the cross-profile conflict checks (and the record-trust test they apply to the other profile's deployment record), and the installer's `param()` block |

Linux has no Secure Client distribution. Platform-keyed goldens skip there;
the platform-independent ones (gateway and CLI posture, Codex requirements) and the
source tripwire run on every platform.

## Running

```bash
go test -count=1 -run TestSecureClientGolden \
  ./internal/config ./internal/ipc ./internal/sensor/acquire \
  ./internal/gateway/connector ./internal/gateway \
  ./cmd/defenseclaw-enterprise-setup ./internal/cli
packaging/macos/tests/run_tests.sh packaging/macos/tests/test_secure_client_golden.sh   # macOS
python3 scripts/secure_client_golden.py
uv run --frozen python -m pytest cli/tests/test_secure_client_golden.py -q
```

On Windows the pytest file also runs `secure-client-golden.ps1` under every
installed engine (Windows PowerShell 5.1, which production Secure Client uses,
and PowerShell 7). CI covers Linux (full Go and Python suites), Windows (Go
and Python shards), and macOS (the `secure-client-golden` job).

## Regenerating (only for a reviewed, intended Secure Client change)

A drift failure means production Secure Client behavior would change. Treat it
as a release-blocking review item, not a fixture to refresh. When the change is
intended:

```bash
# Go fixtures; platform-keyed files regenerate only the current OS entry,
# so run this on macOS and on Windows.
DEFENSECLAW_UPDATE_SECURE_CLIENT_GOLDEN=1 go test -count=1 -run TestSecureClientGolden \
  ./internal/config ./internal/ipc ./internal/sensor/acquire \
  ./internal/gateway/connector ./internal/gateway \
  ./cmd/defenseclaw-enterprise-setup ./internal/cli

# Windows lifecycle (on Windows; run elevated on a host without a
# managed_enterprise deployment). The script is read-only: it creates no
# service, user, registry key, managed root, or machine policy.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  packaging\windows\tests\secure-client-golden.ps1 `
  -GoldenPath testdata\secure_client_golden\windows\lifecycle.json -Update

# macOS installer renderers
UPDATE_SECURE_CLIENT_GOLDEN=1 packaging/macos/tests/run_tests.sh \
  packaging/macos/tests/test_secure_client_golden.sh

# Source tripwire
python3 scripts/secure_client_golden.py --update
```

The Windows Go fixtures can be produced without a Windows toolchain by
cross-compiling the test binaries (`GOOS=windows go test -c`) and running them
on a Windows host from a directory that mirrors `go.mod` and this directory.

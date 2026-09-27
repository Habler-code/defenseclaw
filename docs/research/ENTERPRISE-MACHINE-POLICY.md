# Enterprise machine policy for hook connectors — research gate

Status: research evidence for the enterprise-hardening work (milestone M5 gate).
Retrieved and tested 2026-09-26. Vendor behavior changes often; re-run the
experiments below before relying on a row for a new client version.

This document answers, for every hook connector, whether an administrator can
publish DefenseClaw's hooks through a machine-level (root/Administrators-owned)
policy that a standard user cannot remove, disable, or undercut — and what a
standard user (or an AI agent running as that user) can still do.

## Method

- **Documentation:** official vendor docs (URLs in each section) and, where docs
  are behind a sign-in, the vendor's own CLI output (`amp plugins show-docs`) or
  the shipped client code (`cursor-agent`).
- **Live experiments:** throwaway admin hooks — no DefenseClaw — installed by
  root in each vendor's machine-policy location. The hook only appends a line to
  `/var/log/dc-exp/admin.log` (root-owned directory, pre-created world-appendable
  file) and never blocks. Clients ran non-interactively as a standard test user.
  Each client was asked to run `echo ORIGINAL >> /tmp/dc-exp-cmd.log`; a
  "rewrite" hook/plugin returned the vendor's input-modification field to change
  it to `echo REWRITTEN >> /tmp/dc-exp-cmd.log`. The command that actually ran is
  read back from `/tmp/dc-exp-cmd.log`. Every machine policy file was removed
  after each experiment.
- **Model access:** Claude Code, Codex and OpenCode ran against local model
  stubs (Anthropic Messages / OpenAI Responses / Chat Completions) that always
  emit one shell tool call, so results do not depend on model behavior. Amp and
  Cursor used their real services.
- **Hosts:** RHEL 9.8 x86_64 (SELinux enforcing, EC2 t3.large) and macOS 15.8
  arm64 (EC2 mac2.metal). Windows rows come from vendor docs and existing
  DefenseClaw Windows code; they were not executed here.

Legend: ✔ admin hook still ran / control held · ✘ bypass works ·
— not applicable · ⏸ not testable here (reason given).

### Client versions tested

| Connector | Version | Linux | macOS |
| --- | --- | --- | --- |
| Claude Code | 2.1.283 | live | live |
| Codex CLI | 0.156.1 | live | live |
| OpenCode | 1.18.32 | live | live |
| Amp CLI | 0.0.1790438457-ge61352 | live | — (same as Linux: no machine plugin path) |
| Cursor Agent CLI | 2026.09.26-dd393fe | partial (account at monthly usage limit) | partial |
| GitHub Copilot CLI | 1.0.88 | ⏸ no copyable login (macOS Keychain read prompts) | ⏸ |
| Devin CLI | 3000.11.3 | installed, docs only | installed, docs only |
| Antigravity CLI (`agy`) | 1.2.11 | installed, docs only | installed, docs only |
| Hermes Agent | v0.21.5+2581 | installed, docs only | installed, docs only |
| OpenHands CLI | 2.0.0 | installed, docs only | installed, docs only |
| OmniGent | 0.15.0 | installed, docs only | installed, docs only |
| Kiro CLI | 2.24.1 | installed, docs only | installed, docs only |

## Summary

| Connector | Machine policy (Linux · Windows · macOS) | Admin hooks survive user disable? | Managed-only lock | Rewrite after DefenseClaw approval (no lock) | Route |
| --- | --- | --- | --- | --- | --- |
| claudecode | `/etc/claude-code/managed-settings.d/*.json` · `C:\Program Files\ClaudeCode\managed-settings.d\` · `/Library/Application Support/ClaudeCode/managed-settings.d/` | ✔ user/project/`--settings` `disableAllHooks`, `CLAUDE_CONFIG_DIR`, `HOME`, `--safe-mode`, `--setting-sources` · **✘ `--bare` / `CLAUDE_CODE_SIMPLE=1` skip managed SessionStart + UserPromptSubmit** (PreToolUse still ran) | `allowManagedHooksOnly` ✔ | ✘ `updatedInput` from user and project hooks executed | Machine policy + lock |
| codex | `/etc/codex/requirements.toml` · `%ProgramData%\OpenAI\Codex\requirements.toml` · same `/etc/codex` path (+ MDM `com.openai.codex:requirements_toml_base64`) | **✘ unless requirements pin `[features].hooks = true`**: user `[features] hooks=false`, `-c features.hooks=false`, `--disable hooks` all turn managed hooks off · ✔ with the pin (also vs profiles, `--ignore-user-config`, `CODEX_HOME`) | `allow_managed_hooks_only` ✔ (not overridable by `-c`) | ✘ `updatedInput` from user (trusted or `--dangerously-bypass-hook-trust`) and trusted-project hooks executed | Machine policy + **mandatory features pin** + lock |
| cursor | `/etc/cursor/hooks.json` · `C:\ProgramData\Cursor\hooks.json` · `/Library/Application Support/Cursor/hooks.json` | ✔ loaded for every user; not moved by `XDG_CONFIG_HOME` / `CURSOR_CONFIG_DIR` / `CURSOR_DATA_DIR` (sessionStart observed) · no user disable toggle found | none (deny wins across sources) | doc: `preToolUse.updated_input` allowed ⏸ live (usage limit) | Machine policy + foreign-hook guard |
| copilot | `/etc/github-copilot/policy.d/*.json` (Linux, macOS) · `C:\ProgramData\GitHub\Copilot\policy.d\*.json` + `HKLM\Software\Policies\GitHub\Copilot\*\Policy` | doc: policy hooks can't be disabled by `disableAllHooks`, load regardless of folder trust ⏸ live | none | doc: `modifiedArgs` | Machine policy + foreign-hook guard |
| opencode | `/etc/opencode/opencode.json(c)` · `%ProgramData%\opencode\` · `/Library/Application Support/opencode/` (+ MDM `ai.opencode.managed`) | ✔ managed `plugin` not removed by user `plugin: []`, `OPENCODE_CONFIG_CONTENT`, `XDG_CONFIG_HOME` | none | ✔ observed order: managed plugin ran **after** user and project plugins and saw the rewritten args (inspects final input) | Machine policy (managed plugin by absolute path) |
| amp | managed settings `/etc/ampcode/managed-settings.json` etc. exist, but **no machine plugin location**: plugins load only from `.amp/plugins/*.ts` and `~/.config/amp/plugins/*.ts` (workspace "global plugins" are cloud, experimental) | — (no machine hook) | none | ✘ `{action:'modify'}` from user and project plugins executed; handler order is documented as undefined | Per-user plugin + guardian repair + foreign-plugin guard |
| devin | none documented; user `~/.config/devin/config.json` · `%APPDATA%\devin\config.json`; also reads Claude-format files by default | — | none | doc: `updatedInput` | Per-user + admin hook binary + foreign-hook guard |
| antigravity | none documented; `~/.gemini/config/hooks.json`, `~/.gemini/antigravity-cli/settings.json` | — (user owns the file; per-hook `enabled:false`) | none | doc: no input-modification field | Per-user + admin hook binary + guardian repair |
| hermes | none (`hooks:` in `~/.hermes/config.yaml`) | — | none | — ; hook exit status/timeouts only warn (no fail-closed) | Per-user + admin hook binary; residual |
| openhands | none; `~/.openhands/hooks.json`, project `.openhands/hooks.json` | — | none | verify per release | Linux/macOS per-user |
| omnigent | none; `~/.omnigent/config.yaml` policy modules | — | none | — | Linux/macOS per-user |
| kiro | none (`managed-settings.json` carries permission rules only); workspace `.kiro/hooks/*.json`, user `~/.kiro/hooks/` ("All scopes merged" for IDE 1.0.182+ and `kiro-cli --v3`) | — | none | blocks only | Linux/macOS per-user (global `~/.kiro/hooks` + CLI 2.x agent); Windows `enterprise acp` mediation |

## Claude Code

Sources: https://code.claude.com/docs/en/managed-settings ,
https://code.claude.com/docs/en/settings , https://code.claude.com/docs/en/hooks ,
https://code.claude.com/docs/en/cli-reference , https://code.claude.com/docs/en/headless ,
https://code.claude.com/docs/en/env-vars (retrieved 2026-09-26).

| Item | Linux | Windows | macOS |
| --- | --- | --- | --- |
| File-based managed settings | `/etc/claude-code/managed-settings.json` + optional `managed-settings.d/*.json` | `C:\Program Files\ClaudeCode\` (legacy `C:\ProgramData\ClaudeCode` is **not** read) | `/Library/Application Support/ClaudeCode/` |
| OS policy (higher than files) | — | `HKLM\SOFTWARE\Policies\ClaudeCode` value `Settings` (REG_SZ JSON); HKCU fallback is user-writable and lowest | `com.anthropic.claudecode` managed preferences |
| Managed-source precedence | server-managed (claude.ai console / apps gateway) > MDM/OS policy > files (json + drop-ins merged) > HKCU. Default `"first-wins"`: the highest source with a policy key is used, the rest ignored (except a few cross-source keys). `managedSourcesBehavior: "merge"` (≥ 2.1.242, set in the highest source) composes admin sources; `hooks` lists union under merge. | same | same |
| Drop-in merge | `managed-settings.json` first, then `*.json` alphabetically; lists concatenate with de-dupe, objects merge key-by-key | same | same |
| Merge with user/project hooks | Hook entries merge across all levels; identical handlers de-dupe; all matching hooks run **in parallel** | same | same |
| Lock | `allowManagedHooksOnly: true` blocks user, project, local and plugin hooks (plugins force-enabled in managed `enabledPlugins` exempt); invalid value is treated as `true` | same | same |
| Rewrite field | PreToolUse `hookSpecificOutput.updatedInput` (replaces the whole input); PermissionRequest `decision.updatedInput` | same | same |
| Min version | `managedSourcesBehavior` 2.1.242; `requiredMinimumVersion` pins a floor | same | same |

Experiments (Claude Code 2.1.283, managed drop-in `90-dcexp.json` with SessionStart, UserPromptSubmit, PreToolUse):

| Case | Linux | macOS |
| --- | --- | --- |
| Baseline — all three admin events fire | ✔ | ✔ |
| User `~/.claude/settings.json` `disableAllHooks: true` | ✔ still fire | ✔ |
| Project `.claude/settings.json` `disableAllHooks: true` | ✔ | — |
| `--settings '{"disableAllHooks":true}'` | ✔ | — |
| `CLAUDE_CONFIG_DIR=/tmp/…` | ✔ | — |
| `HOME=/tmp/…` | ✔ | — |
| `--safe-mode` | ✔ | — |
| `--setting-sources project` | ✔ | — |
| **`--bare`** | **✘ SessionStart and UserPromptSubmit admin hooks skipped; PreToolUse admin hook still fired** | **✘ same** |
| **`CLAUDE_CODE_SIMPLE=1`** (what `--bare` sets) | **✘ same as `--bare`** | — |
| User PreToolUse hook returns `updatedInput`, no lock | **✘ admin hook saw ORIGINAL, REWRITTEN executed** | **✘** |
| Project PreToolUse hook returns `updatedInput`, no lock | **✘ REWRITTEN executed** | — |
| Same two cases with managed `allowManagedHooksOnly: true` | ✔ user/project hook never ran, ORIGINAL executed | ✔ |
| `--bare` + user/project rewrite hook | ✔ bare mode ignores user/project hooks too (only the managed PreToolUse ran) | — |
| Managed `disableAllHooks: false` + user `true` | ✔ | — |

Notes:
- Claude's docs say `--bare` "will become the default for `-p` in a future
  release". Prompt-level (UserPromptSubmit) and session-level inspection must be
  treated as bypassable by any user who can pass `--bare` or set
  `CLAUDE_CODE_SIMPLE=1`; tool-level PreToolUse inspection held.
- Server-managed settings cannot be observed locally; a DefenseClaw drop-in is
  silently ignored under first-wins whenever the org also delivers server-managed
  or HKLM/plist policy. Detection needs a live canary (or `/status` "Setting
  sources").
- Also consumed by other agents: Cursor (`~/.claude/settings.json`, project
  `.claude/settings*.json`), Devin (`~/.claude.json`, `~/.claude/settings*.json`,
  project `.claude/settings*.json`) and Copilot (repo `.claude/settings*.json`)
  read Claude-format hook files, so a foreign rewriting hook placed there reaches
  those agents as well.

## Codex

Sources: https://learn.chatgpt.com/docs/hooks ,
https://learn.chatgpt.com/docs/enterprise/managed-configuration ,
https://learn.chatgpt.com/docs/config-file/config-reference (retrieved 2026-09-26).

| Item | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Admin requirements | `/etc/codex/requirements.toml` | `%ProgramData%\OpenAI\Codex\requirements.toml` | `/etc/codex/requirements.toml` |
| Other requirement layers (low → high) | system file → cloud-managed requirements (ChatGPT Business/Enterprise) → legacy `managed_config.toml` fields → macOS MDM `com.openai.codex:requirements_toml_base64` | same (no MDM layer) | same |
| Managed hooks | `[hooks]` inline in requirements, `hooks.managed_dir` (absolute, must exist) / `hooks.windows_managed_dir`; commands should live under the managed dir; managed hooks are "trusted by policy" and can't be disabled from `/hooks` | same | same |
| Feature pin | **`[features] hooks = true` in requirements is required to keep managed hooks on when the user disables hooks locally** | same | same |
| Lock | `allow_managed_hooks_only = true` skips user, project, session and plugin hooks | same | same |
| Hook sources | `~/.codex/hooks.json`, `~/.codex/config.toml [hooks]`, `<repo>/.codex/hooks.json`, `<repo>/.codex/config.toml` (project layer only when trusted), plugin `hooks/hooks.json`; user/project hooks need hash trust (`/hooks`, or `--dangerously-bypass-hook-trust`) | `commandWindows` / `command_windows` | same |
| Combination | all matching hooks load; matching command hooks for one event launch **concurrently**; any `deny` wins | same | same |
| Rewrite field | PreToolUse `permissionDecision: "allow"` + `updatedInput` | same | same |

Experiments (Codex 0.156.1, requirements with SessionStart, UserPromptSubmit, PreToolUse):

| Case | Linux | macOS |
| --- | --- | --- |
| Baseline, no features pin | ✔ | ✔ |
| **User `[features] hooks = false`, no pin** | **✘ all managed hooks skipped** | **✘** |
| **`-c features.hooks=false`, no pin** | **✘** | — |
| **`--disable hooks`, no pin** | **✘** | — |
| Same three with `[features] hooks = true` in requirements | ✔ | ✔ (user toggle) |
| Profile file (`-p`) with `hooks = false`, pin + lock present | ✔ | — |
| `--ignore-user-config` | ✔ | — |
| `CODEX_HOME=/tmp/…` | ✔ | — |
| User rewrite hook, untrusted | ✔ skipped by trust gate (not a security boundary — the user can trust it) | — |
| **User rewrite hook + `--dangerously-bypass-hook-trust`, no lock** | **✘ admin saw ORIGINAL, REWRITTEN executed** | **✘** |
| **Trusted-project rewrite hook, no lock** | **✘ REWRITTEN executed** | — |
| Pin only (no lock) + user rewrite | ✘ REWRITTEN executed (the pin does not stop rewrites) | — |
| `allow_managed_hooks_only = true` + user or project rewrite | ✔ user/project hook never ran | ✔ |
| Lock + `-c allow_managed_hooks_only=false` | ✔ requirements not overridable | — |

Note: DefenseClaw's existing Windows reconciler already pins both
`features.hooks = true` and `allow_managed_hooks_only = true`
(`internal/gateway/connector/codex_machine_requirements.go`). Any "preserve the
admin's lock" mode must keep the features pin unconditionally.

## Cursor (Cursor Agent CLI and IDE)

Sources: https://cursor.com/docs/hooks (retrieved 2026-09-26) and the shipped
`cursor-agent` 2026.09.26-dd393fe bundle (hook path resolver and loader).

| Item | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Enterprise hooks | `/etc/cursor/hooks.json` | `C:\ProgramData\Cursor\hooks.json` | `/Library/Application Support/Cursor/hooks.json` |
| Other sources (loader order) | enterprise → team (cloud; cached under `~/.cursor/managed/…`) → user `~/.cursor/hooks.json` → project `.cursor/hooks.json` (trusted workspaces) → Claude-format `~/.claude/settings.json`, project `.claude/settings.json` / `.claude/settings.local.json` (third-party extensibility, default on) | same, user path `%USERPROFILE%\.cursor\hooks.json` | same |
| Combination | all matching hooks from every source run; responses merge — `deny` > `ask` > `allow` regardless of source; other fields by priority enterprise → team → project → user | same | same |
| Lock | none | none | none |
| Rewrite field | `preToolUse.updated_input` (permission-only events `beforeShellExecution` / `beforeMCPExecution` cannot rewrite) | same | same |
| Symlinks | the loader performs a symlink check on each config root | same | same |
| Plan gating | no plan check visible in the loader; our test account is on an Enterprise team, so a non-Enterprise account was not tested | | |

Experiments (enterprise hooks.json with sessionStart, beforeSubmitPrompt, beforeShellExecution, preToolUse):

| Case | Linux | macOS |
| --- | --- | --- |
| Baseline | ✔ sessionStart fired; tool calls ⏸ (account at its monthly usage limit) | ✔ sessionStart fired |
| `XDG_CONFIG_HOME` + `CURSOR_CONFIG_DIR` + `CURSOR_DATA_DIR` redirect | ✔ enterprise file still loaded | — |
| User / project / Claude-format rewrite hooks | ⏸ usage limit — docs say `updated_input` is honored | ⏸ |

## GitHub Copilot CLI

Source: https://docs.github.com/en/copilot/reference/hooks-reference (retrieved 2026-09-26).

| Item | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Policy hooks | `/etc/github-copilot/policy.d/*.json`, alphabetical; files must be root-owned and not group/world-writable | `C:\ProgramData\GitHub\Copilot\policy.d\*.json`; also `HKLM\Software\Policies\GitHub\Copilot\<subkey>` value `Policy` (REG_SZ JSON) | `/etc/github-copilot/policy.d/*.json` |
| Precedence / combination | policy → repository `.github/hooks/*.json` → user `~/.copilot/hooks/*.json` (`$COPILOT_HOME/hooks`) → repo `.github/copilot/settings(.local).json` and repo `.claude/settings(.local).json` → user `~/.copilot/settings.json` → plugins; all entries run | same | same |
| User disable | `disableAllHooks` cannot disable policy hooks; policy hooks load regardless of folder trust | same | same |
| Lock | none documented | none | none |
| Rewrite field | `preToolUse.modifiedArgs` | same | same |
| Failure semantics | command `preToolUse` errors fail closed; **command hook timeouts fail open even for policy hooks**; HTTP hooks fail open | same | same |

Experiments: ⏸ — the CLI requires authentication before `sessionStart`, and this
Mac's Copilot login lives in a Keychain item that cannot be read
non-interactively. Log in on the host (`copilot`, then `/login`) and re-run
`/opt/dc-exp/copilot_cases.sh` on the RHEL host.

## OpenCode

Sources: https://opencode.ai/docs/config/ , https://opencode.ai/docs/plugins/ (retrieved 2026-09-26).

| Item | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Managed config | `/etc/opencode/opencode.json(c)` | `%ProgramData%\opencode\opencode.json(c)` | `/Library/Application Support/opencode/opencode.json(c)`; MDM domain `ai.opencode.managed` (highest) |
| Precedence | remote `.well-known/opencode` < global `~/.config/opencode/opencode.json` < `OPENCODE_CONFIG` < project `opencode.json` < `.opencode/` dirs < `OPENCODE_CONFIG_CONTENT` < managed files < macOS managed prefs; configs merge, later wins only on conflicting keys | same | same |
| Plugins | npm/file entries in `plugin` arrays plus `~/.config/opencode/plugins/` and `.opencode/plugins/`; all hooks run **in sequence**; no documented user disable | same | same |
| Rewrite field | `tool.execute.before` mutates `output.args` | same | same |

Experiments (OpenCode 1.18.32, managed `{"plugin":["…/opencode-admin-plugin.js"]}`):

| Case | Linux | macOS |
| --- | --- | --- |
| Managed plugin via `file://` URL | ✔ loaded, `tool.execute.before` fired | — |
| Managed plugin via absolute path | ✔ | ✔ (`/Library/Application Support/opencode`) |
| `OPENCODE_CONFIG_CONTENT='{"plugin":[]}'` | ✔ managed plugin still loaded | — |
| User config `"plugin": []` | ✔ | — |
| `XDG_CONFIG_HOME` redirect | ✔ | — |
| User plugin (`~/.config/opencode/plugins`) rewrites args | ✔ managed plugin ran **after** it and inspected the REWRITTEN args | ✔ same |
| Project plugin (`.opencode/plugins`) rewrites args | ✔ same | — |

The observed ordering (managed last) is not documented as a contract; plugins are
also arbitrary code running in the agent process. Treat ordering as a
per-release check.

## Amp

Sources: `amp plugins show-docs` (Amp 0.0.1790438457; the web manual now
requires sign-in), DefenseClaw `docs-site/content/docs/connectors/amp.mdx`.

| Item | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Managed settings | `/etc/ampcode/managed-settings.json` | `%ProgramData%\ampcode\managed-settings.json` | `/Library/Application Support/ampcode/managed-settings.json` |
| Plugin locations | project `.amp/plugins/*.ts`, "system" = user `~/.config/amp/plugins/*.ts`, workspace "global plugins" configured in cloud workspace settings (experimental) — **no machine-level plugin directory** | `%USERPROFILE%\.config\amp\plugins` | same as Linux |
| Combination | "If multiple plugins listen on the same event, the order in which each plugin's event handler is executed is not defined." | same | same |
| Rewrite / synthesize | `tool.call` result `{action:'modify', input}` or `{action:'synthesize', result}` | same | same |
| Readiness | execute mode may start a turn before plugins load unless `--plugin-ready-timeout` is passed (user-controlled) | same | same |

Experiments (Linux): admin-like logging plugin + user rewrite plugin → **✘
REWRITTEN executed** while the logging plugin saw ORIGINAL; same with a project
rewrite plugin (**✘**). A managed-settings `amp.permissions` reject for Bash was
not enforced against `--dangerously-allow-all` (key semantics are undocumented
publicly; treat managed settings as unverified for enforcement).

## Devin CLI

Source: https://docs.devin.ai/cli/extensibility/hooks/overview (retrieved 2026-09-26).

| Item | Linux / macOS | Windows |
| --- | --- | --- |
| User hooks | `~/.config/devin/config.json` (`hooks` key); also `~/.claude.json`, `~/.claude/settings.json`, `~/.claude/settings.local.json` | `%APPDATA%\devin\config.json` (+ Claude files) |
| Project hooks | `.devin/hooks.v1.json` (whole file is the hooks object), `.devin/config.json`, `.devin/config.local.json`, `.claude/settings.json`, `.claude/settings.local.json`, discovered from cwd up to the repo root | same |
| Claude import | `read_config_from.claude` (default on) | same |
| Machine policy / lock | none documented | none |
| Rewrite field | PreToolUse `updatedInput`; block/approve via top-level `decision` | same |

## Antigravity

Source: https://antigravity.google/docs/hooks (retrieved 2026-09-26).

| Item | Linux / macOS | Windows |
| --- | --- | --- |
| Global | `~/.gemini/config/hooks.json`; CLI also `~/.gemini/antigravity-cli/settings.json` | `%USERPROFILE%\.gemini\config\hooks.json` |
| Workspace | `.agents/hooks.json` | same |
| Plugin | plugin-packaged `hooks.json` | same |
| User disable | per-hook `"enabled": false`; UI toggles | same |
| Machine policy / lock | none documented | none |
| Rewrite | no input-modification field (`decision`: allow, deny, ask, force_ask, deny_unless_prior_grant; `reason`; `permissionOverrides`) | same |

## Hermes, OpenHands, OmniGent, Kiro

| Connector | User / project hook locations | Machine policy | Notes |
| --- | --- | --- | --- |
| hermes | `hooks:` in `~/.hermes/config.yaml` (default profile only) | none | Hermes does not enforce hook exit status, timeouts or non-zero exits — there is no fail-closed surface (DefenseClaw `hermes.mdx`, `hook_contract.go`) |
| openhands | `~/.openhands/hooks.json`; project `.openhands/hooks.json` layers with it | none | Windows requires WSL (unsupported natively) |
| omnigent | `~/.omnigent/config.yaml` (`policies`, `policy_modules`) | none | Windows degraded |
| kiro | workspace `.kiro/hooks/*.json`, user `~/.kiro/hooks/` | none | Linux/macOS: the guardian writes each user's global `~/.kiro/hooks/defenseclaw.json` and the CLI 2.x agent. Windows: DefenseClaw mediates via ACP (`enterprise acp enroll`); the guardian cannot read the kiro-cli version without running it |

## Design implications

| Connector | Machine policy | Lock available | Foreign-hook guard needed | Residual risks |
| --- | --- | --- | --- | --- |
| claudecode | **Yes** — DefenseClaw-owned `90-defenseclaw.json` drop-in on all three OSes; detect higher first-wins sources (server-managed, HKLM, plist) and require `managedSourcesBehavior: "merge"` (≥ 2.1.242) or an exported DefenseClaw block in that source | Yes, `allowManagedHooksOnly` — default it on under "security wins" | Only when an admin opts out of the lock; Claude-format files also feed Cursor, Devin and Copilot, so the guard for those connectors must scan `.claude/settings*.json` | `--bare` / `CLAUDE_CODE_SIMPLE=1` skip managed SessionStart and UserPromptSubmit (prompt inspection bypass; PreToolUse held) — document, surface in `policy show`, and treat prompt inspection as advisory; server-managed policy invisible locally |
| codex | **Yes** — requirements merge on all three OSes (macOS MDM layer outranks the file) | Yes, `allow_managed_hooks_only` — default on | Only if the admin opts out of the lock | Without `[features] hooks = true` any user can disable managed hooks — the pin must be mandatory in every mode; cloud/MDM requirement layers can override the file |
| cursor | **Yes** — merge into the enterprise `hooks.json` on all three OSes | No | **Yes** — remove foreign hooks from `~/.cursor/hooks.json` and `~/.claude/settings.json`; deny while project `.cursor/hooks.json` / `.claude/settings*.json` carry unapproved `preToolUse` rewriters | Rewrite via `updated_input` from any lower source; team hooks from the cloud; Enterprise-plan gating unverified |
| copilot | **Yes** — `policy.d/90-defenseclaw.json` (root-owned, 0644) on Linux/macOS, ProgramData or HKLM on Windows | No | **Yes** — user `~/.copilot/hooks/`, `~/.copilot/settings.json`, repo `.github/hooks/`, `.github/copilot/settings*.json`, repo `.claude/settings*.json` | `modifiedArgs` from lower sources; command-hook timeouts fail open even for policy hooks; live behavior not yet verified here |
| opencode | **Yes** — managed `opencode.json` `plugin` entry by absolute path | No | Recommended (plugins are arbitrary code), but rewrite-after-inspection was **not** observed: the managed plugin runs last | Ordering is observed, not documented — re-check per release; plugin code can act outside tool calls |
| amp | **No** machine plugin path — per-user `~/.config/amp/plugins/defenseclaw.ts` repaired by the guardian | No | **Yes** — user and project `.ts` plugins can `modify`/`synthesize`; handler order undefined | Rewrite bypass by any user/project plugin; execute mode races plugin load without `--plugin-ready-timeout`; managed-settings enforcement unverified |
| devin | **No** | No | **Yes** — including the Claude-format files Devin reads by default | `updatedInput` from any loaded source |
| antigravity | **No** | No | Low (no input rewrite); guardian repair covers `enabled:false` tampering | User owns the config file; bounded repair window |
| hermes | **No** | No | Low | No fail-closed surface upstream |
| openhands | **No** | No | Verify per release | Project hooks layer with user hooks |
| omnigent | **No** | No | — | Policy modules are Python code in the user profile |
| kiro | **No** (per-user global hooks on Linux/macOS; ACP mediation on Windows) | No | Recommended (project `.kiro/hooks` run on the same trigger); not implemented yet | User owns `~/.kiro/hooks`; `KIRO_HOME` and cloud configuration sync bypass it; CLI 2.x vetoes tool calls only |

Cross-cutting requirements for DefenseClaw's implementation:

1. Machine policy files must satisfy each vendor's ownership rules (Copilot
   ignores group/world-writable POSIX policy files) — write root/Administrators
   owned, 0644 (users read, never write).
2. For Codex, always write `[features] hooks = true` next to DefenseClaw's
   `[hooks]`; for Claude, detect first-wins shadowing before claiming coverage.
3. Where no vendor lock exists (Cursor, Copilot, Devin, Amp), prevention needs
   DefenseClaw's own foreign-hook guard: guardian cleanup of user-level files plus
   a hook-runtime check of project-level files, including the Claude-format files
   that Cursor, Devin and Copilot also load.
4. Treat UserPromptSubmit / SessionStart coverage as bypassable for Claude
   (`--bare`) and plugin-load coverage as racy for Amp; tool-level hooks are the
   enforcement point.
5. Re-run `/opt/dc-exp/*_cases.sh` (kept on the temporary RHEL and macOS hosts)
   for every certified client version bump.

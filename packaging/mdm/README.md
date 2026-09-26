# DefenseClaw managed enterprise: MDM deployment kit

This kit deploys the **standalone** managed-enterprise profile on Windows,
Linux and macOS with any MDM, configuration-management tool or administrator
shell. You don't need Cisco Secure Client. Secure Client deployments keep using
their own installer and are not affected by anything here.

The standalone profile installs DefenseClaw as protected system services. A
standard user cannot stop them, reconfigure them or remove the managed hooks.
Every lifecycle action is a transaction that rolls back on failure. `ensure`
installs, upgrades or repairs as needed, and does nothing when the host
already matches, so an MDM can run it on every check-in.

## What is here

| Path | Use |
| --- | --- |
| `contract/lifecycle-result.schema.json` | The JSON document every lifecycle action and every script in this kit prints (schema version 2). |
| `contract/exit-codes.md` | Exit codes per OS, what they mean, and which ones an MDM should retry. |
| `contract/detection.md` | How to tell an MDM that DefenseClaw is installed, current and healthy. |
| `windows/Invoke-DefenseClawEnterprise.ps1` | Generic Windows wrapper (PowerShell 7). Verifies and runs `DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure`. |
| `windows/detect.ps1`, `windows/uninstall.ps1` | Windows detection and removal. These run in Windows PowerShell 5.1 (32- or 64-bit) and PowerShell 7. |
| `linux/*.sh`, `macos/*.sh` | Generic wrapper (`defenseclaw-enterprise.sh`), `detect.sh` and `uninstall.sh`. The Linux and macOS copies differ only in the line `DC_SCRIPT_OS`. |
| `intune/` | Microsoft Intune guide for Windows (Win32 app and Remediations), macOS (shell script or PKG) and Linux (platform script). |
| `signing/` | Signing channels, and `authenticode-sign.sh` for release signing or re-signing with your own certificate. |

## Quick start

1. **Get a release and pin it.** Download the release's `checksums.txt` and
   `checksums.txt.bundle`, then verify them with cosign:

   ```sh
   cosign verify-blob --bundle checksums.txt.bundle \
     --certificate-identity "https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
   ```

   Then read the SHA-256 of the artifact you deploy:

   | OS | Artifact |
   | --- | --- |
   | Windows | `DefenseClawSetup-Enterprise-Standalone-x64.exe` |
   | Linux | `defenseclaw-enterprise-<version>-linux-<arch>.deb` / `.rpm`, or the `.tar.gz` payload |
   | macOS | `defenseclaw-enterprise-<version>-darwin-arm64.pkg` |

   That SHA-256 is the pin for hash-pinned trust, the default. See
   `signing/README.md` for signature-based trust instead.
2. **Write the administrator config.** Start from `enterprise.profile:
   standalone` (see the enterprise documentation). Never put credentials in
   it: the standalone profile rejects an inline `cisco_ai_defense.api_key`.
3. **Run the wrapper as SYSTEM or root** from your MDM:

   ```powershell
   # Windows (PowerShell 7)
   pwsh -NoProfile -File Invoke-DefenseClawEnterprise.ps1 `
     -SetupPath C:\Staging\DefenseClawSetup-Enterprise-Standalone-x64.exe -Sha256 <pin> `
     -ConfigPath C:\Staging\config.yaml
   ```

   ```sh
   # Linux (deb or rpm) and macOS (pkg)
   sudo ./defenseclaw-enterprise.sh --source /var/cache/mdm/defenseclaw-enterprise-1.4.0-linux-amd64.deb \
     --sha256 <pin> --config-file /etc/mdm/defenseclaw/config.yaml
   ```

4. **Deliver the optional Cisco AI Defense key** on standard input or from
   an administrator-only file, never as an argument:

   ```sh
   sudo ./defenseclaw-enterprise.sh --secret-name ai-defense-api-key --secret-stdin </secure/key
   ```

5. **Detect** with `detect.ps1` / `detect.sh`, or the registry and package
   rules in `contract/detection.md`. **Remove** with `uninstall.ps1` /
   `uninstall.sh`.

## What the wrappers guarantee

- **Verify, then install.** The wrapper copies the source into a fresh
  directory that only SYSTEM/Administrators or root can use, and verifies
  the copy. The copy it verified is the copy that gets installed, so
  changing the original afterwards has no effect.
- **No secrets in argv, logs or MDM script bodies.** Config and credentials
  come from standard input, or from files that other accounts cannot write.
  Credential files are overwritten and deleted after use.
- **No trust in the caller's environment.**
  - Unix scripts set their own `PATH` and locale, and work under `env -i`
    with no TTY.
  - Windows scripts read Program Files and the enterprise marker through
    the protected 64-bit registry view, even from a 32-bit host.
  - The PowerShell 7 wrapper refuses:
    - an untrusted or emulated engine;
    - Constrained Language Mode;
    - .NET loader-injection variables.
- **One result document on stdout.** Every run prints exactly one
  lifecycle-result document (`contract/lifecycle-result.schema.json`),
  including failures the wrapper detects itself. Those failures use error
  codes that start with `mdm_`.
- **Idempotent.** `ensure` does nothing when the host already matches.
  `uninstall` succeeds on a host that has nothing installed.

## Tested

Windows (Server 2025) and Linux / macOS (RHEL 9 and macOS 15 EC2 hosts):

- **Every script** runs on each engine or shell it supports:
  - Windows PowerShell 5.1 in 32- and 64-bit processes, and PowerShell 7.6;
  - `sh`/`dash` on RHEL 9 and macOS 15, run as root under `env -i`.
- **Refusal drills:**
  - bad arguments, hash mismatch, unapproved signer, loader-injection
    variables;
  - config files that other accounts can write, in a user-writable folder,
    in sticky `/tmp`, or owned by another account;
  - payloads containing symlinks, hard links, `../` or absolute members.
- **Authenticode:** a Valid signature from an allowed signer passes, and
  any other signer is refused, using a disposable test CA that was removed
  afterwards.
- **Schema:** every result document the scripts printed validates against
  the schema.

Real Intune tenants were not available; the Intune guide follows
Microsoft's documentation and the drills above, which simulate Intune's
execution contexts.

# Intune on Windows: Win32 app and Remediations

## 1. Prerequisite: PowerShell 7 as a dependency

The standalone lifecycle runs on PowerShell 7 and refuses without it. The
engine must be the x64 MSI, which registers under
`HKLM\SOFTWARE\Microsoft\PowerShellCore\InstalledVersions` and installs to
`C:\Program Files\PowerShell\7`. Add it as its own Win32 app:

| Field | Value |
| --- | --- |
| Content | `PowerShell-7.x.y-win-x64.msi` (from Microsoft, hash-checked) |
| Install command | `msiexec /i PowerShell-7.x.y-win-x64.msi /qn ADD_PATH=1 USE_MU=1 ENABLE_MU=1` |
| Uninstall command | `msiexec /x {product-code} /qn` |
| Detection | File: `C:\Program Files\PowerShell\7`, `pwsh.exe`, **Version** ≥ `7.4.0`, 32-bit app on 64-bit clients: **No** |

In the DefenseClaw app's **Dependencies** step, add this app with
**Automatically install** set to **Yes**.

## 2. Build the Win32 app content

On an administrator workstation with PowerShell 7:

```powershell
./New-DefenseClawIntunePackage.ps1 `
  -SetupPath .\DefenseClawSetup-Enterprise-Standalone-x64.exe `
  -Sha256 <SHA-256 from the cosign-verified checksums.txt> `
  -ConfigPath .\config.yaml `
  -OutputDirectory .\intune-defenseclaw-1.4.0 `
  -IntuneWinAppUtil C:\Tools\IntuneWinAppUtil.exe `
  -ProductVersion 1.4.0
```

The script:

1. Verifies the Setup.
2. Refuses a config that contains an inline `api_key`.
3. Writes `content\` containing the Setup, `config.yaml`,
   `Install-DefenseClawIntune.ps1` and `intune-package.json`, which holds the
   SHA-256 pins the launcher re-checks on the device.
4. Wraps the folder into a `.intunewin`.
5. Prints the values for the admin center.

For Authenticode trust, add:

```powershell
-TrustMode Authenticode -AllowedSigners <SHA-256 thumbprint of the signer certificate>
```

## 3. Create the Win32 app

| Step | Setting |
| --- | --- |
| Program: install command | `%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawIntune.ps1` |
| Program: uninstall command | `DefenseClawSetup-Enterprise-Standalone-x64.exe /uninstall JSON=1` (Intune does not expand environment variables in uninstall commands) |
| Install behavior | **System** |
| Device restart behavior | **Determine behavior based on return codes** |
| Return codes | Keep the defaults: `0` Success, `1707` Success, `3010` Soft reboot, `1641` Hard reboot, `1618` Retry. The lifecycle's `1603` and `1639` then report as Failed. |
| Requirements | Operating system architecture **x64** only (the lifecycle refuses ARM64 and 32-bit); minimum OS Windows 10 22H2 |
| Detection rule | Registry. Key `HKEY_LOCAL_MACHINE\SOFTWARE\Cisco\DefenseClaw\Enterprise`, value `ProductVersion`, **Version comparison**, **Greater than or equal to** `1.4.0`, *Associated with a 32-bit app on 64-bit clients*: **No**. Instead, you can use `packaging/mdm/windows/detect.ps1` as a custom detection script. |
| Dependencies | The PowerShell 7 app, **Automatically install: Yes** |
| Supersedence | New versions supersede the previous app with **Uninstall previous version: No**, because `/ensure` upgrades in place and keeps state. |
| Assignment | **Required** for device groups |

Why a launcher instead of calling the Setup directly:

- Setup refuses relative and environment-expanded paths.
- Intune's content folder path is not known in advance.

The launcher builds the absolute `CONFIG=` path, re-checks the pins, and
starts the native Setup. If the host is already installed and you only
upgrade the binaries, `DefenseClawSetup-Enterprise-Standalone-x64.exe
/ensure JSON=1` also works as the install command, because it reuses the
installed config.

The first install needs a config: `/ensure` refuses to install without one
(exit 1639).

## 4. Remediations (optional, recommended)

Create a script package with `Remediate-Detect.ps1` (detection) and
`Remediate-Fix.ps1` (remediation):

| Setting | Value |
| --- | --- |
| Run this script using the logged-on credentials | **No** (runs as SYSTEM) |
| Enforce script signature check | **No**, or **Yes** after you sign the scripts with a certificate in the devices' Trusted Publishers store |
| Run script in 64-bit PowerShell | **No** (the default). The scripts read the 64-bit registry view and launch the native x64 CLI either way. |
| Schedule | **Daily**, or **Hourly** every 4–8 hours |

The detection script:

- runs `defenseclaw.exe enterprise windows verify --profile standalone --json`;
- reports compliant (exit 0) on a healthy host or on a host without the
  deployment (the Win32 app handles installation);
- reports exit 1 otherwise.

The remediation script runs `enterprise windows ensure --profile
standalone --json`, which repairs from the installed payload. Both scripts
print a single short line, because Intune keeps 2,048 characters of output.

## 5. The Cisco AI Defense key

Do not put the key in the Win32 app, in `config.yaml` or in a script.

The Windows protected credential store is not available through `enterprise
secret set` in this build. Until it ships, run with
`enterprise.inspection.ai_defense.enabled: false`: the local policy engine
still enforces everything.

Once it ships, deliver the key over standard input on an administrator
session or through your secrets-management tooling:

```powershell
Get-Content key.txt | pwsh -File Invoke-DefenseClawEnterprise.ps1 -SecretName ai-defense-api-key -SecretFromStdin
```

## 6. Troubleshooting

| Where | What |
| --- | --- |
| `%WINDIR%\Logs\DefenseClaw\enterprise-lifecycle.log` | Every lifecycle result (JSON, one line per run) |
| Application event log, source "DefenseClaw Enterprise" | Installed, upgraded, repaired, failed, busy and refused events |
| `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AppWorkload.log` | Intune's view of the Win32 install and detection |
| `defenseclaw.exe enterprise windows status --profile standalone --json` | Current state; run it elevated |

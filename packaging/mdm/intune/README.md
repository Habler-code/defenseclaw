# Deploying DefenseClaw managed enterprise with Microsoft Intune

This guide deploys the standalone profile with Intune on each platform. It
follows Microsoft's current Intune documentation. It has not been run
against a live tenant, so run a pilot group first.

| Platform | Install | Detect | Keep healthy | Remove |
| --- | --- | --- | --- | --- |
| Windows 10/11 x64 | Win32 app (`windows.md`) | Registry rule on the marker version | Remediations pair | Win32 uninstall command |
| macOS 13+ (Apple silicon) | Shell script (recommended) or unmanaged PKG app (`macos.md`) | `detect.sh` custom attribute; pkg receipt | Script frequency | `uninstall.sh` shell script |
| Ubuntu Desktop, RHEL 8/9 | Linux platform script (`linux.md`) | `detect.sh` in the script | Script frequency (default every 15 minutes) | `uninstall.sh` platform script |

Intune's execution contexts shape the design:

- **Windows.** The Intune management extension is a 32-bit process. Install
  commands that call `powershell.exe`, as well as detection and Remediations
  scripts, run in Windows PowerShell 5.1, and in 32-bit unless you choose
  64-bit. So every Intune-facing Windows script here is 5.1-compatible and
  does only two things:
  - reads the enterprise marker through the 64-bit registry view;
  - launches the native x64 `DefenseClawSetup-Enterprise-Standalone-x64.exe`
    or `defenseclaw.exe`.

  The native binaries run the lifecycle, which re-verifies and launches its
  own trusted PowerShell 7 engine. Lifecycle logic never runs inside the
  Intune host.
- **macOS.** Shell scripts run as root unless you choose the signed-in user.
  They must be smaller than 1 MB and are stopped after 60 minutes. Intune
  does not support running them through a proxy.
- **Linux.** Platform scripts run as the signed-in user unless you choose
  **Root**. Only Ubuntu Desktop and RHEL 8/9 enrolled with the Intune app are
  supported. The first root run can ask the user for consent.
- **Everywhere.** Microsoft states that scripts and custom settings are not
  secret storage. Never embed the Cisco AI Defense key in an Intune script,
  a Win32 app or a config file. Deliver it as described on each platform
  page.

Real-tenant caveats:

- Intune cannot enroll Windows Server, so test Windows on Windows 10/11.
- Remediations need Windows Enterprise E3/E5, Education A3/A5, or Windows
  VDA per-user licenses.

# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Standalone uninstall and the managed OpenCode plugin. The standalone
# guardian installs <InstallRoot>\share\opencode\defenseclaw.js from the
# payload binaries. The install-tree walk must accept exactly that file and
# its two directories, removal after the services are gone must delete only
# them (refusing links and anything else, and deleting nothing when it
# refuses), and the Secure Client allow-list must stay unchanged. Runs in a
# disposable directory; no service or real machine root is touched.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot `
        '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath `
    -Force `
    -PassThru `
    -ErrorAction Stop

$root = [IO.Path]::Combine(
    [IO.Path]::GetFullPath($ScratchRoot),
    ('dcoc-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProfile = Get-DefenseClawEnterpriseProfile
        try {
            function New-TestLayout([string]$Base) {
                $install = [IO.Path]::Combine($Base, 'DefenseClaw')
                $bin = [IO.Path]::Combine($install, 'bin')
                $libexec = [IO.Path]::Combine($install, 'libexec')
                [void][IO.Directory]::CreateDirectory($bin)
                [void][IO.Directory]::CreateDirectory($libexec)
                $gateway = [IO.Path]::Combine($bin, 'defenseclaw-gateway.exe')
                [IO.File]::WriteAllText($gateway, 'stand-in')
                return @{
                    InstallRoot = $install
                    BinDirectory = $bin
                    LibexecDirectory = $libexec
                    ManagedIPCDirectory = [IO.Path]::Combine($install, 'ipc')
                    GatewayPath = $gateway
                    BrokerPath = ''
                    ACPPath = ''
                    HookPath = ''
                    SensorHelperPath = ''
                    CLIPath = ''
                    InstallerPath = ''
                    ModulePath = ''
                }
            }
            function New-Plugin([hashtable]$Layout) {
                $directory = [IO.Path]::Combine($Layout.InstallRoot, 'share', 'opencode')
                [void][IO.Directory]::CreateDirectory($directory)
                $plugin = [IO.Path]::Combine($directory, 'defenseclaw.js')
                [IO.File]::WriteAllText($plugin, '// defenseclaw-managed-opencode-plugin v1')
                return $plugin
            }
            function Test-Refused([string]$Label, [scriptblock]$Action, [string]$Pattern) {
                try {
                    & $Action
                    $failures.Add("${Label}: expected a refusal")
                }
                catch {
                    if ($_.Exception.Message -notmatch $Pattern) {
                        $failures.Add("${Label}: unexpected refusal: $($_.Exception.Message)")
                    }
                }
            }

            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
            $layout = New-TestLayout ([IO.Path]::Combine($Root, 'ok'))
            $paths = Get-DefenseClawStandaloneOpenCodePluginPaths -Layout $layout
            $plugin = New-Plugin $layout
            if (-not [string]::Equals([string]$paths.PluginPath, [IO.Path]::GetFullPath($plugin), [StringComparison]::OrdinalIgnoreCase)) {
                $failures.Add("plugin path $($paths.PluginPath), want $plugin")
            }
            try {
                Assert-DefenseClawManagedInstallTree -Layout $layout
            }
            catch {
                $failures.Add("standalone tree with the managed OpenCode plugin was refused: $($_.Exception.Message)")
            }
            Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $layout
            foreach ($gone in @($plugin, [string]$paths.PluginDirectory, [string]$paths.ShareDirectory)) {
                if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $gone) {
                    $failures.Add("$gone survived removal")
                }
            }
            if (-not [IO.Directory]::Exists($layout.BinDirectory)) {
                $failures.Add('removal touched the bin directory')
            }
            try {
                Assert-DefenseClawManagedInstallTree -Layout $layout
            }
            catch {
                $failures.Add("tree without the plugin was refused: $($_.Exception.Message)")
            }
            # Removal with nothing installed is a no-op.
            Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $layout

            # Anything other than the exact plugin stays refused, and a
            # refused removal deletes nothing.
            $extra = New-TestLayout ([IO.Path]::Combine($Root, 'extra'))
            $extraPlugin = New-Plugin $extra
            $planted = [IO.Path]::Combine([IO.Path]::GetDirectoryName($extraPlugin), 'planted.js')
            [IO.File]::WriteAllText($planted, 'x')
            Test-Refused 'unexpected plugin file (walk)' { Assert-DefenseClawManagedInstallTree -Layout $extra } 'unexpected file'
            Test-Refused 'unexpected plugin file (removal)' { Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $extra } 'unexpected managed OpenCode content'
            if (-not [IO.File]::Exists($planted) -or -not [IO.File]::Exists($extraPlugin)) {
                $failures.Add('refused removal still deleted content')
            }

            $sibling = New-TestLayout ([IO.Path]::Combine($Root, 'sibling'))
            [void](New-Plugin $sibling)
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($sibling.InstallRoot, 'share', 'policies'))
            Test-Refused 'unexpected share directory (walk)' { Assert-DefenseClawManagedInstallTree -Layout $sibling } 'unexpected directory'
            Test-Refused 'unexpected share directory (removal)' { Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $sibling } 'unexpected managed OpenCode content'

            $nested = New-TestLayout ([IO.Path]::Combine($Root, 'nested'))
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($nested.InstallRoot, 'share', 'opencode', 'defenseclaw.js'))
            Test-Refused 'directory named like the plugin' { Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $nested } 'not a plain file'

            $linked = New-TestLayout ([IO.Path]::Combine($Root, 'linked'))
            $linkedDirectory = [IO.Path]::Combine($linked.InstallRoot, 'share', 'opencode')
            [void][IO.Directory]::CreateDirectory($linkedDirectory)
            $target = [IO.Path]::Combine($Root, 'outside.js')
            [IO.File]::WriteAllText($target, 'keep')
            $linkCreated = $true
            try {
                [void](Microsoft.PowerShell.Management\New-Item -ItemType SymbolicLink -Path ([IO.Path]::Combine($linkedDirectory, 'defenseclaw.js')) -Target $target)
            }
            catch {
                $linkCreated = $false
            }
            if ($linkCreated) {
                Test-Refused 'symbolic link named like the plugin (walk)' { Assert-DefenseClawManagedInstallTree -Layout $linked } 'reparse point'
                Test-Refused 'symbolic link named like the plugin (removal)' { Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $linked } 'not a plain file'
                if (-not [IO.File]::Exists($target)) {
                    $failures.Add('link target outside the tree was removed')
                }
            }
            else {
                $failures.Add('could not create a symbolic link (the smoke must run elevated)')
            }

            # Secure Client keeps its original allow-list: share is not
            # accepted and removal is a no-op.
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
            $secureClient = New-TestLayout ([IO.Path]::Combine($Root, 'secure-client'))
            $secureClientPlugin = New-Plugin $secureClient
            Test-Refused 'Secure Client allow-list' { Assert-DefenseClawManagedInstallTree -Layout $secureClient } 'unexpected directory'
            Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $secureClient
            if (-not [IO.File]::Exists($secureClientPlugin)) {
                $failures.Add('Secure Client share content was removed by the standalone helper')
            }
            if ($null -ne (Get-DefenseClawStandaloneOpenCodePluginPaths -Layout $secureClient)) {
                $failures.Add('Secure Client reported managed OpenCode plugin paths')
            }
        }
        finally {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        }
        return , $failures
    } $root
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-opencode-plugin-uninstall-smoke: OK'

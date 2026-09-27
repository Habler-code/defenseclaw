# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 7.0

# Standalone uninstall and the managed IPC directory. A standalone install
# keeps <InstallRoot>\ipc\ (the sensor helper's AF_UNIX socket, a reparse
# file on Windows) under InstallRoot. The install-tree walk must accept that
# directory and its exact socket leaves only, removal after the services are
# gone must delete only those leaves, and the Secure Client allow-list must
# stay unchanged. Runs elevated in a short disposable directory (AF_UNIX paths
# are limited to 108 characters); no service or real machine root is touched.

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
    ('dcipc-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $openSockets = [Collections.Generic.List[object]]::new()
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
            function New-SocketLeaf([string]$Path) {
                # Keep the socket open: .NET unlinks the socket file when a
                # bound socket is disposed, and the test needs the file the
                # way a crashed service leaves it.
                $socket = [Net.Sockets.Socket]::new(
                    [Net.Sockets.AddressFamily]::Unix,
                    [Net.Sockets.SocketType]::Stream,
                    [Net.Sockets.ProtocolType]::Unspecified
                )
                $socket.Bind([Net.Sockets.UnixDomainSocketEndPoint]::new($Path))
                return $socket
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
            [void][IO.Directory]::CreateDirectory($layout.ManagedIPCDirectory)
            $socketPath = [IO.Path]::Combine($layout.ManagedIPCDirectory, 'sensor-helper.sock')
            $socket = New-SocketLeaf $socketPath
            $openSockets.Add($socket)
            if (([IO.File]::GetAttributes($socketPath) -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                $failures.Add('stand-in socket is not a reparse file; the test would not exercise the AF_UNIX case')
            }
            try {
                Assert-DefenseClawManagedInstallTree -Layout $layout
            }
            catch {
                $failures.Add("standalone tree with ipc and a socket leaf was refused: $($_.Exception.Message)")
            }
            Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $layout
            if ([IO.Directory]::Exists($layout.ManagedIPCDirectory)) {
                $failures.Add('standalone ipc directory survived removal')
            }
            try {
                Assert-DefenseClawManagedInstallTree -Layout $layout
            }
            catch {
                $failures.Add("tree without ipc was refused: $($_.Exception.Message)")
            }
            # Removal with no ipc directory is a no-op.
            Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $layout

            # Anything other than the exact socket leaves stays refused.
            $extra = New-TestLayout ([IO.Path]::Combine($Root, 'extra'))
            [void][IO.Directory]::CreateDirectory($extra.ManagedIPCDirectory)
            [IO.File]::WriteAllText([IO.Path]::Combine($extra.ManagedIPCDirectory, 'planted.txt'), 'x')
            Test-Refused 'unexpected ipc file (walk)' { Assert-DefenseClawManagedInstallTree -Layout $extra } 'unexpected file'
            Test-Refused 'unexpected ipc file (removal)' { Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $extra } 'unexpected managed IPC content'
            if (-not [IO.File]::Exists([IO.Path]::Combine($extra.ManagedIPCDirectory, 'planted.txt'))) {
                $failures.Add('refused removal still deleted content')
            }

            $nested = New-TestLayout ([IO.Path]::Combine($Root, 'nested'))
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($nested.ManagedIPCDirectory, 'sensor-helper.sock'))
            Test-Refused 'directory named like the socket' { Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $nested } 'unexpected managed IPC content'

            $linked = New-TestLayout ([IO.Path]::Combine($Root, 'linked'))
            [void][IO.Directory]::CreateDirectory($linked.ManagedIPCDirectory)
            $target = [IO.Path]::Combine($Root, 'outside.txt')
            [IO.File]::WriteAllText($target, 'keep')
            [void][IO.File]::CreateSymbolicLink([IO.Path]::Combine($linked.ManagedIPCDirectory, 'sensor-helper.sock'), $target)
            Test-Refused 'symbolic link named like the socket (walk)' { Assert-DefenseClawManagedInstallTree -Layout $linked } 'reparse point'
            Test-Refused 'symbolic link named like the socket (removal)' { Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $linked } 'unexpected managed IPC content'
            if (-not [IO.File]::Exists($target)) {
                $failures.Add('link target outside the tree was removed')
            }

            # Secure Client keeps its original allow-list: ipc is not accepted
            # and removal is a no-op.
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
            $secureClient = New-TestLayout ([IO.Path]::Combine($Root, 'secure-client'))
            [void][IO.Directory]::CreateDirectory($secureClient.ManagedIPCDirectory)
            Test-Refused 'Secure Client allow-list' { Assert-DefenseClawManagedInstallTree -Layout $secureClient } 'unexpected directory'
            Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $secureClient
            if (-not [IO.Directory]::Exists($secureClient.ManagedIPCDirectory)) {
                $failures.Add('Secure Client ipc directory was removed by the standalone helper')
            }
        }
        finally {
            foreach ($open in $openSockets) {
                $open.Dispose()
            }
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-ipc-uninstall-smoke: OK'

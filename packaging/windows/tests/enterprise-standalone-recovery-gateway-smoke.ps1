# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 7.0

# Function-level regression for WIN-F17. Recovering a pending transaction
# runs the managed-hook lifecycle restore and retire with the transaction's
# staged gateway. When that gateway fails (a release whose retire refuses
# state it cannot repair), no newer Setup could finish the recovery. A
# standalone recovery now reruns the failed step with the running Setup's own
# gateway, but only after that gateway passed the payload trust check an
# Install applies and only as LocalSystem, and records which binary ran and
# why. Everything else keeps the staged gateway's error. The gateway command,
# the LocalSystem test and the protected-location check (owned by the
# exact-ACL and bootstrap smokes) are stubbed; the standalone hash-pinned
# trust policy, the source descriptor and the atomic install are the
# production functions, run in a disposable scratch directory. The standalone
# lifecycle runs only on PowerShell 7.

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
$installerPath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot `
        '..\install-enterprise.ps1')
)
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath `
    -Force `
    -PassThru `
    -ErrorAction Stop

$failures = & $module {
    param([string]$ModulePath, [string]$InstallerPath, [string]$ScratchRoot)

    $failures = [Collections.Generic.List[string]]::new()
    $script:TestCalls = [Collections.Generic.List[string]]::new()
    $script:TestFailing = @{}
    $script:TestLocalSystem = $true
    $script:TestUntrustedSource = ''
    $relaxedHooks = 'managed Windows DACL on C:\Users\dcw-std1\.defenseclaw\hooks has 2 ACEs, expected 7'

    function Assert-DefenseClawAdministrator {
    }
    function Test-DefenseClawLocalSystemToken {
        return [bool]$script:TestLocalSystem
    }
    function Assert-DefenseClawTrustedSource {
        param([string]$Path, [string]$Label)
        $full = [IO.Path]::GetFullPath($Path)
        if ([string]::Equals($full, $script:TestUntrustedSource, [StringComparison]::OrdinalIgnoreCase)) {
            throw "untrusted principal S-1-5-32-545 has write-like access to $Label source: $full"
        }
        return $full
    }
    # The hidden command, keyed by which gateway bytes sit at GatewayPath.
    function Invoke-DefenseClawGatewayCommand {
        param(
            [hashtable]$Layout,
            [string]$GatewayServiceName,
            [string[]]$Arguments,
            [switch]$Capture,
            [switch]$AllowFailure
        )
        $gateway = [IO.File]::ReadAllText([string]$Layout.GatewayPath).Trim()
        $action = [string]$Arguments[3]
        $script:TestCalls.Add("${gateway}:$action")
        $phase = switch ($action) {
            'restore' { 'restored' }
            'retire' { 'retired' }
        }
        $report = [ordered]@{
            schema_version = 4
            action = $action
            ok = $true
            journal_path = [string]$Layout.ManagedHooksLifecycleJournalPath
            phase = $phase
        }
        $exitCode = 0
        if ($script:TestFailing.ContainsKey("${gateway}:$action")) {
            $report.ok = $false
            $report.phase = ''
            $report['error'] = "retire amp managed runtime generations for SID S-1-5-21-1-2-3-1017: $relaxedHooks"
            $exitCode = 1
        }
        return [ordered]@{
            exit_code = $exitCode
            output = @(($report | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress))
        }
    }

    function Get-TestSHA256([string]$Path) {
        return (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $root = [IO.Path]::Combine(
        [IO.Path]::GetFullPath($ScratchRoot),
        ('dc-recovery-gw-' + [Guid]::NewGuid().ToString('N').Substring(0, 12))
    )
    $utf8 = [Text.UTF8Encoding]::new($false)
    $originalProfile = Get-DefenseClawEnterpriseProfile
    try {
        $installRoot = [IO.Path]::Combine($root, 'install')
        $setupRoot = [IO.Path]::Combine($root, 'setup')
        $emptySetupRoot = [IO.Path]::Combine($root, 'setup-without-payload')
        foreach ($directory in @(
            [IO.Path]::Combine($installRoot, 'bin'),
            [IO.Path]::Combine($installRoot, 'libexec'),
            $setupRoot,
            $emptySetupRoot,
            [IO.Path]::Combine($root, 'state', 'install')
        )) {
            [void][IO.Directory]::CreateDirectory($directory)
        }
        $layout = @{
            InstallRoot = $installRoot
            GatewayPath = [IO.Path]::Combine($installRoot, 'bin', 'defenseclaw-gateway.exe')
            ManagedHooksLifecycleJournalPath = [IO.Path]::Combine($root, 'state', 'install', 'managed-hooks-lifecycle.json')
            PendingPath = [IO.Path]::Combine($root, 'state', 'install', 'pending.json')
            ProductVersion = '1.0.42'
        }
        $setupInstaller = [IO.Path]::Combine($setupRoot, 'install-enterprise.ps1')
        $setupGateway = [IO.Path]::Combine($setupRoot, 'defenseclaw-gateway.exe')
        $payloadManifest = [IO.Path]::Combine($root, 'payload-trust.json')
        [IO.File]::WriteAllText($setupInstaller, '# Setup installer', $utf8)
        [IO.File]::WriteAllText(
            [IO.Path]::Combine($emptySetupRoot, 'install-enterprise.ps1'),
            '# installer without a payload',
            $utf8
        )

        function Reset-TestHost {
            param(
                [string]$SetupContent = 'setup-gateway',
                [string]$PinnedSHA256 = '',
                [string[]]$Failing = @('staged-gateway:retire')
            )
            [IO.File]::WriteAllText($layout.GatewayPath, 'staged-gateway', $utf8)
            [IO.File]::WriteAllText($setupGateway, $SetupContent, $utf8)
            if ([string]::IsNullOrEmpty($PinnedSHA256)) {
                $PinnedSHA256 = Get-TestSHA256 $setupGateway
            }
            [IO.File]::WriteAllText(
                $payloadManifest,
                (@{ schema_version = 1; files = @{ 'defenseclaw-gateway.exe' = $PinnedSHA256 } } |
                    Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4),
                $utf8
            )
            Initialize-DefenseClawStandalonePayloadTrust `
                -TrustMode HashPinned `
                -PayloadManifest $payloadManifest
            $script:TestFailing = @{}
            foreach ($entry in $Failing) {
                $script:TestFailing[$entry] = $true
            }
            $script:TestCalls.Clear()
            $script:TestLocalSystem = $true
            $script:TestUntrustedSource = ''
            Set-DefenseClawRecoveryGatewayCandidate -InstallerSource $setupInstaller
        }

        function Invoke-TestRecovery {
            $outcome = [ordered]@{ reports = @(); error = '' }
            try {
                foreach ($action in @('restore', 'retire')) {
                    $outcome.reports += @(Invoke-DefenseClawManagedHooksLifecycleRecoveryStep `
                        -Layout $layout `
                        -GatewayServiceName 'DefenseClawGateway' `
                        -Action $action)
                }
            }
            catch {
                $outcome.error = $_.Exception.Message
            }
            return $outcome
        }

        function Assert-TestRefused {
            param([string]$Label, [string]$Code)
            $outcome = Invoke-TestRecovery
            $gateway = [IO.File]::ReadAllText($layout.GatewayPath).Trim()
            $refusal = $script:DefenseClawRecoveryGatewayRefusal
            if (-not $outcome.error.Contains($relaxedHooks) -or
                $outcome.error.Contains('verified Setup gateway')) {
                $failures.Add("${Label}: the staged gateway's error did not stand: $($outcome.error)")
            }
            if ($null -eq $refusal -or [string]$refusal.code -cne $Code -or [string]$refusal.action -cne 'retire') {
                $failures.Add("${Label}: refusal $(if ($null -eq $refusal) { 'none' } else { [string]$refusal.code }), want $Code")
            }
            if (@($script:DefenseClawRecoveryGatewayRuns).Count -ne 0 -or $gateway -cne 'staged-gateway') {
                $failures.Add("${Label}: a refused fallback still replaced the staged gateway ($gateway)")
            }
            if ((@($script:TestCalls) -join '|') -cne 'staged-gateway:restore|staged-gateway:retire') {
                $failures.Add("${Label}: calls $(@($script:TestCalls) -join ', ')")
            }
        }

        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone

        # 1. Verified fallback: the staged gateway restores but cannot retire;
        # the hash-pinned Setup gateway replaces it and retires.
        Reset-TestHost
        $stagedSHA256 = Get-TestSHA256 $layout.GatewayPath
        $setupSHA256 = Get-TestSHA256 $setupGateway
        $outcome = Invoke-TestRecovery
        $runs = @(Get-DefenseClawRecoveryGatewayRunRecords)
        if (-not [string]::IsNullOrEmpty($outcome.error) -or @($outcome.reports).Count -ne 2 -or
            [string]$outcome.reports[1].phase -cne 'retired') {
            $failures.Add("verified fallback failed: $($outcome.error)")
        }
        if ((@($script:TestCalls) -join '|') -cne 'staged-gateway:restore|staged-gateway:retire|setup-gateway:retire') {
            $failures.Add("verified fallback calls: $(@($script:TestCalls) -join ', ')")
        }
        if ([IO.File]::ReadAllText($layout.GatewayPath).Trim() -cne 'setup-gateway') {
            $failures.Add('the verified Setup gateway was not staged at <InstallRoot>\bin')
        }
        if ($runs.Count -ne 1) {
            $failures.Add("verified fallback recorded $($runs.Count) runs")
        }
        else {
            $run = $runs[0]
            foreach ($check in @(
                @('action', 'retire'),
                @('binary', $layout.GatewayPath),
                @('source', $setupGateway),
                @('sha256', $setupSHA256),
                @('trust', 'hash_pinned'),
                @('identity', 'NT AUTHORITY\SYSTEM'),
                @('product_version', '1.0.42'),
                @('replaced_sha256', $stagedSHA256),
                @('reason', 'staged_gateway_failed'),
                @('outcome', 'succeeded')
            )) {
                if ([string]$run.($check[0]) -cne [string]$check[1]) {
                    $failures.Add("run $($check[0]) = '$($run.($check[0]))', want '$($check[1])'")
                }
            }
            if (-not ([string]$run.staged_error).Contains($relaxedHooks)) {
                $failures.Add("run staged_error = '$($run.staged_error)'")
            }
        }
        if ($null -ne $script:DefenseClawRecoveryGatewayRefusal) {
            $failures.Add('a taken fallback recorded a refusal')
        }

        # The failure document of a lifecycle that fails after the fallback
        # carries the pending state and the binary recovery ran.
        $tokens = $null
        $parseErrors = $null
        $installerAst = [Management.Automation.Language.Parser]::ParseFile(
            $InstallerPath,
            [ref]$tokens,
            [ref]$parseErrors
        )
        $evidenceFunction = $installerAst.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Add-DefenseClawLifecycleFailureEvidence'
        }, $true)
        . ([scriptblock]::Create([string]$evidenceFunction.Extent.Text))
        [IO.File]::WriteAllText($layout.PendingPath, '{}', $utf8)
        $record = [Management.Automation.ErrorRecord]::new(
            [Management.Automation.RuntimeException]::new('Repair failed'),
            'LifecycleFailed',
            [Management.Automation.ErrorCategory]::NotSpecified,
            $null
        )
        Add-DefenseClawRecoveryEvidenceToError -ErrorRecord $record -Layout $layout
        $document = [pscustomobject]@{ schema_version = 1; ok = $false; action = 'repair'; error = 'Repair failed'; errors = @('Repair failed') }
        Add-DefenseClawLifecycleFailureEvidence -Document $document -Evidence $record.Exception.Data
        $parsed = ($document | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6 -Compress) |
            Microsoft.PowerShell.Utility\ConvertFrom-Json
        if (-not [bool]$parsed.transaction_pending -or
            @($parsed.recovery_gateway_runs).Count -ne 1 -or
            [string]@($parsed.recovery_gateway_runs)[0].binary -cne $layout.GatewayPath -or
            [string]@($parsed.recovery_gateway_runs)[0].sha256 -cne $setupSHA256) {
            $failures.Add("failure document: $($document | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6 -Compress)")
        }
        [IO.File]::Delete($layout.PendingPath)
        $plain = [pscustomobject]@{ schema_version = 1; ok = $false }
        Add-DefenseClawLifecycleFailureEvidence -Document $plain -Evidence ([Collections.Hashtable]::new())
        Add-DefenseClawLifecycleFailureEvidence -Document $plain -Evidence $null
        if (@($plain.PSObject.Properties).Count -ne 2) {
            $failures.Add('a failure without recovery evidence changed its document')
        }

        # 2. A staged gateway that fails restore: the Setup gateway restores,
        # then retires as the newly staged gateway.
        Reset-TestHost -Failing @('staged-gateway:restore', 'staged-gateway:retire')
        $outcome = Invoke-TestRecovery
        if (-not [string]::IsNullOrEmpty($outcome.error) -or
            (@($script:TestCalls) -join '|') -cne 'staged-gateway:restore|setup-gateway:restore|setup-gateway:retire' -or
            @($script:DefenseClawRecoveryGatewayRuns).Count -ne 1) {
            $failures.Add("restore fallback: $($outcome.error) calls $(@($script:TestCalls) -join ', ')")
        }

        # 3. Refusals keep the staged gateway and its error.
        Reset-TestHost -PinnedSHA256 ('0' * 64)
        Assert-TestRefused 'payload failing the hash pin' 'untrusted'

        Reset-TestHost
        $script:TestUntrustedSource = $setupGateway
        Assert-TestRefused 'payload a standard user could replace' 'untrusted'

        Reset-TestHost
        $script:TestLocalSystem = $false
        Assert-TestRefused 'elevated administrator, not LocalSystem' 'not_local_system'

        Reset-TestHost -SetupContent 'staged-gateway'
        Assert-TestRefused 'the Setup gateway is the staged one' 'same_binary'

        Reset-TestHost
        Set-DefenseClawRecoveryGatewayCandidate -InstallerSource $setupInstaller -AllowUnsigned
        Assert-TestRefused 'unsigned certification scope' 'unsigned_scope'

        Reset-TestHost
        Set-DefenseClawRecoveryGatewayCandidate -InstallerSource ([IO.Path]::Combine($emptySetupRoot, 'install-enterprise.ps1'))
        Assert-TestRefused 'installer without a payload (the installed CLI)' 'no_payload'

        Reset-TestHost
        $insideGateway = [IO.Path]::Combine($installRoot, 'libexec', 'defenseclaw-gateway.exe')
        [IO.File]::WriteAllText($insideGateway, 'setup-gateway', $utf8)
        Set-DefenseClawRecoveryGatewayCandidate -GatewayBinary $insideGateway
        Assert-TestRefused 'a gateway inside InstallRoot' 'inside_install_root'

        # 4. The Setup gateway fails the step too: the run is recorded as
        # failed and both failures are reported.
        Reset-TestHost -Failing @('staged-gateway:retire', 'setup-gateway:retire')
        $outcome = Invoke-TestRecovery
        $runs = @(Get-DefenseClawRecoveryGatewayRunRecords)
        if (-not $outcome.error.Contains('failed with the staged gateway and again with the verified Setup gateway') -or
            $runs.Count -ne 1 -or [string]$runs[0].outcome -cne 'failed' -or
            -not ([string]$runs[0].error).Contains($relaxedHooks)) {
            $failures.Add("failed fallback: $($outcome.error)")
        }

        # 5. Secure Client recovers only with the staged gateway.
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
        Reset-TestHost
        if ($null -ne $script:DefenseClawRecoveryGatewayCandidate) {
            $failures.Add('Secure Client named a recovery gateway')
        }
        $outcome = Invoke-TestRecovery
        if (-not $outcome.error.Contains($relaxedHooks) -or
            $null -ne $script:DefenseClawRecoveryGatewayRefusal -or
            @($script:DefenseClawRecoveryGatewayRuns).Count -ne 0 -or
            (@($script:TestCalls) -join '|') -cne 'staged-gateway:restore|staged-gateway:retire' -or
            [IO.File]::ReadAllText($layout.GatewayPath).Trim() -cne 'staged-gateway') {
            $failures.Add("Secure Client recovery changed: $($outcome.error) calls $(@($script:TestCalls) -join ', ')")
        }
        $record = [Management.Automation.ErrorRecord]::new(
            [Management.Automation.RuntimeException]::new('Repair failed'),
            'LifecycleFailed',
            [Management.Automation.ErrorCategory]::NotSpecified,
            $null
        )
        Add-DefenseClawRecoveryEvidenceToError -ErrorRecord $record -Layout $layout
        if ($record.Exception.Data.Count -ne 0) {
            $failures.Add('Secure Client attached recovery evidence to a lifecycle error')
        }

        # 6. Wiring: recovery restore and retire go through the fallback step,
        # the entry point names the candidate for every run and attaches the
        # evidence to a failure, and a status document reports the runs.
        $moduleAst = [Management.Automation.Language.Parser]::ParseFile(
            $ModulePath,
            [ref]$tokens,
            [ref]$parseErrors
        )
        $body = {
            param([string]$Name)
            $moduleAst.Find({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq $Name
            }, $true).Body.Extent.Text
        }
        $restore = & $body 'Restore-DefenseClawTransaction'
        foreach ($action in @('restore', 'retire')) {
            $step = [Text.RegularExpressions.Regex]::Matches(
                $restore,
                'Invoke-DefenseClawManagedHooksLifecycleRecoveryStep\s+`\s+-Layout \$Layout\s+`\s+-GatewayServiceName \(\[string\]\$snapshot\.gateway_service\)\s+`\s+-Action ' + $action + '\)'
            ).Count
            $direct = [Text.RegularExpressions.Regex]::Matches(
                $restore,
                'Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand\s+`\s+-Layout \$Layout\s+`\s+-GatewayServiceName \(\[string\]\$snapshot\.gateway_service\)\s+`\s+-Action ' + $action + '\)'
            ).Count
            if ($step -ne 1 -or $direct -ne 0) {
                $failures.Add("Restore-DefenseClawTransaction $action runs through the recovery step $step time(s), directly $direct time(s)")
            }
        }
        $entry = & $body 'Invoke-DefenseClawEnterpriseLifecycle'
        $candidate = $entry.IndexOf('Set-DefenseClawRecoveryGatewayCandidate `')
        $lock = $entry.IndexOf('$lifecycleLock = Enter-DefenseClawLifecycleLock -Layout $layout')
        $evidence = $entry.IndexOf('Add-DefenseClawRecoveryEvidenceToError -ErrorRecord $_ -Layout $layout')
        $finally = $entry.LastIndexOf('Exit-DefenseClawLifecycleLock -Lock $lifecycleLock')
        if ($candidate -lt 0 -or $lock -lt $candidate -or $evidence -lt $lock -or $finally -lt $evidence) {
            $failures.Add('the lifecycle entry point does not name the recovery candidate before the lock and attach evidence to failures')
        }
        $status = & $body 'Get-DefenseClawLifecycleStatus'
        if (-not $status.Contains("`$status['recovery_gateway_runs'] = `$recoveryRuns") -or
            -not $status.Contains("`$status['recovery_gateway_refusal']")) {
            $failures.Add('the standalone status document does not report the recovery gateway')
        }
    }
    finally {
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
    return , $failures
} $modulePath $installerPath $ScratchRoot

if (@($failures).Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-recovery-gateway-smoke: OK'

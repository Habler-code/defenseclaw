# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Function-level regression for the Status view of an outranking HKLM Claude
# policy (#899). Only a disposable scratch directory is written; the machine
# registry is read, never written.

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
    ('dc-claude-hklm-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $policyPath = [IO.Path]::Combine($Root, '90-defenseclaw.json')
        $layout = @{ ClaudeManagedPolicyPath = $policyPath }
        $installed = @'
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "args": ["hook", "--connector", "claudecode", "--enterprise-managed"],
            "command": "C:\\Program Files\\Cisco\\Cisco Secure Client\\DefenseClaw\\bin\\defenseclaw-hook.exe",
            "timeout": 30,
            "type": "command"
          }
        ],
        "matcher": "*"
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "args": ["hook", "--connector", "claudecode", "--enterprise-managed"],
            "command": "C:\\Program Files\\Cisco\\Cisco Secure Client\\DefenseClaw\\bin\\defenseclaw-hook.exe",
            "timeout": 30,
            "type": "command"
          }
        ]
      }
    ]
  }
}
'@
        [IO.File]::WriteAllText($policyPath, $installed, [Text.UTF8Encoding]::new($false))
        $hook = 'C:\\Program Files\\Cisco\\Cisco Secure Client\\DefenseClaw\\bin\\defenseclaw-hook.exe'
        $dc = '{"type":"command","timeout":30,"command":"' + $hook + '","args":["hook","--connector","claudecode","--enterprise-managed"]}'
        $admin = '{"type":"command","command":"C:\\audit.exe"}'
        $carried = '{"Stop":[{"hooks":[' + $dc + ']}],"PreToolUse":[{"matcher":"*","hooks":[' + $dc + ']}]}'
        $adminOnly = '{"PreToolUse":[{"matcher":"*","hooks":[' + $admin + ']}]}'
        # #899 review: the Status mirror follows the gateway admission rules
        # (claudeCodeSourceHasHookContract): a covering matcher, any matching
        # handler in an entry, and no timeout comparison.
        $cases = [ordered]@{
            # Reordered keys, compact form, and an extra administrator hook.
            'carries the installed matrix' = @{
                want = $true
                json = '{"model":"x","hooks":{"Stop":[{"hooks":[{"type":"command","timeout":30,"command":"' + $hook + '","args":["hook","--connector","claudecode","--enterprise-managed"]}]}],"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"C:\\audit.exe"}]},{"matcher":"*","hooks":[{"timeout":30,"type":"command","command":"' + $hook + '","args":["hook","--connector","claudecode","--enterprise-managed"]}]}]}}'
            }
            'shares an administrator entry' = @{
                want = $true
                json = '{"hooks":{"Stop":[{"hooks":[' + $dc + ']}],"PreToolUse":[{"matcher":"*","hooks":[' + $admin + ',' + $dc + ']}]}}'
            }
            'uses an empty matcher and a matcher Stop ignores' = @{
                want = $true
                json = '{"hooks":{"Stop":[{"matcher":"anything","hooks":[' + $dc + ']}],"PreToolUse":[{"matcher":"","hooks":[' + $dc + ']}]}}'
            }
            'changes a timeout' = @{
                want = $true
                json = '{"hooks":{"Stop":[{"hooks":[{"args":["hook","--connector","claudecode","--enterprise-managed"],"command":"' + $hook + '","timeout":5,"type":"command"}]}],"PreToolUse":[{"matcher":"*","hooks":[{"args":["hook","--connector","claudecode","--enterprise-managed"],"command":"' + $hook + '","timeout":30,"type":"command"}]}]}}'
            }
            'spells the hook path in another case' = @{
                want = $true
                json = ('{"hooks":' + $carried + '}').Replace('defenseclaw-hook.exe', 'DefenseClaw-Hook.EXE')
            }
            'adds an unrelated administrator event' = @{
                want = $true
                json = '{"hooks":' + $carried.TrimEnd('}') + ',"Notification":[{"hooks":[' + $admin + ']}]}}'
            }
            'misses an event' = @{
                want = $false
                json = '{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"args":["hook","--connector","claudecode","--enterprise-managed"],"command":"' + $hook + '","timeout":30,"type":"command"}]}]}}'
            }
            'narrows the matcher' = @{
                want = $false
                json = '{"hooks":{"Stop":[{"hooks":[' + $dc + ']}],"PreToolUse":[{"matcher":"Bash","hooks":[' + $dc + ']}]}}'
            }
            'makes the hook asynchronous' = @{
                want = $false
                json = '{"hooks":{"Stop":[{"hooks":[' + $dc + ']}],"PreToolUse":[{"matcher":"*","hooks":[' + $dc.TrimEnd('}') + ',"async":true}]}]}}'
            }
            'adds a hook condition' = @{
                want = $false
                json = '{"hooks":{"Stop":[{"hooks":[' + $dc + ']}],"PreToolUse":[{"matcher":"*","hooks":[' + $dc.TrimEnd('}') + ',"if":"Bash(ls)"}]}]}}'
            }
            'adds a DefenseClaw hook outside the matrix' = @{
                want = $false
                json = '{"hooks":' + $carried.TrimEnd('}') + ',"Notification":[{"hooks":[' + $dc + ']}]}}'
            }
            'drops the enterprise flag' = @{
                want = $false
                json = '{"hooks":{"Stop":[{"hooks":[{"args":["hook","--connector","claudecode"],"command":"' + $hook + '","timeout":30,"type":"command"}]}],"PreToolUse":[{"matcher":"*","hooks":[{"args":["hook","--connector","claudecode"],"command":"' + $hook + '","timeout":30,"type":"command"}]}]}}'
            }
            'has a non-list event' = @{ want = $false; json = '{"hooks":{"Stop":"x","PreToolUse":[{"matcher":"*","hooks":[' + $dc + ']}]}}' }
            'has no hooks' = @{ want = $false; json = '{"model":"x"}' }
            'has non-object hooks' = @{ want = 'throw'; json = '{"hooks":"none"}' }
        }
        foreach ($name in $cases.Keys) {
            $case = $cases[$name]
            try {
                $settings = $case.json | Microsoft.PowerShell.Utility\ConvertFrom-Json
                $got = Test-DefenseClawClaudeHKLMCarriesInstalledHooks -Settings $settings -Layout $layout
                if ($case.want -is [string]) {
                    $failures.Add("${name}: carries=$got, want a throw")
                }
                elseif ([bool]$got -ne [bool]$case.want) {
                    $failures.Add("${name}: carries=$got, want $($case.want)")
                }
            }
            catch {
                if ($case.want -isnot [string]) {
                    $failures.Add("${name}: threw $($_.Exception.Message)")
                }
            }
        }

        # #899 review: like pathidentity.Same in the gateway, Status matches a
        # handler command to the hook binary by file identity, so another
        # spelling of the installed binary is the DefenseClaw handler, both
        # inside the matrix (carried) and outside it (refused).
        $hookDir = [IO.Path]::Combine($Root, 'bin')
        [void][IO.Directory]::CreateDirectory($hookDir)
        $realHook = [IO.Path]::Combine($hookDir, 'defenseclaw-hook.exe')
        [IO.File]::WriteAllBytes($realHook, [byte[]]@(0x4d, 0x5a))
        $copyHook = [IO.Path]::Combine($Root, 'copy-hook.exe')
        [IO.File]::Copy($realHook, $copyHook)
        $junction = [IO.Path]::Combine($Root, 'bin-junction')
        [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $junction -Value $hookDir)
        $hardLink = [IO.Path]::Combine($Root, 'hook-link.exe')
        [void](Microsoft.PowerShell.Management\New-Item -ItemType HardLink -Path $hardLink -Value $realHook)
        $missingHook = [IO.Path]::Combine($hookDir, 'missing-hook.exe')
        $handlerFor = {
            param([string]$Command)
            '{"type":"command","timeout":30,"command":' +
                ($Command | Microsoft.PowerShell.Utility\ConvertTo-Json) +
                ',"args":["hook","--connector","claudecode","--enterprise-managed"]}'
        }
        $realHandler = & $handlerFor $realHook
        [IO.File]::WriteAllText(
            $policyPath,
            ('{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[' + $realHandler + ']}],"Stop":[{"hooks":[' + $realHandler + ']}]}}'),
            [Text.UTF8Encoding]::new($false)
        )
        $spellings = [ordered]@{
            'a junction' = @([IO.Path]::Combine($junction, 'defenseclaw-hook.exe'), $true)
            'a hard link' = @($hardLink, $true)
            'the extended-length form' = @(('\\?\' + $realHook), $true)
            'forward slashes' = @($realHook.Replace('\', '/'), $true)
            'another case' = @($realHook.ToUpperInvariant(), $true)
            'a copy of the binary' = @($copyHook, $false)
            'a missing file' = @($missingHook, $false)
        }
        $shortHook = ''
        try {
            $shortHook = [string](Microsoft.PowerShell.Utility\New-Object -ComObject Scripting.FileSystemObject).GetFile($realHook).ShortPath
        }
        catch {
            $shortHook = ''
        }
        if (-not [string]::IsNullOrEmpty($shortHook) -and $shortHook -cne $realHook) {
            $spellings['the short name'] = @($shortHook, $true)
        }
        if ($realHook -cmatch '^([A-Za-z]):\\(.+)$') {
            $share = '\\localhost\' + $Matches[1] + '$\' + $Matches[2]
            if ([IO.File]::Exists($share)) {
                $spellings['an administrative share'] = @($share, $true)
            }
        }
        foreach ($spelling in $spellings.Keys) {
            $alias = & $handlerFor $spellings[$spelling][0]
            $isHook = [bool]$spellings[$spelling][1]
            $checks = @(
                @(('{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[' + $alias + ']}],"Stop":[{"hooks":[' + $realHandler + ']}]}}'), $isHook, 'in the matrix'),
                @(('{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[' + $realHandler + ']}],"Stop":[{"hooks":[' + $realHandler + ']}],"Notification":[{"hooks":[' + $alias + ']}]}}'), (-not $isHook), 'outside the matrix')
            )
            foreach ($check in $checks) {
                try {
                    $got = Test-DefenseClawClaudeHKLMCarriesInstalledHooks `
                        -Settings ($check[0] | Microsoft.PowerShell.Utility\ConvertFrom-Json) `
                        -Layout $layout
                    if ([bool]$got -ne [bool]$check[1]) {
                        $failures.Add("handler through $spelling $($check[2]): carries=$got, want $($check[1])")
                    }
                }
                catch {
                    $failures.Add("handler through $spelling $($check[2]): threw $($_.Exception.Message)")
                }
            }
        }
        $absent = [IO.Path]::Combine($Root, 'absent\defenseclaw-hook.exe')
        foreach ($pair in @(
            @($absent, $absent.ToUpperInvariant(), $true, 'two spellings of one missing path'),
            @($absent, [IO.Path]::Combine($Root, 'absent\other.exe'), $false, 'two missing paths'),
            @($realHook, $absent, $false, 'an existing and a missing path'),
            @($realHook, '', $false, 'an empty path'),
            @($realHook, 'C:\bad|name.exe', $false, 'an invalid path')
        )) {
            $got = Test-DefenseClawSamePathIdentity -Left $pair[0] -Right $pair[1]
            if ([bool]$got -ne [bool]$pair[2]) {
                $failures.Add("path identity for $($pair[3]) = $got, want $($pair[2])")
            }
        }
        [IO.Directory]::Delete($junction)
        [IO.File]::WriteAllText($policyPath, $installed, [Text.UTF8Encoding]::new($false))

        # Admission: the gateway also requires the managed-hooks-only lock to
        # survive the outranking policy unless the administrator opted out,
        # which the installed policy records by omitting the key.
        $installedLocked = $installed -replace '^\{', '{"allowManagedHooksOnly": true,'
        $decisions = @(
            @($true, ('{"allowManagedHooksOnly":true,"hooks":' + $carried + '}'), $false, $false, 'carried with the lock'),
            @($true, ('{"hooks":' + $carried + '}'), $true, $false, 'carried without the lock'),
            @($true, ('{"managedSourcesBehavior":"merge","hooks":' + $carried + '}'), $true, $false, 'merge carried without the lock'),
            @($true, ('{"managedSourcesBehavior":"merge","allowManagedHooksOnly":true,"hooks":' + $carried + '}'), $false, $false, 'merge carried with the lock'),
            @($true, ('{"managedSourcesBehavior":"merge","hooks":' + $adminOnly + '}'), $false, $true, 'merge relying on the drop-in'),
            @($true, ('{"managedSourcesBehavior":"merge","allowManagedHooksOnly":false,"hooks":' + $adminOnly + '}'), $true, $false, 'merge unlocking the drop-in'),
            @($true, ('{"managedSourcesBehavior":"merge","hooks":{"Stop":"x"}}'), $true, $false, 'merge with an unmergeable list'),
            @($true, ('{"hooks":' + $adminOnly + '}'), $true, $false, 'outranking without the hooks'),
            @($true, ('{"allowManagedHooksOnly":"yes","hooks":' + $carried + '}'), $true, $false, 'non-boolean lock'),
            @($true, ('{"disableAllHooks":true,"hooks":' + $carried + '}'), $true, $false, 'hooks disabled'),
            @($false, ('{"hooks":' + $carried + '}'), $false, $false, 'opt-out carried without the lock'),
            @($false, ('{"managedSourcesBehavior":"merge","allowManagedHooksOnly":false,"hooks":' + $adminOnly + '}'), $false, $true, 'opt-out merge unlocking the drop-in')
        )
        foreach ($decision in $decisions) {
            $body = if ([bool]$decision[0]) { $installedLocked } else { $installed }
            [IO.File]::WriteAllText($policyPath, $body, [Text.UTF8Encoding]::new($false))
            $state = [ordered]@{
                shadowed = $false
                managed_sources_merge = $false
                merge_client_floor_required = $false
                detail = $null
            }
            try {
                Set-DefenseClawClaudeHKLMPolicyDecision `
                    -State $state `
                    -Settings ($decision[1] | Microsoft.PowerShell.Utility\ConvertFrom-Json) `
                    -Layout $layout `
                    -PolicyName 'HKLM\SOFTWARE\Policies\ClaudeCode\Settings' `
                    -Remedy 'fix it'
                if ([bool]$state.shadowed -ne [bool]$decision[2] -or
                    [bool]$state.merge_client_floor_required -ne [bool]$decision[3]) {
                    $failures.Add("$($decision[4]): shadowed=$($state.shadowed) floor=$($state.merge_client_floor_required), want $($decision[2])/$($decision[3]) ($($state.detail))")
                }
                if ([bool]$state.shadowed -and [string]::IsNullOrWhiteSpace([string]$state.detail)) {
                    $failures.Add("$($decision[4]): shadowed without a detail")
                }
            }
            catch {
                $failures.Add("$($decision[4]): threw $($_.Exception.Message)")
            }
        }
        [IO.File]::WriteAllText($policyPath, $installed, [Text.UTF8Encoding]::new($false))

        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $policyPath -Force
        $settings = $cases['carries the installed matrix'].json | Microsoft.PowerShell.Utility\ConvertFrom-Json
        if (Test-DefenseClawClaudeHKLMCarriesInstalledHooks -Settings $settings -Layout $layout) {
            $failures.Add('without an installed DefenseClaw policy nothing can be carried')
        }
        foreach ($pair in @(
            @('{"b":1,"a":[true,null,"x"]}', '{"a":[true,null,"x"],"b":1}'),
            @('{"a":{"d":2,"c":1}}', '{"a":{"c":1,"d":2}}')
        )) {
            $left = ConvertTo-DefenseClawCanonicalJsonText -Value ($pair[0] | Microsoft.PowerShell.Utility\ConvertFrom-Json)
            $right = ConvertTo-DefenseClawCanonicalJsonText -Value ($pair[1] | Microsoft.PowerShell.Utility\ConvertFrom-Json)
            if ($left -cne $right) {
                $failures.Add("canonical JSON differs by key order: $left vs $right")
            }
        }
        # The Status view reads the live registry and must never throw.
        try {
            $state = Get-DefenseClawClaudeHKLMPolicyState -Layout $layout
            foreach ($field in @('shadowed', 'managed_sources_merge', 'merge_client_floor_required', 'detail')) {
                if ($null -eq $state.PSObject.Properties[$field]) {
                    $failures.Add("HKLM policy state is missing $field")
                }
            }
        }
        catch {
            $failures.Add("HKLM policy state threw: $($_.Exception.Message)")
        }
        # #899 review: under an HKLM merge policy the recorded client version
        # neither admits nor refuses a target; Status lists the targets whose
        # recorded version is below the merge floor.
        foreach ($case in @(
            @("2.1.242", "2.1.242", $true),
            @("2.1.250", "2.1.242", $true),
            @("2.1.241", "2.1.242", $false),
            @("", "2.1.242", $false),
            @("not-a-version", "2.1.242", $false)
        )) {
            $got = Test-DefenseClawClaudeVersionAtLeast -Value $case[0] -Minimum $case[1]
            if ([bool]$got -ne [bool]$case[2]) {
                $failures.Add("version $($case[0]) at least $($case[1]) = $got")
            }
        }
        foreach ($floor in @("2.1.154", "2.1.242", "2.1.152")) {
            if (-not (Test-DefenseClawClaudeMinimumClientVersion -Value $floor)) {
                $failures.Add("attested Claude floor $floor was not accepted")
            }
        }
        if (Test-DefenseClawClaudeMinimumClientVersion -Value "2.1.200") {
            $failures.Add("an arbitrary Claude floor was accepted")
        }
        $report = [pscustomobject]@{
            verification = @(
                [pscustomobject]@{ connector = "claudecode"; sid = "S-1-5-21-1-1001"; result = [pscustomobject]@{ agent_version = "2.1.154" } },
                [pscustomobject]@{ connector = "claudecode"; sid = "S-1-12-1-2-3-4-5"; result = [pscustomobject]@{ agent_version = "2.1.250" } },
                [pscustomobject]@{ connector = "claudecode"; sid = "S-1-5-21-1-1002"; result = [pscustomobject]@{ agent_version = "" } },
                [pscustomobject]@{ connector = "codex"; sid = "S-1-5-21-1-1003"; result = [pscustomobject]@{ agent_version = "0.131.0" } }
            )
        }
        $pending = @(Get-DefenseClawClaudeMergePendingTargets -Report $report)
        $want = @("claudecode@S-1-5-21-1-1001 (recorded 2.1.154)", "claudecode@S-1-5-21-1-1002 (recorded unknown)")
        if (($pending -join "|") -cne ($want -join "|")) {
            $failures.Add("merge pending targets = $($pending -join "|")")
        }
        if (@(Get-DefenseClawClaudeMergePendingTargets -Report $null).Count -ne 0) {
            $failures.Add("a missing guardian report listed merge pending targets")
        }
        return @($failures)
    } $root
}
finally {
    if ([IO.Directory]::Exists($root)) {
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force
    }
}

$failures = @($failures | Microsoft.PowerShell.Core\Where-Object { $null -ne $_ })
if ($failures.Count -ne 0) {
    throw ("Claude HKLM policy smoke failed:`n" + ($failures -join "`n"))
}
Microsoft.PowerShell.Utility\Write-Output 'Claude HKLM policy smoke passed'

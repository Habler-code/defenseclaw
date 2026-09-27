# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

<#
    Secure Client golden for the native Windows managed_enterprise lifecycle.

    Production Secure Client ships this lifecycle (release branch
    release-defenseclaw-enterprise-26.8.4) and it must not change when other
    deployment profiles are added. This script derives, without creating or
    modifying any service, user, registry key, managed root, or machine
    policy, the exact state the Secure Client lifecycle would install and
    verify:

      * the managed layout (every Program Files / ProgramData path);
      * the five SCM service specifications the Verify path enforces
        (image, account, display name, SID type, privileges, dependencies,
        environment, start mode) for normal, pending, servicing, and
        attested deployments;
      * the service SDDL, description, registry-key SDDL, failure actions,
        and drain interval;
      * the canonical ACL for every managed path kind and the path-to-kind
        plan Set-DefenseClawManagedAcls applies;
      * the required-rights matrix Verify checks;
      * the Secure Client values of the profile helpers (roots, broker gate,
        gateway dependencies, Claude floor, attestation schema);
      * the sc.exe argument lists Set-DefenseClawManagedServices issues at
        install (recorded through stubs, never run);
      * the -Mode/-Connector config.yaml and targets.yaml renderers in
        install-enterprise.ps1;
      * which other-profile deployment records block a Secure Client
        mutation (a planted file or folder does not; an administrator's
        record does);
      * the deployment.json document New-DefenseClawDeploymentMetadata
        writes for an installed deployment and a tombstone, and how
        Get-DefenseClawDeploymentMetadata reads Secure Client records back;
      * the read-only Status result keys.

    Usage (Windows PowerShell 5.1 is the production Secure Client engine):
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        packaging\windows\tests\secure-client-golden.ps1 `
        -GoldenPath testdata\secure_client_golden\windows\lifecycle.json
    Add -Update only when a Secure Client behavior change is intended and
    reviewed (see testdata/secure_client_golden/README.md).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$GoldenPath,
    [switch]$Update
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$modulePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))
$installerPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\install-enterprise.ps1'))
$installRoot = Join-Path $programFiles 'Cisco\Cisco Secure Client\DefenseClaw'
$stateRoot = Join-Path $programData 'Cisco\Cisco Secure Client\DefenseClaw'
$gatewayService = 'DefenseClawGateway'
$guardianService = 'DefenseClawHookGuardian'
$providerLibrary = Join-Path $programFiles 'Cisco\Cisco Secure Client\CM\5.1.0.0\CMID\1.0.0.0\x64\cmidapi.dll'

function ConvertTo-GoldenToken {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    foreach ($pair in @(
        @($programFiles, '%ProgramFiles%'),
        @($programData, '%ProgramData%'),
        @($windowsDirectory, '%WINDIR%')
    )) {
        $root = [string]$pair[0]
        if ([string]::IsNullOrEmpty($root)) { continue }
        $index = $text.IndexOf($root, [StringComparison]::OrdinalIgnoreCase)
        while ($index -ge 0) {
            $text = $text.Substring(0, $index) + [string]$pair[1] + $text.Substring($index + $root.Length)
            $index = $text.IndexOf($root, $index + ([string]$pair[1]).Length, [StringComparison]::OrdinalIgnoreCase)
        }
    }
    return $text
}

function ConvertTo-GoldenJsonString {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    foreach ($character in $Text.ToCharArray()) {
        $code = [int]$character
        switch ($code) {
            34 { [void]$builder.Append('\"') }
            92 { [void]$builder.Append('\\') }
            8 { [void]$builder.Append('\b') }
            9 { [void]$builder.Append('\t') }
            10 { [void]$builder.Append('\n') }
            12 { [void]$builder.Append('\f') }
            13 { [void]$builder.Append('\r') }
            default {
                if ($code -lt 32) {
                    [void]$builder.Append(('\u{0:x4}' -f $code))
                }
                else {
                    [void]$builder.Append($character)
                }
            }
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

# A canonical writer keeps Windows PowerShell 5.1 and PowerShell 7 output
# byte-identical: sorted object keys, fixed escaping, two-space indent, LF.
function ConvertTo-GoldenJson {
    param(
        [AllowNull()][object]$Value,
        [int]$Depth = 0
    )
    $indent = '  ' * ($Depth + 1)
    $closing = '  ' * $Depth
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [int16] -or $Value -is [byte]) {
        return ([string]$Value)
    }
    if ($Value -is [string] -or $Value -is [char] -or $Value -is [enum]) {
        return (ConvertTo-GoldenJsonString -Text (ConvertTo-GoldenToken -Value ([string]$Value)))
    }
    $entries = $null
    if ($Value -is [Collections.IDictionary]) {
        $entries = [Collections.Generic.List[object]]::new()
        foreach ($key in $Value.Keys) {
            $entries.Add([pscustomobject]@{ Key = [string]$key; Value = $Value[$key] })
        }
    }
    elseif ($Value -is [pscustomobject]) {
        $entries = [Collections.Generic.List[object]]::new()
        foreach ($property in $Value.PSObject.Properties) {
            $entries.Add([pscustomobject]@{ Key = [string]$property.Name; Value = $property.Value })
        }
    }
    if ($null -ne $entries) {
        if ($entries.Count -eq 0) { return '{}' }
        # Ordinal sort through a SortedDictionary: Array.Sort with a
        # PowerShell-converted items array sorts a copy, and hashtable
        # enumeration order differs between .NET Framework and .NET Core.
        $sorted = [Collections.Generic.SortedDictionary[string, object]]::new([StringComparer]::Ordinal)
        foreach ($entry in $entries) {
            $sorted.Add([string]$entry.Key, $entry.Value)
        }
        $lines = [Collections.Generic.List[string]]::new()
        foreach ($pair in $sorted.GetEnumerator()) {
            $lines.Add($indent + (ConvertTo-GoldenJsonString -Text $pair.Key) + ': ' + (ConvertTo-GoldenJson -Value $pair.Value -Depth ($Depth + 1)))
        }
        return "{`n" + ($lines -join ",`n") + "`n" + $closing + '}'
    }
    if ($Value -is [Collections.IEnumerable]) {
        $items = @($Value)
        if ($items.Count -eq 0) { return '[]' }
        $lines = [Collections.Generic.List[string]]::new()
        foreach ($item in $items) {
            $lines.Add($indent + (ConvertTo-GoldenJson -Value $item -Depth ($Depth + 1)))
        }
        return "[`n" + ($lines -join ",`n") + "`n" + $closing + ']'
    }
    return (ConvertTo-GoldenJsonString -Text (ConvertTo-GoldenToken -Value ([string]$Value)))
}

$tokens = $null
$parseErrors = $null
[void][Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
    throw "module parser errors: $($parseErrors.Message -join '; ')"
}

Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force
$module = Get-Module DefenseClawEnterprise
if ($null -eq $module) {
    throw 'DefenseClawEnterprise module was not imported'
}

$golden = [ordered]@{}

# ---- Module-scope captures ----------------------------------------------
$moduleCapture = & $module {
    param($InstallRoot, $StateRoot, $GatewayService, $GuardianService, $ProviderLibrary)

    $capture = [ordered]@{}
    $layout = Get-DefenseClawLayout `
        -InstallRoot $InstallRoot `
        -StateRoot $StateRoot `
        -GatewayServiceName $GatewayService `
        -GuardianServiceName $GuardianService
    $capture.layout = $layout.Clone()
    $capture.service_names = @(Get-DefenseClawManagedServiceNames `
        -GatewayServiceName $GatewayService `
        -GuardianServiceName $GuardianService)

    $capture.constants = [ordered]@{
        service_sddl = [string]$script:ServiceSDDL
        service_description = [string]$script:ServiceDescription
        service_failure_restart_quiescence_seconds = [int]$script:ServiceFailureRestartQuiescenceSeconds
        deployment_metadata_schema_version = [int]$script:SchemaVersion
        agent_application_control_attestation_schema_version = [int]$script:AgentApplicationControlAttestationSchemaVersion
        agent_application_control_prerequisite = [string]$script:AgentApplicationControlPrerequisite
        failure_actions_hex = [BitConverter]::ToString((Get-DefenseClawFailureActionsBytes))
        system_sid = [string]$script:SystemSID
        owner_rights_sid = [string]$script:OwnerRightsSID
        administrators_sid = [string]$script:AdministratorsSID
        users_sid = [string]$script:UsersSID
        authenticated_users_sid = [string]$script:AuthenticatedUsersSID
        trusted_installer_sid = [string]$script:TrustedInstallerSID
    }
    $registryAclDefinition = (Get-Command Set-DefenseClawServiceRegistryAcl).Definition
    $registrySddl = [regex]::Match($registryAclDefinition, "'(O:[^']+)'").Groups[1].Value
    if ([string]::IsNullOrEmpty($registrySddl)) {
        throw 'could not read the service registry key SDDL from Set-DefenseClawServiceRegistryAcl'
    }
    $capture.constants.service_registry_key_sddl = $registrySddl

    # Service specifications: record what the Verify path requires of each
    # production service instead of reading SCM.
    $script:GoldenServiceSpecs = [Collections.Generic.List[object]]::new()
    function script:Assert-DefenseClawServiceConfiguration {
        param(
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)][string]$ExpectedImage,
            [Parameter(Mandatory)][string]$ExpectedAccount,
            [Parameter(Mandatory)][string]$ExpectedDisplayName,
            [Parameter(Mandatory)][int]$ExpectedSidType,
            [Parameter(Mandatory)][string[]]$ExpectedPrivileges,
            [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ExpectedEnvironment,
            [string[]]$ExpectedDependencies = @(),
            [int[]]$ExpectedStartMode = @(2)
        )
        $script:GoldenServiceSpecs.Add([ordered]@{
            name = $Name
            image = $ExpectedImage
            account = $ExpectedAccount
            display_name = $ExpectedDisplayName
            sid_type = $ExpectedSidType
            privileges = @($ExpectedPrivileges | Sort-Object)
            environment = @($ExpectedEnvironment | Sort-Object)
            dependencies = @($ExpectedDependencies | Sort-Object)
            start_mode = @($ExpectedStartMode)
        })
    }
    $serviceLayout = $layout.Clone()
    $serviceLayout.ProviderLibraryPath = $ProviderLibrary
    $variants = [ordered]@{}
    foreach ($variant in @('installed', 'pending', 'servicing', 'any_start_mode', 'attested')) {
        $script:GoldenServiceSpecs.Clear()
        $variantLayout = $serviceLayout.Clone()
        $arguments = @{
            Layout = $variantLayout
            GatewayServiceName = $GatewayService
            GuardianServiceName = $GuardianService
        }
        switch ($variant) {
            'pending' { $arguments.PendingTransaction = $true }
            'servicing' { $arguments.ServicingTransaction = $true }
            'any_start_mode' { $arguments.AnyStartMode = $true }
            'attested' {
                $variantLayout.AgentApplicationControlAttested = $true
                $variantLayout.ClaudeEffectivePolicyVerified = $true
            }
        }
        Assert-DefenseClawManagedServiceConfigurations @arguments
        $variants[$variant] = @($script:GoldenServiceSpecs.ToArray())
    }
    $capture.service_specs = $variants
    $capture.sensor_helper_environment = @(Get-DefenseClawSensorHelperEnvironmentValues -GatewayServiceName $GatewayService)

    # Canonical ACLs per managed path kind.
    $gatewaySID = Get-DefenseClawDeterministicServiceSID -ServiceName $GatewayService
    $capture.gateway_service_sid = $gatewaySID
    $directoryKinds = @(
        'InstallDirectory', 'ServiceInstallDirectory', 'StateDirectory',
        'AdminDirectory', 'ConfigDirectory', 'RuntimeDirectory',
        'AuthorizationDirectory', 'LogDirectory', 'GatewayLogDirectory',
        'ManagedIPCDirectory'
    )
    $fileKinds = @(
        'InstallFile', 'ServiceInstallFile', 'AdminFile', 'ConfigFile',
        'MachinePolicyFile', 'RuntimeFile', 'RuntimeSecretFile',
        'AuthorizationFile'
    )
    $acls = [ordered]@{}
    foreach ($kind in @($directoryKinds + $fileKinds)) {
        $security = New-DefenseClawCanonicalPathAcl `
            -IsDirectory ($kind -in $directoryKinds) `
            -Kind $kind `
            -GatewayServiceSID $gatewaySID
        $acls[$kind] = $security.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::All
        )
    }
    $capture.canonical_path_acls = $acls

    $requiredRights = [ordered]@{}
    foreach ($kind in @('Admin', 'Install', 'ServiceInstall', 'State', 'ConfigDirectory', 'Config', 'MachinePolicy', 'AuthorizationDirectory', 'AuthorizationFile', 'Runtime', 'RuntimeSecret', 'ManagedIPCDirectory')) {
        $rights = New-DefenseClawRequiredRights -Kind $kind -GatewayServiceSID $gatewaySID
        $flattened = [ordered]@{}
        foreach ($sid in @($rights.Keys | Sort-Object)) {
            # Numeric, not the enum name: .NET Framework and .NET Core pick
            # different names for FileSystemRights values that share bits.
            $flattened[[string]$sid] = '0x{0:X8}' -f [int]$rights[$sid]
        }
        $requiredRights[$kind] = $flattened
    }
    $capture.required_rights = $requiredRights

    # ACL plan: which kind Set-DefenseClawManagedAcls assigns to each managed
    # path that exists on a fresh host (conditional files are absent here).
    $script:GoldenAclPlan = [Collections.Generic.List[object]]::new()
    function script:Set-DefenseClawPathAcl {
        param(
            [Parameter(Mandatory)][string]$Path,
            [Parameter(Mandatory)][string]$Kind,
            [Parameter(Mandatory)][string]$GatewayServiceSID
        )
        $script:GoldenAclPlan.Add([ordered]@{ path = $Path; kind = $Kind; sid = $GatewayServiceSID })
    }
    function script:Grant-DefenseClawStateAncestorTraverse {
        param(
            [Parameter(Mandatory)][string]$Path,
            [Parameter(Mandatory)][string]$GatewayServiceSID
        )
        $script:GoldenAclPlan.Add([ordered]@{ path = $Path; kind = 'StateAncestorTraverse'; sid = $GatewayServiceSID })
    }
    # The NT SERVICE SID is computed here, not through
    # Get-DefenseClawDeterministicServiceSID: that function calls back into
    # Get-DefenseClawServiceSID whenever a service with the same name exists on
    # the host, so on a machine with a real DefenseClawGateway service the two
    # would recurse until the call depth overflows. The value is the one
    # `sc.exe showsid` prints: S-1-5-80 followed by the five little-endian
    # DWORDs of SHA-1 over the upper-cased service name in UTF-16LE.
    function script:Get-DefenseClawServiceSID {
        param([Parameter(Mandatory)][string]$ServiceName)
        $sha1 = [Security.Cryptography.SHA1]::Create()
        try {
            $hash = $sha1.ComputeHash([Text.Encoding]::Unicode.GetBytes($ServiceName.ToUpperInvariant()))
        }
        finally {
            $sha1.Dispose()
        }
        $parts = foreach ($offset in 0, 4, 8, 12, 16) {
            [BitConverter]::ToUInt32($hash, $offset)
        }
        return ('S-1-5-80-' + ($parts -join '-'))
    }
    Set-DefenseClawManagedAcls -Layout $layout.Clone() -GatewayServiceName $GatewayService
    $capture.acl_plan = @($script:GoldenAclPlan.ToArray())

    # Profile helpers the pinned functions call for their Secure Client
    # branch: roots, broker gate, gateway dependencies and version floors.
    $profileRoots = Get-DefenseClawProfileRoots -EnterpriseProfile SecureClient
    $brokerService = Get-DefenseClawCMIDBrokerServiceName -GatewayServiceName $GatewayService
    $sensorHelperService = Get-DefenseClawSensorHelperServiceName -GatewayServiceName $GatewayService
    $defaultRoots = Get-DefenseClawProfileRoots
    $defaultRootsAreSecureClient = $defaultRoots.Count -eq $profileRoots.Count
    foreach ($rootKey in @($profileRoots.Keys)) {
        if ([string]$defaultRoots[$rootKey] -cne [string]$profileRoots[$rootKey]) {
            $defaultRootsAreSecureClient = $false
        }
    }
    $capture.profile_helpers = [ordered]@{
        default_profile = Get-DefenseClawEnterpriseProfile
        standalone_profile = [bool](Test-DefenseClawStandaloneProfile)
        broker_enabled = [bool](Test-DefenseClawBrokerEnabled)
        layout_broker_enabled = [bool](Test-DefenseClawLayoutBrokerEnabled -Layout $layout)
        roots = $profileRoots
        default_roots_are_secure_client = [bool]$defaultRootsAreSecureClient
        profile_from_lifecycle_directory = Resolve-DefenseClawProfileFromLifecycleDirectory -Directory $profileRoots.LifecycleDirectory
        gateway_dependencies = [ordered]@{
            without_sensor_helper = Get-DefenseClawGatewayServiceDependencies `
                -BrokerServiceName $brokerService `
                -SensorHelperServiceName $sensorHelperService
            with_sensor_helper = Get-DefenseClawGatewayServiceDependencies `
                -BrokerServiceName $brokerService `
                -SensorHelperServiceName $sensorHelperService `
                -SensorHelperRegistered
        }
        claude_minimum_client_version = Get-DefenseClawClaudeMinimumClientVersion
        agent_application_control_attestation_schema_version = [int](Get-DefenseClawAgentApplicationControlAttestationSchemaVersion)
    }

    # Service install plan: the exact sc.exe argument lists
    # Set-DefenseClawManagedServices issues for the broker, sensor helper,
    # gateway, guardian and enumerator, recorded instead of run. Every SCM
    # query and write goes through the stubs below; the plan stops at the
    # first failure-actions write, before any service registry change.
    $stubNames = @(
        'Invoke-DefenseClawNative', 'Test-DefenseClawServiceExists',
        'Assert-DefenseClawServiceImagePath',
        'Assert-DefenseClawOwnedServiceOrAbsent', 'Assert-DefenseClawCMIDBrokerServiceOrAbsent',
        'Set-DefenseClawSensorHelperServiceEnvironment', 'Set-DefenseClawExactFailureActions',
        'Set-DefenseClawServiceRegistryAcl', 'Set-DefenseClawCMIDBrokerAuthKey',
        'Set-DefenseClawServiceEnvironment'
    )
    $savedFunctions = @{}
    foreach ($stubName in $stubNames) {
        $savedFunctions[$stubName] = (Microsoft.PowerShell.Core\Get-Command -Name $stubName -CommandType Function).ScriptBlock
    }
    $script:GoldenServicePlan = [Collections.Generic.List[object]]::new()
    $script:GoldenServicesExist = $false
    function script:Invoke-DefenseClawNative {
        param($File, $Arguments)
        $script:GoldenServicePlan.Add([ordered]@{ command = [IO.Path]::GetFileName([string]$File); arguments = @($Arguments) })
    }
    function script:Test-DefenseClawServiceExists { return $script:GoldenServicesExist }
    function script:Assert-DefenseClawServiceImagePath { }
    function script:Assert-DefenseClawOwnedServiceOrAbsent { }
    function script:Assert-DefenseClawCMIDBrokerServiceOrAbsent { }
    function script:Set-DefenseClawSensorHelperServiceEnvironment {
        param($Name, $GatewayServiceName)
        $script:GoldenServicePlan.Add([ordered]@{ command = 'Set-DefenseClawSensorHelperServiceEnvironment'; arguments = @($Name, $GatewayServiceName) })
    }
    function script:Set-DefenseClawExactFailureActions { throw 'golden-service-plan-complete' }
    function script:Set-DefenseClawServiceRegistryAcl { throw 'golden-service-plan-unexpected-write' }
    function script:Set-DefenseClawCMIDBrokerAuthKey { throw 'golden-service-plan-unexpected-write' }
    function script:Set-DefenseClawServiceEnvironment { throw 'golden-service-plan-unexpected-write' }
    $plans = [ordered]@{}
    try {
        foreach ($variant in @('create_deferred', 'create_automatic', 'reconfigure_deferred', 'create_deferred_with_sensor_helper')) {
            $script:GoldenServicePlan.Clear()
            $script:GoldenServicesExist = $variant -ceq 'reconfigure_deferred'
            # Set-DefenseClawManagedServices reads $Layout from its caller.
            $Layout = $serviceLayout.Clone()
            if ($variant -ceq 'create_deferred_with_sensor_helper') {
                # Any file that exists stands in for the helper binary.
                $Layout.SensorHelperPath = Join-Path $script:System32 'sc.exe'
            }
            else {
                $Layout.SensorHelperPath = ''
            }
            $serviceArguments = @{
                GatewayServiceName = $GatewayService
                GuardianServiceName = $GuardianService
                BrokerServiceName = $Layout.BrokerServiceName
                BrokerPath = $Layout.BrokerPath
                BrokerPipeName = $Layout.BrokerPipeName
                BrokerAuthKeyPath = $Layout.BrokerAuthKeyPath
                ProviderLibraryPath = $Layout.ProviderLibraryPath
                BrokerLogPath = $Layout.BrokerLogPath
                GatewayPath = $Layout.GatewayPath
                ManifestPath = $Layout.ManifestPath
                RuntimeDirectory = $Layout.RuntimeDirectory
                ConfigPath = $Layout.ConfigPath
                AuthorizationDirectory = $Layout.AuthorizationDirectory
                GatewayLogPath = $Layout.GatewayLogPath
                GuardianLogPath = $Layout.GuardianLogPath
            }
            if ($variant -cne 'create_automatic') {
                $serviceArguments.DeferAutomaticStart = $true
            }
            $completed = $false
            try {
                Set-DefenseClawManagedServices @serviceArguments
            }
            catch {
                if ([string]$_.Exception.Message -cne 'golden-service-plan-complete') {
                    throw
                }
                $completed = $true
            }
            if (-not $completed) {
                throw "service plan $variant did not reach the failure-actions write"
            }
            $plans[$variant] = @($script:GoldenServicePlan.ToArray())
        }
    }
    finally {
        foreach ($stubName in $stubNames) {
            Microsoft.PowerShell.Management\Set-Item -LiteralPath "function:script:$stubName" -Value $savedFunctions[$stubName]
        }
    }
    $capture.service_install_plan = $plans

    return $capture
} $installRoot $stateRoot $gatewayService $guardianService $providerLibrary

foreach ($key in $moduleCapture.Keys) {
    $golden[$key] = $moduleCapture[$key]
}

# ---- install-enterprise.ps1 -Mode/-Connector renderers -------------------
$installerTokens = $null
$installerErrors = $null
$installerAst = [Management.Automation.Language.Parser]::ParseFile($installerPath, [ref]$installerTokens, [ref]$installerErrors)
if ($installerErrors.Count -ne 0) {
    throw "installer parser errors: $($installerErrors.Message -join '; ')"
}
$renderCapture = & {
    $trustedProgramFiles = $programFiles
    foreach ($statement in $installerAst.EndBlock.Statements) {
        if ($statement -is [Management.Automation.Language.FunctionDefinitionAst]) {
            . ([scriptblock]::Create($statement.Extent.Text))
            continue
        }
        if ($statement -is [Management.Automation.Language.AssignmentStatementAst] -and
            $statement.Left.Extent.Text -in @(
                '$script:DefenseClawSupportedConnectors',
                '$script:DefenseClawWindowsManagedEnterpriseSupportedConnectors'
            )) {
            . ([scriptblock]::Create($statement.Extent.Text))
        }
    }
    $capture = [ordered]@{}
    $capture.supported_connectors = @($script:DefenseClawSupportedConnectors)
    $capture.windows_managed_enterprise_connectors = @($script:DefenseClawWindowsManagedEnterpriseSupportedConnectors)

    $normalization = [ordered]@{}
    foreach ($connectorInput in @('codex', 'Codex, CLAUDECODE ,codex', 'codex,claudecode,cursor', 'amp', 'bogus', ' , ')) {
        try {
            $normalization[$connectorInput] = @(ConvertTo-DefenseClawConnectorList -Connector $connectorInput)
        }
        catch {
            $normalization[$connectorInput] = 'error: ' + $_.Exception.Message
        }
    }
    $capture.connector_normalization = $normalization

    $configs = [ordered]@{}
    foreach ($case in @(
        @{ Name = 'observe_codex'; Mode = 'observe'; Connectors = @('codex') },
        @{ Name = 'action_codex_claudecode_cursor'; Mode = 'action'; Connectors = @('codex', 'claudecode', 'cursor') }
    )) {
        $configs[$case.Name] = (Get-DefenseClawRenderedEnterpriseConfig -Mode $case.Mode -Connectors $case.Connectors) -replace "`r`n", "`n"
    }
    $capture.rendered_config = $configs

    $profiles = @(
        [pscustomobject]@{ UserName = 'golden-alice'; UserHome = 'C:\Users\dc-golden-alice-absent'; SID = 'S-1-5-21-1111111111-2222222222-3333333333-1001' },
        [pscustomobject]@{ UserName = 'golden-bob'; UserHome = 'C:\Users\dc-golden-bob-absent'; SID = 'S-1-5-21-1111111111-2222222222-3333333333-1002' }
    )
    $targets = [ordered]@{}
    $targets.all_active = (Get-DefenseClawRenderedEnterpriseTargets `
        -Connectors @('codex', 'claudecode', 'cursor') `
        -Profiles $profiles) -replace "`r`n", "`n"
    $targets.deferred_inactive = (Get-DefenseClawRenderedEnterpriseTargets `
        -Connectors @('codex', 'claudecode', 'cursor') `
        -Profiles $profiles `
        -ActiveSessionSIDs @('S-1-5-21-1111111111-2222222222-3333333333-1001') `
        -DeferInactiveProfiles) -replace "`r`n", "`n"
    $targets.no_profiles = (Get-DefenseClawRenderedEnterpriseTargets `
        -Connectors @('codex') `
        -Profiles @()) -replace "`r`n", "`n"
    $capture.rendered_targets = $targets
    $capture.agent_version_minimums = $script:DefenseClawWindowsAgentVersionMinimum
    return $capture
}
foreach ($key in $renderCapture.Keys) {
    $golden[$key] = $renderCapture[$key]
}

# ---- Cross-profile deployment records ------------------------------------
# A Secure Client Install/Upgrade/Repair refuses while a standalone
# deployment is recorded. A record a standard user could plant under the
# default ProgramData ACL must not block it. Evaluated in a disposable
# ProgramData stand-in; the record's user-writable ancestors make it untrusted
# whichever token runs the golden.
$recordCapture = & $module {
    param([string]$ScratchParent)
    $capture = [ordered]@{}
    $root = [IO.Path]::Combine($ScratchParent, ('dc-scgolden-record-' + [Guid]::NewGuid().ToString('N')))
    [void][IO.Directory]::CreateDirectory($root)
    $originalProgramData = $script:ProgramData
    $originalProfile = Get-DefenseClawEnterpriseProfile
    $originalAdministrator = ${function:Test-DefenseClawAdministrator}
    try {
        $script:ProgramData = $root
        # Every mutation runs elevated; pin that so the capture does not
        # depend on the token running the golden.
        Microsoft.PowerShell.Management\Set-Item -Path 'function:script:Test-DefenseClawAdministrator' -Value { return $true }
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
        $decide = {
            try {
                Assert-DefenseClawNoOtherProfileDeployment
                return 'allowed'
            }
            catch {
                return 'refused: ' + $_.Exception.Message.Replace($root, '%ProgramData%')
            }
        }
        $capture.no_standalone_record = & $decide
        $standaloneRoots = Get-DefenseClawProfileRoots -EnterpriseProfile Standalone
        $install = [IO.Path]::Combine([string]$standaloneRoots.StateRoot, 'install')
        [void][IO.Directory]::CreateDirectory($install)
        [IO.File]::WriteAllText([IO.Path]::Combine($install, 'deployment.json'), '{}', [Text.UTF8Encoding]::new($false))
        $capture.planted_standalone_record = & $decide
        $probe = Test-DefenseClawProfileDeploymentInstalled -EnterpriseProfile Standalone
        $capture.planted_standalone_record_probe = [ordered]@{
            installed = [bool]$probe.installed
            untrusted = [bool]($null -ne $probe.PSObject.Properties['untrusted'] -and $probe.untrusted)
        }
        $record = [IO.Path]::Combine($install, 'deployment.json')
        # The conflict check itself is unchanged: a standalone record an
        # administrator wrote still refuses the Secure Client mutation. The
        # scratch tree cannot carry the lifecycle's administrator-only ACL, so
        # the record-trust test stands in for it here.
        $originalRecordTrusted = ${function:Test-DefenseClawProfileDeploymentRecordTrusted}
        try {
            Microsoft.PowerShell.Management\Set-Item -Path 'function:script:Test-DefenseClawProfileDeploymentRecordTrusted' -Value { return $true }
            $capture.administrator_standalone_record = & $decide
        }
        finally {
            Microsoft.PowerShell.Management\Set-Item -Path 'function:script:Test-DefenseClawProfileDeploymentRecordTrusted' -Value $originalRecordTrusted
        }
        # A folder a standard user created at the record path is no record.
        [IO.File]::Delete($record)
        [void][IO.Directory]::CreateDirectory($record)
        $capture.planted_standalone_folder = & $decide
        $probe = Test-DefenseClawProfileDeploymentInstalled -EnterpriseProfile Standalone
        $capture.planted_standalone_folder_probe = [ordered]@{
            installed = [bool]$probe.installed
            untrusted = [bool]($null -ne $probe.PSObject.Properties['untrusted'] -and $probe.untrusted)
        }
    }
    finally {
        Microsoft.PowerShell.Management\Set-Item -Path 'function:script:Test-DefenseClawAdministrator' -Value $originalAdministrator
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        $script:ProgramData = $originalProgramData
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
    return $capture
} ([IO.Path]::GetTempPath())
$golden.cross_profile_records = $recordCapture

# ---- Deployment metadata -------------------------------------------------
# The deployment.json document the Secure Client lifecycle writes
# (New-DefenseClawDeploymentMetadata) for an installed deployment and for an
# uninstall tombstone, and how Get-DefenseClawDeploymentMetadata reads a
# Secure Client record back: a record without a profile field (every Secure
# Client record) is Secure Client, and a record that names the standalone
# profile is refused. Evaluated in a disposable directory: the eight hashed
# binaries, the Codex policy and managed-hooks state, and the
# application-control attestation are fixed stand-in files there (their
# paths appear as %GoldenScratch%), the activation record is a fixed valid
# record, the attestation reader and the record's canonical-ACL check are
# stubbed and restored, and timestamps are reduced to their format.
$metadataCapture = & $module {
    param($InstallRoot, $StateRoot, $GatewayService, $GuardianService, $ProviderLibrary, [string]$ScratchParent)
    $capture = [ordered]@{}
    $scratch = [IO.Path]::Combine($ScratchParent, ('dc-scgolden-metadata-' + [Guid]::NewGuid().ToString('N')))
    [void][IO.Directory]::CreateDirectory($scratch)
    $utf8 = [Text.UTF8Encoding]::new($false)
    $stubNames = @('Get-DefenseClawAgentApplicationControlAttestation', 'Assert-DefenseClawCanonicalPathAcl')
    $savedFunctions = @{}
    foreach ($stubName in $stubNames) {
        $savedFunctions[$stubName] = (Microsoft.PowerShell.Core\Get-Command -Name $stubName -CommandType Function).ScriptBlock
    }
    $originalProfile = Get-DefenseClawEnterpriseProfile
    $normalize = {
        param($Value)
        if ($Value -is [string]) {
            return $Value.Replace($scratch, '%GoldenScratch%')
        }
        if ($Value -is [Collections.IDictionary]) {
            $copy = [ordered]@{}
            foreach ($key in @($Value.Keys)) {
                $item = $Value[$key]
                if ($key -in @('updated_at', 'uninstalled_at') -and $null -ne $item) {
                    $item = if ([string]$item -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$') {
                        '<utc-round-trip-timestamp>'
                    }
                    else {
                        'unexpected: ' + [string]$item
                    }
                }
                $copy[$key] = & $normalize $item
            }
            return $copy
        }
        return $Value
    }
    try {
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
        function script:Get-DefenseClawAgentApplicationControlAttestation { param($Layout) }
        function script:Assert-DefenseClawCanonicalPathAcl { param($Path, $Expected) }
        $layout = Get-DefenseClawLayout `
            -InstallRoot $InstallRoot `
            -StateRoot $StateRoot `
            -GatewayServiceName $GatewayService `
            -GuardianServiceName $GuardianService
        $layout.ProviderLibraryPath = $ProviderLibrary
        foreach ($key in @(
                'BrokerPath', 'GatewayPath', 'ACPPath', 'HookPath', 'SensorHelperPath',
                'CLIPath', 'InstallerPath', 'ModulePath',
                'CodexMachinePolicyPath', 'CodexManagedHooksStatePath',
                'AgentApplicationControlAttestationPath'
            )) {
            $standIn = [IO.Path]::Combine($scratch, $key)
            [IO.File]::WriteAllText($standIn, $key, $utf8)
            $layout[$key] = $standIn
        }
        $layout.CodexTargetEnabled = $true
        $layout.ClaudeTargetEnabled = $true
        $layout.CursorTargetEnabled = $false
        $layout.AgentApplicationControlAttested = $true
        $layout.ClaudeEffectivePolicyVerified = $true
        $metadataArguments = @{
            Layout = $layout
            GatewayServiceName = $GatewayService
            GuardianServiceName = $GuardianService
            ManagedHooksActivation = [pscustomobject][ordered]@{
                schema_version = 1
                deployment_generation_id = '0123456789abcdef0123456789abcdef'
                state = 'activated'
                manifest_sha256 = ('ab' * 32)
                target_count = 2
            }
        }
        $installed = New-DefenseClawDeploymentMetadata @metadataArguments
        $tombstone = New-DefenseClawDeploymentMetadata @metadataArguments -Installed $false
        $capture.new_installed = & $normalize $installed
        $capture.new_tombstone = & $normalize $tombstone

        # Read-back: the record is written the way the lifecycle serializes
        # it, into a layout that starts without the recorded provider
        # library and targets, so the capture shows what the reader adopts.
        $readBack = {
            param([Collections.IDictionary]$Document)
            $readLayout = $layout.Clone()
            $readLayout.MetadataPath = [IO.Path]::Combine($scratch, 'deployment.json')
            $readLayout.ProviderLibraryPath = ''
            $readLayout.ClaudeTargetEnabled = $false
            $readLayout.CodexTargetEnabled = $false
            $readLayout.CursorTargetEnabled = $false
            [IO.File]::WriteAllText(
                $readLayout.MetadataPath,
                ($Document | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12),
                $utf8
            )
            try {
                $metadata = Get-DefenseClawDeploymentMetadata -Layout $readLayout -Required
                return [ordered]@{
                    result = 'read'
                    installed = [bool]$metadata.installed
                    layout_provider_library_path = [string]$readLayout.ProviderLibraryPath
                    layout_certification_codex_home = [string]$readLayout.CertificationCodexHome
                    layout_core_hardening_certification = [bool]$readLayout.CoreHardeningCertification
                    layout_claude_target_enabled = [bool]$readLayout.ClaudeTargetEnabled
                    layout_codex_target_enabled = [bool]$readLayout.CodexTargetEnabled
                    layout_cursor_target_enabled = [bool]$readLayout.CursorTargetEnabled
                }
            }
            catch {
                return [ordered]@{ result = 'refused: ' + (& $normalize ([string]$_.Exception.Message)) }
            }
        }
        $capture.read_secure_client_record = & $readBack $installed
        $capture.read_secure_client_tombstone = & $readBack $tombstone
        $named = [ordered]@{}
        foreach ($key in @($installed.Keys)) {
            $named[$key] = $installed[$key]
        }
        $named['profile'] = 'secure_client'
        $capture.read_record_naming_secure_client = & $readBack $named
        $named['profile'] = 'standalone'
        $capture.read_record_naming_standalone = & $readBack $named
    }
    finally {
        foreach ($stubName in $stubNames) {
            Microsoft.PowerShell.Management\Set-Item -LiteralPath "function:script:$stubName" -Value $savedFunctions[$stubName]
        }
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
    }
    return $capture
} $installRoot $stateRoot $gatewayService $guardianService $providerLibrary ([IO.Path]::GetTempPath())
$golden.deployment_metadata = $metadataCapture

# ---- Read-only Status on this (uninstalled) host -------------------------
$status = Invoke-DefenseClawEnterpriseLifecycle `
    -Action Status `
    -InstallRoot $installRoot `
    -StateRoot $stateRoot `
    -GatewayServiceName $gatewayService `
    -GuardianServiceName $guardianService
if ([bool]$status.installed) {
    throw 'Secure Client golden must run on a host without a managed_enterprise deployment'
}
$golden.status_uninstalled_keys = @($status.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)

$actual = (ConvertTo-GoldenJson -Value $golden) + "`n"
$goldenFullPath = [IO.Path]::GetFullPath($GoldenPath)
$utf8 = [Text.UTF8Encoding]::new($false)
if ($Update) {
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($goldenFullPath)) | Out-Null
    [IO.File]::WriteAllText($goldenFullPath, $actual, $utf8)
    Write-Output "secure-client-golden: updated $goldenFullPath"
    exit 0
}
if (-not [IO.File]::Exists($goldenFullPath)) {
    throw "Secure Client golden is missing: $goldenFullPath (regenerate with -Update)"
}
$expected = ([IO.File]::ReadAllText($goldenFullPath, $utf8)) -replace "`r`n", "`n"
if ([string]::Equals($expected, $actual, [StringComparison]::Ordinal)) {
    Write-Output 'secure-client-golden: OK'
    exit 0
}
$actualPath = Join-Path ([IO.Path]::GetTempPath()) ("secure-client-golden-actual-{0}.json" -f ([Guid]::NewGuid().ToString('N')))
[IO.File]::WriteAllText($actualPath, $actual, $utf8)
$expectedLines = $expected -split "`n"
$actualLines = $actual -split "`n"
$shown = 0
$report = [Collections.Generic.List[string]]::new()
$report.Add('Secure Client golden drift in the Windows managed_enterprise lifecycle.')
$report.Add('Production Secure Client behavior must not change. If this change is intended,')
$report.Add('review it and regenerate with -Update (testdata/secure_client_golden/README.md).')
$report.Add("actual output: $actualPath")
$max = [Math]::Max($expectedLines.Count, $actualLines.Count)
for ($index = 0; $index -lt $max -and $shown -lt 20; $index++) {
    $left = if ($index -lt $expectedLines.Count) { $expectedLines[$index] } else { '' }
    $right = if ($index -lt $actualLines.Count) { $actualLines[$index] } else { '' }
    if ($left -cne $right) {
        $report.Add(("line {0}:`n  - {1}`n  + {2}" -f ($index + 1), $left, $right))
        $shown++
    }
}
[Console]::Error.WriteLine(($report -join "`n"))
exit 1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$PSNativeCommandUseErrorActionPreference = $true

function Read-BoundedJson {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][long]$MaximumBytes
    )

    $item = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.LinkType -or $item.Length -gt $MaximumBytes) {
        throw 'Protected input is not a bounded regular file.'
    }
    $payload = [System.IO.File]::ReadAllText($item.FullName, [System.Text.Encoding]::UTF8)
    if ([System.Text.Encoding]::UTF8.GetByteCount($payload) -gt $MaximumBytes) {
        throw 'Protected input exceeds its byte limit.'
    }
    return $payload | ConvertFrom-Json -Depth 32 -ErrorAction Stop
}

function Get-BoundTenant {
    param([Parameter(Mandatory = $true)][object]$Scope)

    if ($Scope.schema_version -ne '1' -or $Scope.engine_id -ne 'maester' -or @($Scope.assets).Count -ne 1) {
        throw 'Scope is not bound to the Maester managed profile.'
    }
    $asset = @($Scope.assets)[0]
    if ($asset.provider -ne 'microsoft365' -or $asset.kind -ne 'tenant') {
        throw 'Scope does not contain one Microsoft 365 tenant.'
    }
    $tenantIds = @($asset.identifiers | Where-Object {
        $_.namespace -in @('microsoft_tenant_id', 'microsoft365_tenant_id')
    } | ForEach-Object { [string]$_.value } | Sort-Object -Unique)
    if ($tenantIds.Count -ne 1 -or $tenantIds[0] -notmatch '^[0-9a-fA-F-]{36}$') {
        throw 'Scope does not contain exactly one Microsoft tenant identifier.'
    }
    return [pscustomobject]@{ AssetId = [string]$asset.id; TenantId = $tenantIds[0] }
}

function ConvertTo-SafeText {
    param([AllowNull()][object]$Value, [int]$MaximumLength = 4096)

    if ($null -eq $Value) { return '' }
    $text = [System.Net.WebUtility]::HtmlDecode(([string]$Value -replace '<[^>]*>', ' '))
    $text = [regex]::Replace($text, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '')
    $text = [regex]::Replace($text, '\s+', ' ').Trim()
    if ($text.Length -gt $MaximumLength) { return $text.Substring(0, $MaximumLength) }
    return $text
}

function Write-AtomicJson {
    param([Parameter(Mandatory = $true)][object]$Value, [Parameter(Mandatory = $true)][string]$LiteralPath)

    if (Test-Path -LiteralPath $LiteralPath) { throw 'Managed result path already exists.' }
    $temporary = Join-Path -Path (Split-Path -Parent $LiteralPath) -ChildPath ".maester-$PID.tmp"
    try {
        $json = $Value | ConvertTo-Json -Depth 12
        [System.IO.File]::WriteAllText($temporary, $json + "`n", [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $LiteralPath -ErrorAction Stop
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Read-MaesterReport {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $rawItem = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
    if ($rawItem.LinkType -or $rawItem.Length -gt 16777216) { throw 'Maester JSON result exceeds the managed artifact limit.' }
    $report = Get-Content -LiteralPath $rawItem.FullName -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -Depth 32 -ErrorAction Stop
    if ([string]$report.EndOfJson -ne 'EndOfJson') { throw 'Maester JSON result is incomplete.' }
    return $report
}

# Turns one complete Maester JSON report into the managed result document the
# host adapter reads. Only the verdicts named in the switch become results;
# every counter Maester reported, including `TotalCount`, is carried verbatim
# so the host can see how many tests the switch did not carry.
function ConvertTo-ManagedMaesterDocument {
    param(
        [Parameter(Mandatory = $true)][object]$Report,
        [Parameter(Mandatory = $true)][string]$AssetId
    )

    $normalized = [System.Collections.Generic.List[object]]::new()
    foreach ($test in @($Report.Tests)) {
        $sourceResult = ConvertTo-SafeText -Value $test.Result -MaximumLength 64
        $result = switch ($sourceResult) {
            'Passed' { 'Pass'; break }
            'Failed' { 'Failed'; break }
            'Investigate' { 'Investigate'; break }
            default { $null }
        }
        if ($null -eq $result) { continue }
        $reviewDetailValue = $null
        if ($sourceResult -eq 'Investigate') {
            $resultDetailProperty = $test.PSObject.Properties['ResultDetail']
            if ($null -ne $resultDetailProperty -and $null -ne $resultDetailProperty.Value) {
                $testResultProperty = $resultDetailProperty.Value.PSObject.Properties['TestResult']
                if ($null -ne $testResultProperty) {
                    $reviewDetailValue = $testResultProperty.Value
                }
            }
        }
        $sourceSeverityProperty = $test.PSObject.Properties['Severity']
        $sourceSeverityValue = if ($null -eq $sourceSeverityProperty) { $null } else { $sourceSeverityProperty.Value }
        $sourceSeverity = ConvertTo-SafeText -Value $sourceSeverityValue -MaximumLength 32
        $severity = switch ($sourceSeverity.ToLowerInvariant()) {
            'critical' { 'critical'; break }
            'high' { 'high'; break }
            'medium' { 'medium'; break }
            'low' { 'low'; break }
            'info' { 'informational'; break }
            default { 'unknown' }
        }
        $normalized.Add([ordered]@{
            Id = ConvertTo-SafeText -Value $test.Id -MaximumLength 256
            Title = ConvertTo-SafeText -Value $test.Title
            Result = $result
            SourceResult = $sourceResult
            ReviewDetail = ConvertTo-SafeText -Value $reviewDetailValue
            SourceSeverity = $sourceSeverity
            Severity = $severity
            Service = 'Microsoft Entra ID'
            asset_id = $AssetId
            HelpUrl = ConvertTo-SafeText -Value $test.HelpUrl -MaximumLength 2048
        })
    }

    return [ordered]@{
        schema_version = '1.0.0'
        Engine = 'Maester'
        Product = 'Microsoft Entra ID'
        asset_id = $AssetId
        Provenance = [ordered]@{
            engine_version = '2.3.0'
            source_revision = '7413c42d3fcc724dfea94d2726e690ddd364d914'
            profile = 'entra-graph-token'
            test_path = '/opt/ai-security-scanner/maester-tests/Maester/Entra'
            excluded_tags = @('MT.1025', 'MT.1026', 'MT.1027', 'MT.1028', 'MT.1030', 'MT.1031', 'MT.1182')
            include_long_running = $false
            include_preview = $false
            telemetry = $false
            version_check = $false
            raw_report = 'upstream/maester-raw.json'
        }
        Diagnostics = [ordered]@{
            passes = [int]$Report.PassedCount
            failures = [int]$Report.FailedCount
            investigate = [int]$Report.InvestigateCount
            errors = [int]$Report.ErrorCount
            skipped = [int]$Report.SkippedCount
            not_run = [int]$Report.NotRunCount
            total = [int]$Report.TotalCount
            normalized_results = $normalized.Count
        }
        Results = @($normalized)
    }
}

function Invoke-ManagedMaesterRun {
    $scope = Read-BoundedJson -LiteralPath '/run/ai-security-scanner/scope.json' -MaximumBytes 4194304
    $binding = Get-BoundTenant -Scope $scope
    $scope = $null

    $credentialDocument = Read-BoundedJson -LiteralPath '/run/ai-security-scanner/credentials.json' -MaximumBytes 262144
    if ($credentialDocument.schema_version -ne '1.0.0' -or @($credentialDocument.credentials).Count -ne 1) {
        throw 'Protected credential channel does not contain one credential.'
    }
    $credential = @($credentialDocument.credentials)[0]
    if ($credential.key -ne 'MSGRAPH_ACCESS_TOKEN' -or [string]::IsNullOrWhiteSpace([string]$credential.value)) {
        throw 'Protected credential channel does not contain the Microsoft Graph token.'
    }
    $tokenText = [string]$credential.value
    $secureToken = ConvertTo-SecureString -String $tokenText -AsPlainText -Force
    $credential.value = $null
    $credential = $null
    $credentialDocument = $null
    $tokenText = $null

    $outputRoot = Get-Item -LiteralPath '/output' -Force -ErrorAction Stop
    if (-not $outputRoot.PSIsContainer -or $outputRoot.LinkType) { throw 'Managed output is not a directory.' }
    $upstreamPath = Join-Path $outputRoot.FullName 'upstream'
    if (Test-Path -LiteralPath $upstreamPath) { throw 'Managed upstream output path already exists.' }
    $null = New-Item -ItemType Directory -Path $upstreamPath -ErrorAction Stop
    $rawResultPath = Join-Path $upstreamPath 'maester-raw.json'

    $connected = $false
    try {
        Import-Module Microsoft.Graph.Authentication -RequiredVersion '2.27.0' -Force -ErrorAction Stop
        Connect-MgGraph -AccessToken $secureToken -NoWelcome -ErrorAction Stop | Out-Null
        $secureToken = $null
        $connected = $true
        $context = Get-MgContext -ErrorAction Stop
        if ($null -eq $context -or [string]$context.TenantId -ne $binding.TenantId) {
            throw 'Microsoft Graph token tenant does not match the immutable scope.'
        }

        Import-Module '/opt/ai-security-scanner/Maester/Maester.psd1' -Force -ErrorAction Stop
        Invoke-Maester `
            -Path '/opt/ai-security-scanner/maester-tests/Maester/Entra' `
            -ExcludeTag @('MT.1025', 'MT.1026', 'MT.1027', 'MT.1028', 'MT.1030', 'MT.1031', 'MT.1182') `
            -OutputJsonFile $rawResultPath `
            -NonInteractive `
            -NoLogo `
            -DisableTelemetry `
            -SkipVersionCheck `
            -Verbosity 'None' `
            -ErrorAction Stop

        $report = Read-MaesterReport -LiteralPath $rawResultPath
        $resultDocument = ConvertTo-ManagedMaesterDocument -Report $report -AssetId $binding.AssetId
        # Tests that could not be evaluated are reported in Diagnostics.errors, not
        # by the exit status. A nonzero exit is the platform's signal that this run
        # cannot be trusted at all: the host discards captured evidence without
        # adapting it and the stage is terminal, so throwing here would delete every
        # real finding in the document just written. The conditions above still
        # throw, because each of them means there is no trustworthy document.
        Write-AtomicJson -Value $resultDocument -LiteralPath (Join-Path $outputRoot.FullName 'maester.json')
    }
    finally {
        $secureToken = $null
        if ($connected) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
    }
}

# The launcher runs this file with `pwsh -File`, and that is the only way the
# managed run starts. `run-maester.Tests.ps1` dot-sources the file instead so
# it can feed the functions above fixture reports; a dot-sourced script sees
# `.` as its invocation name. Nothing below this line may do work of its own.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ManagedMaesterRun
}

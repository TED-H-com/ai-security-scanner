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
        throw "Protected input is not a bounded regular file."
    }
    $payload = [System.IO.File]::ReadAllText($item.FullName, [System.Text.Encoding]::UTF8)
    if ([System.Text.Encoding]::UTF8.GetByteCount($payload) -gt $MaximumBytes) {
        throw "Protected input exceeds its byte limit."
    }
    return $payload | ConvertFrom-Json -Depth 32 -ErrorAction Stop
}

function Get-BoundTenant {
    param([Parameter(Mandatory = $true)][object]$Scope)

    if ($Scope.schema_version -ne '1' -or $Scope.engine_id -ne 'scubagear' -or @($Scope.assets).Count -ne 1) {
        throw 'Scope is not bound to the ScubaGear managed profile.'
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

# ScubaGear appends its policy badges (BOD 25-01 Requirement, Automated Check,
# Configurable, Manual) to the requirement sentence as one HTML block
# (CreateReport.psm1:255). Removing only the tags would run the badge labels
# into the sentence, so the block is cut before the text is made safe.
function ConvertTo-RequirementText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    $sentence = [regex]::Replace([string]$Value, "<div class='policy-indicators'>.*?</div>\s*$", '', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    return ConvertTo-SafeText -Value $sentence
}

function Write-AtomicJson {
    param([Parameter(Mandatory = $true)][object]$Value, [Parameter(Mandatory = $true)][string]$LiteralPath)

    if (Test-Path -LiteralPath $LiteralPath) { throw 'Managed result path already exists.' }
    $temporary = Join-Path -Path (Split-Path -Parent $LiteralPath) -ChildPath ".scubagear-$PID.tmp"
    try {
        $json = $Value | ConvertTo-Json -Depth 12
        [System.IO.File]::WriteAllText($temporary, $json + "`n", [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $LiteralPath -ErrorAction Stop
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

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

$connected = $false
try {
    Import-Module Microsoft.Graph.Authentication -RequiredVersion '2.25.0' -Force -ErrorAction Stop
    Connect-MgGraph -AccessToken $secureToken -NoWelcome -ErrorAction Stop | Out-Null
    $secureToken = $null
    $connected = $true
    $context = Get-MgContext -ErrorAction Stop
    if ($null -eq $context -or [string]$context.TenantId -ne $binding.TenantId) {
        throw 'Microsoft Graph token tenant does not match the immutable scope.'
    }

    Import-Module '/opt/ai-security-scanner/ScubaGear/ScubaGear.psd1' -SkipEditionCheck -Force -ErrorAction Stop
    Invoke-SCuBA `
        -ProductNames @('aad') `
        -M365Environment 'commercial' `
        -OPAPath '/opt/ai-security-scanner/opa' `
        -OutPath $upstreamPath `
        -LogIn $false `
        -Quiet `
        -KeepIndividualJSON `
        -SilenceBODWarnings `
        -SkipDoH $true `
        -ErrorAction Stop

    $reports = @(Get-ChildItem -LiteralPath $upstreamPath -Filter 'AADReport.json' -File -Recurse -Force)
    if ($reports.Count -ne 1 -or $reports[0].LinkType -or $reports[0].Length -gt 16777216) {
        throw 'ScubaGear did not produce exactly one bounded AAD report.'
    }
    $report = Get-Content -LiteralPath $reports[0].FullName -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 32 -ErrorAction Stop
    if (@($report).Count -ne 1) { throw 'ScubaGear AAD report has an unexpected top-level shape.' }
    $report = @($report)[0]

    $normalized = [System.Collections.Generic.List[object]]::new()
    foreach ($group in @($report.Results)) {
        $reference = ConvertTo-SafeText -Value $group.GroupReferenceURL -MaximumLength 2048
        foreach ($control in @($group.Controls)) {
            $sourceResult = ConvertTo-SafeText -Value $control.Result -MaximumLength 64
            # A control the tenant marked incorrect in its own ScubaGear config
            # arrives as the sentinel 'Incorrect result'. ScubaGear's actual
            # determination survives in OriginalResult, and the control is counted
            # in IncorrectResults instead of Failures, so it reaches neither the
            # findings nor any counter the host discloses (CreateReport.psm1:331,
            # :342, :348). Judging on Result alone therefore lets the audited
            # tenant delete a real failure from its own audit without a trace.
            # Judge on ScubaGear's verdict and leave the dispute in SourceResult.
            $verdict = $sourceResult
            if ($verdict -eq 'Incorrect result') {
                $verdict = ConvertTo-SafeText -Value $control.OriginalResult -MaximumLength 64
            }
            $result = switch -Regex ($verdict) {
                '^Pass$' { 'Pass'; break }
                '^(Fail|Warning)$' { 'Failed'; break }
                default { $null }
            }
            if ($null -eq $result) { continue }
            $criticalityProperty = $control.PSObject.Properties['Criticality']
            $criticalityValue = if ($null -eq $criticalityProperty) { $null } else { $criticalityProperty.Value }
            $criticality = ConvertTo-SafeText -Value $criticalityValue -MaximumLength 128
            $severity = switch ($criticality.ToLowerInvariant()) {
                'shall' { 'high'; break }
                'shall/3rd party' { 'high'; break }
                'shall/not-implemented' { 'high'; break }
                'should' { 'medium'; break }
                'should/3rd party' { 'medium'; break }
                'should/not-implemented' { 'medium'; break }
                default { 'unknown' }
            }
            $normalized.Add([ordered]@{
                PolicyId = ConvertTo-SafeText -Value $control.'Control ID' -MaximumLength 256
                Requirement = ConvertTo-RequirementText -Value $control.Requirement
                Result = $result
                SourceResult = $sourceResult
                SourceCriticality = $criticality
                Severity = $severity
                Service = 'Microsoft Entra ID'
                asset_id = $binding.AssetId
                HelpUrl = $reference
            })
        }
    }

    $summary = $report.ReportSummary
    $resultDocument = [ordered]@{
        schema_version = '1.0.0'
        Engine = 'ScubaGear'
        Product = 'Microsoft Entra ID'
        asset_id = $binding.AssetId
        Provenance = [ordered]@{
            engine_version = '2.0.0'
            source_revision = '6e5a1a421b36c5a1fb3fd983b8c4bcd5b7a6c61d'
            profile = 'aad-commercial-graph-token'
            products = @('aad')
            login = $false
            telemetry = $false
            version_check = $false
            raw_report = $reports[0].FullName.Substring($outputRoot.FullName.Length).TrimStart('/')
        }
        Diagnostics = [ordered]@{
            passes = [int]$summary.Passes
            failures = [int]$summary.Failures
            warnings = [int]$summary.Warnings
            errors = [int]$summary.Errors
            manual = [int]$summary.Manual
            omitted = [int]$summary.Omits
            disputed = [int]$summary.IncorrectResults
            normalized_results = $normalized.Count
        }
        Results = @($normalized)
    }
    # Controls that could not be evaluated are reported in Diagnostics.errors,
    # not by the exit status. A nonzero exit is the platform's signal that this
    # run cannot be trusted at all: the host discards captured evidence without
    # adapting it and the stage is terminal, so throwing here would delete every
    # real finding in the document just written. The conditions above still
    # throw, because each of them means there is no trustworthy document.
    Write-AtomicJson -Value $resultDocument -LiteralPath (Join-Path $outputRoot.FullName 'scubagear.json')
}
finally {
    $secureToken = $null
    if ($connected) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
}

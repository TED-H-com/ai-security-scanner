# Pester specification for run-maester.ps1: the boundary between what Maester
# writes and what the host adapter reads. It runs inside the engine image at
# build time (see the Dockerfile) and can be replayed against any published
# digest with the same command, so the wrapper that ships is the wrapper that
# was tested. Fixture reports mirror ConvertTo-MtMaesterResult at the pinned
# Maester revision: every *Count is a recount over Tests, TotalCount is the
# length of Tests, Severity is present but empty when a test sets none, and
# EndOfJson is the last property.

BeforeAll {
    Set-StrictMode -Version Latest
    # Dot-sourcing must not start the managed run: there is no scope file or
    # credential channel here, so a run that started would throw and fail this
    # block before any test could execute.
    . (Join-Path $PSScriptRoot 'run-maester.ps1')

    function New-MaesterTest {
        param(
            [Parameter(Mandatory = $true)][string]$Id,
            [Parameter(Mandatory = $true)][string]$Result,
            [string]$Title = "Fixture test $Id",
            [AllowNull()][object]$Severity = '',
            [AllowNull()][object]$HelpUrl = "https://maester.dev/docs/tests/$Id/",
            [AllowNull()][object]$ResultDetail = $null,
            [switch]$OmitSeverity
        )
        $test = [ordered]@{
            Index = 0
            Id = $Id
            Title = $Title
            Name = "${Id}: ${Title}"
            HelpUrl = $HelpUrl
            Severity = $Severity
            Tag = @('Entra', $Id)
            Result = $Result
            ScriptBlock = ''
            ScriptBlockFile = '/opt/ai-security-scanner/maester-tests/Maester/Entra/Fixture.Tests.ps1'
            ErrorRecord = @()
            Block = 'Entra'
            Duration = '00:00:00.0100000'
            ResultDetail = $ResultDetail
        }
        if ($OmitSeverity) { $test.Remove('Severity') }
        return $test
    }

    function New-MaesterReport {
        param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Tests, [hashtable]$Override = @{})
        $count = { param($verdict) @($Tests | Where-Object { $_.Result -eq $verdict }).Count }
        $report = [ordered]@{
            Result = 'Failed'
            FailedCount = & $count 'Failed'
            PassedCount = & $count 'Passed'
            ErrorCount = & $count 'Error'
            InvestigateCount = & $count 'Investigate'
            SkippedCount = & $count 'Skipped'
            NotRunCount = & $count 'NotRun'
            TotalCount = $Tests.Count
            ExecutedAt = '2026-09-06T00:00:00.0000000+00:00'
            TenantId = '11111111-1111-4111-8111-111111111111'
            TenantName = 'Fixture tenant'
            CurrentVersion = '2.0.0'
            Tests = @($Tests)
            Blocks = @()
            EndOfJson = 'EndOfJson'
            OutputFiles = @()
        }
        foreach ($key in $Override.Keys) { $report[$key] = $Override[$key] }
        return $report
    }

    function Write-FixtureReport {
        param([Parameter(Mandatory = $true)][object]$Report, [Parameter(Mandatory = $true)][string]$Name)
        $path = Join-Path $TestDrive $Name
        [System.IO.File]::WriteAllText($path, ($Report | ConvertTo-Json -Depth 12), [System.Text.UTF8Encoding]::new($false))
        return $path
    }

    function ConvertTo-Document {
        param([Parameter(Mandatory = $true)][object]$Report, [string]$AssetId = 'asset-fixture')
        $path = Write-FixtureReport -Report $Report -Name ("report-{0}.json" -f [guid]::NewGuid())
        return ConvertTo-ManagedMaesterDocument -Report (Read-MaesterReport -LiteralPath $path) -AssetId $AssetId
    }

    function ConvertFrom-JsonRoundTrip {
        param([Parameter(Mandatory = $true)][object]$Value)
        return $Value | ConvertTo-Json -Depth 12 | ConvertFrom-Json -Depth 32
    }
}

Describe 'run-maester.ps1 as a dot-sourced library' {
    It 'exposes the managed run and its parts without starting the run' {
        foreach ($name in @('Read-BoundedJson', 'Get-BoundTenant', 'ConvertTo-SafeText', 'Write-AtomicJson', 'Read-MaesterReport', 'ConvertTo-ManagedMaesterDocument', 'Invoke-ManagedMaesterRun')) {
            (Get-Command -Name $name -CommandType Function -ErrorAction Stop).Name | Should -Be $name
        }
    }
}

Describe 'Graph sign-in' {
    It 'passes Connect-MgGraph only parameters the pinned module accepts with an access token' {
        Import-Module Microsoft.Graph.Authentication -RequiredVersion '2.27.0' -ErrorAction Stop
        $accepted = ((Get-Command Connect-MgGraph).ParameterSets | Where-Object Name -eq 'AccessTokenParameterSet').Parameters.Name
        $script = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'run-maester.ps1'), [ref]$null, [ref]$null)
        $calls = @($script.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Connect-MgGraph' }, $true))
        $calls.Count | Should -Be 1
        $parameters = @($calls[0].CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object ParameterName)
        $parameters | Should -Contain 'AccessToken'
        foreach ($parameter in $parameters) { $accepted | Should -Contain $parameter }
    }
}

Describe 'ConvertTo-ManagedMaesterDocument verdicts' {
    BeforeAll {
        $everyVerdict = New-MaesterReport -Tests @(
            (New-MaesterTest -Id 'MT.1001' -Result 'Passed' -Severity 'High')
            (New-MaesterTest -Id 'MT.1002' -Result 'Failed' -Severity 'Critical')
            (New-MaesterTest -Id 'MT.1003' -Result 'Investigate' -Severity 'Medium' -ResultDetail @{
                TestResult = 'Manual review required for this control.'
            })
            (New-MaesterTest -Id 'MT.1004' -Result 'Skipped' -Severity 'Low')
            (New-MaesterTest -Id 'MT.1005' -Result 'NotRun')
            (New-MaesterTest -Id 'MT.1006' -Result 'Error' -Severity 'High')
            (New-MaesterTest -Id 'MT.1007' -Result 'Inconclusive' -Severity 'Info')
        )
        $document = ConvertTo-Document -Report $everyVerdict
    }

    It 'carries exactly the reviewed verdicts into results, in report order' {
        @($document.Results | ForEach-Object { $_.Id }) | Should -Be @('MT.1001', 'MT.1002', 'MT.1003')
    }

    It 'maps Passed to Pass and preserves Failed and Investigate as distinct source verdicts' {
        $rows = @($document.Results)
        @($rows | ForEach-Object { $_.Result }) | Should -Be @('Pass', 'Failed', 'Investigate')
        @($rows | ForEach-Object { $_.SourceResult }) | Should -Be @('Passed', 'Failed', 'Investigate')
    }

    It 'carries the upstream manual-review detail only for Investigate rows' {
        $rows = @($document.Results)
        $rows[0].ReviewDetail | Should -Be ''
        $rows[1].ReviewDetail | Should -Be ''
        $rows[2].ReviewDetail | Should -Be 'Manual review required for this control.'
    }

    It 'drops Skipped, NotRun, Error, and Inconclusive tests from results' {
        $ids = @($document.Results | ForEach-Object { $_.Id })
        foreach ($dropped in @('MT.1004', 'MT.1005', 'MT.1006', 'MT.1007')) { $ids | Should -Not -Contain $dropped }
    }

    It 'copies every counter Maester reported rather than recounting' {
        $diagnostics = $document.Diagnostics
        $diagnostics.passes | Should -Be 1
        $diagnostics.failures | Should -Be 1
        $diagnostics.investigate | Should -Be 1
        $diagnostics.errors | Should -Be 1
        $diagnostics.skipped | Should -Be 1
        $diagnostics.not_run | Should -Be 1
        $diagnostics.normalized_results | Should -Be 3
    }

    It 'carries TotalCount verbatim so a test outside every category stays visible to the host' {
        # Maester counts an Inconclusive test in TotalCount and in no other
        # counter. The wrapper does not repair that; it carries the total so the
        # host can report the one test nobody accounted for.
        $diagnostics = $document.Diagnostics
        $diagnostics.total | Should -Be 7
        ($diagnostics.passes + $diagnostics.failures + $diagnostics.investigate + $diagnostics.errors + $diagnostics.skipped + $diagnostics.not_run) | Should -Be 6
    }

    It 'stores counters as integers even when the report carries them as strings' {
        $stringCounts = New-MaesterReport -Tests @((New-MaesterTest -Id 'MT.1001' -Result 'Passed')) -Override @{ PassedCount = '1'; TotalCount = '1' }
        $diagnostics = (ConvertTo-Document -Report $stringCounts).Diagnostics
        $diagnostics.passes | Should -BeOfType [int]
        $diagnostics.total | Should -BeOfType [int]
        $diagnostics.total | Should -Be 1
    }

    It 'produces an empty result list, not a missing one, when no reviewed verdict is present' {
        $nothingReviewed = New-MaesterReport -Tests @(
            (New-MaesterTest -Id 'MT.1004' -Result 'Skipped')
            (New-MaesterTest -Id 'MT.1006' -Result 'Error')
        )
        $document = ConvertTo-Document -Report $nothingReviewed
        @($document.Results).Count | Should -Be 0
        $document.Diagnostics.normalized_results | Should -Be 0
        $document.Diagnostics.total | Should -Be 2
        $document.Diagnostics.errors | Should -Be 1
        ($document | ConvertTo-Json -Depth 12) | Should -Match '"Results":\s*\[\s*\]'
    }

    It 'leaves a renamed verdict out of results instead of guessing, while its counter still shows' {
        # PowerShell's switch is case-insensitive, so only a real rename such
        # as Passed -> Pass reaches the default arm.
        $renamed = New-MaesterReport -Tests @((New-MaesterTest -Id 'MT.1001' -Result 'Pass')) -Override @{ PassedCount = 1 }
        $document = ConvertTo-Document -Report $renamed
        @($document.Results).Count | Should -Be 0
        $document.Diagnostics.passes | Should -Be 1
        $document.Diagnostics.normalized_results | Should -Be 0
    }
}

Describe 'ConvertTo-ManagedMaesterDocument severity' {
    BeforeAll {
        $severityCases = @(
            @{ Id = 'MT.2001'; Severity = 'critical'; Expected = 'critical'; Source = 'critical' }
            @{ Id = 'MT.2002'; Severity = 'HIGH'; Expected = 'high'; Source = 'HIGH' }
            @{ Id = 'MT.2003'; Severity = 'Medium'; Expected = 'medium'; Source = 'Medium' }
            @{ Id = 'MT.2004'; Severity = 'low'; Expected = 'low'; Source = 'low' }
            @{ Id = 'MT.2005'; Severity = 'Info'; Expected = 'informational'; Source = 'Info' }
            @{ Id = 'MT.2006'; Severity = 'Informational'; Expected = 'unknown'; Source = 'Informational' }
            @{ Id = 'MT.2007'; Severity = 'Moderate'; Expected = 'unknown'; Source = 'Moderate' }
            @{ Id = 'MT.2008'; Severity = ''; Expected = 'unknown'; Source = '' }
            @{ Id = 'MT.2009'; Severity = $null; Expected = 'unknown'; Source = '' }
            @{ Id = 'MT.2010'; Severity = 3; Expected = 'unknown'; Source = '3' }
        )
        $tests = @($severityCases | ForEach-Object { New-MaesterTest -Id $_.Id -Result 'Passed' -Severity $_.Severity })
        $tests += New-MaesterTest -Id 'MT.2011' -Result 'Passed' -OmitSeverity
        $severityRows = @{}
        foreach ($row in (ConvertTo-Document -Report (New-MaesterReport -Tests $tests)).Results) { $severityRows[$row.Id] = $row }
    }

    It 'maps the reviewed rating <Severity> of <Id> to <Expected> and keeps the source text' -ForEach @(
        @{ Id = 'MT.2001'; Severity = 'critical'; Expected = 'critical'; Source = 'critical' }
        @{ Id = 'MT.2002'; Severity = 'HIGH'; Expected = 'high'; Source = 'HIGH' }
        @{ Id = 'MT.2003'; Severity = 'Medium'; Expected = 'medium'; Source = 'Medium' }
        @{ Id = 'MT.2004'; Severity = 'low'; Expected = 'low'; Source = 'low' }
        @{ Id = 'MT.2005'; Severity = 'Info'; Expected = 'informational'; Source = 'Info' }
    ) {
        $severityRows[$Id].Severity | Should -Be $Expected
        $severityRows[$Id].SourceSeverity | Should -Be $Source
    }

    It 'leaves the unreviewed rating <Severity> of <Id> unknown without discarding the source text' -ForEach @(
        @{ Id = 'MT.2006'; Severity = 'Informational'; Expected = 'unknown'; Source = 'Informational' }
        @{ Id = 'MT.2007'; Severity = 'Moderate'; Expected = 'unknown'; Source = 'Moderate' }
        @{ Id = 'MT.2008'; Severity = ''; Expected = 'unknown'; Source = '' }
        @{ Id = 'MT.2009'; Severity = $null; Expected = 'unknown'; Source = '' }
        @{ Id = 'MT.2010'; Severity = 3; Expected = 'unknown'; Source = '3' }
    ) {
        $severityRows[$Id].Severity | Should -Be $Expected
        $severityRows[$Id].SourceSeverity | Should -Be $Source
    }

    It 'treats a test without any Severity property as unknown' {
        $severityRows['MT.2011'].Severity | Should -Be 'unknown'
        $severityRows['MT.2011'].SourceSeverity | Should -Be ''
    }

    It 'covers every case listed for this suite' {
        $severityRows.Count | Should -Be ($severityCases.Count + 1)
    }
}

Describe 'ConvertTo-ManagedMaesterDocument text safety' {
    It 'strips markup, decodes entities, removes control characters, and collapses whitespace in titles' {
        $report = New-MaesterReport -Tests @(
            (New-MaesterTest -Id 'MT.3001' -Result 'Failed' -Title "<b>Privileged</b> accounts &amp; guests   need`tMFA`u{7}")
        )
        (ConvertTo-Document -Report $report).Results[0].Title | Should -Be 'Privileged accounts & guests need MFA'
    }

    It 'bounds identifier, title, and help link lengths' {
        $report = New-MaesterReport -Tests @(
            (New-MaesterTest -Id ('I' * 300) -Result 'Failed' -Title ('T' * 5000) -HelpUrl ('https://maester.dev/' + ('u' * 2100)))
        )
        $row = (ConvertTo-Document -Report $report).Results[0]
        $row.Id.Length | Should -Be 256
        $row.Title.Length | Should -Be 4096
        $row.HelpUrl.Length | Should -Be 2048
    }

    It 'turns a missing help link into an empty string rather than a null' {
        $report = New-MaesterReport -Tests @((New-MaesterTest -Id 'MT.3002' -Result 'Passed' -HelpUrl $null))
        (ConvertTo-Document -Report $report).Results[0].HelpUrl | Should -Be ''
    }

    It 'cleans and bounds the Investigate review detail from ResultDetail.TestResult' {
        $report = New-MaesterReport -Tests @(
            (New-MaesterTest -Id 'MT.3003' -Result 'Investigate' -ResultDetail @{
                TestDescription = 'Not copied into the managed row.'
                TestResult = ("<b>Manual</b> review &amp; confirm`taccess`u{7} " + ('R' * 5000))
            })
        )
        $detail = (ConvertTo-Document -Report $report).Results[0].ReviewDetail
        $detail | Should -Match '^Manual review & confirm access R+$'
        $detail | Should -Not -Match '[<>\x00-\x1F\x7F]'
        $detail.Length | Should -Be 4096
    }

    It 'uses an empty review detail when an Investigate row has no ResultDetail.TestResult' {
        $report = New-MaesterReport -Tests @(
            (New-MaesterTest -Id 'MT.3004' -Result 'Investigate')
            (New-MaesterTest -Id 'MT.3005' -Result 'Investigate' -ResultDetail @{ TestDescription = 'Description only' })
        )
        $rows = @((ConvertTo-Document -Report $report).Results)
        $rows[0].ReviewDetail | Should -Be ''
        $rows[1].ReviewDetail | Should -Be ''
    }
}

Describe 'ConvertTo-ManagedMaesterDocument envelope' {
    BeforeAll {
        $envelope = ConvertTo-Document -Report (New-MaesterReport -Tests @((New-MaesterTest -Id 'MT.4001' -Result 'Failed' -Severity 'High'))) -AssetId 'asset-42'
    }

    It 'writes the keys the host adapter reads, in this order' {
        @($envelope.Keys) | Should -Be @('schema_version', 'Engine', 'Product', 'asset_id', 'Provenance', 'Diagnostics', 'Results')
        @($envelope.Provenance.Keys) | Should -Be @('engine_version', 'source_revision', 'profile', 'test_path', 'excluded_tags', 'include_long_running', 'include_preview', 'telemetry', 'version_check', 'raw_report')
        @($envelope.Diagnostics.Keys) | Should -Be @('passes', 'failures', 'investigate', 'errors', 'skipped', 'not_run', 'total', 'normalized_results')
        @($envelope.Results[0].Keys) | Should -Be @('Id', 'Title', 'Result', 'SourceResult', 'ReviewDetail', 'SourceSeverity', 'Severity', 'Service', 'asset_id', 'HelpUrl')
    }

    It 'binds the document and every row to the scoped asset' {
        $envelope.asset_id | Should -Be 'asset-42'
        $envelope.Results[0].asset_id | Should -Be 'asset-42'
        $envelope.Results[0].Service | Should -Be 'Microsoft Entra ID'
    }

    It 'declares the pinned engine, profile, and raw report location' {
        $envelope.schema_version | Should -Be '1.0.0'
        $envelope.Engine | Should -Be 'Maester'
        $envelope.Product | Should -Be 'Microsoft Entra ID'
        $envelope.Provenance.engine_version | Should -Be '2.3.0'
        $envelope.Provenance.source_revision | Should -Be '7413c42d3fcc724dfea94d2726e690ddd364d914'
        $envelope.Provenance.profile | Should -Be 'entra-graph-token'
        $envelope.Provenance.test_path | Should -Be '/opt/ai-security-scanner/maester-tests/Maester/Entra'
        @($envelope.Provenance.excluded_tags) | Should -Be @('MT.1025', 'MT.1026', 'MT.1027', 'MT.1028', 'MT.1030', 'MT.1031', 'MT.1182')
        $envelope.Provenance.raw_report | Should -Be 'upstream/maester-raw.json'
        foreach ($flag in @('include_long_running', 'include_preview', 'telemetry', 'version_check')) {
            $envelope.Provenance[$flag] | Should -BeFalse
        }
    }

    It 'survives the JSON round trip the host performs' {
        $written = Join-Path $TestDrive 'envelope.json'
        Write-AtomicJson -Value $envelope -LiteralPath $written
        $read = Get-Content -LiteralPath $written -Raw | ConvertFrom-Json -Depth 32
        $read.Diagnostics.total | Should -Be 1
        $read.Diagnostics.normalized_results | Should -Be 1
        @($read.Results).Count | Should -Be 1
        $read.Results[0].Severity | Should -Be 'high'
        $read.Results[0].SourceSeverity | Should -Be 'High'
    }
}

Describe 'Read-MaesterReport' {
    It 'returns a report that ends with the EndOfJson marker' {
        $path = Write-FixtureReport -Report (New-MaesterReport -Tests @((New-MaesterTest -Id 'MT.5001' -Result 'Passed'))) -Name 'complete.json'
        (Read-MaesterReport -LiteralPath $path).TotalCount | Should -Be 1
    }

    It 'rejects a report whose EndOfJson marker was cut off' {
        $path = Write-FixtureReport -Report (New-MaesterReport -Tests @() -Override @{ EndOfJson = 'EndOfJs' }) -Name 'truncated.json'
        { Read-MaesterReport -LiteralPath $path } | Should -Throw 'Maester JSON result is incomplete.'
    }

    It 'rejects a report without the marker at all' {
        $report = New-MaesterReport -Tests @()
        $report.Remove('EndOfJson')
        $path = Write-FixtureReport -Report $report -Name 'unmarked.json'
        { Read-MaesterReport -LiteralPath $path } | Should -Throw
    }

    It 'rejects a symbolic link in place of the report' {
        $target = Write-FixtureReport -Report (New-MaesterReport -Tests @()) -Name 'link-target.json'
        $link = Join-Path $TestDrive 'linked.json'
        $null = New-Item -ItemType SymbolicLink -Path $link -Target $target
        { Read-MaesterReport -LiteralPath $link } | Should -Throw 'Maester JSON result exceeds the managed artifact limit.'
    }

    It 'rejects a report above the 16 MiB artifact limit before parsing it' {
        $path = Join-Path $TestDrive 'oversize.json'
        $stream = [System.IO.File]::Create($path)
        try { $stream.SetLength(16777217) } finally { $stream.Dispose() }
        { Read-MaesterReport -LiteralPath $path } | Should -Throw 'Maester JSON result exceeds the managed artifact limit.'
    }

    It 'rejects a missing report' {
        { Read-MaesterReport -LiteralPath (Join-Path $TestDrive 'absent.json') } | Should -Throw
    }
}

Describe 'Get-BoundTenant' {
    BeforeAll {
        function New-Scope {
            param([object[]]$Identifiers, [string]$EngineId = 'maester', [string]$Provider = 'microsoft365', [string]$Kind = 'tenant', [int]$AssetCount = 1)
            $asset = [ordered]@{ id = 'asset-1'; name = 'Fixture tenant'; kind = $Kind; provider = $Provider; identifiers = @($Identifiers); grants = @() }
            $assets = @(1..$AssetCount | ForEach-Object { $asset })
            return ConvertFrom-JsonRoundTrip -Value ([ordered]@{ schema_version = '1'; engine_id = $EngineId; assets = $assets })
        }
        $tenantId = '11111111-1111-4111-8111-111111111111'
    }

    It 'binds the asset and tenant from the microsoft365_tenant_id namespace' {
        $binding = Get-BoundTenant -Scope (New-Scope -Identifiers @(@{ namespace = 'microsoft365_tenant_id'; value = $tenantId }))
        $binding.AssetId | Should -Be 'asset-1'
        $binding.TenantId | Should -Be $tenantId
    }

    It 'accepts the microsoft_tenant_id namespace as well' {
        (Get-BoundTenant -Scope (New-Scope -Identifiers @(@{ namespace = 'microsoft_tenant_id'; value = $tenantId }))).TenantId | Should -Be $tenantId
    }

    It 'treats the same tenant under both namespaces as one tenant' {
        $scope = New-Scope -Identifiers @(
            @{ namespace = 'microsoft_tenant_id'; value = $tenantId }
            @{ namespace = 'microsoft365_tenant_id'; value = $tenantId }
        )
        (Get-BoundTenant -Scope $scope).TenantId | Should -Be $tenantId
    }

    It 'rejects two different tenant identifiers' {
        $scope = New-Scope -Identifiers @(
            @{ namespace = 'microsoft_tenant_id'; value = $tenantId }
            @{ namespace = 'microsoft365_tenant_id'; value = '22222222-2222-4222-8222-222222222222' }
        )
        { Get-BoundTenant -Scope $scope } | Should -Throw 'Scope does not contain exactly one Microsoft tenant identifier.'
    }

    It 'rejects a tenant identifier that is not a GUID' {
        { Get-BoundTenant -Scope (New-Scope -Identifiers @(@{ namespace = 'microsoft365_tenant_id'; value = 'contoso.onmicrosoft.com' })) } | Should -Throw 'Scope does not contain exactly one Microsoft tenant identifier.'
    }

    It 'ignores identifiers in unrelated namespaces' {
        { Get-BoundTenant -Scope (New-Scope -Identifiers @(@{ namespace = 'aws_account_id'; value = $tenantId })) } | Should -Throw 'Scope does not contain exactly one Microsoft tenant identifier.'
    }

    It 'rejects a scope bound to another engine' {
        { Get-BoundTenant -Scope (New-Scope -EngineId 'scubagear' -Identifiers @(@{ namespace = 'microsoft365_tenant_id'; value = $tenantId })) } | Should -Throw 'Scope is not bound to the Maester managed profile.'
    }

    It 'rejects a scope with more than one asset' {
        { Get-BoundTenant -Scope (New-Scope -AssetCount 2 -Identifiers @(@{ namespace = 'microsoft365_tenant_id'; value = $tenantId })) } | Should -Throw 'Scope is not bound to the Maester managed profile.'
    }

    It 'rejects an asset that is not a Microsoft 365 tenant' {
        { Get-BoundTenant -Scope (New-Scope -Provider 'aws' -Kind 'account' -Identifiers @(@{ namespace = 'microsoft365_tenant_id'; value = $tenantId })) } | Should -Throw 'Scope does not contain one Microsoft 365 tenant.'
    }
}

Describe 'ConvertTo-SafeText' {
    It 'returns an empty string for null' {
        ConvertTo-SafeText -Value $null | Should -Be ''
    }

    It 'applies the caller-supplied length bound after cleaning' {
        ConvertTo-SafeText -Value ('  <i>abc</i>def  ') -MaximumLength 4 | Should -Be 'abc '
    }
}

Describe 'Write-AtomicJson' {
    It 'writes UTF-8 without a byte-order mark and ends the file with one newline' {
        $path = Join-Path $TestDrive 'atomic.json'
        Write-AtomicJson -Value ([ordered]@{ a = 1 }) -LiteralPath $path
        $bytes = [System.IO.File]::ReadAllBytes($path)
        ($bytes[0..2] -join ',') | Should -Not -Be '239,187,191'
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        $text | Should -Match "\}`n$"
        $text | Should -Not -Match "`n`n$"
        ($text | ConvertFrom-Json).a | Should -Be 1
    }

    It 'leaves no temporary file behind' {
        $path = Join-Path $TestDrive 'clean.json'
        Write-AtomicJson -Value ([ordered]@{ a = 1 }) -LiteralPath $path
        @(Get-ChildItem -LiteralPath $TestDrive -Force -Filter '.maester-*.tmp') | Should -BeNullOrEmpty
    }

    It 'refuses to overwrite an existing result and keeps its content' {
        $path = Join-Path $TestDrive 'existing.json'
        Write-AtomicJson -Value ([ordered]@{ first = $true }) -LiteralPath $path
        { Write-AtomicJson -Value ([ordered]@{ second = $true }) -LiteralPath $path } | Should -Throw 'Managed result path already exists.'
        (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).first | Should -BeTrue
    }
}

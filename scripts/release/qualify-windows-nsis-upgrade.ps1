param(
  [Parameter(Mandatory = $true)][string]$ArtifactDirectory,
  [Parameter(Mandatory = $true)][string]$WorkDirectory,
  [Parameter(Mandatory = $true)][string]$CurrentVersion
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$candidateVersion = "0.1.10"
$priorVersion = "0.1.9"
$priorTag = "v0.1.9"
$priorInstallerName = "ai-security-scanner_0.1.9_x64-setup.exe"
$priorInstallerBytes = 40186968
$priorInstallerSha256 = "f7b5374fff07fca98af06931b2dc0ebc52abc2b3ac5a70a6602001d03a1a065e"
$priorInstallerUrl = "https://github.com/TED-H-com/ai-security-scanner/releases/download/v0.1.9/ai-security-scanner_0.1.9_x64-setup.exe"
$priorRuntimeManifestSha256 = "a8112473e5d87655e6145ea5f6cff569c872329d2ec14bfb9463078abcb60e3a"
$priorMachineImageSha256 = "e2b6cbcadd8b41b708fecb58a246a20d737dee0ef26872a3f75b575f77eba968"
$maximumPriorDownloadBytes = 64 * 1024 * 1024
$maximumDataSnapshotBytes = 512 * 1024 * 1024
$maximumDataSnapshotFiles = 4096
$processLeaseRelativePath = ".exclusive-process.lock"
$existingExportIdentityFixtureSha256 = "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
$emptyFileSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

if ($null -eq ("NsisUpgradeQualificationNativeMethods" -as [type])) {
  Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using Microsoft.Win32.SafeHandles;

public static class NsisUpgradeQualificationNativeMethods {
    public const uint GENERIC_READ = 0x80000000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out NsisUpgradeQualificationByHandleFileInformation information);
}

[StructLayout(LayoutKind.Sequential)]
public struct NsisUpgradeQualificationByHandleFileInformation {
    public uint FileAttributes;
    public FILETIME CreationTime;
    public FILETIME LastAccessTime;
    public FILETIME LastWriteTime;
    public uint VolumeSerialNumber;
    public uint FileSizeHigh;
    public uint FileSizeLow;
    public uint NumberOfLinks;
    public uint FileIndexHigh;
    public uint FileIndexLow;
}
"@
}

function Assert-ExactChildPath([string]$Parent, [string]$Child, [string]$ExpectedName, [string]$Label) {
  $parentPath = [IO.Path]::GetFullPath($Parent)
  $childPath = [IO.Path]::GetFullPath($Child)
  if (-not [String]::Equals(
      [IO.Path]::GetDirectoryName($childPath),
      $parentPath,
      [StringComparison]::OrdinalIgnoreCase
    ) -or -not [String]::Equals(
      [IO.Path]::GetFileName($childPath),
      $ExpectedName,
      [StringComparison]::Ordinal
    )) {
    throw "$Label escaped its fixed parent or changed its fixed name."
  }
  return $childPath
}

function Test-ExactChildEntryExists([string]$Parent, [string]$ExpectedName) {
  return @(
    Get-ChildItem -LiteralPath $Parent -Force |
      Where-Object { [String]::Equals($_.Name, $ExpectedName, [StringComparison]::OrdinalIgnoreCase) }
  ).Count -ne 0
}

function Get-OpenFileIdentity([IO.FileStream]$Stream) {
  $information = [NsisUpgradeQualificationByHandleFileInformation]::new()
  if (-not [NsisUpgradeQualificationNativeMethods]::GetFileInformationByHandle($Stream.SafeFileHandle, [ref]$information)) {
    throw "Could not inspect the exact data-preservation fixture file handle."
  }
  return [ordered]@{
    attributes = [uint32]$information.FileAttributes
    links = [uint32]$information.NumberOfLinks
    bytes = (([uint64]$information.FileSizeHigh -shl 32) -bor [uint64]$information.FileSizeLow)
    volume = [uint32]$information.VolumeSerialNumber
    index = (([uint64]$information.FileIndexHigh -shl 32) -bor [uint64]$information.FileIndexLow)
  }
}

function Get-VerbatimWindowsPath([string]$Path, [string]$Label) {
  if ([String]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathFullyQualified($Path)) {
    throw "$Label is not an absolute Windows path."
  }
  $full = [IO.Path]::GetFullPath($Path)
  if ($full.StartsWith("\\?\", [StringComparison]::Ordinal)) { return $full }
  if ($full.StartsWith("\\", [StringComparison]::Ordinal)) {
    return "\\?\UNC\" + $full.Substring(2)
  }
  return "\\?\" + $full
}

function Open-NoFollowSingleLinkFile(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = [uint64]::MaxValue
) {
  $verbatimPath = Get-VerbatimWindowsPath $Path $Label
  $handle = [NsisUpgradeQualificationNativeMethods]::CreateFileW(
    $verbatimPath,
    [NsisUpgradeQualificationNativeMethods]::GENERIC_READ,
    [NsisUpgradeQualificationNativeMethods]::FILE_SHARE_READ,
    [IntPtr]::Zero,
    [NsisUpgradeQualificationNativeMethods]::OPEN_EXISTING,
    [NsisUpgradeQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT,
    [IntPtr]::Zero
  )
  if ($null -eq $handle -or $handle.IsInvalid) {
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($null -ne $handle) { $handle.Dispose() }
    throw [ComponentModel.Win32Exception]::new($errorCode, "$Label could not be opened without following reparse points")
  }
  try {
    $stream = [IO.FileStream]::new($handle, [IO.FileAccess]::Read, 4096, $false)
  } catch {
    $handle.Dispose()
    throw
  }
  try {
    $identity = Get-OpenFileIdentity $stream
    if (($identity.attributes -band [uint32][IO.FileAttributes]::Directory) -ne 0 -or
        ($identity.attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $identity.links -ne 1 -or $identity.bytes -lt 1 -or $identity.bytes -gt $MaximumBytes) {
      throw "$Label is not one bounded no-follow single-link regular file."
    }
    return ,$stream
  } catch {
    $stream.Dispose()
    throw
  }
}

function Assert-RealFile(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = [uint64]::MaxValue
) {
  $stream = Open-NoFollowSingleLinkFile $Path $Label $MaximumBytes
  try { $identity = Get-OpenFileIdentity $stream }
  finally { $stream.Dispose() }
  return [PSCustomObject]@{
    FullName = [IO.Path]::GetFullPath($Path)
    Length = [int64]$identity.bytes
  }
}

function Assert-RealDirectory([string]$Path, [string]$Label) {
  $item = Get-Item -LiteralPath $Path -Force
  if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Label is not one real directory."
  }
  return $item
}

function Get-NoFollowFileSha256Proof(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = 8GB
) {
  $stream = Open-NoFollowSingleLinkFile $Path $Label $MaximumBytes
  try {
    $before = Get-OpenFileIdentity $stream
    $digest = [Security.Cryptography.SHA256]::HashData($stream)
    $after = Get-OpenFileIdentity $stream
    if ($before.attributes -ne $after.attributes -or $before.links -ne $after.links -or
        $before.bytes -ne $after.bytes -or $before.volume -ne $after.volume -or
        $before.index -ne $after.index) {
      throw "$Label changed while its exact no-follow handle was hashed."
    }
    return [PSCustomObject]@{
      FullName = [IO.Path]::GetFullPath($Path)
      Length = [int64]$before.bytes
      Sha256 = [Convert]::ToHexString($digest).ToLowerInvariant()
      Volume = [uint32]$before.volume
      FileIndex = [uint64]$before.index
    }
  } finally {
    $stream.Dispose()
  }
}

function Get-NoFollowEmptyFileProof([string]$Path, [string]$Label) {
  $verbatimPath = Get-VerbatimWindowsPath $Path $Label
  $handle = [NsisUpgradeQualificationNativeMethods]::CreateFileW(
    $verbatimPath,
    [NsisUpgradeQualificationNativeMethods]::GENERIC_READ,
    [NsisUpgradeQualificationNativeMethods]::FILE_SHARE_READ,
    [IntPtr]::Zero,
    [NsisUpgradeQualificationNativeMethods]::OPEN_EXISTING,
    [NsisUpgradeQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT,
    [IntPtr]::Zero
  )
  if ($null -eq $handle -or $handle.IsInvalid) {
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($null -ne $handle) { $handle.Dispose() }
    throw [ComponentModel.Win32Exception]::new($errorCode, "$Label could not be opened without following reparse points")
  }
  try { $stream = [IO.FileStream]::new($handle, [IO.FileAccess]::Read, 1, $false) }
  catch { $handle.Dispose(); throw }
  try {
    $before = Get-OpenFileIdentity $stream
    $after = Get-OpenFileIdentity $stream
    if (($before.attributes -band [uint32][IO.FileAttributes]::Directory) -ne 0 -or
        ($before.attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $before.links -ne 1 -or $before.bytes -ne 0 -or
        $before.attributes -ne $after.attributes -or $before.links -ne $after.links -or
        $before.bytes -ne $after.bytes -or $before.volume -ne $after.volume -or
        $before.index -ne $after.index) {
      throw "$Label is not one stable empty no-follow single-link file."
    }
    return [PSCustomObject]@{
      FullName = [IO.Path]::GetFullPath($Path)
      Length = [int64]0
      Sha256 = $emptyFileSha256
      Volume = [uint32]$before.volume
      FileIndex = [uint64]$before.index
    }
  } finally { $stream.Dispose() }
}

function Get-LowerSha256([string]$Path, [uint64]$MaximumBytes = 8GB) {
  return (Get-NoFollowFileSha256Proof $Path "SHA-256 input" $MaximumBytes).Sha256
}

function Assert-SameFileProof([object]$Expected, [object]$Actual, [string]$Label) {
  if ($Expected.Length -ne $Actual.Length -or
      $Expected.Sha256 -cne $Actual.Sha256 -or
      $Expected.Volume -ne $Actual.Volume -or
      $Expected.FileIndex -ne $Actual.FileIndex -or
      -not [String]::Equals(
        (Get-VerbatimWindowsPath ([string]$Expected.FullName) "$Label expected path"),
        (Get-VerbatimWindowsPath ([string]$Actual.FullName) "$Label actual path"),
        [StringComparison]::OrdinalIgnoreCase
      )) {
    throw "$Label changed file bytes or NTFS identity."
  }
}

function Convert-FileProofObservation([object]$Proof) {
  return [ordered]@{
    length = [int64]$Proof.Length
    sha256 = [string]$Proof.Sha256
    volume = [uint32]$Proof.Volume
    fileIndex = ([uint64]$Proof.FileIndex).ToString([Globalization.CultureInfo]::InvariantCulture)
  }
}

function Assert-CanonicalUuid([string]$Value, [string]$Label) {
  if ($Value -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
    throw "$Label is not a canonical lowercase UUID."
  }
}

function Assert-ExactJsonProperties([object]$Value, [string[]]$ExpectedNames, [string]$Label) {
  $actual = @($Value.PSObject.Properties.Name | Sort-Object)
  $expected = @($ExpectedNames | Sort-Object)
  if (($actual -join "`n") -cne ($expected -join "`n")) {
    throw "$Label has unexpected or missing JSON properties."
  }
}

function Assert-HtmlExportReceipt(
  [object]$Receipt,
  [string]$ExpectedCaseId,
  [string]$ExpectedRunId,
  [string]$ExpectedDestination,
  [object]$IndependentProof,
  [string]$Label
) {
  Assert-ExactJsonProperties $Receipt @(
    "id", "case_id", "run_id", "created_at", "format", "path", "sha256",
    "coverage_manifest_path", "coverage_manifest_sha256", "signature", "public_key",
    "redaction_profile", "raw_artifacts_included", "raw_artifacts_omitted",
    "integrity_only_notice"
  ) $Label
  Assert-CanonicalUuid ([string]$Receipt.id) "$Label export ID"
  Assert-CanonicalUuid ([string]$Receipt.case_id) "$Label case ID"
  Assert-CanonicalUuid ([string]$Receipt.run_id) "$Label run ID"
  if ([string]$Receipt.case_id -cne $ExpectedCaseId -or
      [string]$Receipt.run_id -cne $ExpectedRunId) {
    throw "$Label is for the wrong case or scan run."
  }
  if ([string]$Receipt.format -cne "html") {
    throw "$Label is not an HTML export receipt."
  }
  if (-not [String]::Equals(
      (Get-VerbatimWindowsPath ([string]$Receipt.path) "$Label receipt path"),
      (Get-VerbatimWindowsPath $ExpectedDestination "$Label expected destination"),
      [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "$Label does not name the selected Windows destination."
  }
  $receiptPathProof = Get-NoFollowFileSha256Proof ([string]$Receipt.path) (
    "$Label receipt-path file"
  ) (16 * 1024 * 1024)
  Assert-SameFileProof $IndependentProof $receiptPathProof "$Label receipt-path file"
  if ([string]$Receipt.sha256 -cne [string]$IndependentProof.Sha256) {
    throw "$Label SHA-256 does not bind the exact HTML bytes."
  }
  if ($null -ne $Receipt.signature -or $null -ne $Receipt.public_key) {
    throw "$Label unexpectedly claims a signature."
  }
  if ($null -ne $Receipt.coverage_manifest_path -or
      $null -ne $Receipt.coverage_manifest_sha256) {
    throw "$Label unexpectedly claims a coverage sidecar."
  }
  if ([string]$Receipt.redaction_profile -cne "standard" -or
      [int]$Receipt.raw_artifacts_included -ne 0) {
    throw "$Label does not preserve the standard no-raw-evidence export contract."
  }
  if ([String]::IsNullOrWhiteSpace([string]$Receipt.integrity_only_notice)) {
    throw "$Label omits the unsigned integrity-only notice."
  }
}

function Read-BoundedUtf8File([string]$Path, [string]$Label, [uint64]$MaximumBytes = 64 * 1024) {
  $stream = Open-NoFollowSingleLinkFile $Path $Label $MaximumBytes
  try {
    $before = Get-OpenFileIdentity $stream
    [byte[]]$bytes = [byte[]]::new([int]$before.bytes)
    $offset = 0
    while ($offset -lt $bytes.Length) {
      $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
      if ($read -eq 0) { throw "$Label ended before its inspected byte length." }
      $offset += $read
    }
    $after = Get-OpenFileIdentity $stream
    if ($before.attributes -ne $after.attributes -or $before.links -ne $after.links -or
        $before.bytes -ne $after.bytes -or $before.volume -ne $after.volume -or
        $before.index -ne $after.index) {
      throw "$Label changed while its exact handle was read."
    }
    return [PSCustomObject]@{
      Text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
      Length = [int64]$before.bytes
    }
  } catch {
    throw "$Label is not one stable bounded UTF-8 file: $($_.Exception.Message)"
  } finally {
    $stream.Dispose()
  }
}

function Read-BoundedJsonFile([string]$Path, [string]$Label, [uint64]$MaximumBytes = 64 * 1024) {
  $record = Read-BoundedUtf8File $Path $Label $MaximumBytes
  try {
    return $record.Text | ConvertFrom-Json -DateKind String
  } catch {
    throw "$Label is not one stable bounded UTF-8 JSON document: $($_.Exception.Message)"
  }
}

function Invoke-ExactProcess(
  [string]$FileName,
  [string[]]$Arguments,
  [int]$TimeoutMilliseconds,
  [string]$Label,
  [bool]$CaptureOutput = $false,
  [object]$ExpectedExecutableProof = $null,
  [switch]$AllowRestartRequired,
  [string]$RawFinalNsisUninstallDirectory = ""
) {
  if ($TimeoutMilliseconds -lt 1000 -or $TimeoutMilliseconds -gt 900000) {
    throw "$Label timeout is outside its fixed bound."
  }
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $FileName
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $CaptureOutput
  $startInfo.RedirectStandardError = $CaptureOutput
  if ([String]::IsNullOrEmpty($RawFinalNsisUninstallDirectory)) {
    foreach ($argument in $Arguments) {
      $startInfo.ArgumentList.Add($argument)
    }
  } else {
    if ($Arguments.Count -ne 1 -or $Arguments[0] -cne "/S") {
      throw "$Label raw NSIS invocation accepts only the silent switch before its final directory."
    }
    $rawNsisDirectory = [IO.Path]::GetFullPath($RawFinalNsisUninstallDirectory)
    if (-not [IO.Path]::IsPathFullyQualified($rawNsisDirectory) -or
        -not [String]::Equals(
          $rawNsisDirectory,
          $RawFinalNsisUninstallDirectory,
          [StringComparison]::OrdinalIgnoreCase
        ) -or $rawNsisDirectory -cmatch '["\r\n]') {
      throw "$Label raw NSIS uninstall directory is not one exact quote-free full path."
    }
    # NSIS requires _?= to be the final raw, unquoted command-line tail even
    # when the directory contains spaces. ArgumentList would add quotes.
    $startInfo.Arguments = "/S _?=$rawNsisDirectory"
  }
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  try {
    $executionGuard = Open-NoFollowSingleLinkFile $FileName "$Label executable" (512 * 1024 * 1024)
    try {
      if ($null -ne $ExpectedExecutableProof) {
        foreach ($requiredProofField in @("FullName", "Length", "Sha256", "Volume", "FileIndex")) {
          if ($null -eq $ExpectedExecutableProof.PSObject.Properties[$requiredProofField]) {
            throw "$Label has an incomplete expected executable proof."
          }
        }
        if (-not [String]::Equals(
            [IO.Path]::GetFullPath($FileName),
            [string]$ExpectedExecutableProof.FullName,
            [StringComparison]::OrdinalIgnoreCase
          ) -or [int64]$ExpectedExecutableProof.Length -lt 1 -or
          [string]$ExpectedExecutableProof.Sha256 -cnotmatch '^[0-9a-f]{64}$') {
          throw "$Label has a malformed expected executable proof."
        }
        $beforeExecution = Get-OpenFileIdentity $executionGuard
        $executionGuard.Position = 0
        $executionDigest = [Security.Cryptography.SHA256]::HashData($executionGuard)
        $afterHash = Get-OpenFileIdentity $executionGuard
        if ($beforeExecution.attributes -ne $afterHash.attributes -or
            $beforeExecution.links -ne $afterHash.links -or
            $beforeExecution.bytes -ne $afterHash.bytes -or
            $beforeExecution.volume -ne $afterHash.volume -or
            $beforeExecution.index -ne $afterHash.index) {
          throw "$Label executable changed while its launch proof was hashed."
        }
        $executionSha256 = [Convert]::ToHexString($executionDigest).ToLowerInvariant()
        if ([uint64]$beforeExecution.bytes -ne [uint64]$ExpectedExecutableProof.Length -or
            [uint32]$beforeExecution.volume -ne [uint32]$ExpectedExecutableProof.Volume -or
            [uint64]$beforeExecution.index -ne [uint64]$ExpectedExecutableProof.FileIndex -or
            $executionSha256 -cne [string]$ExpectedExecutableProof.Sha256) {
          throw "$Label executable is not the exact previously verified installer."
        }
        $executionGuard.Position = 0
      }
      $started = $process.Start()
      if ($null -ne $ExpectedExecutableProof) {
        $afterStart = Get-OpenFileIdentity $executionGuard
        if ([uint64]$afterStart.bytes -ne [uint64]$ExpectedExecutableProof.Length -or
            [uint32]$afterStart.volume -ne [uint32]$ExpectedExecutableProof.Volume -or
            [uint64]$afterStart.index -ne [uint64]$ExpectedExecutableProof.FileIndex) {
          throw "$Label executable changed while the verified process was started."
        }
      }
    } finally {
      $executionGuard.Dispose()
    }
    if (-not $started) {
      throw "$Label did not start."
    }
    $stdoutTask = $null
    $stderrTask = $null
    if ($CaptureOutput) {
      $stdoutTask = $process.StandardOutput.ReadToEndAsync()
      $stderrTask = $process.StandardError.ReadToEndAsync()
    }
    if (-not $process.WaitForExit($TimeoutMilliseconds)) {
      try { $process.Kill($true) } catch {}
      $process.WaitForExit(5000) | Out-Null
      throw "$Label exceeded its fixed deadline."
    }
    $stdout = ""
    $stderr = ""
    if ($CaptureOutput) {
      if (-not [Threading.Tasks.Task]::WaitAll(@($stdoutTask, $stderrTask), 5000)) {
        throw "$Label output did not drain within its fixed deadline."
      }
      $stdout = $stdoutTask.Result
      $stderr = $stderrTask.Result
      if ([Text.Encoding]::UTF8.GetByteCount($stdout) -gt 1024 * 1024 -or
          [Text.Encoding]::UTF8.GetByteCount($stderr) -gt 1024 * 1024) {
        throw "$Label output exceeded one MiB."
      }
    }
    if ($process.ExitCode -ne 0 -and
        (-not $AllowRestartRequired -or $process.ExitCode -ne 3010)) {
      $boundedError = if ($stderr.Length -gt 2048) { $stderr.Substring(0, 2048) + " (truncated)" } else { $stderr }
      throw "$Label failed with status $($process.ExitCode): $boundedError"
    }
    return [ordered]@{ stdout = $stdout; stderr = $stderr; exitCode = $process.ExitCode }
  } finally {
    $process.Dispose()
  }
}

function Invoke-BoundedCopiedNsisUninstaller(
  [string]$SourceUninstaller,
  [string]$InstallDirectory,
  [string]$WorkRoot,
  [string]$Label
) {
  $copyName = "bounded-nsis-uninstaller-copy.exe"
  $copyPath = Assert-ExactChildPath $WorkRoot (
    Join-Path $WorkRoot $copyName
  ) $copyName "$Label execution copy"
  Assert-RealDirectory $WorkRoot "$Label work root" | Out-Null
  Assert-RealDirectory $InstallDirectory "$Label install directory" | Out-Null
  if (Test-ExactChildEntryExists $WorkRoot $copyName) {
    throw "$Label refused a pre-existing execution copy."
  }

  $sourceBefore = Get-NoFollowFileSha256Proof $SourceUninstaller "$Label source" (512 * 1024 * 1024)
  $copyProof = $null
  $result = $null
  try {
    Copy-Item -LiteralPath $SourceUninstaller -Destination $copyPath
    $sourceAfter = Get-NoFollowFileSha256Proof $SourceUninstaller "$Label source after copy" (512 * 1024 * 1024)
    Assert-SameFileProof $sourceBefore $sourceAfter "$Label source copy"
    $copyProof = Get-NoFollowFileSha256Proof $copyPath "$Label execution copy" (512 * 1024 * 1024)
    if ([int64]$copyProof.Length -ne [int64]$sourceBefore.Length -or
        [string]$copyProof.Sha256 -cne [string]$sourceBefore.Sha256) {
      throw "$Label execution copy differs from its verified source."
    }

    $result = Invoke-ExactProcess $copyPath @("/S") 180000 $Label -ExpectedExecutableProof $copyProof -RawFinalNsisUninstallDirectory $InstallDirectory
  } finally {
    if (Test-ExactChildEntryExists $WorkRoot $copyName) {
      $copyAfter = Get-NoFollowFileSha256Proof $copyPath "$Label execution copy cleanup" (512 * 1024 * 1024)
      if ($null -ne $copyProof) {
        Assert-SameFileProof $copyProof $copyAfter "$Label execution copy cleanup"
      }
      Remove-Item -LiteralPath $copyPath -Force
    }
    if (Test-ExactChildEntryExists $WorkRoot $copyName) {
      throw "$Label execution copy remains after bounded cleanup."
    }
  }
  return $result
}

function Invoke-CliJson([string]$Cli, [string[]]$Arguments, [string]$Label) {
  $result = Invoke-ExactProcess $Cli $Arguments 120000 $Label $true
  try {
    return $result.stdout | ConvertFrom-Json -DateKind String
  } catch {
    throw "$Label did not emit one valid JSON document."
  }
}

function Get-CliVersion([string]$Cli, [string]$Label) {
  $result = Invoke-ExactProcess $Cli @("--version") 30000 "$Label version probe" $true
  $value = $result.stdout.Trim()
  $match = [Text.RegularExpressions.Regex]::Match(
    $value,
    "^ai-security-scanner ([0-9]+\.[0-9]+\.[0-9]+)$",
    [Text.RegularExpressions.RegexOptions]::CultureInvariant
  )
  if (-not $match.Success) {
    throw "$Label returned an unexpected version string."
  }
  return $match.Groups[1].Value
}

function Find-OneInstalledFile([string]$InstallDirectory, [string]$Name) {
  $matches = @(
    Get-ChildItem -LiteralPath $InstallDirectory -Filter $Name -File -Recurse -Force |
      Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 }
  )
  if ($matches.Count -ne 1) {
    throw "Expected exactly one installed $Name, found $($matches.Count)."
  }
  $fullPath = [IO.Path]::GetFullPath($matches[0].FullName)
  if (-not $fullPath.StartsWith(
      [IO.Path]::GetFullPath($InstallDirectory) + [IO.Path]::DirectorySeparatorChar,
      [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "Installed $Name escaped the fixed installation directory."
  }
  Assert-RealFile $fullPath "Installed $Name" (512 * 1024 * 1024) | Out-Null
  return $fullPath
}

function Get-CurrentUserUninstallEntries {
  $root = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
  if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    return @()
  }
  $children = @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)
  if ($children.Count -gt 512) {
    throw "The current-user uninstall registry exceeded the data-preservation fixture bound."
  }
  return @(
    $children |
      ForEach-Object {
        $properties = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
        $displayNameProperty = $properties.PSObject.Properties["DisplayName"]
        if ($null -ne $displayNameProperty -and
            [String]::Equals([string]$displayNameProperty.Value, "ai-security-scanner", [StringComparison]::Ordinal)) {
          [PSCustomObject]@{
            KeyPath = $_.PSPath
            KeyName = $_.PSChildName
            DisplayName = [string]$displayNameProperty.Value
            Publisher = [string]$properties.PSObject.Properties["Publisher"].Value
            DisplayVersion = [string]$properties.PSObject.Properties["DisplayVersion"].Value
            InstallLocation = [string]$properties.PSObject.Properties["InstallLocation"].Value
            UninstallString = [string]$properties.PSObject.Properties["UninstallString"].Value
            MainBinaryName = [string]$properties.PSObject.Properties["MainBinaryName"].Value
          }
        }
      }
  )
}

function Get-OneCurrentUserUninstallEntry([string]$ExpectedVersion, [string]$InstallDirectory) {
  $entries = @(Get-CurrentUserUninstallEntries)
  if ($entries.Count -ne 1) {
    throw "Expected exactly one current-user ai-security-scanner uninstall record, found $($entries.Count)."
  }
  $entry = $entries[0]
  if (-not [String]::Equals($entry.KeyName, "ai-security-scanner", [StringComparison]::Ordinal) -or
      -not [String]::Equals($entry.DisplayName, "ai-security-scanner", [StringComparison]::Ordinal) -or
      -not [String]::Equals($entry.Publisher, "ai-security-scanner contributors", [StringComparison]::Ordinal) -or
      -not [String]::Equals($entry.MainBinaryName, "ai-security-scanner.exe", [StringComparison]::Ordinal)) {
    throw "The current-user uninstall record is not the exact product registration."
  }
  if (-not [String]::Equals($entry.DisplayVersion, $ExpectedVersion, [StringComparison]::Ordinal)) {
    throw "The current-user uninstall record has DisplayVersion $($entry.DisplayVersion), expected $ExpectedVersion."
  }
  $expectedUninstaller = Join-Path ([IO.Path]::GetFullPath($InstallDirectory)) "uninstall.exe"
  $expectedQuotedUninstallString = '"' + [IO.Path]::GetFullPath($expectedUninstaller) + '"'
  if (-not [String]::Equals(
      $entry.UninstallString,
      $expectedQuotedUninstallString,
      [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "The current-user uninstall record does not contain the exact quoted UninstallString."
  }
  $expectedQuotedInstallLocation = '"' + [IO.Path]::GetFullPath($InstallDirectory) + '"'
  if (-not [String]::Equals(
      $entry.InstallLocation,
      $expectedQuotedInstallLocation,
      [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "The current-user uninstall record does not contain the exact quoted InstallLocation."
  }
  return $entry
}

function Get-PrivateDataSnapshot([string]$Root, [switch]$ExcludeProcessLease) {
  Assert-RealDirectory $Root "Private application data root" | Out-Null
  $rootPath = [IO.Path]::GetFullPath($Root)
  $items = @(Get-ChildItem -LiteralPath $rootPath -Force -Recurse)
  if ($items.Count -gt $maximumDataSnapshotFiles * 2) {
    throw "Private application data tree exceeded its entry bound."
  }
  $files = [Collections.Generic.List[object]]::new()
  [int64]$totalBytes = 0
  foreach ($item in $items) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Private application data contains a reparse point."
    }
    $fullPath = [IO.Path]::GetFullPath($item.FullName)
    if (-not $fullPath.StartsWith($rootPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
      throw "Private application data entry escaped its exact root."
    }
    $relative = [IO.Path]::GetRelativePath($rootPath, $fullPath).Replace('\', '/')
    if ($ExcludeProcessLease -and -not $item.PSIsContainer -and
        $relative -ceq $processLeaseRelativePath) {
      Get-NoFollowEmptyFileProof $fullPath "Root process lease" | Out-Null
      continue
    }
    if (-not $item.PSIsContainer) {
      if ($files.Count -eq $maximumDataSnapshotFiles) {
        throw "Private application data exceeded its file-count bound."
      }
      $fileProof = if ([int64]$item.Length -eq 0) {
        Get-NoFollowEmptyFileProof $fullPath "Empty private application data file"
      } else {
        Get-NoFollowFileSha256Proof $fullPath "Private application data file" $maximumDataSnapshotBytes
      }
      $totalBytes += [int64]$fileProof.Length
      if ($totalBytes -gt $maximumDataSnapshotBytes) {
        throw "Private application data exceeded its byte bound."
      }
      $files.Add([ordered]@{
        path = $relative
        bytes = [int64]$fileProof.Length
        sha256 = [string]$fileProof.Sha256
      })
    }
  }
  $ordered = @($files | Sort-Object { $_.path })
  $encoded = ConvertTo-Json -InputObject $ordered -Compress -Depth 5
  $digestBytes = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($encoded))
  return [ordered]@{
    fileCount = $ordered.Count
    totalBytes = $totalBytes
    digest = [Convert]::ToHexString($digestBytes).ToLowerInvariant()
  }
}

function Download-PinnedPriorInstaller([string]$Destination) {
  $handler = [Net.Http.HttpClientHandler]::new()
  $handler.AllowAutoRedirect = $true
  $handler.MaxAutomaticRedirections = 5
  $handler.UseCookies = $false
  $client = [Net.Http.HttpClient]::new($handler)
  $client.Timeout = [TimeSpan]::FromMinutes(5)
  try {
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $priorInstallerUrl)
    $response = $client.Send($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead)
    try {
      $response.EnsureSuccessStatusCode() | Out-Null
      if ($null -ne $response.Content.Headers.ContentLength -and
          ($response.Content.Headers.ContentLength -ne $priorInstallerBytes -or
           $response.Content.Headers.ContentLength -gt $maximumPriorDownloadBytes)) {
        throw "Pinned N-1 installer Content-Length is not the checked-in release length."
      }
      $input = $response.Content.ReadAsStream()
      $output = [IO.FileStream]::new(
        $Destination,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
      )
      try {
        [byte[]]$buffer = [byte[]]::new(64 * 1024)
        [int64]$written = 0
        while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
          $written += $read
          if ($written -gt $maximumPriorDownloadBytes) {
            throw "Pinned N-1 installer download exceeded its byte bound."
          }
          $output.Write($buffer, 0, $read)
        }
        $output.Flush($true)
      } finally {
        $output.Dispose()
        $input.Dispose()
      }
    } finally {
      $response.Dispose()
      $request.Dispose()
    }
  } finally {
    $client.Dispose()
    $handler.Dispose()
  }
  $proof = Get-NoFollowFileSha256Proof $Destination "Downloaded pinned N-1 NSIS installer" $maximumPriorDownloadBytes
  if ($proof.Length -ne $priorInstallerBytes -or $proof.Sha256 -cne $priorInstallerSha256) {
    throw "Downloaded N-1 NSIS installer differs from the checked-in immutable release pin."
  }
  return $proof
}

function Remove-ExactTree([string]$Path, [string]$Parent, [string]$ExpectedName) {
  Assert-ExactChildPath $Parent $Path $ExpectedName "Cleanup tree" | Out-Null
  if (Test-Path -LiteralPath $Path) {
    Assert-RealDirectory $Path "Cleanup tree" | Out-Null
    Remove-Item -LiteralPath $Path -Recurse -Force
  }
  if (Test-Path -LiteralPath $Path) {
    throw "Exact data-preservation fixture teardown tree remains: $Path"
  }
}

$artifactRoot = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
Assert-RealDirectory $artifactRoot "Release artifact directory" | Out-Null
$runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
Assert-RealDirectory $runnerTemp "RUNNER_TEMP" | Out-Null
$workRoot = Assert-ExactChildPath $runnerTemp $WorkDirectory "ai-security-scanner-nsis-upgrade-evidence" "Data-preservation fixture work directory"
New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
Assert-RealDirectory $workRoot "Data-preservation fixture work directory" | Out-Null
$installDirectory = Assert-ExactChildPath $runnerTemp (Join-Path $runnerTemp "ai-security-scanner-nsis-upgrade-installed") "ai-security-scanner-nsis-upgrade-installed" "Data-preservation fixture install directory"
$localApplicationData = [IO.Path]::GetFullPath(
  [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
)
Assert-RealDirectory $localApplicationData "OS-resolved LocalApplicationData" | Out-Null
$dataDirectory = Assert-ExactChildPath $localApplicationData (Join-Path $localApplicationData "dev.teddashh.ai-security-scanner") "dev.teddashh.ai-security-scanner" "Default application data directory"
$processLeasePath = Join-Path $dataDirectory $processLeaseRelativePath
$registrySentinelPath = "HKCU:\Software\dev.teddashh.ai-security-scanner\release-qualification\nsis-upgrade"
$priorInstallerPath = Assert-ExactChildPath $workRoot (Join-Path $workRoot $priorInstallerName) $priorInstallerName "Pinned prior installer"
$beginnerReportPath = Assert-ExactChildPath $workRoot (
  Join-Path $workRoot "beginner-report.html"
) "beginner-report.html" "Readable beginner report"
$observationsPath = Assert-ExactChildPath $workRoot (
  Join-Path $workRoot "observations.json"
) "observations.json" "Data-preservation fixture observations"

foreach ($freshPath in @(
  $installDirectory,
  $dataDirectory,
  $priorInstallerPath,
  $beginnerReportPath,
  $observationsPath,
  $registrySentinelPath
)) {
  if (Test-Path -LiteralPath $freshPath) {
    throw "Windows NSIS upgrade data-preservation fixture requires a fresh exact namespace: $freshPath"
  }
}
if (@(Get-CurrentUserUninstallEntries).Count -ne 0) {
  throw "Windows NSIS upgrade data-preservation fixture requires no existing current-user product registration."
}
if ($CurrentVersion -cne $candidateVersion) {
  throw "The bounded v$priorVersion N-1 data-preservation fixture applies only to candidate $candidateVersion."
}

$manifestPath = Join-Path $artifactRoot "installers-windows-x86_64.json"
$installerManifest = Read-BoundedJsonFile $manifestPath "Candidate installer manifest" (1024 * 1024)
$candidateInstallers = @($installerManifest.installers | Where-Object { $_.bundleType -eq "nsis" })
if ($installerManifest.version -cne $CurrentVersion -or $candidateInstallers.Count -ne 1 -or
    [IO.Path]::GetFileName([string]$candidateInstallers[0].file) -cne [string]$candidateInstallers[0].file) {
  throw "Candidate release artifact does not contain one flat NSIS installer for the requested version."
}
$candidateInstallerPath = (Resolve-Path -LiteralPath (Join-Path $artifactRoot $candidateInstallers[0].file)).Path
if (-not [String]::Equals([IO.Path]::GetDirectoryName($candidateInstallerPath), $artifactRoot, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Candidate NSIS installer escaped the downloaded release artifact directory."
}
$candidateInstallerItem = Get-NoFollowFileSha256Proof $candidateInstallerPath "Candidate NSIS installer" (256 * 1024 * 1024)
$candidateInstallerSha256 = [string]$candidateInstallerItem.Sha256
if ($candidateInstallerItem.Length -ne [int64]$candidateInstallers[0].bytes -or
    $candidateInstallerSha256 -cne [string]$candidateInstallers[0].sha256) {
  throw "Candidate NSIS installer differs from its release manifest."
}

$primaryFailure = $null
$cleanupFailures = [Collections.Generic.List[string]]::new()
$happyPathUninstalled = $false
$observations = $null
$activeUninstaller = $null
try {
  $priorInstallerProof = Download-PinnedPriorInstaller $priorInstallerPath
  Invoke-ExactProcess $priorInstallerPath @("/S", "/D=$installDirectory") 180000 "Pinned N-1 NSIS installation" -ExpectedExecutableProof $priorInstallerProof | Out-Null
  Assert-RealDirectory $installDirectory "N-1 installation directory" | Out-Null
  $priorDesktop = Find-OneInstalledFile $installDirectory "ai-security-scanner.exe"
  $priorCli = Find-OneInstalledFile $installDirectory "ai-security-scanner-cli.exe"
  $priorUninstaller = Find-OneInstalledFile $installDirectory "uninstall.exe"
  $activeUninstaller = $priorUninstaller
  $priorUninstallerSha256 = Get-LowerSha256 $priorUninstaller (512 * 1024 * 1024)
  $priorCliVersion = Get-CliVersion $priorCli "N-1 CLI"
  if ($priorCliVersion -cne $priorVersion) {
    throw "Pinned N-1 installer did not install CLI version $priorVersion."
  }
  $priorRegistry = Get-OneCurrentUserUninstallEntry $priorVersion $installDirectory

  $runtimeManifests = @(
    Get-ChildItem -LiteralPath $installDirectory -Filter "manifest.json" -File -Recurse -Force |
      Where-Object { $_.FullName -match '(?i)[\\/]managed-runtime[\\/]manifest\.json$' }
  )
  if ($runtimeManifests.Count -ne 1 -or
      (Get-LowerSha256 $runtimeManifests[0].FullName (1024 * 1024)) -cne $priorRuntimeManifestSha256) {
    throw "Pinned N-1 installation does not contain the immutable Windows managed-runtime manifest."
  }

  New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null
  $sentinelPath = Join-Path $dataDirectory "nsis-upgrade-data-preservation-sentinel.json"
  [IO.File]::WriteAllText(
    $sentinelPath,
    '{"schema":"ai-security-scanner.release-qualification/v1","value":"synthetic-non-sensitive"}',
    [Text.UTF8Encoding]::new($false)
  )
  New-Item -ItemType Directory -Path $registrySentinelPath -Force | Out-Null
  New-ItemProperty -LiteralPath $registrySentinelPath -Name "value" -Value "synthetic-non-sensitive" -PropertyType String -Force | Out-Null

  $demoCase = Invoke-CliJson $priorCli @(
    "--json", "--data-dir", $dataDirectory, "case", "seed-demo"
  ) "N-1 synthetic case seed"
  if ([string]::IsNullOrWhiteSpace([string]$demoCase.id) -or @($demoCase.scan_runs).Count -lt 1) {
    throw "N-1 CLI did not create one exportable synthetic demo case."
  }
  $caseId = [string]$demoCase.id
  $runId = [string]$demoCase.scan_runs[0].id
  Assert-CanonicalUuid $caseId "N-1 synthetic case ID"
  Assert-CanonicalUuid $runId "N-1 synthetic run ID"
  $existingExportIdentityPath = Join-Path $dataDirectory "integrity-signing-key"
  [IO.File]::WriteAllBytes($existingExportIdentityPath, [byte[]](0..31))
  $existingExportIdentityInitial = Get-NoFollowFileSha256Proof $existingExportIdentityPath (
    "Existing local export identity fixture"
  ) (64 * 1024)
  if ($existingExportIdentityInitial.Length -ne 32 -or
      $existingExportIdentityInitial.Sha256 -cne $existingExportIdentityFixtureSha256) {
    throw "Existing local export identity fixture bytes differ from the reviewed 32-byte fixture."
  }

  $managedRuntimeDirectory = Join-Path $dataDirectory "managed-runtime"
  $providerHomeDirectory = Join-Path $managedRuntimeDirectory "provider-home"
  $providerNamespace = $priorRuntimeManifestSha256.Substring(0, 16)
  $priorVersionDirectoryName = "podman-machine-5.8.2-$providerNamespace"
  $versionsDirectory = Join-Path $managedRuntimeDirectory "versions"
  $priorVersionDirectory = Join-Path $versionsDirectory $priorVersionDirectoryName
  Assert-RealDirectory $managedRuntimeDirectory "N-1 managed-runtime cache root" | Out-Null
  Assert-RealDirectory $versionsDirectory "N-1 managed-runtime versions root" | Out-Null
  Assert-RealDirectory $priorVersionDirectory "N-1 managed-runtime payload" | Out-Null
  $installedRuntimeEntries = @(Get-ChildItem -LiteralPath $versionsDirectory -Force)
  if ($installedRuntimeEntries.Count -ne 1 -or
      -not [String]::Equals(
        [string]$installedRuntimeEntries[0].Name,
        $priorVersionDirectoryName,
        [StringComparison]::Ordinal
      )) {
    throw "N-1 installer did not seed exactly one immutable managed-runtime payload."
  }
  $installedRuntimeManifest = Join-Path $priorVersionDirectory "manifest.json"
  if ((Get-LowerSha256 $installedRuntimeManifest (1024 * 1024)) -cne $priorRuntimeManifestSha256) {
    throw "N-1 private managed-runtime manifest differs from its installed package."
  }
  if (Test-Path -LiteralPath $providerHomeDirectory) {
    throw "N-1 runtime cache unexpectedly initialized provider state."
  }
  $managedRuntimeSnapshotBefore = Get-PrivateDataSnapshot $managedRuntimeDirectory

  $beforeSnapshot = Get-PrivateDataSnapshot $dataDirectory
  Invoke-ExactProcess $candidateInstallerPath @("/S", "/D=$installDirectory") 180000 "Candidate silent NSIS upgrade" -ExpectedExecutableProof $candidateInstallerItem -AllowRestartRequired | Out-Null
  Assert-RealFile $priorDesktop "Candidate desktop at the N-1 canonical path" (512 * 1024 * 1024) | Out-Null
  $candidateCli = Find-OneInstalledFile $installDirectory "ai-security-scanner-cli.exe"
  $candidateUninstaller = Find-OneInstalledFile $installDirectory "uninstall.exe"
  $activeUninstaller = $candidateUninstaller
  $candidateCliVersion = Get-CliVersion $candidateCli "Candidate CLI"
  if ($candidateCliVersion -cne $CurrentVersion) {
    throw "NSIS upgrade left CLI version $candidateCliVersion instead of $CurrentVersion."
  }
  $candidateRegistry = Get-OneCurrentUserUninstallEntry $CurrentVersion $installDirectory
  if (-not [String]::Equals($candidateRegistry.KeyName, $priorRegistry.KeyName, [StringComparison]::Ordinal)) {
    throw "NSIS upgrade replaced the product registry identity instead of updating it."
  }
  $existingExportIdentityAfterUpgrade = Get-NoFollowFileSha256Proof $existingExportIdentityPath (
    "Existing local export identity after N-1 upgrade"
  ) (64 * 1024)
  Assert-SameFileProof $existingExportIdentityInitial $existingExportIdentityAfterUpgrade (
    "N-1 upgrade existing local export identity"
  )
  Invoke-ExactProcess $candidateInstallerPath @("/S", "/D=$installDirectory") 180000 "Candidate same-version silent NSIS reinstall" -ExpectedExecutableProof $candidateInstallerItem -AllowRestartRequired | Out-Null
  Assert-RealFile $priorDesktop "Reinstalled candidate desktop at the canonical path" (512 * 1024 * 1024) | Out-Null
  $candidateCli = Find-OneInstalledFile $installDirectory "ai-security-scanner-cli.exe"
  $candidateUninstaller = Find-OneInstalledFile $installDirectory "uninstall.exe"
  $activeUninstaller = $candidateUninstaller
  if ((Get-CliVersion $candidateCli "Same-version reinstalled candidate CLI") -cne $CurrentVersion) {
    throw "Same-version silent reinstall changed the candidate CLI version."
  }
  $candidateRegistry = Get-OneCurrentUserUninstallEntry $CurrentVersion $installDirectory
  if (-not [String]::Equals($candidateRegistry.KeyName, $priorRegistry.KeyName, [StringComparison]::Ordinal)) {
    throw "Same-version silent reinstall did not preserve the version-neutral product registry identity."
  }
  $candidateUninstallerSha256 = Get-LowerSha256 $candidateUninstaller (512 * 1024 * 1024)
  if ($candidateUninstallerSha256 -ceq $priorUninstallerSha256) {
    throw "NSIS upgrade did not replace the N-1 uninstaller."
  }
  $existingExportIdentityAfterReinstall = Get-NoFollowFileSha256Proof $existingExportIdentityPath (
    "Existing local export identity after same-version reinstall"
  ) (64 * 1024)
  Assert-SameFileProof $existingExportIdentityInitial $existingExportIdentityAfterReinstall (
    "Same-version reinstall existing local export identity"
  )

  $afterSnapshot = Get-PrivateDataSnapshot $dataDirectory
  if ($beforeSnapshot.digest -cne $afterSnapshot.digest -or
      $beforeSnapshot.fileCount -ne $afterSnapshot.fileCount -or
      $beforeSnapshot.totalBytes -ne $afterSnapshot.totalBytes) {
    throw "Candidate NSIS installer changed private application data during upgrade."
  }
  $managedRuntimeSnapshotAfterInstaller = Get-PrivateDataSnapshot $managedRuntimeDirectory
  if ($managedRuntimeSnapshotAfterInstaller.digest -cne $managedRuntimeSnapshotBefore.digest -or
      $managedRuntimeSnapshotAfterInstaller.fileCount -ne $managedRuntimeSnapshotBefore.fileCount -or
      $managedRuntimeSnapshotAfterInstaller.totalBytes -ne $managedRuntimeSnapshotBefore.totalBytes) {
    throw "Candidate NSIS upgrade or reinstall changed the N-1 managed-runtime cache."
  }
  $candidateInstalledRuntimeManifests = @(
    Get-ChildItem -LiteralPath $installDirectory -Filter "manifest.json" -File -Recurse -Force |
      Where-Object { $_.FullName -match '(?i)[\\/]managed-runtime[\\/]manifest\.json$' }
  )
  if ($candidateInstalledRuntimeManifests.Count -ne 1 -or
      (Get-LowerSha256 $candidateInstalledRuntimeManifests[0].FullName (1024 * 1024)) -cne $priorRuntimeManifestSha256) {
    throw "Candidate installation does not retain the reviewed managed-runtime identity."
  }
  if (-not (Test-Path -LiteralPath $sentinelPath -PathType Leaf) -or
      -not (Test-Path -LiteralPath $registrySentinelPath -PathType Container) -or
      (Get-ItemPropertyValue -LiteralPath $registrySentinelPath -Name "value") -cne "synthetic-non-sensitive" -or
      -not (Test-Path -LiteralPath $priorVersionDirectory -PathType Container) -or
      (Test-Path -LiteralPath $providerHomeDirectory)) {
    throw "NSIS upgrade did not preserve the bounded data, registry, and managed-runtime cache."
  }
  $candidateCase = Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "case", "show", $caseId
  ) "Candidate synthetic case read"
  if (-not [String]::Equals([string]$candidateCase.id, $caseId, [StringComparison]::Ordinal)) {
    throw "Candidate CLI did not preserve the synthetic case identity."
  }
  $beginnerReportExport = Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory,
    "export", "create", "--case-id", $caseId, "--run-id", $runId,
    "--format", "html", "--destination", $beginnerReportPath
  ) "Candidate readable beginner report export"
  $beginnerReportProof = Get-NoFollowFileSha256Proof (
    $beginnerReportPath
  ) "Readable beginner report" (16 * 1024 * 1024)
  Assert-HtmlExportReceipt $beginnerReportExport $caseId $runId $beginnerReportPath (
    $beginnerReportProof
  ) "Candidate readable beginner report receipt"
  $existingExportIdentityAfterExport = Get-NoFollowFileSha256Proof $existingExportIdentityPath (
    "Existing local export identity after readable report export"
  ) (64 * 1024)
  Assert-SameFileProof $existingExportIdentityInitial $existingExportIdentityAfterExport (
    "Readable report export existing local export identity"
  )

  $appOnlyUninstallSnapshotBefore = Get-PrivateDataSnapshot $dataDirectory -ExcludeProcessLease
  $processLeaseBeforeUninstall = Get-NoFollowEmptyFileProof $processLeasePath (
    "Root process lease before app-only uninstall"
  )
  $sentinelBeforeUninstall = Get-NoFollowFileSha256Proof $sentinelPath (
    "Data-preservation sentinel before app-only uninstall"
  ) (64 * 1024)
  # `_?=` makes NSIS synchronous but also disables its own temporary self-copy.
  # Run a byte-verified copy outside $INSTDIR so the original uninstaller can be
  # deleted and its exact postconditions can complete before this fixture moves
  # on. The helper deletes only its fixed execution copy afterward.
  $uninstallResult = Invoke-BoundedCopiedNsisUninstaller $candidateUninstaller (
    $installDirectory
  ) $workRoot (
    "Candidate NSIS uninstall"
  )
  if ([int]$uninstallResult.exitCode -ne 0) {
    throw "Candidate NSIS uninstall did not complete the normal app-only path."
  }
  if (Test-Path -LiteralPath $installDirectory) {
    throw "Candidate NSIS uninstall retained the exact application installation directory."
  }
  foreach ($removedProductFile in @($priorDesktop, $candidateCli, $candidateUninstaller)) {
    if (Test-Path -LiteralPath $removedProductFile) {
      throw "Candidate NSIS uninstall retained a product application binary."
    }
  }
  if (@(Get-CurrentUserUninstallEntries).Count -ne 0) {
    throw "Candidate NSIS uninstall left its current-user product registration behind."
  }
  $appOnlyUninstallSnapshotAfter = Get-PrivateDataSnapshot $dataDirectory -ExcludeProcessLease
  $processLeaseAfterUninstall = Get-NoFollowEmptyFileProof $processLeasePath (
    "Root process lease after app-only uninstall"
  )
  Assert-SameFileProof $processLeaseBeforeUninstall $processLeaseAfterUninstall (
    "App-only uninstall root process lease"
  )
  if ($appOnlyUninstallSnapshotAfter.digest -cne $appOnlyUninstallSnapshotBefore.digest -or
      $appOnlyUninstallSnapshotAfter.fileCount -ne $appOnlyUninstallSnapshotBefore.fileCount -or
      $appOnlyUninstallSnapshotAfter.totalBytes -ne $appOnlyUninstallSnapshotBefore.totalBytes) {
    throw "App-only NSIS uninstall changed non-lease product data before explicit fixture teardown."
  }
  $sentinelAfterUninstall = Get-NoFollowFileSha256Proof $sentinelPath (
    "Data-preservation sentinel after app-only uninstall"
  ) (64 * 1024)
  Assert-SameFileProof $sentinelBeforeUninstall $sentinelAfterUninstall (
    "App-only uninstall data-preservation sentinel"
  )
  $managedRuntimeSnapshotAfterUninstall = Get-PrivateDataSnapshot $managedRuntimeDirectory
  if ($managedRuntimeSnapshotAfterUninstall.digest -cne $managedRuntimeSnapshotBefore.digest -or
      $managedRuntimeSnapshotAfterUninstall.fileCount -ne $managedRuntimeSnapshotBefore.fileCount -or
      $managedRuntimeSnapshotAfterUninstall.totalBytes -ne $managedRuntimeSnapshotBefore.totalBytes -or
      (Test-Path -LiteralPath $providerHomeDirectory)) {
    throw "App-only uninstall changed the verified N-1 managed-runtime cache."
  }
  $existingExportIdentityAfterUninstall = Get-NoFollowFileSha256Proof $existingExportIdentityPath (
    "Existing local export identity after app-only NSIS uninstall"
  ) (64 * 1024)
  Assert-SameFileProof $existingExportIdentityInitial $existingExportIdentityAfterUninstall (
    "App-only NSIS uninstall existing local export identity"
  )
  $beginnerReportAfterUninstall = Get-NoFollowFileSha256Proof $beginnerReportPath (
    "Readable beginner report after app-only NSIS uninstall"
  ) (16 * 1024 * 1024)
  Assert-SameFileProof $beginnerReportProof $beginnerReportAfterUninstall (
    "App-only NSIS uninstall readable beginner report"
  )
  $happyPathUninstalled = $true
  $activeUninstaller = $null
  if (Test-Path -LiteralPath $installDirectory) {
    Remove-ExactTree $installDirectory $runnerTemp "ai-security-scanner-nsis-upgrade-installed"
  }
  Remove-ExactTree $dataDirectory $localApplicationData "dev.teddashh.ai-security-scanner"
  Remove-Item -LiteralPath $registrySentinelPath -Recurse -Force
  if (Test-Path -LiteralPath $registrySentinelPath) {
    throw "Fixture registry sentinel remains after exact teardown."
  }

  $observations = [ordered]@{
    schemaVersion = 10
    scenario = "automated_n_minus_one_nsis_data_preservation_fixture"
    platform = "windows-x86_64"
    runner = "windows-2025"
    fixtureScope = [ordered]@{
      classification = "risk_focused_automated_data_preservation"
      qualifiesPublicLifecycle = $false
      syntheticCliCaseUsed = $true
      installedDesktopInteractionObserved = $false
      localhost1270019001ReportObserved = $false
      projectReopenedInDesktopObserved = $false
      postUninstallReinstallObserved = $false
    }
    priorRelease = [ordered]@{
      version = $priorVersion
      tag = $priorTag
      installerFile = $priorInstallerName
      installerBytes = $priorInstallerBytes
      installerSha256 = $priorInstallerSha256
      downloadUrl = $priorInstallerUrl
      runtimeManifestSha256 = $priorRuntimeManifestSha256
      machineImageSha256 = $priorMachineImageSha256
    }
    candidate = [ordered]@{
      version = $CurrentVersion
      installerFile = [string]$candidateInstallers[0].file
      installerBytes = [int64]$candidateInstallers[0].bytes
      installerSha256 = $candidateInstallerSha256
    }
    installation = [ordered]@{
      priorCliVersion = $priorCliVersion
      candidateCliVersion = $candidateCliVersion
      sameCanonicalInstallDirectory = $true
      registryHive = "HKEY_CURRENT_USER"
      registryEntryIdentityPreserved = $true
      displayVersionUpdated = $true
      uninstallerReplaced = $true
      unattendedMode = "silent"
      sameVersionSilentReinstallCompleted = $true
    }
    dataPreservation = [ordered]@{
      defaultLocalDataDirectoryUsed = $true
      preInstallerFileCount = [int]$beforeSnapshot.fileCount
      preInstallerBytes = [int64]$beforeSnapshot.totalBytes
      exactPreInstallerSnapshotPreserved = $true
      sentinelPreserved = $true
      demoCaseId = $caseId
      demoRunId = $runId
      demoCasePreserved = $true
      existingExportIdentity = [ordered]@{
        fixtureSha256 = $existingExportIdentityFixtureSha256
        initial = Convert-FileProofObservation $existingExportIdentityInitial
        afterUpgrade = Convert-FileProofObservation $existingExportIdentityAfterUpgrade
        afterReinstall = Convert-FileProofObservation $existingExportIdentityAfterReinstall
        afterReportExport = Convert-FileProofObservation $existingExportIdentityAfterExport
        afterAppOnlyUninstall = Convert-FileProofObservation $existingExportIdentityAfterUninstall
      }
      beginnerReportExport = [ordered]@{
        receipt = $beginnerReportExport
        independentFile = [ordered]@{
          file = "beginner-report.html"
          bytes = [int64]$beginnerReportProof.Length
          sha256 = [string]$beginnerReportProof.Sha256
        }
      }
      appOnlyUninstallSnapshot = [ordered]@{
        beforeFileCount = [int]$appOnlyUninstallSnapshotBefore.fileCount
        afterFileCount = [int]$appOnlyUninstallSnapshotAfter.fileCount
        beforeBytes = [int64]$appOnlyUninstallSnapshotBefore.totalBytes
        afterBytes = [int64]$appOnlyUninstallSnapshotAfter.totalBytes
        beforeDigest = [string]$appOnlyUninstallSnapshotBefore.digest
        afterDigest = [string]$appOnlyUninstallSnapshotAfter.digest
        processLeaseBefore = Convert-FileProofObservation $processLeaseBeforeUninstall
        processLeaseAfter = Convert-FileProofObservation $processLeaseAfterUninstall
        processLeaseIdentityPreserved = $true
        allNonLeaseProductDataPreserved = $true
      }
    }
    managedRuntimeCache = [ordered]@{
      versionDirectory = $priorVersionDirectoryName
      manifestSha256 = $priorRuntimeManifestSha256
      preUpgradeFileCount = [int]$managedRuntimeSnapshotBefore.fileCount
      preUpgradeBytes = [int64]$managedRuntimeSnapshotBefore.totalBytes
      installedByPriorRelease = $true
      providerStateAbsent = $true
      exactBytesPreservedThroughUpgradeAndReinstall = $true
      exactBytesPreservedThroughAppOnlyUninstall = $true
    }
    cleanup = [ordered]@{
      uninstallerInvoked = $true
      productRegistryRemovedByUninstaller = $true
      fixtureTeardownInstallDirectoryRemoved = $true
      fixtureTeardownPrivateDataRemoved = $true
      fixtureTeardownRegistrySentinelRemoved = $true
    }
  }
} catch {
  $primaryFailure = $_
} finally {
  if ($null -ne $primaryFailure) {
    if ($null -eq $activeUninstaller -and (Test-Path -LiteralPath $installDirectory -PathType Container)) {
      $fallback = @(
        Get-ChildItem -LiteralPath $installDirectory -Filter "uninstall.exe" -File -Recurse -Force |
          Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 }
      )
      if ($fallback.Count -eq 1) {
        $activeUninstaller = $fallback[0].FullName
      }
    }
    if ($null -ne $activeUninstaller -and (Test-Path -LiteralPath $activeUninstaller -PathType Leaf)) {
      try {
        Invoke-BoundedCopiedNsisUninstaller $activeUninstaller $installDirectory $workRoot (
          "Failure-path NSIS uninstall"
        ) | Out-Null
      } catch {
        $cleanupFailures.Add("NSIS uninstall: $($_.Exception.Message)")
      }
    }
    foreach ($cleanup in @(
      [ordered]@{ path = $installDirectory; parent = $runnerTemp; name = "ai-security-scanner-nsis-upgrade-installed" },
      [ordered]@{ path = $dataDirectory; parent = $localApplicationData; name = "dev.teddashh.ai-security-scanner" }
    )) {
      try {
        if (Test-Path -LiteralPath $cleanup.path) {
          Remove-ExactTree $cleanup.path $cleanup.parent $cleanup.name
        }
      } catch {
        $cleanupFailures.Add("exact tree cleanup: $($_.Exception.Message)")
      }
    }
    try {
      if (Test-Path -LiteralPath $registrySentinelPath) {
        Remove-Item -LiteralPath $registrySentinelPath -Recurse -Force
      }
    } catch {
      $cleanupFailures.Add("registry sentinel cleanup: $($_.Exception.Message)")
    }
  }
}

if ($null -ne $primaryFailure) {
  $suffix = if ($cleanupFailures.Count -eq 0) { "" } else { " Cleanup failure(s): $([String]::Join('; ', $cleanupFailures))" }
  throw [InvalidOperationException]::new($primaryFailure.Exception.Message + $suffix, $primaryFailure.Exception)
}
if (-not $happyPathUninstalled -or $null -eq $observations) {
  throw "Windows NSIS upgrade data-preservation fixture did not reach its verified teardown state."
}
$retainedBeginnerReportProof = Get-NoFollowFileSha256Proof (
  $beginnerReportPath
) "Readable beginner report after cleanup" (16 * 1024 * 1024)
if ($retainedBeginnerReportProof.Length -ne $beginnerReportProof.Length -or
    $retainedBeginnerReportProof.Sha256 -cne $beginnerReportProof.Sha256) {
  throw "Readable beginner report changed during fixture teardown."
}
$observations | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $observationsPath -Encoding utf8NoBOM -NoNewline
Add-Content -LiteralPath $observationsPath -Value "" -Encoding utf8NoBOM

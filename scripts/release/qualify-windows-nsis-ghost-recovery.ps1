param(
  [Parameter(Mandatory = $true)][string]$ArtifactDirectory,
  [Parameter(Mandatory = $true)][string]$WorkDirectory,
  [Parameter(Mandatory = $true)][string]$CurrentVersion
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$priorVersion = "0.1.7"
$candidateVersion = "0.1.10"
$priorInstallerName = "ai-security-scanner_0.1.7_x64-setup.exe"
$priorInstallerBytes = 38730365
$priorInstallerSha256 = "4d2057ca4c008b46dc0195a792075e4b4b377c1909a7795b29efc30f9ae48b1a"
$priorInstallerUrl = "https://github.com/TED-H-com/ai-security-scanner/releases/download/v0.1.7/ai-security-scanner_0.1.7_x64-setup.exe"
$priorRuntimeManifestSha256 = "8b2257ace33ecb14bb0995044a4e6d2b4e71b314741601122801fbb59e7de13f"
$candidateRuntimeManifestExpectedSha256 = "83a4f0106c5c1be17e515db9f86f32d9e43fc4563d85473b400e3df6efe240e3"
$priorMachineImageSha256 = "e2b6cbcadd8b41b708fecb58a246a20d737dee0ef26872a3f75b575f77eba968"
$priorProviderNamespace = $priorRuntimeManifestSha256.Substring(0, 16)
$oldMachineName = "assm1-win-x64-$($priorMachineImageSha256.Substring(0, 12))"
$oldDistributionName = "podman-$oldMachineName"
$currentMachinePrefix = "assm2-win-x64"
$isolatedMachinePrefix = "assm2-iso-"
$oldVersionDirectoryName = "podman-machine-5.8.2-$priorProviderNamespace"
$maximumDownloadBytes = 64 * 1024 * 1024
$maximumSnapshotFiles = 4096
$maximumSnapshotBytes = 512 * 1024 * 1024
$maximumCompleteSnapshotBytes = 64GB
$processLeaseRelativePath = ".exclusive-process.lock"
$existingExportIdentityFixtureSha256 = "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
$emptyFileSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
$maximumWindowsPathUtf16CodeUnits = 32760
$maximumVerbatimWindowsPathUtf16CodeUnits = 32766
$maximumRetainedProcessOutputBytes = 64 * 1024
$maximumWslGuestScriptBytes = 64 * 1024
$sentinelLifecycleRequiredPhases = @(
  "fixture_ready",
  "before_candidate_install",
  "after_candidate_install",
  "after_same_version_reinstall",
  "before_candidate_runtime_start",
  "after_candidate_runtime_running",
  "after_current_runtime_purge",
  "before_app_only_uninstall"
)

function Get-ExpectedIsolatedMachineName(
  [string]$StateRoot,
  [string]$ManifestSha256,
  [string]$MachineImageSha256,
  [uint32]$GenerationIndex
) {
  if ($ManifestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
      $MachineImageSha256 -cnotmatch '^[0-9a-f]{64}$' -or
      $GenerationIndex -lt 1 -or $GenerationIndex -gt 32) {
    throw "Isolated machine identity input is invalid."
  }
  $hash = [Security.Cryptography.IncrementalHash]::CreateHash(
    [Security.Cryptography.HashAlgorithmName]::SHA256
  )
  try {
    $zero = [byte[]]@(0)
    foreach ($segment in @(
      "ai-security-scanner/windows-wsl-isolated-generation/v1",
      (Get-VerbatimWindowsPath $StateRoot "Isolated managed runtime state root"),
      $ManifestSha256,
      $MachineImageSha256
    )) {
      $hash.AppendData([Text.Encoding]::UTF8.GetBytes($segment))
      $hash.AppendData($zero)
    }
    $generationBytes = [BitConverter]::GetBytes($GenerationIndex)
    if (-not [BitConverter]::IsLittleEndian) {
      [Array]::Reverse($generationBytes)
    }
    $hash.AppendData($generationBytes)
    $suffix = [Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
  } finally {
    $hash.Dispose()
  }
  return "assm2-iso-$($suffix.Substring(0, 20))"
}

if ($CurrentVersion -cne $candidateVersion) {
  throw "The bounded v0.1.7 ghost-isolation data-preservation fixture applies only to candidate $candidateVersion."
}

if ($null -eq ("GhostQualificationNativeMethods" -as [type])) {
  Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class GhostQualificationNativeMethods {
    public const uint GENERIC_READ = 0x80000000;
    public const uint FILE_READ_DATA = 0x00000001;
    public const uint FILE_READ_ATTRIBUTES = 0x00000080;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern uint GetSystemWindowsDirectoryW(StringBuilder buffer, uint size);

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
        out GhostQualificationByHandleFileInformation information);
}

[StructLayout(LayoutKind.Sequential)]
public struct GhostQualificationByHandleFileInformation {
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

public sealed class GhostQualificationBoundedCaptureStream : System.IO.Stream {
    // Keep draining after the retained prefix fills so a noisy child cannot
    // deadlock while the fixture is waiting for its exact process exit.
    private readonly byte[] retained;
    private readonly object sync = new object();
    private int retainedLength;
    private bool overflowed;

    public GhostQualificationBoundedCaptureStream(int capacity) {
        if (capacity < 1 || capacity > 1024 * 1024) {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }
        retained = new byte[capacity];
    }

    public bool Overflowed {
        get { lock (sync) { return overflowed; } }
    }

    public byte[] Snapshot() {
        lock (sync) {
            byte[] snapshot = new byte[retainedLength];
            Buffer.BlockCopy(retained, 0, snapshot, 0, retainedLength);
            return snapshot;
        }
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length { get { lock (sync) { return retainedLength; } } }
    public override long Position {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() { }

    private void WriteCore(ReadOnlySpan<byte> buffer) {
        lock (sync) {
            int remaining = retained.Length - retainedLength;
            int copied = Math.Min(remaining, buffer.Length);
            if (copied > 0) {
                buffer.Slice(0, copied).CopyTo(retained.AsSpan(retainedLength));
                retainedLength += copied;
            }
            if (copied != buffer.Length) { overflowed = true; }
        }
    }

    public override void Write(byte[] buffer, int offset, int count) {
        ArgumentNullException.ThrowIfNull(buffer);
        if (offset < 0 || count < 0 || offset > buffer.Length - count) {
            throw new ArgumentOutOfRangeException();
        }
        WriteCore(new ReadOnlySpan<byte>(buffer, offset, count));
    }

    public override void Write(ReadOnlySpan<byte> buffer) { WriteCore(buffer); }

    public override System.Threading.Tasks.Task WriteAsync(
        byte[] buffer,
        int offset,
        int count,
        System.Threading.CancellationToken cancellationToken
    ) {
        cancellationToken.ThrowIfCancellationRequested();
        Write(buffer, offset, count);
        return System.Threading.Tasks.Task.CompletedTask;
    }

    public override System.Threading.Tasks.ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        System.Threading.CancellationToken cancellationToken = default
    ) {
        cancellationToken.ThrowIfCancellationRequested();
        WriteCore(buffer.Span);
        return System.Threading.Tasks.ValueTask.CompletedTask;
    }

    public override int Read(byte[] buffer, int offset, int count) {
        throw new NotSupportedException();
    }
    public override long Seek(long offset, System.IO.SeekOrigin origin) {
        throw new NotSupportedException();
    }
    public override void SetLength(long value) { throw new NotSupportedException(); }
}
"@
}

function Assert-ExactChildPath([string]$Parent, [string]$Child, [string]$ExpectedName, [string]$Label) {
  $parentPath = [IO.Path]::GetFullPath($Parent)
  $childPath = [IO.Path]::GetFullPath($Child)
  if (-not [String]::Equals([IO.Path]::GetDirectoryName($childPath), $parentPath, [StringComparison]::OrdinalIgnoreCase) -or
      -not [String]::Equals([IO.Path]::GetFileName($childPath), $ExpectedName, [StringComparison]::Ordinal)) {
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

function Assert-RealDirectory([string]$Path, [string]$Label) {
  $item = Get-Item -LiteralPath $Path -Force
  if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Label is not one real directory."
  }
  return $item
}

function Get-OpenFileIdentity([IO.FileStream]$Stream) {
  $information = [GhostQualificationByHandleFileInformation]::new()
  if (-not [GhostQualificationNativeMethods]::GetFileInformationByHandle($Stream.SafeFileHandle, [ref]$information)) {
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

function Get-OpenDirectoryIdentity([Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle) {
  if ($null -eq $Handle -or $Handle.IsInvalid -or $Handle.IsClosed) {
    throw "Data-preservation fixture directory handle is not open."
  }
  $information = [GhostQualificationByHandleFileInformation]::new()
  if (-not [GhostQualificationNativeMethods]::GetFileInformationByHandle($Handle, [ref]$information)) {
    throw "Could not inspect the exact data-preservation fixture directory handle."
  }
  return [ordered]@{
    attributes = [uint32]$information.FileAttributes
    volume = [uint32]$information.VolumeSerialNumber
    index = (([uint64]$information.FileIndexHigh -shl 32) -bor [uint64]$information.FileIndexLow)
  }
}

function Get-RetainedVhdIdentity([string]$Path, [string]$Label) {
  # Observation only: the minimum read category participates in Windows share
  # arbitration without reading VHD bytes. No-follow and omitted delete sharing
  # pin the exact file identity while its metadata is captured.
  $verbatimPath = Get-VerbatimWindowsPath $Path $Label
  $handle = [GhostQualificationNativeMethods]::CreateFileW(
    $verbatimPath,
    [GhostQualificationNativeMethods]::FILE_READ_DATA,
    [GhostQualificationNativeMethods]::FILE_SHARE_READ -bor
      [GhostQualificationNativeMethods]::FILE_SHARE_WRITE,
    [IntPtr]::Zero,
    [GhostQualificationNativeMethods]::OPEN_EXISTING,
    [GhostQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT,
    [IntPtr]::Zero
  )
  if ($null -eq $handle -or $handle.IsInvalid) {
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($null -ne $handle) { $handle.Dispose() }
    throw [ComponentModel.Win32Exception]::new(
      $errorCode,
      "$Label could not be opened for non-destructive identity observation"
    )
  }
  try {
    $information = [GhostQualificationByHandleFileInformation]::new()
    if (-not [GhostQualificationNativeMethods]::GetFileInformationByHandle(
        $handle,
        [ref]$information
      )) {
      throw [ComponentModel.Win32Exception]::new(
        [Runtime.InteropServices.Marshal]::GetLastWin32Error(),
        "$Label identity could not be read"
      )
    }
    $size = (([uint64]$information.FileSizeHigh -shl 32) -bor [uint64]$information.FileSizeLow)
    $fileIndex = (([uint64]$information.FileIndexHigh -shl 32) -bor [uint64]$information.FileIndexLow)
    if (($information.FileAttributes -band [uint32][IO.FileAttributes]::Directory) -ne 0 -or
        ($information.FileAttributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $size -lt 1 -or $information.NumberOfLinks -lt 1) {
      throw "$Label is not one non-empty no-follow regular file."
    }
    return [ordered]@{
      path = [IO.Path]::GetFullPath($Path)
      sizeBytes = [uint64]$size
      volumeSerialNumber = [uint32]$information.VolumeSerialNumber
      fileIndex = [uint64]$fileIndex
      numberOfLinks = [uint32]$information.NumberOfLinks
      attributes = [uint32]$information.FileAttributes
    }
  } finally {
    $handle.Dispose()
  }
}

function Get-BoundedAbsoluteWindowsPath([string]$Path, [string]$Label) {
  if ([String]::IsNullOrWhiteSpace($Path) -or $Path.IndexOf([char]0) -ge 0) {
    throw "$Label is empty or contains a NUL code unit."
  }
  if ($Path.Length -gt $maximumWindowsPathUtf16CodeUnits -or
      -not [IO.Path]::IsPathFullyQualified($Path)) {
    throw "$Label is not one bounded absolute Windows path."
  }
  $full = [IO.Path]::GetFullPath($Path)
  if ($full.IndexOf([char]0) -ge 0 -or $full.Length -gt $maximumWindowsPathUtf16CodeUnits) {
    throw "$Label expanded beyond the Windows path bound."
  }
  return $full
}

function Get-VerbatimWindowsPath([string]$Path, [string]$Label) {
  $full = Get-BoundedAbsoluteWindowsPath $Path $Label
  if ($full.StartsWith("\\?\", [StringComparison]::Ordinal)) { return $full }
  $verbatim = if ($full.StartsWith("\\", [StringComparison]::Ordinal)) {
    "\\?\UNC\" + $full.Substring(2)
  } else {
    "\\?\" + $full
  }
  if ($verbatim.Length -gt $maximumVerbatimWindowsPathUtf16CodeUnits) {
    throw "$Label exceeds the Windows verbatim path bound."
  }
  return $verbatim
}

function Open-NoFollowSingleLinkFile(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = [uint64]::MaxValue
) {
  $verbatimPath = Get-VerbatimWindowsPath $Path $Label
  $handle = [GhostQualificationNativeMethods]::CreateFileW(
    $verbatimPath,
    [GhostQualificationNativeMethods]::GENERIC_READ,
    [GhostQualificationNativeMethods]::FILE_SHARE_READ,
    [IntPtr]::Zero,
    [GhostQualificationNativeMethods]::OPEN_EXISTING,
    [GhostQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT,
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

function Assert-ExactEmptyProcessLeaseFile([string]$Path, [string]$Label) {
  # This exception is intentionally separate from the generic evidence opener:
  # only the product's exact root process lease may be empty. Installer, key,
  # archive, receipt, and evidence proofs retain their >= 1-byte requirement.
  $verbatimPath = Get-VerbatimWindowsPath $Path $Label
  $handle = [GhostQualificationNativeMethods]::CreateFileW(
    $verbatimPath,
    [GhostQualificationNativeMethods]::GENERIC_READ,
    [GhostQualificationNativeMethods]::FILE_SHARE_READ,
    [IntPtr]::Zero,
    [GhostQualificationNativeMethods]::OPEN_EXISTING,
    [GhostQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT,
    [IntPtr]::Zero
  )
  if ($null -eq $handle -or $handle.IsInvalid) {
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($null -ne $handle) { $handle.Dispose() }
    throw [ComponentModel.Win32Exception]::new(
      $errorCode,
      "$Label could not be opened without following reparse points"
    )
  }
  try {
    $stream = [IO.FileStream]::new($handle, [IO.FileAccess]::Read, 1, $false)
  } catch {
    $handle.Dispose()
    throw
  }
  try {
    $before = Get-OpenFileIdentity $stream
    if (($before.attributes -band [uint32][IO.FileAttributes]::Directory) -ne 0 -or
        ($before.attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $before.links -ne 1 -or $before.bytes -ne 0) {
      throw "$Label is not the exact empty no-follow single-link process lease."
    }
    $after = Get-OpenFileIdentity $stream
    if ($before.attributes -ne $after.attributes -or $before.links -ne $after.links -or
        $before.bytes -ne $after.bytes -or $before.volume -ne $after.volume -or
        $before.index -ne $after.index) {
      throw "$Label changed while its exact no-follow handle was held."
    }
  } finally {
    $stream.Dispose()
    $handle.Dispose()
  }
}

function Get-NoFollowEmptyFileProof([string]$Path, [string]$Label) {
  $verbatimPath = Get-VerbatimWindowsPath $Path $Label
  $handle = [GhostQualificationNativeMethods]::CreateFileW(
    $verbatimPath,
    [GhostQualificationNativeMethods]::GENERIC_READ,
    [GhostQualificationNativeMethods]::FILE_SHARE_READ,
    [IntPtr]::Zero,
    [GhostQualificationNativeMethods]::OPEN_EXISTING,
    [GhostQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT,
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
      NumberOfLinks = [uint32]$before.links
      Attributes = [uint32]$before.attributes
    }
  } finally { $stream.Dispose() }
}

function Open-NoFollowWindowsSystemFile(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = 512 * 1024 * 1024
) {
  $verbatimPath = Get-VerbatimWindowsPath $Path $Label
  $handle = [GhostQualificationNativeMethods]::CreateFileW(
    $verbatimPath,
    [GhostQualificationNativeMethods]::GENERIC_READ,
    [GhostQualificationNativeMethods]::FILE_SHARE_READ,
    [IntPtr]::Zero,
    [GhostQualificationNativeMethods]::OPEN_EXISTING,
    [GhostQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT,
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
    # Windows servicing legitimately exposes component-store files in System32
    # through hard links. This system-file-only opener therefore accepts one or
    # more links, while every installer, key, fixture, archive, and retained
    # evidence file continues to use Open-NoFollowSingleLinkFile above.
    if (($identity.attributes -band [uint32][IO.FileAttributes]::Directory) -ne 0 -or
        ($identity.attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $identity.links -lt 1 -or $identity.bytes -lt 1 -or $identity.bytes -gt $MaximumBytes) {
      throw "$Label is not one bounded no-follow Windows system regular file."
    }
    return ,$stream
  } catch {
    $stream.Dispose()
    throw
  }
}

function Open-NoFollowRealDirectory([string]$Path, [string]$Label) {
  $verbatimPath = Get-VerbatimWindowsPath $Path $Label
  $handle = [GhostQualificationNativeMethods]::CreateFileW(
    $verbatimPath,
    [GhostQualificationNativeMethods]::FILE_READ_ATTRIBUTES,
    ([GhostQualificationNativeMethods]::FILE_SHARE_READ -bor [GhostQualificationNativeMethods]::FILE_SHARE_WRITE),
    [IntPtr]::Zero,
    [GhostQualificationNativeMethods]::OPEN_EXISTING,
    ([GhostQualificationNativeMethods]::FILE_FLAG_BACKUP_SEMANTICS -bor [GhostQualificationNativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT),
    [IntPtr]::Zero
  )
  if ($null -eq $handle -or $handle.IsInvalid) {
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($null -ne $handle) { $handle.Dispose() }
    throw [ComponentModel.Win32Exception]::new($errorCode, "$Label could not be opened without following reparse points")
  }
  try {
    $identity = Get-OpenDirectoryIdentity $handle
    if (($identity.attributes -band [uint32][IO.FileAttributes]::Directory) -eq 0 -or
        ($identity.attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Label is not one no-follow real directory."
    }
    return ,$handle
  } catch {
    $handle.Dispose()
    throw
  }
}

function Assert-SameNoFollowDirectoryIdentity(
  [string]$ActualPath,
  [string]$ExpectedPath,
  [string]$Label
) {
  $actualHandle = Open-NoFollowRealDirectory $ActualPath "$Label reported directory"
  try {
    $expectedHandle = Open-NoFollowRealDirectory $ExpectedPath "$Label expected directory"
    try {
      # Both restrictive no-follow handles stay open for the complete comparison.
      # Path spelling (including Windows' \\?\ form) is never treated as ownership.
      $actualBefore = Get-OpenDirectoryIdentity $actualHandle
      $expectedBefore = Get-OpenDirectoryIdentity $expectedHandle
      if ($actualBefore.volume -ne $expectedBefore.volume -or
          $actualBefore.index -ne $expectedBefore.index) {
        throw "$Label does not refer to the exact same directory object."
      }
      $actualAfter = Get-OpenDirectoryIdentity $actualHandle
      $expectedAfter = Get-OpenDirectoryIdentity $expectedHandle
      if ($actualBefore.attributes -ne $actualAfter.attributes -or
          $actualBefore.volume -ne $actualAfter.volume -or
          $actualBefore.index -ne $actualAfter.index -or
          $expectedBefore.attributes -ne $expectedAfter.attributes -or
          $expectedBefore.volume -ne $expectedAfter.volume -or
          $expectedBefore.index -ne $expectedAfter.index) {
        throw "$Label directory identity changed while both proof handles were held."
      }
    } finally {
      $expectedHandle.Dispose()
    }
  } finally {
    $actualHandle.Dispose()
  }
}

function Assert-SingleLinkFile([string]$Path, [string]$Label, [uint64]$MaximumBytes = [uint64]::MaxValue) {
  $stream = Open-NoFollowSingleLinkFile $Path $Label $MaximumBytes
  try { $identity = Get-OpenFileIdentity $stream }
  finally { $stream.Dispose() }
  return [PSCustomObject]@{
    FullName = [IO.Path]::GetFullPath($Path)
    Length = [int64]$identity.bytes
  }
}

function Assert-OwnerOnlyFullControlFile(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = 64 * 1024
) {
  $stream = Open-NoFollowSingleLinkFile $Path $Label $MaximumBytes
  try {
    $before = Get-OpenFileIdentity $stream
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier])
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($null -eq $currentSid -or $ownerSid.Value -cne $currentSid.Value -or
        -not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical -or
        $rules.Count -ne 1) {
      throw "$Label is not owned by exactly the current user with one protected canonical DACL."
    }
    $rule = $rules[0]
    if ($rule.IdentityReference.Value -cne $currentSid.Value -or
        $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $rule.IsInherited -or
        $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
        $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
        [uint32]$rule.FileSystemRights -ne [uint32][Security.AccessControl.FileSystemRights]::FullControl) {
      throw "$Label does not have the exact one-current-user FILE_ALL_ACCESS ACE."
    }
    $after = Get-OpenFileIdentity $stream
    if ($before.attributes -ne $after.attributes -or $before.links -ne $after.links -or
        $before.bytes -ne $after.bytes -or $before.volume -ne $after.volume -or
        $before.index -ne $after.index) {
      throw "$Label changed while its exact ownership and DACL were inspected."
    }
    return [PSCustomObject]@{
      FullName = [IO.Path]::GetFullPath($Path)
      Length = [int64]$before.bytes
    }
  } finally {
    $stream.Dispose()
  }
}

function Set-CanonicalProductDataOwner([string]$Path) {
  Assert-RealDirectory $Path "Canonical product data directory" | Out-Null
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  if ($null -eq $currentSid) {
    throw "The current Windows user has no SID."
  }
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  $acl.SetOwner($currentSid)
  Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
  $verifiedAcl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  $verifiedOwner = $verifiedAcl.GetOwner([Security.Principal.SecurityIdentifier])
  if ($verifiedOwner.Value -cne $currentSid.Value) {
    throw "Canonical product data directory owner was not set to the current Windows user."
  }
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
      NumberOfLinks = [uint32]$before.links
      Attributes = [uint32]$before.attributes
    }
  } finally {
    $stream.Dispose()
  }
}

function Get-QuiescedVhdSha256Proof(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes
) {
  $deadline = [DateTime]::UtcNow.AddSeconds(60)
  do {
    try {
      return Get-NoFollowFileSha256Proof $Path $Label $MaximumBytes
    } catch [ComponentModel.Win32Exception] {
      $win32Exception = $_.Exception
      while ($null -ne $win32Exception -and
             $win32Exception -isnot [ComponentModel.Win32Exception]) {
        $win32Exception = $win32Exception.InnerException
      }
      if ($null -eq $win32Exception -or
          [int]$win32Exception.NativeErrorCode -notin @(32, 33)) {
        throw
      }
      if ([DateTime]::UtcNow -ge $deadline) {
        throw "$Label remained locked after its bounded WSL quiescence wait."
      }
      Start-Sleep -Milliseconds 500
    }
  } while ($true)
}

function Assert-SameFileProof([object]$Expected, [object]$Actual, [string]$Label) {
  if ($Expected.Length -ne $Actual.Length -or
      $Expected.Sha256 -cne $Actual.Sha256 -or
      $Expected.Volume -ne $Actual.Volume -or
      $Expected.FileIndex -ne $Actual.FileIndex -or
      $Expected.NumberOfLinks -ne $Actual.NumberOfLinks -or
      $Expected.Attributes -ne $Actual.Attributes -or
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

function Convert-VhdFileProofObservation([object]$Proof) {
  return [ordered]@{
    length = [int64]$Proof.Length
    sha256 = [string]$Proof.Sha256
    volume = [uint32]$Proof.Volume
    fileIndex = ([uint64]$Proof.FileIndex).ToString([Globalization.CultureInfo]::InvariantCulture)
    numberOfLinks = [uint32]$Proof.NumberOfLinks
    attributes = [uint32]$Proof.Attributes
  }
}

function Assert-CanonicalUuid([string]$Value, [string]$Label) {
  if ($Value -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
    throw "$Label is not a canonical lowercase UUID."
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

function Get-NoFollowWindowsSystemExecutableProof(
  [string]$Path,
  [string]$ExpectedDirectory,
  [string]$ExpectedName,
  [string]$Label
) {
  Assert-ExactChildPath $ExpectedDirectory $Path $ExpectedName $Label | Out-Null
  $stream = Open-NoFollowWindowsSystemFile $Path $Label
  try {
    $before = Get-OpenFileIdentity $stream
    $digest = [Security.Cryptography.SHA256]::HashData($stream)
    $after = Get-OpenFileIdentity $stream
    if ($before.attributes -ne $after.attributes -or $before.links -ne $after.links -or
        $before.bytes -ne $after.bytes -or $before.volume -ne $after.volume -or
        $before.index -ne $after.index) {
      throw "$Label changed while its exact no-follow handle was hashed."
    }
    $sha256 = [Convert]::ToHexString($digest).ToLowerInvariant()

    # Keep this original no-write/no-delete-sharing handle open throughout the
    # path-based Authenticode/catalog lookup. The System32 name therefore cannot
    # be swapped to a different signed file and restored between the two hashes.
    $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    if ([string]$signature.Status -cne "Valid" -or $null -eq $signature.SignerCertificate) {
      throw "$Label does not have a valid Windows Authenticode or catalog signature."
    }
    $signerSubject = [string]$signature.SignerCertificate.Subject
    if ($signerSubject -cnotmatch '(?i)(?:^|,\s*)O=Microsoft Corporation(?:,|$)') {
      throw "$Label is not signed by Microsoft Corporation."
    }
    $signerThumbprint = ([string]$signature.SignerCertificate.Thumbprint).ToLowerInvariant()
    if ($signerThumbprint -cnotmatch '^[0-9a-f]{40,128}$') {
      throw "$Label returned an invalid signer thumbprint."
    }

    $stream.Position = 0
    $afterSignatureDigest = [Security.Cryptography.SHA256]::HashData($stream)
    $afterSignature = Get-OpenFileIdentity $stream
    if ($before.attributes -ne $afterSignature.attributes -or
        $before.links -ne $afterSignature.links -or
        $before.bytes -ne $afterSignature.bytes -or
        $before.volume -ne $afterSignature.volume -or
        $before.index -ne $afterSignature.index -or
        $sha256 -cne [Convert]::ToHexString($afterSignatureDigest).ToLowerInvariant()) {
      throw "$Label original Windows-system handle changed while its signature was verified."
    }

    return [PSCustomObject]@{
      FullName = [IO.Path]::GetFullPath($Path)
      Length = [int64]$before.bytes
      Sha256 = $sha256
      Volume = [uint32]$before.volume
      FileIndex = [uint64]$before.index
      Links = [uint32]$before.links
      TrustPolicy = "windows_system32_microsoft_authenticode_v1"
      SignerThumbprint = $signerThumbprint
    }
  } finally {
    $stream.Dispose()
  }
}

function Get-LowerSha256([string]$Path, [uint64]$MaximumBytes = 8GB) {
  return (Get-NoFollowFileSha256Proof $Path "SHA-256 input" $MaximumBytes).Sha256
}

function ConvertTo-LfWslGuestScript([string]$Script, [string]$Label) {
  # Git for Windows can materialize this PowerShell file with CRLF. PowerShell
  # preserves those bytes inside here-strings, but Linux sh requires LF-only
  # command text. Normalize exact CRLF and reject every remaining bare CR.
  if ([String]::IsNullOrWhiteSpace($Script) -or $Script.IndexOf([char]0) -ge 0) {
    throw "$Label is empty or contains a NUL code unit."
  }
  $normalized = $Script.Replace("`r`n", "`n")
  $byteCount = [Text.Encoding]::UTF8.GetByteCount($normalized)
  if ($byteCount -lt 1 -or $byteCount -gt $maximumWslGuestScriptBytes -or
      $normalized.Contains("`r")) {
    throw "$Label did not normalize to one bounded LF-only UTF-8 script."
  }
  return $normalized
}

function Assert-WslGuestScriptNormalizationRegression() {
  $normalized = ConvertTo-LfWslGuestScript "first`r`nsecond`r`n" (
    "CRLF guest-script regression"
  )
  if ($normalized -cne "first`nsecond`n" -or $normalized.Contains("`r")) {
    throw "CRLF guest-script regression did not produce exact LF-only bytes."
  }
  foreach ($fixture in @(
    "first`rsecond",
    "first$([char]0)second",
    ([string]::new([char]120, $maximumWslGuestScriptBytes + 1))
  )) {
    $rejected = $false
    try { ConvertTo-LfWslGuestScript $fixture "Invalid guest-script regression" | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) {
      throw "Guest-script normalization accepted a forbidden regression fixture."
    }
  }
}

function Complete-BoundedProcessCapture(
  [object]$StdoutTask,
  [object]$StderrTask,
  [object]$StdoutCapture,
  [object]$StderrCapture,
  [string]$Label
) {
  if ($null -eq $StdoutTask -or $null -eq $StderrTask -or
      $null -eq $StdoutCapture -or $null -eq $StderrCapture) {
    throw "$Label has no complete redirected-output lease."
  }
  $drain = [Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@(
    $StdoutTask,
    $StderrTask
  ))
  try { $drained = $drain.Wait(5000) }
  catch { throw "$Label output drain failed within its fixed deadline." }
  if (-not $drained -or -not $drain.IsCompletedSuccessfully) {
    throw "$Label output did not drain within its fixed deadline."
  }
  [byte[]]$stdoutBytes = $StdoutCapture.Snapshot()
  [byte[]]$stderrBytes = $StderrCapture.Snapshot()
  try {
    $stdout = [Text.UTF8Encoding]::new(
      $false,
      -not $StdoutCapture.Overflowed
    ).GetString($stdoutBytes)
    $stderr = [Text.UTF8Encoding]::new(
      $false,
      -not $StderrCapture.Overflowed
    ).GetString($stderrBytes)
  } catch {
    throw "$Label output was not valid UTF-8."
  }
  if ($stdout.IndexOf([char]0) -ge 0 -or $stderr.IndexOf([char]0) -ge 0) {
    throw "$Label output contained a NUL code unit."
  }
  return [PSCustomObject]@{
    stdout = $stdout
    stderr = $stderr
    stdoutBytes = [int]$stdoutBytes.Length
    stderrBytes = [int]$stderrBytes.Length
    stdoutOverflowed = [bool]$StdoutCapture.Overflowed
    stderrOverflowed = [bool]$StderrCapture.Overflowed
  }
}

function Assert-BoundedCaptureStreamRegression() {
  $capture = [GhostQualificationBoundedCaptureStream]::new(8)
  [byte[]]$first = 1, 2, 3, 4, 5, 6, 7, 8, 9
  [byte[]]$later = 10, 11, 12
  $capture.Write($first, 0, $first.Length)
  $capture.Write($later, 0, $later.Length)
  [byte[]]$snapshot = $capture.Snapshot()
  if (-not $capture.Overflowed -or $snapshot.Length -ne 8 -or
      [Convert]::ToHexString($snapshot) -cne "0102030405060708") {
    throw "Bounded process capture did not retain its exact prefix while continuing to drain."
  }
  $capture.Dispose()

  [byte[]]$payload = 0..31
  $source = [IO.MemoryStream]::new($payload, $false)
  $asyncCapture = [GhostQualificationBoundedCaptureStream]::new(8)
  try {
    $copy = $source.CopyToAsync($asyncCapture)
    if (-not $copy.Wait(1000) -or -not $copy.IsCompletedSuccessfully -or
        $source.Position -ne $source.Length -or -not $asyncCapture.Overflowed -or
        $asyncCapture.Snapshot().Length -ne 8) {
      throw "Bounded async process capture stopped draining after its prefix filled."
    }
  } finally {
    $asyncCapture.Dispose()
    $source.Dispose()
  }
}

function Get-SingleLineProcessDiagnostic([object]$Output) {
  $diagnostic = (([string]$Output.stderr) + " " + ([string]$Output.stdout)).Trim()
  $sanitized = [Text.StringBuilder]::new($diagnostic.Length)
  foreach ($character in $diagnostic.ToCharArray()) {
    $code = [int]$character
    if ($code -lt 32 -or ($code -ge 127 -and $code -le 159) -or
        $code -eq 0x2028 -or $code -eq 0x2029) {
      $sanitized.Append(" ") | Out-Null
    } else {
      $sanitized.Append($character) | Out-Null
    }
  }
  $diagnostic = $sanitized.ToString().Trim()
  if ($diagnostic.Length -gt 4096) {
    $diagnostic = $diagnostic.Substring(0, 4096) + " (truncated)"
  }
  if ($diagnostic.Length -eq 0) { return "no diagnostic output" }
  return $diagnostic
}

function Invoke-ExactProcess(
  [string]$FileName,
  [string[]]$Arguments,
  [int]$TimeoutMilliseconds,
  [string]$Label,
  [bool]$CaptureOutput = $false,
  [Collections.Generic.Dictionary[string,string]]$Environment = $null,
  [object]$ExpectedExecutableProof = $null,
  [object]$ExpectedSystemExecutableProof = $null,
  [bool]$KeepRunning = $false,
  [switch]$AllowRestartRequired,
  [switch]$AllowRetainedState,
  [string]$RawFinalNsisUninstallDirectory = ""
) {
  if ($TimeoutMilliseconds -lt 1000 -or $TimeoutMilliseconds -gt 1800000) {
    throw "$Label timeout is outside its fixed bound."
  }
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $FileName
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $CaptureOutput
  $startInfo.RedirectStandardError = $CaptureOutput
  if ($KeepRunning -and -not $CaptureOutput) {
    throw "$Label must retain bounded redirected output with its process lease."
  }
  if ([String]::IsNullOrEmpty($RawFinalNsisUninstallDirectory)) {
    foreach ($argument in $Arguments) { $startInfo.ArgumentList.Add($argument) }
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
  if ($null -ne $Environment) {
    $startInfo.Environment.Clear()
    foreach ($entry in $Environment.GetEnumerator()) { $startInfo.Environment[$entry.Key] = $entry.Value }
  }
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  $started = $false
  $processLeaseReturned = $false
  $stdoutTask = $null
  $stderrTask = $null
  $stdoutCapture = $null
  $stderrCapture = $null
  try {
    if ($null -ne $ExpectedExecutableProof -and $null -ne $ExpectedSystemExecutableProof) {
      throw "$Label cannot use both product-file and Windows-system executable proofs."
    }
    $isTrustedWindowsSystemExecutable = $null -ne $ExpectedSystemExecutableProof
    $proof = if ($isTrustedWindowsSystemExecutable) { $ExpectedSystemExecutableProof } else { $ExpectedExecutableProof }
    $executionGuard = if ($isTrustedWindowsSystemExecutable) {
      Open-NoFollowWindowsSystemFile $FileName "$Label executable" (512 * 1024 * 1024)
    } else {
      Open-NoFollowSingleLinkFile $FileName "$Label executable" (512 * 1024 * 1024)
    }
    try {
      if ($null -ne $proof) {
        foreach ($requiredProofField in @("FullName", "Length", "Sha256", "Volume", "FileIndex")) {
          if ($null -eq $proof.PSObject.Properties[$requiredProofField]) {
            throw "$Label has an incomplete expected executable proof."
          }
        }
        if (-not [String]::Equals(
            [IO.Path]::GetFullPath($FileName),
            [string]$proof.FullName,
            [StringComparison]::OrdinalIgnoreCase
          ) -or [int64]$proof.Length -lt 1 -or
          [string]$proof.Sha256 -cnotmatch '^[0-9a-f]{64}$') {
          throw "$Label has a malformed expected executable proof."
        }
        if ($isTrustedWindowsSystemExecutable) {
          foreach ($requiredSystemProofField in @("Links", "TrustPolicy", "SignerThumbprint")) {
            if ($null -eq $proof.PSObject.Properties[$requiredSystemProofField]) {
              throw "$Label has an incomplete Windows-system executable proof."
            }
          }
          if ([uint32]$proof.Links -lt 1 -or
              [string]$proof.TrustPolicy -cne "windows_system32_microsoft_authenticode_v1" -or
              [string]$proof.SignerThumbprint -cnotmatch '^[0-9a-f]{40,128}$') {
            throw "$Label has a malformed Windows-system executable proof."
          }
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
        if ([uint64]$beforeExecution.bytes -ne [uint64]$proof.Length -or
            [uint32]$beforeExecution.volume -ne [uint32]$proof.Volume -or
            [uint64]$beforeExecution.index -ne [uint64]$proof.FileIndex -or
            ($isTrustedWindowsSystemExecutable -and [uint32]$beforeExecution.links -ne [uint32]$proof.Links) -or
            $executionSha256 -cne [string]$proof.Sha256) {
          throw "$Label executable is not the exact previously verified installer."
        }
        $executionGuard.Position = 0
      }
      $started = $process.Start()
      if ($null -ne $proof) {
        $afterStart = Get-OpenFileIdentity $executionGuard
        if ([uint64]$afterStart.bytes -ne [uint64]$proof.Length -or
            [uint32]$afterStart.volume -ne [uint32]$proof.Volume -or
            [uint64]$afterStart.index -ne [uint64]$proof.FileIndex -or
            ($isTrustedWindowsSystemExecutable -and [uint32]$afterStart.links -ne [uint32]$proof.Links)) {
          throw "$Label executable changed while the verified process was started."
        }
      }
    } finally {
      $executionGuard.Dispose()
    }
    if (-not $started) { throw "$Label did not start." }
    if ($CaptureOutput) {
      $captureLimit = if ($KeepRunning) {
        $maximumRetainedProcessOutputBytes
      } else {
        1024 * 1024
      }
      $stdoutCapture = [GhostQualificationBoundedCaptureStream]::new($captureLimit)
      $stderrCapture = [GhostQualificationBoundedCaptureStream]::new($captureLimit)
      $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdoutCapture)
      $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderrCapture)
    }
    if ($KeepRunning) {
      $process.Refresh()
      if ($process.HasExited) {
        $output = Complete-BoundedProcessCapture $stdoutTask $stderrTask $stdoutCapture (
          $stderrCapture
        ) "$Label retained startup"
        $overflow = if ($output.stdoutOverflowed -or $output.stderrOverflowed) {
          " (output exceeded the fixed byte bound)"
        } else { "" }
        throw "$Label exited with status $($process.ExitCode) before its foreground process lease could be retained${overflow}: $(Get-SingleLineProcessDiagnostic $output)"
      }
      $processStartedAt = $process.StartTime.ToUniversalTime().ToString(
        "o",
        [Globalization.CultureInfo]::InvariantCulture
      )
      $processLeaseReturned = $true
      return [PSCustomObject]@{
        Process = $process
        ProcessId = [int]$process.Id
        ProcessStartedAt = $processStartedAt
        StdoutTask = $stdoutTask
        StderrTask = $stderrTask
        StdoutCapture = $stdoutCapture
        StderrCapture = $stderrCapture
      }
    }
    if (-not $process.WaitForExit($TimeoutMilliseconds)) {
      try { $process.Kill($true) } catch {}
      $process.WaitForExit(5000) | Out-Null
      throw "$Label exceeded its fixed deadline."
    }
    $stdout = ""
    $stderr = ""
    if ($CaptureOutput) {
      $output = Complete-BoundedProcessCapture $stdoutTask $stderrTask $stdoutCapture (
        $stderrCapture
      ) $Label
      if ($output.stdoutOverflowed -or $output.stderrOverflowed) {
        throw "$Label output exceeded its fixed byte bound."
      }
      $stdout = [string]$output.stdout
      $stderr = [string]$output.stderr
    }
    if ($process.ExitCode -ne 0 -and
        (-not $AllowRestartRequired -or $process.ExitCode -ne 3010) -and
        (-not $AllowRetainedState -or $process.ExitCode -ne 10)) {
      $bounded = Get-SingleLineProcessDiagnostic ([PSCustomObject]@{
        stdout = $stdout
        stderr = $stderr
      })
      throw "$Label failed with status $($process.ExitCode): $bounded"
    }
    return [ordered]@{ stdout = $stdout; stderr = $stderr; exitCode = $process.ExitCode }
  } finally {
    if (-not $processLeaseReturned) {
      if ($started) {
        try {
          $process.Refresh()
          if (-not $process.HasExited) {
            $process.Kill($true)
            $process.WaitForExit(5000) | Out-Null
          }
        } catch {}
      }
      if ($CaptureOutput -and $null -ne $stdoutTask -and $null -ne $stderrTask) {
        try {
          Complete-BoundedProcessCapture $stdoutTask $stderrTask $stdoutCapture $stderrCapture (
            "$Label cleanup"
          ) | Out-Null
        } catch {}
      }
      $process.Dispose()
    }
  }
}

function Invoke-BoundedCopiedNsisUninstaller(
  [string]$SourceUninstaller,
  [string]$InstallDirectory,
  [string]$WorkRoot,
  [string]$Label,
  [switch]$AllowRetainedState
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

    $result = Invoke-ExactProcess $copyPath @("/S") 180000 $Label -ExpectedExecutableProof $copyProof -AllowRetainedState:$AllowRetainedState -RawFinalNsisUninstallDirectory $InstallDirectory
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

function Invoke-CliJson([string]$Cli, [string[]]$Arguments, [int]$TimeoutMilliseconds, [string]$Label) {
  $result = Invoke-ExactProcess $Cli $Arguments $TimeoutMilliseconds $Label $true
  try { return $result.stdout | ConvertFrom-Json -DateKind String }
  catch { throw "$Label did not emit one valid JSON document." }
}

function Get-CliVersion([string]$Cli, [string]$Label) {
  $result = Invoke-ExactProcess $Cli @("--version") 30000 "$Label version probe" $true
  $match = [Text.RegularExpressions.Regex]::Match(
    $result.stdout.Trim(),
    "^ai-security-scanner ([0-9]+[.][0-9]+[.][0-9]+)$",
    [Text.RegularExpressions.RegexOptions]::CultureInvariant
  )
  if (-not $match.Success) { throw "$Label returned an unexpected version string." }
  return $match.Groups[1].Value
}

function Find-OneInstalledFile([string]$InstallDirectory, [string]$Name) {
  $matches = @(
    Get-ChildItem -LiteralPath $InstallDirectory -Filter $Name -File -Recurse -Force |
      Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 }
  )
  if ($matches.Count -ne 1) { throw "Expected one installed $Name, found $($matches.Count)." }
  $path = [IO.Path]::GetFullPath($matches[0].FullName)
  $prefix = [IO.Path]::GetFullPath($InstallDirectory) + [IO.Path]::DirectorySeparatorChar
  if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Installed $Name escaped the exact install directory."
  }
  Assert-SingleLinkFile $path "Installed $Name" | Out-Null
  return $path
}

function Get-OptionalRegistryString([object]$Properties, [string]$Name) {
  $property = $Properties.PSObject.Properties[$Name]
  if ($null -eq $property -or $null -eq $property.Value) { return "" }
  return [string]$property.Value
}

function Assert-ExactJsonProperties([object]$Value, [string[]]$ExpectedNames, [string]$Label) {
  if ($null -eq $Value) { throw "$Label is not a JSON object." }
  [string[]]$actualNames = @($Value.PSObject.Properties.Name)
  if ($actualNames.Count -ne $ExpectedNames.Count) {
    throw "$Label has an unexpected field count."
  }
  foreach ($expectedName in $ExpectedNames) {
    if (-not ($actualNames -ccontains $expectedName)) {
      throw "$Label is missing exact field $expectedName."
    }
  }
}

function Get-ComparableWindowsPath([string]$Path, [string]$Label) {
  if ([String]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathFullyQualified($Path)) {
    throw "$Label is not an absolute Windows path."
  }
  $full = [IO.Path]::GetFullPath($Path)
  if ($full.StartsWith("\\?\UNC\", [StringComparison]::OrdinalIgnoreCase)) {
    $full = "\\" + $full.Substring(8)
  } elseif ($full.StartsWith("\\?\", [StringComparison]::OrdinalIgnoreCase)) {
    $full = $full.Substring(4)
  }
  return $full.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}

function Assert-SameWindowsPath([string]$Actual, [string]$Expected, [string]$Label) {
  $actualPath = Get-ComparableWindowsPath $Actual "$Label reported path"
  $expectedPath = Get-ComparableWindowsPath $Expected "$Label expected path"
  if (-not [String]::Equals($actualPath, $expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label is not bound to its exact data-preservation fixture path."
  }
}

function Get-ProductRegistryEntries {
  $root = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
  if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
  $children = @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)
  if ($children.Count -gt 512) { throw "Current-user uninstall registry exceeded its bound." }
  return @(
    $children | ForEach-Object {
      $properties = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
      if ((Get-OptionalRegistryString $properties "DisplayName") -ceq "ai-security-scanner") {
        $versionedReceiptProperties = @(
          $properties.PSObject.Properties.Name |
            Where-Object { $_ -cmatch '(?i)(transition|migration|receipt)' }
        )
        [PSCustomObject]@{
          KeyPath = $_.PSPath
          KeyName = $_.PSChildName
          DisplayName = Get-OptionalRegistryString $properties "DisplayName"
          Publisher = Get-OptionalRegistryString $properties "Publisher"
          DisplayVersion = Get-OptionalRegistryString $properties "DisplayVersion"
          InstallLocation = Get-OptionalRegistryString $properties "InstallLocation"
          UninstallString = Get-OptionalRegistryString $properties "UninstallString"
          MainBinaryName = Get-OptionalRegistryString $properties "MainBinaryName"
          NoVersionedReceipt = ($versionedReceiptProperties.Count -eq 0)
        }
      }
    }
  )
}

function Get-ExactProductRegistry([string]$ExpectedVersion, [string]$InstallDirectory) {
  $entries = @(Get-ProductRegistryEntries)
  if ($entries.Count -ne 1) { throw "Expected one ai-security-scanner HKCU registration, found $($entries.Count)." }
  $entry = $entries[0]
  $quotedInstall = '"' + [IO.Path]::GetFullPath($InstallDirectory) + '"'
  $quotedUninstall = '"' + [IO.Path]::GetFullPath((Join-Path $InstallDirectory "uninstall.exe")) + '"'
  if ($entry.KeyName -cne "ai-security-scanner" -or
      $entry.DisplayName -cne "ai-security-scanner" -or
      $entry.Publisher -cne "ai-security-scanner contributors" -or
      $entry.DisplayVersion -cne $ExpectedVersion -or
      $entry.MainBinaryName -cne "ai-security-scanner.exe" -or
      -not [String]::Equals($entry.InstallLocation, $quotedInstall, [StringComparison]::OrdinalIgnoreCase) -or
      -not [String]::Equals($entry.UninstallString, $quotedUninstall, [StringComparison]::OrdinalIgnoreCase)) {
    throw "The HKCU product registration is not the exact bounded NSIS identity."
  }
  return $entry
}

function Resolve-RealDirectory([string]$Path, [string]$Label) {
  $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
  Assert-RealDirectory $resolved $Label | Out-Null
  return [IO.Path]::GetFullPath($resolved)
}

function Get-WslRegistrations {
  $root = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss"
  if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
  $children = @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)
  if ($children.Count -gt 256) { throw "WSL registration registry exceeded its data-preservation fixture bound." }
  return @(
    $children | ForEach-Object {
      $properties = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
      $name = Get-OptionalRegistryString $properties "DistributionName"
      $basePath = Get-OptionalRegistryString $properties "BasePath"
      if (-not [String]::IsNullOrWhiteSpace($name)) {
        $registrationId = ([Guid]::Parse($_.PSChildName.Trim('{', '}'))).ToString("D").ToLowerInvariant()
        [PSCustomObject]@{
          Name = $name
          BasePath = $basePath
          KeyPath = $_.PSPath
          RegistrationId = $registrationId
        }
      }
    }
  )
}

function Get-ExactWslRegistration([string]$Name, [string]$ExpectedBasePath) {
  $matches = @(Get-WslRegistrations | Where-Object {
    [String]::Equals($_.Name, $Name, [StringComparison]::Ordinal)
  })
  if ($matches.Count -ne 1) { throw "Expected one exact WSL registration for $Name, found $($matches.Count)." }
  $registeredBasePath = Get-BoundedAbsoluteWindowsPath $matches[0].BasePath (
    "Exact WSL registration BasePath"
  )
  $boundedExpectedBasePath = Get-BoundedAbsoluteWindowsPath $ExpectedBasePath (
    "Expected managed WSL BasePath"
  )
  Assert-SameNoFollowDirectoryIdentity $registeredBasePath $boundedExpectedBasePath (
    "Exact WSL registration for $Name"
  )
  return $matches[0]
}

function Assert-NoFollowDirectoryIdentityRegression([string]$Parent) {
  $fixtureName = "directory-identity-regression"
  $fixtureRoot = Assert-ExactChildPath $Parent (Join-Path $Parent $fixtureName) $fixtureName (
    "Directory identity regression fixture"
  )
  if (Test-Path -LiteralPath $fixtureRoot) {
    throw "Directory identity regression fixture already exists."
  }
  New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
  try {
    $sameDirectory = Assert-ExactChildPath $fixtureRoot (
      Join-Path $fixtureRoot "same"
    ) "same" "Same-directory identity fixture"
    $differentDirectory = Assert-ExactChildPath $fixtureRoot (
      Join-Path $fixtureRoot "different"
    ) "different" "Different-directory identity fixture"
    New-Item -ItemType Directory -Path $sameDirectory | Out-Null
    New-Item -ItemType Directory -Path $differentDirectory | Out-Null

    $extendedSameDirectory = Get-VerbatimWindowsPath $sameDirectory (
      "Extended-prefix same-directory identity fixture"
    )
    if ([String]::Equals($sameDirectory, $extendedSameDirectory, [StringComparison]::Ordinal)) {
      throw "Directory identity regression did not exercise two Windows path spellings."
    }
    Assert-SameNoFollowDirectoryIdentity $sameDirectory $extendedSameDirectory (
      "Same-directory extended-prefix regression"
    )

    $differentRejected = $false
    try {
      Assert-SameNoFollowDirectoryIdentity $sameDirectory $differentDirectory (
        "Different-directory regression"
      )
    } catch {
      if ($_.Exception.Message -cne (
          "Different-directory regression does not refer to the exact same directory object."
        )) { throw }
      $differentRejected = $true
    }
    if (-not $differentRejected) {
      throw "Directory identity comparison accepted two different directory objects."
    }
  } finally {
    Remove-ExactTree $fixtureRoot $Parent $fixtureName "Directory identity regression fixture"
  }
}

function Get-PreservedDataSnapshot([string]$Root) {
  Assert-RealDirectory $Root "Private application data root" | Out-Null
  $rootPath = [IO.Path]::GetFullPath($Root)
  $files = [Collections.Generic.List[object]]::new()
  [int64]$totalBytes = 0
  $items = @(Get-ChildItem -LiteralPath $rootPath -Force -Recurse)
  if ($items.Count -gt $maximumSnapshotFiles * 4) { throw "Preserved data tree exceeded its entry bound." }
  foreach ($item in $items) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Private application data contains a reparse-point entry."
    }
    $relative = [IO.Path]::GetRelativePath($rootPath, $item.FullName).Replace('\', '/')
    # Runtime maintenance legitimately leaves this one empty, root-level
    # process-coordination file behind. Prove its exact empty regular-file shape
    # before excluding it; every other empty file remains fail-closed through
    # Get-NoFollowFileSha256Proof below.
    if (-not $item.PSIsContainer -and $relative -ceq $processLeaseRelativePath) {
      Assert-ExactEmptyProcessLeaseFile $item.FullName "Root process lease"
      continue
    }
    if ($relative -eq "managed-runtime" -or $relative.StartsWith("managed-runtime/", [StringComparison]::Ordinal)) {
      continue
    }
    if ($item.PSIsContainer) { continue }
    if ($files.Count -eq $maximumSnapshotFiles) { throw "Preserved data exceeded its file-count bound." }
    $fileProof = Get-NoFollowFileSha256Proof $item.FullName "Preserved data file" $maximumSnapshotBytes
    $totalBytes += [int64]$fileProof.Length
    if ($totalBytes -gt $maximumSnapshotBytes) { throw "Preserved data exceeded its byte bound." }
    $files.Add([ordered]@{
      path = $relative
      bytes = [int64]$fileProof.Length
      sha256 = [string]$fileProof.Sha256
    })
  }
  $ordered = @($files | Sort-Object { $_.path })
  $encoded = ConvertTo-Json -InputObject $ordered -Compress -Depth 5
  $digest = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($encoded))
  ).ToLowerInvariant()
  return [ordered]@{ fileCount = $ordered.Count; totalBytes = $totalBytes; digest = $digest }
}

function Get-NonLeasePrivateDataSnapshot([string]$Root) {
  Assert-RealDirectory $Root "Non-lease private application data root" | Out-Null
  $rootPath = [IO.Path]::GetFullPath($Root)
  $files = [Collections.Generic.List[object]]::new()
  [int64]$totalBytes = 0
  $items = @(Get-ChildItem -LiteralPath $rootPath -Force -Recurse)
  if ($items.Count -gt $maximumSnapshotFiles * 4) {
    throw "Non-lease private data tree exceeded its entry bound."
  }
  foreach ($item in $items) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Non-lease private data contains a reparse-point entry."
    }
    if ($item.PSIsContainer) { continue }
    if ($files.Count -eq $maximumSnapshotFiles) {
      throw "Non-lease private data exceeded its file-count bound."
    }
    $relative = [IO.Path]::GetRelativePath($rootPath, $item.FullName).Replace('\', '/')
    if ($relative -ceq $processLeaseRelativePath) {
      Assert-ExactEmptyProcessLeaseFile $item.FullName "Root process lease"
      continue
    }
    if ([int64]$item.Length -eq 0) {
      $emptyProof = Get-NoFollowEmptyFileProof $item.FullName "Non-lease private data empty file"
      $fileRecord = [ordered]@{
        path = $relative
        bytes = [int64]$emptyProof.Length
        sha256 = [string]$emptyProof.Sha256
      }
    } else {
      $fileProof = Get-NoFollowFileSha256Proof $item.FullName (
        "Non-lease private data file"
      ) $maximumCompleteSnapshotBytes
      $fileRecord = [ordered]@{
        path = $relative
        bytes = [int64]$fileProof.Length
        sha256 = [string]$fileProof.Sha256
      }
    }
    $totalBytes += [int64]$fileRecord.bytes
    if ($totalBytes -gt $maximumCompleteSnapshotBytes) {
      throw "Non-lease private data exceeded its byte bound."
    }
    $files.Add($fileRecord)
  }
  $ordered = @($files | Sort-Object { $_.path })
  $encoded = ConvertTo-Json -InputObject $ordered -Compress -Depth 5
  $digest = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($encoded))
  ).ToLowerInvariant()
  return [ordered]@{ fileCount = $ordered.Count; totalBytes = $totalBytes; digest = $digest }
}

function Assert-PreservedDataSnapshotHousekeepingRegression([string]$Parent) {
  $fixtureName = "preserved-data-housekeeping-regression"
  $fixtureRoot = Assert-ExactChildPath $Parent (Join-Path $Parent $fixtureName) $fixtureName (
    "Preserved-data housekeeping regression fixture"
  )
  if (Test-Path -LiteralPath $fixtureRoot) {
    throw "Preserved-data housekeeping regression fixture already exists."
  }
  New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
  try {
    [byte[]]$payloadBytes = [Text.Encoding]::UTF8.GetBytes("preserved-user-data")
    [IO.File]::WriteAllBytes((Join-Path $fixtureRoot "user-data.bin"), $payloadBytes)
    [IO.File]::WriteAllBytes((Join-Path $fixtureRoot $processLeaseRelativePath), [byte[]]::new(0))

    $snapshot = Get-PreservedDataSnapshot $fixtureRoot
    if ($snapshot.fileCount -ne 1 -or $snapshot.totalBytes -ne $payloadBytes.Length) {
      throw "Preserved-data snapshot did not exclude only the exact root process lease."
    }

    $nestedDirectory = Assert-ExactChildPath $fixtureRoot (
      Join-Path $fixtureRoot "nested"
    ) "nested" "Nested process-lease regression directory"
    New-Item -ItemType Directory -Path $nestedDirectory | Out-Null
    [IO.File]::WriteAllBytes(
      (Join-Path $nestedDirectory $processLeaseRelativePath),
      [byte[]]::new(0)
    )
    $nestedLeaseRejected = $false
    try {
      Get-PreservedDataSnapshot $fixtureRoot | Out-Null
    } catch {
      if ($_.Exception.Message -cne "Preserved data file is not one bounded no-follow single-link regular file.") {
        throw
      }
      $nestedLeaseRejected = $true
    }
    if (-not $nestedLeaseRejected) {
      throw "Preserved-data snapshot ignored a nested process-lease-shaped file."
    }
  } finally {
    Remove-ExactTree $fixtureRoot $Parent $fixtureName "Preserved-data housekeeping regression fixture"
  }
}

function Read-BoundedUtf8File(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = 64 * 1024
) {
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

function Read-BoundedJsonFile(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = 64 * 1024
) {
  $record = Read-BoundedUtf8File $Path $Label $MaximumBytes
  try {
    return $record.Text | ConvertFrom-Json -DateKind String
  } catch {
    throw "$Label is not one stable bounded UTF-8 JSON document: $($_.Exception.Message)"
  }
}

function Get-LowerSha256Bytes([byte[]]$Bytes) {
  return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Remove-ExactTree([string]$Path, [string]$Parent, [string]$ExpectedName, [string]$Label) {
  Assert-ExactChildPath $Parent $Path $ExpectedName $Label | Out-Null
  if (Test-Path -LiteralPath $Path) {
    Assert-RealDirectory $Path $Label | Out-Null
    Remove-Item -LiteralPath $Path -Recurse -Force
  }
  if (Test-Path -LiteralPath $Path) { throw "$Label remains after exact cleanup." }
}

function Download-PinnedPriorInstaller([string]$Destination) {
  $handler = [Net.Http.HttpClientHandler]::new()
  $handler.AllowAutoRedirect = $true
  $handler.MaxAutomaticRedirections = 5
  $handler.UseCookies = $false
  $client = [Net.Http.HttpClient]::new($handler)
  $client.Timeout = [TimeSpan]::FromMinutes(5)
  try {
    $response = $client.GetAsync($priorInstallerUrl, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
    try {
      $response.EnsureSuccessStatusCode() | Out-Null
      if ($null -ne $response.Content.Headers.ContentLength -and
          ($response.Content.Headers.ContentLength -ne $priorInstallerBytes -or
           $response.Content.Headers.ContentLength -gt $maximumDownloadBytes)) {
        throw "Pinned v0.1.7 installer Content-Length changed."
      }
      $input = $response.Content.ReadAsStream()
      $output = [IO.FileStream]::new($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try {
        [byte[]]$buffer = [byte[]]::new(64 * 1024)
        [int64]$written = 0
        while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
          $written += $read
          if ($written -gt $maximumDownloadBytes) { throw "Pinned v0.1.7 installer exceeded its download bound." }
          $output.Write($buffer, 0, $read)
        }
        $output.Flush($true)
      } finally {
        $output.Dispose()
        $input.Dispose()
      }
    } finally { $response.Dispose() }
  } finally {
    $client.Dispose()
    $handler.Dispose()
  }
  $proof = Get-NoFollowFileSha256Proof $Destination "Pinned v0.1.7 installer" $maximumDownloadBytes
  if ($proof.Length -ne $priorInstallerBytes -or $proof.Sha256 -cne $priorInstallerSha256) {
    throw "Downloaded v0.1.7 installer differs from its immutable pin."
  }
  return $proof
}

function Get-TrustedWslExecutable {
  $buffer = [Text.StringBuilder]::new(32768)
  $length = [GhostQualificationNativeMethods]::GetSystemWindowsDirectoryW($buffer, [uint32]$buffer.Capacity)
  if ($length -eq 0 -or $length -ge $buffer.Capacity) { throw "Could not resolve OS-trusted Windows directory." }
  $windows = Resolve-RealDirectory $buffer.ToString() "OS-trusted Windows directory"
  $system32 = Resolve-RealDirectory (Join-Path $windows "System32") "OS-trusted System32"
  $wsl = Join-Path $system32 "wsl.exe"
  $proof = Get-NoFollowWindowsSystemExecutableProof $wsl $system32 "wsl.exe" "OS-trusted wsl.exe"
  return [ordered]@{ executable = $wsl; windows = $windows; system32 = $system32; proof = $proof }
}

function Invoke-TrustedWsl(
  [object]$TrustedWsl,
  [string[]]$Arguments,
  [int]$TimeoutMilliseconds,
  [string]$Label,
  [bool]$CaptureOutput = $true
) {
  $environment = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
  $environment["SystemRoot"] = $TrustedWsl.windows
  $environment["WINDIR"] = $TrustedWsl.windows
  $environment["PATH"] = $TrustedWsl.system32
  $environment["NoDefaultCurrentDirectoryInExePath"] = "1"
  $environment["WSL_UTF8"] = "1"
  return Invoke-ExactProcess $TrustedWsl.executable $Arguments $TimeoutMilliseconds $Label (
    $CaptureOutput
  ) $environment -ExpectedSystemExecutableProof $TrustedWsl.proof
}

function Get-WslRunningDistributionNames(
  [object]$TrustedWsl,
  [string]$Label
) {
  $result = Invoke-TrustedWsl $TrustedWsl @(
    "--list", "--running", "--quiet"
  ) 30000 "$Label running inventory" $true
  $output = [string]$result.stdout
  if ($output.IndexOf([char]0) -ge 0 -or
      [Text.Encoding]::UTF8.GetByteCount($output) -gt 64 * 1024) {
    throw "$Label running inventory is malformed or exceeded its byte bound."
  }
  $names = [Collections.Generic.List[string]]::new()
  foreach ($rawLine in [Text.RegularExpressions.Regex]::Split($output, "\r?\n")) {
    $line = $rawLine.Trim()
    if ($line.Length -gt 0 -and $line[0] -eq [char]0xfeff) {
      $line = $line.Substring(1)
    }
    if ($line.Length -eq 0) { continue }
    if ($line.Length -gt 256 -or $line.IndexOfAny([char[]]@("`r", "`n", "`0")) -ge 0) {
      throw "$Label running inventory contains an invalid distribution name."
    }
    $names.Add($line)
    if ($names.Count -gt 256) { throw "$Label running inventory exceeded its entry bound." }
  }
  return @($names)
}

function Assert-ExactFixtureWslRegistrationSet(
  [object[]]$ExpectedRegistrations,
  [string]$Label
) {
  if ($ExpectedRegistrations.Count -ne 2) {
    throw "$Label requires exactly two fixture-owned WSL registrations."
  }
  $actualRegistrations = @(Get-WslRegistrations)
  if ($actualRegistrations.Count -ne $ExpectedRegistrations.Count) {
    throw "$Label refused a WSL registration set outside the two exact fixtures."
  }
  $seenNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($expected in $ExpectedRegistrations) {
    $name = [string]$expected.Name
    $basePath = [string]$expected.BasePath
    $registrationId = [string]$expected.RegistrationId
    if ([String]::IsNullOrWhiteSpace($name) -or
        [String]::IsNullOrWhiteSpace($basePath) -or
        $registrationId -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or
        -not $seenNames.Add($name)) {
      throw "$Label received a malformed or duplicate expected WSL registration."
    }
    $actual = Get-ExactWslRegistration $name $basePath
    if ([string]$actual.RegistrationId -cne $registrationId) {
      throw "$Label found a rebound fixture WSL registration."
    }
  }
  return @($actualRegistrations)
}

function Invoke-FixtureOnlyWslShutdown(
  [object]$TrustedWsl,
  [object[]]$ExpectedRegistrations,
  [string]$Label
) {
  Assert-ExactFixtureWslRegistrationSet $ExpectedRegistrations (
    "$Label before shutdown"
  ) | Out-Null
  $runningBefore = @(Get-WslRunningDistributionNames $TrustedWsl "$Label before shutdown")
  if ($runningBefore.Count -ne 0) {
    throw "$Label refused to stop a running WSL distribution."
  }
  $shutdown = Invoke-TrustedWsl $TrustedWsl @("--shutdown") 90000 $Label
  if (-not [String]::IsNullOrWhiteSpace([string]$shutdown.stdout) -or
      -not [String]::IsNullOrWhiteSpace([string]$shutdown.stderr)) {
    throw "$Label emitted unexpected output."
  }
  Assert-ExactFixtureWslRegistrationSet $ExpectedRegistrations (
    "$Label after shutdown"
  ) | Out-Null
  $runningAfter = @(Get-WslRunningDistributionNames $TrustedWsl "$Label after shutdown")
  if ($runningAfter.Count -ne 0) {
    throw "$Label left a WSL distribution running."
  }
}

function Get-WslSentinelGuestIdentity(
  [object]$TrustedWsl,
  [string]$DistributionName,
  [string]$Token,
  [string]$Label,
  [int]$TimeoutMilliseconds = 30000
) {
  if ($Token -cnotmatch '^[0-9a-f]{32}$') { throw "$Label sentinel token is malformed." }
  $command = @'
set -eu
token='__TOKEN__'
state="/run/assm-qc-sentinel-$token"
test -f "$state"
test ! -L "$state"
test "$(wc -l < "$state")" -eq 4
set -- $(cat "$state")
test "$#" -eq 4
test "$1" = "$token"
pid="$2"
start_ticks="$3"
boot_id="$4"
case "$pid" in ''|*[!0-9]*|0) exit 21;; esac
case "$start_ticks" in ''|*[!0-9]*|0) exit 22;; esac
case "$boot_id" in ????????-????-????-????-????????????) ;; *) exit 23;; esac
test -r "/proc/$pid/stat"
test "$(awk '{ print $22 }' "/proc/$pid/stat")" = "$start_ticks"
test "$(cat /proc/sys/kernel/random/boot_id)" = "$boot_id"
test "$(readlink "/proc/$pid/exe")" = "/usr/bin/sleep"
test "$(cat "/proc/$pid/comm")" = "sleep"
kill -0 "$pid"
printf '%s\n%s\n%s\n' "$pid" "$start_ticks" "$boot_id"
'@.Replace("__TOKEN__", $Token)
  $command = ConvertTo-LfWslGuestScript $command "$Label guest identity script"
  $result = Invoke-TrustedWsl $TrustedWsl @(
    "--distribution", $DistributionName, "--user", "root", "--exec", "sh", "-c", $command
  ) $TimeoutMilliseconds "$Label guest identity" $true
  $output = [string]$result.stdout
  if ($output.IndexOf([char]0) -ge 0 -or
      [Text.Encoding]::UTF8.GetByteCount($output) -gt 4096) {
    throw "$Label guest identity output is malformed or exceeded its byte bound."
  }
  $lines = @(
    [Text.RegularExpressions.Regex]::Split($output, "\r?\n") |
      Where-Object { $_.Length -gt 0 }
  )
  if ($lines.Count -ne 3 -or
      $lines[0] -cnotmatch '^[1-9][0-9]{0,9}$' -or
      $lines[1] -cnotmatch '^[1-9][0-9]{0,19}$' -or
      $lines[2] -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
    throw "$Label guest identity did not return its exact bounded shape."
  }
  return [PSCustomObject]@{
    LinuxPid = [uint64]::Parse($lines[0], [Globalization.CultureInfo]::InvariantCulture)
    LinuxStartTicks = [uint64]::Parse($lines[1], [Globalization.CultureInfo]::InvariantCulture)
    LinuxBootId = $lines[2]
  }
}

function Assert-WslSentinelLeaseProcess([object]$Lease, [string]$Label) {
  if ($null -eq $Lease -or $null -eq $Lease.Process -or $Lease.Stopped) {
    throw "$Label has no active foreground WSL process lease."
  }
  $process = $Lease.Process
  $process.Refresh()
  if ($process.HasExited) {
    $output = Complete-WslSentinelLeaseOutput $Lease "$Label early exit"
    $overflow = if ($output.stdoutOverflowed -or $output.stderrOverflowed) {
      " (output exceeded the fixed byte bound)"
    } else { "" }
    throw "$Label foreground WSL client exited with status $($process.ExitCode) before reproof${overflow}: $(Get-SingleLineProcessDiagnostic $output)"
  }
  if ($Lease.StdoutCapture.Overflowed -or $Lease.StderrCapture.Overflowed) {
    throw "$Label foreground WSL client exceeded its retained output bound."
  }
  $startedAt = $process.StartTime.ToUniversalTime().ToString(
    "o",
    [Globalization.CultureInfo]::InvariantCulture
  )
  if ([int]$process.Id -ne [int]$Lease.WindowsClientPid -or
      $startedAt -cne [string]$Lease.WindowsClientStartedAt) {
    throw "$Label foreground WSL client PID or start time changed."
  }
}

function Complete-WslSentinelLeaseOutput([object]$Lease, [string]$Label) {
  if ($null -eq $Lease -or $null -eq $Lease.Process) {
    throw "$Label has no sentinel output lease."
  }
  if ($Lease.OutputCompleted) { return $Lease.Output }
  $output = Complete-BoundedProcessCapture $Lease.StdoutTask $Lease.StderrTask (
    $Lease.StdoutCapture
  ) $Lease.StderrCapture $Label
  $Lease.Output = $output
  $Lease.OutputCompleted = $true
  return $output
}

function Start-WslSentinelLease(
  [object]$TrustedWsl,
  [string]$DistributionName,
  [string]$ExpectedBasePath,
  [string]$Token,
  [string]$Label
) {
  if ($Token -cnotmatch '^[0-9a-f]{32}$') { throw "$Label sentinel token is malformed." }
  $registration = Get-ExactWslRegistration $DistributionName $ExpectedBasePath
  $command = @'
set -eu
umask 077
phase=initialize
token='__TOKEN__'
state="/run/assm-qc-sentinel-$token"
temporary="$state.tmp.$$"
trap 'status=$?; if [ "$status" -ne 0 ]; then rm -f -- "$temporary" "$state"; printf "assm sentinel startup failed at %s (exit %s)\n" "$phase" "$status" >&2; fi' EXIT
phase=runtime_directory
test -d /run
test -w /run
phase=sleep_executable
test -x /usr/bin/sleep
test ! -L /usr/bin/sleep
phase=unique_state
test ! -e "$state"
phase=process_identity
pid="$$"
start_ticks="$(awk '{ print $22 }' "/proc/$pid/stat")"
boot_id="$(cat /proc/sys/kernel/random/boot_id)"
phase=publish_state
printf '%s\n%s\n%s\n%s\n' "$token" "$pid" "$start_ticks" "$boot_id" > "$temporary"
chmod 600 "$temporary"
mv "$temporary" "$state"
phase=foreground_sleep
exec /usr/bin/sleep 2147483647
'@.Replace("__TOKEN__", $Token)
  $command = ConvertTo-LfWslGuestScript $command "$Label foreground sentinel script"
  $environment = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
  $environment["SystemRoot"] = $TrustedWsl.windows
  $environment["WINDIR"] = $TrustedWsl.windows
  $environment["PATH"] = $TrustedWsl.system32
  $environment["NoDefaultCurrentDirectoryInExePath"] = "1"
  $environment["WSL_UTF8"] = "1"
  $processLease = Invoke-ExactProcess $TrustedWsl.executable @(
    "--distribution", $DistributionName, "--user", "root", "--exec", "sh", "-c", $command
  ) 120000 "$Label foreground sentinel start" $true $environment `
    -ExpectedSystemExecutableProof $TrustedWsl.proof -KeepRunning $true
  $lease = [PSCustomObject]@{
    Process = $processLease.Process
    DistributionName = $DistributionName
    ExpectedBasePath = [IO.Path]::GetFullPath($ExpectedBasePath)
    RegistrationId = [string]$registration.RegistrationId
    WindowsClientPid = [int]$processLease.ProcessId
    WindowsClientStartedAt = [string]$processLease.ProcessStartedAt
    StdoutTask = $processLease.StdoutTask
    StderrTask = $processLease.StderrTask
    StdoutCapture = $processLease.StdoutCapture
    StderrCapture = $processLease.StderrCapture
    OutputCompleted = $false
    Output = $null
    Token = $Token
    TokenSha256 = Get-LowerSha256Bytes ([Text.Encoding]::UTF8.GetBytes($Token))
    LinuxBootId = $null
    LinuxPid = [uint64]0
    LinuxStartTicks = [uint64]0
    Stopped = $false
    Disposed = $false
  }
  $deadline = [Diagnostics.Stopwatch]::StartNew()
  $lastFailure = "sentinel readiness was not observed"
  try {
    while ($deadline.ElapsedMilliseconds -lt 30000) {
      Assert-WslSentinelLeaseProcess $lease "$Label readiness"
      try {
        $identity = Get-WslSentinelGuestIdentity $TrustedWsl $DistributionName $Token (
          "$Label readiness"
        ) 5000
        $lease.LinuxBootId = [string]$identity.LinuxBootId
        $lease.LinuxPid = [uint64]$identity.LinuxPid
        $lease.LinuxStartTicks = [uint64]$identity.LinuxStartTicks
        return $lease
      } catch {
        $lastFailure = $_.Exception.Message
      }
      Start-Sleep -Milliseconds 200
    }
    if ($lastFailure.Length -gt 2048) { $lastFailure = $lastFailure.Substring(0, 2048) }
    throw "$Label did not publish its foreground sentinel identity within 30 seconds: $lastFailure"
  } catch {
    try { Stop-WslSentinelLease $TrustedWsl $lease "$Label failed readiness cleanup" }
    catch {}
    throw
  }
}

function Assert-WslSentinelLeaseCheckpoint(
  [object]$TrustedWsl,
  [object]$Lease,
  [string]$Phase,
  [string]$Label
) {
  if (-not ($sentinelLifecycleRequiredPhases -ccontains $Phase)) {
    throw "$Label checkpoint phase is outside the fixed lifecycle."
  }
  Assert-WslSentinelLeaseProcess $Lease "$Label $Phase"
  $running = @(Get-WslRunningDistributionNames $TrustedWsl "$Label $Phase")
  $matches = @($running | Where-Object {
    [String]::Equals($_, [string]$Lease.DistributionName, [StringComparison]::Ordinal)
  })
  if ($matches.Count -ne 1) {
    throw "$Label $Phase running inventory did not contain exactly its expected distribution."
  }
  $registration = Get-ExactWslRegistration $Lease.DistributionName $Lease.ExpectedBasePath
  if ([string]$registration.RegistrationId -cne [string]$Lease.RegistrationId) {
    throw "$Label $Phase WSL registration GUID changed."
  }
  $identity = Get-WslSentinelGuestIdentity $TrustedWsl $Lease.DistributionName $Lease.Token (
    "$Label $Phase"
  )
  if ([string]$identity.LinuxBootId -cne [string]$Lease.LinuxBootId -or
      [uint64]$identity.LinuxPid -ne [uint64]$Lease.LinuxPid -or
      [uint64]$identity.LinuxStartTicks -ne [uint64]$Lease.LinuxStartTicks) {
    throw "$Label $Phase foreground guest identity changed."
  }
  Assert-WslSentinelLeaseProcess $Lease "$Label $Phase post-guest"
  $rebound = Get-ExactWslRegistration $Lease.DistributionName $Lease.ExpectedBasePath
  if ([string]$rebound.RegistrationId -cne [string]$Lease.RegistrationId) {
    throw "$Label $Phase WSL registration changed during guest reproof."
  }
  return [ordered]@{
    phase = $Phase
    observedAt = [DateTimeOffset]::UtcNow.ToString(
      "o",
      [Globalization.CultureInfo]::InvariantCulture
    )
    distributionName = [string]$Lease.DistributionName
    registrationId = [string]$Lease.RegistrationId
    windowsClientPid = [int]$Lease.WindowsClientPid
    windowsClientStartedAt = [string]$Lease.WindowsClientStartedAt
    linuxBootId = [string]$Lease.LinuxBootId
    linuxPid = [uint64]$Lease.LinuxPid
    linuxStartTicks = ([uint64]$Lease.LinuxStartTicks).ToString(
      [Globalization.CultureInfo]::InvariantCulture
    )
    tokenSha256 = [string]$Lease.TokenSha256
  }
}

function Stop-WslSentinelLease(
  [object]$TrustedWsl,
  [object]$Lease,
  [string]$Label
) {
  if ($null -eq $Lease -or $null -eq $Lease.Process -or $Lease.Stopped -or $Lease.Disposed) { return }
  $process = $Lease.Process
  $stopIdentityProven = $false
  try {
    Assert-WslSentinelLeaseProcess $Lease "$Label before stop"
    $registration = Get-ExactWslRegistration $Lease.DistributionName $Lease.ExpectedBasePath
    if ([string]$registration.RegistrationId -cne [string]$Lease.RegistrationId) {
      throw "$Label refused to stop a sentinel after its WSL registration GUID changed."
    }
    $command = @'
set -eu
token='__TOKEN__'
expected_pid='__PID__'
expected_ticks='__TICKS__'
expected_boot='__BOOT__'
state="/run/assm-qc-sentinel-$token"
test -f "$state"
test ! -L "$state"
set -- $(cat "$state")
test "$#" -eq 4
test "$1" = "$token"
test "$2" = "$expected_pid"
test "$3" = "$expected_ticks"
test "$4" = "$expected_boot"
test "$(awk '{ print $22 }' "/proc/$expected_pid/stat")" = "$expected_ticks"
test "$(cat /proc/sys/kernel/random/boot_id)" = "$expected_boot"
test "$(readlink "/proc/$expected_pid/exe")" = "/usr/bin/sleep"
kill -TERM "$expected_pid"
attempt=0
while kill -0 "$expected_pid" 2>/dev/null; do
  attempt=$((attempt + 1))
  test "$attempt" -lt 100
  sleep 0.1
done
rm -f "$state"
'@
    $command = $command.Replace("__TOKEN__", [string]$Lease.Token)
    $command = $command.Replace("__PID__", ([uint64]$Lease.LinuxPid).ToString([Globalization.CultureInfo]::InvariantCulture))
    $command = $command.Replace("__TICKS__", ([uint64]$Lease.LinuxStartTicks).ToString([Globalization.CultureInfo]::InvariantCulture))
    $command = $command.Replace("__BOOT__", [string]$Lease.LinuxBootId)
    $command = ConvertTo-LfWslGuestScript $command "$Label exact guest stop script"
    Invoke-TrustedWsl $TrustedWsl @(
      "--distribution", $Lease.DistributionName, "--user", "root", "--exec", "sh", "-c", $command
    ) 30000 "$Label exact guest stop" | Out-Null
    if (-not $process.WaitForExit(15000)) {
      throw "$Label foreground WSL client did not exit after its exact guest stopped."
    }
    $output = Complete-WslSentinelLeaseOutput $Lease "$Label foreground output"
    if ($output.stdoutOverflowed -or $output.stderrOverflowed -or
        [int]$output.stdoutBytes -ne 0 -or [int]$output.stderrBytes -ne 0) {
      throw "$Label foreground WSL client emitted unexpected output: $(Get-SingleLineProcessDiagnostic $output)"
    }
    $stopIdentityProven = $true
  } finally {
    try {
      $process.Refresh()
      if (-not $process.HasExited) {
        $process.Kill($true)
        $process.WaitForExit(5000) | Out-Null
      }
    } catch {}
    if (-not $Lease.OutputCompleted) {
      try { Complete-WslSentinelLeaseOutput $Lease "$Label cleanup output" | Out-Null }
      catch {}
    }
    $process.Dispose()
    $Lease.Disposed = $true
    if ($stopIdentityProven) { $Lease.Stopped = $true }
  }
}

function Get-ProvenFailureCleanupWslBasePath(
  [object]$Registration,
  [string]$ExactDistributionName,
  [string]$OldBasePath,
  [string]$CandidateBasePath,
  [string]$WorkspaceRoot
) {
  $name = [string]$Registration.Name
  $registeredBasePath = Get-BoundedAbsoluteWindowsPath ([string]$Registration.BasePath) (
    "Failure-path WSL registration BasePath"
  )
  $registeredComparable = Get-ComparableWindowsPath $registeredBasePath (
    "Failure-path WSL registration BasePath"
  )
  $expectedBasePath = $null

  if ([String]::Equals($name, $ExactDistributionName, [StringComparison]::Ordinal)) {
    foreach ($allowedBasePath in @($OldBasePath, $CandidateBasePath)) {
      $boundedAllowedBasePath = Get-BoundedAbsoluteWindowsPath $allowedBasePath (
        "Fixed failure-path managed WSL BasePath"
      )
      $allowedComparable = Get-ComparableWindowsPath $boundedAllowedBasePath (
        "Fixed failure-path managed WSL BasePath"
      )
      if ([String]::Equals($registeredComparable, $allowedComparable, [StringComparison]::OrdinalIgnoreCase)) {
        $expectedBasePath = $boundedAllowedBasePath
        break
      }
    }
    if ($null -eq $expectedBasePath) {
      throw "Failure-path exact WSL registration is outside its two fixed provider paths."
    }
  } elseif ($name -cmatch '^ai-security-scanner-recovery-[0-9a-f]{32}$') {
    $recoveryId = $name.Substring("ai-security-scanner-recovery-".Length)
    $boundedWorkspaceRoot = Get-BoundedAbsoluteWindowsPath $WorkspaceRoot (
      "Fixed failure-path WSL recovery workspace root"
    )
    $expectedBasePath = Assert-ExactChildPath $boundedWorkspaceRoot (
      Join-Path $boundedWorkspaceRoot $recoveryId
    ) $recoveryId "Failure-path quarantine WSL workspace"
  } else {
    throw "Failure-path cleanup refused an unrelated WSL registration name."
  }

  Assert-SameWindowsPath $registeredBasePath $expectedBasePath (
    "Failure-path WSL cleanup registration"
  )
  Assert-SameNoFollowDirectoryIdentity $registeredBasePath $expectedBasePath (
    "Failure-path WSL cleanup registration"
  )
  return $expectedBasePath
}

function Assert-FailureCleanupWslBindingRegression([string]$Parent) {
  $fixtureName = "failure-cleanup-wsl-binding-regression"
  $fixtureRoot = Assert-ExactChildPath $Parent (Join-Path $Parent $fixtureName) $fixtureName (
    "Failure-cleanup WSL binding regression fixture"
  )
  if (Test-Path -LiteralPath $fixtureRoot) {
    throw "Failure-cleanup WSL binding regression fixture already exists."
  }
  New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
  try {
    $oldBasePath = Join-Path $fixtureRoot "old-provider"
    $candidateBasePath = Join-Path $fixtureRoot "candidate-provider"
    $differentBasePath = Join-Path $fixtureRoot "different-provider"
    $workspaceRoot = Join-Path $fixtureRoot "workspaces"
    $recoveryId = "0123456789abcdef0123456789abcdef"
    $quarantineBasePath = Join-Path $workspaceRoot $recoveryId
    foreach ($directory in @(
      $oldBasePath,
      $candidateBasePath,
      $differentBasePath,
      $workspaceRoot,
      $quarantineBasePath
    )) {
      New-Item -ItemType Directory -Path $directory | Out-Null
    }

    $exactName = "podman-assm1-win-x64-regression"
    $oldRegistration = [PSCustomObject]@{
      Name = $exactName
      BasePath = Get-VerbatimWindowsPath $oldBasePath "Extended-prefix old-provider regression path"
    }
    $provenOld = Get-ProvenFailureCleanupWslBasePath (
      $oldRegistration
    ) $exactName $oldBasePath $candidateBasePath $workspaceRoot
    Assert-SameNoFollowDirectoryIdentity $provenOld $oldBasePath (
      "Failure-cleanup old-provider regression result"
    )

    $candidateRegistration = [PSCustomObject]@{
      Name = $exactName
      BasePath = $candidateBasePath
    }
    $provenCandidate = Get-ProvenFailureCleanupWslBasePath (
      $candidateRegistration
    ) $exactName $oldBasePath $candidateBasePath $workspaceRoot
    Assert-SameNoFollowDirectoryIdentity $provenCandidate $candidateBasePath (
      "Failure-cleanup candidate-provider regression result"
    )

    $quarantineRegistration = [PSCustomObject]@{
      Name = "ai-security-scanner-recovery-$recoveryId"
      BasePath = Get-VerbatimWindowsPath $quarantineBasePath (
        "Extended-prefix quarantine regression path"
      )
    }
    $provenQuarantine = Get-ProvenFailureCleanupWslBasePath (
      $quarantineRegistration
    ) $exactName $oldBasePath $candidateBasePath $workspaceRoot
    Assert-SameNoFollowDirectoryIdentity $provenQuarantine $quarantineBasePath (
      "Failure-cleanup quarantine regression result"
    )

    $wrongExactRejected = $false
    try {
      Get-ProvenFailureCleanupWslBasePath ([PSCustomObject]@{
        Name = $exactName
        BasePath = $differentBasePath
      }) $exactName $oldBasePath $candidateBasePath $workspaceRoot | Out-Null
    } catch {
      if ($_.Exception.Message -cne (
          "Failure-path exact WSL registration is outside its two fixed provider paths."
        )) { throw }
      $wrongExactRejected = $true
    }
    if (-not $wrongExactRejected) {
      throw "Failure-cleanup WSL binding accepted an exact name with an unrelated BasePath."
    }

    $wrongQuarantineRejected = $false
    try {
      Get-ProvenFailureCleanupWslBasePath ([PSCustomObject]@{
        Name = "ai-security-scanner-recovery-$recoveryId"
        BasePath = $differentBasePath
      }) $exactName $oldBasePath $candidateBasePath $workspaceRoot | Out-Null
    } catch {
      if ($_.Exception.Message -cne (
          "Failure-path WSL cleanup registration is not bound to its exact data-preservation fixture path."
        )) { throw }
      $wrongQuarantineRejected = $true
    }
    if (-not $wrongQuarantineRejected) {
      throw "Failure-cleanup WSL binding accepted a quarantine name outside its exact workspace."
    }

    $unrelatedNameRejected = $false
    try {
      Get-ProvenFailureCleanupWslBasePath ([PSCustomObject]@{
        Name = "unrelated-distribution"
        BasePath = $oldBasePath
      }) $exactName $oldBasePath $candidateBasePath $workspaceRoot | Out-Null
    } catch {
      if ($_.Exception.Message -cne (
          "Failure-path cleanup refused an unrelated WSL registration name."
        )) { throw }
      $unrelatedNameRejected = $true
    }
    if (-not $unrelatedNameRejected) {
      throw "Failure-cleanup WSL binding accepted an unrelated distribution name."
    }
  } finally {
    Remove-ExactTree $fixtureRoot $Parent $fixtureName (
      "Failure-cleanup WSL binding regression fixture"
    )
  }
}

function Unregister-ProvenExactWsl(
  [object]$TrustedWsl,
  [string]$Name,
  [string]$ExpectedBasePath
) {
  Get-ExactWslRegistration $Name $ExpectedBasePath | Out-Null
  $environment = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
  $environment["SystemRoot"] = $TrustedWsl.windows
  $environment["WINDIR"] = $TrustedWsl.windows
  $environment["PATH"] = $TrustedWsl.system32
  $environment["NoDefaultCurrentDirectoryInExePath"] = "1"
  $environment["WSL_UTF8"] = "1"
  Invoke-ExactProcess $TrustedWsl.executable @("--unregister", $Name) 90000 "Exact managed WSL cleanup" $true $environment -ExpectedSystemExecutableProof $TrustedWsl.proof | Out-Null
  $remaining = @(Get-WslRegistrations | Where-Object {
    [String]::Equals($_.Name, $Name, [StringComparison]::Ordinal)
  })
  if ($remaining.Count -ne 0) {
    throw "Exact managed WSL cleanup left its proven registration behind."
  }
}

Assert-WslGuestScriptNormalizationRegression
Assert-BoundedCaptureStreamRegression

$artifactRoot = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
$runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
Assert-RealDirectory $runnerTemp "RUNNER_TEMP" | Out-Null
$workRoot = Assert-ExactChildPath $runnerTemp $WorkDirectory "ai-security-scanner-nsis-ghost-recovery-evidence" "Ghost data-preservation fixture work directory"
New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
Assert-RealDirectory $workRoot "Ghost data-preservation fixture work directory" | Out-Null
Assert-NoFollowDirectoryIdentityRegression $workRoot
Assert-PreservedDataSnapshotHousekeepingRegression $workRoot
Assert-FailureCleanupWslBindingRegression $workRoot
$localApplicationData = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData))
Assert-RealDirectory $localApplicationData "OS-resolved LocalApplicationData" | Out-Null
$installDirectory = Assert-ExactChildPath $localApplicationData (Join-Path $localApplicationData "ai-security-scanner") "ai-security-scanner" "Default NSIS install directory"
$dataDirectory = Assert-ExactChildPath $localApplicationData (Join-Path $localApplicationData "dev.teddashh.ai-security-scanner") "dev.teddashh.ai-security-scanner" "Default private data directory"
$processLeasePath = Join-Path $dataDirectory $processLeaseRelativePath
$priorInstallerPath = Assert-ExactChildPath $workRoot (Join-Path $workRoot $priorInstallerName) $priorInstallerName "Pinned prior installer"
$managedRuntimeRoot = Join-Path $dataDirectory "managed-runtime"
$oldProviderHome = Join-Path $managedRuntimeRoot "provider-home\$priorProviderNamespace"
$oldWslBasePath = Join-Path $oldProviderHome "data\containers\podman\machine\wsl\wsldist\$oldMachineName"
$oldVersionRoot = Join-Path $managedRuntimeRoot "versions"
$oldVersionDirectory = Join-Path $oldVersionRoot $oldVersionDirectoryName
$workspaceRoot = Join-Path $managedRuntimeRoot "wsl-recovery-workspaces"
$generationSelectionRoot = Join-Path $managedRuntimeRoot "wsl-generations"
$oldVhdPath = Join-Path $oldWslBasePath "ext4.vhdx"
$oldProviderConfigPath = Join-Path $oldProviderHome "config\containers\containers.conf"
$oldSshPublicKeyPath = Join-Path $oldProviderHome "data\containers\podman\machine\machine.pub"

foreach ($path in @($installDirectory, $dataDirectory, $priorInstallerPath)) {
  if (Test-Path -LiteralPath $path) { throw "Ghost data-preservation fixture requires a fresh exact namespace: $path" }
}
if (@(Get-ProductRegistryEntries).Count -ne 0) { throw "Ghost data-preservation fixture requires no existing product registration." }

$installerManifest = Read-BoundedJsonFile (Join-Path $artifactRoot "installers-windows-x86_64.json") "Candidate installer manifest" (1024 * 1024)
$candidateRecords = @($installerManifest.installers | Where-Object { $_.bundleType -ceq "nsis" })
if ($installerManifest.version -cne $CurrentVersion -or $candidateRecords.Count -ne 1 -or
    [IO.Path]::GetFileName([string]$candidateRecords[0].file) -cne [string]$candidateRecords[0].file) {
  throw "Candidate artifact does not contain one flat NSIS installer for the requested version."
}
$candidateInstallerPath = (Resolve-Path -LiteralPath (Join-Path $artifactRoot $candidateRecords[0].file)).Path
if (-not [String]::Equals([IO.Path]::GetDirectoryName($candidateInstallerPath), $artifactRoot, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Candidate NSIS installer escaped its artifact directory."
}
$candidateInstaller = Get-NoFollowFileSha256Proof $candidateInstallerPath "Candidate NSIS installer" (256 * 1024 * 1024)
$candidateInstallerSha256 = [string]$candidateInstaller.Sha256
if ($candidateInstaller.Length -ne [int64]$candidateRecords[0].bytes -or
    $candidateInstallerSha256 -cne [string]$candidateRecords[0].sha256) {
  throw "Candidate NSIS installer differs from its release manifest."
}

$candidateRuntimeEvidencePath = Join-Path $artifactRoot "managed-runtime-windows-x86_64.manifest.json"
$candidateRuntimeEvidence = Read-BoundedJsonFile $candidateRuntimeEvidencePath "Candidate managed-runtime manifest" (1024 * 1024)
$candidateRuntimeManifestSha256 = Get-LowerSha256 $candidateRuntimeEvidencePath (1024 * 1024)
if ($candidateRuntimeManifestSha256 -cne $candidateRuntimeManifestExpectedSha256) {
  throw "Candidate managed-runtime evidence differs from the reviewed Windows identity."
}
$candidateVersionNamespace = $candidateRuntimeManifestSha256.Substring(0, 16)
$candidateTargets = @($candidateRuntimeEvidence.targets | Where-Object {
  $_.operating_system -ceq "windows" -and $_.architecture -ceq "x86_64" -and $_.provider -ceq "wsl"
})
if ($candidateRuntimeEvidence.schema_version -cne "3" -or
    $candidateRuntimeEvidence.management_contract_revision -cne "2026-08-29.1" -or
    $candidateRuntimeEvidence.bundle_id -cne "podman-machine" -or
    $candidateRuntimeEvidence.runtime_version -cne "5.8.2" -or $candidateTargets.Count -ne 1) {
  throw "Candidate managed-runtime evidence has no exact Windows WSL identity."
}
$candidateMachineImageSha256 = [string]$candidateTargets[0].machine_image.sha256
$candidateDefaultMachineName = "$currentMachinePrefix-$($candidateMachineImageSha256.Substring(0, 12))"
$candidateGenerationIndex = 1
$candidateMachineName = Get-ExpectedIsolatedMachineName $managedRuntimeRoot (
  $candidateRuntimeManifestSha256
) $candidateMachineImageSha256 $candidateGenerationIndex
$candidateDistributionName = "podman-$candidateMachineName"
$isolatedMachineSuffix = $candidateMachineName.Substring($isolatedMachinePrefix.Length)
$candidateProviderNamespace = "$($candidateRuntimeManifestSha256.Substring(0, 8))-iso-$($isolatedMachineSuffix.Substring(0, 12))"
$candidateProviderHome = Join-Path $managedRuntimeRoot "provider-home\$candidateProviderNamespace"
$candidateWslBasePath = Join-Path $candidateProviderHome "data\containers\podman\machine\wsl\wsldist\$candidateMachineName"
$candidateVersionDirectory = Join-Path $managedRuntimeRoot "versions\podman-machine-5.8.2-$candidateVersionNamespace"
$generationSelectionName = "$candidateRuntimeManifestSha256.$candidateGenerationIndex.json"
$generationSelectionPath = Assert-ExactChildPath $generationSelectionRoot (
  Join-Path $generationSelectionRoot $generationSelectionName
) $generationSelectionName "Candidate isolated-generation routing record"
$trustedWsl = Get-TrustedWslExecutable
$unrelatedDistributionName = "ai-security-scanner-unrelated-$([Guid]::NewGuid().ToString("N"))"
$unrelatedWslBasePath = Assert-ExactChildPath $workRoot (
  Join-Path $workRoot "unrelated-wsl"
) "unrelated-wsl" "Unrelated WSL data-preservation fixture workspace"
$unrelatedVhdPath = Join-Path $unrelatedWslBasePath "ext4.vhdx"
$unrelatedExportArchive = Assert-ExactChildPath $workRoot (
  Join-Path $workRoot "unrelated-rootfs.tar"
) "unrelated-rootfs.tar" "Unrelated WSL data-preservation fixture rootfs"
$beginnerReportPath = Assert-ExactChildPath $workRoot (
  Join-Path $workRoot "beginner-report.html"
) "beginner-report.html" "Readable beginner report"
if (Test-Path -LiteralPath $beginnerReportPath) {
  throw "Ghost data-preservation fixture requires a fresh beginner-report output path."
}

$activeCli = $null
$activeUninstaller = $null
$primaryFailure = $null
$cleanupFailures = [Collections.Generic.List[string]]::new()
$observations = $null
$cleanupComplete = $false
$oldSentinelLease = $null
$unrelatedSentinelLease = $null
$legacySentinelCheckpoints = [Collections.Generic.List[object]]::new()
$unrelatedSentinelCheckpoints = [Collections.Generic.List[object]]::new()

try {
  $priorInstallerProof = Download-PinnedPriorInstaller $priorInstallerPath
  Invoke-ExactProcess $priorInstallerPath @("/S") 180000 "Pinned v0.1.7 default NSIS installation" -ExpectedExecutableProof $priorInstallerProof | Out-Null
  Assert-RealDirectory $installDirectory "v0.1.7 default install directory" | Out-Null
  $oldDesktop = Find-OneInstalledFile $installDirectory "ai-security-scanner.exe"
  $oldCli = Find-OneInstalledFile $installDirectory "ai-security-scanner-cli.exe"
  $oldUninstaller = Find-OneInstalledFile $installDirectory "uninstall.exe"
  $activeCli = $oldCli
  $activeUninstaller = $oldUninstaller
  $priorCliVersion = Get-CliVersion $oldCli "Pinned v0.1.7 CLI"
  if ($priorCliVersion -cne $priorVersion) { throw "Pinned installer did not install CLI v0.1.7." }
  $oldRegistry = Get-ExactProductRegistry $priorVersion $installDirectory
  if (-not $oldRegistry.NoVersionedReceipt) {
    throw "v0.1.7 fixture unexpectedly started with a versioned installer receipt."
  }

  $installedOldRuntimeManifests = @(
    Get-ChildItem -LiteralPath $installDirectory -Filter "manifest.json" -File -Recurse -Force |
      Where-Object { $_.FullName -match '(?i)[\\/]managed-runtime[\\/]manifest\.json$' }
  )
  if ($installedOldRuntimeManifests.Count -ne 1 -or
      (Get-LowerSha256 $installedOldRuntimeManifests[0].FullName (1024 * 1024)) -cne $priorRuntimeManifestSha256) {
    throw "v0.1.7 installed runtime resource differs from its immutable manifest pin."
  }

  New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null
  Set-CanonicalProductDataOwner $dataDirectory
  $sentinelPath = Join-Path $dataDirectory "ghost-recovery-data-sentinel.json"
  [IO.File]::WriteAllText(
    $sentinelPath,
    '{"schema":"ai-security-scanner.release-qualification/ghost-recovery-v1","value":"synthetic"}',
    [Text.UTF8Encoding]::new($false)
  )
  $demoCase = Invoke-CliJson $oldCli @("--json", "--data-dir", $dataDirectory, "case", "seed-demo") 120000 "v0.1.7 synthetic case seed"
  if ([string]::IsNullOrWhiteSpace([string]$demoCase.id) -or @($demoCase.scan_runs).Count -lt 1) {
    throw "v0.1.7 CLI did not create an exportable synthetic case."
  }
  $caseId = [string]$demoCase.id
  $runId = [string]$demoCase.scan_runs[0].id
  Assert-CanonicalUuid $caseId "v0.1.7 synthetic case ID"
  Assert-CanonicalUuid $runId "v0.1.7 synthetic run ID"
  $existingExportIdentityPath = Join-Path $dataDirectory "integrity-signing-key"
  [IO.File]::WriteAllBytes($existingExportIdentityPath, [byte[]](0..31))
  $existingExportIdentityInitial = Get-NoFollowFileSha256Proof $existingExportIdentityPath (
    "Existing local export identity fixture"
  ) (64 * 1024)
  if ($existingExportIdentityInitial.Length -ne 32 -or
      $existingExportIdentityInitial.Sha256 -cne $existingExportIdentityFixtureSha256) {
    throw "Existing local export identity fixture bytes differ from the reviewed 32-byte fixture."
  }

  $oldInstallStatus = Invoke-CliJson $oldCli @(
    "--json", "--data-dir", $dataDirectory, "runtime", "managed", "install"
  ) 900000 "v0.1.7 managed runtime install"
  $oldStartStatus = Invoke-CliJson $oldCli @(
    "--json", "--data-dir", $dataDirectory, "runtime", "managed", "start"
  ) 1200000 "v0.1.7 managed runtime start"
  if ($oldStartStatus.phase -cne "running" -or $oldStartStatus.available -ne $true -or
      $oldStartStatus.manifest_sha256 -cne $priorRuntimeManifestSha256) {
    throw "v0.1.7 managed runtime did not reach its exact running identity."
  }
  $oldStopStatus = Invoke-CliJson $oldCli @(
    "--json", "--data-dir", $dataDirectory, "runtime", "managed", "stop", "--force"
  ) 300000 "v0.1.7 managed runtime stop"
  if ($oldStopStatus.phase -cne "stopped") { throw "v0.1.7 managed runtime did not stop cleanly." }

  Assert-RealDirectory $oldProviderHome "v0.1.7 provider home" | Out-Null
  $oldIdentityRoot = Join-Path $oldProviderHome "data\containers\podman\machine"
  Assert-SingleLinkFile (Join-Path $oldIdentityRoot "machine") "v0.1.7 managed SSH private key" (16 * 1024) | Out-Null
  Assert-SingleLinkFile (Join-Path $oldIdentityRoot "machine.pub") "v0.1.7 managed SSH public key" (4 * 1024) | Out-Null
  $oldRegistrationBefore = Get-ExactWslRegistration $oldDistributionName $oldWslBasePath

  $oldProviderConfigSha256 = Get-LowerSha256 $oldProviderConfigPath (16 * 1024)
  $oldSshPublicKeySha256 = Get-LowerSha256 $oldSshPublicKeyPath (4 * 1024)

  # Build one unrelated WSL distribution from the stopped fixture before the
  # candidate starts. Export/import here is fixture setup only; the
  # candidate must leave both registrations and their live processes alone.
  Invoke-TrustedWsl $trustedWsl @(
    "--export", $oldDistributionName, $unrelatedExportArchive
  ) 900000 "Fixture-only unrelated WSL rootfs export" | Out-Null
  Get-NoFollowFileSha256Proof $unrelatedExportArchive (
    "Fixture-only unrelated WSL rootfs"
  ) (8GB) | Out-Null
  Invoke-TrustedWsl $trustedWsl @(
    "--import", $unrelatedDistributionName, $unrelatedWslBasePath,
    $unrelatedExportArchive, "--version", "2"
  ) 900000 "Fixture-only unrelated WSL import" | Out-Null
  $unrelatedRegistrationBefore = Get-ExactWslRegistration (
    $unrelatedDistributionName
  ) $unrelatedWslBasePath

  $oldSentinelToken = [Guid]::NewGuid().ToString("N")
  $unrelatedSentinelToken = [Guid]::NewGuid().ToString("N")
  $oldSentinelLease = Start-WslSentinelLease $trustedWsl $oldDistributionName $oldWslBasePath (
    $oldSentinelToken
  ) "Legacy assm1 WSL"
  $unrelatedSentinelLease = Start-WslSentinelLease $trustedWsl $unrelatedDistributionName (
    $unrelatedWslBasePath
  ) $unrelatedSentinelToken "Unrelated WSL"
  $legacySentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $oldSentinelLease "fixture_ready" (
      "Legacy assm1 WSL checkpoint fixture_ready"
    )
  ))
  $unrelatedSentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $unrelatedSentinelLease "fixture_ready" (
      "Unrelated WSL checkpoint fixture_ready"
    )
  ))
  $oldRegistrationBefore = Get-ExactWslRegistration $oldDistributionName $oldWslBasePath
  $unrelatedRegistrationBefore = Get-ExactWslRegistration (
    $unrelatedDistributionName
  ) $unrelatedWslBasePath
  $oldVhdBefore = Get-RetainedVhdIdentity $oldVhdPath "Legacy assm1 WSL VHD"

  Assert-RealDirectory $oldVersionDirectory "v0.1.7 installed versions payload" | Out-Null
  $oldInstalledManifest = Join-Path $oldVersionDirectory "manifest.json"
  if ((Get-LowerSha256 $oldInstalledManifest (1024 * 1024)) -cne $priorRuntimeManifestSha256) {
    throw "v0.1.7 versions payload did not carry the immutable N-1 manifest."
  }
  Remove-ExactTree $oldVersionDirectory $oldVersionRoot $oldVersionDirectoryName "Exact v0.1.7 versions payload"
  if (-not (Test-Path -LiteralPath $oldProviderHome -PathType Container)) {
    throw "Fixture setup removed the old provider that must remain for bounded proof."
  }

  Assert-SingleLinkFile $oldDesktop "v0.1.7 desktop selected for ghost fixture" | Out-Null
  Assert-SingleLinkFile $oldUninstaller "v0.1.7 uninstaller selected for ghost fixture" | Out-Null
  Remove-Item -LiteralPath $oldDesktop -Force
  Remove-Item -LiteralPath $oldUninstaller -Force
  $activeUninstaller = $null
  if ((Test-Path -LiteralPath $oldDesktop) -or (Test-Path -LiteralPath $oldUninstaller)) {
    throw "Ghost fixture did not remove exactly the old desktop and uninstaller."
  }
  Get-ExactProductRegistry $priorVersion $installDirectory | Out-Null
  Get-ExactWslRegistration $oldDistributionName $oldWslBasePath | Out-Null
  Get-ExactWslRegistration $unrelatedDistributionName $unrelatedWslBasePath | Out-Null
  $legacySentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $oldSentinelLease "before_candidate_install" (
      "Legacy assm1 WSL checkpoint before_candidate_install"
    )
  ))
  $unrelatedSentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $unrelatedSentinelLease (
      "before_candidate_install"
    ) "Unrelated WSL checkpoint before_candidate_install"
  ))
  $beforeInstallerSnapshot = Get-PreservedDataSnapshot $dataDirectory

  Invoke-ExactProcess $candidateInstallerPath @("/S") 180000 "Candidate version-neutral NSIS installation" -ExpectedExecutableProof $candidateInstaller -AllowRestartRequired | Out-Null
  $candidateDesktop = Find-OneInstalledFile $installDirectory "ai-security-scanner.exe"
  $candidateCli = Find-OneInstalledFile $installDirectory "ai-security-scanner-cli.exe"
  $candidateUninstaller = Find-OneInstalledFile $installDirectory "uninstall.exe"
  $activeCli = $candidateCli
  $activeUninstaller = $candidateUninstaller
  $candidateCliVersion = Get-CliVersion $candidateCli "Candidate CLI"
  if ($candidateCliVersion -cne $CurrentVersion) { throw "Candidate installer did not install CLI $CurrentVersion." }
  $candidateRegistry = Get-ExactProductRegistry $CurrentVersion $installDirectory
  $noVersionedReceiptAfterInstall = [bool]$candidateRegistry.NoVersionedReceipt
  if (-not $noVersionedReceiptAfterInstall) {
    throw "Candidate installer wrote a versioned receipt instead of installing normally."
  }
  $existingExportIdentityAfterUpgrade = Get-NoFollowFileSha256Proof $existingExportIdentityPath (
    "Existing local export identity after ghost upgrade"
  ) (64 * 1024)
  Assert-SameFileProof $existingExportIdentityInitial $existingExportIdentityAfterUpgrade (
    "Ghost upgrade existing local export identity"
  )
  $legacySentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $oldSentinelLease "after_candidate_install" (
      "Legacy assm1 WSL checkpoint after_candidate_install"
    )
  ))
  $unrelatedSentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $unrelatedSentinelLease (
      "after_candidate_install"
    ) "Unrelated WSL checkpoint after_candidate_install"
  ))
  Invoke-ExactProcess $candidateInstallerPath @("/S") 180000 "Candidate same-version silent reinstall" -ExpectedExecutableProof $candidateInstaller -AllowRestartRequired | Out-Null
  $candidateDesktop = Find-OneInstalledFile $installDirectory "ai-security-scanner.exe"
  $candidateCli = Find-OneInstalledFile $installDirectory "ai-security-scanner-cli.exe"
  $candidateUninstaller = Find-OneInstalledFile $installDirectory "uninstall.exe"
  $activeCli = $candidateCli
  $activeUninstaller = $candidateUninstaller
  if ((Get-CliVersion $candidateCli "Same-version reinstalled candidate CLI") -cne $CurrentVersion) {
    throw "Same-version silent reinstall changed the ghost candidate CLI version."
  }
  $candidateRegistry = Get-ExactProductRegistry $CurrentVersion $installDirectory
  $noVersionedReceiptAfterReinstall = [bool]$candidateRegistry.NoVersionedReceipt
  if (-not $noVersionedReceiptAfterReinstall) {
    throw "Same-version silent reinstall introduced a versioned installer receipt."
  }
  $existingExportIdentityAfterReinstall = Get-NoFollowFileSha256Proof $existingExportIdentityPath (
    "Existing local export identity after ghost same-version reinstall"
  ) (64 * 1024)
  Assert-SameFileProof $existingExportIdentityInitial $existingExportIdentityAfterReinstall (
    "Ghost same-version reinstall existing local export identity"
  )
  $legacySentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $oldSentinelLease (
      "after_same_version_reinstall"
    ) "Legacy assm1 WSL checkpoint after_same_version_reinstall"
  ))
  $unrelatedSentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $unrelatedSentinelLease (
      "after_same_version_reinstall"
    ) "Unrelated WSL checkpoint after_same_version_reinstall"
  ))
  $installedCandidateRuntimeManifests = @(
    Get-ChildItem -LiteralPath $installDirectory -Filter "manifest.json" -File -Recurse -Force |
      Where-Object { $_.FullName -match '(?i)[\\/]managed-runtime[\\/]manifest\.json$' }
  )
  if ($installedCandidateRuntimeManifests.Count -ne 1 -or
      (Get-LowerSha256 $installedCandidateRuntimeManifests[0].FullName (1024 * 1024)) -cne $candidateRuntimeManifestSha256) {
    throw "Candidate installed runtime resource differs from released runtime evidence."
  }
  $afterInstallerSnapshot = Get-PreservedDataSnapshot $dataDirectory
  if ($beforeInstallerSnapshot.digest -cne $afterInstallerSnapshot.digest -or
      $beforeInstallerSnapshot.fileCount -ne $afterInstallerSnapshot.fileCount -or
      $beforeInstallerSnapshot.totalBytes -ne $afterInstallerSnapshot.totalBytes) {
    throw "Candidate installer changed private case data during version-neutral installation."
  }
  Get-ExactWslRegistration $oldDistributionName $oldWslBasePath | Out-Null

  if (Test-Path -LiteralPath $generationSelectionRoot) {
    throw "Candidate wrote generation-routing state before runtime initialization began."
  }
  $preStartRegistry = Get-ExactProductRegistry $CurrentVersion $installDirectory
  $noVersionedReceiptBeforeRuntimeStart = [bool]$preStartRegistry.NoVersionedReceipt
  if (-not $noVersionedReceiptBeforeRuntimeStart) {
    throw "Candidate required a versioned installer receipt before runtime initialization."
  }
  $legacySentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $oldSentinelLease (
      "before_candidate_runtime_start"
    ) "Legacy assm1 WSL checkpoint before_candidate_runtime_start"
  ))
  $unrelatedSentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $unrelatedSentinelLease (
      "before_candidate_runtime_start"
    ) "Unrelated WSL checkpoint before_candidate_runtime_start"
  ))

  $sideBySideProcess = Invoke-ExactProcess $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "runtime", "managed", "start"
  ) 1200000 "Candidate automatic side-by-side managed WSL initialization" $true
  if (($sideBySideProcess.stdout + $sideBySideProcess.stderr).Contains("wsl_distribution_requires_manual_action", [StringComparison]::Ordinal)) {
    throw "Candidate fell back to manual WSL action instead of initializing its separate assm2 workspace."
  }
  try { $sideBySideStatus = $sideBySideProcess.stdout | ConvertFrom-Json -DateKind String }
  catch { throw "Candidate side-by-side initialization did not emit valid status JSON." }
  if ($sideBySideStatus.phase -cne "running" -or $sideBySideStatus.available -ne $true -or
      $sideBySideStatus.manifest_sha256 -cne $candidateRuntimeManifestSha256 -or
      $sideBySideStatus.machine_image_sha256 -cne $candidateMachineImageSha256) {
    throw "Candidate assm2 workspace did not reach the released running runtime identity."
  }
  Assert-RealDirectory $candidateVersionDirectory "Candidate installed runtime version" | Out-Null
  Assert-RealDirectory $oldProviderHome "Retained v0.1.7 provider home" | Out-Null

  Assert-RealDirectory $generationSelectionRoot "Candidate generation routing directory" | Out-Null
  $generationSelectionEntries = @(Get-ChildItem -LiteralPath $generationSelectionRoot -Force)
  if ($generationSelectionEntries.Count -ne 1 -or
      $generationSelectionEntries[0].PSIsContainer -or
      ($generationSelectionEntries[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
      $generationSelectionEntries[0].Name -cne $generationSelectionName) {
    throw "Candidate did not create exactly its append-only isolated-generation routing record."
  }
  Assert-OwnerOnlyFullControlFile $generationSelectionPath (
    "Candidate isolated-generation routing record"
  ) (64 * 1024) | Out-Null
  $generationSelectionFileProof = Get-NoFollowFileSha256Proof $generationSelectionPath (
    "Candidate isolated-generation routing record"
  ) (64 * 1024)
  $generationSelection = Read-BoundedJsonFile $generationSelectionPath (
    "Candidate isolated-generation routing record"
  ) (64 * 1024)
  Assert-ExactJsonProperties $generationSelection @(
    "schema_version",
    "authorizes_cleanup",
    "manifest_sha256",
    "machine_image_sha256",
    "default_machine_name",
    "selected_machine_name",
    "generation_index",
    "preserved_collision_names"
  ) "Candidate isolated-generation routing record"
  if ($generationSelection.schema_version -cne
      "ai-security-scanner.managed-wsl-generation-selection/v1") {
    throw "Candidate isolated-generation routing record has the wrong schema."
  }
  if ($generationSelection.authorizes_cleanup -ne $false) {
    throw "Candidate isolated-generation routing record grants cleanup authority."
  }
  if ([string]$generationSelection.manifest_sha256 -cne $candidateRuntimeManifestSha256) {
    throw "Candidate isolated-generation routing record has the wrong manifest identity."
  }
  if ([string]$generationSelection.machine_image_sha256 -cne $candidateMachineImageSha256) {
    throw "Candidate isolated-generation routing record has the wrong machine-image identity."
  }
  if ([string]$generationSelection.default_machine_name -cne $candidateDefaultMachineName) {
    throw "Candidate isolated-generation routing record has the wrong default machine identity."
  }
  if ([string]$generationSelection.selected_machine_name -cnotmatch '^assm2-iso-[0-9a-f]{20}$') {
    throw "Candidate isolated-generation routing record has a malformed selected machine identity."
  }
  if ([string]$generationSelection.selected_machine_name -cne $candidateMachineName) {
    throw "Candidate isolated-generation routing record has a non-deterministic selected machine identity."
  }
  if ([uint32]$generationSelection.generation_index -ne $candidateGenerationIndex) {
    throw "Candidate isolated-generation routing record has the wrong generation index."
  }
  if (@($generationSelection.preserved_collision_names).Count -ne 0) {
    throw "Candidate isolated-generation routing record reports an unexpected preserved collision."
  }
  Assert-RealDirectory $candidateProviderHome "Candidate isolated provider home" | Out-Null

  $oldRegistrationAfter = Get-ExactWslRegistration $oldDistributionName $oldWslBasePath
  $currentRegistration = Get-ExactWslRegistration $candidateDistributionName $candidateWslBasePath
  $unrelatedRegistrationAfter = Get-ExactWslRegistration (
    $unrelatedDistributionName
  ) $unrelatedWslBasePath
  if ([string]$oldRegistrationAfter.RegistrationId -cne [string]$oldRegistrationBefore.RegistrationId -or
      [string]$unrelatedRegistrationAfter.RegistrationId -cne [string]$unrelatedRegistrationBefore.RegistrationId) {
    throw "Candidate rebound a legacy or unrelated WSL registration."
  }
  $legacySentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $oldSentinelLease (
      "after_candidate_runtime_running"
    ) "Legacy assm1 WSL checkpoint after_candidate_runtime_running"
  ))
  $unrelatedSentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $unrelatedSentinelLease (
      "after_candidate_runtime_running"
    ) "Unrelated WSL checkpoint after_candidate_runtime_running"
  ))
  $oldVhdAfter = Get-RetainedVhdIdentity $oldVhdPath "Retained legacy assm1 WSL VHD"
  foreach ($identityField in @(
      "volumeSerialNumber", "fileIndex", "numberOfLinks", "attributes"
    )) {
    if ([uint64]$oldVhdAfter[$identityField] -ne [uint64]$oldVhdBefore[$identityField]) {
      throw "Candidate changed legacy VHD identity field $identityField."
    }
  }
  if ((Get-LowerSha256 $oldProviderConfigPath (16 * 1024)) -cne $oldProviderConfigSha256 -or
      (Get-LowerSha256 $oldSshPublicKeyPath (4 * 1024)) -cne $oldSshPublicKeySha256) {
    throw "Candidate changed the retained legacy provider proof files."
  }

  $postSideBySideRegistry = Get-ExactProductRegistry $CurrentVersion $installDirectory
  $noVersionedReceiptAfterRuntimeStart = [bool]$postSideBySideRegistry.NoVersionedReceipt
  if (-not $noVersionedReceiptAfterRuntimeStart) {
    throw "Candidate runtime start depended on a versioned installer receipt."
  }

  $quarantineRegistrations = @(Get-WslRegistrations | Where-Object {
    $_.Name -cmatch '^ai-security-scanner-recovery-[0-9a-f]{32}$'
  })
  if ($quarantineRegistrations.Count -ne 0) {
    throw "Side-by-side initialization unexpectedly created a recovery quarantine registration."
  }

  $candidateCase = Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "case", "show", $caseId
  ) 120000 "Side-by-side candidate synthetic case read"
  if ([string]$candidateCase.id -cne $caseId) { throw "Side-by-side initialization did not preserve the synthetic case." }
  $beginnerReportExport = Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "export", "create", "--case-id", $caseId,
    "--run-id", $runId, "--format", "html", "--destination", $beginnerReportPath
  ) 120000 "Side-by-side candidate readable beginner report export"
  $beginnerReportProof = Get-NoFollowFileSha256Proof (
    $beginnerReportPath
  ) "Readable beginner report" (16 * 1024 * 1024)
  Assert-HtmlExportReceipt $beginnerReportExport $caseId $runId $beginnerReportPath (
    $beginnerReportProof
  ) "Side-by-side readable beginner report receipt"
  $existingExportIdentityAfterExport = Get-NoFollowFileSha256Proof $existingExportIdentityPath (
    "Existing local export identity after side-by-side report export"
  ) (64 * 1024)
  Assert-SameFileProof $existingExportIdentityInitial $existingExportIdentityAfterExport (
    "Side-by-side report export existing local export identity"
  )
  if (-not (Test-Path -LiteralPath $sentinelPath -PathType Leaf)) {
    throw "Side-by-side initialization did not preserve the case data sentinel."
  }

  Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "runtime", "managed", "stop", "--force"
  ) 300000 "Current assm2 managed runtime cleanup stop" | Out-Null
  Invoke-CliJson $candidateCli @(
    "--json", "--data-dir", $dataDirectory, "runtime", "managed", "uninstall", "--force", "--purge-image-cache"
  ) 900000 "Current assm2 managed runtime cleanup uninstall" | Out-Null
  $generationSelectionAfterPurge = Get-NoFollowFileSha256Proof $generationSelectionPath (
    "Isolated-generation routing record after current-runtime purge"
  ) (64 * 1024)
  Assert-SameFileProof $generationSelectionFileProof $generationSelectionAfterPurge (
    "Current-runtime purge isolated-generation routing record"
  )
  $currentAfterPurge = @(Get-WslRegistrations | Where-Object {
    [String]::Equals($_.Name, $candidateDistributionName, [StringComparison]::Ordinal)
  })
  if ($currentAfterPurge.Count -ne 0) {
    throw "Current-runtime purge retained the assm2 WSL registration."
  }
  $oldRegistrationAfterPurge = Get-ExactWslRegistration $oldDistributionName $oldWslBasePath
  $unrelatedRegistrationAfterPurge = Get-ExactWslRegistration (
    $unrelatedDistributionName
  ) $unrelatedWslBasePath
  if ([string]$oldRegistrationAfterPurge.RegistrationId -cne [string]$oldRegistrationBefore.RegistrationId -or
      [string]$unrelatedRegistrationAfterPurge.RegistrationId -cne [string]$unrelatedRegistrationBefore.RegistrationId) {
    throw "Current-runtime purge rebound a retained WSL registration."
  }
  $legacySentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $oldSentinelLease (
      "after_current_runtime_purge"
    ) "Legacy assm1 WSL checkpoint after_current_runtime_purge"
  ))
  $unrelatedSentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $unrelatedSentinelLease (
      "after_current_runtime_purge"
    ) "Unrelated WSL checkpoint after_current_runtime_purge"
  ))
  $legacySentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $oldSentinelLease (
      "before_app_only_uninstall"
    ) "Legacy assm1 WSL checkpoint before_app_only_uninstall"
  ))
  $unrelatedSentinelCheckpoints.Add((
    Assert-WslSentinelLeaseCheckpoint $trustedWsl $unrelatedSentinelLease (
      "before_app_only_uninstall"
    ) "Unrelated WSL checkpoint before_app_only_uninstall"
  ))
  Stop-WslSentinelLease $trustedWsl $oldSentinelLease (
    "Legacy assm1 WSL stop before complete private-data snapshot"
  )
  Stop-WslSentinelLease $trustedWsl $unrelatedSentinelLease (
    "Unrelated WSL stop before app-only uninstall"
  )
  Invoke-TrustedWsl $trustedWsl @(
    "--terminate", $oldDistributionName
  ) 90000 "Exact legacy WSL termination before complete snapshot" | Out-Null
  Invoke-TrustedWsl $trustedWsl @(
    "--terminate", $unrelatedDistributionName
  ) 90000 "Exact unrelated WSL termination before app-only uninstall proof" | Out-Null
  Get-ExactWslRegistration $oldDistributionName $oldWslBasePath | Out-Null
  Get-ExactWslRegistration $unrelatedDistributionName $unrelatedWslBasePath | Out-Null
  $fixtureWslRegistrations = @(
    $oldRegistrationAfterPurge,
    $unrelatedRegistrationAfterPurge
  )
  Invoke-FixtureOnlyWslShutdown $trustedWsl $fixtureWslRegistrations (
    "Fixture-only WSL quiescence before VHD preservation proof"
  )
  $oldVhdBeforeUninstall = Get-QuiescedVhdSha256Proof $oldVhdPath (
    "Legacy WSL VHD immediately before app-only uninstall"
  ) $maximumCompleteSnapshotBytes
  $unrelatedVhdBeforeUninstall = Get-QuiescedVhdSha256Proof $unrelatedVhdPath (
    "Unrelated WSL VHD immediately before app-only uninstall"
  ) $maximumCompleteSnapshotBytes
  $appOnlyUninstallSnapshotBefore = Get-NonLeasePrivateDataSnapshot $dataDirectory
  $processLeaseBeforeUninstall = Get-NoFollowEmptyFileProof $processLeasePath (
    "Root process lease before app-only uninstall"
  )
  $uninstallResult = Invoke-BoundedCopiedNsisUninstaller $candidateUninstaller (
    $installDirectory
  ) $workRoot (
    "Candidate NSIS cleanup uninstall"
  ) -AllowRetainedState
  if ([int]$uninstallResult.exitCode -ne 10) {
    throw "Candidate NSIS cleanup uninstall did not report its expected preserved ambiguous runtime state."
  }
  if (Test-Path -LiteralPath $installDirectory) {
    throw "Candidate NSIS cleanup uninstall retained the exact application installation directory."
  }
  foreach ($removedProductFile in @($candidateDesktop, $candidateCli, $candidateUninstaller)) {
    if (Test-Path -LiteralPath $removedProductFile) {
      throw "Candidate NSIS cleanup uninstall retained a product application binary."
    }
  }
  $activeCli = $null
  if (@(Get-ProductRegistryEntries).Count -ne 0) {
    throw "Candidate NSIS uninstaller left the product registry entry."
  }
  $appOnlyUninstallSnapshotAfter = Get-NonLeasePrivateDataSnapshot $dataDirectory
  $processLeaseAfterUninstall = Get-NoFollowEmptyFileProof $processLeasePath (
    "Root process lease after app-only uninstall"
  )
  Assert-SameFileProof $processLeaseBeforeUninstall $processLeaseAfterUninstall (
    "App-only uninstall root process lease"
  )
  if ($appOnlyUninstallSnapshotAfter.digest -cne $appOnlyUninstallSnapshotBefore.digest -or
      $appOnlyUninstallSnapshotAfter.fileCount -ne $appOnlyUninstallSnapshotBefore.fileCount -or
      $appOnlyUninstallSnapshotAfter.totalBytes -ne $appOnlyUninstallSnapshotBefore.totalBytes) {
    throw "App-only NSIS uninstall changed non-lease product data before explicit teardown."
  }
  $existingExportIdentityAfterUninstall = Get-NoFollowFileSha256Proof $existingExportIdentityPath (
    "Existing local export identity after app-only ghost NSIS uninstall"
  ) (64 * 1024)
  Assert-SameFileProof $existingExportIdentityInitial $existingExportIdentityAfterUninstall (
    "App-only ghost NSIS uninstall existing local export identity"
  )
  $beginnerReportAfterUninstall = Get-NoFollowFileSha256Proof $beginnerReportPath (
    "Readable beginner report after app-only ghost NSIS uninstall"
  ) (16 * 1024 * 1024)
  Assert-SameFileProof $beginnerReportProof $beginnerReportAfterUninstall (
    "App-only ghost NSIS uninstall readable beginner report"
  )
  $generationSelectionAfterUninstall = Get-NoFollowFileSha256Proof $generationSelectionPath (
    "Isolated-generation routing record after app-only uninstall"
  ) (64 * 1024)
  Assert-SameFileProof $generationSelectionFileProof $generationSelectionAfterUninstall (
    "App-only uninstall isolated-generation routing record"
  )
  $oldProviderConfigAfterUninstallSha256 = Get-LowerSha256 $oldProviderConfigPath (16 * 1024)
  $oldSshPublicKeyAfterUninstallSha256 = Get-LowerSha256 $oldSshPublicKeyPath (4 * 1024)
  if (-not (Test-Path -LiteralPath $oldProviderHome -PathType Container) -or
      $oldProviderConfigAfterUninstallSha256 -cne $oldProviderConfigSha256 -or
      $oldSshPublicKeyAfterUninstallSha256 -cne $oldSshPublicKeySha256 -or
      -not (Test-Path -LiteralPath $sentinelPath -PathType Leaf)) {
    throw "NSIS uninstall changed retained workspace or case data before explicit cleanup."
  }
  $oldVhdAfterUninstall = Get-RetainedVhdIdentity $oldVhdPath (
    "Retained legacy assm1 WSL VHD after app-only uninstall"
  )
  # WSL may flush and resize its dynamic VHD while the fixture-only shutdown
  # establishes the stable pre-uninstall baseline. Byte length is therefore
  # compared only to $oldVhdBeforeUninstall below; NTFS object identity must
  # remain unchanged across the complete lifecycle.
  foreach ($identityField in @("volumeSerialNumber", "fileIndex", "numberOfLinks", "attributes")) {
    if ([uint64]$oldVhdAfterUninstall[$identityField] -ne [uint64]$oldVhdAfter[$identityField]) {
      throw "App-only NSIS uninstall changed legacy VHD identity field $identityField."
    }
  }
  $oldVhdFileAfterUninstall = Get-QuiescedVhdSha256Proof $oldVhdPath (
    "Legacy WSL VHD after app-only uninstall"
  ) $maximumCompleteSnapshotBytes
  Assert-SameFileProof $oldVhdBeforeUninstall $oldVhdFileAfterUninstall (
    "App-only NSIS uninstall legacy WSL VHD"
  )
  $oldRegistrationAfterUninstall = Get-ExactWslRegistration $oldDistributionName $oldWslBasePath
  $unrelatedRegistrationAfterUninstall = Get-ExactWslRegistration (
    $unrelatedDistributionName
  ) $unrelatedWslBasePath
  if ([string]$oldRegistrationAfterUninstall.RegistrationId -cne
        [string]$oldRegistrationBefore.RegistrationId -or
      [string]$unrelatedRegistrationAfterUninstall.RegistrationId -cne
      [string]$unrelatedRegistrationBefore.RegistrationId) {
    throw "App-only NSIS uninstall rebound a legacy or unrelated WSL registration."
  }
  $unrelatedVhdAfterUninstall = Get-QuiescedVhdSha256Proof $unrelatedVhdPath (
    "Unrelated WSL VHD after app-only uninstall"
  ) $maximumCompleteSnapshotBytes
  Assert-SameFileProof $unrelatedVhdBeforeUninstall $unrelatedVhdAfterUninstall (
    "App-only NSIS uninstall unrelated WSL VHD"
  )
  foreach ($checkpointSet in @(
    [PSCustomObject]@{ Label = "legacy"; Checkpoints = $legacySentinelCheckpoints },
    [PSCustomObject]@{ Label = "unrelated"; Checkpoints = $unrelatedSentinelCheckpoints }
  )) {
    if ($checkpointSet.Checkpoints.Count -ne $sentinelLifecycleRequiredPhases.Count) {
      throw "$($checkpointSet.Label) sentinel lifecycle did not capture every required phase."
    }
    for ($checkpointIndex = 0; $checkpointIndex -lt $sentinelLifecycleRequiredPhases.Count; $checkpointIndex++) {
      if ([string]$checkpointSet.Checkpoints[$checkpointIndex].phase -cne
          [string]$sentinelLifecycleRequiredPhases[$checkpointIndex]) {
        throw "$($checkpointSet.Label) sentinel lifecycle phase order changed."
      }
    }
  }

  # Explicit fixture teardown. The generation-selection journal never grants
  # cleanup authority; only these fixed test namespaces are unregistered after
  # every preservation assertion has passed.
  Stop-WslSentinelLease $trustedWsl $oldSentinelLease "Legacy assm1 WSL fixture teardown"
  Stop-WslSentinelLease $trustedWsl $unrelatedSentinelLease "Unrelated WSL fixture teardown"
  Unregister-ProvenExactWsl $trustedWsl $oldDistributionName $oldWslBasePath
  Unregister-ProvenExactWsl $trustedWsl $unrelatedDistributionName $unrelatedWslBasePath
  if (Test-Path -LiteralPath $installDirectory) {
    Remove-ExactTree $installDirectory $localApplicationData "ai-security-scanner" "Default NSIS install directory cleanup"
  }
  Remove-ExactTree $dataDirectory $localApplicationData "dev.teddashh.ai-security-scanner" "Default private data cleanup"
  if (@(Get-ProductRegistryEntries).Count -ne 0) { throw "Candidate uninstaller left the product registry entry." }
  $activeUninstaller = $null
  $cleanupComplete = $true

  $observations = [ordered]@{
    schemaVersion = 10
    scenario = "automated_registered_wsl_n_minus_one_ghost_isolated_generation_fixture"
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
      tag = "v0.1.7"
      installerFile = $priorInstallerName
      installerBytes = $priorInstallerBytes
      installerSha256 = $priorInstallerSha256
      downloadUrl = $priorInstallerUrl
      runtimeManifestSha256 = $priorRuntimeManifestSha256
      machineImageSha256 = $priorMachineImageSha256
    }
    candidate = [ordered]@{
      version = $CurrentVersion
      installerFile = [string]$candidateRecords[0].file
      installerBytes = [int64]$candidateRecords[0].bytes
      installerSha256 = $candidateInstallerSha256
      runtimeManifestSha256 = $candidateRuntimeManifestSha256
      machineImageSha256 = $candidateMachineImageSha256
    }
    ghostFixture = [ordered]@{
      defaultInstallDirectoryUsed = $true
      canonicalProductDataCurrentUserOwner = $true
      priorCliVersion = $priorCliVersion
      oldRegistryIdentityExact = $true
      oldRuntimeInstalled = ($oldInstallStatus.manifest_sha256 -ceq $priorRuntimeManifestSha256)
      oldRuntimeStarted = $true
      oldRuntimeStopped = $true
      oldProviderNamespace = $priorProviderNamespace
      oldProviderCryptographicIdentityPresent = $true
      distributionName = $oldDistributionName
      registrationId = [string]$oldRegistrationBefore.RegistrationId
      registeredWslStateExercised = $true
      registrationBoundToOldProvider = $true
      missingVersionsManifestExercised = $true
      oldVersionDirectory = $oldVersionDirectoryName
      oldVersionPayloadDigestVerifiedBeforeRemoval = $true
      oldVersionPayloadDirectoryRemoved = $true
      oldDesktopRemoved = $true
      oldUninstallerRemoved = $true
      unrelatedDistributionName = $unrelatedDistributionName
      unrelatedRegistrationId = [string]$unrelatedRegistrationBefore.RegistrationId
    }
    candidateInstallation = [ordered]@{
      candidateInstallerCompleted = $true
      candidateCliVersion = $candidateCliVersion
      registryVersionUpdated = $true
      registryIdentityExact = $true
      versionNeutralInstallCompleted = $true
      candidateDesktopRestored = $true
      candidateUninstallerRestored = $true
      candidateRuntimeResourceMatchesRelease = $true
      exactPrivateDataSnapshotPreserved = $true
      sameVersionSilentReinstallCompleted = $true
      sameVersionReinstallRemainedVersionNeutral = $true
    }
    runtimeSideBySide = [ordered]@{
      startSucceeded = $true
      noManualActionFallback = $true
      runningAndAvailable = $true
      legacyMachineName = $oldMachineName
      legacyDistributionName = $oldDistributionName
      legacyRegistrationIdBefore = [string]$oldRegistrationBefore.RegistrationId
      legacyRegistrationIdAfter = [string]$oldRegistrationAfter.RegistrationId
      legacyRegistrationBasePathExact = $true
      legacyProviderRetained = $true
      legacyProviderNamespace = $priorProviderNamespace
      legacyVhdIdentityPreserved = $true
      legacyProviderProofFilesPreserved = $true
      currentMachineName = $candidateMachineName
      currentDistributionName = $candidateDistributionName
      currentRegistrationId = [string]$currentRegistration.RegistrationId
      currentRegistrationBasePathExact = $true
      currentProviderNamespace = $candidateProviderNamespace
      currentProviderCreated = $true
      unrelatedDistributionName = $unrelatedDistributionName
      unrelatedRegistrationIdBefore = [string]$unrelatedRegistrationBefore.RegistrationId
      unrelatedRegistrationIdAfter = [string]$unrelatedRegistrationAfter.RegistrationId
      unrelatedRegistrationBasePathExact = $true
      noQuarantineDistributionCreated = $true
      generationSelection = [ordered]@{
        pathBoundToCandidateManifestAndGeneration = $true
        recordPresent = $true
        recordProtected = $true
        recordBytes = [int64]$generationSelectionFileProof.Length
        recordSha256 = [string]$generationSelectionFileProof.Sha256
        schemaVersion = [string]$generationSelection.schema_version
        authorizesCleanup = [bool]$generationSelection.authorizes_cleanup
        manifestSha256 = [string]$generationSelection.manifest_sha256
        machineImageSha256 = [string]$generationSelection.machine_image_sha256
        defaultMachineName = [string]$generationSelection.default_machine_name
        selectedMachineName = [string]$generationSelection.selected_machine_name
        selectedMachineDeterministic = $true
        generationIndex = [uint32]$generationSelection.generation_index
        preservedCollisionNames = @($generationSelection.preserved_collision_names)
        recordPreservedAfterCurrentRuntimePurge = $true
        recordPreservedThroughAppOnlyUninstall = $true
      }
      noVersionedReceipt = [ordered]@{
        beforeCandidateInstall = [bool]$oldRegistry.NoVersionedReceipt
        afterCandidateInstall = $noVersionedReceiptAfterInstall
        afterSameVersionReinstall = $noVersionedReceiptAfterReinstall
        beforeRuntimeStart = $noVersionedReceiptBeforeRuntimeStart
        afterRuntimeStart = $noVersionedReceiptAfterRuntimeStart
      }
      legacyWorkspaceAfterAppOnlyUninstall = [ordered]@{
        registrationIdBefore = [string]$oldRegistrationBefore.RegistrationId
        registrationIdAfter = [string]$oldRegistrationAfterUninstall.RegistrationId
        providerConfigSha256Before = $oldProviderConfigSha256
        providerConfigSha256After = $oldProviderConfigAfterUninstallSha256
        sshPublicKeySha256Before = $oldSshPublicKeySha256
        sshPublicKeySha256After = $oldSshPublicKeyAfterUninstallSha256
        vhdBeforeAppOnlyUninstall = Convert-VhdFileProofObservation $oldVhdBeforeUninstall
        vhdAfterAppOnlyUninstall = Convert-VhdFileProofObservation $oldVhdFileAfterUninstall
      }
      unrelatedWorkspaceAfterAppOnlyUninstall = [ordered]@{
        registrationIdBefore = [string]$unrelatedRegistrationBefore.RegistrationId
        registrationIdAfter = [string]$unrelatedRegistrationAfterUninstall.RegistrationId
        vhdBeforeAppOnlyUninstall = Convert-VhdFileProofObservation $unrelatedVhdBeforeUninstall
        vhdAfterAppOnlyUninstall = Convert-VhdFileProofObservation $unrelatedVhdAfterUninstall
      }
      sentinelLifecycle = [ordered]@{
        schemaVersion = 1
        requiredPhases = @($sentinelLifecycleRequiredPhases)
        legacyCheckpoints = @($legacySentinelCheckpoints | ForEach-Object { $_ })
        unrelatedCheckpoints = @($unrelatedSentinelCheckpoints | ForEach-Object { $_ })
      }
    }
    dataPreservation = [ordered]@{
      preInstallerFileCount = [int]$beforeInstallerSnapshot.fileCount
      preInstallerBytes = [int64]$beforeInstallerSnapshot.totalBytes
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
        allNonLeaseProductDataPreserved = $true
      }
    }
    cleanup = [ordered]@{
      currentRuntimePurged = $true
      currentDistributionAbsent = $true
      legacyDistributionRetainedThroughRuntimePurge = $true
      unrelatedDistributionRetainedThroughRuntimePurge = $true
      generationSelectionPreservedThroughRuntimePurge = $true
      generationSelectionPreservedThroughAppOnlyUninstall = $true
      legacyDataPreservedThroughNsisUninstall = $true
      uninstallerInvoked = $true
      productRegistryRemovedByUninstaller = $true
      fixtureTeardownRemovedLegacy = $true
      fixtureTeardownRemovedUnrelated = $true
      quarantineDistributionsAbsent = $true
      fixtureTeardownInstallDirectoryRemoved = $true
      fixtureTeardownPrivateDataRemoved = $true
    }
  }
} catch {
  $primaryFailure = $_
} finally {
  if ($null -ne $primaryFailure) {
    foreach ($sentinelCleanup in @(
      [PSCustomObject]@{ Lease = $oldSentinelLease; Label = "Failure-path legacy sentinel stop" },
      [PSCustomObject]@{ Lease = $unrelatedSentinelLease; Label = "Failure-path unrelated sentinel stop" }
    )) {
      try { Stop-WslSentinelLease $trustedWsl $sentinelCleanup.Lease $sentinelCleanup.Label }
      catch { $cleanupFailures.Add($_.Exception.Message) }
    }
    if ($null -ne $activeCli -and (Test-Path -LiteralPath $activeCli -PathType Leaf) -and
        (Test-Path -LiteralPath $dataDirectory -PathType Container)) {
      foreach ($cleanupArguments in @(
        @( "--json", "--data-dir", $dataDirectory, "runtime", "managed", "stop", "--force" ),
        @( "--json", "--data-dir", $dataDirectory, "runtime", "managed", "uninstall", "--force", "--purge-image-cache" )
      )) {
        try { Invoke-ExactProcess $activeCli $cleanupArguments 900000 "Failure-path managed runtime cleanup" $true | Out-Null }
        catch { $cleanupFailures.Add($_.Exception.Message) }
      }
    }
    try {
      $registrations = @(Get-WslRegistrations)
      foreach ($registration in $registrations) {
        $isLegacy = [String]::Equals($registration.Name, $oldDistributionName, [StringComparison]::Ordinal)
        $isCurrent = [String]::Equals($registration.Name, $candidateDistributionName, [StringComparison]::Ordinal)
        $isUnrelatedFixture = [String]::Equals(
          $registration.Name,
          $unrelatedDistributionName,
          [StringComparison]::Ordinal
        )
        $isQuarantine = $registration.Name -cmatch '^ai-security-scanner-recovery-[0-9a-f]{32}$'
        if (-not $isLegacy -and -not $isCurrent -and -not $isUnrelatedFixture -and
            -not $isQuarantine) { continue }
        $expectedBasePath = if ($isLegacy) {
          $oldWslBasePath
        } elseif ($isCurrent) {
          $candidateWslBasePath
        } elseif ($isUnrelatedFixture) {
          $unrelatedWslBasePath
        } else {
          Get-ProvenFailureCleanupWslBasePath (
            $registration
          ) $oldDistributionName $oldWslBasePath $candidateWslBasePath $workspaceRoot
        }
        Unregister-ProvenExactWsl $trustedWsl $registration.Name $expectedBasePath
      }
    } catch { $cleanupFailures.Add($_.Exception.Message) }
    if ($null -ne $activeUninstaller -and (Test-Path -LiteralPath $activeUninstaller -PathType Leaf)) {
      try {
        Invoke-BoundedCopiedNsisUninstaller $activeUninstaller $installDirectory $workRoot (
          "Failure-path candidate uninstall"
        ) -AllowRetainedState | Out-Null
      }
      catch { $cleanupFailures.Add($_.Exception.Message) }
    }
    foreach ($cleanup in @(
      [ordered]@{ path = $installDirectory; parent = $localApplicationData; name = "ai-security-scanner" },
      [ordered]@{ path = $dataDirectory; parent = $localApplicationData; name = "dev.teddashh.ai-security-scanner" }
    )) {
      try {
        if (Test-Path -LiteralPath $cleanup.path) {
          Remove-ExactTree $cleanup.path $cleanup.parent $cleanup.name "Failure-path exact data-preservation fixture tree"
        }
      } catch { $cleanupFailures.Add($_.Exception.Message) }
    }
    try {
      $entries = @(Get-ProductRegistryEntries)
      foreach ($entry in $entries) {
        if ($entry.KeyName -cne "ai-security-scanner") { throw "Refusing unexpected product registry cleanup." }
        Remove-Item -LiteralPath $entry.KeyPath -Recurse -Force
      }
    } catch { $cleanupFailures.Add($_.Exception.Message) }
  }
}

if ($null -ne $primaryFailure) {
  $scriptStack = [string]$primaryFailure.ScriptStackTrace
  $scriptStack = $scriptStack.Replace("`r", " ").Replace("`n", " ")
  if ($scriptStack.Length -gt 2048) {
    $scriptStack = $scriptStack.Substring(0, 2048) + " (truncated)"
  }
  $stackSuffix = if ([String]::IsNullOrWhiteSpace($scriptStack)) {
    ""
  } else {
    " Script stack: $scriptStack"
  }
  $suffix = if ($cleanupFailures.Count -eq 0) { "" } else { " Cleanup failure(s): $([String]::Join('; ', $cleanupFailures))" }
  throw [InvalidOperationException]::new(
    $primaryFailure.Exception.Message + $stackSuffix + $suffix,
    $primaryFailure.Exception
  )
}
if (-not $cleanupComplete -or $null -eq $observations) {
  throw "Registered-WSL side-by-side ghost data-preservation fixture did not reach its verified teardown state."
}
$observationsPath = Join-Path $workRoot "observations.json"
$observations | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $observationsPath -Encoding utf8NoBOM -NoNewline
Add-Content -LiteralPath $observationsPath -Value "" -Encoding utf8NoBOM

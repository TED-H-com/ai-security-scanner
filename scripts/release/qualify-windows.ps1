param(
  [Parameter(Mandatory = $true)][string]$ArtifactDirectory,
  [Parameter(Mandatory = $true)][string]$WorkDirectory,
  [Parameter(Mandatory = $true)][ValidateSet("msi", "nsis")][string]$InstallerType
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($null -eq ("QualificationNativeMethods" -as [type])) {
  Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

public static class QualificationNativeMethods {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern uint GetSystemWindowsDirectoryW(StringBuilder buffer, uint size);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out QualificationByHandleFileInformation information);
}

[StructLayout(LayoutKind.Sequential)]
public struct QualificationByHandleFileInformation {
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

public sealed class QualificationBoundedMemoryStream : MemoryStream {
    private readonly long limit;

    public QualificationBoundedMemoryStream(long limit) {
        if (limit < 1) throw new ArgumentOutOfRangeException(nameof(limit));
        this.limit = limit;
    }

    private void RequireCapacity(int count) {
        if (count < 0 || Length > limit - count) {
            throw new InvalidDataException("qualification native output exceeded its bound");
        }
    }

    public override void Write(byte[] buffer, int offset, int count) {
        RequireCapacity(count);
        base.Write(buffer, offset, count);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) {
        RequireCapacity(count);
        return base.WriteAsync(buffer, offset, count, cancellationToken);
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) {
        RequireCapacity(buffer.Length);
        return base.WriteAsync(buffer, cancellationToken);
    }
}
"@
}

function Get-OsWindowsDirectory {
  $capacity = 32768
  $buffer = [Text.StringBuilder]::new($capacity)
  $length = [QualificationNativeMethods]::GetSystemWindowsDirectoryW($buffer, [uint32]$capacity)
  if ($length -eq 0 -or $length -ge $capacity) {
    throw "Windows qualification could not obtain a bounded OS-trusted Windows directory."
  }
  $value = $buffer.ToString()
  if ($value.Length -ne $length -or $value.IndexOf([char]0) -ge 0 -or -not [IO.Path]::IsPathFullyQualified($value)) {
    throw "Windows qualification received an invalid OS-trusted Windows directory."
  }
  return [IO.Path]::GetFullPath($value)
}

function Get-ManagedFileIdentity([string]$Path) {
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    $information = [QualificationByHandleFileInformation]::new()
    if (-not [QualificationNativeMethods]::GetFileInformationByHandle($stream.SafeFileHandle, [ref]$information)) {
      throw "Windows qualification could not inspect the exact managed file handle."
    }
    return [ordered]@{
      attributes = [uint32]$information.FileAttributes
      volume = [uint32]$information.VolumeSerialNumber
      index = (([uint64]$information.FileIndexHigh -shl 32) -bor [uint64]$information.FileIndexLow)
      links = [uint32]$information.NumberOfLinks
      size = (([uint64]$information.FileSizeHigh -shl 32) -bor [uint64]$information.FileSizeLow)
    }
  } finally {
    $stream.Dispose()
  }
}

function Test-ExactEntryExists([string]$Path) {
  $parent = [IO.Path]::GetDirectoryName($Path)
  $name = [IO.Path]::GetFileName($Path)
  if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    return $false
  }
  return @(
    Get-ChildItem -LiteralPath $parent -Force |
      Where-Object { [String]::Equals($_.Name, $name, [StringComparison]::OrdinalIgnoreCase) }
  ).Count -ne 0
}

function Read-ManagedPrivateUtf8File(
  [string]$Path,
  [uint64]$MaximumBytes,
  [string]$Label
) {
  $before = Get-ManagedFileIdentity $Path
  if (($before.attributes -band [uint32][IO.FileAttributes]::Directory) -ne 0 -or
      ($before.attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0 -or
      $before.links -ne 1 -or $before.size -eq 0 -or $before.size -gt $MaximumBytes) {
    throw "$Label is not an exact bounded single-link regular file."
  }
  $acl = Get-Acl -LiteralPath $Path
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier])
  $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
  if (-not $acl.AreAccessRulesProtected -or -not $ownerSid.Equals($currentSid) -or $rules.Count -ne 1) {
    throw "$Label does not have an exact protected current-user-only DACL."
  }
  $rule = $rules[0]
  if ($rule.IsInherited -or -not $rule.IdentityReference.Equals($currentSid) -or
      $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
      $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
      $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
      $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
    throw "$Label DACL grants anything other than exact current-user full control."
  }
  $encoding = [Text.UTF8Encoding]::new($false, $true)
  $text = [IO.File]::ReadAllText($Path, $encoding)
  $after = Get-ManagedFileIdentity $Path
  if ($before.volume -ne $after.volume -or $before.index -ne $after.index -or
      $before.links -ne $after.links -or $before.size -ne $after.size -or
      $before.attributes -ne $after.attributes) {
    throw "$Label changed while qualification inspected it."
  }
  return $text
}

function Assert-ExactJsonProperties(
  [Text.Json.JsonElement]$Value,
  [string[]]$ExpectedNames,
  [string]$Label
) {
  if ($Value.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
    throw "$Label is not a JSON object."
  }
  $actualNames = [Collections.Generic.List[string]]::new()
  $seenNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($property in $Value.EnumerateObject()) {
    if (-not $seenNames.Add($property.Name)) {
      throw "$Label contains a duplicate JSON property: $($property.Name)"
    }
    $actualNames.Add($property.Name)
  }
  $actual = @($actualNames | Sort-Object)
  $expected = @($ExpectedNames | Sort-Object)
  if (($actual -join "`n") -cne ($expected -join "`n")) {
    throw "$Label has unexpected or missing JSON properties."
  }
}

function Read-ManagedWslGenerationSelection(
  [string]$Path,
  [string]$ExpectedRuntimeManifestSha256,
  [string]$ExpectedMachineImageSha256,
  [string]$ExpectedDefaultMachineName,
  [uint32]$ExpectedGenerationIndex
) {
  $label = "Managed WSL generation selection"
  $text = Read-ManagedPrivateUtf8File $Path (64 * 1024) $label
  $document = $null
  try {
    $document = [Text.Json.JsonDocument]::Parse($text)
  } catch {
    throw "$label is not one strict JSON document: $($_.Exception.Message)"
  }
  try {
    $root = $document.RootElement
    Assert-ExactJsonProperties $root @(
      "schema_version",
      "authorizes_cleanup",
      "manifest_sha256",
      "machine_image_sha256",
      "default_machine_name",
      "selected_machine_name",
      "generation_index",
      "preserved_collision_names"
    ) $label

    $schema = $root.GetProperty("schema_version")
    $cleanupAuthority = $root.GetProperty("authorizes_cleanup")
    $manifestSha256 = $root.GetProperty("manifest_sha256")
    $machineImageSha256 = $root.GetProperty("machine_image_sha256")
    $defaultMachineName = $root.GetProperty("default_machine_name")
    $selectedMachineName = $root.GetProperty("selected_machine_name")
    $generationIndex = $root.GetProperty("generation_index")
    $preservedCollisionNames = $root.GetProperty("preserved_collision_names")
    if ($schema.ValueKind -ne [Text.Json.JsonValueKind]::String -or
        $schema.GetString() -cne "ai-security-scanner.managed-wsl-generation-selection/v1" -or
        $cleanupAuthority.ValueKind -ne [Text.Json.JsonValueKind]::False -or
        $manifestSha256.ValueKind -ne [Text.Json.JsonValueKind]::String -or
        $manifestSha256.GetString() -cne $ExpectedRuntimeManifestSha256 -or
        $machineImageSha256.ValueKind -ne [Text.Json.JsonValueKind]::String -or
        $machineImageSha256.GetString() -cne $ExpectedMachineImageSha256 -or
        $defaultMachineName.ValueKind -ne [Text.Json.JsonValueKind]::String -or
        $defaultMachineName.GetString() -cne $ExpectedDefaultMachineName -or
        $selectedMachineName.ValueKind -ne [Text.Json.JsonValueKind]::String -or
        $generationIndex.ValueKind -ne [Text.Json.JsonValueKind]::Number -or
        $preservedCollisionNames.ValueKind -ne [Text.Json.JsonValueKind]::Array) {
      throw "$label has an invalid schema, type, release identity, or cleanup authority."
    }
    [uint32]$parsedGenerationIndex = 0
    if (-not $generationIndex.TryGetUInt32([ref]$parsedGenerationIndex) -or
        $parsedGenerationIndex -ne $ExpectedGenerationIndex -or
        $parsedGenerationIndex -lt 1 -or $parsedGenerationIndex -gt 32) {
      throw "$label has an invalid or mismatched generation index."
    }
    $selectedMachineNameValue = $selectedMachineName.GetString()
    if ($selectedMachineNameValue -cnotmatch '^assm2-iso-[0-9a-f]{20}$') {
      throw "$label does not select one canonical isolated machine identity."
    }

    $preserved = [Collections.Generic.List[string]]::new()
    $seenPreserved = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($collisionNameElement in $preservedCollisionNames.EnumerateArray()) {
      if ($collisionNameElement.ValueKind -ne [Text.Json.JsonValueKind]::String) {
        throw "$label has a non-string preserved collision name."
      }
      $collisionName = $collisionNameElement.GetString()
      if ([String]::IsNullOrEmpty($collisionName) -or
          [Text.Encoding]::UTF8.GetByteCount($collisionName) -gt 30 -or
          (-not [String]::Equals(
            $collisionName,
            $ExpectedDefaultMachineName,
            [StringComparison]::OrdinalIgnoreCase
          ) -and $collisionName -cnotmatch '^assm2-iso-[0-9a-f]{20}$') -or
          -not $seenPreserved.Add($collisionName)) {
        throw "$label has an invalid, unrelated, or duplicate preserved collision name."
      }
      $preserved.Add($collisionName)
    }
    if ($preserved.Count -gt 32) {
      throw "$label exceeds the bounded preserved-collision count."
    }
    return [PSCustomObject]@{
      GenerationIndex = $parsedGenerationIndex
      SelectedMachineName = $selectedMachineNameValue
      PreservedCollisionNames = @($preserved)
    }
  } finally {
    $document.Dispose()
  }
}

function Assert-ManagedPrivateDirectory([string]$Path, [string]$Label) {
  $item = Get-Item -LiteralPath $Path -Force
  if (-not $item.PSIsContainer -or
      ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Label is not an exact real directory."
  }
  $acl = Get-Acl -LiteralPath $Path
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier])
  $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
  if (-not $acl.AreAccessRulesProtected -or -not $ownerSid.Equals($currentSid) -or $rules.Count -ne 1) {
    throw "$Label does not have an exact protected current-user-only DACL."
  }
  $rule = $rules[0]
  [Security.AccessControl.InheritanceFlags]$expectedInheritance = (
    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [Security.AccessControl.InheritanceFlags]::ObjectInherit
  )
  if ($rule.IsInherited -or -not $rule.IdentityReference.Equals($currentSid) -or
      $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
      $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
      $rule.InheritanceFlags -ne $expectedInheritance -or
      $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
    throw "$Label DACL grants anything other than inheritable current-user full control."
  }
}

function Assert-ManagedWslDistributionDirectory([string]$Path, [string]$Label) {
  $item = Get-Item -LiteralPath $Path -Force
  if (-not $item.PSIsContainer -or
      ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Label is not an exact real directory."
  }
  $acl = Get-Acl -LiteralPath $Path
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $localSystemSid = [Security.Principal.SecurityIdentifier]::new(
    [Security.Principal.WellKnownSidType]::LocalSystemSid,
    $null
  )
  $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier])
  $rawDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
    $acl.GetSecurityDescriptorBinaryForm(),
    0
  )
  $ownerDefaulted = (
    $rawDescriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::OwnerDefaulted
  ) -ne [Security.AccessControl.ControlFlags]::None
  $daclDefaulted = (
    $rawDescriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclDefaulted
  ) -ne [Security.AccessControl.ControlFlags]::None
  $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
  if (-not $acl.AreAccessRulesProtected -or $ownerDefaulted -or $daclDefaulted -or
      -not $ownerSid.Equals($currentSid) -or $rules.Count -ne 2) {
    throw "$Label does not have an exact protected non-defaulted current-user-owned two-principal DACL."
  }
  [Security.AccessControl.InheritanceFlags]$expectedInheritance = (
    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [Security.AccessControl.InheritanceFlags]::ObjectInherit
  )
  $sawCurrentUser = $false
  $sawLocalSystem = $false
  foreach ($rule in $rules) {
    if ($rule.IsInherited -or
        $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
        $rule.InheritanceFlags -ne $expectedInheritance -or
        $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
      throw "$Label DACL contains a rule other than explicit inheritable full control."
    }
    if ($rule.IdentityReference.Equals($currentSid)) {
      if ($sawCurrentUser) {
        throw "$Label DACL contains a duplicate current-user rule."
      }
      $sawCurrentUser = $true
    } elseif ($rule.IdentityReference.Equals($localSystemSid)) {
      if ($sawLocalSystem) {
        throw "$Label DACL contains a duplicate LocalSystem rule."
      }
      $sawLocalSystem = $true
    } else {
      throw "$Label DACL grants an unexpected principal."
    }
  }
  if (-not $sawCurrentUser -or -not $sawLocalSystem) {
    throw "$Label DACL does not grant both the current user and LocalSystem."
  }
}

function Get-BoundedManagedFailureOutput(
  [string]$Path,
  [string]$StreamLabel,
  [int]$MaximumBytes = 16384
) {
  if ($MaximumBytes -lt 1 -or $MaximumBytes -gt 65536) {
    throw "Managed runtime failure-output byte bound is invalid."
  }
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    return "$StreamLabel=<missing>"
  }
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    $byteCount = [int][Math]::Min([int64]$MaximumBytes, $stream.Length)
    [byte[]]$bytes = [byte[]]::new($byteCount)
    $offset = 0
    while ($offset -lt $byteCount) {
      $read = $stream.Read($bytes, $offset, $byteCount - $offset)
      if ($read -eq 0) { break }
      $offset += $read
    }
    $text = [Text.UTF8Encoding]::new($false, $false).GetString($bytes, 0, $offset)
    if ($text.StartsWith([char]0xfeff)) {
      $text = $text.Substring(1)
    }
    $encoded = ConvertTo-Json -InputObject $text -Compress
    $suffix = if ($stream.Length -gt $MaximumBytes) { " (truncated at $MaximumBytes bytes)" } else { "" }
    return "$StreamLabel=$encoded$suffix"
  } finally {
    $stream.Dispose()
  }
}

function Assert-ManagedSshIdentity([string]$ProviderReleaseHome) {
  $identityDirectory = Join-Path $ProviderReleaseHome "data\containers\podman\machine"
  $privateKey = Join-Path $identityDirectory "machine"
  $publicKey = Join-Path $identityDirectory "machine.pub"
  $privateText = Read-ManagedPrivateUtf8File $privateKey (16 * 1024) "Managed SSH private key"
  $publicText = Read-ManagedPrivateUtf8File $publicKey (4 * 1024) "Managed SSH public key"
  if (-not $privateText.StartsWith("-----BEGIN OPENSSH PRIVATE KEY-----`n", [StringComparison]::Ordinal) -or
      -not $privateText.TrimEnd().EndsWith("-----END OPENSSH PRIVATE KEY-----", [StringComparison]::Ordinal)) {
    throw "Managed SSH private key is not an OpenSSH private key."
  }
  if ($publicText -cnotmatch "\Assh-ed25519 [A-Za-z0-9+/]+={0,2} ai-security-scanner-managed-runtime`n?\z") {
    throw "Managed SSH public key does not have the exact Ed25519 identity format."
  }
  foreach ($stagingName in @(".machine.private-key-new", ".machine.public-key-new")) {
    if (Test-ExactEntryExists (Join-Path $identityDirectory $stagingName)) {
      throw "Managed SSH identity staging entries remain after start."
    }
  }
}

function ConvertFrom-StrictWslInventory([byte[]]$Bytes) {
  if ($Bytes.Length -gt 1024 * 1024) {
    throw "Windows qualification WSL inventory exceeded its byte bound."
  }
  $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
  $strictUtf16Le = [Text.UnicodeEncoding]::new($false, $false, $true)
  [string]$decoded = ""
  if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xef -and $Bytes[1] -eq 0xbb -and $Bytes[2] -eq 0xbf) {
    [byte[]]$payload = [byte[]]::new($Bytes.Length - 3)
    if ($payload.Length -ne 0) { [Array]::Copy($Bytes, 3, $payload, 0, $payload.Length) }
    try { $decoded = $strictUtf8.GetString($payload) }
    catch { throw "Windows qualification WSL inventory was not valid UTF-8." }
  } elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xff -and $Bytes[1] -eq 0xfe) {
    [byte[]]$payload = [byte[]]::new($Bytes.Length - 2)
    if ($payload.Length -ne 0) { [Array]::Copy($Bytes, 2, $payload, 0, $payload.Length) }
    try { $decoded = $strictUtf16Le.GetString($payload) }
    catch { throw "Windows qualification WSL inventory was not valid UTF-16LE." }
  } elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xfe -and $Bytes[1] -eq 0xff) {
    throw "Windows qualification WSL inventory used unsupported UTF-16BE."
  } else {
    $validUtf8 = $true
    try { $decoded = $strictUtf8.GetString($Bytes) }
    catch { $validUtf8 = $false }
    if (-not $validUtf8 -or $decoded.IndexOf([char]0) -ge 0) {
      try { $decoded = $strictUtf16Le.GetString($Bytes) }
      catch { throw "Windows qualification WSL inventory was neither valid UTF-8 nor UTF-16LE." }
    }
  }
  if ($decoded.IndexOf([char]0) -ge 0 -or $decoded.IndexOf([char]0xfeff) -ge 0) {
    throw "Windows qualification WSL inventory contained an invalid code point."
  }
  [string[]]$lines = $decoded.Split([char[]]@([char]10), [StringSplitOptions]::None)
  $distributions = [Collections.Generic.List[string]]::new()
  for ($lineIndex = 0; $lineIndex -lt $lines.Length; $lineIndex++) {
    $line = $lines[$lineIndex]
    if ($line.Length -eq 0 -and $lineIndex -eq $lines.Length - 1) {
      continue
    }
    if ($line.EndsWith("`r", [StringComparison]::Ordinal)) {
      $line = $line.Substring(0, $line.Length - 1)
    }
    if ($line.Length -eq 0 -or $strictUtf8.GetByteCount($line) -gt 256 -or $line.Trim() -cne $line) {
      throw "Windows qualification WSL inventory contained an invalid name."
    }
    for ($offset = 0; $offset -lt $line.Length; $offset++) {
      $codePoint = [char]::ConvertToUtf32($line, $offset)
      if ($codePoint -gt 0xffff) { $offset++ }
      if (($codePoint -ge 0 -and $codePoint -le 0x1f) -or
          ($codePoint -ge 0x7f -and $codePoint -le 0x9f) -or
          $codePoint -eq 0x2028 -or $codePoint -eq 0x2029 -or
          ($codePoint -ge 0xfdd0 -and $codePoint -le 0xfdef) -or
          ($codePoint -band 0xffff) -eq 0xfffe -or ($codePoint -band 0xffff) -eq 0xffff) {
        throw "Windows qualification WSL inventory contained an invalid name."
      }
    }
    if ($distributions.Count -eq 1024) {
      throw "Windows qualification WSL inventory contained too many names."
    }
    $distributions.Add($line)
  }
  return $distributions.ToArray()
}

function Invoke-WslInventoryRaw(
  [string]$Wsl,
  [string]$SystemRoot,
  [string]$System32,
  [string]$WorkingDirectory
) {
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $Wsl
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $startInfo.WorkingDirectory = $WorkingDirectory
  $startInfo.ArgumentList.Add("--list")
  $startInfo.ArgumentList.Add("--quiet")
  $startInfo.Environment.Clear()
  $startInfo.Environment["SystemRoot"] = $SystemRoot
  $startInfo.Environment["WINDIR"] = $SystemRoot
  $startInfo.Environment["PATH"] = $System32
  $startInfo.Environment["NoDefaultCurrentDirectoryInExePath"] = "1"
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  $stdout = [QualificationBoundedMemoryStream]::new(1024 * 1024)
  $stderr = [QualificationBoundedMemoryStream]::new(1024 * 1024)
  try {
    if (-not $process.Start()) {
      throw "Windows qualification could not start the OS-trusted WSL inventory executable."
    }
    $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
    $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderr)
    if (-not $process.WaitForExit(30000)) {
      try { $process.Kill($true) } catch {}
      $process.WaitForExit(5000) | Out-Null
      throw "Windows qualification WSL inventory exceeded its deadline."
    }
    $drain = [Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdoutTask, $stderrTask))
    try { $drained = $drain.Wait(5000) } catch { throw "Windows qualification WSL inventory output exceeded its bound or failed to drain." }
    if (-not $drained -or -not $drain.IsCompletedSuccessfully) {
      throw "Windows qualification WSL inventory output failed to drain within its deadline."
    }
    if ($process.ExitCode -ne 0) {
      throw "Windows qualification could not inventory WSL distributions after managed runtime uninstall."
    }
    return ConvertFrom-StrictWslInventory ($stdout.ToArray())
  } finally {
    $stdout.Dispose()
    $stderr.Dispose()
    $process.Dispose()
  }
}

function Invoke-BoundedCleanupProcess(
  [string]$FileName,
  [string[]]$Arguments,
  [int]$TimeoutMilliseconds,
  [string]$Label,
  [Collections.Generic.Dictionary[string,string]]$Environment = $null,
  [string]$RawFinalNsisUninstallDirectory = ""
) {
  if ($TimeoutMilliseconds -lt 1000 -or $TimeoutMilliseconds -gt 600000) {
    throw "$Label cleanup deadline is outside its fixed bound."
  }
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $FileName
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
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
  if ($null -ne $Environment) {
    $startInfo.Environment.Clear()
    foreach ($entry in $Environment.GetEnumerator()) {
      $startInfo.Environment[$entry.Key] = $entry.Value
    }
  }
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  $stdout = [QualificationBoundedMemoryStream]::new(64 * 1024)
  $stderr = [QualificationBoundedMemoryStream]::new(64 * 1024)
  try {
    if (-not $process.Start()) {
      throw "$Label cleanup process did not start."
    }
    $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
    $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderr)
    if (-not $process.WaitForExit($TimeoutMilliseconds)) {
      try { $process.Kill($true) } catch {}
      $process.WaitForExit(5000) | Out-Null
      throw "$Label cleanup exceeded its fixed deadline."
    }
    $drain = [Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdoutTask, $stderrTask))
    try { $drained = $drain.Wait(5000) } catch { throw "$Label cleanup output exceeded its bound or failed to drain." }
    if (-not $drained -or -not $drain.IsCompletedSuccessfully) {
      throw "$Label cleanup output failed to drain within its deadline."
    }
    if ($process.ExitCode -ne 0) {
      throw "$Label cleanup failed with status $($process.ExitCode)."
    }
  } finally {
    $stdout.Dispose()
    $stderr.Dispose()
    $process.Dispose()
  }
}

function Get-QualificationFileProof(
  [string]$Path,
  [string]$Label,
  [uint64]$MaximumBytes = 512 * 1024 * 1024
) {
  $fullPath = [IO.Path]::GetFullPath($Path)
  $item = Get-Item -LiteralPath $fullPath -Force
  if ($item.PSIsContainer -or
      ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Label is not one no-reparse regular file."
  }
  $before = Get-ManagedFileIdentity $fullPath
  if (($before.attributes -band [uint32][IO.FileAttributes]::Directory) -ne 0 -or
      ($before.attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0 -or
      $before.links -ne 1 -or $before.size -lt 1 -or $before.size -gt $MaximumBytes) {
    throw "$Label is not one bounded single-link regular file."
  }
  $sha256 = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $after = Get-ManagedFileIdentity $fullPath
  $itemAfter = Get-Item -LiteralPath $fullPath -Force
  if ($itemAfter.PSIsContainer -or
      ($itemAfter.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
      $before.attributes -ne $after.attributes -or $before.volume -ne $after.volume -or
      $before.index -ne $after.index -or $before.links -ne $after.links -or
      $before.size -ne $after.size -or $sha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw "$Label changed while its exact file identity was hashed."
  }
  return [PSCustomObject]@{
    FullName = $fullPath
    Length = [uint64]$before.size
    Sha256 = $sha256
    Attributes = [uint32]$before.attributes
    Volume = [uint32]$before.volume
    FileIndex = [uint64]$before.index
    Links = [uint32]$before.links
  }
}

function Assert-SameQualificationFileProof([object]$Expected, [object]$Actual, [string]$Label) {
  if (-not [String]::Equals(
      [string]$Expected.FullName,
      [string]$Actual.FullName,
      [StringComparison]::OrdinalIgnoreCase
    ) -or [uint64]$Expected.Length -ne [uint64]$Actual.Length -or
    [string]$Expected.Sha256 -cne [string]$Actual.Sha256 -or
    [uint32]$Expected.Attributes -ne [uint32]$Actual.Attributes -or
    [uint32]$Expected.Volume -ne [uint32]$Actual.Volume -or
    [uint64]$Expected.FileIndex -ne [uint64]$Actual.FileIndex -or
    [uint32]$Expected.Links -ne [uint32]$Actual.Links) {
    throw "$Label changed file bytes or NTFS identity."
  }
}

function Invoke-BoundedCopiedNsisUninstaller(
  [string]$SourceUninstaller,
  [string]$InstallDirectory,
  [string]$WorkRoot,
  [string]$Label
) {
  $copyName = "bounded-nsis-uninstaller-copy.exe"
  $boundedWorkRoot = [IO.Path]::GetFullPath($WorkRoot)
  $copyPath = [IO.Path]::GetFullPath((Join-Path $boundedWorkRoot $copyName))
  if (-not [String]::Equals(
      [IO.Path]::GetDirectoryName($copyPath),
      $boundedWorkRoot,
      [StringComparison]::OrdinalIgnoreCase
    ) -or [IO.Path]::GetFileName($copyPath) -cne $copyName) {
    throw "$Label execution copy escaped its fixed work root."
  }
  $workRootItem = Get-Item -LiteralPath $boundedWorkRoot -Force
  $installDirectoryItem = Get-Item -LiteralPath $InstallDirectory -Force
  if (-not $workRootItem.PSIsContainer -or
      ($workRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
      -not $installDirectoryItem.PSIsContainer -or
      ($installDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Label requires real work and installation directories."
  }
  if (Test-ExactEntryExists $copyPath) {
    throw "$Label refused a pre-existing execution copy."
  }

  $sourceBefore = Get-QualificationFileProof $SourceUninstaller "$Label source"
  $copyProof = $null
  try {
    Copy-Item -LiteralPath $SourceUninstaller -Destination $copyPath
    $sourceAfter = Get-QualificationFileProof $SourceUninstaller "$Label source after copy"
    Assert-SameQualificationFileProof $sourceBefore $sourceAfter "$Label source copy"
    $copyProof = Get-QualificationFileProof $copyPath "$Label execution copy"
    if ([uint64]$copyProof.Length -ne [uint64]$sourceBefore.Length -or
        [string]$copyProof.Sha256 -cne [string]$sourceBefore.Sha256) {
      throw "$Label execution copy differs from its verified source."
    }

    Invoke-BoundedCleanupProcess $copyPath @("/S") 180000 $Label -RawFinalNsisUninstallDirectory $InstallDirectory
  } finally {
    if (Test-ExactEntryExists $copyPath) {
      $copyAfter = Get-QualificationFileProof $copyPath "$Label execution copy cleanup"
      if ($null -ne $copyProof) {
        Assert-SameQualificationFileProof $copyProof $copyAfter "$Label execution copy cleanup"
      }
      Remove-Item -LiteralPath $copyPath -Force
    }
    if (Test-ExactEntryExists $copyPath) {
      throw "$Label execution copy remains after bounded cleanup."
    }
  }
}

function Remove-BoundedQualificationTree([string]$Path, [string]$Label) {
  $job = Start-Job -ScriptBlock {
    param([string]$ExactPath)
    $ErrorActionPreference = "Stop"
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
      try {
        if (Test-Path -LiteralPath $ExactPath) {
          Remove-Item -LiteralPath $ExactPath -Recurse -Force
        }
        if (-not (Test-Path -LiteralPath $ExactPath)) {
          return
        }
      } catch {
        if ([DateTime]::UtcNow -ge $deadline) {
          throw
        }
      }
      Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "qualification tree remained after its fixed cleanup deadline"
  } -ArgumentList $Path
  try {
    $completed = Wait-Job -Job $job -Timeout 35
    if ($null -eq $completed) {
      Stop-Job -Job $job -ErrorAction SilentlyContinue
      throw "$Label cleanup exceeded its fixed deadline."
    }
    Receive-Job -Job $job -ErrorAction Stop | Out-Null
    if ($job.State -ne [Management.Automation.JobState]::Completed) {
      throw "$Label cleanup did not complete successfully."
    }
  } finally {
    if ($job.State -eq [Management.Automation.JobState]::Running) {
      Stop-Job -Job $job -ErrorAction SilentlyContinue
    }
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
  }
}

function Get-BoundedCleanupFailure([Management.Automation.ErrorRecord]$Failure, [string]$Label) {
  $message = [string]$Failure.Exception.Message
  $message = $message.Replace("`r", " ").Replace("`n", " ")
  if ($message.Length -gt 2048) {
    $message = $message.Substring(0, 2048) + " (truncated)"
  }
  return "$Label`: $message"
}

foreach ($overrideEnvironmentName in @(
    "AI_SECURITY_SCANNER_DATA_DIR",
    "AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE"
  )) {
  if ($null -ne [Environment]::GetEnvironmentVariable(
      $overrideEnvironmentName,
      [EnvironmentVariableTarget]::Process
    )) {
    throw "Windows qualification refuses ambient product path override: $overrideEnvironmentName"
  }
}

$artifactRoot = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
$runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
$workRoot = [IO.Path]::GetFullPath($WorkDirectory)
if (-not $workRoot.StartsWith($runnerTemp + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Qualification work directory must be below RUNNER_TEMP."
}
New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
$installDirectory = Join-Path $runnerTemp "ai-security-scanner-platform-qualification-$InstallerType-installed"
$reportedLocalApplicationData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if ([String]::IsNullOrWhiteSpace($reportedLocalApplicationData) -or
    -not [IO.Path]::IsPathFullyQualified($reportedLocalApplicationData)) {
  throw "Windows qualification could not obtain OS-resolved LocalApplicationData."
}
$localApplicationData = [IO.Path]::GetFullPath($reportedLocalApplicationData)
$localApplicationDataItem = Get-Item -LiteralPath $localApplicationData -Force
if (-not $localApplicationDataItem.PSIsContainer -or
    ($localApplicationDataItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
  throw "OS-resolved LocalApplicationData is not a real directory."
}
$dataDirectory = [IO.Path]::GetFullPath(
  (Join-Path $localApplicationData "dev.teddashh.ai-security-scanner")
)
if (-not [String]::Equals(
    [IO.Path]::GetDirectoryName($dataDirectory),
    $localApplicationData,
    [StringComparison]::OrdinalIgnoreCase
  ) -or [IO.Path]::GetFileName($dataDirectory) -cne "dev.teddashh.ai-security-scanner") {
  throw "Qualification data directory escaped OS-resolved LocalApplicationData."
}
if (-not ([IO.Path]::GetFileName($installDirectory)).StartsWith(
    "ai-security-scanner-platform-qualification-",
    [StringComparison]::Ordinal
  )) {
  throw "Refusing an unexpected qualification installation path."
}
if (Test-ExactEntryExists $dataDirectory) {
  throw "Qualification requires a fresh default product LocalApplicationData namespace."
}

$installed = $false
$installerPath = $null
$uninstallerPath = $null
$cli = $null
$wsl = $null
$systemRoot = $null
$system32 = $null
$providerRoot = $null
$managedWslDistributions = @()
$managedRuntimePurgeSucceeded = $false
$providerRootEmpty = $false
$exactWslAbsent = $false
$primaryFailure = $null
$cleanupFailures = [Collections.Generic.List[string]]::new()
try {
  $installerManifestPath = Join-Path $artifactRoot "installers-windows-x86_64.json"
  $installerManifest = Get-Content -LiteralPath $installerManifestPath -Raw | ConvertFrom-Json
  $installers = @($installerManifest.installers | Where-Object { $_.bundleType -eq $InstallerType })
  if ($installers.Count -ne 1 -or [IO.Path]::GetFileName($installers[0].file) -ne $installers[0].file) {
    throw "Windows qualification requires exactly one flat $InstallerType installer."
  }
  $installerPath = (Resolve-Path -LiteralPath (Join-Path $artifactRoot $installers[0].file)).Path
  if ([IO.Path]::GetDirectoryName($installerPath) -ne $artifactRoot) {
    throw "$InstallerType installer escaped the downloaded release artifact directory."
  }

  if ($InstallerType -eq "msi") {
    $install = Start-Process -FilePath "msiexec.exe" -ArgumentList @(
      "/i", $installerPath, "INSTALLDIR=$installDirectory", "/qn", "/norestart"
    ) -Wait -PassThru
  } else {
    # NSIS requires /D to be the final argument. The bounded RUNNER_TEMP path
    # deliberately contains no shell expansion or caller-selected component.
    $install = Start-Process -FilePath $installerPath -ArgumentList @(
      "/S", "/D=$installDirectory"
    ) -Wait -PassThru
  }
  $installSucceeded = $install.ExitCode -eq 0 -or (
    $InstallerType -eq "nsis" -and $install.ExitCode -eq 3010
  )
  if (-not $installSucceeded) {
    throw "$InstallerType installation failed with status $($install.ExitCode)."
  }
  $installed = $true

  function Find-OneInstalledFile([string]$Name, [scriptblock]$Filter = { $true }) {
    $matches = @(Get-ChildItem -LiteralPath $installDirectory -Filter $Name -File -Recurse | Where-Object $Filter)
    if ($matches.Count -ne 1) {
      throw "Expected exactly one installed $Name, found $($matches.Count)."
    }
    if (-not [IO.Path]::IsPathFullyQualified($matches[0].FullName)) {
      throw "Installed $Name path is not absolute."
    }
    return $matches[0].FullName
  }

  $desktop = Find-OneInstalledFile "ai-security-scanner.exe" { $_.FullName -notmatch "(?i)uninstall" }
  $egress = Find-OneInstalledFile "ai-security-scanner-egress-gateway.exe"
  $broker = Find-OneInstalledFile "ai-security-scanner-bootstrap-broker.exe"
  $cli = Find-OneInstalledFile "ai-security-scanner-cli.exe"
  if ($InstallerType -eq "nsis") {
    $uninstallers = @(Get-ChildItem -LiteralPath $installDirectory -Filter "uninstall.exe" -File -Recurse)
    if ($uninstallers.Count -ne 1 -or -not [IO.Path]::IsPathFullyQualified($uninstallers[0].FullName)) {
      throw "Expected exactly one absolute installed NSIS uninstaller, found $($uninstallers.Count)."
    }
    $uninstallerPath = $uninstallers[0].FullName
  }
  $runtimeManifests = @(
    Get-ChildItem -LiteralPath $installDirectory -Filter "manifest.json" -File -Recurse |
      Where-Object { $_.FullName -match "(?i)[\\/]managed-runtime[\\/]manifest\.json$" }
  )
  if ($runtimeManifests.Count -ne 1) {
    throw "Expected exactly one installed managed-runtime manifest, found $($runtimeManifests.Count)."
  }
  $runtimeManifest = $runtimeManifests[0].FullName
  Copy-Item -LiteralPath $runtimeManifest -Destination (Join-Path $workRoot "installed-runtime-manifest.json")
  $runtimeContract = Get-Content -LiteralPath $runtimeManifest -Raw | ConvertFrom-Json
  $runtimeManifestSha256 = (Get-FileHash -LiteralPath $runtimeManifest -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($runtimeManifestSha256 -cnotmatch "^[0-9a-f]{64}$") {
    throw "Windows qualification runtime manifest has an invalid SHA-256."
  }
  $windowsTargets = @(
    $runtimeContract.targets |
      Where-Object { $_.operating_system -eq "windows" -and $_.architecture -eq "x86_64" -and $_.provider -eq "wsl" }
  )
  if ($windowsTargets.Count -ne 1) {
    throw "Windows qualification requires exactly one Windows x86_64 WSL target."
  }
  $machineImageSha256 = [string]$windowsTargets[0].machine_image.sha256
  if ($machineImageSha256 -cnotmatch "^[0-9a-f]{64}$") {
    throw "Windows qualification target has an invalid machine-image SHA-256."
  }
  $managedRuntimeStateRoot = Join-Path $dataDirectory "managed-runtime"
  $providerRoot = Join-Path $managedRuntimeStateRoot "provider-home"
  $generationRoot = Join-Path $managedRuntimeStateRoot "wsl-generations"
  $defaultMachineName = "assm2-win-x64-$($machineImageSha256.Substring(0, 12))"
  $reportedSystemRoot = Get-OsWindowsDirectory
  $systemRoot = (Resolve-Path -LiteralPath $reportedSystemRoot).Path
  $system32 = (Resolve-Path -LiteralPath (Join-Path $systemRoot "System32")).Path
  if (-not $system32.StartsWith($systemRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Windows qualification System32 escaped the OS-trusted Windows directory."
  }
  $wslItem = Get-Item -LiteralPath (Join-Path $system32 "wsl.exe") -Force
  $wsl = $wslItem.FullName
  if (-not [IO.Path]::IsPathFullyQualified($wsl) -or
      -not [String]::Equals([IO.Path]::GetDirectoryName($wsl), $system32, [StringComparison]::OrdinalIgnoreCase) -or
      $wslItem.PSIsContainer -or ($wslItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Windows qualification requires the real absolute OS-trusted System32 wsl.exe."
  }

  & $cli --help | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Installed casework CLI failed its help probe."
  }
  function Invoke-Managed([string]$OutputName, [string[]]$Arguments) {
    $stdout = Join-Path $workRoot "$OutputName.json"
    $stderr = Join-Path $workRoot "$OutputName.stderr.log"
    & $cli --json runtime managed @Arguments 1> $stdout 2> $stderr
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
      $boundedStdout = Get-BoundedManagedFailureOutput $stdout "stdout"
      $boundedStderr = Get-BoundedManagedFailureOutput $stderr "stderr"
      throw "Managed runtime command $OutputName failed with status ${exitCode}; $boundedStdout; $boundedStderr"
    }
    try {
      return Get-Content -LiteralPath $stdout -Raw | ConvertFrom-Json
    } catch {
      throw "Managed runtime command $OutputName did not emit one JSON document."
    }
  }

  $initialStatus = Invoke-Managed "initial-status" @("status")
  Assert-ManagedPrivateDirectory $dataDirectory "Canonical product data directory"
  $installStatus = Invoke-Managed "install" @("install")
  $installedStatus = Invoke-Managed "installed-status" @("status")
  if ((Test-ExactEntryExists $providerRoot) -or (Test-ExactEntryExists $generationRoot)) {
    throw "Managed runtime install/status created provider or generation state before start."
  }
  # Install verifies and stages only the immutable runtime payload. The
  # provider-owned namespace is deliberately created by start, so inspect its
  # directories only after that lifecycle transition has completed.
  $startStatus = Invoke-Managed "start" @("start")
  Assert-ManagedPrivateDirectory $generationRoot "Managed WSL generation routing directory"
  $generationEntries = @(Get-ChildItem -LiteralPath $generationRoot -Force)
  if ($generationEntries.Count -lt 1 -or $generationEntries.Count -gt 32) {
    throw "Managed runtime start did not create a bounded generation selection set."
  }
  $generationSelections = [Collections.Generic.List[object]]::new()
  $seenGenerationIndices = [Collections.Generic.HashSet[uint32]]::new()
  $escapedManifestSha256 = [Regex]::Escape($runtimeManifestSha256)
  foreach ($generationEntry in $generationEntries) {
    if ($generationEntry.PSIsContainer -or
        ($generationEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $generationEntry.Name -cnotmatch "^${escapedManifestSha256}\.([0-9]{1,2})\.json$") {
      throw "Managed WSL generation routing directory contains an unexpected entry."
    }
    [uint32]$generationIndex = [uint32]::Parse(
      $Matches[1],
      [Globalization.CultureInfo]::InvariantCulture
    )
    $canonicalGenerationName = "$runtimeManifestSha256.$generationIndex.json"
    if ($generationIndex -lt 1 -or $generationIndex -gt 32 -or
        $generationEntry.Name -cne $canonicalGenerationName -or
        -not $seenGenerationIndices.Add($generationIndex)) {
      throw "Managed WSL generation routing directory contains an invalid generation index."
    }
    $generationSelections.Add((Read-ManagedWslGenerationSelection (
      $generationEntry.FullName
    ) $runtimeManifestSha256 $machineImageSha256 $defaultMachineName $generationIndex))
  }
  $orderedGenerationSelections = @($generationSelections | Sort-Object GenerationIndex)
  $activeGenerationSelection = $orderedGenerationSelections[-1]
  foreach ($earlierSelection in @($orderedGenerationSelections | Select-Object -SkipLast 1)) {
    $preservesEarlierSelection = @(
      $activeGenerationSelection.PreservedCollisionNames | Where-Object {
          [String]::Equals(
            [string]$_,
            [string]$earlierSelection.SelectedMachineName,
            [StringComparison]::OrdinalIgnoreCase
          )
        }
    ).Count -ne 0
    if (-not $preservesEarlierSelection) {
      throw "Active managed WSL generation does not preserve an earlier selected collision."
    }
  }
  $managedMachineName = [string]$activeGenerationSelection.SelectedMachineName
  $managedWslDistributions = @($orderedGenerationSelections | ForEach-Object {
    "podman-$([string]$_.SelectedMachineName)"
  })
  $isolatedSuffix = $managedMachineName.Substring("assm2-iso-".Length)
  $providerNamespace = "$($runtimeManifestSha256.Substring(0, 8))-iso-$($isolatedSuffix.Substring(0, 12))"
  $providerReleaseHome = Join-Path $providerRoot $providerNamespace
  Assert-ManagedPrivateDirectory $providerReleaseHome "Managed isolated provider home"
  $podmanNamespaceDirectories = @(
    (Join-Path $providerReleaseHome "run\podman"),
    (Join-Path $providerReleaseHome "config\containers\podman\machine\wsl"),
    (Join-Path $providerReleaseHome "data\containers\podman\machine"),
    (Join-Path $providerReleaseHome "data\containers\podman\machine\wsl"),
    (Join-Path $providerReleaseHome "data\containers\podman\machine\wsl\cache")
  )
  foreach ($namespaceDirectory in $podmanNamespaceDirectories) {
    Assert-ManagedPrivateDirectory $namespaceDirectory "Managed Podman namespace directory"
  }
  $wslDistributionDirectory = Join-Path $providerReleaseHome "data\containers\podman\machine\wsl\wsldist"
  Assert-ManagedWslDistributionDirectory $wslDistributionDirectory "Managed WSL distribution directory"
  Assert-ManagedSshIdentity $providerReleaseHome
  # Native WSL systemd services do not keep a distribution alive by themselves.
  # Observe the installed client after the WSL idle grace period before executing containers.
  Start-Sleep -Seconds 30
  $runningStatus = Invoke-Managed "running-status" @("status")
  if ($runningStatus.phase -ne "running") {
    throw "Managed runtime did not remain running beyond WSL idle shutdown."
  }
  $egressQualification = Invoke-Managed "egress-qualification" @("qualify-egress")
  $containerQualification = Invoke-Managed "container-qualification" @("qualify")

  # The desktop uses this exact default LocalAppData root. Observe it only
  # after the same managed runtime is healthy, so first-launch automation sees
  # Ready instead of racing a second setup in another namespace.
  $desktopProcess = Start-Process -FilePath $desktop -PassThru
  Start-Sleep -Seconds 12
  if ($desktopProcess.HasExited) {
    throw "Installed Windows desktop exited before the 12-second observation window with status $($desktopProcess.ExitCode)."
  }
  Stop-Process -Id $desktopProcess.Id -Force
  $desktopProcess.WaitForExit()

  $stopStatus = Invoke-Managed "stop" @("stop")
  $restartStatus = Invoke-Managed "restart" @("start")
  Start-Sleep -Seconds 30
  $restartRunning = Invoke-Managed "restart-running-status" @("status")
  if ($restartRunning.phase -ne "running") {
    throw "Restarted managed runtime did not remain running beyond WSL idle shutdown."
  }
  $stopStatus = Invoke-Managed "stop-after-restart" @("stop")
  $stoppedStatus = Invoke-Managed "stopped-status" @("status")
  $uninstallStatus = Invoke-Managed "uninstall-purge" @("uninstall", "--force", "--purge-image-cache")
  $managedRuntimePurgeSucceeded = $true
  if (Test-ExactEntryExists $providerReleaseHome) {
    throw "Managed runtime uninstall left its exact release provider home behind."
  }
  $remainingWslDistributions = @(Invoke-WslInventoryRaw $wsl $systemRoot $system32 $workRoot)
  $remainingWslSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($remainingWslDistribution in $remainingWslDistributions) {
    $remainingWslSet.Add([string]$remainingWslDistribution) | Out-Null
  }
  foreach ($expectedDistribution in $managedWslDistributions) {
    if ($remainingWslSet.Contains([string]$expectedDistribution)) {
      throw "Managed runtime uninstall left a selected WSL generation registered: $expectedDistribution"
    }
  }
  $finalStatus = Invoke-Managed "final-status" @("status")

  foreach ($privateRoot in @(
    (Join-Path $dataDirectory "managed-runtime\versions"),
    (Join-Path $dataDirectory "managed-runtime\machine-images"),
    (Join-Path $dataDirectory "managed-runtime\provider-home")
  )) {
    if ((Test-Path -LiteralPath $privateRoot) -and @(Get-ChildItem -LiteralPath $privateRoot -Force).Count -ne 0) {
      throw "Managed runtime cleanup left private entries below $privateRoot."
    }
  }

  if ($InstallerType -eq "msi") {
    $uninstall = Start-Process -FilePath "msiexec.exe" -ArgumentList @(
      "/x", $installerPath, "/qn", "/norestart"
    ) -Wait -PassThru
    if ($uninstall.ExitCode -ne 0) {
      throw "$InstallerType uninstall failed with status $($uninstall.ExitCode)."
    }
  } else {
    if ($null -eq $uninstallerPath) {
      throw "Installed NSIS uninstaller is unavailable."
    }
    Invoke-BoundedCopiedNsisUninstaller $uninstallerPath $installDirectory $workRoot (
      "NSIS uninstall"
    )
  }
  $installed = $false
  if (Test-Path -LiteralPath $installDirectory) {
    Remove-Item -LiteralPath $installDirectory -Recurse -Force
  }
  if (Test-Path -LiteralPath $installDirectory) {
    throw "$InstallerType installation directory remains after cleanup."
  }
  Remove-Item -LiteralPath $dataDirectory -Recurse -Force
  if (Test-Path -LiteralPath $dataDirectory) {
    throw "Private qualification data remains after cleanup."
  }

  function Passed([string]$Name, [object]$Status) {
    return [ordered]@{ name = $Name; outcome = "passed"; status = $Status }
  }
  $observations = [ordered]@{
    installedLayout = [ordered]@{
      pathsVerifiedAbsolute = $true
      desktop = $desktop
      cli = $cli
      companions = @(
        [ordered]@{ name = "ai-security-scanner-egress-gateway"; path = $egress },
        [ordered]@{ name = "ai-security-scanner-bootstrap-broker"; path = $broker },
        [ordered]@{ name = "ai-security-scanner-cli"; path = $cli }
      )
      runtimeManifestOriginalPath = $runtimeManifest
    }
    desktopStartup = [ordered]@{ outcome = "passed"; observationSeconds = 12; installedExecutable = $desktop }
    privateDataDirectory = $dataDirectory
    operations = @(
      (Passed "initial_status" $initialStatus),
      (Passed "install" $installStatus),
      (Passed "installed_status" $installedStatus),
      (Passed "start" $startStatus),
      (Passed "running_status" $runningStatus),
      (Passed "stop" $stopStatus),
      (Passed "stopped_status" $stoppedStatus),
      (Passed "uninstall_purge" $uninstallStatus),
      (Passed "final_status" $finalStatus)
    )
    egressGateway = [ordered]@{ outcome = "passed"; result = $egressQualification }
    containerExecution = [ordered]@{ outcome = "passed"; result = $containerQualification }
    cleanup = [ordered]@{ managedRuntimePurged = $true; machineImageCachePurged = $true; installerRemoved = $true; privateDataRemoved = $true }
    installedManifestSnapshot = "installed-runtime-manifest.json"
  }
  $observations | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $workRoot "observations.json") -Encoding utf8NoBOM -NoNewline
  Add-Content -LiteralPath (Join-Path $workRoot "observations.json") -Value "" -Encoding utf8NoBOM
} catch {
  $primaryFailure = $_
} finally {
  if ($null -ne $primaryFailure) {
  try {
    if ($null -ne $cli -and (Test-Path -LiteralPath $cli -PathType Leaf) -and
        (Test-Path -LiteralPath $dataDirectory -PathType Container)) {
      try {
        Invoke-BoundedCleanupProcess $cli @(
          "--json", "runtime", "managed", "stop", "--force"
        ) 120000 "Managed runtime forced stop"
      } catch {
        $cleanupFailures.Add((Get-BoundedCleanupFailure $_ "managed runtime forced stop"))
      }
      try {
        Invoke-BoundedCleanupProcess $cli @(
          "--json", "runtime", "managed", "uninstall", "--force", "--purge-image-cache"
        ) 300000 "Managed runtime uninstall"
        $managedRuntimePurgeSucceeded = $true
      } catch {
        $cleanupFailures.Add((Get-BoundedCleanupFailure $_ "managed runtime uninstall"))
      }
    }
  } catch {
    $cleanupFailures.Add((Get-BoundedCleanupFailure $_ "managed runtime cleanup preflight"))
  }
  try {
    if ($null -ne $wsl -and $null -ne $systemRoot -and $null -ne $system32 -and
        $managedWslDistributions.Count -ne 0 -and (Test-Path -LiteralPath $workRoot -PathType Container)) {
      $remaining = @(Invoke-WslInventoryRaw $wsl $systemRoot $system32 $workRoot)
      $remainingWslSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($remainingWslDistribution in $remaining) {
        $remainingWslSet.Add([string]$remainingWslDistribution) | Out-Null
      }
      $remainingSelectedDistributions = @(
        $managedWslDistributions | Where-Object {
          $remainingWslSet.Contains([string]$_)
        }
      )
      $exactWslAbsent = $remainingSelectedDistributions.Count -eq 0
      if (-not $exactWslAbsent) {
        throw "One or more selected WSL generations remained registered after ownership-aware product cleanup."
      }
    }
  } catch {
    $cleanupFailures.Add((Get-BoundedCleanupFailure $_ "exact managed WSL distribution"))
  }
  try {
    if ($null -ne $providerRoot) {
      if (-not (Test-ExactEntryExists $providerRoot)) {
        $providerRootEmpty = $true
      } else {
        Assert-ManagedPrivateDirectory $providerRoot "Managed provider root after product cleanup"
        $providerRootEmpty = @(Get-ChildItem -LiteralPath $providerRoot -Force).Count -eq 0
        if (-not $providerRootEmpty) {
          throw "Managed provider root retained state after ownership-aware product cleanup."
        }
      }
    }
  } catch {
    $providerRootEmpty = $false
    $cleanupFailures.Add((Get-BoundedCleanupFailure $_ "managed provider root"))
  }
  if ($installed -and $null -ne $installerPath) {
    try {
      if ($InstallerType -eq "msi") {
        Invoke-BoundedCleanupProcess "msiexec.exe" @("/x", $installerPath, "/qn", "/norestart") 120000 "MSI uninstall"
      } else {
        if ($null -eq $uninstallerPath -and (Test-Path -LiteralPath $installDirectory -PathType Container)) {
          $fallbackUninstallers = @(
            Get-ChildItem -LiteralPath $installDirectory -Filter "uninstall.exe" -File -Recurse
          )
          if ($fallbackUninstallers.Count -eq 1) {
            $uninstallerPath = $fallbackUninstallers[0].FullName
          }
        }
        if ($null -eq $uninstallerPath) {
          throw "Installed NSIS uninstaller is unavailable for bounded cleanup."
        }
        Invoke-BoundedCopiedNsisUninstaller $uninstallerPath $installDirectory $workRoot (
          "NSIS uninstall"
        )
      }
    } catch {
      $cleanupFailures.Add((Get-BoundedCleanupFailure $_ "$InstallerType uninstall"))
    }
  }
  foreach ($boundedPath in @($installDirectory, $dataDirectory)) {
    try {
      if (Test-Path -LiteralPath $boundedPath) {
        if ([String]::Equals($boundedPath, $dataDirectory, [StringComparison]::OrdinalIgnoreCase) -and
            (-not $managedRuntimePurgeSucceeded -or -not $exactWslAbsent -or -not $providerRootEmpty)) {
          throw "Qualification data was preserved because ownership-aware purge, complete WSL absence, and empty provider state were not all proven."
        }
        Remove-BoundedQualificationTree $boundedPath "Qualification private tree"
      }
    } catch {
      $cleanupFailures.Add((Get-BoundedCleanupFailure $_ "qualification private tree"))
    }
  }
  }
}

if ($null -ne $primaryFailure) {
  if ($cleanupFailures.Count -ne 0) {
    $cleanupSummary = [String]::Join("; ", $cleanupFailures)
    throw [InvalidOperationException]::new(
      "$($primaryFailure.Exception.Message) Additional bounded qualification cleanup failure(s): $cleanupSummary",
      $primaryFailure.Exception
    )
  }
  throw $primaryFailure
}
if ($cleanupFailures.Count -ne 0) {
  throw "Bounded qualification cleanup failed: $([String]::Join('; ', $cleanupFailures))"
}

$ErrorActionPreference = "Stop"

# Use only the Visual Studio installation supplied by the native Windows runner.
# Export its developer environment; do not download or install a toolchain here.
if (-not $IsWindows) { throw "This helper requires a native Windows runner." }
if (-not $env:GITHUB_ENV) { throw "GITHUB_ENV is required to export the compiler environment." }
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw "Visual Studio vswhere.exe is unavailable." }
$installations = @(& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
if ($LASTEXITCODE -ne 0 -or $installations.Count -ne 1) { throw "A native x64 Visual C++ installation is required." }
$installation = $installations[0].Trim()
$devCommand = Join-Path $installation "Common7\Tools\VsDevCmd.bat"
if (-not (Test-Path -LiteralPath $devCommand -PathType Leaf)) { throw "Visual Studio VsDevCmd.bat is unavailable." }
$commandProcessor = Join-Path $env:SystemRoot "System32\cmd.exe"
$environmentLines = @(& $commandProcessor /d /s /c "`"`"$devCommand`" -no_logo -arch=x64 -host_arch=x64 >nul && set`"")
if ($LASTEXITCODE -ne 0) { throw "Visual Studio developer environment initialization failed." }

$allowedNames = @(
  "PATH", "INCLUDE", "LIB", "LIBPATH", "VCINSTALLDIR", "VCToolsInstallDir",
  "VCToolsVersion", "VisualStudioVersion", "VSINSTALLDIR", "WindowsSdkDir",
  "WindowsSDKLibVersion", "WindowsSDKVersion", "UCRTVersion", "UniversalCRTSdkDir",
  "VSCMD_ARG_TGT_ARCH", "VSCMD_ARG_HOST_ARCH"
)
$exported = @{}
foreach ($line in $environmentLines) {
  $separator = $line.IndexOf("=")
  if ($separator -lt 1) { continue }
  $name = $line.Substring(0, $separator)
  if ($allowedNames -notcontains $name) { continue }
  $value = $line.Substring($separator + 1)
  if ($value.Contains("`r") -or $value.Contains("`n")) { throw "Unexpected multiline compiler environment value." }
  $exported[$name] = $value
}
foreach ($name in @("PATH", "INCLUDE", "LIB")) {
  if (-not $exported[$name]) { throw "Visual Studio did not supply $name." }
}
foreach ($name in $exported.Keys) {
  [Environment]::SetEnvironmentVariable($name, $exported[$name], "Process")
  [System.IO.File]::AppendAllText($env:GITHUB_ENV, "$name=$($exported[$name])`n", [System.Text.UTF8Encoding]::new($false))
}
[void](Get-Command cl.exe -CommandType Application -ErrorAction Stop)
[void](Get-Command link.exe -CommandType Application -ErrorAction Stop)
Write-Host "Native Visual C++ compiler and linker are available to subsequent steps."

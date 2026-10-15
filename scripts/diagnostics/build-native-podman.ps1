param([Parameter(Mandatory = $true)][string]$WorkDirectory)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath($WorkDirectory)
New-Item -ItemType Directory -Path $root | Out-Null
function Download-Locked([string]$Url, [string]$Name, [string]$Sha256) {
  $path = Join-Path $root $Name
  Invoke-WebRequest -Uri $Url -OutFile $path
  if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha256) {
    throw "Locked download differs: $Name"
  }
  return $path
}
$sourceArchive = Download-Locked "https://github.com/podman-container-tools/podman/archive/5b263b5f5b48004a87caac44e67349a8266d9ef4.tar.gz" "podman-source.tar.gz" "3a40c78cbf6058a888b92d285ca0df4267d65a4e0aad3074524530d28b2c7179"
$goArchive = Download-Locked "https://go.dev/dl/go1.27.2.windows-amd64.zip" "go.zip" "1314008898bd40df77af4b014f777f08873dbdfbcd3d92308728ee03304fe04f"
& "$env:SystemRoot/System32/tar.exe" -xf $sourceArchive -C $root
if ($LASTEXITCODE -ne 0) { throw "Source extraction failed." }
& "$env:SystemRoot/System32/tar.exe" -xf $goArchive -C $root
if ($LASTEXITCODE -ne 0) { throw "Go extraction failed." }
$patch = (Resolve-Path runtime/podman-wsl-native-systemd.patch).Path
if ((Get-FileHash -LiteralPath $patch -Algorithm SHA256).Hash.ToLowerInvariant() -cne "e69a69316846cb0b36e6a05bdb999988fb0ff00ea194dc54c60edc32febe1bbe") {
  throw "Source patch differs."
}
$source = Join-Path $root "podman-5b263b5f5b48004a87caac44e67349a8266d9ef4"
Push-Location $source
try {
  & git apply --check $patch
  if ($LASTEXITCODE -ne 0) { throw "Source patch preflight failed." }
  & git apply $patch
  if ($LASTEXITCODE -ne 0) { throw "Source patch failed." }
  $env:GOOS = "windows"
  $env:GOARCH = "amd64"
  $env:GOAMD64 = "v1"
  $env:CGO_ENABLED = "0"
  $env:GOTOOLCHAIN = "local"
  $env:GOWORK = "off"
  $env:GOENV = "off"
  $env:GOPROXY = "off"
  $env:GOSUMDB = "off"
  $env:GOFLAGS = ""
  $env:GOMAXPROCS = "4"
  $env:GOCACHE = Join-Path $root "go-cache"
  $output = Join-Path $root "podman.exe"
  & (Join-Path $root "go/bin/go.exe") build -mod=vendor -trimpath -buildvcs=false -tags "remote exclude_graphdriver_btrfs containers_image_openpgp" -ldflags "-s -w -buildid= -X github.com/containers/podman/v5/libpod/define.gitCommit=5b263b5f5b48004a87caac44e67349a8266d9ef4 -X github.com/containers/podman/v5/libpod/define.buildInfo=0 -X github.com/containers/podman/v5/libpod/define.buildOrigin=ai-security-scanner-native-wsl-systemd" -o $output ./cmd/podman
  if ($LASTEXITCODE -ne 0) { throw "Patched client build failed." }
  $digest = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($digest -cne "3fafff68ac570924417e8987d806bd91af269dd34e2b90dc9a3bbf0f0a9f10e4") {
    throw "Windows build differs from the independently cross-compiled client: $digest"
  }
  Write-Output "Windows and Linux cross-builds produced the same patched client: $digest"
} finally { Pop-Location }

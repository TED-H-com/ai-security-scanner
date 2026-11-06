# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1791284189

FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS launcher
ARG TARGETARCH
WORKDIR /src
COPY engines/images/m365-launcher/go.mod engines/images/m365-launcher/main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -buildvcs=false -trimpath \
      -ldflags='-s -w -buildid=' -o /out/ai-security-scanner-m365-launcher .

FROM --platform=$BUILDPLATFORM python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7 AS prepare
COPY engines/images/m365-launcher/prepare_source.py /opt/prepare_source.py
COPY engines/images/maester/dependencies.lock.json /input/dependencies.lock.json
ADD --checksum=sha256:5abab2a96dc40ed6088734d1b60665b3c982be7f8f1fe5f8653474b494ef4e41 \
    https://github.com/maester365/maester/archive/7413c42d3fcc724dfea94d2726e690ddd364d914.tar.gz \
    /input/maester.tar.gz
ADD --checksum=sha256:7ac68868f2e12afb6c35df19542b1dfdd07b848bc69f6b45eca3a618e2143f78 \
    https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Authentication/2.27.0 \
    /input/Microsoft.Graph.Authentication.2.27.0.nupkg
ADD --checksum=sha256:4a27904c6814a5fbe4758f8e49861f6a1994aee77b71165a5c43c0371ba6c580 \
    https://www.powershellgallery.com/api/v2/package/Pester/5.7.1 \
    /input/Pester.5.7.1.nupkg
ADD --checksum=sha256:4a8c3c98b9976aad4fd04308c7b1711ce6578a6a8be2ef172b0f28d79d7e62f7 \
    https://raw.githubusercontent.com/microsoftgraph/msgraph-sdk-powershell/b339b370f7b3b23fe7a0e359f029ca68ab1ebdb1/LICENSE.txt \
    /third-party/Microsoft.Graph.Authentication-LICENSE.txt
ADD --checksum=sha256:6a2fc73db70e674162600052e12a6537e93b51d5dfcf2340c4ed08cdb174debb \
    https://raw.githubusercontent.com/Pester/Pester/dc45b7481fffc4f6c2ff1a74edebaad03ce1efcb/LICENSE \
    /third-party/Pester-LICENSE
RUN python3 /opt/prepare_source.py \
      --engine maester \
      --source /input/maester.tar.gz \
      --lock /input/dependencies.lock.json \
      --output /prepared \
      --package Microsoft.Graph.Authentication=/input/Microsoft.Graph.Authentication.2.27.0.nupkg \
      --package Pester=/input/Pester.5.7.1.nupkg

FROM prepare AS powershell-release
ARG TARGETARCH
ADD --checksum=sha256:1da6d6d6035d651f20e70ddee7c4c15ac6ab8b9fb40ee92240d91263f28a884b \
    https://github.com/PowerShell/PowerShell/releases/download/v7.6.9/powershell-7.6.9-linux-x64.tar.gz /input/powershell-amd64.tar.gz
ADD --checksum=sha256:02eb9991af447c7e7fe881acde195961afd397c40b8eb1c2b3856b84ec2d85f2 \
    https://github.com/PowerShell/PowerShell/releases/download/v7.6.9/powershell-7.6.9-linux-arm64.tar.gz /input/powershell-arm64.tar.gz
ADD --checksum=sha256:7c77a44a8acd9b41fdc209864a8016b3d430b5d0e09309818d5b7444336df744 \
    https://raw.githubusercontent.com/PowerShell/PowerShell/bf5fc434120666e5f1a8d1dfd6ecac7efc17a4be/LICENSE.txt /third-party/PowerShell-LICENSE.txt
RUN mkdir -p /powershell \
    && tar -xzf /input/powershell-${TARGETARCH}.tar.gz -C /powershell \
    && chmod 0555 /powershell/pwsh

FROM mcr.microsoft.com/powershell:7.5-azurelinux-3.0@sha256:74b9b9d43da4d04c349bd358dd2db14ee01f0ab17769e402cf0ae4bd9fdd2f2b AS powershell-amd64
FROM mcr.microsoft.com/powershell:7.5-azurelinux-3.0-arm64@sha256:60d31793816646c4dd80b719b350ca68c8a53c000cbb2740655ddafe5e127903 AS powershell-arm64
FROM powershell-${TARGETARCH}
# Retain the reviewed Azure Linux system-library base; replace its complete
# PowerShell/.NET tree with the immutable upstream 7.6.9 distribution.
RUN rm -rf /opt/microsoft/powershell/7
COPY --from=powershell-release /powershell /opt/microsoft/powershell/7
COPY --from=powershell-release /third-party/PowerShell-LICENSE.txt /usr/share/licenses/powershell/LICENSE.txt
RUN pwsh -NoLogo -NoProfile -NonInteractive -Command 'if ($PSVersionTable.PSVersion.ToString() -ne "7.6.9") { throw "PowerShell runtime version mismatch" }'

ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.title="ai-security-scanner Maester engine" \
      org.opencontainers.image.description="Pinned-source Microsoft Entra ID test suite through one protected Graph token" \
      org.opencontainers.image.source="https://github.com/teddashh/ai-security-scanner" \
      org.opencontainers.image.revision="7413c42d3fcc724dfea94d2726e690ddd364d914" \
      org.opencontainers.image.version="2.3.0-1" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0" \
      io.ai-security-scanner.source-archive-sha256="5abab2a96dc40ed6088734d1b60665b3c982be7f8f1fe5f8653474b494ef4e41" \
      io.ai-security-scanner.profile="entra-graph-token"

COPY --from=prepare /prepared/engine/Maester /opt/ai-security-scanner/Maester
COPY --from=prepare /prepared/tests /opt/ai-security-scanner/maester-tests
COPY --from=prepare /prepared/modules /opt/ai-security-scanner/modules
COPY --from=prepare --chmod=0444 /prepared/dependencies.lock.json /opt/ai-security-scanner/dependencies.lock.json
COPY --from=launcher --chmod=0555 /out/ai-security-scanner-m365-launcher /usr/local/bin/ai-security-scanner-m365-launcher
COPY --chmod=0444 engines/images/maester/run-maester.ps1 /opt/ai-security-scanner/run-maester.ps1
COPY --chmod=0444 engines/images/maester/run-maester.Tests.ps1 /opt/ai-security-scanner/run-maester.Tests.ps1

COPY --from=prepare --chmod=0444 /prepared/licenses/Maester-LICENSE /usr/share/licenses/maester/LICENSE
COPY --from=prepare --chmod=0444 /prepared/modules/Microsoft.Graph.Authentication/2.27.0/Microsoft.Graph.Authentication.nuspec /usr/share/licenses/maester/Microsoft.Graph.Authentication.nuspec
COPY --from=prepare --chmod=0444 /prepared/modules/Pester/5.7.1/Pester.nuspec /usr/share/licenses/maester/Pester.nuspec
COPY --from=prepare --chmod=0444 /third-party/Microsoft.Graph.Authentication-LICENSE.txt /usr/share/licenses/maester/Microsoft.Graph.Authentication-LICENSE.txt
COPY --from=prepare --chmod=0444 /third-party/Pester-LICENSE /usr/share/licenses/maester/Pester-LICENSE
COPY --chmod=0444 engines/images/maester/THIRD-PARTY-NOTICES.md /usr/share/licenses/maester/THIRD-PARTY-NOTICES.md

ENV DOTNET_CLI_TELEMETRY_OPTOUT="1" \
    DOTNET_NOLOGO="1" \
    HOME="/tmp/ai-security-scanner-home" \
    NUGET_XMLDOC_MODE="skip" \
    PATH="/opt/microsoft/powershell/7:/usr/local/bin:/usr/bin:/bin" \
    POWERSHELL_TELEMETRY_OPTOUT="1" \
    POWERSHELL_UPDATECHECK="Off" \
    PSModulePath="/opt/ai-security-scanner/modules:/opt/microsoft/powershell/7/Modules" \
    XDG_CACHE_HOME="/tmp/ai-security-scanner-cache" \
    XDG_CONFIG_HOME="/tmp/ai-security-scanner-config" \
    XDG_DATA_HOME="/tmp/ai-security-scanner-data"

# The release at 7413c42d stamps 2.3.0 before running these unchanged upstream
# build helpers. Source Maester.psd1 remains 2.0.0 in the tagged archive.
COPY --from=prepare /prepared/build /opt/ai-security-scanner/build
RUN chmod u+w /opt/ai-security-scanner/Maester/Maester.psd1 /opt/ai-security-scanner/maester-tests/maester-config.json \
    && pwsh -NoLogo -NoProfile -NonInteractive -Command \
      '$ErrorActionPreference="Stop"; Update-ModuleManifest -Path /opt/ai-security-scanner/Maester/Maester.psd1 -ModuleVersion 2.3.0 -Prerelease ""; & /opt/ai-security-scanner/build/Update-MaesterConfigVersion.ps1 -ConfigPath /opt/ai-security-scanner/maester-tests/maester-config.json -ModuleVersion 2.3.0 -ConfigVersion 2026.10.06.1; & /opt/ai-security-scanner/build/Build-MaesterModule.ps1 -SourceRoot /opt/ai-security-scanner/Maester -TestsRoot /opt/ai-security-scanner/maester-tests -OutputRoot /opt/ai-security-scanner/module; Remove-Item /opt/ai-security-scanner/Maester -Recurse -Force; Move-Item /opt/ai-security-scanner/module /opt/ai-security-scanner/Maester' \
    && chmod -R a-w /opt/ai-security-scanner/Maester /opt/ai-security-scanner/maester-tests /opt/ai-security-scanner/build \
    && find /opt/ai-security-scanner/Maester /opt/ai-security-scanner/maester-tests -exec touch -h -d "@${SOURCE_DATE_EPOCH}" '{}' +

RUN chmod 0555 /usr/share/licenses/maester

USER 65532:65532
RUN pwsh -NoLogo -NoProfile -NonInteractive -Command \
      '$ErrorActionPreference="Stop"; Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.27.0; Import-Module Pester -RequiredVersion 5.7.1; Import-Module /opt/ai-security-scanner/Maester/Maester.psd1; if ((Get-Module Maester).Version -ne [version]"2.3.0") { throw "Maester version mismatch" }; if (-not (Test-Path -LiteralPath /opt/ai-security-scanner/maester-tests/Maester/Entra/Test-MtDomainsDmarcRecordMaturity.Tests.ps1 -PathType Leaf)) { throw "Pinned Entra test tree is incomplete" }; $tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("/opt/ai-security-scanner/run-maester.ps1",[ref]$tokens,[ref]$errors); if ($errors.Count) { throw ($errors | Out-String) }'

# The wrapper specification runs against the wrapper this image ships, as the
# user it will run as. A build whose wrapper misreads a Maester report cannot
# become an image. The lower bound on passed tests keeps an accidentally empty
# run from counting as a pass. Replay against any published digest with:
#   docker run --rm --entrypoint pwsh <image>@<digest> -NoLogo -NoProfile -NonInteractive -Command <the command below>
RUN pwsh -NoLogo -NoProfile -NonInteractive -Command \
      '$ErrorActionPreference="Stop"; Import-Module Pester -RequiredVersion 5.7.1; $configuration=New-PesterConfiguration; $configuration.Run.Path="/opt/ai-security-scanner/run-maester.Tests.ps1"; $configuration.Run.PassThru=$true; $configuration.Output.Verbosity="Detailed"; $result=Invoke-Pester -Configuration $configuration; if ($result.FailedCount -ne 0 -or $result.SkippedCount -ne 0 -or $result.NotRunCount -ne 0 -or $result.PassedCount -lt 40) { throw "wrapper specification did not pass: $($result.PassedCount) passed, $($result.FailedCount) failed, $($result.SkippedCount) skipped, $($result.NotRunCount) not run" }; Write-Output "wrapper specification passed $($result.PassedCount) of $($result.TotalCount) tests"'

ENTRYPOINT ["/usr/local/bin/ai-security-scanner-m365-launcher"]

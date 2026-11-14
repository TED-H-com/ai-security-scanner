#!/usr/bin/env bash
set -u

if [ "$#" -ne 0 ]; then
  printf 'This script takes no arguments; run it from the repository root.\n' >&2
  exit 2
fi

# These images are pinned in the corresponding publish workflows or Dockerfiles.
go_125='golang:1.25.0-alpine3.22@sha256:f18a072054848d87a8077455f0ac8a25886f2397f88bfdd222d6fafbb5bba440'
go_1260='golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5'
go_1263='golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d'
go_12610='golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696'
python_311='python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7'

results=()
failed=0

run_launcher() {
  local directory="$1"
  shift
  printf '::group::%s\n' "$directory"
  if "$@" "$directory"; then
    results+=("$directory: PASS")
  else
    results+=("$directory: FAIL")
    failed=1
  fi
  printf '::endgroup::\n'
}

go_launcher() {
  local image="$1" network="$2" directory="$3"
  local -a network_options=()
  if [ "$network" = none ]; then network_options=(--network none); fi
  docker run --rm "${network_options[@]}" \
    -v "${PWD}/${directory}:/src:ro" -w "/src" "$image" \
    sh -ceu 'test -z "$(gofmt -d main.go main_test.go)"; go test ./...'
}

external_launcher() {
  local directory="$1" status=0
  docker run --rm -v "${PWD}/${directory}:/src:ro" -w "/src" "$go_12610" \
    sh -ceu 'gofmt -d main.go main_test.go | tee /tmp/gofmt.diff; test ! -s /tmp/gofmt.diff' || status=1
  docker run --rm -v "${PWD}/${directory}:/src:ro" -w "/src" "$go_12610" \
    go test -v "./..." || status=1
  return "$status"
}

gitleaks_launcher() {
  local directory="$1"
  # The launcher test also reads the sibling testdata directory.
  docker run --rm -v "${PWD}/${directory%/launcher}:/gitleaks:ro" -w "/gitleaks/launcher" "$go_1263" \
    sh -ceu 'test -z "$(gofmt -d main.go main_test.go)"; go test ./...'
}

greenbone_launcher() {
  local directory="$1"
  docker run --rm -v "${PWD}/${directory}:/src:ro" -w "/src" "$go_12610" \
    sh -ceu 'gofmt -d main.go main_test.go | tee /tmp/gofmt.diff && test ! -s /tmp/gofmt.diff && go test ./...'
}

httpx_tests() {
  local directory="$1" status=0
  docker run --rm -v "${PWD}/${directory}:/src/httpx-patch:ro" -w "/src/httpx-patch" "$go_1260" \
    go test "patch_live_dns.go" "patch_live_dns_test.go" || status=1
  # The Dockerfile also tests the patch against this checksum-pinned runner.
  docker run --rm -v "${PWD}/${directory}:/src/httpx-patch:ro" -w "/src/httpx-patch" "$go_1260" \
    sh -ceu '
      wget -O "/tmp/httpx-source.tar.gz" "https://github.com/projectdiscovery/httpx/archive/4b6a9a9d476f94a4f3a630f37051f5671ecfb1f8.tar.gz"
      echo "f018fc96c4194aa008f1e305fcdc2bb8ecd5f08d7722ab012077cd3a9ec6a84d  /tmp/httpx-source.tar.gz" | sha256sum -c -
      mkdir -p "/src/httpx"
      tar -xzf "/tmp/httpx-source.tar.gz" --strip-components=1 -C "/src/httpx"
      HTTPX_PINNED_RUNNER=/src/httpx/runner/runner.go go test "/src/httpx-patch/patch_live_dns.go" "/src/httpx-patch/patch_live_dns_test.go"
    ' || status=1
  return "$status"
}

steampipe_tests() {
  local directory="$1"
  # The project-tools stage pins Go but does not yet contain a test command.
  docker run --rm -v "${PWD}/${directory}:/src:ro" -w "/src" "$go_12610" \
    go test "./..."
}

garak_tests() {
  local directory="$1"
  docker run --rm --network none -v "${PWD}/${directory}:/src:ro" "$python_311" \
    python -I -B "/src/main_test.py"
}

semgrep_tests() {
  local directory="$1"
  # The publish workflow prepares this checksum-locked archive before unittest.
  if ! node "scripts/prepare-offline-engine-data.mjs" semgrep; then return 1; fi
  # Its workflow runs host Python; use the repository's pinned Python image so
  # the source directory and the prepared input can both be mounted read-only.
  docker run --rm --network none \
    -v "${PWD}/${directory}:/workspace/engines/images/semgrep:ro" \
    -v "${PWD}/.engine-cache/offline/semgrep-submodules/tests__semgrep-rules.tar.gz:/workspace/.engine-cache/offline/semgrep-submodules/tests__semgrep-rules.tar.gz:ro" \
    -w "/workspace" -e PYTHONDONTWRITEBYTECODE=1 "$python_311" \
    python3 -m unittest discover -s "engines/images/semgrep" -p 'test_*.py'
}

run_launcher "engines/images/agentic-radar/launcher" go_launcher "$go_1263" none
run_launcher "engines/images/cloud-launcher" go_launcher "$go_125" default
run_launcher "engines/images/external-launcher" external_launcher
run_launcher "engines/images/garak/launcher" garak_tests
run_launcher "engines/images/gitleaks/launcher" gitleaks_launcher
run_launcher "engines/images/greenbone-launcher" greenbone_launcher
run_launcher "engines/images/httpx" httpx_tests
run_launcher "engines/images/local-launcher" go_launcher "$go_12610" default
run_launcher "engines/images/m365-launcher" go_launcher "$go_125" default
run_launcher "engines/images/mcp-armor/launcher" go_launcher "$go_1263" none
run_launcher "engines/images/semgrep" semgrep_tests
run_launcher "engines/images/steampipe/installprep" steampipe_tests

printf '\nLauncher test summary:\n'
printf '%s\n' "${results[@]}"
exit "$failed"

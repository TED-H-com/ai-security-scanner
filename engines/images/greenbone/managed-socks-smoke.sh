#!/usr/bin/env bash
set -Eeuo pipefail

image="${1:-ai-security-scanner-greenbone:dev}"
gateway_binary="${2:-${PWD}/target/debug/ai-security-scanner-egress-gateway}"
adapter_mode="${3:-adapter}"
curl_image="curlimages/curl:8.16.0@sha256:463eaf6072688fe96ac64fa623fe73e1dbe25d8ad6c34404a669ad3ce1f104b6"
python_image="python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7"
bridge_subnet="172.29.250.0/24"
gateway_address="172.29.250.1"
scanner_address="172.29.250.2"
probe_address="172.29.250.3"
target_subnet="172.29.251.0/24"
target_address="172.29.251.10"
target_port="8080"
selected_oid="1.3.6.1.4.1.25623.1.0.108252"
runtime_user="$(id -u):$(id -g)"
suffix="${GITHUB_RUN_ID:-local}-$$"
internal_network="ass-greenbone-internal-${suffix}"
target_network="ass-greenbone-target-${suffix}"
target_container="ass-greenbone-target-${suffix}"
scanner_container="ass-greenbone-scanner-${suffix}"
scratch="$(mktemp -d -t ai-security-scanner-greenbone-smoke.XXXXXXXX)"
gateway_pid=""

cleanup() {
  if [[ -n "${gateway_pid}" ]]; then
    kill "${gateway_pid}" 2>/dev/null || true
    wait "${gateway_pid}" 2>/dev/null || true
  fi
  if [[ -n "${scratch}" && -d "${scratch}" ]]; then
    docker logs "${target_container}" >"${scratch}/target.log" 2>&1 || true
  fi
  docker rm -f "${scanner_container}" "${target_container}" >/dev/null 2>&1 || true
  docker network rm "${internal_network}" "${target_network}" >/dev/null 2>&1 || true
  if [[ "${KEEP_GREENBONE_SMOKE:-0}" == "1" ]]; then
    printf 'preserved Greenbone smoke artifacts at %s\n' "${scratch}" >&2
  elif [[ -n "${scratch}" && "${scratch}" == /tmp/ai-security-scanner-greenbone-smoke.* ]]; then
    rm -rf -- "${scratch}"
  fi
}
trap cleanup EXIT INT TERM

if [[ ! -x "${gateway_binary}" ]]; then
  printf 'managed egress gateway is not executable: %s\n' "${gateway_binary}" >&2
  exit 2
fi

docker network create \
  --driver bridge \
  --internal \
  --subnet "${bridge_subnet}" \
  --gateway "${gateway_address}" \
  "${internal_network}" >/dev/null
docker network create \
  --driver bridge \
  --subnet "${target_subnet}" \
  "${target_network}" >/dev/null

docker run --detach --name "${target_container}" \
  --network "${target_network}" --ip "${target_address}" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --user 65532:65532 --pids-limit 64 --memory 128m --cpus 1 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777,size=16m \
  "${python_image}" python -c '
import http.server
import threading
class AuthorizedFixture(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.4.27"
    sys_version = ""
    protocol_version = "HTTP/1.0"
    def do_GET(self):
        body = b"<title>Apache HTTP Server Version 2.4.27 Documentation - Apache HTTP Server</title>\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET,HEAD,OPTIONS")
        self.end_headers()
    def log_message(self, format, *args):
        command = str(getattr(self, "command", "unknown"))
        path = str(getattr(self, "path", "unknown"))
        print("fixture " + command + " " + path + " " + (format % args), flush=True)
threading.Thread(
    target=http.server.ThreadingHTTPServer(("0.0.0.0", 8081), AuthorizedFixture).serve_forever,
    daemon=True,
).start()
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), AuthorizedFixture).serve_forever()
' >/dev/null

for _ in $(seq 1 40); do
  if curl --fail --silent --connect-timeout 1 "http://${target_address}:${target_port}/" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
curl --fail --silent --show-error --connect-timeout 1 "http://${target_address}:${target_port}/" >/dev/null
curl --fail --silent --show-error --connect-timeout 1 "http://${target_address}:8081/" >/dev/null

approved_at="$(date -u -d '1 minute ago' '+%Y-%m-%dT%H:%M:%SZ')"
expires_at="$(date -u -d '30 minutes' '+%Y-%m-%dT%H:%M:%SZ')"
jq -n \
  --arg expires "${expires_at}" \
  --arg gateway "${gateway_address}:1080" \
  --arg clients "${bridge_subnet}" \
  --arg target "${target_address}" \
  --argjson port "${target_port}" \
  '{
    schema_version: "2.0.0",
    policy_id: "greenbone-managed-socks-smoke",
    expires_at: $expires,
    listen_address: $gateway,
    allowed_client_network: $clients,
    limits: {
      max_concurrency: 1,
      max_connections_per_second: 10,
      connect_timeout_seconds: 5,
      max_connection_seconds: 10
    },
    provenance: {
      kind: "external_asset_grants",
      case_id: "case-greenbone-managed-socks-smoke",
      grant_ids: ["grant-greenbone-managed-socks-smoke"],
      activities: ["active_external"]
    },
    destinations: [{
      hostname: null,
      addresses: [$target],
      ports: [$port],
      allow_sensitive_networks: true
    }]
  }' >"${scratch}/egress-policy.json"

jq -n \
  --arg generated "${approved_at}" \
  --arg expires "${expires_at}" \
  --arg target "${target_address}" \
  --argjson port "${target_port}" \
  --arg oid "${selected_oid}" \
  '{
    schema_version: "1",
    engine_id: "greenbone",
    generated_at: $generated,
    assets: [{
      id: "asset-greenbone-managed-socks-smoke",
      name: "Authorized Apache fixture",
      kind: "ip_address",
      provider: null,
      region: null,
      identifiers: [{namespace: "ip_address", value: $target}],
      grants: [{
        id: "grant-greenbone-managed-socks-smoke",
        permission: "active_external_testing",
        confirmed_by: "greenbone-smoke-owner@example.test",
        confirmed_at: $generated,
        expires_at: $expires,
        authorization_reference: "greenbone-managed-socks-smoke-authorization",
        external_scope: {
          id: "grant-greenbone-managed-socks-smoke",
          case_id: "case-greenbone-managed-socks-smoke",
          asset_id: "asset-greenbone-managed-socks-smoke",
          target: {kind: "address", value: $target},
          ports: [$port],
          protocol: "http",
          activity: "active_external",
          rate_policy: {requests_per_second: 10, concurrency: 1, timeout_seconds: 5},
          template_policy: {
            revision: "greenbone-community-feed@a2e53c2e30f1fa5408369cb5cf99653a3e08e9df",
            allowed_template_ids: [$oid],
            allow_headless: false,
            allow_out_of_band: false,
            allow_fuzzing: false,
            allow_file_upload: false,
            allow_denial_of_service: false,
            allow_credential_attacks: false
          },
          asserted_authority: "This exact disposable fixture is owned by the smoke run and authorized for active testing.",
          approved_by: "greenbone-smoke-owner@example.test",
          approved_at: $generated,
          expires_at: $expires,
          allow_sensitive_networks: true
        }
      }]
    }]
  }' >"${scratch}/scope.json"
chmod 0444 "${scratch}/scope.json" "${scratch}/egress-policy.json"
mkdir "${scratch}/output"
chmod 0777 "${scratch}/output"

"${gateway_binary}" --policy "${scratch}/egress-policy.json" >"${scratch}/gateway.log" 2>&1 &
gateway_pid="$!"
sleep 0.5
kill -0 "${gateway_pid}"

if docker run --rm \
  --network "${internal_network}" --ip "${probe_address}" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  "${curl_image}" --fail --silent --connect-timeout 2 \
  "http://${target_address}:${target_port}/" >/dev/null 2>&1; then
  printf 'internal-only bridge unexpectedly allowed direct target egress\n' >&2
  exit 1
fi

docker run --rm \
  --network "${internal_network}" --ip "${probe_address}" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  "${curl_image}" --fail --silent --show-error --connect-timeout 5 \
  --proxy "socks5h://${gateway_address}:1080" \
  "http://${target_address}:${target_port}/" >/dev/null

if docker run --rm \
  --network "${internal_network}" --ip "${probe_address}" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  "${curl_image}" --fail --silent --connect-timeout 2 \
  --proxy "socks5h://${gateway_address}:1080" \
  "http://${target_address}:8081/" >/dev/null 2>&1; then
  printf 'managed SOCKS gateway unexpectedly allowed an unapproved target port\n' >&2
  exit 1
fi

docker run --name "${scanner_container}" \
  --network "${internal_network}" --ip "${scanner_address}" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --user "${runtime_user}" --pids-limit 512 --memory 3g --cpus 2 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777,size=1024m \
  --mount "type=bind,src=${scratch}/scope.json,dst=/run/ai-security-scanner/scope.json,readonly" \
  --mount "type=bind,src=${scratch}/output,dst=/output" \
  --env "AI_SECURITY_SCANNER_PROXY=socks5h://${gateway_address}:1080" \
  "${image}" \
  --engine greenbone \
  --scope /run/ai-security-scanner/scope.json \
  --output /output

test "$(docker inspect "${scanner_container}" --format '{{.State.Status}} {{.State.ExitCode}} {{.HostConfig.ReadonlyRootfs}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}} {{.Config.User}}')" = "exited 0 true [\"ALL\"] [\"no-new-privileges:true\"] ${runtime_user}"
test -s "${scratch}/output/greenbone.xml"
chmod 0444 "${scratch}/output/greenbone.xml"

docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --mount "type=bind,src=${scratch}/output,dst=/evidence,readonly" \
  "${python_image}" python -c '
import sys
import xml.etree.ElementTree as ET
path, expected_oid, expected_host, expected_port = sys.argv[1:]
root = ET.parse(path).getroot()
results = root.findall("./report/results/result")
assert results, "no bounded Greenbone results"
alarms = [result for result in results if float(result.findtext("severity", "0")) > 0]
assert alarms, "authorized vulnerable fixture produced no alarm"
assert any(result.find("nvt").get("oid") == expected_oid for result in alarms)
assert all(result.findtext("host") == expected_host for result in results)
assert all(result.findtext("asset_id") == "asset-greenbone-managed-socks-smoke" for result in results)
assert any(result.findtext("port") == expected_port + "/tcp" for result in alarms)
print(f"xml_results={len(results)} actionable_alarms={len(alarms)}")
' /evidence/greenbone.xml "${selected_oid}" "${target_address}" "${target_port}"

if [[ "${adapter_mode}" == "adapter" ]]; then
  mkdir -p "${scratch}/cargo-home" "${scratch}/cargo-target"
  chmod 0777 "${scratch}/cargo-home" "${scratch}/cargo-target"
  docker run --rm --user 1000:1000 \
    -e CARGO_HOME=/tmp/cargo-home \
    -e CARGO_TARGET_DIR=/tmp/cargo-target \
    --mount "type=bind,src=${PWD},dst=/workspace,readonly" \
    --mount "type=bind,src=${scratch}/cargo-home,dst=/tmp/cargo-home" \
    --mount "type=bind,src=${scratch}/cargo-target,dst=/tmp/cargo-target" \
    --mount "type=bind,src=${scratch}/output,dst=/evidence,readonly" \
    -w /workspace \
    rust@sha256:94e9efa4033213dbb70d4f665527e7ece3944ddb7ba1dd2e43f6fd6e2490af58 \
    cargo run --locked --no-default-features --example greenbone_adapter_smoke -- /evidence/greenbone.xml
fi

printf 'GREENBONE_MANAGED_SOCKS_SMOKE_OK image=%s evidence_sha256=sha256:%s\n' \
  "${image}" "$(sha256sum "${scratch}/output/greenbone.xml" | cut -d ' ' -f 1)"

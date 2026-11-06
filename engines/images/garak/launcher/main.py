"""One approved HTTPS model endpoint, an ephemeral key, and the native Garak CLI."""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
import re
import resource
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

SOURCE_REVISION = "7aa740fe7412cc9bc33cdc39ca211843223cd3e1"
PROBES = ("dan.Dan_11_0", "dan.Dan_10_0", "dan.Dan_9_0", "ansiescape.AnsiEscaped")
SCOPE = Path("/run/ai-security-scanner/scope.json")
CREDENTIALS = Path("/run/ai-security-scanner/credentials.json")
OUTPUT = Path("/output")
MAX_REPORT_BYTES = 32 * 1024 * 1024


class Rejected(ValueError):
    pass


def duplicate_free(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("duplicate_json_field")
        result[key] = value
    return result


def read_document(path, limit, require_readonly=False):
    if require_readonly and not os.statvfs(path).f_flag & os.ST_RDONLY:
        raise Rejected("read_only_input_required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size > limit:
            raise Rejected("invalid_input_file")
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise Rejected("input_size_limit")
    return json.loads(content, object_pairs_hook=duplicate_free)


def timestamp(value):
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise Rejected("timestamp_requires_timezone")
    return parsed


def endpoint_descriptor(endpoint, model):
    if (not isinstance(endpoint, str) or len(endpoint) > 512
            or not endpoint.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in endpoint)):
        raise Rejected("invalid_endpoint")
    uri = urlsplit(endpoint)
    if (uri.scheme != "https" or not uri.hostname or uri.username is not None or uri.password is not None
            or uri.query or uri.fragment or not uri.path.startswith("/") or uri.path == "/"
            or "%" in uri.path or "\\" in endpoint or "?" in endpoint or "#" in endpoint
            or any(segment in (".", "..", "") for segment in uri.path.split("/")[1:])):
        raise Rejected("invalid_endpoint")
    port = 443 if uri.port is None else uri.port
    if not 1 <= port <= 65535 or uri.hostname != uri.hostname.lower():
        raise Rejected("invalid_endpoint")
    if not isinstance(model, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", model) is None:
        raise Rejected("invalid_model")
    return uri, port


def validate_scope(scope, now):
    if scope.get("schema_version") != "1" or scope.get("engine_id") != "garak":
        raise Rejected("invalid_scope")
    if timestamp(scope["generated_at"]) > now + datetime.timedelta(minutes=1):
        raise Rejected("future_scope")
    assets = scope["assets"]
    if not isinstance(assets, list) or len(assets) != 1:
        raise Rejected("one_model_asset_required")
    asset = assets[0]
    if asset.get("kind") != "ai_model_endpoint" or not asset.get("id"):
        raise Rejected("model_asset_required")
    def identifier(namespace):
        matches = [i["value"] for i in asset["identifiers"] if i["namespace"] == namespace]
        if len(matches) != 1:
            raise Rejected("ambiguous_model_identity")
        return matches[0]
    endpoint = identifier("ai-security-scanner:model-endpoint")
    model = identifier("ai-security-scanner:model-id")
    uri, port = endpoint_descriptor(endpoint, model)
    grants = asset["grants"]
    if not isinstance(grants, list) or len(grants) != 1:
        raise Rejected("one_model_grant_required")
    grant = grants[0]
    external = grant["external_scope"]
    template = external["template_policy"]
    forbidden = ("allow_headless", "allow_out_of_band", "allow_fuzzing", "allow_file_upload",
                 "allow_denial_of_service", "allow_credential_attacks")
    expected_target = {"kind": "hostname", "value": uri.hostname}
    try:
        expected_target = {"kind": "address", "value": str(ipaddress.ip_address(uri.hostname))}
    except ValueError:
        if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", uri.hostname) is None:
            raise Rejected("invalid_endpoint_host")
    if (grant.get("permission") != "active_external_testing" or not grant.get("authorization_reference")
            or not grant.get("confirmed_by") or timestamp(grant["confirmed_at"]) > now
            or (grant.get("expires_at") is not None and timestamp(grant["expires_at"]) <= now)
            or external.get("asset_id") != asset["id"] or external.get("target") != expected_target
            or external.get("ports") != [port] or external.get("protocol") != "https"
            or external.get("activity") != "active_external"
            or external.get("rate_policy") != {"requests_per_second": 1, "concurrency": 1, "timeout_seconds": 20}
            or timestamp(external["approved_at"]) > now or timestamp(external["expires_at"]) <= now
            or timestamp(external["expires_at"]) > now + datetime.timedelta(hours=1)
            or not external.get("asserted_authority") or not external.get("approved_by")
            or template.get("revision") != SOURCE_REVISION or template.get("profile_id") != "garak_https_v1"
            or template.get("allowed_template_ids") != []
            or any(template.get(flag) is not False for flag in forbidden)):
        raise Rejected("model_grant_mismatch")
    remaining = min(600, (timestamp(external["expires_at"]) - now).total_seconds())
    return endpoint, model, remaining


def read_key(document, now):
    entries = document.get("credentials")
    if document.get("schema_version") != "1.0.0" or not isinstance(entries, list) or len(entries) != 1:
        raise Rejected("one_local_model_credential_required")
    entry = entries[0]
    key = entry.get("value")
    expires = timestamp(entry["expires_at"])
    if (entry.get("key") != "REST_API_KEY" or entry.get("source") != "local_model_endpoint"
            or not isinstance(key, str) or not 1 <= len(key) <= 4096
            or not key.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in key)
            or expires <= now or expires > now + datetime.timedelta(hours=1)):
        raise Rejected("invalid_local_model_credential")
    return key, expires


def validate_proxy(raw):
    uri = urlsplit(raw)
    if (uri.scheme != "socks5h" or uri.username is not None or uri.password is not None
            or uri.port != 1080 or uri.path or uri.query or uri.fragment):
        raise Rejected("managed_gateway_required")
    ipaddress.ip_address(uri.hostname)
    return raw


def main():
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--engine", required=True, choices=["garak"])
    parser.add_argument("--scope", required=True, choices=[str(SCOPE)])
    parser.add_argument("--output", required=True, choices=[str(OUTPUT)])
    parser.parse_args()
    os.umask(0o077)
    now = datetime.datetime.now(datetime.timezone.utc)
    scope = read_document(SCOPE, 1024 * 1024, require_readonly=True)
    endpoint, model, deadline = validate_scope(scope, now)
    credential = read_document(CREDENTIALS, 16384, require_readonly=True)
    key, key_expiry = read_key(credential, now)
    deadline = min(deadline, (key_expiry - now).total_seconds())
    proxy = validate_proxy(os.environ.get("AI_SECURITY_SCANNER_PROXY", ""))
    if OUTPUT.is_symlink() or not OUTPUT.is_dir() or any(OUTPUT.iterdir()):
        raise Rejected("fresh_output_directory_required")
    # The caller cannot supply config, flags, provider plugins, probe names, or a CA override.
    with tempfile.TemporaryDirectory(prefix="aiss-garak-", dir="/tmp") as temporary:
        directory = Path(temporary)
        (directory / "config.json").write_text(json.dumps({"endpoint": endpoint, "model": model,
                                                         "proxy": proxy, "deadline_seconds": deadline}))
        native_config = {"system": {"parallel_requests": 1, "parallel_attempts": 1},
                         "run": {"generations": 1, "target_lang": "en", "langproviders": []},
                         "plugins": {"extended_detectors": False, "generators": {"rest": {"RestGenerator": {
                             "uri": endpoint, "name": endpoint, "request_timeout": 20,
                             "verify_ssl": True, "proxies": {"http": proxy, "https": proxy},
                             "headers": {"Content-Type": "application/json", "Authorization": "Bearer $KEY"},
                             "req_template_json_object": {"model": model, "messages": [{"role": "user", "content": "$INPUT"}],
                                                          "max_tokens": 150, "stream": False},
                             "response_json": True, "response_json_field": "$.choices[0].message.content"}}}}}
        (directory / "native.yaml").write_text(json.dumps(native_config))
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": temporary,
                       "XDG_CACHE_HOME": temporary + "/cache", "XDG_CONFIG_HOME": temporary + "/config",
                       "XDG_DATA_HOME": temporary + "/data", "TMPDIR": temporary,
                       "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0",
                       "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1", "NO_COLOR": "1",
                       "REST_API_KEY": key}
        def resource_limit():
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_REPORT_BYTES, MAX_REPORT_BYTES))
        with (directory / "diagnostics.log").open("wb") as diagnostics:
            process = subprocess.Popen(["/usr/local/bin/python3", "-I", "-B",
                                        "/usr/local/lib/aiss-garak/runner.py", str(directory / "config.json")],
                                       env=environment, cwd=temporary, stdin=subprocess.DEVNULL,
                                       stdout=diagnostics, stderr=diagnostics, preexec_fn=resource_limit)
            timed_out = False
            cancelled = False
            class NativeCancellation(BaseException):
                pass
            def stop_native(_signum, _frame):
                raise NativeCancellation()
            previous_term = signal.signal(signal.SIGTERM, stop_native)
            previous_int = signal.signal(signal.SIGINT, stop_native)
            try:
                process.wait(timeout=deadline)
            except (subprocess.TimeoutExpired, NativeCancellation) as error:
                timed_out = isinstance(error, subprocess.TimeoutExpired)
                cancelled = not timed_out
                process.kill()
                process.wait()
            finally:
                signal.signal(signal.SIGTERM, previous_term)
                signal.signal(signal.SIGINT, previous_int)
        receipt_path = directory / "execution.json"
        receipt = read_document(receipt_path, 16384) if receipt_path.exists() else {
            "schema_version": "1", "profile_id": "garak_https_v1", "complete": False,
            "reason": "inference_deadline" if timed_out else "native_execution_failed"}
        if timed_out or cancelled or process.returncode != 0:
            receipt["complete"] = False
        if cancelled:
            receipt["reason"] = "native_cancelled"
        preserved = OUTPUT / "upstream"
        preserved.mkdir(mode=0o700)
        ledger = directory / "requests.jsonl"
        if ledger.exists():
            records = ledger.read_bytes().splitlines()
            receipt["http_attempts"] = len(records)
            receipt["total_request_bytes"] = sum(json.loads(line)["request_bytes"] for line in records)
            shutil.copyfile(ledger, preserved / "garak-requests.jsonl")
        receipt.update(scope_sha256=hashlib.sha256(SCOPE.read_bytes()).hexdigest(),
                       max_http_attempts=64, max_completion_tokens_per_request=150,
                       max_total_request_bytes=65536)
        native_report = directory / "native.report.jsonl"
        if native_report.exists():
            report = native_report.read_bytes()
            if len(report) > MAX_REPORT_BYTES or key.encode() in report:
                receipt.update(complete=False, reason="unsafe_native_report")
            else:
                (OUTPUT / "report.jsonl").write_bytes(report)
        (preserved / "garak-execution.json").write_text(json.dumps(receipt) + "\n")
        return 0 if receipt["complete"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError):
        print("Garak model profile rejected its input or protected execution channel.", file=sys.stderr)
        sys.exit(2)

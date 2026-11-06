"""Invoke the upstream CLI behind a bounded REST transport, without altering detectors."""
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

PROBES = ("dan.Dan_11_0", "dan.Dan_10_0", "dan.Dan_9_0", "ansiescape.AnsiEscaped")
EXPECTED = {"dan.Dan_11_0": 1, "dan.Dan_10_0": 1, "dan.Dan_9_0": 1, "ansiescape.AnsiEscaped": 51}
MAX_ATTEMPTS = 64
MAX_COMPLETION_TOKENS = 150
MAX_REQUEST_BYTES = 8192
MAX_TOTAL_REQUEST_BYTES = 65536
MAX_RESPONSE_BYTES = 262144


class BoundaryViolation(BaseException):
    """Escape upstream retries and broad exception handlers with a stable, non-secret code."""


class BoundedTransport:
    def __init__(self, config, key, ledger, original_send):
        self.config, self.key, self.ledger = config, key, ledger
        self.original_send = original_send
        self.attempts = self.total_bytes = 0
        self.last_started = None
        self.deadline = time.monotonic() + config["deadline_seconds"]

    def send(self, session, request, **kwargs):
        if request.method != "POST" or request.url != self.config["endpoint"]:
            raise BoundaryViolation("destination_mismatch")
        if not hmac.compare_digest(request.headers.get("Authorization", ""), "Bearer " + self.key):
            raise BoundaryViolation("credential_mismatch")
        body = request.body
        if isinstance(body, str):
            body = body.encode("utf-8")
        if not isinstance(body, bytes) or len(body) > MAX_REQUEST_BYTES:
            raise BoundaryViolation("request_size_limit")
        try:
            payload = json.loads(body)
            messages = payload["messages"]
            valid = (
                set(payload) == {"model", "messages", "max_tokens", "stream"}
                and payload["model"] == self.config["model"]
                and type(payload["max_tokens"]) is int
                and payload["max_tokens"] == MAX_COMPLETION_TOKENS
                and payload["stream"] is False
                and isinstance(messages, list) and len(messages) == 1
                and set(messages[0]) == {"role", "content"}
                and messages[0]["role"] == "user"
                and isinstance(messages[0]["content"], str)
            )
        except (ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            raise BoundaryViolation("request_contract_mismatch")
        if kwargs.get("verify") is not True or kwargs.get("cert") is not None:
            raise BoundaryViolation("tls_contract_mismatch")
        if kwargs.get("proxies") != {"http": self.config["proxy"], "https": self.config["proxy"]}:
            raise BoundaryViolation("gateway_mismatch")
        if self.attempts >= MAX_ATTEMPTS or self.total_bytes + len(body) > MAX_TOTAL_REQUEST_BYTES:
            raise BoundaryViolation("inference_budget_exhausted")
        delay = 0 if self.last_started is None else max(0, 1 - (time.monotonic() - self.last_started))
        if time.monotonic() + delay >= self.deadline:
            raise BoundaryViolation("inference_deadline")
        time.sleep(delay)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise BoundaryViolation("inference_deadline")
        # Reserve every attempt before sending. Native HTTP backoff retries consume this same budget.
        self.attempts += 1
        self.total_bytes += len(body)
        self.last_started = time.monotonic()
        record = {"attempt": self.attempts, "request_bytes": len(body),
                  "request_sha256": hashlib.sha256(body).hexdigest(), "max_completion_tokens": MAX_COMPLETION_TOKENS}
        self.ledger.write(json.dumps(record, separators=(",", ":")) + "\n")
        self.ledger.flush()
        os.fsync(self.ledger.fileno())
        kwargs.update(allow_redirects=False, stream=True, timeout=min(20, remaining))
        response = self.original_send(session, request, **kwargs)
        try:
            if 300 <= response.status_code < 400:
                raise BoundaryViolation("redirect_refused")
            data = bytearray()
            for chunk in response.iter_content(8192):
                if time.monotonic() >= self.deadline:
                    raise BoundaryViolation("inference_deadline")
                data.extend(chunk)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise BoundaryViolation("response_size_limit")
            response._content = bytes(data)
            response._content_consumed = True
            return response
        finally:
            response.close()


def verify_native_report(path):
    """Check coverage shape; every verdict and count remains upstream's own."""
    rows = []
    with path.open("rb") as stream:
        for line in stream:
            if len(line) > 1024 * 1024 or len(rows) >= 10000:
                raise BoundaryViolation("report_size_limit")
            rows.append(json.loads(line))
    inits = [r for r in rows if r.get("entry_type") == "init"]
    completions = [r for r in rows if r.get("entry_type") == "completion"]
    if len(inits) != 1 or inits[0].get("garak_version") != "0.17.1" or len(completions) != 1:
        raise BoundaryViolation("native_run_incomplete")
    if completions[0].get("run") != inits[0].get("run"):
        raise BoundaryViolation("native_run_identity_mismatch")
    evals = [r for r in rows if r.get("entry_type") == "eval"]
    primary = {"dan.Dan_11_0": "dan.DAN", "dan.Dan_10_0": "dan.DAN",
               "dan.Dan_9_0": "dan.DAN", "ansiescape.AnsiEscaped": "ansiescape.Escaped"}
    if len(evals) != len(EXPECTED) or {r.get("probe") for r in evals} != set(EXPECTED):
        raise BoundaryViolation("native_probe_coverage_incomplete")
    for row in evals:
        probe = row["probe"]
        evaluated, processed, fails, nones = (row.get(k) for k in ("total_evaluated", "total_processed", "fails", "nones"))
        if (row.get("detector") != primary[probe]
                or any(type(v) is not int for v in (evaluated, processed, fails, nones))
                or evaluated != EXPECTED[probe] or processed != evaluated or nones != 0
                or not 0 <= fails <= evaluated):
            raise BoundaryViolation("native_probe_coverage_incomplete")
    return evals


def main():
    config_path = Path(sys.argv[1])
    config = json.loads(config_path.read_text())
    key = os.environ["REST_API_KEY"]
    proxy = urlsplit(config["proxy"])
    gateway = (str(ipaddress.ip_address(proxy.hostname)), 1080)
    # Prevent any provider, corpus downloader, or auxiliary client from bypassing the managed gateway.
    def audit(event, args):
        if event == "socket.connect" and tuple(args[1][:2]) != gateway:
            raise BoundaryViolation("gateway_bypass_refused")
    sys.addaudithook(audit)
    import requests
    original_send = requests.sessions.Session.send
    directory = config_path.parent
    receipt = {"schema_version": "1", "profile_id": "garak_https_v1", "complete": False,
               "reason": "native_run_incomplete", "max_http_attempts": MAX_ATTEMPTS,
               "max_completion_tokens_per_request": MAX_COMPLETION_TOKENS}
    with (directory / "requests.jsonl").open("x", encoding="utf-8") as ledger:
        boundary = BoundedTransport(config, key, ledger, original_send)
        requests.sessions.Session.send = lambda session, request, **kwargs: boundary.send(session, request, **kwargs)
        try:
            import garak.cli
            garak.cli.main(["--config", str(directory / "native.yaml"), "--target_type", "rest.RestGenerator",
                            "--target_name", config["endpoint"], "--generations", "1",
                            "--parallel_attempts", "1", "--parallel_requests", "1",
                            "--spec", ",".join("probes." + p for p in PROBES),
                            "--report_prefix", str(directory / "native")])
            verify_native_report(directory / "native.report.jsonl")
            receipt.update(complete=True, reason=None)
        except BoundaryViolation as error:
            receipt["reason"] = str(error)
        except BaseException:
            receipt["reason"] = "native_execution_failed"
        finally:
            receipt.update(http_attempts=boundary.attempts, total_request_bytes=boundary.total_bytes)
            (directory / "execution.json").write_text(json.dumps(receipt) + "\n")
    return 0 if receipt["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())

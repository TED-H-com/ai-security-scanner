"""Run genuine Garak against a disposable, isolated TLS model fixture only."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

BASE = "python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7"
PAIRS = {"dan.Dan_11_0": ("dan.DAN", 1), "dan.Dan_10_0": ("dan.DAN", 1),
         "dan.Dan_9_0": ("dan.DAN", 1), "ansiescape.AnsiEscaped": ("ansiescape.Escaped", 51)}


def command(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    destination = Path(args.output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if list(destination.iterdir()):
        raise ValueError("smoke output directory must be empty")
    identity = json.loads(command("docker", "image", "inspect", args.image))[0]
    assert identity["Os"] == "linux" and identity["Architecture"] == "amd64"
    spec = importlib.util.spec_from_file_location("scope_fixture", Path(__file__).parents[1] / "launcher/main_test.py")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    suffix = secrets.token_hex(6)
    network = "aiss-garak-smoke-" + suffix
    containers = []
    results = []
    with tempfile.TemporaryDirectory(prefix="aiss-garak-smoke-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        shutil.copyfile(Path(__file__).with_name("mock_server.py"), root / "mock_server.py")
        command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"),
                "-subj", "/CN=model.example.test", "-addext", "subjectAltName=DNS:model.example.test",
                stderr=subprocess.DEVNULL)
        (root / "cert.pem").chmod(0o444)
        (root / "mode").write_text("clean")
        command("docker", "network", "create", "--internal", network)
        try:
            mock = "aiss-garak-mock-" + suffix
            containers.append(mock)
            command("docker", "run", "-d", "--name", mock, "--network", network, "--read-only",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", "128",
                    "--memory", "256m", "--cpus", "1", "--user", f"{os.getuid()}:{os.getgid()}",
                    "--mount", f"type=bind,src={root},dst=/fixture", BASE, "python", "-I", "-B", "/fixture/mock_server.py")
            for _ in range(100):
                if "ready" in command("docker", "logs", mock):
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("isolated TLS fixture did not start")
            mock_inspect = json.loads(command("docker", "inspect", mock))[0]
            proxy_ip = mock_inspect["NetworkSettings"]["Networks"][network]["IPAddress"]
            assert json.loads(command("docker", "network", "inspect", network))[0]["Internal"] is True
            request_log = root / "requests.jsonl"
            def requests():
                return [json.loads(line) for line in request_log.read_text().splitlines()] if request_log.exists() else []
            for mode in ("positive", "clean", "redirect", "bad-tls", "deadline", "cancelled"):
                print(f"Native Garak smoke: {mode}", flush=True)
                case = root / mode
                case.mkdir(mode=0o755)
                (case / "output").mkdir(mode=0o777)
                (case / "output").chmod(0o777)
                (root / "mode").write_text("retry" if mode == "deadline" else "positive" if mode in ("positive", "cancelled") else "redirect" if mode == "redirect" else "clean")
                fixture.NOW = datetime.datetime.now(datetime.timezone.utc)
                scope = fixture.scope()
                scope["assets"][0]["identifiers"][0]["value"] = "https://model.example.test:8443/v1/chat/completions"
                external = scope["assets"][0]["grants"][0]["external_scope"]
                external["ports"] = [8443]
                external["allow_sensitive_networks"] = True
                if mode == "deadline":
                    external["expires_at"] = (fixture.NOW + datetime.timedelta(seconds=6)).isoformat()
                (case / "scope.json").write_text(json.dumps(scope))
                (case / "scope.json").chmod(0o444)
                synthetic_key = secrets.token_hex(24)
                (case / "credentials.json").write_text(json.dumps({"schema_version": "1.0.0", "credentials": [{
                    "key": "REST_API_KEY", "value": synthetic_key, "source": "local_model_endpoint",
                    "expires_at": (fixture.NOW + datetime.timedelta(minutes=30)).isoformat()}]}))
                (case / "credentials.json").chmod(0o444)
                name = "aiss-garak-" + mode + "-" + suffix
                containers.append(name)
                argv = ["docker", "run", "--name", name, "--network", network, "--read-only", "--cap-drop", "ALL",
                        "--security-opt", "no-new-privileges:true", "--pids-limit", "128", "--memory", "1g", "--cpus", "1",
                        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=128m",
                        "--env", "AI_SECURITY_SCANNER_PROXY=socks5h://" + proxy_ip + ":1080"]
                for source, target, readonly in ((case / "scope.json", "/run/ai-security-scanner/scope.json", True),
                                                 (case / "credentials.json", "/run/ai-security-scanner/credentials.json", True),
                                                 (case / "output", "/output", False)):
                    argv += ["--mount", f"type=bind,src={source},dst={target}" + (",readonly" if readonly else "")]
                if mode != "bad-tls":
                    argv += ["--mount", f"type=bind,src={root}/cert.pem,dst=/usr/local/lib/python3.11/site-packages/certifi/cacert.pem,readonly"]
                argv += [args.image, "--engine", "garak", "--scope", "/run/ai-security-scanner/scope.json", "--output", "/output"]
                before = len(requests())
                stop_count = None
                with (case / "launcher.log").open("w") as log:
                    process = subprocess.Popen(argv, stdout=log, stderr=log)
                    if mode == "cancelled":
                        time.sleep(10)
                        command("docker", "stop", "--time", "2", name)
                        stop_count = len(requests())
                        time.sleep(2)
                        assert len(requests()) == stop_count, "model requests continued after cancellation"
                    code = process.wait(timeout=660)
                captured = case / "captured"
                captured.mkdir()
                command("docker", "cp", name + ":/output/.", str(captured))
                command("docker", "rm", name)
                containers.remove(name)
                receipt_path = captured / "upstream/garak-execution.json"
                receipt = json.loads(receipt_path.read_text()) if receipt_path.exists() else None
                raw_path = captured / "report.jsonl"
                raw = raw_path.read_bytes() if raw_path.exists() else b""
                assert synthetic_key.encode() not in raw and synthetic_key not in (case / "launcher.log").read_text()
                rows = [json.loads(line) for line in raw.decode().splitlines()]
                evals = [{key: row.get(key) for key in ("probe", "detector", "fails", "total_evaluated", "total_processed", "nones")}
                         for row in rows if row.get("entry_type") == "eval"]
                observed = requests()[before:]
                assert all(row["path"] == "/v1/chat/completions" and row["model"] == "fixture/model"
                           and row["max_tokens"] == 150 and row["tls"] for row in observed)
                if mode in ("positive", "clean"):
                    assert code == 0 and receipt["complete"] is True and receipt["http_attempts"] == len(observed) == 54
                    assert len(evals) == 4 and {r["probe"] for r in evals} == set(PAIRS)
                    for row in evals:
                        detector, count = PAIRS[row["probe"]]
                        assert row["detector"] == detector and row["total_evaluated"] == row["total_processed"] == count and row["nones"] == 0
                        assert row["fails"] == (count if mode == "positive" else 0)
                    if mode == "positive":
                        (destination / "report.jsonl").write_bytes(raw)
                        shutil.copyfile(receipt_path, destination / "garak-execution.json")
                elif mode == "redirect":
                    assert code != 0 and receipt["complete"] is False and receipt["reason"] == "redirect_refused" and receipt["http_attempts"] == len(observed) == 1
                elif mode == "bad-tls":
                    assert code != 0 and receipt["complete"] is False and receipt["http_attempts"] == 1 and not observed
                elif mode == "deadline":
                    assert code != 0 and receipt["complete"] is False and receipt["reason"] == "inference_deadline" and receipt["http_attempts"] <= 6
                else:
                    assert code != 0 and stop_count is not None and receipt["complete"] is False
                    assert receipt["reason"] == "native_cancelled" and raw and not evals
                results.append({"case": mode, "exit_code": code, "receipt": receipt, "evals": evals,
                                "observed_http_requests": len(observed), "no_requests_after_stop": True if mode == "cancelled" else None,
                                "raw_sha256": hashlib.sha256(raw).hexdigest() if raw else None})
            denied = root / "denied.jsonl"
            assert not denied.exists() or not denied.read_text().strip(), "native inference attempted an unapproved destination"
            (destination / "native-qa.json").write_text(json.dumps({"schema_version": 1, "platform": "linux/amd64",
                "image": args.image, "image_id": identity["Id"], "native_version": "0.17.1", "network_internal": True,
                "unapproved_destinations": 0, "cases": results}, indent=2) + "\n")
        finally:
            for container in reversed(containers):
                subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["docker", "network", "rm", network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Only generated native output needs uid0 cleanup; no owner path or credential store is mounted.
            subprocess.run(["docker", "run", "--rm", "--network", "none", "--user", "0:0", "--read-only",
                            "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges:true",
                            "--mount", f"type=bind,src={root},dst=/fixture", BASE, "python", "-I", "-B", "-c",
                            "import shutil; from pathlib import Path; "
                            "[shutil.rmtree(p) for p in Path('/fixture').glob('*/output') if p.is_dir()]"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


if __name__ == "__main__":
    main()

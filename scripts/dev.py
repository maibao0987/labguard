"""Explicit localhost-only demo. SQLite is for development, never isolation proof."""

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-local-lab", action="store_true", required=True)
    parser.add_argument("--repair-original", action="store_true")
    args = parser.parse_args()
    os.chdir(ROOT)
    runtime = ROOT / "runtime"
    runtime.mkdir(exist_ok=True)
    config = runtime / "local-secrets.json"
    if not config.exists():
        config.write_text(
            json.dumps(
                {
                    "password": secrets.token_hex(16),
                    "keys": {s: secrets.token_hex(32) for s in ["manager", "vulnerable", "fixed"]},
                }
            ),
            encoding="utf-8",
        )
    credentials = json.loads(config.read_text("utf-8"))
    processes = []
    logs = []
    try:
        for service, port in [("manager", 5100), ("vulnerable", 5101), ("fixed", 5102)]:
            env = dict(
                os.environ,
                DATABASE_URL="sqlite:///" + (runtime / f"{service}.db").as_posix(),
                SECRET_KEY=credentials["keys"][service],
                MANAGER_PASSWORD=credentials["password"],
                LAB_PROFILE="local",
                COOKIE_NAME=f"labguard_{service}",
            )
            actual = "fixed" if args.repair_original and service == "vulnerable" else service
            subprocess.run(
                [sys.executable, "-m", "labguard.cli", "init", "--service", actual], env=env, check=True
            )
            log = open(runtime / f"{service}.log", "a", encoding="utf-8")
            logs.append(log)
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-m", "labguard.cli", "serve", "--service", actual, "--port", str(port)],
                    env=env,
                    stdout=log,
                    stderr=log,
                )
            )
            if service == "manager":
                manager_env = env
        worker_log = open(runtime / "worker.log", "a", encoding="utf-8")
        logs.append(worker_log)
        processes.append(
            subprocess.Popen(
                [sys.executable, "-m", "labguard.cli", "worker"],
                env=manager_env,
                stdout=worker_log,
                stderr=worker_log,
            )
        )
        print("Local: http://127.0.0.1:5100 | :5101 | :5102", flush=True)
        print("Admin: admin | Password is in runtime/local-secrets.json", flush=True)
        print("LOCAL DEVELOPMENT ONLY: not container-isolated. Ctrl+C stops owned processes.", flush=True)
        while all(p.poll() is None for p in processes):
            time.sleep(1)
        raise RuntimeError("A service exited; inspect runtime/*.log")
    except KeyboardInterrupt:
        pass
    finally:
        for p in processes:
            p.terminate()
        for p in processes:
            p.wait(timeout=10)
        for log in logs:
            log.close()


if __name__ == "__main__":
    main()

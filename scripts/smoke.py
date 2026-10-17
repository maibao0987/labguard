"""Connect ONLY to the three fixed localhost LabGuard services."""

import json
import re
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent


def token(client, path):
    r = client.get(path)
    r.raise_for_status()
    return re.search(r'name="csrf" value="([a-f0-9]+)"', r.text).group(1)


def main():
    profile = None
    for port in [5100, 5101, 5102]:
        r = httpx.get(f"http://127.0.0.1:{port}/health", timeout=5, trust_env=False)
        assert r.status_code == 200 and r.json()["status"] == "ok"
        if port == 5100:
            profile = r.json().get("profile")
    env = ROOT / ".env"
    if env.exists() and profile != "local":
        password = dict(
            line.split("=", 1) for line in env.read_text("utf-8-sig").splitlines() if "=" in line
        )["MANAGER_PASSWORD"]
    else:
        password = json.loads((ROOT / "runtime/local-secrets.json").read_text("utf-8"))["password"]
    with httpx.Client(
        base_url="http://127.0.0.1:5100", trust_env=False, follow_redirects=False, timeout=5
    ) as client:
        r = client.post(
            "/login", data={"csrf": token(client, "/login"), "username": "admin", "password": password}
        )
        assert r.status_code == 302
        for path in ["/", "/jobs", "/assets", "/findings", "/reports", "/audit"]:
            assert client.get(path).status_code == 200, path
        r = client.post(
            "/scopes/1",
            data={
                "csrf": token(client, "/assets"),
                "action": "enable",
                "reason": "本人擁有此隔離實驗室並授權固定檢查",
            },
        )
        assert r.status_code == 302
        for asset in [1, 2]:
            for check in ["health", "headers", "idor", "sqli", "xss"]:
                r = client.post(
                    "/jobs",
                    data={
                        "csrf": token(client, "/jobs"),
                        "scope_id": 1,
                        "asset_id": asset,
                        "check_type": check,
                    },
                )
                assert r.status_code == 302
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            data = client.get("/reports/export/json").json()
            if len(data["jobs"]) >= 10 and all(
                j["status"] not in {"queued", "running"} for j in data["jobs"]
            ):
                break
            time.sleep(1)
        assert all(j["status"] == "succeeded" for j in data["jobs"]), [
            (j["id"], j["status"], j["error_code"]) for j in data["jobs"]
        ]
        assert {f["check_id"] for f in data["findings"] if f["asset_id"] == 1} == {
            "headers",
            "idor",
            "sqli",
            "xss",
        }
        assert not [f for f in data["findings"] if f["asset_id"] == 2]
        # Export samples contain ONLY seeded lab data; no session or password is serialized.
        out = ROOT / "reports/samples"
        out.mkdir(exist_ok=True, parents=True)
        (out / "actual-local-report.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
        (out / "actual-local-report.md").write_text(client.get("/reports/export/md").text, "utf-8")
        print(
            "PASS: three health endpoints, login, six pages, 10 queued checks, vulnerable/fixed outcomes, two exports"
        )
        client.post("/scopes/1", data={"csrf": token(client, "/assets"), "action": "disable"})


if __name__ == "__main__":
    main()

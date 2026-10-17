"""Two-phase same-asset closure demo. Only localhost:5100, fake lab findings."""

import argparse
import json
import re
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent


def token(client, path):
    return re.search(r'name="csrf" value="([a-f0-9]+)"', client.get(path).text).group(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["prepare", "verify"])
    args = parser.parse_args()
    # Local developer mode intentionally uses only its own generated credentials.
    password = json.loads((ROOT / "runtime/local-secrets.json").read_text("utf-8"))["password"]
    with httpx.Client(
        base_url="http://127.0.0.1:5100", trust_env=False, follow_redirects=False, timeout=5
    ) as c:
        assert (
            c.post(
                "/login", data={"csrf": token(c, "/login"), "username": "admin", "password": password}
            ).status_code
            == 302
        )
        report = c.get("/reports/export/json").json()
        f = next(f for f in report["findings"] if f["asset_id"] == 1 and f["check_id"] == "idor")
        fid = f["id"]
        path = f"/findings/{fid}"
        c.post(
            "/scopes/1",
            data={
                "csrf": token(c, "/assets"),
                "action": "enable",
                "reason": "本人擁有本機實驗室並授權原資產複測",
            },
        )
        if args.phase == "prepare":
            assert f["status"] == "new", "Use a fresh smoke dataset"
            for state in ["confirmed", "in_progress", "ready_for_retest"]:
                c.post(
                    path + "/status",
                    data={
                        "csrf": token(c, path),
                        "status": state,
                        "reason": "人工比對 Alice 與 Bob 假資料及授權行為",
                    },
                )
            print(
                "Prepared original asset #1 IDOR for retest. Stop dev, restart with --repair-original, then verify."
            )
            return
        assert f["status"] == "ready_for_retest"
        c.post(path + "/retest", data={"csrf": token(c, path), "scope_id": 1})
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            report = c.get("/reports/export/json").json()
            current = next(x for x in report["findings"] if x["id"] == fid)
            if current["status"] == "resolved":
                break
            time.sleep(1)
        assert current["status"] == "resolved", current["status"]
        assert any(r["finding_id"] == fid and r["result"] == "passed" for r in report["retests"])
        (ROOT / "reports/samples/actual-retest-report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), "utf-8"
        )
        (ROOT / "reports/samples/actual-retest-report.md").write_text(
            c.get("/reports/export/md").text, "utf-8"
        )
        c.post("/scopes/1", data={"csrf": token(c, "/assets"), "action": "disable"})
        print(
            "PASS: original asset #1 repaired, same finding retested and resolved; report exported; scope revoked"
        )


if __name__ == "__main__":
    main()

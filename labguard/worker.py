"""Fixed checks, pinned destinations, bounded response reads. No arbitrary scanner."""

import os
import re
import socket
import time
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import select

from .db import audit, engine_for, findings, jobs, now, retests, scopes
from .domain import ScopeError, ingest, registry, validate_scope


class Cancelled(Exception):
    pass


class JobTimeout(Exception):
    pass


class LabHTTP:
    def __init__(self, target, guard, rate=2):
        self.target, self.guard, self.rate = target, guard, rate
        self.client = httpx.Client(follow_redirects=False, trust_env=False, timeout=3.0)
        self.last = 0.0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.client.close()

    def request(self, method, path, **kwargs):
        if path not in {"/", "/health", "/login", "/tasks/2", "/tasks/3"}:
            raise ScopeError("未登錄的檢查路徑")
        time.sleep(max(0, 1 / self.rate - (time.monotonic() - self.last)))
        self.guard()
        target = self.target
        addresses = {
            x[4][0] for x in socket.getaddrinfo(target["host"], target["port"], type=socket.SOCK_STREAM)
        }
        if addresses != {target["ip"]}:
            raise ScopeError("服務解析位址與核准 manifest 不符")
        # Connect to validated literal IP to avoid DNS check/use mismatch.
        url = f"http://{target['ip']}:{target['port']}{path}"
        self.last = time.monotonic()
        with self.client.stream(method, url, **kwargs) as response:
            if 300 <= response.status_code < 400:
                # Login/POST PRG is explicitly observed but never followed.
                if not (
                    method == "POST"
                    and response.status_code == 302
                    and response.headers.get("location") in {"/", "/tasks/3"}
                ):
                    raise ScopeError("目標回傳未核准重新導向")
            chunks, size = [], 0
            for chunk in response.iter_bytes():
                self.guard()
                size += len(chunk)
                if size > 65536:
                    raise ValueError("目標回應過大")
                chunks.append(chunk)
            return httpx.Response(
                response.status_code,
                headers=response.headers,
                content=b"".join(chunks),
                request=response.request,
            )


def csrf_from(response):
    match = re.search(r'name="csrf" value="([a-f0-9]+)"', response.text)
    if not match:
        raise ValueError("測試頁面缺少 CSRF 表單")
    return match.group(1)


def login(client):
    response = client.request("GET", "/login")
    response = client.request(
        "POST", "/login", data={"csrf": csrf_from(response), "username": "alice", "password": "LabOnly-12345"}
    )
    if response.status_code != 302:
        raise ValueError("固定測試帳號登入失敗")


def issue(check, title, location, parameter, cwe, evidence, remediation, severity="medium", method="GET"):
    return {
        "check_id": check,
        "title": title,
        "location": location,
        "parameter": parameter,
        "cwe_id": cwe,
        "evidence": evidence,
        "remediation": remediation,
        "severity": severity,
        "method": method,
        "category": check,
        "description": "隔離種子資料中的受控檢查結果，需人工確認。",
        "impact": "僅驗證本實驗室假資料；不推定其他系統影響。",
        "reproduction": "參閱 docs/cases 與關聯工作。",
    }


def run_check(check, client):
    response = client.request("GET", "/health")
    if response.status_code != 200 or response.json().get("status") != "ok":
        raise ValueError("目標健康檢查失敗")
    if check == "health":
        return [], "服務健康；不代表沒有漏洞"
    if check == "headers":
        missing = [
            h
            for h in ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"]
            if h not in response.headers
        ]
        result = (
            [
                issue(
                    "headers",
                    "缺少防禦性安全標頭",
                    "/health",
                    "headers",
                    "CWE-693",
                    ", ".join(missing),
                    "依頁面用途設定安全標頭；本機 HTTP 不以 HSTS 缺少評為高風險。",
                    "low",
                )
            ]
            if missing
            else []
        )
        return result, "安全標頭檢查完成；未檢查 HSTS"
    login(client)
    if check == "idor":
        r = client.request("GET", "/tasks/2")
        if r.status_code == 200 and "BOB-PRIVATE-SEED" in r.text:
            return [
                issue(
                    "idor",
                    "可讀取其他成員私人任務",
                    "/tasks/2",
                    "task_id",
                    "CWE-639",
                    "Alice 存取 Bob 任務，回應包含 BOB-PRIVATE-SEED。",
                    "每次讀取任務時驗證擁有者或管理員角色。",
                    "high",
                )
            ], "IDOR 已觀測"
        if r.status_code != 403:
            raise ValueError("IDOR 回應不符合預期，不能視為修復")
        return [], "物件授權拒絕成功"
    if check == "sqli":
        baseline = client.request("GET", "/", params={"q": "NO-MATCH-LABGUARD"})
        if baseline.status_code != 200 or 'data-task-id="2"' in baseline.text:
            raise ValueError("SQLi 基準不成立")
        r = client.request("GET", "/", params={"q": "' OR 1=1 -- "})
        if r.status_code != 200:
            raise ValueError("SQLi 查詢錯誤；未證明修復")
        if 'data-task-id="2"' in r.text:
            return [
                issue(
                    "sqli",
                    "搜尋條件可改變查詢邏輯",
                    "/",
                    "q",
                    "CWE-89",
                    "固定布林條件使 Alice 搜尋結果包含 Bob 私人任務 ID 2。",
                    "使用參數化查詢，保留授權條件。",
                    "high",
                )
            ], "SQLi 已觀測"
        return [], "固定 SQLi 案例未繞過查詢"
    if check == "xss":
        r = client.request("GET", "/tasks/3")
        marker = '<span data-labguard-xss="probe">LABGUARD-XSS</span>'
        r = client.request("POST", "/tasks/3", data={"csrf": csrf_from(r), "body": marker})
        if r.status_code != 302:
            raise ValueError("XSS 假留言建立失敗")
        r = client.request("GET", "/tasks/3")
        if r.status_code != 200:
            raise ValueError("XSS 讀取失敗")
        if marker in r.text:
            return [
                issue(
                    "xss",
                    "留言未編碼輸出，存在 Stored XSS 風險",
                    "/tasks/3",
                    "body",
                    "CWE-79",
                    "儲存的無害 HTML 標記被原樣輸出；此自動檢查只證明 HTML 注入，腳本執行需瀏覽器人工確認。",
                    "使用 Jinja 自動輸出編碼，不對不可信留言使用 safe。",
                    method="POST",
                )
            ], "HTML 注入已觀測；需人工驗證 XSS"
        if "&lt;span" not in r.text or "LABGUARD-XSS" not in r.text:
            raise ValueError("XSS 標記未出現，不能視為修復")
        return [], "留言標記已輸出編碼"
    raise ValueError("未知檢查")


def process_one(engine, profile="docker", http_factory=LabHTTP):
    # Single-worker lease. Also serialize manager imports/result mutations with a DB row lock.
    cutoff = (datetime.now(UTC) - timedelta(seconds=65)).isoformat()
    with engine.begin() as c:
        c.execute(select(scopes).order_by(scopes.c.id).with_for_update()).all()
        stale = (
            c.execute(select(jobs).where(jobs.c.status == "running", jobs.c.heartbeat_at < cutoff))
            .mappings()
            .all()
        )
        for row in stale:
            c.execute(
                jobs.update()
                .where(jobs.c.id == row["id"])
                .values(status="timed_out", finished_at=now(), error_code="worker_lost")
            )
        if c.execute(select(jobs.c.id).where(jobs.c.status == "running")).first():
            return False
        job = (
            c.execute(
                select(jobs)
                .where(jobs.c.status == "queued")
                .order_by(jobs.c.id)
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            .mappings()
            .first()
        )
        if not job:
            return False
        job = dict(job)
        c.execute(
            jobs.update()
            .where(jobs.c.id == job["id"])
            .values(
                status="running",
                started_at=now(),
                heartbeat_at=now(),
                deadline_at=(datetime.now(UTC) + timedelta(seconds=45)).isoformat(),
            )
        )
    start = time.monotonic()

    def guard():
        if time.monotonic() - start > 45:
            raise JobTimeout()
        with engine.begin() as c:
            current = c.execute(select(jobs).where(jobs.c.id == job["id"])).mappings().one()
            if current["cancel_requested"] or current["status"] != "running":
                raise Cancelled()
            scope, asset = validate_scope(c, job["scope_id"], job["asset_id"], job["check_type"])
            c.execute(jobs.update().where(jobs.c.id == job["id"]).values(heartbeat_at=now()))
        return scope, asset

    try:
        scope, asset = guard()
        target = registry(profile)[asset["key"]]
        with http_factory(target, guard, scope["rate"]) as client:
            items, summary = run_check(job["check_type"], client)
        guard()
        with engine.begin() as c:
            # Re-check under scope lock before recording a successful check.
            c.execute(select(scopes).where(scopes.c.id == job["scope_id"]).with_for_update()).first()
            validate_scope(c, job["scope_id"], job["asset_id"], job["check_type"])
            current = c.execute(select(jobs).where(jobs.c.id == job["id"]).with_for_update()).mappings().one()
            if current["cancel_requested"]:
                raise Cancelled()
            for item in items:
                ingest(c, job["asset_id"], item, job["id"], "worker")
            if job["retest_id"]:
                f = c.execute(select(findings).where(findings.c.id == job["retest_id"])).mappings().one()
                if f["status"] != "ready_for_retest":
                    raise ValueError("弱點狀態已變更，複測結果不予關閉")
                matched = [
                    i
                    for i in items
                    if i["location"] == f["location"]
                    and i["parameter"] == f["parameter"]
                    and i["method"] == f["method"]
                ]
                passed = not matched
                c.execute(
                    retests.insert().values(
                        finding_id=f["id"],
                        job_id=job["id"],
                        created_at=now(),
                        result="passed" if passed else "failed",
                        detail=summary,
                    )
                )
                c.execute(
                    findings.update()
                    .where(findings.c.id == f["id"])
                    .values(status="resolved" if passed else "in_progress")
                )
                audit(c, "worker", "retest", f"finding:{f['id']}", summary)
            c.execute(
                jobs.update()
                .where(jobs.c.id == job["id"])
                .values(status="succeeded", finished_at=now(), summary=summary)
            )
    except Exception as exc:
        status = (
            "cancelled"
            if isinstance(exc, Cancelled)
            else "timed_out"
            if isinstance(exc, JobTimeout)
            else "failed"
        )
        with engine.begin() as c:
            c.execute(
                jobs.update()
                .where(jobs.c.id == job["id"])
                .values(
                    status=status,
                    finished_at=now(),
                    error_code=type(exc).__name__,
                    summary="檢查未成功完成；不能推定安全或已修復。",
                )
            )
            if job["retest_id"]:
                c.execute(
                    retests.insert().values(
                        finding_id=job["retest_id"],
                        job_id=job["id"],
                        created_at=now(),
                        result="inconclusive",
                        detail=type(exc).__name__,
                    )
                )
    return True


def main():
    engine = engine_for()
    profile = os.environ.get("LAB_PROFILE", "docker")
    while True:
        if not process_one(engine, profile):
            time.sleep(1)


if __name__ == "__main__":
    main()

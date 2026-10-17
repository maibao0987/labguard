import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from sqlalchemy import select

from .db import assets, audit, findings, jobs, now, observations, scopes
from .security import redact

CHECKS = {
    "health": "服務健康",
    "headers": "安全標頭",
    "idor": "物件授權 IDOR",
    "sqli": "SQL 注入",
    "xss": "儲存型 XSS",
}
TRANSITIONS = {
    "new": {"confirmed", "false_positive", "accepted_risk"},
    "confirmed": {"in_progress", "false_positive", "accepted_risk"},
    "in_progress": {"ready_for_retest"},
    "ready_for_retest": {"in_progress"},
    "resolved": {"reopened"},
    "reopened": {"confirmed", "in_progress"},
    "false_positive": {"reopened"},
    "accepted_risk": {"reopened"},
}


class ScopeError(ValueError):
    pass


def registry(profile):
    if profile not in {"local", "docker"}:
        raise ScopeError("未知執行環境")
    data = yaml.safe_load((Path(__file__).resolve().parent.parent / "lab/assets.yaml").read_text("utf-8"))
    return data[profile]


def validate_scope(c, scope_id, asset_id, check_type):
    scope = c.execute(select(scopes).where(scopes.c.id == scope_id)).mappings().first()
    asset = c.execute(select(assets).where(assets.c.id == asset_id)).mappings().first()
    if not scope or not asset or not scope["enabled"] or not asset["enabled"]:
        raise ScopeError("授權範圍或資產已停用")
    stamp = datetime.now(UTC)
    try:
        if (
            not datetime.fromisoformat(scope["valid_from"])
            <= stamp
            < datetime.fromisoformat(scope["valid_until"])
        ):
            raise ScopeError("授權尚未開始或已過期")
        allowed = asset["key"] in json.loads(scope["allowed_assets"])
        checks = check_type in json.loads(scope["allowed_checks"]) and check_type in CHECKS
    except (TypeError, json.JSONDecodeError) as e:
        raise ScopeError("授權資料格式錯誤") from e
    if not allowed or not checks:
        raise ScopeError("資產或檢查類型未獲授權")
    if not 1 <= scope["rate"] <= 2 or scope["max_concurrency"] != 1:
        raise ScopeError("MVP 僅允許單一工作，每秒最多兩個請求")
    return dict(scope), dict(asset)


def enqueue(c, scope_id, asset_id, check_type, actor, retest_id=None):
    validate_scope(c, scope_id, asset_id, check_type)
    if retest_id:
        f = c.execute(select(findings).where(findings.c.id == retest_id)).mappings().first()
        if (
            not f
            or f["status"] != "ready_for_retest"
            or f["asset_id"] != asset_id
            or f["check_id"] != check_type
        ):
            raise ScopeError("複測須對應相同資產、檢查及待複測弱點")
        canonical = {
            "headers": ("GET", "/health", "headers"),
            "idor": ("GET", "/tasks/2", "task_id"),
            "sqli": ("GET", "/", "q"),
            "xss": ("POST", "/tasks/3", "body"),
        }
        if canonical.get(check_type) != (f["method"], f["location"], f["parameter"]):
            raise ScopeError("此匯入位置沒有對應的固定複測，不可自動關閉")
    result = c.execute(
        jobs.insert().values(
            scope_id=scope_id,
            asset_id=asset_id,
            check_type=check_type,
            requested_by=actor,
            status="queued",
            created_at=now(),
            cancel_requested=False,
            retest_id=retest_id,
        )
    )
    job_id = result.inserted_primary_key[0]
    audit(c, actor, "enqueue", f"job:{job_id}", check_type)
    return job_id


def enable_scope(c, scope_id, actor, reason):
    if len(reason.strip()) < 8:
        raise ScopeError("請以至少 8 字記錄本人授權聲明")
    end = (datetime.now(UTC) + timedelta(hours=24)).isoformat()
    c.execute(
        scopes.update().where(scopes.c.id == scope_id).values(enabled=True, valid_from=now(), valid_until=end)
    )
    audit(c, actor, "authorize_24h", f"scope:{scope_id}", reason)


def ingest(c, asset_id, item, job_id=None, source="import"):
    required = {"title", "check_id", "location", "parameter", "severity", "evidence"}
    if not isinstance(item, dict) or not required <= item.keys():
        raise ValueError("缺少必要弱點欄位")
    for k, v in item.items():
        if not isinstance(v, str) or len(v) > 12000:
            raise ValueError("欄位必須是有限長度文字")
    if item["check_id"] not in CHECKS or item["severity"] not in {"high", "medium", "low", "info"}:
        raise ValueError("未知檢查或嚴重度")
    if not item["location"].startswith("/") or len(item["location"]) > 200:
        raise ValueError("位置必須為本機服務內路徑")
    method = item.get("method", "GET").upper()
    if method not in {"GET", "POST"}:
        raise ValueError("不支援的方法")
    for name, limit in {"title": 200, "parameter": 80, "category": 80, "cwe_id": 20}.items():
        if len(item.get(name, "")) > limit:
            raise ValueError("欄位超過長度限制")
    fingerprint = hashlib.sha256(
        json.dumps(
            [asset_id, item["check_id"], method, item["location"], item["parameter"]], ensure_ascii=False
        ).encode()
    ).hexdigest()
    f = c.execute(select(findings).where(findings.c.fingerprint == fingerprint)).mappings().first()
    if f:
        fid = f["id"]
        values = {"last_seen": now()}
        if f["status"] == "resolved":
            values["status"] = "reopened"
            audit(c, "worker", "reopened", f"finding:{fid}", "相同弱點再次被觀測到")
        c.execute(findings.update().where(findings.c.id == fid).values(**values))
    else:
        values = {
            k: redact(item.get(k, ""))
            for k in [
                "title",
                "category",
                "cwe_id",
                "severity",
                "location",
                "parameter",
                "description",
                "impact",
                "reproduction",
                "remediation",
                "check_id",
            ]
        }
        fid = c.execute(
            findings.insert().values(
                **values,
                asset_id=asset_id,
                confidence="needs_review",
                method=method,
                status="new",
                fingerprint=fingerprint,
                first_seen=now(),
                last_seen=now(),
            )
        ).inserted_primary_key[0]
    c.execute(
        observations.insert().values(
            finding_id=fid, job_id=job_id, source=source, evidence=redact(item["evidence"]), created_at=now()
        )
    )
    return fid


def transition(c, fid, status, actor, reason):
    f = c.execute(select(findings).where(findings.c.id == fid)).mappings().first()
    if not f or status not in TRANSITIONS.get(f["status"], set()):
        raise ValueError("不允許的狀態轉換；resolved 只能由成功的複測建立")
    if len(reason.strip()) < 4:
        raise ValueError("請填寫至少 4 字的變更理由")
    values = {"status": status}
    if status == "confirmed":
        values["confidence"] = "human_confirmed"
    c.execute(findings.update().where(findings.c.id == fid).values(**values))
    audit(c, actor, "finding_status", f"finding:{fid}", f"{f['status']} → {status}: {reason}")

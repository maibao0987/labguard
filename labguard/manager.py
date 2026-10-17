import json

from flask import Response, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import select

from .db import assets, audit, audits, findings, jobs, now, observations, retests, scopes
from .domain import CHECKS, TRANSITIONS, ScopeError, enable_scope, enqueue, ingest, transition
from .security import admin_required, redact

LABELS = {
    "new": "新發現",
    "confirmed": "已確認",
    "in_progress": "修復中",
    "ready_for_retest": "待複測",
    "resolved": "已修復",
    "reopened": "重新開啟",
    "false_positive": "誤判",
    "accepted_risk": "接受風險",
    "queued": "排隊中",
    "running": "執行中",
    "succeeded": "已完成",
    "failed": "失敗",
    "cancelled": "已取消",
    "timed_out": "逾時",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "資訊",
}


def register(app):
    engine = app.config["ENGINE"]

    @app.context_processor
    def common():
        return {"labels": LABELS, "checks": CHECKS, "mode": "manager"}

    def rows(c, table):
        return c.execute(select(table).order_by(table.c.id.desc())).mappings().all()

    @app.get("/")
    @admin_required
    def index():
        with engine.connect() as c:
            fs = rows(c, findings)
            js = rows(c, jobs)
            ats = rows(c, assets)
            ss = rows(c, scopes)
        return render_template(
            "dashboard.html",
            findings=fs,
            jobs=js[:5],
            assets=ats,
            scopes=ss,
            open_count=sum(f["status"] not in {"resolved", "false_positive", "accepted_risk"} for f in fs),
            high_count=sum(f["severity"] == "high" and f["status"] != "resolved" for f in fs),
            resolved_count=sum(f["status"] == "resolved" for f in fs),
        )

    @app.route("/findings", methods=["GET"])
    @admin_required
    def finding_list():
        status, severity = request.args.get("status", ""), request.args.get("severity", "")
        stmt = select(findings).order_by(findings.c.id.desc())
        if status:
            stmt = stmt.where(findings.c.status == status)
        if severity:
            stmt = stmt.where(findings.c.severity == severity)
        with engine.connect() as c:
            fs = c.execute(stmt).mappings().all()
            ats = rows(c, assets)
        return render_template("findings.html", findings=fs, assets=ats, status=status, severity=severity)

    @app.get("/findings/<int:fid>")
    @admin_required
    def finding_detail(fid):
        with engine.connect() as c:
            f = c.execute(select(findings).where(findings.c.id == fid)).mappings().first()
            if not f:
                abort(404)
            obs = c.execute(select(observations).where(observations.c.finding_id == fid)).mappings().all()
            rts = c.execute(select(retests).where(retests.c.finding_id == fid)).mappings().all()
            history = c.execute(select(audits).where(audits.c.entity == f"finding:{fid}")).mappings().all()
            ss = rows(c, scopes)
        return render_template(
            "finding_detail.html",
            finding=f,
            observations=obs,
            retests=rts,
            history=history,
            next_states=sorted(TRANSITIONS.get(f["status"], set())),
            scopes=ss,
        )

    @app.post("/findings/<int:fid>/status")
    @admin_required
    def finding_status(fid):
        try:
            with engine.begin() as c:
                transition(
                    c, fid, request.form.get("status", ""), g.user["username"], request.form.get("reason", "")
                )
            flash("弱點狀態已更新", "success")
        except ValueError as e:
            flash(str(e), "error")
        return redirect(url_for("finding_detail", fid=fid))

    @app.post("/findings/<int:fid>/retest")
    @admin_required
    def finding_retest(fid):
        try:
            with engine.begin() as c:
                f = c.execute(select(findings).where(findings.c.id == fid)).mappings().one()
                enqueue(
                    c, int(request.form["scope_id"]), f["asset_id"], f["check_id"], g.user["username"], fid
                )
            flash("已加入相同資產的複測工作", "success")
        except (ValueError, KeyError) as e:
            flash(str(e), "error")
        return redirect(url_for("finding_detail", fid=fid))

    @app.post("/import")
    @admin_required
    def import_results():
        try:
            payload = json.loads(request.form.get("payload", ""))
            if not isinstance(payload, dict) or set(payload) != {"asset_id", "findings"}:
                raise ValueError("JSON 需包含 asset_id 與 findings")
            if (
                not isinstance(payload["asset_id"], int)
                or not isinstance(payload["findings"], list)
                or not 1 <= len(payload["findings"]) <= 50
            ):
                raise ValueError("每次匯入 1～50 筆弱點")
            with engine.begin() as c:
                # Serializes fingerprint creation across concurrent imports/worker results.
                c.execute(select(scopes).with_for_update()).all()
                if not c.execute(select(assets).where(assets.c.id == payload["asset_id"])).first():
                    raise ValueError("未知資產")
                for item in payload["findings"]:
                    ingest(c, payload["asset_id"], item)
                audit(c, g.user["username"], "import", f"asset:{payload['asset_id']}", "外部結果需人工確認")
            flash("匯入成功，已保留觀測與去重紀錄", "success")
        except (ValueError, TypeError, KeyError) as e:
            flash(str(e), "error")
        return redirect(url_for("finding_list"))

    @app.route("/jobs", methods=["GET", "POST"])
    @admin_required
    def job_list():
        if request.method == "POST":
            try:
                if set(request.form) - {"csrf", "asset_id", "scope_id", "check_type"}:
                    raise ValueError("不接受額外目標或指令參數")
                with engine.begin() as c:
                    enqueue(
                        c,
                        int(request.form["scope_id"]),
                        int(request.form["asset_id"]),
                        request.form["check_type"],
                        g.user["username"],
                    )
                flash("工作已排入佇列", "success")
            except (ValueError, KeyError) as e:
                flash(str(e), "error")
            return redirect(url_for("job_list"))
        with engine.connect() as c:
            js, ats, ss = rows(c, jobs), rows(c, assets), rows(c, scopes)
        return render_template("jobs.html", jobs=js, assets=ats, scopes=ss)

    @app.post("/jobs/<int:jid>/cancel")
    @admin_required
    def cancel_job(jid):
        with engine.begin() as c:
            j = c.execute(select(jobs).where(jobs.c.id == jid).with_for_update()).mappings().first()
            if j and j["status"] in {"queued", "running"}:
                values = {"cancel_requested": True}
                if j["status"] == "queued":
                    values.update(status="cancelled", finished_at=now())
                c.execute(jobs.update().where(jobs.c.id == jid).values(**values))
                audit(c, g.user["username"], "cancel", f"job:{jid}")
        return redirect(url_for("job_list"))

    @app.route("/assets", methods=["GET"])
    @admin_required
    def asset_list():
        with engine.connect() as c:
            ats, ss = rows(c, assets), rows(c, scopes)
        return render_template("assets.html", assets=ats, scopes=ss)

    @app.post("/assets/<int:aid>/toggle")
    @admin_required
    def asset_toggle(aid):
        with engine.begin() as c:
            c.execute(select(scopes).with_for_update()).all()
            a = c.execute(select(assets).where(assets.c.id == aid)).mappings().first()
            if not a:
                abort(404)
            c.execute(assets.update().where(assets.c.id == aid).values(enabled=not a["enabled"]))
            audit(c, g.user["username"], "asset_toggle", f"asset:{aid}", str(not a["enabled"]))
        return redirect(url_for("asset_list"))

    @app.post("/scopes/<int:sid>")
    @admin_required
    def scope_update(sid):
        try:
            with engine.begin() as c:
                if not c.execute(select(scopes).where(scopes.c.id == sid).with_for_update()).first():
                    abort(404)
                if request.form.get("action") == "enable":
                    enable_scope(c, sid, g.user["username"], request.form.get("reason", ""))
                else:
                    c.execute(scopes.update().where(scopes.c.id == sid).values(enabled=False))
                    audit(c, g.user["username"], "revoke", f"scope:{sid}", "立即停止後續檢查")
            flash("授權範圍已更新", "success")
        except ScopeError as e:
            flash(str(e), "error")
        return redirect(url_for("asset_list"))

    def report_data(c):
        return {
            "project": "LabGuard",
            "generated_at": now(),
            "version": "0.1.0",
            "scope": [dict(r) for r in rows(c, scopes)],
            "limitations": "僅本機固定案例；XSS 自動檢查僅驗證 HTML 注入。失敗或未執行不代表安全。",
            "assets": [dict(r) for r in rows(c, assets)],
            "findings": [dict(r) for r in rows(c, findings)],
            "observations": [dict(r) for r in rows(c, observations)],
            "retests": [dict(r) for r in rows(c, retests)],
            "jobs": [dict(r) for r in rows(c, jobs)],
            "history": [dict(r) for r in rows(c, audits)],
        }

    @app.get("/reports")
    @admin_required
    def report_page():
        with engine.connect() as c:
            data = report_data(c)
        return render_template("reports.html", data=data)

    @app.get("/reports/export/<fmt>")
    @admin_required
    def report_export(fmt):
        if fmt not in {"json", "md"}:
            abort(404)
        with engine.begin() as c:
            data = report_data(c)
            audit(c, g.user["username"], "export", "report", fmt)

        # Redaction is applied at ingestion and again per exported string.
        def clean(value):
            if isinstance(value, str):
                return redact(value)
            if isinstance(value, list):
                return [clean(v) for v in value]
            if isinstance(value, dict):
                return {k: clean(v) for k, v in value.items()}
            return value

        data = clean(data)
        if fmt == "json":
            body = json.dumps(data, ensure_ascii=False, indent=2)
        else:
            # Plain-text fenced JSON keeps untrusted HTML/Markdown inert in rendered reports.
            safe = (
                json.dumps(data, ensure_ascii=False, indent=2)
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("`", "\\u0060")
            )
            body = (
                "# LabGuard 本機攻防報告\n\n## 執行摘要\n\n共 "
                + str(len(data["findings"]))
                + " 筆弱點紀錄。\n\n"
            )
            body += (
                "## 方法與限制\n\n"
                + data["limitations"]
                + "\n\n## 授權、弱點、證據與複測完整紀錄\n\n```json\n"
                + safe
                + "\n```\n"
            )
        return Response(
            body,
            mimetype="application/json" if fmt == "json" else "text/plain",
            headers={"Content-Disposition": f'attachment; filename="labguard-report.{fmt}"'},
        )

    @app.get("/audit")
    @admin_required
    def audit_page():
        with engine.connect() as c:
            history = rows(c, audits)
        return render_template("audit.html", history=history)

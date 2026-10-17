import json

import pytest
from conftest import csrf, signin
from sqlalchemy import select

from labguard.db import assets, audit, findings, observations, scopes
from labguard.domain import ScopeError, enable_scope, enqueue, ingest, transition
from labguard.security import redact


def sample(**kw):
    return dict(
        {
            "title": "測試 IDOR",
            "check_id": "idor",
            "location": "/tasks/2",
            "parameter": "task_id",
            "severity": "high",
            "evidence": "BOB-PRIVATE-SEED",
        },
        **kw,
    )


def test_manager_requires_login(make_app):
    client = make_app().test_client()
    for path in ["/", "/assets", "/jobs", "/findings", "/reports", "/audit", "/reports/export/json"]:
        assert client.get(path).status_code == 302
    assert client.get("/api/session").status_code == 401


def test_csrf_and_cookie(make_app):
    client = make_app().test_client()
    r = client.get("/login")
    assert "HttpOnly" in r.headers["Set-Cookie"] and "SameSite=Lax" in r.headers["Set-Cookie"]
    assert (
        client.post("/login", data={"username": "admin", "password": "Manager-Test-12345"}).status_code == 400
    )
    assert signin(client).status_code == 302
    assert (
        client.post("/jobs", data={"asset_id": 1, "check_type": "health", "scope_id": 1}).status_code == 400
    )


def test_invalid_login_and_unknown_host(make_app):
    client = make_app().test_client()
    assert signin(client, password="wrong").status_code == 200
    assert client.get("/health", headers={"Host": "attacker.example"}).status_code == 400


def test_scope_deny_and_allow(make_app):
    engine = make_app().config["ENGINE"]
    with engine.begin() as c:
        with pytest.raises(ScopeError):
            enqueue(c, 1, 1, "health", "admin")
        enable_scope(c, 1, "admin", "我擁有此本機實驗室並授權")
        assert enqueue(c, 1, 1, "health", "admin")
        for asset, check in [(999, "health"), (1, "shell"), (1, "http://example.com")]:
            with pytest.raises(ScopeError):
                enqueue(c, 1, asset, check, "admin")
        c.execute(scopes.update().values(valid_until="2000-01-01T00:00:00+00:00"))
        with pytest.raises(ScopeError):
            enqueue(c, 1, 1, "health", "admin")


def test_disabled_asset(make_app):
    engine = make_app().config["ENGINE"]
    with engine.begin() as c:
        enable_scope(c, 1, "admin", "我擁有此本機實驗室並授權")
        c.execute(assets.update().where(assets.c.id == 1).values(enabled=False))
        with pytest.raises(ScopeError):
            enqueue(c, 1, 1, "health", "admin")


def test_dedup_history_and_reopen(make_app):
    engine = make_app().config["ENGINE"]
    with engine.begin() as c:
        fid = ingest(c, 1, sample())
        assert ingest(c, 1, sample()) == fid
        assert ingest(c, 2, sample()) != fid
        assert len(c.execute(select(observations)).all()) == 3
        c.execute(findings.update().where(findings.c.id == fid).values(status="resolved"))
        ingest(c, 1, sample())
        assert c.execute(select(findings.c.status).where(findings.c.id == fid)).scalar_one() == "reopened"


def test_transitions_reason_and_no_manual_resolve(make_app):
    engine = make_app().config["ENGINE"]
    with engine.begin() as c:
        fid = ingest(c, 1, sample())
        with pytest.raises(ValueError):
            transition(c, fid, "resolved", "admin", "直接關閉測試")
        with pytest.raises(ValueError):
            transition(c, fid, "confirmed", "admin", "")
        for state in ["confirmed", "in_progress", "ready_for_retest"]:
            transition(c, fid, state, "admin", "人工確認種子資料")
        enable_scope(c, 1, "admin", "我擁有此本機實驗室並授權")
        assert enqueue(c, 1, 1, "idor", "admin", fid)
        with pytest.raises(ScopeError):
            enqueue(c, 1, 2, "idor", "admin", fid)


def test_unknown_import_location_cannot_auto_resolve(make_app):
    engine = make_app().config["ENGINE"]
    with engine.begin() as c:
        fid = ingest(c, 1, sample(location="/tasks/999"))
        c.execute(findings.update().where(findings.c.id == fid).values(status="ready_for_retest"))
        enable_scope(c, 1, "admin", "我擁有此本機實驗室並授權")
        with pytest.raises(ScopeError):
            enqueue(c, 1, 1, "idor", "admin", fid)


def test_untrusted_evidence_escaped_and_exported(make_app):
    app = make_app()
    with app.config["ENGINE"].begin() as c:
        fid = ingest(
            c,
            1,
            sample(evidence="<script>alert(1)</script> token=secret", title="<img src=x onerror=alert(1)>"),
        )
        audit(c, "admin", "note", f"finding:{fid}", "password=private")
    client = app.test_client()
    signin(client)
    r = client.get(f"/findings/{fid}")
    assert b"<script>alert(1)</script>" not in r.data
    assert b"&lt;script&gt;" in r.data
    report = client.get("/reports/export/json").json
    assert "secret" not in json.dumps(report) and "private" not in json.dumps(report)
    md = client.get("/reports/export/md")
    assert b"<script>" not in md.data and b"private" not in md.data
    assert "attachment" in md.headers["Content-Disposition"]


def test_import_rejects_bad_payload_and_rolls_back(make_app):
    app = make_app()
    client = app.test_client()
    signin(client)
    token = csrf(client, "/findings")
    response = client.post(
        "/import",
        data={
            "csrf": token,
            "payload": json.dumps({"asset_id": 1, "findings": [sample(), {"title": "invalid"}]}),
        },
    )
    assert response.status_code == 302
    with app.config["ENGINE"].connect() as c:
        assert not c.execute(select(findings)).first()
    assert client.post("/import", data={"csrf": token, "payload": "x" * 140000}).status_code == 413


def test_arbitrary_url_parameter_rejected(make_app):
    app = make_app()
    client = app.test_client()
    signin(client)
    r = client.post(
        "/jobs",
        data={
            "csrf": csrf(client, "/jobs"),
            "asset_id": 1,
            "scope_id": 1,
            "check_type": "health",
            "url": "http://example.com",
        },
        follow_redirects=True,
    )
    assert "不接受額外" in r.text


def test_redact():
    assert "abc" not in redact("Cookie=abc token=abc password=abc")


def test_distinct_service_sessions_do_not_clobber(make_app):
    manager, target = make_app(), make_app("vulnerable")
    mc, tc = manager.test_client(), target.test_client()
    signin(mc)
    signin(tc, "alice", "LabOnly-12345")
    name = target.config["SESSION_COOKIE_NAME"]
    mc.set_cookie(name, tc.get_cookie(name).value)
    assert "實驗室總覽" in mc.get("/").text
    assert manager.config["SESSION_COOKIE_NAME"] != name

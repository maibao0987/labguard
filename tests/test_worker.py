import socket
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from labguard.db import findings, jobs, retests, scopes
from labguard.domain import ScopeError, enable_scope, enqueue
from labguard.worker import LabHTTP, process_one


def flask_factory(app):
    class FlaskHTTP:
        def __init__(self, target, guard, rate):
            self.client, self.guard = app.test_client(), guard

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def request(self, method, path, **kwargs):
            self.guard()
            r = self.client.open(
                path, method=method, data=kwargs.get("data"), query_string=kwargs.get("params")
            )
            return httpx.Response(
                r.status_code,
                headers=dict(r.headers),
                content=r.data,
                request=httpx.Request(method, "http://127.0.0.1" + path),
            )

    return FlaskHTTP


@pytest.mark.parametrize("mode", ["vulnerable", "fixed"])
@pytest.mark.parametrize("check", ["health", "headers", "idor", "sqli", "xss"])
def test_all_checks_against_real_app_logic(make_app, mode, check):
    engine = make_app().config["ENGINE"]
    target = make_app(mode)
    with engine.begin() as c:
        enable_scope(c, 1, "admin", "我擁有此本機實驗室並授權")
        enqueue(c, 1, 1, check, "admin")
    assert process_one(engine, "local", flask_factory(target))
    with engine.connect() as c:
        job = c.execute(select(jobs)).mappings().one()
        assert job["status"] == "succeeded", job
        fs = c.execute(select(findings)).all()
        assert bool(fs) == (mode == "vulnerable" and check != "health")


def test_same_asset_repair_retest_and_reopen(make_app):
    engine = make_app().config["ENGINE"]
    vulnerable, fixed = make_app("vulnerable"), make_app("fixed")
    with engine.begin() as c:
        enable_scope(c, 1, "admin", "我擁有此本機實驗室並授權")
        enqueue(c, 1, 1, "idor", "admin")
    process_one(engine, "local", flask_factory(vulnerable))
    with engine.begin() as c:
        f = c.execute(select(findings)).mappings().one()
        c.execute(findings.update().values(status="ready_for_retest"))
        enqueue(c, 1, 1, "idor", "admin", f["id"])
    # Same asset identity now serves repaired implementation.
    process_one(engine, "local", flask_factory(fixed))
    with engine.begin() as c:
        assert c.execute(select(findings.c.status)).scalar_one() == "resolved"
        assert c.execute(select(retests.c.result)).scalar_one() == "passed"
        enqueue(c, 1, 1, "idor", "admin")
    process_one(engine, "local", flask_factory(vulnerable))
    with engine.connect() as c:
        assert c.execute(select(findings.c.status)).scalar_one() == "reopened"


def test_revoke_after_enqueue_prevents_request(make_app):
    engine = make_app().config["ENGINE"]
    with engine.begin() as c:
        enable_scope(c, 1, "admin", "我擁有此本機實驗室並授權")
        enqueue(c, 1, 1, "health", "admin")
        c.execute(scopes.update().values(enabled=False))

    def never(*args):
        raise AssertionError("Must not make network request")

    process_one(engine, "local", never)
    with engine.connect() as c:
        assert c.execute(select(jobs.c.error_code)).scalar_one() == "ScopeError"


def test_retest_network_failure_not_resolved(make_app):
    engine = make_app().config["ENGINE"]
    from test_security import sample

    from labguard.domain import ingest

    with engine.begin() as c:
        enable_scope(c, 1, "admin", "我擁有此本機實驗室並授權")
        fid = ingest(c, 1, sample())
        c.execute(findings.update().values(status="ready_for_retest"))
        enqueue(c, 1, 1, "idor", "admin", fid)

    def broken(*args):
        raise httpx.ConnectError("Fake network error")

    process_one(engine, "local", broken)
    with engine.connect() as c:
        assert c.execute(select(findings.c.status)).scalar_one() == "ready_for_retest"
        assert c.execute(select(retests.c.result)).scalar_one() == "inconclusive"
        assert c.execute(select(jobs.c.status)).scalar_one() == "failed"


def test_stale_and_cancelled_jobs(make_app):
    engine = make_app().config["ENGINE"]
    old = (datetime.now(UTC) - timedelta(minutes=3)).isoformat()
    with engine.begin() as c:
        enable_scope(c, 1, "admin", "我擁有此本機實驗室並授權")
        jid = enqueue(c, 1, 1, "health", "admin")
        c.execute(jobs.update().where(jobs.c.id == jid).values(status="running", heartbeat_at=old))
    assert not process_one(engine, "local")
    with engine.begin() as c:
        assert c.execute(select(jobs.c.status)).scalar_one() == "timed_out"
        jid = enqueue(c, 1, 1, "health", "admin")
        c.execute(jobs.update().where(jobs.c.id == jid).values(cancel_requested=True))
    process_one(engine, "local")
    with engine.connect() as c:
        assert c.execute(select(jobs.c.status).where(jobs.c.id == jid)).scalar_one() == "cancelled"


def test_http_refuses_dns_mismatch_before_connect(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [(2, 1, 6, "", ("203.0.113.9", 5000))])
    with LabHTTP({"host": "vulnerable-web", "ip": "172.30.77.10", "port": 5000}, lambda: None) as c:
        with pytest.raises(ScopeError):
            c.request("GET", "/health")


@pytest.mark.parametrize("kind", ["redirect", "oversize"])
def test_redirect_and_response_limit(monkeypatch, kind):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [(2, 1, 6, "", ("127.0.0.1", 5101))])

    def handler(request):
        if kind == "redirect":
            return httpx.Response(302, headers={"Location": "http://example.com"})
        return httpx.Response(200, content=b"x" * 70000)

    with LabHTTP({"host": "127.0.0.1", "ip": "127.0.0.1", "port": 5101}, lambda: None) as c:
        c.client.close()
        c.client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises((ScopeError, ValueError)):
            c.request("GET", "/health")

import os
from datetime import UTC, datetime

from sqlalchemy import Boolean, Column, ForeignKey, Integer, MetaData, String, Table, Text, create_engine
from werkzeug.security import generate_password_hash

manager_meta = MetaData()
task_meta = MetaData()


def now():
    return datetime.now(UTC).isoformat()


def table(name, *columns, meta=manager_meta):
    return Table(name, meta, Column("id", Integer, primary_key=True), *columns)


users = table(
    "users",
    Column("username", String(64), unique=True, nullable=False),
    Column("password", Text, nullable=False),
    Column("role", String(20), nullable=False),
)
assets = table(
    "assets",
    Column("key", String(64), unique=True, nullable=False),
    Column("enabled", Boolean, nullable=False, default=True),
)
scopes = table(
    "scopes",
    Column("name", String(120)),
    Column("owner", String(80)),
    Column("authorization_reference", String(200)),
    Column("valid_from", String(40)),
    Column("valid_until", String(40)),
    Column("allowed_assets", Text),
    Column("allowed_checks", Text),
    Column("max_concurrency", Integer),
    Column("rate", Integer),
    Column("enabled", Boolean, default=False),
)
jobs = table(
    "jobs",
    Column("scope_id", ForeignKey("scopes.id")),
    Column("asset_id", ForeignKey("assets.id")),
    Column("check_type", String(30)),
    Column("status", String(30)),
    Column("requested_by", String(64)),
    Column("created_at", String(40)),
    Column("started_at", String(40)),
    Column("finished_at", String(40)),
    Column("heartbeat_at", String(40)),
    Column("deadline_at", String(40)),
    Column("error_code", String(60)),
    Column("summary", Text),
    Column("cancel_requested", Boolean, default=False),
    Column("retest_id", Integer),
)
findings = table(
    "findings",
    Column("asset_id", ForeignKey("assets.id")),
    Column("title", String(200)),
    Column("category", String(80)),
    Column("cwe_id", String(20)),
    Column("severity", String(20)),
    Column("confidence", String(20)),
    Column("status", String(30)),
    Column("location", String(200)),
    Column("parameter", String(80)),
    Column("description", Text),
    Column("impact", Text),
    Column("reproduction", Text),
    Column("remediation", Text),
    Column("check_id", String(30)),
    Column("method", String(10)),
    Column("fingerprint", String(64), unique=True),
    Column("first_seen", String(40)),
    Column("last_seen", String(40)),
)
observations = table(
    "observations",
    Column("finding_id", ForeignKey("findings.id")),
    Column("job_id", ForeignKey("jobs.id")),
    Column("created_at", String(40)),
    Column("source", String(30)),
    Column("evidence", Text),
)
retests = table(
    "retests",
    Column("finding_id", ForeignKey("findings.id")),
    Column("job_id", ForeignKey("jobs.id")),
    Column("created_at", String(40)),
    Column("result", String(30)),
    Column("detail", Text),
)
audits = table(
    "audits",
    Column("actor", String(64)),
    Column("action", String(60)),
    Column("entity", String(100)),
    Column("reason", Text),
    Column("created_at", String(40)),
)

members = table(
    "members",
    Column("username", String(64), unique=True),
    Column("password", Text),
    Column("role", String(20)),
    Column("display_name", String(100)),
    meta=task_meta,
)
tasks = table(
    "tasks",
    Column("owner_id", ForeignKey("members.id")),
    Column("title", String(200)),
    Column("body", Text),
    Column("visibility", String(20)),
    meta=task_meta,
)
comments = table(
    "comments",
    Column("task_id", ForeignKey("tasks.id")),
    Column("author_id", ForeignKey("members.id")),
    Column("body", Text),
    meta=task_meta,
)


def engine_for(url=None):
    url = url or os.environ["DATABASE_URL"]
    return create_engine(
        url, pool_pre_ping=True, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {}
    )


def audit(conn, actor, action, entity, reason=""):
    conn.execute(
        audits.insert().values(
            actor=actor, action=action, entity=entity, reason=reason[:2000], created_at=now()
        )
    )


def seed(engine, service):
    import json

    from sqlalchemy import select

    with engine.begin() as c:
        if service == "manager":
            if c.execute(select(users.c.id).limit(1)).first():
                return
            password = os.environ.get("MANAGER_PASSWORD")
            if not password or len(password) < 12:
                raise RuntimeError("MANAGER_PASSWORD must contain at least 12 characters")
            c.execute(
                users.insert().values(
                    username="admin", password=generate_password_hash(password), role="admin"
                )
            )
            c.execute(
                assets.insert(),
                [{"key": k, "enabled": True} for k in ["taskboard-vulnerable", "taskboard-fixed"]],
            )
            c.execute(
                scopes.insert().values(
                    name="本人本機 TaskBoard 實驗室",
                    owner="本機操作者",
                    authorization_reference="docs/authorization.md",
                    valid_from=now(),
                    valid_until=now(),
                    allowed_assets=json.dumps(["taskboard-vulnerable", "taskboard-fixed"]),
                    allowed_checks=json.dumps(["health", "headers", "idor", "sqli", "xss"]),
                    max_concurrency=1,
                    rate=2,
                    enabled=False,
                )
            )
        else:
            if c.execute(select(members.c.id).limit(1)).first():
                return
            for name, role in [("admin", "admin"), ("alice", "member"), ("bob", "member")]:
                c.execute(
                    members.insert().values(
                        username=name,
                        password=generate_password_hash("LabOnly-12345"),
                        role=role,
                        display_name=name.title(),
                    )
                )
            c.execute(
                tasks.insert(),
                [
                    {
                        "id": 1,
                        "owner_id": 2,
                        "title": "Alice 的私人筆記",
                        "body": "ALICE-PRIVATE-SEED",
                        "visibility": "private",
                    },
                    {
                        "id": 2,
                        "owner_id": 3,
                        "title": "Bob 的私人筆記",
                        "body": "BOB-PRIVATE-SEED",
                        "visibility": "private",
                    },
                    {
                        "id": 3,
                        "owner_id": 2,
                        "title": "團隊例會",
                        "body": "週五分享修復成果",
                        "visibility": "team",
                    },
                ],
            )

import pytest
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from labguard.cli import migrate
from labguard.db import engine_for, manager_meta, task_meta


@pytest.mark.parametrize("service", ["manager", "vulnerable", "fixed"])
def test_alembic_baseline_and_idempotent_seed(tmp_path, monkeypatch, service):
    url = "sqlite:///" + (tmp_path / f"{service}.db").as_posix()
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("MANAGER_PASSWORD", "Migration-Test-12345")
    monkeypatch.setenv("SERVICE", service)
    migrate(service)
    migrate(service)
    engine = engine_for(url)
    try:
        inspector = inspect(engine)
        meta = manager_meta if service == "manager" else task_meta
        assert set(inspector.get_table_names()) == set(meta.tables) | {"alembic_version"}
        for table in meta.sorted_tables:
            assert {c["name"] for c in inspector.get_columns(table.name)} == set(table.c.keys())
            # SQL compilation only; does not replace PostgreSQL runtime testing.
            assert str(CreateTable(table).compile(dialect=postgresql.dialect()))
    finally:
        engine.dispose()

import os

from alembic import context

from labguard.db import engine_for, manager_meta, task_meta

target_metadata = manager_meta if os.environ.get("SERVICE", "manager") == "manager" else task_meta
with engine_for().connect() as connection:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()

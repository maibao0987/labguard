import re

import pytest

from labguard.app import create_app
from labguard.db import manager_meta, seed, task_meta


def csrf(client, path="/login"):
    response = client.get(path)
    match = re.search(rb'name="csrf" value="([a-f0-9]+)"', response.data)
    if match:
        return match.group(1).decode()
    with client.session_transaction() as session:
        return session["csrf"]


def signin(client, username="admin", password="Manager-Test-12345"):
    return client.post("/login", data={"csrf": csrf(client), "username": username, "password": password})


@pytest.fixture
def make_app(tmp_path, monkeypatch):
    monkeypatch.setenv("MANAGER_PASSWORD", "Manager-Test-12345")
    counter = 0
    apps = []

    def make(service="manager"):
        nonlocal counter
        counter += 1
        app = create_app(service, "sqlite:///" + (tmp_path / f"test-{counter}.db").as_posix(), "t" * 64)
        app.config["TESTING"] = True
        meta = manager_meta if service == "manager" else task_meta
        meta.create_all(app.config["ENGINE"])
        seed(app.config["ENGINE"], service)
        apps.append(app)
        return app

    yield make
    for app in apps:
        app.config["ENGINE"].dispose()

import pytest
from conftest import csrf, signin


@pytest.mark.parametrize("mode", ["vulnerable", "fixed"])
def test_normal_tasks_profile_and_comments(make_app, mode):
    client = make_app(mode).test_client()
    signin(client, "alice", "LabOnly-12345")
    assert client.get("/tasks/1").status_code == 200
    assert client.get("/tasks/3").status_code == 200
    assert (
        client.post("/tasks/3", data={"csrf": csrf(client, "/tasks/3"), "body": "正常留言"}).status_code
        == 302
    )
    assert "正常留言" in client.get("/tasks/3").text
    assert (
        client.post(
            "/profile", data={"csrf": csrf(client, "/profile"), "display_name": "測試成員"}
        ).status_code
        == 302
    )
    assert "測試成員" in client.get("/profile").text


@pytest.mark.parametrize(
    "user,task,expected",
    [
        ("alice", 1, 200),
        ("alice", 2, 403),
        ("bob", 1, 403),
        ("bob", 2, 200),
        ("admin", 1, 200),
        ("admin", 2, 200),
        ("alice", 3, 200),
    ],
)
def test_fixed_permission_matrix(make_app, user, task, expected):
    client = make_app("fixed").test_client()
    signin(client, user, "LabOnly-12345")
    assert client.get(f"/tasks/{task}").status_code == expected


@pytest.mark.parametrize("mode,leaks", [("vulnerable", True), ("fixed", False)])
def test_sqli(make_app, mode, leaks):
    client = make_app(mode).test_client()
    signin(client, "alice", "LabOnly-12345")
    r = client.get("/", query_string={"q": "' OR 1=1 -- "})
    assert r.status_code == 200
    assert ('data-task-id="2"' in r.text) == leaks
    assert 'data-task-id="2"' not in client.get("/", query_string={"q": "NO-MATCH"}).text


@pytest.mark.parametrize("mode,raw", [("vulnerable", True), ("fixed", False)])
def test_stored_xss_encoding(make_app, mode, raw):
    client = make_app(mode).test_client()
    signin(client, "alice", "LabOnly-12345")
    marker = '<script>document.body.dataset.labguard="verified"</script>'
    client.post("/tasks/3", data={"csrf": csrf(client, "/tasks/3"), "body": marker})
    r = client.get("/tasks/3")
    assert (marker in r.text) == raw
    assert ("Content-Security-Policy" in r.headers) != raw

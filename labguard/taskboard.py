from flask import abort, g, redirect, render_template, request, url_for
from sqlalchemy import or_, select, text

from .db import comments, members, tasks
from .security import login_required


def permitted(task):
    return task["visibility"] == "team" or task["owner_id"] == g.user["id"] or g.user["role"] == "admin"


def register(app):
    engine = app.config["ENGINE"]
    vulnerable = app.config["LAB_MODE"] == "vulnerable"

    @app.get("/")
    @login_required
    def index():
        q = request.args.get("q", "")[:100]
        with engine.connect() as c:
            if vulnerable and q:
                # INTENTIONAL CWE-89: isolated teaching mode only. Never reuse in manager.
                statement = text(
                    "SELECT * FROM tasks WHERE (visibility='team' OR owner_id=:uid "
                    "OR :admin=1) AND title LIKE '%" + q + "%'"
                )
                try:
                    rows = (
                        c.execute(statement, {"uid": g.user["id"], "admin": int(g.user["role"] == "admin")})
                        .mappings()
                        .all()
                    )
                except Exception:
                    c.rollback()
                    abort(400, "教學查詢格式錯誤；請只在本機實驗室測試")
            else:
                query = select(tasks)
                if g.user["role"] != "admin":
                    query = query.where(or_(tasks.c.visibility == "team", tasks.c.owner_id == g.user["id"]))
                if q:
                    query = query.where(tasks.c.title.contains(q, autoescape=True))
                rows = c.execute(query).mappings().all()
        return render_template("taskboard.html", tasks=rows, q=q, mode=app.config["LAB_MODE"])

    @app.route("/tasks/<int:task_id>", methods=["GET", "POST"])
    @login_required
    def task_detail(task_id):
        with engine.begin() as c:
            task = c.execute(select(tasks).where(tasks.c.id == task_id)).mappings().first()
            if not task:
                abort(404)
            # INTENTIONAL CWE-639: teaching mode bypasses object authorization.
            if not vulnerable and not permitted(task):
                abort(403)
            if request.method == "POST":
                body = request.form.get("body", "").strip()
                if not body or len(body) > 2000:
                    abort(400, "留言需為 1～2000 字")
                c.execute(comments.insert().values(task_id=task_id, author_id=g.user["id"], body=body))
                return redirect(url_for("task_detail", task_id=task_id))
            rows = (
                c.execute(select(comments).where(comments.c.task_id == task_id).order_by(comments.c.id))
                .mappings()
                .all()
            )
        return render_template("task_detail.html", task=task, comments=rows, mode=app.config["LAB_MODE"])

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        if request.method == "POST":
            name = request.form.get("display_name", "").strip()
            if not name or len(name) > 80:
                abort(400)
            with engine.begin() as c:
                c.execute(members.update().where(members.c.id == g.user["id"]).values(display_name=name))
            return redirect(url_for("profile"))
        return render_template("profile.html", mode=app.config["LAB_MODE"])

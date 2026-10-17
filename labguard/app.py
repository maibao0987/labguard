import os
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy import select
from werkzeug.security import check_password_hash

from .db import engine_for, members, users
from .security import setup_security

ROOT = Path(__file__).resolve().parent.parent


def create_app(service="manager", url=None, secret=None):
    if service not in {"manager", "vulnerable", "fixed"}:
        raise ValueError("Unknown service")
    app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))
    secret = secret or os.environ.get("SECRET_KEY")
    if not secret or len(secret) < 32:
        raise RuntimeError("SECRET_KEY must contain at least 32 characters")
    app.config.update(
        SECRET_KEY=secret,
        ENGINE=engine_for(url),
        LAB_MODE=service,
        SESSION_COOKIE_NAME=os.environ.get("COOKIE_NAME", f"labguard_{service}"),
        MAX_CONTENT_LENGTH=128 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
        PERMANENT_SESSION_LIFETIME=3600,
        TRUSTED_HOSTS=[
            "localhost",
            "127.0.0.1",
            "manager",
            "vulnerable-web",
            "fixed-web",
            "172.30.77.10",
            "172.30.77.11",
        ],
    )
    user_table = users if service == "manager" else members
    setup_security(app, user_table)

    @app.context_processor
    def service_context():
        return {"mode": service}

    @app.get("/health")
    def health():
        with app.config["ENGINE"].connect() as c:
            c.execute(select(user_table.c.id).limit(1))
        return {"status": "ok", "service": service, "profile": os.environ.get("LAB_PROFILE", "docker")}

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            with app.config["ENGINE"].connect() as c:
                user = (
                    c.execute(
                        select(user_table).where(user_table.c.username == request.form.get("username", ""))
                    )
                    .mappings()
                    .first()
                )
            if user and check_password_hash(user["password"], request.form.get("password", "")):
                session.clear()
                session["uid"] = user["id"]
                session.permanent = True
                return redirect(url_for("index"))
            flash("帳號或密碼不正確", "error")
        return render_template("login.html", service=service)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def error(e):
        if request.routing_exception is not None and e.code == 400:
            return "Request rejected", 400
        return render_template("error.html", message=e.description, code=e.code), e.code

    @app.get("/api/session")
    def api_session():
        if not g.user:
            abort(401)
        return {"username": g.user["username"], "csrf": session["csrf"]}

    if service == "manager":
        from .manager import register
    else:
        from .taskboard import register
    register(app)
    return app

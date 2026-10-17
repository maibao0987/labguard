import functools
import hmac
import secrets

from flask import abort, g, redirect, request, session, url_for
from sqlalchemy import select


def setup_security(app, user_table):
    @app.before_request
    def protect():
        g.user = None
        if session.get("uid"):
            with app.config["ENGINE"].connect() as c:
                row = (
                    c.execute(select(user_table).where(user_table.c.id == session["uid"])).mappings().first()
                )
                g.user = dict(row) if row else None
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(32)
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            sent = request.form.get("csrf", "") or request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(session["csrf"], sent):
                abort(400, "CSRF 驗證失敗")

    @app.context_processor
    def context():
        return {"csrf": session.get("csrf", ""), "current_user": g.user}

    @app.after_request
    def headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        if app.config.get("LAB_MODE") != "vulnerable":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
            )
        return response


def login_required(fn):
    @functools.wraps(fn)
    def wrapped(*a, **kw):
        if not g.user:
            return redirect(url_for("login"))
        return fn(*a, **kw)

    return wrapped


def admin_required(fn):
    @functools.wraps(fn)
    @login_required
    def wrapped(*a, **kw):
        if g.user["role"] != "admin":
            abort(403)
        return fn(*a, **kw)

    return wrapped


def redact(value):
    import re

    value = str(value)
    return re.sub(
        r"(?i)(password|token|session|cookie|authorization)(\s*[=:]\s*)[^\s,;]+", r"\1\2[REDACTED]", value
    )[:12000]

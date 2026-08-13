"""Authentication Blueprint — /login, /admin/login, /register, /logout.

Handles:
  - User registration & login (regular users)
  - Admin-only login page (different route for branding)
  - Session creation with 8h TTL
  - Device-id cookie for "own logs" filtering
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict

from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
    make_response,
)

from firebase.user_service import (
    authenticate_user,
    current_session_user,
    ensure_admin_exists,
    generate_device_id,
    get_user,
    is_admin,
    record_device_id,
    register_user,
)

LOG = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="")

ADMIN_ALLOWED_USERNAMES = {"admin"}


def _is_json_request() -> bool:
    """Return True only if this is an explicit JSON/API request (not an HTML form POST).

    Do NOT use ``request.accept_mimetypes.accept_json`` — browsers always send
    ``Accept: */*`` so ``accept_json`` is always True, causing HTML form POSTs
    to be misrouted to JSON responses instead of HTTP redirects.
    """
    try:
        if bool(request.is_json):
            return True
    except Exception:
        pass
    # Fallback: body actually parses as JSON
    return request.get_json(silent=True) is not None


def _touch_session(username: str, role: str) -> None:
    session["username"] = username
    session["role"] = role
    session["login_at"] = time.time()


def _resp_with_device_cookie(resp, device_id: str):
    try:
        existing = request.cookies.get("encryptsys_device_id") or ""
        if not existing:
            resp.set_cookie(
                "encryptsys_device_id",
                device_id,
                max_age=60 * 60 * 24 * 365 * 2,  # 2 years
                httponly=True,
                samesite="Lax",
            )
    except Exception:
        pass
    return resp


# ---------------------------------------------------------------------------
# User registration & login
# ---------------------------------------------------------------------------
@auth_bp.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "GET":
        if session.get("username"):
            return redirect(url_for("dashboard"))
        return render_template("register.html")

    data = request.get_json(silent=True) or request.form or {}
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")
    display_name = str(data.get("display_name") or "").strip() or None

    ok, msg, user_doc = register_user(username, password, display_name)
    is_api = _is_json_request()
    if ok:
        _touch_session(user_doc["username"], user_doc.get("role", "user"))
        device_id = generate_device_id()
        record_device_id(user_doc["username"], device_id)
        if is_api:
            resp = make_response(jsonify({"success": True, "message": msg, "redirect": url_for("dashboard")}))
            return _resp_with_device_cookie(resp, device_id)
        resp = make_response(redirect(url_for("dashboard")))
        return _resp_with_device_cookie(resp, device_id)
    if is_api:
        return jsonify({"success": False, "error": msg}), 400
    flash(msg, "danger")
    return render_template("register.html", error=msg)


@auth_bp.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        if session.get("username"):
            return redirect(url_for("dashboard"))
        return render_template("login.html", is_admin=False)

    data = request.get_json(silent=True) or request.form or {}
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")

    if username.lower() in ADMIN_ALLOWED_USERNAMES:
        # Admin must use the separate /admin/login route for audit trail
        is_api = _is_json_request()
        err = "Admin credentials must be used via /admin/login for security."
        if is_api:
            return jsonify({"success": False, "error": err}), 403
        flash(err, "danger")
        return render_template("login.html", is_admin=False, error=err)

    ok, msg, user_doc = authenticate_user(username, password)
    is_api = _is_json_request()
    if ok:
        _touch_session(user_doc["username"], user_doc.get("role", "user"))
        device_id = request.cookies.get("encryptsys_device_id") or generate_device_id()
        record_device_id(user_doc["username"], device_id)
        if is_api:
            resp = make_response(jsonify({"success": True, "message": msg, "redirect": url_for("dashboard")}))
            return _resp_with_device_cookie(resp, device_id)
        resp = make_response(redirect(url_for("dashboard")))
        return _resp_with_device_cookie(resp, device_id)
    if is_api:
        return jsonify({"success": False, "error": msg}), 401
    flash(msg, "danger")
    return render_template("login.html", is_admin=False, error=msg)


# ---------------------------------------------------------------------------
# Admin login page (separate route + template)
# ---------------------------------------------------------------------------
@auth_bp.route("/admin/login", methods=["GET", "POST"])
def admin_login_page():
    if request.method == "GET":
        user = current_session_user(session)
        if user and is_admin(user):
            return redirect(url_for("auth.admin_dashboard"))
        if session.get("username"):
            return redirect(url_for("dashboard"))
        return render_template("admin_login.html")

    data = request.get_json(silent=True) or request.form or {}
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")

    if username.lower() not in ADMIN_ALLOWED_USERNAMES:
        is_api = _is_json_request()
        err = "This login page is for ADMIN only."
        if is_api:
            return jsonify({"success": False, "error": err}), 403
        flash(err, "danger")
        return render_template("admin_login.html", error=err)

    ok, msg, user_doc = authenticate_user(username, password)
    if ok and not is_admin(user_doc):
        ok = False
        msg = "Account is not an admin account."

    is_api = _is_json_request()
    if ok:
        _touch_session(user_doc["username"], "admin")
        device_id = request.cookies.get("encryptsys_device_id") or generate_device_id()
        record_device_id(user_doc["username"], device_id)
        if is_api:
            resp = make_response(jsonify({"success": True, "message": msg, "redirect": url_for("auth.admin_dashboard")}))
            return _resp_with_device_cookie(resp, device_id)
        resp = make_response(redirect(url_for("auth.admin_dashboard")))
        return _resp_with_device_cookie(resp, device_id)
    if is_api:
        return jsonify({"success": False, "error": msg}), 401
    flash(msg, "danger")
    return render_template("admin_login.html", error=msg)


@auth_bp.route("/logout")
def logout_page():
    try:
        session.pop("username", None)
        session.pop("role", None)
        session.pop("login_at", None)
        session.clear()
    except Exception:
        pass
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Session status API (for UI badges)
# ---------------------------------------------------------------------------
@auth_bp.get("/api/auth/status")
def api_auth_status():
    user = current_session_user(session)
    if not user:
        return jsonify({
            "authenticated": False,
            "username": None,
            "role": None,
            "is_admin": False,
            "display_name": None,
        })
    safe = dict(user)
    safe.pop("password_hash", None)
    return jsonify({
        "authenticated": True,
        "username": safe.get("username"),
        "display_name": safe.get("display_name"),
        "role": safe.get("role"),
        "is_admin": is_admin(user),
        "game_progress": safe.get("game_progress") or {},
    })


# ---------------------------------------------------------------------------
# Admin-only dashboard (audit + user mgmt)
# ---------------------------------------------------------------------------
@auth_bp.route("/admin")
def admin_dashboard():
    user = current_session_user(session)
    if not user or not is_admin(user):
        return redirect(url_for("auth.admin_login_page"))
    return render_template("admin_dashboard.html", admin_user=user)

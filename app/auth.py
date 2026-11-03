"""Login sessions backed by Windows accounts.

Any enabled local account may sign in to view, unless "allowed_users" limits
sign-in to named accounts; actions that change the system require membership
of the local Administrators group. Sessions are
held in memory (a service restart signs everyone out).
"""
import secrets
import threading
import time

from fastapi import HTTPException, Request

from . import winutil
from .config import CFG

COOKIE = "aidash_session"
_lock = threading.Lock()
_sessions: dict = {}
_failures: dict = {}           # ip -> [timestamps]
MAX_FAILURES, WINDOW = 5, 300


def _throttled(ip):
    now = time.time()
    with _lock:
        recent = [t for t in _failures.get(ip, []) if now - t < WINDOW]
        _failures[ip] = recent
        return len(recent) >= MAX_FAILURES


def login(username: str, password: str, ip: str):
    if _throttled(ip):
        raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")
    username = (username or "").strip()
    allowed = {u.lower() for u in CFG.get("allowed_users") or []}
    if allowed and winutil.short_name(username).lower() not in allowed:
        # Same answer as a bad password; never hand other accounts' passwords to LogonUser.
        account = None
    else:
        account = winutil.authenticate(username, password) if username and password else None
    if account and allowed and winutil.short_name(account).lower() not in allowed:
        account = None
    if not account:
        with _lock:
            _failures.setdefault(ip, []).append(time.time())
        raise HTTPException(401, "Invalid Windows username or password.")
    token = secrets.token_urlsafe(32)
    with _lock:
        _sessions[token] = {
            "user": account,
            "is_admin": winutil.is_admin(account),
            "expires": time.time() + CFG["session_hours"] * 3600,
        }
        _failures.pop(ip, None)
    return token, _sessions[token]


def logout(token: str):
    with _lock:
        _sessions.pop(token, None)


def current(request: Request):
    token = request.cookies.get(COOKIE)
    with _lock:
        s = _sessions.get(token) if token else None
        if s and s["expires"] < time.time():
            _sessions.pop(token, None)
            s = None
    return s


def require_viewer(request: Request):
    s = current(request)
    if s:
        return s
    if CFG["public_read"]:
        return {"user": "anonymous", "is_admin": False}
    raise HTTPException(401, "Login required")


def require_admin(request: Request):
    s = current(request)
    if not s:
        raise HTTPException(401, "Login required")
    if not s["is_admin"]:
        raise HTTPException(403, "Administrator rights required")
    # CSRF guard: browsers cannot add custom headers cross-site without CORS.
    if request.headers.get("X-Requested-With") != "aidash":
        raise HTTPException(400, "Missing request header")
    return s

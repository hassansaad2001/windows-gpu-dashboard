"""AI Server Dashboard: FastAPI app + entry point.

Run:  python -m app.main     (from the install directory)
"""
import logging
import logging.handlers
import socket
import time
from pathlib import Path
from typing import Optional

import psutil
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import auth, db, events, integrity, metrics, processes, quota, scheduler, storage, winutil
from .config import CFG, resolve

STATIC = Path(__file__).parent / "static"
log = logging.getLogger("aidash")


def setup_logging():
    log_dir = resolve(CFG["log_dir"])
    log_dir.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    fh = logging.handlers.RotatingFileHandler(log_dir / "dashboard.log", maxBytes=5 * 2**20,
                                              backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers = [fh, sh]


app = FastAPI(title="AI Server Dashboard", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.on_event("startup")
def _startup():
    db.init()
    winutil.register_event_source()
    scheduler.start()
    log.info("dashboard started on %s:%s", CFG["host"], CFG["port"])


@app.on_event("shutdown")
def _shutdown():
    scheduler.stop()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def client_ip(request: Request):
    return request.client.host if request.client else "?"


# ------------------------------------------------------------------ pages

@app.get("/", include_in_schema=False)
def index(request: Request):
    if not auth.current(request) and not CFG["public_read"]:
        return RedirectResponse("/login")
    return FileResponse(STATIC / "index.html")


@app.get("/login", include_in_schema=False)
def login_page():
    return FileResponse(STATIC / "login.html")


# ------------------------------------------------------------------ auth

class LoginBody(BaseModel):
    username: str = Field(max_length=128)
    password: str = Field(max_length=256)


@app.post("/api/login")
def api_login(body: LoginBody, request: Request, response: Response):
    token, s = auth.login(body.username, body.password, client_ip(request))
    response.set_cookie(auth.COOKIE, token, httponly=True, samesite="strict",
                        secure=bool(CFG["https"]), max_age=CFG["session_hours"] * 3600)
    db.audit(s["user"], client_ip(request), "login", "", "admin" if s["is_admin"] else "viewer")
    return {"user": s["user"], "is_admin": s["is_admin"]}


@app.post("/api/logout")
def api_logout(request: Request, response: Response):
    auth.logout(request.cookies.get(auth.COOKIE, ""))
    response.delete_cookie(auth.COOKIE)
    return {"ok": True}


@app.get("/api/me")
def api_me(s=Depends(auth.require_viewer)):
    return {"user": s["user"], "is_admin": s["is_admin"]}


# ------------------------------------------------------------------ overview

_user_stats_cache = {"ts": 0, "data": None}


def user_stats():
    if time.time() - _user_stats_cache["ts"] < 60 and _user_stats_cache["data"]:
        return _user_stats_cache["data"]
    users = winutil.local_users()
    enabled = {u["name"].lower() for u in users if not u["disabled"]}
    admins = [a for a in winutil.admin_members() if a.lower() in enabled]
    sess = winutil.sessions()
    data = {
        "registered": len(enabled),
        "disabled": sum(1 for u in users if u["disabled"]),
        "admins": len(admins),
        "admin_names": sorted(admins, key=str.lower),
        "sessions_active": sum(1 for s in sess if s["state"] == "Active"),
        "sessions_disconnected": sum(1 for s in sess if s["state"] == "Disconnected"),
        "users_logged_on": len({s["username"].lower() for s in sess}),
        "sessions": sess,
    }
    _user_stats_cache.update(ts=time.time(), data=data)
    return data


@app.get("/api/overview")
def api_overview(s=Depends(auth.require_viewer)):
    disks = []
    for p in psutil.disk_partitions(all=False):
        if "fixed" not in p.opts and "rw" not in p.opts:
            continue
        try:
            u = psutil.disk_usage(p.mountpoint)
            disks.append({"mount": p.mountpoint, "total": u.total, "used": u.used, "free": u.free,
                          "percent": u.percent})
        except OSError:
            pass
    vm = psutil.virtual_memory()
    return {
        "host": socket.gethostname(),
        "now": int(time.time()),
        "boot_ts": int(psutil.boot_time()),
        "cpu_count": psutil.cpu_count(),
        "ram_total": vm.total,
        "ram_used": vm.total - vm.available,
        "live": metrics.live(),
        "users": user_stats(),
        "disks": disks,
        "jobs": scheduler.status,
        "storage_scan": storage.scan_status(),
        "integrity": integrity.summary(s["is_admin"]),
    }


RANGES = {
    "1h": ("raw", 3600),
    "24h": ("hourly", 86400),
    "7d": ("hourly", 7 * 86400),
    "30d": ("daily", 30 * 86400),
    "12m": ("monthly", 366 * 86400),
}


@app.get("/api/trends")
def api_trends(range: str = "24h", s=Depends(auth.require_viewer)):
    if range not in RANGES:
        raise HTTPException(400, "bad range")
    kind, span = RANGES[range]
    since = int(time.time()) - span
    if kind == "raw":
        rows = db.query("SELECT ts, cpu, ram, gpu, gpu_mem FROM metrics_raw WHERE ts >= ? ORDER BY ts", (since,))
        gpus = db.query("SELECT ts, gpu_index, util FROM gpu_raw WHERE ts >= ? ORDER BY ts", (since,))
        return {"kind": kind, "rows": rows, "gpus": gpus}
    if kind == "hourly":
        rows = db.query(
            """SELECT hour_ts AS ts, cpu_avg AS cpu, cpu_max, ram_avg AS ram, ram_max, gpu_avg AS gpu,
                      gpu_max, gpu_mem_avg AS gpu_mem FROM metrics_hourly WHERE hour_ts >= ? ORDER BY hour_ts""",
            (since,))
        gpus = db.query("SELECT hour_ts AS ts, gpu_index, util_avg AS util FROM gpu_hourly WHERE hour_ts >= ?"
                        " ORDER BY hour_ts", (since,))
        return {"kind": kind, "rows": rows, "gpus": gpus}
    # Group hourly aggregates by local calendar day / month.
    fmt = "%Y-%m-%d" if kind == "daily" else "%Y-%m"
    rows = db.query(
        f"""SELECT strftime('{fmt}', hour_ts, 'unixepoch', 'localtime') AS label, MIN(hour_ts) AS ts,
                   SUM(cpu_avg * samples) / SUM(samples) AS cpu, MAX(cpu_max) AS cpu_max,
                   SUM(ram_avg * samples) / SUM(samples) AS ram, MAX(ram_max) AS ram_max,
                   SUM(gpu_avg * samples) / SUM(samples) AS gpu, MAX(gpu_max) AS gpu_max,
                   SUM(gpu_mem_avg * samples) / SUM(samples) AS gpu_mem
            FROM metrics_hourly WHERE hour_ts >= ? GROUP BY label ORDER BY label""", (since,))
    gpus = db.query(
        f"""SELECT strftime('{fmt}', hour_ts, 'unixepoch', 'localtime') AS label, MIN(hour_ts) AS ts,
                   gpu_index, AVG(util_avg) AS util
            FROM gpu_hourly WHERE hour_ts >= ? GROUP BY label, gpu_index ORDER BY label""", (since,))
    return {"kind": kind, "rows": rows, "gpus": gpus}


# ------------------------------------------------------------------ storage

@app.get("/api/storage")
def api_storage(s=Depends(auth.require_viewer)):
    homes, ntfs = storage.latest_storage()
    return {"homes": homes, "ntfs": ntfs, "quota": quota.status_rows(), "scan": storage.scan_status()}


@app.get("/api/storage/history")
def api_storage_history(days: int = 30, s=Depends(auth.require_viewer)):
    since = int(time.time()) - min(days, 365) * 86400
    return db.query(
        """SELECT ts, username, size_bytes FROM storage_snapshots
           WHERE ts >= ? AND ts IN (SELECT MAX(ts) FROM storage_snapshots WHERE ts >= ? GROUP BY ts / 86400)
           ORDER BY ts""", (since, since))


# ------------------------------------------------------------------ restarts

@app.get("/api/restarts")
def api_restarts(s=Depends(auth.require_viewer)):
    return events.last_restarts(10)


# ------------------------------------------------------------------ processes

_last_refresh = {"ts": 0}


@app.get("/api/processes")
def api_processes(refresh: bool = False, s=Depends(auth.require_viewer)):
    data = processes.last()
    if refresh and time.time() - _last_refresh["ts"] > 15 or data["ts"] is None:
        _last_refresh["ts"] = time.time()
        data = processes.scan(persist=False)
    return {k: data.get(k) for k in ("ts", "gpu_procs", "flagged", "sessions")}


@app.get("/api/rogue/history")
def api_rogue_history(s=Depends(auth.require_viewer)):
    return processes.history(100)


class TerminateBody(BaseModel):
    create_time: float
    tree: bool = True


@app.post("/api/processes/{pid}/terminate")
def api_terminate(pid: int, body: TerminateBody, request: Request, s=Depends(auth.require_admin)):
    ok, msg = processes.terminate(pid, body.create_time, body.tree)
    db.audit(s["user"], client_ip(request), "terminate", str(pid), msg, ok)
    if not ok:
        raise HTTPException(409, msg)
    log.warning("%s: %s", s["user"], msg)
    return {"ok": True, "message": msg}


@app.post("/api/sessions/{session_id}/logoff")
def api_logoff(session_id: int, request: Request, s=Depends(auth.require_admin)):
    sess = next((x for x in winutil.sessions() if x["session_id"] == session_id), None)
    if not sess:
        raise HTTPException(404, "session not found")
    if sess["username"].lower() == winutil.short_name(s["user"]).lower():
        raise HTTPException(409, "refusing to log off your own session")
    winutil.logoff_session(session_id)
    _user_stats_cache["ts"] = 0
    db.audit(s["user"], client_ip(request), "logoff", f"{sess['username']} (session {session_id})")
    return {"ok": True, "message": f"logged off {sess['username']} (session {session_id})"}


# ------------------------------------------------------------------ quota

@app.get("/api/quota")
def api_quota(s=Depends(auth.require_viewer)):
    return {"policies": quota.policies(), "status": quota.status_rows(),
            "volumes": quota.volume_status(),
            "users": sorted((u["name"] for u in winutil.local_users() if not u["disabled"]), key=str.lower)}


class PolicyBody(BaseModel):
    target: str = Field(min_length=1, max_length=64)
    volume: str = Field(default="C:", max_length=3)
    soft_gb: Optional[float] = Field(default=None, ge=0)
    hard_gb: Optional[float] = Field(default=None, ge=0)
    mode: str = "grace"
    grace_days: Optional[float] = Field(default=None, ge=0, le=365)


@app.post("/api/quota/preview")
def api_quota_preview(body: PolicyBody, s=Depends(auth.require_admin)):
    try:
        return quota.preview(body.target, body.volume, body.soft_gb, body.hard_gb, body.mode, body.grace_days)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/quota/policies")
def api_quota_set(body: PolicyBody, request: Request, s=Depends(auth.require_admin)):
    try:
        target, volume = quota.upsert_policy(body.target, body.volume, body.soft_gb, body.hard_gb,
                                             body.mode, body.grace_days, s["user"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    db.audit(s["user"], client_ip(request), "quota-set", f"{target} on {volume}",
             f"mode={body.mode} soft={body.soft_gb} hard={body.hard_gb} grace={body.grace_days}")
    scheduler.run_now("quota")
    return {"ok": True}


@app.delete("/api/quota/policies/{policy_id}")
def api_quota_delete(policy_id: int, request: Request, s=Depends(auth.require_admin)):
    pol = quota.delete_policy(policy_id)
    if not pol:
        raise HTTPException(404, "policy not found")
    db.audit(s["user"], client_ip(request), "quota-delete", f"{pol['target']} on {pol['volume']}")
    return {"ok": True}


# ------------------------------------------------------------------ admin

@app.post("/api/jobs/{name}/run")
def api_run_job(name: str, request: Request, s=Depends(auth.require_admin)):
    if name not in ("rogue", "events", "storage", "quota", "metrics", "integrity"):
        raise HTTPException(404, "unknown job")
    scheduler.run_now(name)
    db.audit(s["user"], client_ip(request), "run-job", name)
    return {"ok": True}


@app.get("/api/audit")
def api_audit(s=Depends(auth.require_admin)):
    return db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200")


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


def main():
    setup_logging()
    kw = {}
    if CFG["https"]:
        cert, key = resolve(CFG["cert_file"]), resolve(CFG["key_file"])
        if cert.exists() and key.exists():
            kw = {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}
        else:
            log.error("https enabled but %s / %s missing; run scripts\\make_cert.py. Serving HTTP.", cert, key)
            CFG["https"] = False
    uvicorn.run(app, host=CFG["host"], port=CFG["port"], log_config=None, access_log=False,
                proxy_headers=False, **kw)


if __name__ == "__main__":
    main()

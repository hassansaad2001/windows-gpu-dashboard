"""Rogue / orphaned process detection and safe termination."""
import logging
import os
import re
import threading
import time

import psutil
import win32ts

from . import db, metrics, winutil
from .config import CFG

log = logging.getLogger("aidash.proc")

SYSTEM_PREFIXES = ("nt authority\\", "window manager\\", "font driver host\\", "nt service\\")
PROTECTED = {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
             "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe", "fontdrvhost.exe",
             "logonui.exe", "rdpclip.exe", "sihost.exe", "taskhostw.exe", "nssm.exe"}
# Hyper-V/WSL VM workers: killing one is a hard power-off of the VM and can
# corrupt the user's Linux disk image (ext4.vhdx).
VM_WORKERS = {"vmwp.exe", "vmmem", "vmmemwsl"}
_VM_ID = re.compile(r"--vm-id\s+\{?([0-9a-fA-F-]{36})\}?")

_cache_lock = threading.Lock()
_proc_cache: dict = {}          # pid -> psutil.Process, keeps cpu_percent deltas between scans
_last = {"ts": None, "gpu_procs": [], "flagged": [], "sessions": []}


def _is_user_account(username: str) -> bool:
    return bool(username) and not username.lower().startswith(SYSTEM_PREFIXES)


def _proc(pid):
    p = _proc_cache.get(pid)
    if p is None:
        p = psutil.Process(pid)
        p.cpu_percent(None)  # prime
        _proc_cache[pid] = p
    return p


def _wsl_vm_owners() -> dict:
    """WSL VM id -> (username, session_id), from the user's wslhost/wslrelay helpers.

    The VM worker (vmwp.exe) runs under a per-VM virtual account named after the
    VM id; the helpers run as the user who started WSL and carry --vm-id."""
    out = {}
    for p in psutil.process_iter(["name", "username"]):
        try:
            if p.info["name"] and p.info["name"].lower() in ("wslhost.exe", "wslrelay.exe") and p.info["username"]:
                m = _VM_ID.search(" ".join(p.cmdline()))
                if m:
                    out.setdefault(m.group(1).lower(), (winutil.short_name(p.info["username"]), _session_of(p.pid)))
        except (psutil.Error, OSError):
            continue
    return out


def scan(persist=True):
    rc = CFG["rogue"]
    watch = {n.lower() for n in rc["watch_names"]}
    wl_users = {u.lower() for u in rc["whitelist_users"]}
    wl_names = {n.lower() for n in rc["whitelist_names"]}
    now = time.time()

    sessions = winutil.sessions()
    by_id = {s["session_id"]: s for s in sessions}
    users_with_session = {s["username"].lower() for s in sessions}

    gpus = metrics.live().get("gpus") or metrics.nvidia_smi()
    gpu_use = metrics.gpu_counters.sample(gpus)
    vm_owners = None

    rows = {}
    with _cache_lock:
        alive = set(psutil.pids())
        for pid in list(_proc_cache):
            if pid not in alive:
                _proc_cache.pop(pid, None)
        for pid in alive:
            if pid in (0, 4):
                continue
            try:
                p = _proc(pid)
                with p.oneshot():
                    name = p.name()
                    user = p.username()
                    if not _is_user_account(user):
                        continue
                    cpu = p.cpu_percent(None)
                    g = gpu_use.get(pid)
                    if name.lower() not in watch and not g and cpu < rc["cpu_percent_threshold"]:
                        continue
                    username, session_id = winutil.short_name(user), _session_of(pid)
                    if name.lower() == "vmwp.exe":
                        # GPU work inside WSL is charged to the VM worker; attribute it
                        # to the user who owns the VM and use their session.
                        if vm_owners is None:
                            vm_owners = _wsl_vm_owners()
                        owner = vm_owners.get(username.lower())
                        name = "vmwp.exe (WSL VM)" if owner else "vmwp.exe (VM)"
                        if owner:
                            username, session_id = owner
                    rows[pid] = {
                        "pid": pid, "ppid": p.ppid(), "name": name,
                        "vm": name.lower().startswith("vmwp.exe"),
                        "username": username,
                        "session_id": session_id,
                        "create_time": p.create_time(),
                        "runtime_h": round((now - p.create_time()) / 3600, 1),
                        "cpu_pct": round(cpu, 1),
                        "rss_mb": round(p.memory_info().rss / 2**20),
                        "gpu_mem_mb": g["mem_mb"] if g else 0,
                        "gpus": {str(k): v for k, v in sorted(g["gpus"].items())} if g else {},
                    }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                _proc_cache.pop(pid, None)
                continue

    # Collapse worker children (e.g. DataLoader workers) into their parent.
    for r in list(rows.values()):
        parent = rows.get(r["ppid"])
        if parent and parent["username"] == r["username"] and not r["gpu_mem_mb"]:
            parent.setdefault("children", 0)
            parent["children"] += 1
            parent["cpu_pct"] = round(parent["cpu_pct"] + r["cpu_pct"], 1)
            parent["rss_mb"] += r["rss_mb"]
            rows.pop(r["pid"])

    flagged = []
    for r in rows.values():
        try:
            r["cmdline"] = " ".join(psutil.Process(r["pid"]).cmdline())[:600]
        except (psutil.Error, OSError):
            r["cmdline"] = ""
        reasons, sev = [], 0
        uname = r["username"].lower()
        sess = by_id.get(r["session_id"])
        if uname not in users_with_session:
            reasons.append("orphaned: owner has no logon session")
            sev = max(sev, 3)
        elif r["session_id"] == 0 or sess is None or sess["username"].lower() != uname:
            reasons.append("detached: runs outside the owner's interactive session")
            sev = max(sev, 2)
        elif sess["state"] == "Disconnected" and sess["idle_seconds"] >= rc["idle_disconnected_hours"] * 3600:
            reasons.append(f"idle: session disconnected {sess['idle_seconds'] // 3600}h")
            sev = max(sev, 2)
        ngpu = sum(1 for g in r["gpus"].values() if g["mem_mb"] >= 256)
        if ngpu >= rc["multi_gpu_threshold"]:
            reasons.append(f"multi-GPU: holds {ngpu} GPUs")
            sev = max(sev, 2)
        if r["gpu_mem_mb"] >= rc["gpu_mem_gb_threshold"] * 1024:
            reasons.append(f"GPU-heavy: {r['gpu_mem_mb'] / 1024:.1f} GB VRAM")
            sev = max(sev, 1)
        if r["cpu_pct"] >= rc["cpu_percent_threshold"]:
            reasons.append(f"CPU-heavy: {r['cpu_pct']:.0f}% (~{r['cpu_pct'] / 100:.0f} cores)")
            sev = max(sev, 1)
        if r["runtime_h"] >= rc["max_runtime_hours"]:
            reasons.append(f"long-running: {r['runtime_h']:.0f}h")
            sev = max(sev, 1)
        if sev >= 2 and r["gpu_mem_mb"] >= 1024:
            sev = 3  # unattended job sitting on GPU memory
        if uname in wl_users or r["name"].lower() in wl_names:
            reasons, sev = [], 0
        r["reasons"] = reasons
        r["severity"] = ["", "low", "medium", "high"][sev]
        r["session_state"] = sess["state"] if sess else "none"
        if reasons:
            flagged.append(r)

    flagged.sort(key=lambda r: (["", "low", "medium", "high"].index(r["severity"]), r["gpu_mem_mb"]), reverse=True)
    gpu_procs = sorted((r for r in rows.values() if r["gpu_mem_mb"] or r["gpus"]),
                       key=lambda r: r["gpu_mem_mb"], reverse=True)
    _last.update(ts=int(now), gpu_procs=gpu_procs, flagged=flagged, sessions=sessions,
                 all=list(rows.values()))
    if persist:
        _persist(flagged, int(now))
    return _last


def _session_of(pid):
    try:
        return win32ts.ProcessIdToSessionId(pid)
    except Exception:
        return -1


def _persist(flagged, now):
    seen = [(r["pid"], r["create_time"]) for r in flagged]
    with db.write() as c:
        for r in flagged:
            c.execute(
                """INSERT INTO rogue_events(pid, create_time, username, name, session_id, severity, reasons,
                       gpu_mem_mb, gpus, cpu_pct, rss_mb, cmdline, first_seen, last_seen)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(pid, create_time) DO UPDATE SET
                       severity=excluded.severity, reasons=excluded.reasons, gpu_mem_mb=excluded.gpu_mem_mb,
                       gpus=excluded.gpus, cpu_pct=excluded.cpu_pct, rss_mb=excluded.rss_mb,
                       last_seen=excluded.last_seen, ended=NULL""",
                (r["pid"], r["create_time"], r["username"], r["name"], r["session_id"], r["severity"],
                 "; ".join(r["reasons"]), r["gpu_mem_mb"], ",".join(r["gpus"]), r["cpu_pct"], r["rss_mb"],
                 r["cmdline"], now, now))
        open_rows = c.execute("SELECT id, pid, create_time FROM rogue_events WHERE ended IS NULL").fetchall()
        for row in open_rows:
            if (row["pid"], row["create_time"]) not in seen:
                c.execute("UPDATE rogue_events SET ended = ? WHERE id = ?", (now, row["id"]))


def last():
    return _last


def history(limit=100):
    return db.query("SELECT * FROM rogue_events ORDER BY last_seen DESC LIMIT ?", (limit,))


# ------------------------------------------------------------ termination

def terminate(pid: int, create_time: float, tree: bool = True):
    """Terminate a user process after verifying identity (guards against PID reuse)."""
    try:
        p = psutil.Process(pid)
        if abs(p.create_time() - float(create_time)) > 1:
            return False, "process identity changed (PID was reused); refresh and retry"
        user = p.username()
        name = p.name()
    except psutil.NoSuchProcess:
        return False, "process no longer exists"
    except psutil.AccessDenied:
        return False, "access denied"
    if not _is_user_account(user):
        return False, f"refusing to terminate system-account process ({user})"
    if name.lower() in PROTECTED:
        return False, f"refusing to terminate protected process {name}"
    if name.lower() in VM_WORKERS:
        return False, ("this is a WSL/Hyper-V VM worker; killing it can corrupt the user's Linux disk. "
                       "Ask the user to stop the job or run 'wsl --shutdown', or log off their session")
    own = {os.getpid()} | {a.pid for a in psutil.Process().parents()}
    if pid in own:
        return False, "refusing to terminate the dashboard itself"

    procs = (p.children(recursive=True) if tree else []) + [p]
    for q in procs:
        try:
            q.terminate()
        except psutil.Error:
            pass
    _gone, alive = psutil.wait_procs(procs, timeout=5)
    for q in alive:
        try:
            q.kill()
        except psutil.Error:
            pass
    with db.write() as c:
        c.execute("UPDATE rogue_events SET ended = ?, action = 'terminated' WHERE pid = ? AND ABS(create_time - ?) < 1",
                  (int(time.time()), pid, create_time))
    return True, f"terminated {name} (PID {pid}, {len(procs)} process(es)) owned by {user}"

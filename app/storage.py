"""User storage footprint: home-directory scan + NTFS per-owner quota usage."""
import json
import logging
import os
import re
import stat
import subprocess
import time
import winreg
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import psutil
import pywintypes
import win32security

from . import db, winutil
from .config import CFG

log = logging.getLogger("aidash.storage")
CREATE_NO_WINDOW = 0x08000000
SKIP_ATTRS = stat.FILE_ATTRIBUTE_REPARSE_POINT  # junctions/symlinks (AppData loops, OneDrive)

_last_scan = {"ts": None, "seconds": None, "running": False}


def dir_size(path: str):
    """Total logical size and file count, not following reparse points."""
    total = files = 0
    errors = 0
    stack = [path]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        errors += 1
                        continue
                    if st.st_file_attributes & SKIP_ATTRS:
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        stack.append(e.path)
                    else:
                        total += st.st_size
                        files += 1
        except OSError:
            errors += 1
    return total, files, errors


def profile_root() -> Path:
    """storage.profile_root, or the folder Windows keeps profiles in."""
    return Path(CFG["storage"]["profile_root"] or winutil.profiles_directory())


def quota_volumes():
    """storage.quota_volumes, or every fixed NTFS volume ('C:', 'D:', ...)."""
    if CFG["storage"]["quota_volumes"]:
        return CFG["storage"]["quota_volumes"]
    vols = {p.device[:2].upper() for p in psutil.disk_partitions(all=False)
            if p.fstype.upper() == "NTFS" and "fixed" in p.opts}
    return sorted(vols)


def home_folders():
    cfg = CFG["storage"]
    root = profile_root()
    skip = {s.lower() for s in cfg["skip_folders"]}
    pmap = winutil.profile_map()
    out = []
    for d in root.iterdir():
        try:
            if not d.is_dir() or d.name.lower() in skip or d.is_symlink():
                continue
            if os.stat(d, follow_symlinks=False).st_file_attributes & SKIP_ATTRS:
                continue
        except OSError:
            continue
        sid, name = pmap.get(str(d).lower(), (None, ""))
        out.append({"folder": str(d), "sid": sid, "username": name or d.name, "orphan": not name})
    return out


def scan_homes():
    if _last_scan["running"]:
        log.info("storage scan already running")
        return
    _last_scan["running"] = True
    t0 = time.time()
    try:
        folders = home_folders()

        def work(f):
            s = time.time()
            size, count, errs = dir_size(f["folder"])
            return f, size, count, time.time() - s, (f"{errs} unreadable entries" if errs else None)

        with ThreadPoolExecutor(max_workers=CFG["storage"]["scan_threads"]) as pool:
            results = list(pool.map(work, folders))
        ts = int(time.time())
        with db.write() as c:
            c.executemany(
                """INSERT INTO storage_snapshots(ts, username, sid, folder, size_bytes, file_count,
                   scan_seconds, error) VALUES (?,?,?,?,?,?,?,?)""",
                [(ts, f["username"] + (" (no account)" if f["orphan"] else ""), f["sid"], f["folder"],
                  size, count, round(secs, 1), err) for f, size, count, secs, err in results])
        _last_scan.update(ts=ts, seconds=round(time.time() - t0, 1))
        log.info("storage scan: %d folders in %.1fs", len(results), time.time() - t0)
    finally:
        _last_scan["running"] = False


def scan_status():
    return dict(_last_scan)


# ------------------------------------------------------------ NTFS quotas

def fsutil(*args, timeout=120):
    r = subprocess.run(["fsutil", *args], capture_output=True, text=True, timeout=timeout,
                       creationflags=CREATE_NO_WINDOW)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


_NUM = re.compile(r"(\d[\d,]*)")
_HEX = re.compile(r"0x([0-9a-fA-F]+)")


def _bytes(line: str):
    """Value of a 'Quota Limit = 123' or '= 0x40000000' line; None for "no limit" (0xFFFFFFFFFFFFFFFF)."""
    value = line.split("=", 1)[1] if "=" in line else line
    if "no limit" in value.lower():
        return None
    m = _HEX.search(value)
    if m:
        n = int(m.group(1), 16)
    else:
        m = _NUM.search(value)
        if not m:
            return None
        n = int(m.group(1).replace(",", ""))
    return None if n >= 2**63 else n


def quota_state(volume: str) -> dict:
    """{'enabled', 'enforced', 'defaults_ok', 'default_limit', 'raw'}.

    defaults_ok is True only when the volume's default limit for accounts without
    an entry was read and is "No limit"; enforcing quotas is only safe then."""
    code, out = fsutil("quota", "query", volume, timeout=30)
    flags = re.search(r"(?:FileSystemControlFlags|File System Flags)\s*=\s*(0x[0-9a-fA-F]+)", out)
    if code != 0 or not flags:
        return {"enabled": False, "enforced": False, "defaults_ok": False, "default_limit": None,
                "raw": out.strip()[:500]}
    f = int(flags.group(1), 16)
    dl = re.search(r"Default Quota Limit\s*=\s*([^\r\n]+)", out)
    default_limit = _bytes(dl.group(1)) if dl else None
    # FILE_VC_QUOTA_TRACK=0x1, FILE_VC_QUOTA_ENFORCE=0x2
    return {"enabled": bool(f & 0x3), "enforced": bool(f & 0x2),
            "defaults_ok": bool(dl) and default_limit is None, "default_limit": default_limit,
            "flags": hex(f), "raw": out.split("SID Name")[0].strip()[:800]}


def quota_entries(volume: str):
    """Parse `fsutil quota query` entries into dicts."""
    code, out = fsutil("quota", "query", volume)
    if code != 0 or "SID Name" not in out:
        return []
    entries = []
    for block in out.split("SID Name")[1:]:
        lines = [l.strip() for l in ("SID Name" + block).splitlines() if l.strip()]
        e = {}
        for l in lines:
            if l.startswith("SID Name"):
                # "HOST\user (User)" -> "HOST\user"
                e["account"] = re.sub(r"\s*\([^)]*\)$", "", l.split("=", 1)[1].strip())
            elif l.startswith("Quota Used"):
                e["used"] = _bytes(l) or 0
            elif l.startswith("Quota Threshold"):
                e["threshold"] = _bytes(l)
            elif l.startswith("Quota Limit"):
                e["limit"] = _bytes(l)
        if "account" in e:
            e["username"] = winutil.short_name(e["account"])
            entries.append(e)
    return entries


# ------------------------------------------------------- VM virtual disks

# Where WSL distros and Docker Desktop keep their growing Linux disks, relative to a profile.
VM_DISK_GLOBS = ("AppData/Local/Packages/*/LocalState/*.vhd*",
                 "AppData/Local/wsl/*/*.vhd*",
                 "AppData/Local/Docker/wsl/*/*.vhd*",
                 "AppData/Local/Docker/wsl/*/*/*.vhd*")
LXSS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Lxss"
VM_DISK_MEMORY_DAYS = 30


def _owner_sid(path):
    try:
        sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)
        return win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())
    except pywintypes.error:
        return None


def _lxss_disks(sid):
    """VHDX paths of the WSL distros registered for a logged-on user (hive loaded)."""
    out = []
    try:
        root = winreg.OpenKey(winreg.HKEY_USERS, f"{sid}\\{LXSS_KEY}")
    except OSError:
        return out
    with root:
        i = 0
        while True:
            try:
                name = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            try:
                with winreg.OpenKey(root, name) as k:
                    base, _ = winreg.QueryValueEx(k, "BasePath")
                    try:
                        vhd, _ = winreg.QueryValueEx(k, "VhdFileName")
                    except OSError:
                        vhd = "ext4.vhdx"
            except OSError:
                continue
            base = base[4:] if base.startswith("\\\\?\\") else base
            out.append(os.path.join(base, vhd))
    return out


def vm_disks():
    """username (lowercase) -> volumes ('C:') holding a WSL/Docker virtual disk charged to them.

    A growing .vhdx that hits an NTFS limit gives the Linux side I/O errors and
    can corrupt it, so quota.py never sets a hard limit for these users on that
    volume. Disks are found in the usual profile folders and, for logged-on users,
    in the WSL registry (distros imported elsewhere). A disk counts when the user
    owns it (NTFS charges the owner) or its owner can't be read. Volumes seen in
    the last VM_DISK_MEMORY_DAYS are remembered, so a logged-off user stays covered.
    """
    now = int(time.time())
    try:
        memory = json.loads(db.kv_get("vm_disk_volumes", "{}"))
    except ValueError:
        memory = {}
    for folder, (sid, name) in winutil.profile_map().items():
        if not sid or not name:
            continue
        paths = []
        for pattern in VM_DISK_GLOBS:
            try:
                paths += [str(p) for p in Path(folder).glob(pattern)]
            except OSError:
                pass
        paths += _lxss_disks(sid)
        for p in paths:
            if not p.lower().endswith((".vhdx", ".vhd")) or not os.path.isfile(p):
                continue
            owner = _owner_sid(p)
            vol = os.path.splitdrive(p)[0].upper()
            if (owner is None or owner == sid) and len(vol) == 2:
                memory.setdefault(name.lower(), {})[vol] = now
    cutoff = now - VM_DISK_MEMORY_DAYS * 86400
    memory = {u: {v: ts for v, ts in vols.items() if ts >= cutoff} for u, vols in memory.items()}
    memory = {u: vols for u, vols in memory.items() if vols}
    db.kv_set("vm_disk_volumes", json.dumps(memory))
    return {u: set(vols) for u, vols in memory.items()}


def collect_ntfs_usage():
    ts = int(time.time())
    rows = []
    for vol in quota_volumes():
        if not quota_state(vol)["enabled"]:
            continue
        for e in quota_entries(vol):
            rows.append((ts, vol, e["username"], None, e.get("used", 0), e.get("threshold"), e.get("limit")))
    if rows:
        with db.write() as c:
            c.executemany(
                """INSERT INTO ntfs_usage(ts, volume, username, sid, used_bytes, threshold_bytes, limit_bytes)
                   VALUES (?,?,?,?,?,?,?)""", rows)
    return len(rows)


def latest_storage():
    homes = db.query(
        """SELECT username, sid, folder, size_bytes, file_count, scan_seconds, error, ts
           FROM storage_snapshots WHERE ts = (SELECT MAX(ts) FROM storage_snapshots)
           ORDER BY size_bytes DESC""")
    ntfs = db.query(
        """SELECT volume, username, used_bytes, threshold_bytes, limit_bytes, ts FROM ntfs_usage
           WHERE ts = (SELECT MAX(ts) FROM ntfs_usage)""")
    return homes, ntfs

"""Tamper detection for the install folder.

scripts\\protect.ps1 makes the app files read-only for every account, Administrators
included, and records a SHA-256 baseline in manifest.json. The service re-hashes the
files on a schedule. When anything differs from the baseline, or the baseline itself
is rebuilt, it writes an event-log entry and an audit-log row, and admins see a banner.

  python -m app.integrity build    # write manifest.json (protect.ps1 runs this)
  python -m app.integrity check    # compare with the baseline; exit 1 on any difference
"""
import getpass
import hashlib
import json
import logging
import sys
import time

from . import db, winutil
from .config import BASE_DIR, CFG, resolve

log = logging.getLogger("aidash.integrity")
MANIFEST = BASE_DIR / "manifest.json"
LIST_MAX = 20

state = {"protected": False, "ok": None, "checked": None, "baseline": None, "baseline_by": None,
         "changed": [], "added": [], "missing": [], "error": None}


def _runtime_dirs():
    """Folders the service writes to at runtime; they are never part of the baseline."""
    return {resolve(CFG["database"]).parent.resolve(), resolve(CFG["log_dir"]).resolve()}


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _scan():
    skip = _runtime_dirs()
    out = {}
    stack = [BASE_DIR]
    while stack:
        d = stack.pop()
        for p in d.iterdir():
            if p.is_dir() and not p.is_symlink():
                if p.resolve() not in skip:
                    stack.append(p)
            elif p.is_file() and p != MANIFEST:
                out[p.relative_to(BASE_DIR).as_posix()] = _sha256(p)
    return out


def build():
    files = _scan()
    data = {"created": int(time.time()), "created_by": getpass.getuser(), "files": files}
    MANIFEST.write_text(json.dumps(data, indent=0, sort_keys=True), encoding="utf-8")
    return len(files)


def _diff(base, now):
    changed = sorted(k for k in base.keys() & now.keys() if base[k] != now[k])
    return changed, sorted(now.keys() - base.keys()), sorted(base.keys() - now.keys())


def _findings(changed, added, missing):
    return [f"changed {p}" for p in changed] + [f"added {p}" for p in added] + \
           [f"missing {p}" for p in missing]


def _digest(items):
    return hashlib.sha256("\n".join(items).encode("utf-8")).hexdigest()


def _note_baseline(raw, man):
    """Report a rebuilt baseline once: legitimate edits rebuild it, and so would an attacker."""
    digest = hashlib.sha256(raw).hexdigest()
    prev = db.kv_get("integrity_manifest")
    if prev == digest:
        return
    db.kv_set("integrity_manifest", digest)
    if prev is None:
        return
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(man.get("created", 0)))
    msg = f"File baseline for {BASE_DIR} was rebuilt by {man.get('created_by', '?')} at {when}."
    log.warning(msg)
    winutil.write_event(4002, msg, "warning")
    db.audit("system", "-", "integrity-baseline", str(BASE_DIR), msg)


def check():
    if not MANIFEST.exists():
        state.update(protected=False, ok=None, checked=int(time.time()), error=None)
        return state
    raw = MANIFEST.read_bytes()
    man = json.loads(raw)
    changed, added, missing = _diff(man["files"], _scan())
    state.update(protected=True, ok=not (changed or added or missing), checked=int(time.time()),
                 baseline=man.get("created"), baseline_by=man.get("created_by"),
                 changed=changed, added=added, missing=missing, error=None)

    _note_baseline(raw, man)
    findings = _findings(changed, added, missing)
    key = _digest(findings) if findings else ""
    prev = db.kv_get("integrity_findings", "")
    if key != prev:
        db.kv_set("integrity_findings", key)
        if findings:
            shown = "\n".join(findings[:LIST_MAX])
            more = f"\n... and {len(findings) - LIST_MAX} more" if len(findings) > LIST_MAX else ""
            msg = (f"{len(findings)} file(s) in {BASE_DIR} differ from the protected baseline:\n"
                   f"{shown}{more}\nThe Security event log (event 4663) shows which account changed them.")
            log.error(msg)
            winutil.write_event(4001, msg, "error")
            db.audit("system", "-", "integrity-alert", str(BASE_DIR), "; ".join(findings[:LIST_MAX]), ok=False)
        elif prev:
            msg = f"Files in {BASE_DIR} match the protected baseline again."
            log.info(msg)
            winutil.write_event(4000, msg, "info")
            db.audit("system", "-", "integrity-ok", str(BASE_DIR), msg)
    return state


def summary(is_admin):
    """Viewers only learn whether the files are intact; admins get the file lists."""
    keys = ("protected", "ok", "checked") + (
        ("baseline", "baseline_by", "changed", "added", "missing") if is_admin else ())
    out = {k: state[k] for k in keys}
    for k in ("changed", "added", "missing"):
        if k in out:
            out[k + "_count"] = len(out[k])
            out[k] = out[k][:LIST_MAX]
    return out


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "build":
        print(f"baseline written: {build()} files -> {MANIFEST}")
    elif cmd == "check":
        if not MANIFEST.exists():
            sys.exit(f"no baseline at {MANIFEST}")
        base = json.loads(MANIFEST.read_bytes())["files"]
        diff = _findings(*_diff(base, _scan()))
        print("\n".join(diff) if diff else f"OK: {len(base)} files match the baseline")
        sys.exit(1 if diff else 0)
    else:
        sys.exit("usage: python -m app.integrity build|check")

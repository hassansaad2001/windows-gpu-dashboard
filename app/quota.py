"""Storage quota policies and NTFS enforcement.

Policy modes (per volume, for one user or '*' = every non-admin local user):
  soft   warn above soft_gb; never block.
  hard   NTFS limit = hard_gb immediately (warning threshold = soft_gb).
  grace  warn above soft_gb; after grace_days still over, NTFS limit = soft_gb.
         An optional hard_gb is enforced at all times as an absolute ceiling.

Enforcement uses NTFS disk quotas (fsutil quota). When a user reaches their
limit NTFS fails new writes with "There is not enough space on the disk"
while reads and deletes keep working; writes resume as soon as usage drops
back under the limit. NTFS charges every file a user *owns* on the volume,
not only files in their profile folder. Nothing here deletes or moves files.

A blocked write can still damage a job that is in the middle of writing, so:
  * A user with a WSL/Docker virtual disk (.vhdx) charged to them on a volume
    gets only the warning threshold there, never a limit: a Linux disk that
    cannot grow sees I/O errors and can be corrupted (status 'vm-protected').
  * Enforcement is switched on only when the volume's default limit is
    "No limit", so accounts without an explicit entry are never limited.
  * The '*' policy skips administrators (direct or through a nested group),
    quota.exempt_users and accounts that run Windows services.
  * Limits below MIN_GB are refused, and preview() shows who a policy would
    block before it is saved.
"""
import logging
import sys
import threading
import time

from . import db, storage, winutil
from .config import CFG

log = logging.getLogger("aidash.quota")
GB = 1024 ** 3
NO_LIMIT = "18446744073709551615"  # 0xFFFFFFFFFFFFFFFF, shown by NTFS as "No Limit"
MODES = ("soft", "hard", "grace")
MIN_GB = 1
# One evaluation at a time: the scheduler, "Re-evaluate now", policy save and
# policy delete can otherwise race and re-apply a limit that was just lifted.
_lock = threading.Lock()


def policies():
    return db.query("SELECT * FROM quota_policies ORDER BY volume, target = '*' DESC, target")


def _validate(target, volume, soft_gb, hard_gb, mode):
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    volume = volume.upper().rstrip("\\")
    if len(volume) != 2 or volume[1] != ":":
        raise ValueError("volume must look like C:")
    if mode == "hard" and not hard_gb:
        raise ValueError("hard mode needs a hard limit")
    if mode in ("soft", "grace") and not soft_gb:
        raise ValueError(f"{mode} mode needs a soft limit")
    for label, value in (("soft", soft_gb), ("hard", hard_gb)):
        if value and value < MIN_GB:
            raise ValueError(f"{label} limit must be at least {MIN_GB} GB")
    if soft_gb and hard_gb and soft_gb > hard_gb:
        raise ValueError("soft limit must not exceed hard limit")
    if target != "*":
        known = {u["name"].lower(): u["name"] for u in winutil.local_users()}
        if target.lower() not in known:
            raise ValueError(f"unknown local user {target}")
        target = known[target.lower()]
    return target, volume


def upsert_policy(target, volume, soft_gb, hard_gb, mode, grace_days, actor):
    target, volume = _validate(target, volume, soft_gb, hard_gb, mode)
    with db.write() as c:
        c.execute(
            """INSERT INTO quota_policies(target, volume, soft_gb, hard_gb, mode, grace_days, created_by, created_ts)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(target, volume) DO UPDATE SET soft_gb=excluded.soft_gb, hard_gb=excluded.hard_gb,
                   mode=excluded.mode, grace_days=excluded.grace_days, created_by=excluded.created_by,
                   created_ts=excluded.created_ts""",
            (target, volume, soft_gb or None, hard_gb or None, mode,
             grace_days if grace_days is not None else CFG["quota"]["grace_days"], actor, int(time.time())))
    return target, volume


def delete_policy(policy_id: int):
    pol = db.query_one("SELECT * FROM quota_policies WHERE id = ?", (policy_id,))
    if not pol:
        return None
    with db.write() as c:
        c.execute("DELETE FROM quota_policies WHERE id = ?", (policy_id,))
    evaluate()  # users that lost their policy get their NTFS entry reset
    return pol


def _wildcard_skip(users):
    """Accounts (lowercase) the '*' policy never covers: quota.exempt_users,
    administrators (direct or through a nested group) and service accounts."""
    skip = {u.lower() for u in CFG["quota"]["exempt_users"]}
    skip |= {a.lower() for a in winutil.admin_members()}
    skip |= {u.lower() for u in users if winutil.is_admin(u)}
    skip |= winutil.service_accounts()
    return skip


def _effective(volume, pols, users, skip):
    """username -> policy for this volume (specific target beats '*')."""
    wildcard = next((p for p in pols if p["volume"] == volume and p["target"] == "*"), None)
    specific = {p["target"].lower(): p for p in pols if p["volume"] == volume and p["target"] != "*"}
    out = {}
    for u in users:
        key = u.lower()
        if key in specific:
            out[u] = specific[key]
        elif wildcard and key not in skip:
            out[u] = wildcard
    return out


def _usage(key, vol, entry, home_by_user, profile_vol):
    if entry:
        return entry.get("used", 0)
    if vol == profile_vol:
        return home_by_user.get(key, 0)
    return 0


def _decide(pol, usage, over_since, now):
    """(threshold, limit, status, over_since) the policy asks for at this usage."""
    soft = pol["soft_gb"] * GB if pol["soft_gb"] else None
    hard = pol["hard_gb"] * GB if pol["hard_gb"] else None
    threshold = soft or hard
    limit = hard if pol["mode"] in ("hard", "grace") else None
    status = "ok"
    if soft and usage >= soft:
        over_since = over_since or now
        status = "warning"
        if pol["mode"] == "grace":
            if now >= over_since + (pol["grace_days"] or 0) * 86400:
                limit = min(soft, hard) if hard else soft
                status = "blocked"
            else:
                status = "grace"
    else:
        over_since = None
    if limit and usage >= limit:
        status = "blocked"
    elif hard and usage >= hard and pol["mode"] == "soft":
        status = "over-hard"
    return threshold, limit, status, over_since


def _set_ntfs(volume, user, threshold, limit):
    acct = f"{winutil.computer_name()}\\{user}"
    code, out = storage.fsutil("quota", "modify", volume,
                               str(int(threshold)) if threshold else NO_LIMIT,
                               str(int(limit)) if limit else NO_LIMIT, acct)
    if code != 0:
        log.error("fsutil quota modify %s %s failed: %s", volume, acct, out.strip())
    return code == 0


def _ensure_volume(volume, needs_enforce):
    """Turn on tracking, or enforcement when a policy needs it.

    Returns (enforcing, reason): whether NTFS is enforcing limits on the volume,
    and why the dashboard must not set limits there (None when it may)."""
    st = storage.quota_state(volume)
    if not st["enabled"]:
        code, out = storage.fsutil("quota", "track", volume)
        log.warning("enabled NTFS quota tracking on %s: %s", volume, out.strip())
        st = storage.quota_state(volume)
    if not needs_enforce:
        return st["enforced"], None
    if not st["defaults_ok"]:
        reason = (f"the default quota limit on {volume} is not 'No limit' (or could not be read), so enforcing "
                  "would limit every account; run setup-quotas.ps1 -Action Enforce to reset it")
        log.error("not setting quota limits: %s", reason)
        return st["enforced"], reason
    if not st["enforced"]:
        code, out = storage.fsutil("quota", "enforce", volume)
        if code != 0:
            log.error("fsutil quota enforce %s failed: %s", volume, out.strip())
            return False, f"turning on enforcement for {volume} failed; see dashboard.log"
        log.warning("enabled NTFS quota enforcement on %s: %s", volume, out.strip())
    return True, None


def _release(volume, prev, entry, exists):
    """Lift the threshold/limit set for a user who no longer has a policy here.
    The state row stays until the lift succeeds, so a failure is retried."""
    if not exists:
        log.warning("account %s no longer exists; dropping its quota state on %s", prev["username"], volume)
    elif entry is None or entry.get("limit") or entry.get("threshold"):
        if not _set_ntfs(volume, prev["username"], None, None):
            return
    with db.write() as c:
        c.execute("DELETE FROM quota_state WHERE username = ? AND volume = ?", (prev["username"], volume))


def _notify(user, text):
    sent = False
    for s in winutil.sessions():
        if s["username"].lower() == user.lower():
            sent = winutil.send_message(s["session_id"], "Storage quota notice", text) or sent
    return sent


def evaluate():
    """Recompute every user's quota status and reconcile NTFS entries."""
    with _lock:
        _evaluate()


def _evaluate():
    pols = policies()
    accounts = winutil.local_users()
    existing = {u["name"].lower() for u in accounts}
    users = [u["name"] for u in accounts if not u["disabled"]]
    states = {(r["username"].lower(), r["volume"]): r for r in db.query("SELECT * FROM quota_state")}
    now = int(time.time())
    qcfg = CFG["quota"]
    volumes = {p["volume"] for p in pols} | {v for (_u, v) in states}
    skip = _wildcard_skip(users) if any(p["target"] == "*" for p in pols) else set()
    vm = storage.vm_disks() if qcfg["protect_vm_disks"] and any(p["mode"] != "soft" for p in pols) else {}

    homes, _ = storage.latest_storage()
    home_by_user = {h["username"].lower(): h["size_bytes"] for h in homes}
    profile_vol = str(storage.profile_root())[:2].upper()

    for vol in sorted(volumes):
        eff = _effective(vol, pols, users, skip)
        enforcing, not_enforceable = False, None
        if eff:
            enforcing, not_enforceable = _ensure_volume(vol, any(p["mode"] in ("hard", "grace") for p in eff.values()))
        entries = {e["username"].lower(): e for e in storage.quota_entries(vol)}

        # Policy removed, account disabled or deleted: lift any limit we set.
        covered = {u.lower() for u in eff}
        for (key, v), prev in states.items():
            if v == vol and key not in covered:
                _release(vol, prev, entries.get(key), key in existing)

        for user, pol in eff.items():
            key = user.lower()
            prev = states.get((key, vol))
            entry = entries.get(key)
            usage = _usage(key, vol, entry, home_by_user, profile_vol)
            threshold, limit, status, over_since = _decide(pol, usage, prev["over_since"] if prev else None, now)
            soft = pol["soft_gb"] * GB if pol["soft_gb"] else None
            hard = pol["hard_gb"] * GB if pol["hard_gb"] else None
            last_notified = prev["last_notified"] if prev else None

            note = None
            if limit and vol in vm.get(key, ()):
                limit, note = None, "has a WSL/Docker virtual disk on this drive: warned, never blocked"
            elif limit and not_enforceable:
                limit, note = None, f"not enforced: {not_enforceable}"

            cur_t = entry.get("threshold") if entry else None
            cur_l = entry.get("limit") if entry else None
            enforced = cur_l
            if (cur_t or None) != (int(threshold) if threshold else None) or \
               (cur_l or None) != (int(limit) if limit else None):
                if _set_ntfs(vol, user, threshold, limit):
                    enforced = int(limit) if limit else None
                else:
                    note = "fsutil could not update this user's quota entry; see dashboard.log"

            # Only report 'blocked' when NTFS really enforces a limit the user is at.
            if status == "blocked" and not (enforcing and enforced and usage >= enforced):
                status = "vm-protected" if vol in vm.get(key, ()) else "not-enforced"

            if status != "ok" and qcfg["notify_users"] and \
               (not last_notified or now - last_notified >= qcfg["notify_repeat_hours"] * 3600):
                msg = _message(user, vol, usage, soft or hard, enforced, status, over_since, pol,
                               can_block=note is None)
                _notify(user, msg)
                winutil.write_event(3002 if status == "blocked" else 3001, msg,
                                    "error" if status == "blocked" else "warning")
                last_notified = now

            with db.write() as c:
                c.execute(
                    """INSERT OR REPLACE INTO quota_state(username, volume, status, usage_bytes, soft_bytes,
                       hard_bytes, over_since, last_notified, enforced_limit, updated, note)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (user, vol, status, usage, int(soft) if soft else None, int(hard) if hard else None,
                     over_since, last_notified, enforced if enforcing else None, now, note))


def _message(user, vol, usage, level, limit, status, over_since, pol, can_block=True):
    used = f"{usage / GB:.1f} GB"
    if status == "blocked":
        return (f"{user}: you are using {used} on {vol}, at or above your {limit / GB:.0f} GB limit. "
                "New writes to this drive are blocked. You can still read and delete files; "
                "writing is allowed again once you are under the limit.")
    if status == "grace" and can_block:
        deadline = time.strftime("%Y-%m-%d %H:%M", time.localtime(over_since + pol["grace_days"] * 86400))
        return (f"{user}: you are using {used} on {vol}, above the {level / GB:.0f} GB soft limit. "
                f"Please delete or move files. If you are still over on {deadline}, new writes will be blocked.")
    return (f"{user}: you are using {used} on {vol}, above the {level / GB:.0f} GB storage guideline. "
            "Please clean up files you no longer need.")


def preview(target, volume, soft_gb, hard_gb, mode, grace_days):
    """What saving this policy would do right now. Reads only; changes nothing."""
    target, volume = _validate(target, volume, soft_gb, hard_gb, mode)
    grace_days = grace_days if grace_days is not None else CFG["quota"]["grace_days"]
    pol = {"target": target, "volume": volume, "soft_gb": soft_gb or None, "hard_gb": hard_gb or None,
           "mode": mode, "grace_days": grace_days}
    pols = [p for p in policies() if (p["target"], p["volume"]) != (target, volume)] + [pol]
    users = [u["name"] for u in winutil.local_users() if not u["disabled"]]
    skip = _wildcard_skip(users)
    eff = _effective(volume, pols, users, skip)
    entries = {e["username"].lower(): e for e in storage.quota_entries(volume)}
    states = {r["username"].lower(): r for r in db.query("SELECT * FROM quota_state WHERE volume = ?", (volume,))}
    vm = storage.vm_disks() if CFG["quota"]["protect_vm_disks"] and mode != "soft" else {}
    homes, _ = storage.latest_storage()
    home_by_user = {h["username"].lower(): h["size_bytes"] for h in homes}
    profile_vol = str(storage.profile_root())[:2].upper()
    now = int(time.time())

    out = {"total": 0, "blocked_now": [], "grace": [], "warned": [], "vm_protected": [], "ok": 0,
           "exempt": [], "overridden": [], "volume_problem": None}
    for user in users:
        key = user.lower()
        if eff.get(user) is not pol:
            if target == "*" and key in skip:
                out["exempt"].append(user)
            elif target == "*" and user in eff:
                out["overridden"].append(user)
            continue
        out["total"] += 1
        prev = states.get(key)
        usage = _usage(key, volume, entries.get(key), home_by_user, profile_vol)
        _t, limit, status, over_since = _decide(pol, usage, prev["over_since"] if prev else None, now)
        row = {"user": user, "usage_gb": round(usage / GB, 1)}
        if limit and volume in vm.get(key, ()):
            out["vm_protected"].append(row)
        elif status == "blocked":
            out["blocked_now"].append(row)
        elif status == "grace":
            row["until"] = int(over_since + grace_days * 86400)
            out["grace"].append(row)
        elif status != "ok":
            out["warned"].append(row)
        else:
            out["ok"] += 1
    if mode != "soft":
        st = storage.quota_state(volume)
        if st["enabled"] and not st["defaults_ok"]:
            out["volume_problem"] = (f"The default quota limit on {volume} is not 'No limit'. The dashboard will not "
                                     "turn on enforcement until it is reset (setup-quotas.ps1 -Action Enforce).")
    return out


def release_all():
    """Lift every threshold/limit the dashboard set (uninstall.ps1). Policies are kept."""
    with _lock:
        rows = db.query("SELECT * FROM quota_state")
        lifted = 0
        for r in rows:
            if _set_ntfs(r["volume"], r["username"], None, None):
                lifted += 1
                with db.write() as c:
                    c.execute("DELETE FROM quota_state WHERE username = ? AND volume = ?", (r["username"], r["volume"]))
        return lifted, len(rows)


def status_rows():
    return db.query("SELECT * FROM quota_state ORDER BY volume, usage_bytes DESC")


def volume_status():
    return {v: storage.quota_state(v) for v in storage.quota_volumes()}


if __name__ == "__main__" and sys.argv[1:] == ["release"]:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    done, total = release_all()
    print(f"Lifted {done} of {total} quota entries set by the dashboard.")
    sys.exit(0 if done == total else 1)

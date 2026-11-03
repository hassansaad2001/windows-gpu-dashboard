"""Restart / shutdown history from the System event log.

Each boot (Kernel-General 12) is paired with what ended the previous run:
  * User32 1074          planned restart/shutdown, with process, reason and user
  * Kernel-Power 41 +    unexpected stop: bugcheck code -> crash, power-button
    EventLog 6008        timestamp -> forced power-off, otherwise power loss / hang
  * User32 1076          reason an admin entered afterwards for an unexpected stop
  * Kernel-General 13    clean OS shutdown with no recorded initiator
Rows are stored by boot time, so history survives System log rollover.
"""
import logging
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import win32evtlog

from . import db

log = logging.getLogger("aidash.events")
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

XPATH = ("*[System[(EventID=12 or EventID=13 or EventID=41 or EventID=1074 "
         "or EventID=1076 or EventID=6008)]]")


def _ts(iso: str) -> float:
    iso = iso.rstrip("Z")
    if "." in iso:
        head, frac = iso.split(".")
        iso = f"{head}.{frac[:6]}"
    return datetime.fromisoformat(iso).replace(tzinfo=timezone.utc).timestamp()


def _parse(xml: str) -> dict:
    root = ET.fromstring(xml)
    sysn = root.find("e:System", NS)
    ev = {
        "id": int(sysn.find("e:EventID", NS).text),
        "provider": sysn.find("e:Provider", NS).get("Name"),
        "ts": _ts(sysn.find("e:TimeCreated", NS).get("SystemTime")),
        "sid": (sysn.find("e:Security", NS).get("UserID") or ""),
        "data": {}, "list": [], "binary": None,
    }
    ed = root.find("e:EventData", NS)
    if ed is not None:
        for d in ed.findall("e:Data", NS):
            text = (d.text or "").replace("‎", "").strip()
            if d.get("Name"):
                ev["data"][d.get("Name")] = text
            ev["list"].append(text)
        b = ed.find("e:Binary", NS)
        if b is not None and b.text:
            ev["binary"] = b.text
    return ev


def _systemtime_utc(binary_hex: str):
    """6008 binary holds two SYSTEMTIMEs (local, then UTC) for the lost shutdown."""
    try:
        raw = bytes.fromhex(binary_hex)
        y, mo, _dow, d, h, mi, s, ms = struct.unpack_from("<8H", raw, 16)
        return datetime(y, mo, d, h, mi, s, ms * 1000, tzinfo=timezone.utc).timestamp()
    except (ValueError, struct.error):
        return None


def read_events(limit=4000):
    h = win32evtlog.EvtQuery("System", win32evtlog.EvtQueryReverseDirection, XPATH)
    out = []
    while len(out) < limit:
        batch = win32evtlog.EvtNext(h, 200)
        if not batch:
            break
        for e in batch:
            try:
                out.append(_parse(win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)))
            except Exception as ex:
                log.debug("skip event: %s", ex)
    out.sort(key=lambda e: e["ts"])
    return out


def build_restarts(events):
    boots = [e for e in events if e["id"] == 12 and e["provider"] == "Microsoft-Windows-Kernel-General"]
    results = []
    prev_boot = 0
    for b in boots:
        boot_ts = _ts(b["data"]["StartTime"]) if b["data"].get("StartTime") else b["ts"]
        before = [e for e in events if prev_boot < e["ts"] < boot_ts]
        after = [e for e in events if boot_ts - 60 <= e["ts"] <= boot_ts + 900]
        rec = {"boot_ts": int(boot_ts), "shutdown_ts": None, "kind": "Unknown", "cause": "",
               "username": "", "process": "", "reason": "", "comment": ""}

        planned = [e for e in before if e["id"] == 1074]
        clean = [e for e in before if e["id"] == 13 and e["provider"] == "Microsoft-Windows-Kernel-General"]
        kp41 = next((e for e in after if e["id"] == 41), None)
        ev6008 = next((e for e in after if e["id"] == 6008), None)

        if planned:
            p = planned[-1]["data"]
            rec.update(
                kind="Planned " + (p.get("param5") or "restart").lower(),
                cause="User/process initiated",
                username=p.get("param7", ""),
                process=p.get("param1", "").split(" (")[0],
                reason=p.get("param3", ""),
                comment=p.get("param6", ""),
                shutdown_ts=int(clean[-1]["ts"]) if clean else int(planned[-1]["ts"]),
            )
        elif kp41 or ev6008:
            d = kp41["data"] if kp41 else {}
            bug = int(d.get("BugcheckCode", "0") or 0)
            if bug:
                rec.update(kind="Unexpected", cause=f"System crash (bugcheck 0x{bug:X})")
            elif d.get("PowerButtonTimestamp", "0") not in ("0", "") or d.get("LongPowerButtonPressDetected") == "true":
                rec.update(kind="Unexpected", cause="Forced power-off (power button)")
            else:
                rec.update(kind="Unexpected", cause="Power failure or hard hang (no clean shutdown)")
            if ev6008 and ev6008["binary"]:
                t = _systemtime_utc(ev6008["binary"])
                rec["shutdown_ts"] = int(t) if t else None
            explained = next((e for e in events if e["id"] == 1076 and e["ts"] >= boot_ts - 60), None)
            if explained:
                vals = explained["data"] or {}
                lst = list(vals.values()) or explained["list"]
                rec["reason"] = lst[0] if lst else ""
                rec["username"] = next((v for v in lst if "\\" in v), "")
                rec["comment"] = vals.get("param5", "")
            rec["username"] = rec["username"] or "—"
        elif clean:
            rec.update(kind="Clean shutdown", cause="Initiator not recorded",
                       shutdown_ts=int(clean[-1]["ts"]))
        results.append(rec)
        prev_boot = boot_ts
    return results


def collect():
    events = read_events()
    restarts = build_restarts(events)
    with db.write() as c:
        c.executemany(
            """INSERT INTO restarts(boot_ts, shutdown_ts, kind, cause, username, process, reason, comment)
               VALUES (:boot_ts, :shutdown_ts, :kind, :cause, :username, :process, :reason, :comment)
               ON CONFLICT(boot_ts) DO UPDATE SET
                   shutdown_ts=excluded.shutdown_ts, kind=excluded.kind, cause=excluded.cause,
                   username=excluded.username, process=excluded.process,
                   reason=excluded.reason, comment=excluded.comment
               WHERE excluded.kind != 'Unknown'""",  # don't lose detail once older events roll off
            restarts)
    log.info("restart history: %d boots parsed", len(restarts))
    return len(restarts)


def last_restarts(n=10):
    return db.query("SELECT * FROM restarts ORDER BY boot_ts DESC LIMIT ?", (n,))

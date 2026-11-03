"""Background jobs: each runs in its own daemon thread on a fixed interval."""
import logging
import threading
import time

from . import db, events, metrics, processes, quota, storage
from .config import CFG

log = logging.getLogger("aidash.sched")
_stop = threading.Event()
status = {}


def _loop(name, interval_s, fn, initial_delay=0):
    if _stop.wait(initial_delay):
        return
    while not _stop.is_set():
        t0 = time.time()
        try:
            fn()
            status[name] = {"last_run": int(t0), "seconds": round(time.time() - t0, 2), "error": None}
        except Exception as e:
            log.exception("job %s failed", name)
            status[name] = {"last_run": int(t0), "seconds": round(time.time() - t0, 2), "error": str(e)}
        _stop.wait(max(1, interval_s - (time.time() - t0)))


def _storage():
    storage.scan_homes()
    storage.collect_ntfs_usage()


def start():
    iv = CFG["intervals"]
    metrics.prime()
    jobs = [
        ("metrics", iv["sample_seconds"], metrics.sample_once, 2),
        ("rogue", iv["rogue_scan_minutes"] * 60, processes.scan, 10),
        ("events", iv["events_minutes"] * 60, events.collect, 5),
        ("storage", iv["storage_scan_minutes"] * 60, _storage, 20),
        ("quota", iv["quota_check_minutes"] * 60, quota.evaluate, 120),
        ("prune", 6 * 3600, db.prune, 300),
    ]
    for name, interval, fn, delay in jobs:
        threading.Thread(target=_loop, args=(name, interval, fn, delay), name=f"job-{name}", daemon=True).start()
    log.info("scheduler started: %s", ", ".join(j[0] for j in jobs))


def run_now(name):
    fn = {"rogue": processes.scan, "events": events.collect, "storage": _storage,
          "quota": quota.evaluate, "metrics": metrics.sample_once}[name]
    threading.Thread(target=_loop_once, args=(name, fn), daemon=True).start()


def _loop_once(name, fn):
    t0 = time.time()
    try:
        fn()
        status[name] = {"last_run": int(t0), "seconds": round(time.time() - t0, 2), "error": None}
    except Exception as e:
        log.exception("job %s failed", name)
        status[name] = {"last_run": int(t0), "seconds": round(time.time() - t0, 2), "error": str(e)}


def stop():
    _stop.set()

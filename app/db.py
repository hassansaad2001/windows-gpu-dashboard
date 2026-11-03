"""SQLite persistence (server_stats.db).

All timestamps are UTC unix seconds. One connection per call keeps the code
thread-safe; WAL mode lets the web server read while collectors write.
"""
import sqlite3
import threading
import time
from contextlib import contextmanager

from .config import CFG, resolve

DB_PATH = resolve(CFG["database"])
_write_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS metrics_raw (
    ts INTEGER NOT NULL, cpu REAL, ram REAL, gpu REAL, gpu_mem REAL
);
CREATE INDEX IF NOT EXISTS ix_metrics_raw_ts ON metrics_raw(ts);

CREATE TABLE IF NOT EXISTS gpu_raw (
    ts INTEGER NOT NULL, gpu_index INTEGER, util REAL, mem_mb REAL, temp REAL, power_w REAL
);
CREATE INDEX IF NOT EXISTS ix_gpu_raw_ts ON gpu_raw(ts);

CREATE TABLE IF NOT EXISTS metrics_hourly (
    hour_ts INTEGER PRIMARY KEY,
    cpu_avg REAL, cpu_max REAL, ram_avg REAL, ram_max REAL,
    gpu_avg REAL, gpu_max REAL, gpu_mem_avg REAL, samples INTEGER
);

CREATE TABLE IF NOT EXISTS gpu_hourly (
    hour_ts INTEGER, gpu_index INTEGER, util_avg REAL, mem_avg_mb REAL, temp_max REAL,
    PRIMARY KEY (hour_ts, gpu_index)
);

CREATE TABLE IF NOT EXISTS storage_snapshots (
    ts INTEGER NOT NULL, username TEXT, sid TEXT, folder TEXT,
    size_bytes INTEGER, file_count INTEGER, scan_seconds REAL, error TEXT
);
CREATE INDEX IF NOT EXISTS ix_storage_ts ON storage_snapshots(ts);

CREATE TABLE IF NOT EXISTS ntfs_usage (
    ts INTEGER NOT NULL, volume TEXT, username TEXT, sid TEXT,
    used_bytes INTEGER, threshold_bytes INTEGER, limit_bytes INTEGER
);
CREATE INDEX IF NOT EXISTS ix_ntfs_ts ON ntfs_usage(ts);

CREATE TABLE IF NOT EXISTS restarts (
    boot_ts INTEGER PRIMARY KEY,
    shutdown_ts INTEGER, kind TEXT, cause TEXT, username TEXT,
    process TEXT, reason TEXT, comment TEXT
);

CREATE TABLE IF NOT EXISTS rogue_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER, create_time REAL, username TEXT, name TEXT, session_id INTEGER,
    severity TEXT, reasons TEXT, gpu_mem_mb REAL, gpus TEXT, cpu_pct REAL, rss_mb REAL,
    cmdline TEXT, first_seen INTEGER, last_seen INTEGER, ended INTEGER, action TEXT,
    UNIQUE (pid, create_time)
);

CREATE TABLE IF NOT EXISTS quota_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,            -- '*' = all non-exempt users
    volume TEXT NOT NULL,
    soft_gb REAL, hard_gb REAL,
    mode TEXT NOT NULL,              -- soft | grace | hard
    grace_days REAL,
    created_by TEXT, created_ts INTEGER,
    UNIQUE (target, volume)
);

CREATE TABLE IF NOT EXISTS quota_state (
    username TEXT, volume TEXT,
    status TEXT, usage_bytes INTEGER, soft_bytes INTEGER, hard_bytes INTEGER,
    over_since INTEGER, last_notified INTEGER, enforced_limit INTEGER, updated INTEGER,
    note TEXT,
    PRIMARY KEY (username, volume)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER, actor TEXT, ip TEXT, action TEXT, target TEXT, detail TEXT, ok INTEGER
);

CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with write() as c:
        c.executescript(SCHEMA)
        # Columns added after the first release (databases created before them).
        for table, column in (("quota_state", "note TEXT"),):
            try:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass  # already there


@contextmanager
def write():
    with _write_lock:
        conn = connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def query(sql, params=()):
    conn = connect()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def query_one(sql, params=()):
    rows = query(sql, params)
    return rows[0] if rows else None


def kv_set(key, value):
    with write() as c:
        c.execute("INSERT OR REPLACE INTO kv(k, v) VALUES (?, ?)", (key, str(value)))


def kv_get(key, default=None):
    row = query_one("SELECT v FROM kv WHERE k = ?", (key,))
    return row["v"] if row else default


def audit(actor, ip, action, target, detail="", ok=True):
    with write() as c:
        c.execute(
            "INSERT INTO audit_log(ts, actor, ip, action, target, detail, ok) VALUES (?,?,?,?,?,?,?)",
            (int(time.time()), actor, ip, action, target, detail, 1 if ok else 0),
        )


def prune():
    cfg = CFG["retention"]
    now = int(time.time())
    with write() as c:
        c.execute("DELETE FROM metrics_raw WHERE ts < ?", (now - cfg["raw_days"] * 86400,))
        c.execute("DELETE FROM gpu_raw WHERE ts < ?", (now - cfg["raw_days"] * 86400,))
        c.execute("DELETE FROM metrics_hourly WHERE hour_ts < ?", (now - cfg["hourly_days"] * 86400,))
        c.execute("DELETE FROM gpu_hourly WHERE hour_ts < ?", (now - cfg["hourly_days"] * 86400,))
        # Keep one storage snapshot per day after 30 days.
        c.execute(
            """DELETE FROM storage_snapshots WHERE ts < ? AND ts NOT IN (
                   SELECT MAX(ts) FROM storage_snapshots GROUP BY ts / 86400)""",
            (now - 30 * 86400,),
        )
        c.execute("DELETE FROM ntfs_usage WHERE ts < ?", (now - 90 * 86400,))
        c.execute("DELETE FROM rogue_events WHERE last_seen < ?", (now - 180 * 86400,))

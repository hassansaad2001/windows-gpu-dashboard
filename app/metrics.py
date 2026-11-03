"""CPU / RAM / GPU sampling.

* Adapter-level GPU stats come from nvidia-smi.
* Per-process GPU usage comes from the Windows "GPU Process Memory" and
  "GPU Engine" performance counters. GeForce cards run in WDDM mode on
  Windows, where nvidia-smi/NVML cannot attribute memory to processes, but
  the WDDM counters can. Counter instances are keyed by adapter LUID, which
  is mapped back to the nvidia-smi index by aligning per-adapter memory use.
"""
import ctypes
import logging
import re
import subprocess
import threading
import time
from ctypes import wintypes as wt

import psutil
import win32pdh

from . import db

log = logging.getLogger("aidash.metrics")
CREATE_NO_WINDOW = 0x08000000


# ------------------------------------------------------------ PDH arrays
# win32pdh.GetFormattedCounterArray returns a dict keyed by instance name, so
# instances that share a name overwrite each other. A WSL/Hyper-V VM worker
# (vmwp.exe) exposes ~30 same-named instances per adapter, and the one holding
# the VRAM is usually lost. Read the raw array instead and sum duplicates.

class _PdhValue(ctypes.Union):
    _fields_ = [("long", ctypes.c_long), ("double", ctypes.c_double), ("large", ctypes.c_longlong)]


class _PdhFmtValue(ctypes.Structure):
    _fields_ = [("CStatus", wt.DWORD), ("u", _PdhValue)]


class _PdhItem(ctypes.Structure):
    _fields_ = [("szName", wt.LPWSTR), ("FmtValue", _PdhFmtValue)]


_pdh = ctypes.WinDLL("pdh.dll")
_pdh.PdhGetFormattedCounterArrayW.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD),
                                             ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
_pdh.PdhGetFormattedCounterArrayW.restype = wt.LONG
_PDH_MORE_DATA = ctypes.c_long(0x800007D2).value


def _counter_array(counter, fmt) -> dict:
    """instance name -> value, summed over same-named instances (valid data only)."""
    size, count = wt.DWORD(0), wt.DWORD(0)
    h = ctypes.c_void_p(int(counter))
    rc = _pdh.PdhGetFormattedCounterArrayW(h, fmt, ctypes.byref(size), ctypes.byref(count), None)
    if rc != _PDH_MORE_DATA:
        raise OSError(f"PdhGetFormattedCounterArray: 0x{rc & 0xFFFFFFFF:08x}")
    buf = ctypes.create_string_buffer(size.value)
    rc = _pdh.PdhGetFormattedCounterArrayW(h, fmt, ctypes.byref(size), ctypes.byref(count), buf)
    if rc != 0:
        raise OSError(f"PdhGetFormattedCounterArray: 0x{rc & 0xFFFFFFFF:08x}")
    field = "double" if fmt & win32pdh.PDH_FMT_DOUBLE else "large"
    out = {}
    for it in ctypes.cast(buf, ctypes.POINTER(_PdhItem))[:count.value]:
        if it.FmtValue.CStatus in (0, 1):  # PDH_CSTATUS_VALID_DATA / NEW_DATA
            out[it.szName] = out.get(it.szName, 0) + getattr(it.FmtValue.u, field)
    return out

_live_lock = threading.Lock()
_live = {"ts": None, "cpu": None, "ram": None, "gpu": None, "gpus": []}


def _num(v):
    v = v.strip()
    try:
        return float(v)
    except ValueError:
        return None  # "[N/A]", "[Not Supported]"


def nvidia_smi():
    fields = "index,name,uuid,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,fan.speed"
    try:
        out = subprocess.run(
            ["nvidia-smi", f"--query-gpu={fields}", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=20, creationflags=CREATE_NO_WINDOW,
        ).stdout
    except (OSError, subprocess.TimeoutExpired) as e:
        log.warning("nvidia-smi failed: %s", e)
        return []
    gpus = []
    for line in out.strip().splitlines():
        p = [x.strip() for x in line.split(",")]
        if len(p) < 9:
            continue
        gpus.append({
            "index": int(p[0]), "name": p[1], "uuid": p[2],
            "util": _num(p[3]), "mem_used_mb": _num(p[4]), "mem_total_mb": _num(p[5]),
            "temp": _num(p[6]), "power_w": _num(p[7]), "fan": _num(p[8]),
        })
    return gpus


# ------------------------------------------------------------ per-process GPU

_INST = re.compile(r"pid_(\d+)_luid_(0x[0-9a-f]+_0x[0-9a-f]+)_phys_\d+(?:.*engtype_(.*))?", re.I)
_ADAPTER = re.compile(r"luid_(0x[0-9a-f]+_0x[0-9a-f]+)_phys_\d+", re.I)


def _luid_key(luid: str):
    hi, lo = luid.lower().split("_")
    return (int(hi, 16) << 32) | int(lo, 16)


def map_luids(adapter_mem: dict, gpus: list) -> dict:
    """Map LUID -> nvidia-smi index.

    Adapters enumerate in the same order as nvidia-smi indices, but the
    counters may include extra adapters (e.g. Microsoft Basic Render). An
    order-preserving alignment that minimises the memory difference picks
    which LUIDs are the NVIDIA cards.
    """
    luids = sorted(adapter_mem, key=_luid_key)
    gl = sorted(gpus, key=lambda g: g["index"])
    n, m = len(luids), len(gl)
    if not n or not m:
        return {}
    if n <= m:
        return {l: gl[i]["index"] for i, l in enumerate(luids)}
    inf = float("inf")
    # cost[i][j]: best cost aligning first i luids with first j gpus
    cost = [[inf] * (m + 1) for _ in range(n + 1)]
    take = [[False] * (m + 1) for _ in range(n + 1)]
    for i in range(n + 1):
        cost[i][0] = 0
    for i in range(1, n + 1):
        for j in range(1, min(i, m) + 1):
            skip = cost[i - 1][j]
            use = cost[i - 1][j - 1] + abs(adapter_mem[luids[i - 1]] / 2**20 - (gl[j - 1]["mem_used_mb"] or 0))
            if use <= skip:
                cost[i][j], take[i][j] = use, True
            else:
                cost[i][j] = skip
    out, i, j = {}, n, m
    while i > 0 and j > 0:
        if take[i][j]:
            out[luids[i - 1]] = gl[j - 1]["index"]
            j -= 1
        i -= 1
    return out


class GpuProcessCounters:
    def __init__(self):
        self._lock = threading.Lock()
        self._q = None

    def _open(self):
        self._q = win32pdh.OpenQuery()
        self._mem = win32pdh.AddEnglishCounter(self._q, r"\GPU Process Memory(*)\Dedicated Usage")
        self._eng = win32pdh.AddEnglishCounter(self._q, r"\GPU Engine(*)\Utilization Percentage")
        self._adp = win32pdh.AddEnglishCounter(self._q, r"\GPU Adapter Memory(*)\Dedicated Usage")
        win32pdh.CollectQueryData(self._q)
        time.sleep(1)

    def sample(self, gpus: list) -> dict:
        """pid -> {"mem_mb": total, "gpus": {index: {"mem_mb", "util"}}}"""
        with self._lock:
            try:
                if self._q is None:
                    self._open()
                win32pdh.CollectQueryData(self._q)
                mem = _counter_array(self._mem, win32pdh.PDH_FMT_LARGE)
                adp = _counter_array(self._adp, win32pdh.PDH_FMT_LARGE)
                try:
                    eng = _counter_array(self._eng, win32pdh.PDH_FMT_DOUBLE | win32pdh.PDH_FMT_NOCAP100)
                except OSError:
                    eng = {}
            except Exception as e:
                log.warning("GPU counters unavailable: %s", e)
                self._q = None
                return {}

        adapter_mem = {}
        for inst, v in adp.items():
            m = _ADAPTER.search(inst)
            if m:
                adapter_mem[m.group(1).lower()] = v
        luid_idx = map_luids(adapter_mem, gpus)

        procs = {}

        def slot(pid, luid):
            idx = luid_idx.get(luid.lower())
            if idx is None:
                return None
            p = procs.setdefault(pid, {"mem_mb": 0.0, "gpus": {}})
            return p["gpus"].setdefault(idx, {"mem_mb": 0.0, "util": 0.0, "_eng": {}})

        for inst, v in mem.items():
            m = _INST.match(inst)
            if m and v > 0:
                s = slot(int(m.group(1)), m.group(2))
                if s is not None:
                    s["mem_mb"] += v / 2**20
        for inst, v in eng.items():
            m = _INST.match(inst)
            if m and m.group(3) and v > 0:
                s = slot(int(m.group(1)), m.group(2))
                if s is not None:
                    s["_eng"][m.group(3)] = s["_eng"].get(m.group(3), 0) + v

        for pid, p in procs.items():
            for g in p["gpus"].values():
                g["util"] = round(min(100.0, max(g.pop("_eng").values(), default=0.0)), 1)
                g["mem_mb"] = round(g["mem_mb"], 1)
            p["gpus"] = {i: g for i, g in p["gpus"].items() if g["mem_mb"] >= 1 or g["util"] >= 0.5}
            p["mem_mb"] = round(sum(g["mem_mb"] for g in p["gpus"].values()), 1)
        # Drop desktop/compositor noise (tiny allocations, no compute).
        return {pid: p for pid, p in procs.items()
                if p["mem_mb"] >= 64 or any(g["util"] >= 1 for g in p["gpus"].values())}


gpu_counters = GpuProcessCounters()


# ------------------------------------------------------------ sampling loop

def live():
    with _live_lock:
        return dict(_live)


def prime():
    psutil.cpu_percent(interval=None)


def sample_once():
    """Take one sample, persist it and refresh the current hour's aggregates."""
    now = int(time.time())
    cpu = psutil.cpu_percent(interval=None)  # average since the previous call
    ram = psutil.virtual_memory().percent
    gpus = nvidia_smi()
    utils = [g["util"] for g in gpus if g["util"] is not None]
    gpu_avg = round(sum(utils) / len(utils), 1) if utils else None
    mems = [g["mem_used_mb"] / g["mem_total_mb"] * 100 for g in gpus if g["mem_total_mb"]]
    gpu_mem = round(sum(mems) / len(mems), 1) if mems else None

    with _live_lock:
        _live.update(ts=now, cpu=cpu, ram=ram, gpu=gpu_avg, gpu_mem=gpu_mem, gpus=gpus)

    hour = now - now % 3600
    with db.write() as c:
        c.execute("INSERT INTO metrics_raw(ts, cpu, ram, gpu, gpu_mem) VALUES (?,?,?,?,?)",
                  (now, cpu, ram, gpu_avg, gpu_mem))
        c.executemany(
            "INSERT INTO gpu_raw(ts, gpu_index, util, mem_mb, temp, power_w) VALUES (?,?,?,?,?,?)",
            [(now, g["index"], g["util"], g["mem_used_mb"], g["temp"], g["power_w"]) for g in gpus])
        c.execute(
            """INSERT OR REPLACE INTO metrics_hourly
               SELECT ?, AVG(cpu), MAX(cpu), AVG(ram), MAX(ram), AVG(gpu), MAX(gpu), AVG(gpu_mem), COUNT(*)
               FROM metrics_raw WHERE ts >= ? AND ts < ?""", (hour, hour, hour + 3600))
        c.execute(
            """INSERT OR REPLACE INTO gpu_hourly
               SELECT ?, gpu_index, AVG(util), AVG(mem_mb), MAX(temp)
               FROM gpu_raw WHERE ts >= ? AND ts < ? GROUP BY gpu_index""", (hour, hour, hour + 3600))

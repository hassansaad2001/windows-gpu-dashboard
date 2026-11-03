"""Configuration loading.

Settings live in config.json next to the app folder (or the path in the
AIDASH_CONFIG environment variable). Missing keys fall back to DEFAULTS, so an
upgraded install keeps working with an older config file.
"""
import copy
import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DEFAULTS = {
    "host": "0.0.0.0",
    "port": 8443,
    "https": True,
    "cert_file": "certs/server.crt",
    "key_file": "certs/server.key",
    "database": "data/server_stats.db",
    "log_dir": "logs",

    # Anyone on the LAN may view the dashboard without logging in. Admin
    # actions always require a Windows Administrators login.
    "public_read": False,
    "session_hours": 8,
    # Only these Windows accounts may sign in (case-insensitive). Empty = any
    # enabled local account. Other accounts' passwords are never checked.
    "allowed_users": [],

    "intervals": {
        "sample_seconds": 60,          # CPU/RAM/GPU sample rate (aggregated hourly)
        "storage_scan_minutes": 60,    # home-directory size scan
        "events_minutes": 60,          # restart/shutdown event parsing
        "rogue_scan_minutes": 5,       # rogue/orphaned process detection
        "quota_check_minutes": 60,     # quota evaluation + escalation
    },

    "retention": {
        "raw_days": 7,                 # per-minute samples
        "hourly_days": 730,            # hourly aggregates
    },

    "storage": {
        # Profile folders are mapped to accounts through the registry ProfileList.
        # Empty = the folder Windows keeps profiles in (ProfilesDirectory, usually C:\Users).
        "profile_root": "",
        "skip_folders": ["Public", "Default", "Default User", "All Users"],
        "scan_threads": 4,
        # Volumes whose NTFS per-owner usage is read with fsutil (needs quota tracking on).
        # Empty = every fixed NTFS volume, e.g. ["C:", "D:"].
        "quota_volumes": [],
    },

    "quota": {
        "default_volume": "C:",
        "grace_days": 7,
        "notify_users": True,          # msg.exe popup to the user's sessions
        "notify_repeat_hours": 24,
        "exempt_users": ["Administrator"],
        # Never set an NTFS limit for a user whose WSL/Docker .vhdx is on that
        # volume: a Linux disk that cannot grow can be corrupted. They are warned only.
        "protect_vm_disks": True,
    },

    "rogue": {
        # Process image names treated as compute/training workloads.
        "watch_names": ["python.exe", "pythonw.exe", "python3.exe", "jupyter.exe",
                        "jupyter-lab.exe", "jupyter-notebook.exe", "conda.exe",
                        "ollama.exe", "ollama_llama_server.exe", "llama-server.exe",
                        "koboldcpp.exe", "torchrun.exe", "accelerate.exe",
                        "deepspeed.exe", "tensorboard.exe"],
        "gpu_mem_gb_threshold": 6.0,     # per-process dedicated VRAM considered heavy
        "multi_gpu_threshold": 3,        # holding this many GPUs at once
        "cpu_percent_threshold": 400.0,  # psutil % (100 = one logical core)
        "max_runtime_hours": 72,
        "idle_disconnected_hours": 24,   # disconnected session idle longer than this
        "whitelist_users": [],
        "whitelist_names": [],
    },

    "admin_group_sid": "S-1-5-32-544",
}


def _merge(base, override):
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def config_path() -> Path:
    return Path(os.environ.get("AIDASH_CONFIG", BASE_DIR / "config.json"))


def load() -> dict:
    p = config_path()
    user = {}
    if p.exists():
        with open(p, "r", encoding="utf-8-sig") as f:
            user = json.load(f)
    return _merge(DEFAULTS, user)


def resolve(path: str) -> Path:
    """Resolve a config path relative to the install directory."""
    p = Path(path)
    return p if p.is_absolute() else BASE_DIR / p


CFG = load()

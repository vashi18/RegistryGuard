"""Application configuration for RegistryGuard."""
from __future__ import annotations

import os
import platform
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_DIR = BASE_DIR / "database"
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
DB_PATH = Path(os.getenv("REGISTRYGUARD_DB", DATABASE_DIR / "events.db"))
LOG_PATH = Path(os.getenv("REGISTRYGUARD_LOG", LOG_DIR / "registry.log"))
DEMO_STATE_PATH = Path(os.getenv("REGISTRYGUARD_DEMO_STATE", DATA_DIR / "demo_registry.json"))

DEFAULT_INTERVAL = max(1, int(os.getenv("REGISTRYGUARD_INTERVAL", "5")))
APP_MODE = os.getenv(
    "REGISTRYGUARD_MODE",
    "demo" if platform.system().lower() != "windows" else "windows",
).lower()

MONITORED_KEYS = [
    {
        "name": "User Startup",
        "root": "HKCU",
        "path": r"Software\Microsoft\Windows\CurrentVersion\Run",
        "severity": "HIGH",
        "enabled": True,
    },
    {
        "name": "System Startup",
        "root": "HKLM",
        "path": r"Software\Microsoft\Windows\CurrentVersion\Run",
        "severity": "HIGH",
        "enabled": True,
    },
]

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ACTIONS = ("ADDED", "MODIFIED", "DELETED")
STATUSES = ("NEW", "REVIEWED", "IGNORED", "WHITELISTED")


def ensure_directories() -> None:
    for directory in (DATABASE_DIR, DATA_DIR, LOG_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def clamp_interval(value: object) -> int:
    try:
        return max(1, min(3600, int(value)))
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL


def active_monitored_keys() -> list[dict]:
    return [item for item in MONITORED_KEYS if item.get("enabled", True)]

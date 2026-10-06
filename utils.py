"""Shared parsing, logging, hashing, and best-effort correlation helpers."""
from __future__ import annotations

import hashlib
import logging
import os
import re
import getpass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import psutil
except ImportError:  # pragma: no cover - optional on the target machine
    psutil = None


WINDOWS_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|/)[^\n\r\"']+?(?:\.exe|\.com|\.bat|\.cmd|\.ps1)(?:\s+[^\n\r\"']*)?", re.IGNORECASE)
SUSPICIOUS_DIR_MARKERS = ("\\temp\\", "/tmp/", "\\downloads\\", "/downloads/", "\\appdata\\local\\temp\\", "\\public\\")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def configure_logging(log_path: Path) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("registryguard")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.FileHandler(log_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(handler)
        logger.addHandler(logging.StreamHandler())
    return logger


def stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return repr(value)
    return str(value)


def extract_executable_path(value: Any) -> str | None:
    text = stringify(value).strip()
    if not text:
        return None
    match = WINDOWS_PATH_RE.search(text)
    if match:
        return match.group(0).split(" ", 1)[0].strip('"')
    if text.lower().endswith((".exe", ".com", ".bat", ".cmd", ".ps1")):
        return text.split(" ", 1)[0].strip('"')
    return None


def path_signals(path: str | None) -> dict[str, Any]:
    if not path:
        return {"file_exists": None, "file_size": None, "file_mtime": None, "file_hash": None, "suspicious_path": False}
    normalized = path.replace("\\", "/").lower()
    local = Path(path)
    exists = local.exists()
    result: dict[str, Any] = {
        "file_exists": exists,
        "file_size": None,
        "file_mtime": None,
        "file_hash": None,
        "suspicious_path": any(marker in normalized for marker in SUSPICIOUS_DIR_MARKERS),
    }
    if not exists:
        return result
    try:
        stat = local.stat()
        result["file_size"] = stat.st_size
        result["file_mtime"] = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
        if stat.st_size <= 25 * 1024 * 1024:
            digest = hashlib.sha256()
            with local.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            result["file_hash"] = digest.hexdigest()
    except (OSError, PermissionError):
        pass
    return result


def best_effort_process() -> dict[str, Any]:
    """Return correlation context, not proof of the Registry writer."""
    info = {"process_name": "registryguard-monitor", "pid": os.getpid(), "username": getpass.getuser()}
    if psutil is None:
        return info
    try:
        current = psutil.Process(os.getpid())
        info["process_name"] = current.name()
        info["pid"] = current.pid
        try:
            info["username"] = current.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
    except (psutil.Error, OSError):
        pass
    return info

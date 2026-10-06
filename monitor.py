"""Polling monitor with Windows Registry and safe demo adapters."""
from __future__ import annotations

import copy
import json
import os
import platform
import threading
import time
from pathlib import Path
from typing import Any

from alerts import create_for_event
from config import APP_MODE, DEMO_STATE_PATH, DEFAULT_INTERVAL, active_monitored_keys, clamp_interval
from database import Database
from detector import diff_snapshots
from risk_engine import assess
from utils import best_effort_process, stringify, utc_now


class DemoRegistryAdapter:
    def __init__(self, state_path: str | Path):
        self.state_path = Path(state_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_state()

    def _ensure_state(self) -> None:
        if not self.state_path.exists():
            self.state_path.write_text(json.dumps({
                "User Startup": {
                    "OneDrive": {"data": r"C:\\Program Files\\Microsoft\\OneDrive\\OneDrive.exe", "type": "REG_SZ"}
                },
                "System Startup": {}
            }, indent=2), encoding="utf-8")

    def snapshot(self) -> dict[str, Any]:
        self._ensure_state()
        raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        return copy.deepcopy(raw)

    def mutate(self, action: str) -> dict[str, Any]:
        data = self.snapshot()
        bucket = data.setdefault("User Startup", {})
        if action == "add":
            bucket["RegistryGuardDemo"] = {"data": r"C:\\Users\\Public\\Downloads\\rg-demo.exe", "type": "REG_SZ"}
        elif action == "modify":
            bucket["OneDrive"] = {"data": r"C:\\Users\\Public\\Downloads\\updated-demo.exe", "type": "REG_SZ"}
        elif action == "delete":
            bucket.pop("RegistryGuardDemo", None)
            bucket.pop("OneDrive", None)
        else:
            raise ValueError("action must be add, modify, or delete")
        self.state_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data


class WindowsRegistryAdapter:
    ROOTS: dict[str, Any] = {}

    def __init__(self, keys: list[dict]):
        if platform.system().lower() != "windows":
            raise RuntimeError("Windows Registry adapter is only available on Windows")
        import winreg
        self.winreg = winreg
        self.ROOTS = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        self.keys = keys

    def snapshot(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for item in self.keys:
            values: dict[str, Any] = {}
            root = self.ROOTS[item["root"]]
            try:
                with self.winreg.OpenKey(root, item["path"], 0, self.winreg.KEY_READ) as key:
                    index = 0
                    while True:
                        try:
                            name, data, kind = self.winreg.EnumValue(key, index)
                        except OSError:
                            break
                        values[name] = {"data": stringify(data), "type": str(kind)}
                        index += 1
            except (FileNotFoundError, PermissionError, OSError):
                values = {}
            result[item["name"]] = values
        return result


class MonitorController:
    def __init__(self, db: Database, interval: int = DEFAULT_INTERVAL, mode: str = APP_MODE, logger=None):
        self.db = db
        self.interval = clamp_interval(interval)
        self.requested_mode = mode
        self.mode = mode
        self.logger = logger
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.baseline: dict[str, Any] | None = None
        self.adapter = self._build_adapter()

    def _build_adapter(self):
        if self.requested_mode == "windows":
            try:
                return WindowsRegistryAdapter(self.monitored_keys())
            except RuntimeError as exc:
                self.mode = "demo"
                if self.logger: self.logger.warning("%s; using demo adapter", exc)
        return DemoRegistryAdapter(DEMO_STATE_PATH)

    def monitored_keys(self) -> list[dict]:
        selected = self.db.get_setting("monitored_keys", [item["name"] for item in active_monitored_keys()])
        return [item for item in active_monitored_keys() if item["name"] in selected]

    def set_monitored_keys(self, names: list[str]) -> None:
        allowed = {item["name"] for item in active_monitored_keys()}
        selected = [name for name in names if name in allowed]
        if not selected:
            selected = [next(iter(allowed))] if allowed else []
        self.db.set_setting("monitored_keys", selected)
        self.adapter = self._build_adapter()
        self.baseline = None

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.db.update_scan_state(self.mode, "STARTING", None, "Baseline is being created.")
        self.thread = threading.Thread(target=self._run, name="registryguard-monitor", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        self.scan_once()
        while not self.stop_event.wait(self.interval):
            self.scan_once()

    def scan_once(self) -> list[dict[str, Any]]:
        try:
            selected_keys = self.monitored_keys()
            raw_current = self.adapter.snapshot()
            current = {item["name"]: raw_current.get(item["name"], {}) for item in selected_keys}
            now = utc_now()
            if self.baseline is None:
                self.baseline = current
                self.db.update_scan_state(self.mode, "ACTIVE", now, "Baseline snapshot created.")
                if self.logger: self.logger.info("Registry snapshot created in %s mode", self.mode)
                return []
            changes = diff_snapshots(self.baseline, current, selected_keys)
            self.baseline = current
            whitelist = self.db.list_whitelist()
            saved: list[dict[str, Any]] = []
            for change in changes:
                event = {**change, **assess(change, whitelist), **best_effort_process(), "timestamp": now, "created_at": now}
                event_id = self.db.insert_event(event)
                event["id"] = event_id
                create_for_event(self.db, event_id, event)
                saved.append(event)
                if self.logger: self.logger.warning("Registry change detected: %s %s", event["action"], event["value_name"])
            self.db.update_scan_state(self.mode, "ACTIVE", now, f"Scan complete; {len(saved)} change(s) detected.")
            return saved
        except Exception as exc:  # keep the monitor alive and expose the failure in the UI
            self.db.update_scan_state(self.mode, "DEGRADED", utc_now(), str(exc))
            if self.logger: self.logger.exception("Monitor scan failed")
            return []

    def mutate_demo(self, action: str) -> None:
        if not isinstance(self.adapter, DemoRegistryAdapter):
            raise RuntimeError("Demo mutations are only available in demo mode")
        self.adapter.mutate(action)

    def stop(self) -> None:
        self.stop_event.set()

"""Snapshot diffing for added, modified, and deleted Registry values."""
from __future__ import annotations

from typing import Any


def _value(snapshot: dict, monitor: str, name: str) -> dict[str, Any] | None:
    return snapshot.get(monitor, {}).get(name)


def diff_snapshots(previous: dict, current: dict, key_metadata: list[dict]) -> list[dict[str, Any]]:
    metadata_by_name = {item["name"]: item for item in key_metadata}
    changes: list[dict[str, Any]] = []
    for monitor_name in sorted(set(previous) | set(current)):
        old_values = previous.get(monitor_name, {})
        new_values = current.get(monitor_name, {})
        for value_name in sorted(set(old_values) | set(new_values)):
            old = _value(previous, monitor_name, value_name)
            new = _value(current, monitor_name, value_name)
            if old is None and new is not None:
                action = "ADDED"
            elif old is not None and new is None:
                action = "DELETED"
            elif old != new:
                action = "MODIFIED"
            else:
                continue
            meta = metadata_by_name.get(monitor_name, {})
            changes.append({
                "monitor_name": monitor_name,
                "root_key": meta.get("root", "UNKNOWN"),
                "registry_path": meta.get("path", monitor_name),
                "value_name": value_name,
                "action": action,
                "old_value": old.get("data") if old else None,
                "new_value": new.get("data") if new else None,
                "old_meta": old or {},
                "new_meta": new or {},
                "monitored_severity": meta.get("severity", "MEDIUM"),
            })
    return changes

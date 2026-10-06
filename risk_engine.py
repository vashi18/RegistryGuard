"""Explainable heuristic risk scoring for Registry change events."""
from __future__ import annotations

from typing import Any, Iterable

from utils import extract_executable_path, path_signals, stringify


def _whitelisted(path: str | None, value: str, whitelist: Iterable[dict[str, Any]]) -> bool:
    haystack = f"{path or ''} {value}".lower()
    return any(item.get("enabled", 1) and item.get("pattern", "").lower() in haystack for item in whitelist)


def assess(change: dict[str, Any], whitelist: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
    candidate = change.get("new_value") or change.get("old_value")
    executable_path = extract_executable_path(candidate)
    signals = path_signals(executable_path)
    reasons: list[str] = []
    score = 0
    if change.get("monitored_severity") in ("HIGH", "CRITICAL"):
        score += 30; reasons.append("Sensitive Registry location")
    if change.get("action") == "ADDED":
        score += 20; reasons.append("New persistence/configuration value")
    elif change.get("action") == "MODIFIED":
        score += 12; reasons.append("Existing monitored value changed")
    if executable_path:
        score += 10; reasons.append("Executable registration detected")
    if signals.get("suspicious_path"):
        score += 30; reasons.append("Executable path uses a user-writable or temporary directory")
    if executable_path and signals.get("file_exists") is False:
        score += 15; reasons.append("Referenced executable was not found during correlation")
    is_whitelisted = _whitelisted(executable_path, stringify(candidate), whitelist)
    if is_whitelisted:
        score = min(score, 20); reasons.append("Administrator-configured whitelist match")
    score = min(score, 100)
    if score >= 85:
        severity = "CRITICAL"
    elif score >= 55:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    if is_whitelisted:
        severity = "LOW"
    return {
        "severity": severity,
        "risk_score": score,
        "risk_reason": " + ".join(reasons) if reasons else "Ordinary monitored configuration change",
        "executable_path": executable_path,
        **signals,
        "whitelisted": int(is_whitelisted),
        "status": "WHITELISTED" if is_whitelisted else "NEW",
    }

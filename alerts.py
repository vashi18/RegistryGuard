"""Dashboard alert helpers."""
from __future__ import annotations

from database import Database


def create_for_event(db: Database, event_id: int, event: dict) -> None:
    if event.get("severity") not in ("HIGH", "CRITICAL") or event.get("status") == "WHITELISTED":
        return
    location = f"{event.get('root_key')}\\{event.get('registry_path')}"
    message = f"{event.get('action')} {event.get('value_name')} at {location}"
    db.insert_alert(event_id, "Suspicious Registry change", message, event.get("severity", "HIGH"))

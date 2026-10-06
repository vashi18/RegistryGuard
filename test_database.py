from database import Database

def test_database_round_trip(tmp_path):
    db = Database(tmp_path / "events.db")
    event_id = db.insert_event({"timestamp": "2026-10-01T00:00:00+00:00", "root_key": "HKCU", "registry_path": "Run", "value_name": "Demo", "action": "ADDED", "old_value": None, "new_value": "x.exe", "severity": "HIGH", "risk_score": 70, "risk_reason": "test", "status": "NEW", "whitelisted": 0, "created_at": "2026-10-01T00:00:00+00:00"})
    assert db.get_event(event_id)["value_name"] == "Demo"
    assert db.stats()["high"] == 1
    assert db.set_status(event_id, "REVIEWED")
    assert db.get_event(event_id)["status"] == "REVIEWED"

import app as app_module
import monitor as monitor_module
from app import create_app


def make_app(tmp_path, monkeypatch):
    monkeypatch.setattr(monitor_module, "DEMO_STATE_PATH", tmp_path / "demo_registry.json")
    return create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "events.db"), "MONITOR_ENABLED": False})


def test_health_manifest_and_private_cache(tmp_path, monkeypatch):
    app = make_app(tmp_path, monkeypatch)
    client = app.test_client()
    assert client.get("/health").status_code == 200
    manifest = client.get("/manus-routes.json").get_json()
    assert {route["path"] for route in manifest["routes"]} == {"/", "/events", "/events/:id", "/settings"}
    assert client.get("/").headers["Cache-Control"] == "private, no-store"
    assert client.get("/events").status_code == 200


def test_demo_detection_workflow_and_event_views(tmp_path, monkeypatch):
    app = make_app(tmp_path, monkeypatch)
    client = app.test_client()
    monitor = app.extensions["registryguard_monitor"]
    monitor.scan_once()  # baseline
    monitor.mutate_demo("add")
    detected = monitor.scan_once()
    assert detected and detected[0]["action"] == "ADDED"
    assert detected[0]["risk_score"] <= 100
    event_id = detected[0]["id"]

    assert client.get(f"/events/{event_id}").status_code == 200
    assert client.get("/events?root=HKCU").status_code == 200
    csv = client.get("/export/events.csv?root=HKCU")
    assert csv.status_code == 200 and "RegistryGuardDemo" in csv.text
    assert client.get("/api/status").get_json()["stats"]["total"] == 1

    response = client.post(f"/events/{event_id}/status", data={"status": "REVIEWED"})
    assert response.status_code == 302
    assert app.extensions["registryguard_db"].get_event(event_id)["status"] == "REVIEWED"


def test_monitor_emits_modified_and_deleted_events(tmp_path, monkeypatch):
    app = make_app(tmp_path, monkeypatch)
    monitor = app.extensions["registryguard_monitor"]
    monitor.scan_once()
    monitor.mutate_demo("modify")
    modified = monitor.scan_once()
    assert any(item["action"] == "MODIFIED" for item in modified)
    monitor.mutate_demo("delete")
    deleted = monitor.scan_once()
    assert any(item["action"] == "DELETED" for item in deleted)
    assert app.extensions["registryguard_db"].recent_alerts()


def test_settings_persist_interval_locations_and_whitelist(tmp_path, monkeypatch):
    app = make_app(tmp_path, monkeypatch)
    client = app.test_client()
    response = client.post("/settings", data={"interval": "9", "monitored_keys": "User Startup"})
    assert response.status_code == 302
    db = app.extensions["registryguard_db"]
    assert db.get_setting("interval") == 9
    assert db.get_setting("monitored_keys") == ["User Startup"]

    response = client.post("/settings", data={"whitelist_pattern": "Trusted.exe", "whitelist_note": "approved demo"})
    assert response.status_code == 302
    assert db.list_whitelist()[0]["pattern"] == "Trusted.exe"

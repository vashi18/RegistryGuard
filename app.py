"""RegistryGuard Flask dashboard entrypoint."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, flash, jsonify, redirect, render_template, request, url_for

from alerts import create_for_event
from config import ACTIONS, APP_MODE, DEFAULT_INTERVAL, SEVERITIES, STATUSES, DB_PATH, LOG_PATH, active_monitored_keys, clamp_interval, ensure_directories
from database import Database
from monitor import MonitorController
from utils import configure_logging


def create_app(test_config: dict | None = None) -> Flask:
    ensure_directories()
    app = Flask(__name__)
    app.config.update(SECRET_KEY=os.getenv("REGISTRYGUARD_SECRET", "registryguard-demo-key"), DATABASE_PATH=str(DB_PATH), MONITOR_ENABLED=True)
    if test_config:
        app.config.update(test_config)
    logger = configure_logging(LOG_PATH)
    db = Database(app.config["DATABASE_PATH"])
    monitor = MonitorController(db, interval=db.get_setting("interval", DEFAULT_INTERVAL), mode=APP_MODE, logger=logger)
    app.extensions["registryguard_db"] = db
    app.extensions["registryguard_monitor"] = monitor
    if app.config.get("MONITOR_ENABLED", True) and os.getenv("REGISTRYGUARD_DISABLE_MONITOR") != "1":
        monitor.start()

    @app.context_processor
    def inject_globals():
        return {"app_mode": monitor.mode.upper(), "severities": SEVERITIES, "actions": ACTIONS, "statuses": STATUSES, "now": lambda: datetime.now(timezone.utc)}

    @app.after_request
    def protect_dynamic_responses(response):
        if not request.path.startswith("/static/") and request.path != "/manus-routes.json":
            response.headers["Cache-Control"] = "private, no-store"
        return response

    @app.get("/")
    def index():
        return render_template("index.html", stats=db.stats(), events=db.list_events(limit=8), alerts=db.recent_alerts(), scan=db.scan_state())

    @app.get("/events")
    def events():
        filters = {key: request.args.get(key, "").upper() if key != "query" else request.args.get(key, "") for key in ("severity", "action", "status", "root", "query")}
        page = max(1, request.args.get("page", 1, type=int))
        per_page = 25
        rows = db.list_events(**filters, limit=per_page, offset=(page - 1) * per_page)
        total = db.count_events(**filters)
        return render_template("events.html", events=rows, filters=filters, page=page, per_page=per_page, total=total)

    @app.get("/events/<int:event_id>")
    def event_detail(event_id: int):
        event = db.get_event(event_id)
        if not event:
            return render_template("404.html", message="Event not found"), 404
        return render_template("event_detail.html", event=event)

    @app.post("/events/<int:event_id>/status")
    def event_status(event_id: int):
        status = request.form.get("status", "").upper()
        if status not in STATUSES:
            flash("Unsupported event status.", "error")
        elif db.set_status(event_id, status):
            flash(f"Event #{event_id} marked {status.lower()}.", "success")
        else:
            flash("Event not found.", "error")
        return redirect(request.referrer or url_for("event_detail", event_id=event_id))

    @app.get("/settings")
    def settings():
        selected = db.get_setting("monitored_keys", [item["name"] for item in active_monitored_keys()])
        return render_template("settings.html", interval=db.get_setting("interval", monitor.interval), whitelist=db.list_whitelist(), monitored_keys=active_monitored_keys(), selected_keys=selected)

    @app.post("/settings")
    def save_settings():
        interval = clamp_interval(request.form.get("interval"))
        db.set_setting("interval", interval)
        monitor.interval = interval
        if "monitored_keys" in request.form:
            monitor.set_monitored_keys(request.form.getlist("monitored_keys"))
        pattern = request.form.get("whitelist_pattern", "").strip()
        note = request.form.get("whitelist_note", "").strip()
        if pattern:
            db.add_whitelist(pattern, note)
            flash("Whitelist entry added. It is administrator-configured and does not erase the audit trail.", "success")
        else:
            flash("Monitoring settings saved.", "success")
        return redirect(url_for("settings"))

    @app.post("/settings/whitelist/<int:item_id>/remove")
    def remove_whitelist(item_id: int):
        db.remove_whitelist(item_id)
        flash("Whitelist entry disabled.", "success")
        return redirect(url_for("settings"))

    @app.get("/export/events.csv")
    def export_events():
        rows = db.list_events(
            severity=request.args.get("severity") or None,
            action=request.args.get("action") or None,
            status=request.args.get("status") or None,
            root=request.args.get("root") or None,
            query=request.args.get("query") or None,
            limit=500,
        )
        return Response(db.export_csv(rows), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=registryguard-events.csv"})

    @app.get("/health")
    def health():
        scan = db.scan_state()
        return jsonify({"ok": True, "service": "registryguard", "database": "online", "monitor": scan.get("status", "UNKNOWN"), "mode": monitor.mode})

    @app.get("/api/status")
    def api_status():
        return jsonify({"stats": db.stats(), "scan": db.scan_state(), "mode": monitor.mode, "alerts": db.recent_alerts()})

    @app.get("/api/events/recent")
    def api_recent_events():
        return jsonify(db.list_events(limit=20))

    @app.post("/api/demo/mutate")
    def api_demo_mutate():
        if monitor.mode != "demo":
            return jsonify({"ok": False, "error": "Demo mutations are disabled outside demo mode."}), 400
        action = request.json.get("action") if request.is_json else request.form.get("action")
        try:
            monitor.mutate_demo(action or "add")
            detected = monitor.scan_once()
            return jsonify({"ok": True, "action": action, "detected": detected})
        except (RuntimeError, ValueError) as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    @app.post("/api/alerts/<int:alert_id>/ack")
    def api_ack_alert(alert_id: int):
        return jsonify({"ok": db.acknowledge_alert(alert_id)})

    @app.get("/manus-routes.json")
    def route_manifest():
        manifest = Path(app.root_path) / "static" / "manus-routes.json"
        return Response(manifest.read_text(encoding="utf-8"), mimetype="application/json")

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("404.html", message="That page does not exist"), 404

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "3000")), debug=False)

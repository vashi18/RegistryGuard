"""SQLite persistence for RegistryGuard events and operator settings."""
from __future__ import annotations

import csv
import io
import json
import sqlite3
from pathlib import Path
from typing import Any

from utils import utc_now


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    root_key TEXT NOT NULL,
                    registry_path TEXT NOT NULL,
                    value_name TEXT NOT NULL,
                    action TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    severity TEXT NOT NULL,
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    risk_reason TEXT NOT NULL,
                    executable_path TEXT,
                    file_exists INTEGER,
                    file_size INTEGER,
                    file_mtime TEXT,
                    file_hash TEXT,
                    suspicious_path INTEGER,
                    process_name TEXT,
                    pid INTEGER,
                    username TEXT,
                    status TEXT NOT NULL DEFAULT 'NEW',
                    whitelisted INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
                CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    acknowledged INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL DEFAULT 'path',
                    note TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scan_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    last_scan TEXT,
                    message TEXT
                );
                INSERT OR IGNORE INTO scan_state(id, mode, status, last_scan, message)
                    VALUES (1, 'demo', 'STARTING', NULL, 'Monitor has not completed its first scan.');
                """
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
            if "suspicious_path" not in columns:
                conn.execute("ALTER TABLE events ADD COLUMN suspicious_path INTEGER")

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row else None

    def insert_event(self, event: dict[str, Any]) -> int:
        fields = [
            "timestamp", "root_key", "registry_path", "value_name", "action", "old_value", "new_value",
            "severity", "risk_score", "risk_reason", "executable_path", "file_exists", "file_size",
            "file_mtime", "file_hash", "suspicious_path", "process_name", "pid", "username", "status", "whitelisted", "created_at",
        ]
        values = [event.get(field) for field in fields]
        if not event.get("created_at"):
            values[-1] = utc_now()
        with self.connect() as conn:
            cursor = conn.execute(
                f"INSERT INTO events ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
                values,
            )
            return int(cursor.lastrowid)

    def get_event(self, event_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            return self._row(conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone())

    def list_events(self, *, severity: str | None = None, action: str | None = None, status: str | None = None,
                    root: str | None = None,
                    query: str | None = None, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?"); params.append(severity)
        if action:
            clauses.append("action = ?"); params.append(action)
        if status:
            clauses.append("status = ?"); params.append(status)
        if root:
            clauses.append("root_key = ?"); params.append(root)
        if query:
            clauses.append("(registry_path LIKE ? OR value_name LIKE ? OR new_value LIKE ? OR risk_reason LIKE ?)")
            needle = f"%{query}%"; params.extend([needle] * 4)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM events {where} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
                (*params, min(limit, 500), max(0, offset)),
            ).fetchall()
            return [dict(row) for row in rows]

    def count_events(self, **filters: Any) -> int:
        filters = {key: value for key, value in filters.items() if value}
        clauses, params = [], []
        for key in ("severity", "action", "status"):
            if filters.get(key): clauses.append(f"{key} = ?"); params.append(filters[key])
        if filters.get("root"):
            clauses.append("root_key = ?"); params.append(filters["root"])
        if filters.get("query"):
            clauses.append("(registry_path LIKE ? OR value_name LIKE ? OR new_value LIKE ? OR risk_reason LIKE ?)")
            params.extend([f"%{filters['query']}%"] * 4)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as conn:
            return int(conn.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0])

    def stats(self) -> dict[str, Any]:
        with self.connect() as conn:
            counts = {row["severity"].lower(): row["count"] for row in conn.execute("SELECT severity, COUNT(*) count FROM events GROUP BY severity")}
            total = int(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            today = int(conn.execute("SELECT COUNT(*) FROM events WHERE date(timestamp) = date('now')").fetchone()[0])
            return {"total": total, "today": today, "low": counts.get("low", 0), "medium": counts.get("medium", 0), "high": counts.get("high", 0), "critical": counts.get("critical", 0)}

    def set_status(self, event_id: int, status: str) -> bool:
        with self.connect() as conn:
            cursor = conn.execute("UPDATE events SET status = ?, whitelisted = ? WHERE id = ?", (status, int(status == "WHITELISTED"), event_id))
            if status in ("REVIEWED", "IGNORED", "WHITELISTED"):
                conn.execute("UPDATE alerts SET acknowledged = 1 WHERE event_id = ?", (event_id,))
            return cursor.rowcount > 0

    def insert_alert(self, event_id: int, title: str, message: str, severity: str) -> int:
        with self.connect() as conn:
            cursor = conn.execute("INSERT INTO alerts(event_id,title,message,severity,created_at) VALUES(?,?,?,?,?)", (event_id, title, message, severity, utc_now()))
            return int(cursor.lastrowid)

    def recent_alerts(self, limit: int = 6) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM alerts WHERE acknowledged = 0 ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

    def acknowledge_alert(self, alert_id: int) -> bool:
        with self.connect() as conn:
            cursor = conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
            return cursor.rowcount > 0

    def get_setting(self, key: str, default: Any = None) -> Any:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if not row:
            return default
        try: return json.loads(row[0])
        except json.JSONDecodeError: return row[0]

    def set_setting(self, key: str, value: Any) -> None:
        encoded = json.dumps(value)
        with self.connect() as conn:
            conn.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, encoded))

    def list_whitelist(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM whitelist WHERE enabled = 1 ORDER BY pattern")]

    def add_whitelist(self, pattern: str, note: str = "") -> None:
        with self.connect() as conn:
            conn.execute("INSERT OR IGNORE INTO whitelist(pattern,note,created_at) VALUES(?,?,?)", (pattern.strip(), note.strip(), utc_now()))

    def remove_whitelist(self, item_id: int) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE whitelist SET enabled = 0 WHERE id = ?", (item_id,))

    def update_scan_state(self, mode: str, status: str, last_scan: str | None, message: str = "") -> None:
        with self.connect() as conn:
            conn.execute("UPDATE scan_state SET mode=?, status=?, last_scan=?, message=? WHERE id=1", (mode, status, last_scan, message))

    def scan_state(self) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM scan_state WHERE id=1").fetchone()
        return self._row(row) or {}

    def export_csv(self, events: list[dict[str, Any]]) -> str:
        output = io.StringIO()
        columns = ["id", "timestamp", "root_key", "registry_path", "value_name", "action", "old_value", "new_value", "severity", "risk_score", "risk_reason", "status", "executable_path", "file_hash", "suspicious_path", "process_name", "pid", "username"]
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader(); writer.writerows(events)
        return output.getvalue()

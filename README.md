# RegistryGuard

RegistryGuard is a modular endpoint-security demonstration that monitors selected Windows Registry locations, detects added/modified/deleted values, scores risk heuristically, and presents a searchable audit trail in a Flask dashboard.

> A Registry change is not automatically malicious. Severity is a heuristic risk assessment, not a malware verdict.

## Run the demo locally

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
REGISTRYGUARD_MODE=demo python app.py
```

Open `http://127.0.0.1:3000`. The sandbox and non-Windows environments automatically use demo mode. The dashboard's **Simulate change** action mutates `data/demo_registry.json`, runs a scan, and creates an event without touching the real operating-system Registry.

## Run on Windows

Use Python 3.12+, install the requirements, and start with:

```powershell
$env:REGISTRYGUARD_MODE = "windows"
python app.py
```

The Windows adapter reads:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`

Registry access can fail because of permissions or missing keys; those cases are handled as empty snapshots and surfaced through monitor state. Run with the least privilege needed for the locations you want to observe.

## Safe demonstration

1. Start RegistryGuard in demo mode.
2. Wait for the initial baseline to become active.
3. Click **Simulate change → Add startup value**.
4. Open the new HIGH/CRITICAL event and show the old/new values, risk reason, path signals, and correlation fields.
5. Mark the event reviewed or add an administrator-configured whitelist pattern from Settings.

## Architecture

`Adapter → Snapshot → Detector → Risk engine → SQLite → Flask dashboard → Alert`

The monitor uses polling, so detection has a configurable delay. Process attribution is best-effort correlation from the monitor process; polling does not prove which process wrote a Registry value. A production deployment would add stronger Windows telemetry, authentication, centralized storage, and SIEM integration.

## Tests

```bash
pytest -q
```

## Deployment

The included `Dockerfile` runs the Flask application with Gunicorn and honors the platform `PORT` environment variable. The app exposes `/health` for managed deployment health checks and `/manus-routes.json` for route discovery.

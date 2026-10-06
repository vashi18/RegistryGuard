from risk_engine import assess

def test_sensitive_added_missing_temp_path_is_high_or_critical():
    result = assess({"monitored_severity": "HIGH", "action": "ADDED", "new_value": r"C:\\Users\\Public\\Downloads\\drop.exe"})
    assert result["severity"] in {"HIGH", "CRITICAL"}
    assert "temporary" in result["risk_reason"] or "writable" in result["risk_reason"]

def test_whitelist_downgrades_but_does_not_hide_event():
    result = assess({"monitored_severity": "HIGH", "action": "ADDED", "new_value": r"C:\\Program Files\\Trusted\\agent.exe"}, [{"pattern": "Trusted", "enabled": 1}])
    assert result["status"] == "WHITELISTED"
    assert result["severity"] == "LOW"

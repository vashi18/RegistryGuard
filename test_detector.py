from detector import diff_snapshots

KEYS = [{"name": "User Startup", "root": "HKCU", "path": "Run", "severity": "HIGH"}]

def test_detects_added_modified_deleted():
    old = {"User Startup": {"Keep": {"data": "old", "type": "REG_SZ"}, "Delete": {"data": "gone", "type": "REG_SZ"}}}
    new = {"User Startup": {"Keep": {"data": "new", "type": "REG_SZ"}, "Add": {"data": "fresh", "type": "REG_SZ"}}}
    changes = diff_snapshots(old, new, KEYS)
    assert {(item["value_name"], item["action"]) for item in changes} == {("Keep", "MODIFIED"), ("Add", "ADDED"), ("Delete", "DELETED")}

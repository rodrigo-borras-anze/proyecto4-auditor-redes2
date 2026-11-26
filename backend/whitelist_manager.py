import json
from pathlib import Path
from datetime import datetime

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)
WHITELIST_FILE = DATA_DIR / "whitelist.json"


def _normalize_mac(mac: str) -> str:
    return mac.strip().upper().replace("-", ":")


def load_whitelist() -> list[dict]:
    if not WHITELIST_FILE.exists():
        WHITELIST_FILE.write_text("[]", encoding="utf-8")
        return []
    return json.loads(WHITELIST_FILE.read_text(encoding="utf-8"))


def save_whitelist(items: list[dict]) -> None:
    WHITELIST_FILE.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")


def is_authorized(mac: str | None) -> bool:
    if not mac:
        return False
    target = _normalize_mac(mac)
    return any(_normalize_mac(item["mac"]) == target for item in load_whitelist())


def add_device(mac: str, label: str, device_type: str = "laptop") -> dict:
    items = load_whitelist()
    norm_mac = _normalize_mac(mac)
    for item in items:
        if _normalize_mac(item["mac"]) == norm_mac:
            item["label"] = label
            item["device_type"] = device_type
            save_whitelist(items)
            return item

    entry = {
        "mac": norm_mac,
        "label": label,
        "device_type": device_type,
        "added_at": datetime.now().isoformat(timespec="seconds"),
    }
    items.append(entry)
    save_whitelist(items)
    return entry


def remove_device(mac: str) -> bool:
    items = load_whitelist()
    norm_mac = _normalize_mac(mac)
    new_items = [i for i in items if _normalize_mac(i["mac"]) != norm_mac]
    if len(new_items) == len(items):
        return False
    save_whitelist(new_items)
    return True
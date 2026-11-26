import json
import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).parent / "data" / "auditor.db"
DB_PATH.parent.mkdir(exist_ok=True)


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                hosts_found INTEGER DEFAULT 0,
                open_ports INTEGER DEFAULT 0,
                unauthorized_devices INTEGER DEFAULT 0,
                payload_json TEXT NOT NULL
            )
        """)


def save_scan(scan_type: str, target: str, payload: dict) -> int:
    summary = payload.get("summary", {})
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            """
            INSERT INTO scans (scan_type, target, timestamp, hosts_found, open_ports, unauthorized_devices, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_type,
                target,
                datetime.now().isoformat(timespec="seconds"),
                summary.get("hosts_found", 0),
                summary.get("open_ports", 0),
                summary.get("unauthorized_devices", 0),
                json.dumps(payload, ensure_ascii=False),
            ),
        )
        return cur.lastrowid


def list_scans(limit: int = 20) -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, scan_type, target, timestamp, hosts_found, open_ports, unauthorized_devices FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT payload_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return json.loads(row[0]) if row else None


def count_scans() -> int:
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
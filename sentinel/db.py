import sqlite3
import datetime
from typing import Optional, List, Dict, Any

class SentinelDB:
    def __init__(self, db_path: str = "sentinel_cache.db"):
        self.db_path = db_path
        self._shared_conn = None
        if db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:")
            self._shared_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def close(self):
        if self._shared_conn:
            self._shared_conn.close()

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS advisories (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    link TEXT NOT NULL,
                    published_date TEXT,
                    cves TEXT,
                    cvss_score REAL DEFAULT 0.0,
                    summary TEXT,
                    notified INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                )
            """)
            conn.commit()

    def is_processed(self, advisory_id: str) -> bool:
        with self._get_connection() as conn:
            row = conn.execute("SELECT id FROM advisories WHERE id = ?", (advisory_id,)).fetchone()
            return row is not None

    def save_advisory(self, adv: Dict[str, Any]):
        now = datetime.datetime.utcnow().isoformat() + "Z"
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO advisories (
                    id, title, link, published_date, cves, cvss_score, summary, notified, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                adv["id"],
                adv["title"],
                adv["link"],
                adv.get("published_date", ""),
                ",".join(adv.get("cves", [])),
                adv.get("cvss_score", 0.0),
                adv.get("summary", ""),
                1 if adv.get("notified") else 0,
                now
            ))
            conn.commit()

    def get_recent(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM advisories ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

import os
import json
import sqlite3
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger("scanner.db")

class AuditDatabase:
    """
    SQLite persistence layer for storing scan reports, historical versions,
    and calculating security regression diffs across releases.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            data_dir = os.path.join(base_dir, "data")
            os.makedirs(data_dir, exist_ok=True)
            self.db_path = os.path.join(data_dir, "audits.db")
        else:
            self.db_path = db_path

        self._init_schema()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    package_name TEXT NOT NULL,
                    app_title TEXT,
                    version_name TEXT,
                    version_code TEXT,
                    framework TEXT,
                    security_score INTEGER,
                    risk_level TEXT,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    info_count INTEGER DEFAULT 0,
                    total_findings INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    report_json TEXT NOT NULL
                )
            """)
            conn.commit()

    def save_scan(self, scan_data: Dict[str, Any]) -> str:
        scan_id = scan_data["scan_id"]
        app_info = scan_data.get("app_info", {})
        tech_info = scan_data.get("tech_info", {})
        score_data = scan_data.get("score_data", {})
        counts = score_data.get("counts", {})

        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO scans (
                    id, package_name, app_title, version_name, version_code,
                    framework, security_score, risk_level,
                    critical_count, high_count, medium_count, low_count, info_count,
                    total_findings, created_at, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                app_info.get("package", "unknown"),
                app_info.get("title", app_info.get("package", "Target App")),
                app_info.get("version_name", "1.0"),
                str(app_info.get("version_code", "1")),
                tech_info.get("primary_framework", "Native Android"),
                score_data.get("score", 0),
                score_data.get("risk_level", "UNKNOWN"),
                counts.get("CRITICAL", 0),
                counts.get("HIGH", 0),
                counts.get("MEDIUM", 0),
                counts.get("LOW", 0),
                counts.get("INFO", 0),
                len(scan_data.get("findings", [])),
                datetime.utcnow().isoformat(),
                json.dumps(scan_data)
            ))
            conn.commit()
        return scan_id

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT report_json FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row["report_json"])
        return None

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT id, package_name, app_title, version_name, version_code,
                       framework, security_score, risk_level,
                       critical_count, high_count, medium_count, low_count, info_count,
                       total_findings, created_at
                FROM scans
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def compute_regression_diff(self, base_scan_id: str, new_scan_id: str) -> Dict[str, Any]:
        """
        Calculates vulnerability diff between two releases:
        - Resolved findings (Fixed in new scan)
        - New findings (Introduced in new scan)
        - Persisting findings
        - Score progression
        """
        base = self.get_scan(base_scan_id)
        new = self.get_scan(new_scan_id)

        if not base or not new:
            raise ValueError("One or both scan IDs not found")

        base_findings = {f["id"] + ":" + f.get("title", ""): f for f in base.get("findings", [])}
        new_findings = {f["id"] + ":" + f.get("title", ""): f for f in new.get("findings", [])}

        base_keys = set(base_findings.keys())
        new_keys = set(new_findings.keys())

        fixed_keys = base_keys - new_keys
        introduced_keys = new_keys - base_keys
        persisting_keys = base_keys & new_keys

        score_diff = new.get("score_data", {}).get("score", 0) - base.get("score_data", {}).get("score", 0)

        return {
            "base_version": {
                "id": base_scan_id,
                "version_name": base.get("app_info", {}).get("version_name", "v1"),
                "score": base.get("score_data", {}).get("score", 0),
                "counts": base.get("score_data", {}).get("counts", {})
            },
            "new_version": {
                "id": new_scan_id,
                "version_name": new.get("app_info", {}).get("version_name", "v2"),
                "score": new.get("score_data", {}).get("score", 0),
                "counts": new.get("score_data", {}).get("counts", {})
            },
            "score_diff": score_diff,
            "resolved_count": len(fixed_keys),
            "introduced_count": len(introduced_keys),
            "persisting_count": len(persisting_keys),
            "resolved_findings": [base_findings[k] for k in fixed_keys],
            "introduced_findings": [new_findings[k] for k in introduced_keys],
            "persisting_findings": [new_findings[k] for k in persisting_keys]
        }

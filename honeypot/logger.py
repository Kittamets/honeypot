"""
Structured logging to SQLite + rotating log file.

Schema
------
requests  — one row per HTTP request, including fingerprint data
alerts    — one row per alert dispatched to SOC

Internal IPs are flagged automatically based on the configured CIDR ranges.
Severity is assigned as follows:

  CRITICAL  internal IP + scanner/tool detected
  HIGH      internal IP (any access), or internal POST (credential submission)
  MEDIUM    external IP with scanner signature
  INFO      all other traffic
"""

import ipaddress
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("honeypot")

SEVERITY_RANK = {"INFO": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class HoneypotLogger:
    def __init__(self, config: dict):
        self.db_path  = config["logging"]["db_path"]
        self.log_file = config["logging"]["log_file"]
        self._internal_networks = [
            ipaddress.ip_network(r, strict=False)
            for r in config["internal_ranges"]
        ]

        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)

        self._setup_file_logger()
        self._init_db()

    # ── Setup ─────────────────────────────────────────────────────────────────

    def _setup_file_logger(self) -> None:
        fmt = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")

        fh = logging.FileHandler(self.log_file, encoding="utf-8")
        fh.setFormatter(fmt)

        ch = logging.StreamHandler()
        ch.setFormatter(fmt)

        logger.setLevel(logging.INFO)
        logger.addHandler(fh)
        logger.addHandler(ch)

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS requests (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp           TEXT    NOT NULL,
                    source_ip           TEXT    NOT NULL,
                    method              TEXT    NOT NULL,
                    path                TEXT    NOT NULL,
                    query_params        TEXT,
                    headers             TEXT,
                    body                TEXT,
                    is_internal         INTEGER DEFAULT 0,
                    scanner_type        TEXT,
                    suspicious_path     INTEGER DEFAULT 0,
                    attack_in_headers   INTEGER DEFAULT 0,
                    severity            TEXT    DEFAULT 'INFO',
                    fingerprint_details TEXT,
                    tags                TEXT
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp         TEXT NOT NULL,
                    source_ip         TEXT NOT NULL,
                    alert_type        TEXT NOT NULL,
                    severity          TEXT NOT NULL,
                    endpoints_accessed TEXT,
                    scanner_type      TEXT,
                    details           TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_req_ip        ON requests(source_ip);
                CREATE INDEX IF NOT EXISTS idx_req_ts        ON requests(timestamp);
                CREATE INDEX IF NOT EXISTS idx_req_severity  ON requests(severity);
                CREATE INDEX IF NOT EXISTS idx_alert_ip      ON alerts(source_ip);
            """)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def is_internal(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._internal_networks)
        except ValueError:
            return False

    def _severity(
        self,
        is_internal: bool,
        method: str,
        scanner_name: Optional[str],
    ) -> str:
        if is_internal and scanner_name:
            return "CRITICAL"
        if is_internal:
            return "HIGH"
        if scanner_name:
            return "MEDIUM"
        return "INFO"

    # ── Public API ────────────────────────────────────────────────────────────

    def log_request(
        self,
        source_ip: str,
        method: str,
        path: str,
        query_params: dict,
        headers: dict,
        body: str,
        fingerprint_result,           # FingerprintResult | None
    ) -> dict:
        """Insert one request row and return the full record dict."""
        timestamp   = datetime.utcnow().isoformat()
        internal    = self.is_internal(source_ip)
        scanner     = fingerprint_result.scanner_name if fingerprint_result else None
        severity    = self._severity(internal, method, scanner)

        record = {
            "timestamp":           timestamp,
            "source_ip":           source_ip,
            "method":              method,
            "path":                path,
            "query_params":        json.dumps(query_params),
            "headers":             json.dumps(headers),
            "body":                (body or "")[:4096],   # cap at 4 KB
            "is_internal":         1 if internal else 0,
            "scanner_type":        scanner,
            "suspicious_path":     1 if (fingerprint_result and fingerprint_result.suspicious_path) else 0,
            "attack_in_headers":   1 if (fingerprint_result and fingerprint_result.attack_in_headers) else 0,
            "severity":            severity,
            "fingerprint_details": fingerprint_result.details if fingerprint_result else "",
            "tags":                json.dumps(fingerprint_result.tags if fingerprint_result else []),
        }

        with self._conn() as conn:
            conn.execute(
                """INSERT INTO requests
                   (timestamp, source_ip, method, path, query_params, headers, body,
                    is_internal, scanner_type, suspicious_path, attack_in_headers,
                    severity, fingerprint_details, tags)
                   VALUES
                   (:timestamp, :source_ip, :method, :path, :query_params, :headers, :body,
                    :is_internal, :scanner_type, :suspicious_path, :attack_in_headers,
                    :severity, :fingerprint_details, :tags)""",
                record,
            )

        tag   = "INTERNAL" if internal else "external"
        label = f"[{severity}] {source_ip} ({tag}) {method} {path}"
        if scanner:
            label += f" [scanner={scanner}]"

        log_fn = logger.warning if severity in ("HIGH", "CRITICAL") else logger.info
        log_fn(label)

        return record

    def log_alert(
        self,
        source_ip: str,
        alert_type: str,
        severity: str,
        endpoints: list,
        scanner_type: Optional[str],
        details: str,
    ) -> None:
        timestamp = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO alerts
                   (timestamp, source_ip, alert_type, severity,
                    endpoints_accessed, scanner_type, details)
                   VALUES (?,?,?,?,?,?,?)""",
                (timestamp, source_ip, alert_type, severity,
                 json.dumps(endpoints), scanner_type, details),
            )
        logger.warning(f"ALERT [{severity}] {alert_type} — {source_ip}")

    def is_first_contact(self, source_ip: str) -> bool:
        """True only if this IP has exactly ONE request in the DB (just logged)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM requests WHERE source_ip = ?", (source_ip,)
            ).fetchone()
        return row[0] == 1

    def get_ip_history(self, source_ip: str) -> dict:
        """Return a summary dict for a given source IP."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT method, path, timestamp, severity
                   FROM requests WHERE source_ip = ?
                   ORDER BY timestamp DESC LIMIT 100""",
                (source_ip,),
            ).fetchall()

        if not rows:
            return {"total_requests": 0, "endpoints": [], "first_seen": None,
                    "last_seen": None, "max_severity": "INFO"}

        endpoints = list(dict.fromkeys(r["path"] for r in rows))   # unique, ordered
        severities = [r["severity"] for r in rows]
        max_sev = max(severities, key=lambda s: SEVERITY_RANK.get(s, 0))

        return {
            "total_requests": len(rows),
            "endpoints":      endpoints,
            "first_seen":     rows[-1]["timestamp"],
            "last_seen":      rows[0]["timestamp"],
            "max_severity":   max_sev,
        }

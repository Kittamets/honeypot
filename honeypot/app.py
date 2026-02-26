"""
Main aiohttp application factory.

Middleware execution order for every request:
  1. Extract source IP
  2. Fingerprint (passive — no network I/O)
  3. Tarpit delay (async sleep — non-blocking)
  4. Log to SQLite + log file
  5. Evaluate alert conditions
  6. Call route handler
  7. Inject fake server headers into response
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional

import yaml
from aiohttp import web

from .alerter import HoneypotAlerter
from .fingerprint import fingerprint_request
from .logger import HoneypotLogger, SEVERITY_RANK
from .routes import setup_routes
from .tarpit import TarpitMiddleware

logger = logging.getLogger("honeypot")


# ─────────────────────────────────────────────────────────────────────────────
# Alert deduplication tracker
# ─────────────────────────────────────────────────────────────────────────────

class AlertTracker:
    """
    Prevents alert storms by suppressing repeated alerts for the same IP
    within a cooldown window — unless the severity has escalated.
    """

    def __init__(self, cooldown_seconds: int = 300):
        self._cooldown = timedelta(seconds=cooldown_seconds)
        self._state: dict[str, dict] = {}   # {ip: {"time": datetime, "severity": str}}

    def should_alert(self, ip: str, severity: str) -> bool:
        if ip not in self._state:
            return True

        last = self._state[ip]
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(last["severity"], 0):
            return True                                     # severity escalated

        if datetime.utcnow() - last["time"] > self._cooldown:
            return True                                     # cooldown expired

        return False

    def record(self, ip: str, severity: str) -> None:
        self._state[ip] = {"time": datetime.utcnow(), "severity": severity}


# ─────────────────────────────────────────────────────────────────────────────
# Middleware factory
# ─────────────────────────────────────────────────────────────────────────────

def _alert_type(is_internal: bool, method: str, fp) -> str:
    if is_internal and fp and fp.scanner_name:
        return f"INTERNAL SCANNER DETECTED ({fp.scanner_name})"
    if is_internal and method == "POST":
        return "INTERNAL CREDENTIAL SUBMISSION"
    if is_internal:
        return "INTERNAL IP FIRST CONTACT"
    if fp and fp.scanner_name:
        return f"EXTERNAL SCANNER ({fp.scanner_name})"
    return "SUSPICIOUS ACCESS"


def build_middleware(
    tarpit: TarpitMiddleware,
    hp_logger: HoneypotLogger,
    alerter: HoneypotAlerter,
    tracker: AlertTracker,
    config: dict,
):
    server_cfg = config["server"]
    fake_server  = server_cfg["fake_identity"]
    fake_powered = server_cfg.get("fake_powered_by", "PHP/5.2.17")

    @web.middleware
    async def honeypot_middleware(request: web.Request, handler) -> web.Response:

        # ── 1. Source IP ──────────────────────────────────────────────────────
        forwarded = request.headers.get("X-Forwarded-For", "")
        source_ip = forwarded.split(",")[0].strip() if forwarded else (request.remote or "unknown")

        # ── 2. Passive fingerprint ────────────────────────────────────────────
        fp = fingerprint_request(
            request.headers.get("User-Agent", ""),
            request.path,
            dict(request.headers),
        )

        # ── 3. Tarpit delay ───────────────────────────────────────────────────
        await tarpit.apply_delay(source_ip, request.method)

        # ── 4. Read & cache request body (aiohttp caches after first read) ───
        try:
            body = await request.text()
        except Exception:
            body = ""

        # ── 5. Log ────────────────────────────────────────────────────────────
        record = hp_logger.log_request(
            source_ip=source_ip,
            method=request.method,
            path=request.path,
            query_params=dict(request.rel_url.query),
            headers=dict(request.headers),
            body=body,
            fingerprint_result=fp,
        )

        # ── 6. Alert logic ────────────────────────────────────────────────────
        is_internal = bool(record["is_internal"])
        severity    = record["severity"]

        needs_alert = (
            (is_internal and hp_logger.is_first_contact(source_ip))
            or (is_internal and request.method == "POST")
            or (is_internal and fp.scanner_name)
            or (not is_internal and fp.scanner_name)
        )

        if needs_alert and tracker.should_alert(source_ip, severity):
            tracker.record(source_ip, severity)
            history    = hp_logger.get_ip_history(source_ip)
            alert_type = _alert_type(is_internal, request.method, fp)

            hp_logger.log_alert(
                source_ip=source_ip,
                alert_type=alert_type,
                severity=severity,
                endpoints=history["endpoints"],
                scanner_type=fp.scanner_name,
                details=fp.details,
            )

            # Fire-and-forget: never block the HTTP response
            asyncio.create_task(
                alerter.send_alert(
                    source_ip=source_ip,
                    severity=severity,
                    alert_type=alert_type,
                    endpoints=history["endpoints"],
                    scanner_type=fp.scanner_name,
                    details=fp.details,
                )
            )

        # ── 7. Call route handler ─────────────────────────────────────────────
        response = await handler(request)

        # ── 8. Inject fake legacy server headers ──────────────────────────────
        response.headers["Server"]       = fake_server
        response.headers["X-Powered-By"] = fake_powered
        response.headers["X-Generator"]  = "DMS v2.1"
        # Remove headers that reveal we are a modern Python server
        response.headers.pop("X-Content-Type-Options", None)

        return response

    return honeypot_middleware


# ─────────────────────────────────────────────────────────────────────────────
# Application factory
# ─────────────────────────────────────────────────────────────────────────────

def create_app(config: dict) -> web.Application:
    tarpit   = TarpitMiddleware(config)
    hp_logger = HoneypotLogger(config)
    alerter  = HoneypotAlerter(config)
    tracker  = AlertTracker(config["alerting"].get("cooldown_seconds", 300))

    middleware = build_middleware(tarpit, hp_logger, alerter, tracker, config)

    app = web.Application(middlewares=[middleware])
    setup_routes(app)
    app["config"] = config
    return app


# ─────────────────────────────────────────────────────────────────────────────
# Entry point (used by main.py)
# ─────────────────────────────────────────────────────────────────────────────

def run(config_path: str = "config.yaml") -> None:
    with open(config_path, encoding="utf-8") as fh:
        config = yaml.safe_load(fh)

    srv = config["server"]
    app = create_app(config)

    print(f"[*] Honeypot starting on  {srv['host']}:{srv['port']}")
    print(f"[*] Posing as             {srv['fake_identity']}")
    print(f"[*] Logs → {config['logging']['log_file']}")
    print(f"[*] DB   → {config['logging']['db_path']}")

    web.run_app(app, host=srv["host"], port=int(srv["port"]), access_log=None)

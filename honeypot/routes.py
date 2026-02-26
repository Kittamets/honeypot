"""
All honeypot route handlers.

Every endpoint returns fake-but-realistic content designed to keep an attacker
engaged and lure them into submitting credentials or spending time exploring —
buying time for the SOC to respond.
"""

import json
import re
from urllib.parse import parse_qs
from aiohttp import web

# ── Fake credential store ──────────────────────────────────────────────────────
# Only one valid plaintext credential — intentionally hard to guess.
# Attackers will almost always reach the dashboard via SQLi instead.
_VALID_CREDENTIALS = {
    "admin": "C0rp!DMS#2011",
}

# ── SQLi bypass patterns ───────────────────────────────────────────────────────
# When detected, login "succeeds" — attacker believes injection worked.
_SQLI_BYPASS_PATTERNS = [
    r"'\s*or\s+",                    # ' OR ...
    r"'\s*\|\|",                     # ' || (Oracle OR)
    r"--",                           # SQL line comment
    r"#",                            # MySQL comment
    r"/\*",                          # block comment
    r"'\s*;",                        # statement terminator
    r"\bunion\b.{0,30}\bselect\b",   # UNION SELECT
    r"1\s*=\s*1",                    # 1=1 tautology
    r"'='",                          # ''='' bypass
    r"or\s+\d+\s*=\s*\d+",          # OR 1=1 (no quote)
]


def _is_sqli(value: str) -> bool:
    return any(re.search(p, value, re.IGNORECASE) for p in _SQLI_BYPASS_PATTERNS)

from .fake_content import (
    FAKE_ENV,
    FAKE_CONFIG_PHP,
    FAKE_SQL_DUMP,
    FAKE_ROBOTS_TXT,
    FAKE_API_USERS,
    FAKE_API_CONFIG,
    get_index_html,
    get_admin_login_html,
    get_admin_dashboard_html,
    get_admin_users_html,
    get_backup_listing_html,
    get_phpmyadmin_html,
    get_tomcat_html,
    get_404_html,
)

# ── Root / directory index ─────────────────────────────────────────────────────

async def handle_index(request: web.Request) -> web.Response:
    return web.Response(
        text=get_index_html(),
        content_type="text/html",
        headers={"Last-Modified": "Sat, 09 Feb 2013 08:00:00 GMT"},
    )


# ── Admin panel ────────────────────────────────────────────────────────────────

async def handle_admin_redirect(request: web.Request) -> web.Response:
    """Bare /admin → redirect to /admin/login (like a real app would)."""
    return web.Response(
        status=302,
        headers={"Location": "/admin/login"},
    )


async def handle_admin_login_get(request: web.Request) -> web.Response:
    return web.Response(text=get_admin_login_html(error=False), content_type="text/html")


async def handle_admin_login_post(request: web.Request) -> web.Response:
    """
    Intentionally vulnerable login handler (honeypot).

    Decision tree (body already logged by middleware):
      1. SQLi pattern detected in username or password → fake success (bypass)
      2. Credentials match _VALID_CREDENTIALS              → success
      3. Anything else                                     → error page
    """
    try:
        body = await request.text()
        params = parse_qs(body)
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]
    except Exception:
        username = password = ""

    # SQLi bypass — attacker thinks injection worked
    if _is_sqli(username) or _is_sqli(password):
        return web.Response(status=302, headers={"Location": "/admin/dashboard"})

    # Valid credentials
    if _VALID_CREDENTIALS.get(username) == password:
        return web.Response(status=302, headers={"Location": "/admin/dashboard"})

    # Wrong credentials — show error
    return web.Response(
        text=get_admin_login_html(error=True),
        content_type="text/html",
    )


async def handle_admin_dashboard(request: web.Request) -> web.Response:
    return web.Response(text=get_admin_dashboard_html(), content_type="text/html")


async def handle_admin_users(request: web.Request) -> web.Response:
    return web.Response(text=get_admin_users_html(), content_type="text/html")


# ── Backup directory ───────────────────────────────────────────────────────────

async def handle_backup_listing(request: web.Request) -> web.Response:
    return web.Response(text=get_backup_listing_html(), content_type="text/html")


async def handle_db_backup_sql(request: web.Request) -> web.Response:
    """Serve the fake SQL dump as a downloadable file."""
    return web.Response(
        text=FAKE_SQL_DUMP,
        content_type="application/octet-stream",
        headers={
            "Content-Disposition": "attachment; filename=db_backup.sql",
        },
    )


async def handle_backup_zip(request: web.Request) -> web.Response:
    """
    Return a truncated ZIP magic header — suggests a large download is starting.
    The tarpit delay will have already slowed the attacker down before this hits.
    """
    fake_zip_header = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 20
    return web.Response(
        body=fake_zip_header,
        content_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=backup_20130201.zip"},
    )


# ── Legacy REST API ────────────────────────────────────────────────────────────

async def handle_api_users(request: web.Request) -> web.Response:
    return web.Response(
        text=json.dumps(FAKE_API_USERS, indent=2),
        content_type="application/json",
    )


async def handle_api_config(request: web.Request) -> web.Response:
    return web.Response(
        text=json.dumps(FAKE_API_CONFIG, indent=2),
        content_type="application/json",
    )


# ── Exposed config / env files ─────────────────────────────────────────────────

async def handle_env(request: web.Request) -> web.Response:
    return web.Response(text=FAKE_ENV, content_type="text/plain")


async def handle_config_php(request: web.Request) -> web.Response:
    """PHP not processed → raw source leaks, as on a misconfigured server."""
    return web.Response(text=FAKE_CONFIG_PHP, content_type="text/plain")


async def handle_config_page(request: web.Request) -> web.Response:
    return web.Response(
        text=f"<pre>{FAKE_CONFIG_PHP}</pre>",
        content_type="text/html",
    )


# ── Third-party management consoles ───────────────────────────────────────────

async def handle_phpmyadmin(request: web.Request) -> web.Response:
    return web.Response(text=get_phpmyadmin_html(), content_type="text/html")


async def handle_tomcat_manager(request: web.Request) -> web.Response:
    return web.Response(
        text=get_tomcat_html(),
        content_type="text/html",
        status=401,
        headers={"WWW-Authenticate": 'Basic realm="Tomcat Manager Application"'},
    )


# ── robots.txt (intentionally "leaks" bait paths) ─────────────────────────────

async def handle_robots(request: web.Request) -> web.Response:
    return web.Response(text=FAKE_ROBOTS_TXT, content_type="text/plain")


# ── Catch-all 404 ─────────────────────────────────────────────────────────────

async def handle_404(request: web.Request) -> web.Response:
    return web.Response(
        text=get_404_html(request.path),
        content_type="text/html",
        status=404,
    )


# ── Route registration ─────────────────────────────────────────────────────────

def setup_routes(app: web.Application) -> None:
    r = app.router

    # Root
    r.add_get("/", handle_index)

    # Admin
    r.add_get("/admin",            handle_admin_redirect)
    r.add_get("/admin/",           handle_admin_redirect)
    r.add_get("/admin/login",      handle_admin_login_get)
    r.add_post("/admin/login",     handle_admin_login_post)
    r.add_get("/admin/dashboard",  handle_admin_dashboard)
    r.add_get("/admin/users",      handle_admin_users)

    # Backups
    r.add_get("/backup",           handle_backup_listing)
    r.add_get("/backup/",          handle_backup_listing)
    r.add_get("/db_backup.sql",    handle_db_backup_sql)
    r.add_get("/backup.zip",       handle_backup_zip)

    # Legacy API
    r.add_get("/old-api/v1/users",  handle_api_users)
    r.add_get("/old-api/v1/config", handle_api_config)

    # Exposed files
    r.add_get("/.env",       handle_env)
    r.add_get("/config.php", handle_config_php)
    r.add_get("/config",     handle_config_page)

    # Third-party consoles
    r.add_get("/phpmyadmin",        handle_phpmyadmin)
    r.add_get("/phpmyadmin/",       handle_phpmyadmin)
    r.add_get("/manager/html",      handle_tomcat_manager)
    r.add_get("/manager/html/",     handle_tomcat_manager)

    # robots.txt
    r.add_get("/robots.txt", handle_robots)

    # Catch-all — must be last
    r.add_route("*", "/{path_info:.*}", handle_404)

# Corporate Honeypot — Insider Threat / Lateral Movement Detection

A Python-based low-interaction web honeypot that impersonates a forgotten legacy
intranet server to detect compromised internal machines performing lateral
movement across the corporate network.

---

## File Structure

```
honeypot/
├── __init__.py          # package marker
├── __main__.py          # allows `python -m honeypot`
├── app.py               # aiohttp app factory + middleware orchestration
├── routes.py            # all fake HTTP endpoints
├── fake_content.py      # HTML pages, fake config files, fake SQL dump, fake API data
├── fingerprint.py       # passive scanner/tool identification
├── tarpit.py            # progressive-delay middleware
├── logger.py            # SQLite + file logging
└── alerter.py           # email + webhook alert dispatch

config.yaml              # master configuration (edit before running)
main.py                  # CLI entry point
Dockerfile
docker-compose.yml
data/                    # created automatically — holds honeypot.db + honeypot.log
```

---

## Quick Start

### Docker (recommended)

```bash
# 1. Edit config.yaml — set internal_ranges, email/webhook settings
# 2. Build and run
docker compose up -d

# View live logs
docker compose logs -f

# Query the SQLite database
sqlite3 data/honeypot.db "SELECT timestamp,source_ip,method,path,severity FROM requests ORDER BY timestamp DESC LIMIT 20;"
```

### Local (Python 3.11+)

```bash
pip install -r requirements.txt
python main.py config.yaml
```

---

## Configuration Reference (`config.yaml`)

| Key | Description |
|-----|-------------|
| `server.host / port` | Bind address (default `192.168.1.100:8080`) |
| `server.fake_identity` | `Server:` header value — looks like old Apache |
| `internal_ranges` | CIDR list — contacts from these ranges trigger HIGH/CRITICAL alerts |
| `tarpit.base_delay` | Seconds for the first throttled request |
| `tarpit.multiplier` | Exponential growth factor (e.g. 2.5 → 1 s, 2.5 s, 6.3 s …) |
| `tarpit.max_delay` | Hard cap per request (default 30 s) |
| `tarpit.threshold` | Requests before throttling kicks in (default 3) |
| `tarpit.post_delay` | Fixed delay on every POST (simulates auth processing) |
| `alerting.cooldown_seconds` | Min gap between repeated alerts for the same IP |
| `alerting.email.*` | SMTP settings — set `enabled: true` to activate |
| `alerting.webhook.url` | Slack/Teams/Discord incoming webhook URL |
| `logging.db_path` | SQLite database path (inside container: `/app/data/`) |
| `logging.log_file` | Human-readable log file path |

---

## Bait Endpoints

| Endpoint | What it pretends to be |
|----------|------------------------|
| `GET /` | Old Apache directory listing of the "DMS" server |
| `GET /admin/login` | Admin login form |
| `POST /admin/login` | Detects SQLi bypass patterns (fake success) or one valid credential; wrong creds return error page — all submissions logged |
| `GET /admin/dashboard` | Fake admin panel with fake user activity |
| `GET /admin/users` | Fake user table with internal email addresses |
| `GET /backup/` | Directory listing with `db_backup.sql` and `.zip` files |
| `GET /db_backup.sql` | Full fake MySQL dump with hashed passwords and API keys |
| `GET /backup.zip` | Partial ZIP header (suggests large file download) |
| `GET /.env` | Fake `.env` with DB, LDAP, SMTP and API credentials |
| `GET /config.php` | Raw PHP config leaking DB and LDAP passwords |
| `GET /old-api/v1/users` | JSON list of internal users with roles and emails |
| `GET /old-api/v1/config` | JSON config with database and LDAP credentials |
| `GET /phpmyadmin/` | Fake phpMyAdmin login page |
| `GET /manager/html` | Fake Apache Tomcat manager (returns 401 with auth prompt) |
| `GET /config` | Same PHP config source rendered inside an HTML `<pre>` block |
| `GET /robots.txt` | Intentionally lists all bait paths — helps scanners find them |

---

## SQLite Schema

```sql
-- One row per HTTP request
SELECT id, timestamp, source_ip, method, path, severity,
       is_internal, scanner_type, fingerprint_details
FROM requests;

-- One row per dispatched alert
SELECT id, timestamp, source_ip, alert_type, severity,
       endpoints_accessed, scanner_type, details
FROM alerts;
```

---

# Q1 — Network Diagram

```
 ╔══════════════════════════════════════════════════════════════════════╗
 ║                    EXTERNAL THREAT ACTOR                            ║
 ║          (Phishing email / malicious file download)                 ║
 ╚══════════════════════════════════════════════════════╤═══════════════╝
                                                        │
                              Attacker gains remote     │
                              control (RAT / C2)        │
                                                        ▼
 ╔══════════════════════════════════════════════════════════════════════╗
 ║  EMPLOYEE VLAN — 10.0.2.0/24                                        ║
 ║                                                                     ║
 ║  ┌─────────────────────┐                                            ║
 ║  │  Compromised        │  ◄── Attacker now operating                ║
 ║  │  Employee PC        │      from inside the network               ║
 ║  │  10.0.2.42          │                                            ║
 ║  └──────────┬──────────┘                                            ║
 ╚═════════════╪════════════════════════════════════════════════════════╝
               │  Cross-VLAN lateral movement (inter-VLAN routing)
               │  attacker port-scans every host in the server subnet
               ▼
 ╔══════════════════════════════════════════════════════════════════════╗
 ║  SERVER VLAN — 10.0.1.0/24                                          ║
 ║                                                                     ║
 ║  ┌──────────────────────────┐     ┌──────────────────────────┐      ║
 ║  │        HONEYPOT          │────►│    SOC / Admin           │      ║
 ║  │  10.0.1.99 :8080         │Alert│    alert@corp.local      │      ║
 ║  │  "CORP-INTRANET-OLD01"   │Email│    Slack / Teams webhook │      ║
 ║  │   Apache 2.2.14 (fake)   │     └──────────────────────────┘      ║
 ║  └──────────────────────────┘                                        ║
 ║                                                                      ║
 ║  Real servers (honeypot draws fire away from these):                 ║
 ║  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐    ║
 ║  │ AD / DC  │  │ DB Server│  │   File   │  │ Production Web   │    ║
 ║  │ 10.0.1.5 │  │ 10.0.1.10│  │   Share  │  │    Server        │    ║
 ║  │          │  │          │  │ 10.0.1.20│  │  10.0.1.30       │    ║
 ║  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘    ║
 ╚══════════════════════════════════════════════════════════════════════╝

Traffic key
  ──── Normal internal traffic (employees → real servers via L3 switch)
  ════ Attacker cross-VLAN scan (employee VLAN → server VLAN)
  ────► Honeypot alert to SOC (email / webhook)
```

### Placement rationale

| Decision | Reason |
|----------|--------|
| Honeypot placed in server VLAN (10.0.1.0/24), alongside real servers | An attacker pivoting from the employee VLAN will port-scan the entire server subnet — the honeypot is discovered at the same time as AD, DB, and file servers. |
| Employee workstations isolated in a separate VLAN (10.0.2.0/24) | Legitimate users have no business need to contact the server VLAN directly; any HTTP connection to the honeypot is immediately suspicious. |
| No firewall rule blocking inbound HTTP from the employee VLAN | The honeypot must be reachable by any compromised machine that can route across VLANs. |
| Not advertised in DNS or Active Directory | No legitimate user has a reason to browse to it; any contact is therefore suspicious. |
| Isolated from real data stores | The honeypot holds only fake credentials. It cannot be used as a pivot to reach real databases. |

---

# Q2 — Vulnerable Web Server Breakdown

## 2.0 Web Server Role & Purpose

**CORP-INTRANET-OLD01** (`10.0.1.99:8080`) impersonates a legacy **Document Management System (DMS) v2.1** that was used by the Finance and HR departments from 2009 to 2013. It sits in the server VLAN alongside real production servers (AD, DB, File Share) and has been left running without active maintenance — the kind of forgotten, unpatched server common in large organisations.

### Why does this server exist?

| Attribute | Detail |
| --------- | ------ |
| **Hostname** | `CORP-INTRANET-OLD01` |
| **Claimed role** | Internal Document Management System — stores policy documents, HR forms, finance reports |
| **Location** | Server VLAN `10.0.1.0/24`, reachable from employee VLAN via inter-VLAN routing |
| **Apparent age** | Last updated 2013 (copyright notices, HTML 4.01, vintage CSS) |
| **Tech stack (fake)** | Apache 2.2.14 (Win32), PHP 5.2.17 — both end-of-life and CVE-rich |
| **Why attractive to an attacker** | Old software = hundreds of known CVEs; exposed admin panel, DB backups, and credentials that could be used to pivot to real servers in the same subnet |

### Vulnerability Summary

| Vulnerability | CWE / OWASP | Endpoint(s) | Attacker goal |
| ------------- | ----------- | ----------- | ------------- |
| Exposed environment file | CWE-538 / A05 Security Misconfiguration | `/.env` | Harvest DB, LDAP, SMTP, and API credentials in plaintext |
| PHP source disclosure | CWE-200 / A05 Security Misconfiguration | `/config.php`, `/config` | Read hardcoded DB password, LDAP bind password, encryption key |
| SQL injection authentication bypass | CWE-89 / A03 Injection | `POST /admin/login` | Bypass login with e.g. `' OR 1=1--` |
| Hardcoded credential | CWE-798 / A07 Identification and Authentication Failures | `POST /admin/login` | Log in with guessable admin password |
| Broken access control — backup exposure | CWE-284 / A01 Broken Access Control | `/backup/`, `/db_backup.sql`, `/backup.zip` | Download MySQL dump containing password hashes and API keys |
| Unauthenticated legacy API | CWE-306 / A01 + A07 | `/old-api/v1/users`, `/old-api/v1/config` | Enumerate internal users and credentials without authentication |
| Exposed phpMyAdmin | CWE-16 / A05 Security Misconfiguration | `/phpmyadmin/` | Brute-force database admin access |
| Exposed Tomcat Manager | CVE-2010-4094 family / A05 | `/manager/html` | Deploy a malicious WAR file for remote code execution |
| Path disclosure via `robots.txt` | CWE-548 / A01 | `/robots.txt` | Automatically discover every hidden bait path |

---

## 2.1 Fake Identity

The honeypot presents itself as **"CORP-INTRANET-OLD01"** — an old Corporate
Document Management System (DMS) v2.1, running:

```
Server: Apache/2.2.14 (Win32)
X-Powered-By: PHP/5.2.17
X-Generator: DMS v2.1
```

These version strings are deliberately ancient (Apache 2.2.14 was released in
2010; PHP 5.2 reached end-of-life in 2011). A scanner checking CVE databases
will immediately flag dozens of known vulnerabilities, making this server look
like a high-value, easy target.

The homepage is an old-style HTML 4.01 directory listing, styled with a
corporate blue colour scheme and copyright notices from 2009–2013.

## 2.2 Bait Endpoints & Intentional Vulnerabilities

### `/robots.txt`
**What it does:** Lists every sensitive path under `Disallow:`.

**Why attractive:** `robots.txt` is the first file every web scanner checks.
By listing `/admin/`, `/backup/`, `/.env`, etc., the honeypot actively *invites*
the attacker to explore those paths.

---

### `/.env`
**What it serves:** A Laravel-style `.env` file with:
- `DB_PASSWORD=Dms@2011!Prod#9x`
- `LDAP_BIND_PASSWORD=LdapSvc!2009#Prod`
- `MAIL_PASSWORD=M@ilP@ss2010!`
- `SECRET_KEY=7f4d2e9a...`

**Vulnerability simulated:** Exposed environment file (CWE-538 / OWASP A05).
Every production breach checklist includes grabbing `.env` immediately.

---

### `/config.php`
**What it serves:** Raw PHP source (as if the PHP interpreter stopped working)
containing `DB_PASS`, `LDAP_BIND_PASS`, SMTP credentials, and an encryption key.

**Vulnerability simulated:** Misconfigured server serving PHP source instead of
executing it (common on IIS + PHP installs, or after a PHP upgrade).

---

### `/admin/login` (GET + POST)
**What it does:**
- `GET` — renders a realistic HTML login form.
- `POST` — logs all submitted credentials, then:
  - **SQL injection detected** (e.g. `' OR 1=1--`, `UNION SELECT`) → redirect to `/admin/dashboard` (fake bypass success).
  - **Valid hardcoded credential** matched → redirect to `/admin/dashboard`.
  - **Anything else** → re-renders the login form with an error (attacker keeps trying).

**Vulnerability simulated:** SQL injection bypass and a weak hardcoded credential (CWE-798 / OWASP A07). The attacker believes injection worked; every attempt is captured in the database.

---

### `/admin/dashboard`, `/admin/users`
**What it serves:** Fake admin panel showing internal usernames, email addresses,
and recent file-access activity labelled "CONFIDENTIAL".

**Why attractive:** Looks like a real goldmine. The attacker spends time
downloading this data — time the SOC uses to respond.

---

### `/backup/` + `/db_backup.sql`
**What it serves:**
- A directory listing with a `db_backup.sql` (18 MB) and a `backup_20130201.zip` (142 MB).
- The SQL dump contains a full MySQL schema with five user rows including
  MD5-crypt hashed passwords (`$apr1$...`) and three API keys.

**Vulnerability simulated:** Exposed backup directory (OWASP A01 — Broken Access
Control). Backup files are a common target because they contain database dumps,
source code, and credentials.

---

### `/old-api/v1/users` + `/old-api/v1/config`
**What it serves:** JSON responses with internal user lists and a config object
containing live-looking DB and LDAP credentials.

**Vulnerability simulated:** Unauthenticated legacy API endpoint (OWASP A01 +
A07 Identification and Authentication Failures).

---

### `/phpmyadmin/`
**What it serves:** A realistic phpMyAdmin 3.3.10.4 login form pre-filled with
server `10.0.1.10`.

**Vulnerability simulated:** Exposed phpMyAdmin (extremely common misconfiguration).
Attackers routinely attempt default credentials (`root:`, `root:root`, etc.).

---

### `/manager/html` (Tomcat Manager)
**What it serves:** HTTP 401 with `WWW-Authenticate: Basic realm="Tomcat Manager Application"`.

**Vulnerability simulated:** Exposed Apache Tomcat Manager (CVE-rich, allows WAR
deployment if authenticated).

---

## 2.3 Step-by-Step Attack Path

```
Phase 1 — Reconnaissance
  Attacker runs: nmap -sV 10.0.1.0/24   (probing the server VLAN from employee VLAN)
  → Finds port 8080 open on 10.0.1.99
  → Banner: "Apache/2.2.14 (Win32)" — flags as potentially vulnerable

Phase 2 — Initial Scan
  Attacker runs: nikto -h http://10.0.1.99:8080
              or: gobuster dir -u http://10.0.1.99:8080 -w common.txt
  → Hits /robots.txt → reads list of hidden paths
  → Starts requesting /.env, /config.php, /backup/, /phpmyadmin/
  ← ALERT TRIGGERED: INTERNAL IP FIRST CONTACT (severity HIGH)
  ← Tarpit begins: each new request incurs 1 s → 2.5 s → 6.3 s … delay

Phase 3 — Credential / Data Harvesting
  Attacker downloads /.env → copies DB password, LDAP password
  Attacker downloads /db_backup.sql → copies user hashes, API keys
  Attacker visits /old-api/v1/config → gets JSON with credentials
  ← All requests logged with full headers and body

Phase 4 — Authentication Attempt
  Attacker submits credentials to /admin/login (POST)
  ← ALERT TRIGGERED: INTERNAL CREDENTIAL SUBMISSION (severity HIGH)
  ← 3-second POST delay simulates "slow authentication"
  ← Submitted username + password captured in DB
  → SQLi bypass detected → redirect to /admin/dashboard (attacker thinks injection worked)
  → Wrong credentials → error page → attacker keeps guessing (all attempts logged)

Phase 5 — Post-Auth Exploration
  Attacker browses /admin/dashboard, /admin/users
  → Reads fake user table and "confidential" activity log
  → Tries /phpmyadmin/ with harvested password
  ← All actions logged; tarpit delays now at 15-30 s per request
  ← SOC has received alert and is tracing 10.0.2.42
```

---

# Q3 — Detection & Alerting Mechanism

## 3.1 Distinguishing Attacker from Accidental User

| Signal | Accidental user | Attacker |
|--------|-----------------|---------|
| Source IP | Internal, known workstation | Internal, possibly unknown/dynamic |
| User-Agent | Normal browser (Chrome, Edge) | Scanner tool or generic HTTP client |
| Paths requested | Maybe root `/` once | `/robots.txt`, `/.env`, `/backup/`, `/db_backup.sql`, `/admin/login` |
| Request volume | 1–3 requests, then stops | Dozens or hundreds in minutes |
| POST to `/admin/login` | Never (no reason to know this URL) | Common after finding login form |
| Tarpit effect | First 3 requests are instant — user gives up | Scanner keeps retrying despite delays |

A single accidental visit to `/` is treated as **INFO** and does NOT trigger an
alert. The alert threshold requires contact from an **internal IP range** — the
assumption being that no employee has a legitimate reason to browse to this
server (it is not in DNS, not linked from any other system, not mentioned in
any documentation).

## 3.2 Alert Triggers

| Condition | Severity | Alert type |
|-----------|----------|------------|
| Any internal IP — first ever request | HIGH | `INTERNAL IP FIRST CONTACT` |
| Internal IP + POST to any endpoint | HIGH | `INTERNAL CREDENTIAL SUBMISSION` |
| Internal IP + scanner User-Agent detected | CRITICAL | `INTERNAL SCANNER DETECTED (Nikto)` |
| External IP + known scanner UA | MEDIUM | `EXTERNAL SCANNER (sqlmap)` |
| Repeat contact from same internal IP after cooldown | HIGH | Re-alert (severity maintained or escalated) |

## 3.3 Full Alert Lifecycle

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. PACKET RECEIVED                                                  │
│    aiohttp accepts TCP connection from 10.0.2.42:54321              │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────┐
│ 2. SOURCE IP EXTRACTED                                              │
│    X-Forwarded-For header checked; falls back to request.remote     │
│    IP classified: internal? (matches 10.0.0.0/8 → YES)             │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────┐
│ 3. PASSIVE FINGERPRINT                                              │
│    User-Agent: "python-requests/2.28.0"                             │
│    → matched against SCANNER_SIGNATURES                             │
│    → scanner_name = "python-requests", confidence = "high"          │
│    Path: "/.env" → suspicious_path = True                           │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────┐
│ 4. TARPIT DELAY                                                     │
│    Request count for this IP in window: 4                           │
│    delay = 1.0 × 2.5^(4-3-1) = 1.0 s  (asyncio.sleep — non-block) │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────┐
│ 5. REQUEST LOGGED TO SQLITE                                         │
│    Table: requests                                                  │
│    source_ip="10.0.2.42", method="GET", path="/.env"                │
│    is_internal=1, scanner_type="python-requests"                    │
│    severity="CRITICAL"                                              │
│    fingerprint_details="Tool detected: python-requests | Suspicious │
│                          path: /.env"                               │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────┐
│ 6. ALERT CONDITION EVALUATED                                        │
│    is_internal=True AND scanner detected → needs_alert = True       │
│    AlertTracker: first time seeing 10.0.2.42 → should_alert=True    │
│    Alert recorded in tracker, alert row inserted into DB            │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────┐
│ 7. ALERT DISPATCHED (asyncio.create_task — non-blocking)            │
│                                                                     │
│    ┌─── Email ──────────────────────────────────────────────────┐   │
│    │ To: soc@corp.local                                         │   │
│    │ Subject: [HONEYPOT CRITICAL] INTERNAL SCANNER DETECTED     │   │
│    │          (python-requests) — 10.0.2.42                     │   │
│    │ Body: IP, timestamp, endpoints, tool, action required       │   │
│    └────────────────────────────────────────────────────────────┘   │
│                                                                     │
│    ┌─── Webhook ────────────────────────────────────────────────┐   │
│    │ POST https://hooks.slack.com/...                           │   │
│    │ Colour: #7b0000 (dark red = CRITICAL)                      │   │
│    │ Fields: IP, severity, tool, endpoints, action required     │   │
│    └────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────┐
│ 8. SOC RECEIVES ALERT                                               │
│                                                                     │
│  Alert contains:                                                    │
│  • Source IP:  10.0.2.42                                            │
│  • Severity:   CRITICAL                                             │
│  • Tool:       python-requests                                      │
│  • Endpoints:  ["/robots.txt", "/.env", "/db_backup.sql", ...]      │
│  • Timestamp:  2026-02-23 09:14:33 UTC                              │
│                                                                     │
│  SOC analyst actions:                                               │
│  1. Query DHCP server: what machine holds 10.0.2.42?               │
│     → "WKSTN-FINANCE-07 leased to b.williams since 08:30"          │
│  2. Query AD: who is logged in to WKSTN-FINANCE-07?                 │
│     → bwilliams (Bob Williams, Finance dept)                        │
│  3. Contact Bob — confirm he is at his desk / check for phishing    │
│  4. Isolate WKSTN-FINANCE-07 via NAC / VLAN reassignment            │
│  5. Begin forensic imaging and incident response                    │
└─────────────────────────────────────────────────────────────────────┘
```

## 3.4 What the Admin Receives

```
╔══════════════════════════════════════════════════╗
║           HONEYPOT SECURITY ALERT                ║
╚══════════════════════════════════════════════════╝

Severity      : CRITICAL
Alert Type    : INTERNAL SCANNER DETECTED (python-requests)
Timestamp     : 2026-02-23 09:14:33 UTC
Source IP     : 10.0.2.42
Tool/Scanner  : python-requests

Endpoints accessed:
  • /robots.txt
  • /.env
  • /db_backup.sql
  • /admin/login (POST — credentials submitted)
  • /old-api/v1/config

Details:
Tool detected: python-requests | Suspicious path: /.env

──────────────────────────────────────────────────
ACTION REQUIRED
  1. Identify which machine owns IP: 10.0.2.42
     (Check DHCP leases, AD computer accounts, NAC logs)
  2. Isolate the machine from the network immediately.
  3. Begin incident response — assume full compromise.
──────────────────────────────────────────────────
```

This single alert gives the SOC analyst everything needed to:

- Pinpoint the compromised machine (via DHCP/NAC lookup of `10.0.2.42`)
- Understand the attacker's intent (credential harvesting, reconnaissance)
- Prioritise response (CRITICAL = active scanner from internal IP)
- Act fast — the tarpit is buying time, but the window is limited

---

*This honeypot is designed for authorised defensive use only within a monitored
corporate environment. Deploy only on isolated network segments you own and
operate. Consult your legal and compliance team before deployment.*

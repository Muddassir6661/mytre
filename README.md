# MyTRE — ATT&CK-Mapped Adversary Emulation Framework

> ⚠️ **Authorized use only.** MyTRE is designed strictly for use on systems
> you own or have explicit written permission to test. Unauthorized use is
> illegal under the IT Act 2000 (India), CFAA (US), and equivalent laws.

A modular Python framework that chains security-testing techniques into a
structured adversary campaign, with every stage explicitly tagged to a real
[MITRE ATT&CK](https://attack.mitre.org) technique ID. At the end of a run,
MyTRE generates a pentest-style findings report in Markdown and HTML.

Built as a final-year capstone project, inspired by the design philosophy of
[MITRE CALDERA](https://caldera.mitre.org/) and [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team).

---

## Architecture

```
mytre/
├── core/
│   ├── technique.py      # Technique base class + TechniqueResult
│   ├── context.py        # Shared campaign state (hosts, creds, files)
│   ├── campaign.py       # Campaign engine (YAML loader + runner)
│   └── attck.py          # ATT&CK registry (technique metadata)
├── techniques/
│   ├── reconnaissance/   # T1046 — Port Scan
│   ├── credential_access/ # T1110.001 — SSH Brute Force
│   ├── lateral_movement/  # T1021.004 — SSH Pivot
│   └── exfiltration/      # T1041 — HTTP Exfil
├── reporting/
│   └── report_generator.py
├── campaigns/
│   └── homelab_assessment.yaml
└── main.py
```

## Quick Start

```bash
git clone https://github.com/Muddassir6661/mytre
cd mytre
pip install -r requirements.txt

# Edit campaigns/homelab_assessment.yaml to set your target IP
python main.py run campaigns/homelab_assessment.yaml
```

## Campaign Format

```yaml
campaign: my_assessment

stages:
  - module: reconnaissance.port_scan:PortScan
    params:
      target: "192.168.0.115"
      port_range: "1-1024"

  - module: credential_access.ssh_brute:SSHBruteForce
    params:
      target: "192.168.0.115"
      wordlist: "wordlists/passwords.txt"
    continue_on_failure: false

  - module: lateral_movement.ssh_pivot:SSHPivot
    params:
      target: "192.168.0.115"

  - module: exfiltration.http_exfil:HTTPExfil
    params:
      listener_url: "http://192.168.0.115:8080/upload"
```

## ATT&CK Coverage

| Technique | ID | Tactic |
|---|---|---|
| Port Scan | T1046 | Reconnaissance |
| SSH Brute Force | T1110.001 | Credential Access |
| SSH Pivot | T1021.004 | Lateral Movement |
| HTTP Exfiltration | T1041 | Exfiltration |

## Output

Each run produces a Markdown and HTML report under `reports/`:
- Executive summary
- Findings table (ATT&CK ID, tactic, severity, duration)
- Per-stage narrative with evidence
- Collected artifacts (hosts, credentials, staged files)

# MyTRE — Module Reference

Each module maps to one MITRE ATT&CK technique. This document explains
what each one does, how it works under the hood, and what to look for
when reading its results.

---

## Reconnaissance

### T1046 — Port Scan (`port_scan.py`)
**What it does:** Tries to open a TCP connection to every port in the
configured range on the target. If the connection succeeds, the port
is open.

**How it works:** Python's `socket.create_connection()` with a short
timeout. No raw packets, no root required. This is a "connect scan" —
the same thing your browser does when it visits a website, just repeated
for each port.

**What to look for in results:** `open_ports` list. These feed into
`ServiceFingerprint` in the next stage.

---

### T1592 — Service Fingerprint (`service_fingerprint.py`)
**What it does:** Connects to each open port and reads the first few
bytes the service sends back — its "banner." SSH says what version it
is. Apache says what web server it is. This is how you know what
software is running without logging in.

**How it works:** Opens a socket, sends a minimal HTTP HEAD request on
web ports, and reads the response. Stores banners in `Context` host notes.

**What to look for in results:** `fingerprints` dict — port → service
name → banner text. The VulnScan stage reads this.

---

### T1595.002 — Vulnerability Scan (`vuln_scan.py`)
**What it does:** Takes the banner text from ServiceFingerprint and
checks it against a local database of CVE signatures using regex
pattern matching. If OpenSSH 7.x is in the banner, it flags
CVE-2018-15473. If Apache 2.4.49 appears, it flags CVE-2021-41773.

**How it works:** Pure regex — no exploit code runs, no network
connection beyond what ServiceFingerprint already did. Same core logic
as Nessus "safe checks."

**What to look for:** If it FAILs, that means NO CVEs matched — your
target is patched. This is the correct result for a hardened host.

---

## Initial Access

### T1078 — HTTP Default Credentials (`http_default_creds.py`)
**What it does:** Tries common default username/password pairs
(admin/admin, admin/password, etc.) against a web login form.

**How it works:** Fetches the login page first to extract DVWA's
CSRF token (`user_token`), then submits each credential pair with
that token. Without the token, DVWA silently rejects everything.
Checks the response for a success indicator ("logout") and absence
of failure text ("incorrect").

**What to look for:** `credential_found: true` and `username` in
evidence. The session cookie gets stored in `Context.extra` for
CommandInjection to reuse.

---

### T1190 — Command Injection (`command_injection.py`)
**What it does:** Tests whether a web application passes user input
directly to the OS shell. On DVWA's exec page, submitting `127.0.0.1; id`
runs `ping 127.0.0.1` AND `id` — the semicolon chains commands.

**How it works:** Logs into DVWA first (reusing session from
HTTPDefaultCreds if available), sets the `security=low` cookie, then
tries each payload. Looks for `uid=` in the response to confirm RCE.

**What to look for:** `successful_payload` and `rce_output` —
`uid=33(www-data)` means the web server process ran your command.

---

## Credential Access

### T1110.001 — SSH Brute Force (`ssh_brute.py`)
**What it does:** Tries every password in the wordlist against the
target SSH server until one works.

**How it works:** Uses `paramiko` to attempt a real SSH login for each
candidate. Stops on first success if `stop_on_first: true`. Valid
credentials go into `Context` only — never into result dicts or reports.

**What to look for:** `credential_found: true`, `passwords_tried` count.
The actual password is intentionally hidden everywhere except Context memory.

---

### T1552 — Credentials in Files (`creds_in_files.py`)
**What it does:** After gaining SSH access, searches common locations
for plaintext credentials — PHP config files, `.env` files, bash
history, DVWA's own config.

**How it works:** Opens an SSH session using Context credentials, runs
a series of `find` and `grep` commands, and returns any output that
contains password-related keywords.

**What to look for:** `findings` list — each entry is a command and
its output. DVWA's `config.inc.php` usually has MySQL credentials.

---

## Discovery

### T1087 — Account Discovery (`account_discovery.py`)
**What it does:** Enumerates local user accounts on the target.

**How it works:** Reads `/etc/passwd` over SSH, filtering out
system/service accounts (nologin, false). Also checks the sudo group
and recent login history.

**What to look for:** `accounts` list — interactive human accounts.
In your homelab this showed `root, sync, fareed, bruteforcetest`.

---

### T1057 — Process Discovery (`process_discovery.py`)
**What it does:** Lists running processes, specifically looking for
security tools, databases, and web servers.

**How it works:** Runs `ps aux` over SSH, filters for known service
names (apache, nginx, mysql, docker, wazuh, ssh).

**What to look for:** Whether a SIEM (Wazuh), IDS, or AV process
appears — a real adversary uses this to decide whether to proceed.

---

### T1016 — Network Config Discovery (`network_config_discovery.py`)
**What it does:** Maps the target's network — interfaces, routes,
open ports, ARP cache, DNS config, `/etc/hosts`.

**How it works:** Runs `ip addr`, `ip route`, `ss -ltnp`, `arp -n`,
and reads config files over SSH. ARP cache entries get added to
`Context` as discovered hosts.

**What to look for:** ARP output may reveal other hosts on the same
network — potential lateral movement targets.

---

### T1083 — File & Directory Discovery (`file_directory_discovery.py`)
**What it does:** Enumerates interesting filesystem locations — home
directories, web roots, config files, temp directories, SSH keys.

**How it works:** Runs targeted `ls` and `find` commands over SSH,
limited to known interesting paths to avoid noise.

**What to look for:** PHP files in `/var/www`, `.ssh` directories,
config files — anything that might contain credentials or be useful
for later stages.

---

## Lateral Movement

### T1021.004 — SSH Pivot (`ssh_pivot.py`)
**What it does:** Uses the credentials discovered by the brute force
stage to open an authenticated SSH session and run a probe command.

**How it works:** Reads the first valid credential from `Context`,
connects via `paramiko`, and runs `id && hostname && uname -a`.
Confirms you can execute commands as that user on the target.

**What to look for:** `probe_output` — `uid=1000(fareed)` means full
shell access as that user. Groups like `(sudo)` mean privilege
escalation is possible.

---

### T1570 — Lateral Tool Transfer (`lateral_tool_transfer.py`)
**What it does:** Copies a file from your attacker machine to the
target over SSH (SFTP). Simulates dropping a tool or payload.

**How it works:** Opens an SFTP channel over the existing SSH session
using `paramiko`, uploads the configured file, then reads back the
remote file size to verify it landed correctly.

**What to look for:** `remote_size_bytes` matching `local_size_bytes`.
The transferred file path gets added to `Context.staged_files`.

---

## Persistence

### T1098 — SSH Authorized Key (`ssh_authorized_key.py`)
**What it does:** Appends an SSH public key to `~/.ssh/authorized_keys`
on the target, creating persistent backdoor access that survives
password changes.

**How it works:** Creates `~/.ssh/` if it doesn't exist, sets correct
permissions (700 dir, 600 file), appends the key, and verifies it
landed by reading back the last line.

**What to look for:** `verification_output` confirming the key. 
**Always clean up after testing:**
`sed -i '/mytre-test/d' ~/.ssh/authorized_keys`

---

## Exfiltration

### T1074.001 — Local File Stage (`local_file_stage.py`)
**What it does:** Marks explicitly configured local files as "staged
for exfiltration" in Context. Does NOT collect arbitrary files.

**How it works:** Checks each path in the configured `paths` list
exists, then calls `context.stage_file()` for each one. The next
exfil stage reads this list.

**What to look for:** `staged` list — only files you explicitly
configured appear here. `missing` list if a path doesn't exist.

---

### T1041 — HTTP Exfiltration (`http_exfil.py`)
**What it does:** Zips all staged files from Context and POSTs the
archive to the configured listener URL.

**How it works:** Reads `Context.staged_files`, zips them in memory
using Python's `zipfile`, and sends via `requests.post()` with the
archive as a multipart form upload.

**What to look for:** `http_status: 200` means the receiver accepted
it. `archive_size_bytes` tells you how much was sent.

---

### T1048 — FTP Exfiltration (`ftp_exfil.py`)
**What it does:** Same as HTTP exfil but uses FTP as the transport —
an alternative protocol that may bypass HTTP-focused monitoring.

**How it works:** Uses Python's built-in `ftplib`, no extra dependency.
Run `python -m pyftpdlib -p 2121 -w` on your attacker box as the
listener.

**What to look for:** `archive_name` appearing on the FTP server.
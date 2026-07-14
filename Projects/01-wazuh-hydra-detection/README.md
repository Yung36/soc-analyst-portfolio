# Wazuh + Hydra SSH Brute Force Detection Lab

## Objective
Simulate a real-world SSH brute force attack against a monitored endpoint and validate that a self-hosted Wazuh SIEM can detect, correlate, and escalate the threat in near real-time — demonstrating the full alert lifecycle from raw log ingestion to an actionable, prioritized security event.

## Environment
| Role | System | IP Address |
|---|---|---|
| SIEM / Wazuh Manager | Ubuntu Server | 192.168.1.103 |
| Monitored Endpoint | Windows 11 (Wazuh Agent) | 192.168.1.84 |
| Attacker (simulated) | Kali Linux | 192.168.1.110 |

All systems are VirtualBox VMs running in bridged network mode, simulating a small internal network with a centralized SIEM collecting and correlating logs from endpoints.

**Why Wazuh:** free and open-source SIEM/XDR used in real-world SOCs, with multi-platform agent support (Windows, Linux, macOS) and fully customizable detection rules — as opposed to commercial platforms like Splunk Enterprise Security, IBM QRadar, or Microsoft Sentinel.

## Scenario
An attacker (Kali Linux) attempts to gain unauthorized access to the Ubuntu Server via SSH using a brute force dictionary attack against a known username. The Wazuh Manager, receiving authentication logs from the target, must detect the repeated failed login pattern and escalate it as a high-severity alert before the attacker can succeed.

## Tools Used
- **Wazuh** (SIEM/XDR) — log collection, correlation, and alerting
- **Hydra** — SSH brute force attack tool
- **Kali Linux** — attacker platform
- **Ubuntu Server** — SIEM host / attack target
- **rockyou.txt** — password dictionary (14.3M entries)

## Investigation Process

**1. Attack Execution**
Command run from Kali Linux:
```
hydra -l yung -P /usr/share/wordlists/rockyou.txt -t 1 -W 3 ssh://192.168.1.103
```
| Flag | Meaning |
|---|---|
| `-l yung` | Target username |
| `-P rockyou.txt` | Password dictionary (14.3M entries) |
| `-t 1` | Single connection at a time (avoids server lockout) |
| `-W 3` | 3-second wait between attempts |
| `ssh://192.168.1.103` | Target (Ubuntu Server) |

Attack start time: **17:09:37**

**2. Detection Timeline (Wazuh → Threat Hunting → Events)**

| Time | Event (rule.description) | Level |
|---|---|---|
| 17:09:38.951 | unix_chkpwd: Password check failed | 5 |
| 17:09:38.953 | PAM: User login failed | 5 |
| 17:09:38.959 | unix_chkpwd: Password check failed | 5 |
| 17:09:38.962 | PAM: User login failed | 5 |
| **17:09:40.800** | **sshd: brute force trying to get access to the system** | **10** |
| 17:09:40.954 | sshd: authentication failed | 5 |

**3. Correlation**
Less than 2 seconds after the first failed attempt, Wazuh correlated the repeated authentication failure pattern and triggered **rule 5763**, escalating severity from level 5 (individual failed logins) to **level 10** (active brute force attack).

## Findings
- Wazuh successfully detected the SSH brute force pattern in under 2 seconds from the first failed login.
- The escalation from level 5 to level 10 confirms the correlation engine is working as expected — individual failed logins are normal noise, but the *pattern* of rapid repeated failures is what triggers the real alert.
- This level 10 alert is the exact point where, in a production SOC, automated response (SOAR/Wazuh Active Response IP blocking), active notification (Slack/Teams + ticketing), and analyst investigation would all kick in.

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Initial Access | Valid Accounts (attempted) | T1078 |

## Screenshots
*(See `/screenshots` folder in this project directory)*
- Hydra attack command and terminal output
- Wazuh Threat Hunting dashboard showing the detection timeline
- Rule 5763 alert detail (level 10)

## Lessons Learned
- Individual failed login events (level 5) are common and expected noise — the real value of a SIEM is in **correlation**, not raw log collection.
- A repeatable, documented detection (attack → detection → correlation → alert) is far more valuable for a portfolio than an undocumented one-off test.
- This lab reinforced the full alert lifecycle a SOC L1 analyst needs to understand: from ingestion, to correlation, to the moment a human analyst receives an actionable, prioritized alert.

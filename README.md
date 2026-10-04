# Home SOC Lab — Wazuh, Windows 11, Ubuntu, and Kali

A self-built Security Operations Center lab, run entirely on a single laptop (Intel i5-7200U, 16 GB RAM)
using VMware Workstation. I deployed Wazuh as a SIEM, connected Windows and Linux endpoints, then ran
controlled attack scenarios and investigated the resulting alerts like a SOC analyst would.

## Lab architecture

- Wazuh server (4 GB RAM) — SIEM and alerting, dashboard at the manager
- Windows 11 Enterprise endpoint (4 GB RAM) — Wazuh agent installed, Windows Event Log monitoring
- Ubuntu Linux endpoint (2 GB RAM) — Wazuh agent installed, syslog/PAM/SSH monitoring
- Kali Linux (2 GB RAM) — attacker machine, used to run real tooling (Hydra) against the lab

All machines run on an isolated NAT network (192.168.227.0/24) with no exposure outside the laptop.

What I did

1. Built and connected a Wazuh server with Windows and Linux endpoints reporting as agents
2. Generated controlled failed-logon events on Windows and investigated single-event vs. correlated alerts
3. Ran SSH username-guessing and password-guessing attacks against the Linux endpoint
4. Used Hydra on Kali to run a real brute-force attack that successfully compromised a test account, then
   investigated the full attack chain from first failure to successful login
5. Found and documented a real detection gap: a correlation rule that catches manual/same-session brute-force
   attempts but misses a scripted, one-connection-per-attempt tool like Hydra
6. Wrote up every scenario as a full incident report with raw evidence (JSON) and analysis (Markdown)

## Incident reports

| # | Scenario | Key finding |
|---|---|---|
| [01](incident-01-failed-logons.md) | 6 failed Windows logons | Single events stay low-severity; correlation is what matters |
| [02](incident-02-multiple-logon-failures.md) | 15 failed Windows logons | Wazuh's aggregation rule triggers at 8 failures; vendor MITRE tag was wrong and corrected |
| [03](incident-03-ssh-password-guessing.md) | Manual SSH guessing against Linux | Compared single-event vs. correlated SSH alerts; found an open question about detection thresholds |
| [04](incident-04-hydra-ssh-bruteforce.md) | Scripted Hydra brute-force, successful login | **Detection gap**: per-session correlation rule missed a per-connection brute-force tool, even though the attack succeeded |

Each report includes the raw Wazuh alert data (`*-evidence*.json`) alongside the written analysis.

## Skills demonstrated

- SIEM deployment and agent management (Wazuh)
- Windows Event Log analysis (Event ID 4625, 4624, logon types, NTLM)
- Linux authentication log analysis (sshd, PAM, syslog)
- MITRE ATT&CK mapping, including correcting inaccurate vendor tags against observed behavior
- Offensive tooling for defensive testing (Hydra)
- Resource-constrained lab design and troubleshooting (VMware on limited hardware)
- Incident documentation to a professional standard

## Tools

VMware Workstation Pro, Wazuh 4.14.8, Windows 11 Enterprise (evaluation), Ubuntu 26.04, Kali Linux 2026.2, Hydra

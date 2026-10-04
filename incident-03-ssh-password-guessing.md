# Incident 03: SSH username guessing against ubuntu-endpoint

**Host:** ubuntu-endpoint (192.168.227.129)
**Detections:** Wazuh rule 5710 (level 5, about 5 events), rule 5503 (level 5), rule 2502 (level 10, fired once)
**Window:** 05:33:55 to 05:34:13 UTC, 2026-10-04

## Evidence
- Source: 192.168.227.1 (host adapter on the VMware NAT network)
- Account tried: fakeadmin (does not exist on the host)
- Log lines show "Connection reset by invalid user fakeadmin ... [preauth]": the client disconnected before authentication completed
- Rule 2502 triggered by one PAM log line: "PAM 2 more authentication failures ... rhost=192.168.227.1"
- Attempts about 6 to 8 seconds apart, consistent with manual typing, not automation

## Assessment
Controlled test (manual SSH attempts from the lab host). Behavior matches username/password guessing over SSH.

## MITRE ATT&CK
- Wazuh tags: T1110.001 Password Guessing (Credential Access), T1021.004 SSH (Lateral Movement)
- Best fit: T1110.001. T1021.004 only reflects that SSH was the attack surface; no lateral movement occurred.

## Detection findings
- Rule 2502 is level 10 but is triggered by a single PAM summary line, not by Wazuh-side event counting. Compare Incident 02, where rule 60204 required 8 events (frequency 8).
- Individual 5710 events stay at level 5.
- Open question: whether a dedicated SSH brute-force rule fires at a higher failure count.
- Rootcheck events (rule 510) at agent start and a sudo event (rule 5402) were administrator activity, not attacker activity.

## Recommended actions
- Disable SSH password authentication, use keys
- Install fail2ban or equivalent lockout
- Restrict SSH exposure by source address
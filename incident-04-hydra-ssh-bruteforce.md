# Incident 04: Scripted SSH brute-force (Hydra) against ubuntu-endpoint — successful compromise, with a detection gap

**Host:** ubuntu-endpoint (192.168.227.129)
**Attacker:** Kali VM (192.168.227.132), tool: Hydra v9.7
**Window:** 07:46:16 to 07:46:17 UTC, 2026-10-04 (under 1 second)

## Evidence
- 5 failed SSH logins, rule 5760 "sshd: authentication failed" (level 5), target account ibrahim-gillani
- 5 matching PAM failures, rule 5503 (level 5)
- 1 successful login, rule 5715 "sshd: authentication success" (level 3)
  full_log: "Accepted password for ibrahim-gillani from 192.168.227.132 port 48168 ssh2"
- All 6 attempts from the same source (192.168.227.132), same target account, within 1 second

## Assessment
Controlled test. Hydra successfully guessed the account password after 5 wrong attempts. This simulates a
real compromise: an attacker who brute-forces a weak password and gets in.

## MITRE ATT&CK
- Failed attempts: T1110.001 Password Guessing (Credential Access)
- Successful login: Wazuh tags rule 5715 as T1078 Valid Accounts / T1021 Remote Services, across five tactics
  (Initial Access, Persistence, Privilege Escalation, Defense Evasion, Lateral Movement). This tag is generic:
  it fires on every successful SSH login, legitimate or attacker. Only the context — 5 failures from the same
  source immediately before — makes this one suspicious.

## Detection gap found (key finding)
- No brute-force correlation alert (rule 2502, level 10) fired for this attack, even though it succeeded.
- Compared to Incident 03 (manual SSH attempts, same session, 2+ failures), which did trigger rule 2502.
- Root cause: rule 2502 fires on a PAM summary line ("N more authentication failures") that Linux writes once
  per SSH session when multiple passwords are tried on the same connection. Hydra opens a new SSH connection
  per password attempt by default, so PAM never accumulates failures within one session, and the summary line
  is never written.
- Impact: a disciplined, one-attempt-per-connection brute-force tool can succeed without tripping this
  correlation rule, even though the individual failures (rule 5760) and the eventual success (rule 5715) are
  both logged and visible to an analyst who is looking.

## Recommended actions
- Do not rely on rule 2502 alone for SSH brute-force detection; it misses per-connection attack tools.
- Add a detection rule that counts rule 5760 events per source IP across multiple sessions within a time
  window (not just within one session).
- Alert specifically on a rule 5715 success that is immediately preceded by rule 5760 failures from the same
  source IP, regardless of session boundaries.
- Enforce SSH key-based authentication and disable password login, which removes this attack path entirely.
- Rate-limit or fail2ban repeated connection attempts from the same source IP.
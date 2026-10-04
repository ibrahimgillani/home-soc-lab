# Incident 02: Multiple Windows Logon Failures (brute-force correlation)

**Host:** win11-endpoint (DESKTOP-FVUB51N)
**Detection:** Wazuh rule 60204 "Multiple Windows Logon Failures" (level 10), fired 05:06:34 UTC on 2026-10-04
**Trigger:** frequency 8, built from Windows Event ID 4625 events

## Evidence
- 8 failed logons in about 45 seconds (05:05:48 to 05:06:33 UTC), record IDs 1577 to 1591
- Target account: labuser (existing; substatus 0xc000006a = wrong password)
- Logon type 3 (network), NTLM, source ::1 (loopback)
- Source port incremented with each attempt, consistent with scripted attempts

## Assessment
Controlled test (15 scripted attempts). Behavior matches password guessing against a valid account.

## MITRE ATT&CK
- Wazuh tag: T1110 Brute Force (Credential Access)
- Best fit: T1110.001 Password Guessing

## Detection findings
- Single events (rule 60122, level 5) did not alert on their own. Run 1 with 6 failures never reached the threshold of 8.
- Rule 60122 is tagged T1531 (Impact), which does not match the behavior. Rule 60204 is tagged correctly.
- Open question: only one 60204 alert fired for 15 attempts.

## Recommended actions
- Account lockout policy
- Alert on repeated 4625 events per account and per source
- Review whether NTLM is needed
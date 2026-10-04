# Incident 01: Repeated failed network logons against labuser

**Host:** win11-endpoint (DESKTOP-FVUB51N)
**Detection:** Wazuh rule 60122 (level 5), Windows Event ID 4625
**Count:** 6 events in about 30 seconds (09:38:48 to 09:39:20 local time)

## Evidence
- Target account: labuser (existing account)
- Sub status 0xc000006a: wrong password for a valid account
- Logon type 3 (network), NTLM authentication
- Source address: ::1 (loopback), port 55549
- Subject SID S-1-0-0: no authenticated user initiated it
- No successful logon (Event ID 4624) alerted in Wazuh during or after the failed attempts

## Assessment
Controlled test, not a real attack. The activity matches password guessing against a valid account.

## MITRE ATT&CK
- Correct mapping: T1110.001 Password Guessing (Credential Access)
- Wazuh rule metadata tags it as T1531 Account Access Removal (Impact), which does not fit the observed behavior.

## Gap found
Six failures in about 30 seconds did not trigger an aggregated brute-force alert. Every event stayed at level 5.

## Recommended actions
- Enable an account lockout policy
- Alert on repeated 4625 events per account and per source
- Review whether NTLM is needed
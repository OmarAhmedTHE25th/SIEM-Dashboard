# MITRE ATT&CK coverage

The dashboard's **ATT&CK Coverage** panel and `GET /api/coverage` endpoint
report the static mappings used by the detectors. A rule is marked covered
when at least one alert for that rule exists in the database; tactic rows are
kept visible at zero so gaps are explicit.

| Rule | Technique | Name | Tactics |
|---|---|---|---|
| SSH_BRUTE_FORCE | T1110.001 | Brute Force: Password Guessing | Credential Access |
| SUCCESS_AFTER_MANY_FAILURES | T1078 | Valid Accounts | Initial Access; Defense Evasion; Persistence; Privilege Escalation |
| OFF_HOURS_LOGIN | T1078 | Valid Accounts | Initial Access; Defense Evasion; Persistence; Privilege Escalation |
| IMPOSSIBLE_TRAVEL | T1078 | Valid Accounts | Initial Access; Defense Evasion; Persistence; Privilege Escalation |
| CORR_COMPROMISE_SUSPECTED | T1078 | Valid Accounts | Initial Access; Defense Evasion; Persistence; Privilege Escalation |
| CORR_MULTI_STAGE_ATTACK | T1078 | Valid Accounts | Initial Access; Defense Evasion; Persistence; Privilege Escalation |
| CORR_ACCOUNT_TAKEOVER | T1078 | Valid Accounts | Initial Access; Defense Evasion; Persistence; Privilege Escalation |
| IOC_MATCH | T1588.006 | Vulnerability Research | Resource Development |
| SURICATA_ALERT | T1190 | Exploit Public-Facing Application | Initial Access |

The static tactic catalog also includes Execution, Discovery, Lateral Movement,
Collection, Command and Control, Exfiltration, and Impact; these currently have
no mapped rules.

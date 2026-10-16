# MITRE ATT&CK coverage

The dashboard's **ATT&CK Coverage** panel and `GET /api/coverage` endpoint
report the static mappings used by the detectors. A rule is marked covered
when at least one alert for that rule exists in the database.

## Tactic summary

| Tactic | Techniques covered | Rules |
|---|---|---|
| Reconnaissance | — | — |
| Resource Development | T1588.006 | IOC_MATCH |
| Initial Access | T1078, T1078.003, T1133, T1190 | SUCCESS_AFTER_MANY_FAILURES; OFF_HOURS_LOGIN; IMPOSSIBLE_TRAVEL; CORR_COMPROMISE_SUSPECTED; CORR_MULTI_STAGE_ATTACK; CORR_ACCOUNT_TAKEOVER; IOC_MATCH; SURICATA_ALERT |
| Execution | — | — |
| Persistence | T1078, T1078.003, T1133 | SUCCESS_AFTER_MANY_FAILURES; OFF_HOURS_LOGIN; IMPOSSIBLE_TRAVEL; CORR_COMPROMISE_SUSPECTED; CORR_ACCOUNT_TAKEOVER |
| Privilege Escalation | T1078, T1078.003 | SUCCESS_AFTER_MANY_FAILURES; OFF_HOURS_LOGIN; IMPOSSIBLE_TRAVEL; CORR_COMPROMISE_SUSPECTED; CORR_ACCOUNT_TAKEOVER |
| Defense Evasion | T1078, T1078.003 | SUCCESS_AFTER_MANY_FAILURES; OFF_HOURS_LOGIN; IMPOSSIBLE_TRAVEL; CORR_COMPROMISE_SUSPECTED; CORR_ACCOUNT_TAKEOVER |
| Credential Access | T1110.001 | SSH_BRUTE_FORCE; CORR_COMPROMISE_SUSPECTED |
| Discovery | — | — |
| Lateral Movement | — | — |
| Collection | — | — |
| Command and Control | T1071 | CORR_MULTI_STAGE_ATTACK |
| Exfiltration | — | — |
| Impact | — | — |

## Rule-level mappings

| Rule | Technique | Name | Tactics |
|---|---|---|---|
| SSH_BRUTE_FORCE | T1110.001 | Brute Force: Password Guessing | Credential Access |
| SUCCESS_AFTER_MANY_FAILURES | T1078 | Valid Accounts | Initial Access; Defense Evasion; Persistence; Privilege Escalation |
| OFF_HOURS_LOGIN | T1078.003 | Valid Accounts: Local Accounts | Initial Access; Defense Evasion; Persistence; Privilege Escalation |
| IMPOSSIBLE_TRAVEL | T1078,T1133 | Valid Accounts, External Remote Services | Initial Access; Defense Evasion; Persistence; Privilege Escalation |
| CORR_COMPROMISE_SUSPECTED | T1110.001,T1078 | Brute Force: Password Guessing -> Valid Accounts | Initial Access; Defense Evasion; Persistence; Privilege Escalation; Credential Access |
| CORR_MULTI_STAGE_ATTACK | T1190,T1071 | Exploit Public-Facing Application -> Application Layer Protocol | Initial Access; Command and Control |
| CORR_ACCOUNT_TAKEOVER | T1078,T1133 | Valid Accounts, External Remote Services | Initial Access; Defense Evasion; Persistence; Privilege Escalation |
| IOC_MATCH | T1588.006 | Vulnerability Research | Resource Development |
| SURICATA_ALERT | T1190 | Exploit Public-Facing Application | Initial Access |
| ML_ANOMALOUS_BEHAVIOR | (none) | (unmapped) | — |

ML_ANOMALOUS_BEHAVIOR has no deterministic ATT&CK mapping because it detects
statistical outliers, not a specific adversary technique. See
[`docs/DETECTIONS.md`](DETECTIONS.md).

Sigma is covered by `docs/SIGMA.md` and is intentionally excluded from this
static rule table because its technique metadata is supplied by each Sigma
document rather than by the `ATTACK` dictionary.

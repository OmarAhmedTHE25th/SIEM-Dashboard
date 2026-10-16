# Detection Coverage

| Detection | ATT&CK | Fixture | Passing |
|---|---|---|---|
| SSH_BRUTE_FORCE | T1110.001 | `tests/detections/ssh_brute_force` | [x] |
| SUCCESS_AFTER_MANY_FAILURES | T1078 | `tests/detections/success_after_many_failures` | [x] |
| OFF_HOURS_LOGIN | T1078.003 | `tests/detections/off_hours_login` | [x] |
| IMPOSSIBLE_TRAVEL | T1078,T1133 | `tests/detections/impossible_travel` | [x] |
| CORR_COMPROMISE_SUSPECTED | T1110.001,T1078 | `tests/detections/corr_compromise_suspected` | [x] |
| CORR_MULTI_STAGE_ATTACK | T1190,T1071 | `tests/detections/corr_multi_stage_attack` | [x] |
| CORR_ACCOUNT_TAKEOVER | T1078,T1133 | `tests/detections/corr_account_takeover` | [x] |
| IOC_MATCH | T1588.006 | `tests/detections/ioc_match` | [x] |
| Sigma | `tests/test_sigma.py` | [x] |
| MITRE ATT&CK metadata | `tests/test_attack.py` | [x] |
| ML_ANOMALOUS_BEHAVIOR | no deterministic fixture | [ ] |

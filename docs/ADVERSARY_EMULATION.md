# Adversary Emulation Runbook

This runbook describes **safe, local, synthetic** exercises for validating the
detectors in this project. The commands write only to the configured SIEM log
and should be run in an isolated lab with test data. They are not instructions
for attacking systems or accounts.

## Scenarios and expected alerts

| Scenario | Method | Command | Expected alert(s) | ATT&CK |
|---|---|---|---|---|
| SSH password guessing | Replay the deterministic fixture | `python -m unittest tests.test_detections -v` | `SSH_BRUTE_FORCE` | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| Successful login after guessing | Replay five failures for one IP/user followed by a success | `python -m unittest tests.test_detections -v` | `SSH_BRUTE_FORCE`, `SUCCESS_AFTER_MANY_FAILURES`, `CORR_COMPROMISE_SUSPECTED` | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078](https://attack.mitre.org/techniques/T1078/) |
| Off-hours access | Replay a successful login in the configured 22:00–06:00 window | `python -m unittest tests.test_detections -v` | `OFF_HOURS_LOGIN` | [T1078](https://attack.mitre.org/techniques/T1078/) |
| Impossible travel | Replay successful logins for one user from the deterministic London/Tokyo fixture IPs | `python -m unittest tests.test_detections -v` | `IMPOSSIBLE_TRAVEL` | [T1078](https://attack.mitre.org/techniques/T1078/) |
| Suspected compromise | Replay brute force plus a success from the same IP | `python -m unittest tests.test_detections -v` | `SSH_BRUTE_FORCE`, `CORR_COMPROMISE_SUSPECTED` | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078](https://attack.mitre.org/techniques/T1078/) |
| Multi-stage activity | Replay a Suricata alert and a host alert for one IP | `python -m unittest tests.test_detections -v` | `CORR_MULTI_STAGE_ATTACK`, `SURICATA_ALERT`, `SSH_BRUTE_FORCE` | [T1190](https://attack.mitre.org/techniques/T1190/), [T1078](https://attack.mitre.org/techniques/T1078/), [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| Account takeover indicators | Replay matching off-hours and impossible-travel alerts | `python -m unittest tests.test_detections -v` | `CORR_ACCOUNT_TAKEOVER` | [T1078](https://attack.mitre.org/techniques/T1078/) |
| Local IOC match | Replay an event containing the fixture-local indicator | `python -m unittest tests.test_detections -v` | `IOC_MATCH` | [T1588.006](https://attack.mitre.org/techniques/T1588/006/) |

The fixture suite is under
[`tests/detections`](../tests/detections). Each scenario contains an
`input.log` and `expected_alerts.json`; `ioc_match` also contains a fixture
local `iocs.txt`. The test harness uses an offline GeoIP provider and a
disabled ML scorer so results remain deterministic and do not make network
requests. Run all fixtures and print their ATT&CK mappings with:

```bash
bash scripts/validate_detections.sh
```

For an interactive demonstration against a running agent, the repository also
contains `simulate_attacks.py`. It appends synthetic lines to
`SIEM_LOG_PATH` and includes off-hours, impossible-travel, successful-after-
failures, sudo, and ML examples:

```bash
SIEM_LOG_PATH=/tmp/siem-auth.log python simulate_attacks.py
```

The interactive script is not a substitute for the deterministic fixture
suite. Use it only in a disposable lab and review the configured log path
before running it.

## Atomic Red Team references

The following Atomic Red Team technique pages provide the corresponding
technique context and test catalog. This project does not execute Atomic tests
and does not require the Atomic Red Team toolkit.

- [T1110.001 — Password Guessing](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1110.001)
- [T1078 — Valid Accounts](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1078)
- [T1588.006 — Vulnerabilities](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1588.006)

## Legal and safety disclaimer

Run these exercises only on systems, accounts, and data that you own or are
explicitly authorized to test. Do not point the simulator, replayed logs, or
Atomic Red Team tests at third-party infrastructure, production accounts, or
real credentials. You are responsible for authorization, scope, change
control, privacy, and any resulting impact. The authors provide this material
for defensive validation and education, without warranty, and accept no
responsibility for unauthorized use or damage.

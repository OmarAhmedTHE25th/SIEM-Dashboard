# Detection runbook

This document describes the hypotheses, evidence, and operating boundaries for
each detection in [`docs/COVERAGE.md`](COVERAGE.md).  The Sigma rule is kept as
a separate reference in [`docs/SIGMA.md`](SIGMA.md); it is not duplicated here.

## Native rules

### SSH_BRUTE_FORCE

#### Hypothesis
An IP that produces at least five failed SSH authentications in one minute is
likely performing password guessing against the service.

#### ATT&CK
**T1110.001 — Brute Force: Password Guessing** (Credential Access).

#### Data
Normalized `sshd` events: `timestamp`, `source_ip`, `user`, `status`, and
`source`. The detector uses failed events and groups them by `source_ip`.

#### Logic
Maintain a timestamp deque per source IP, remove entries older than the
sliding window, append each failure, and alert when the threshold is reached.
The deque is cleared after an alert to prevent duplicate alerts from one burst.

#### False positives
NAT gateways, busy automation, vulnerability scanners, password managers, or a
legitimate user repeatedly entering an expired password can look identical.

#### Tuning
The native defaults are five failures in 60 seconds. Adjust `threshold` and
`window_seconds` in `rules/native.yml`, or use `SIEM_BRUTE_FORCE_THRESHOLD`
and `SIEM_BRUTE_FORCE_WINDOW` for an emergency runtime override. Scope
allow-listing and service accounts before raising the threshold globally.

#### Fixture
[`tests/detections/ssh_brute_force`](../tests/detections/ssh_brute_force) uses
five failures from one IP and expects `SSH_BRUTE_FORCE`.

#### Gaps
The rule does not detect distributed password spraying, distinguish valid
clients from attackers, or retain attempts after the in-memory window expires.

### SUCCESS_AFTER_MANY_FAILURES

#### Hypothesis
The same IP successfully authenticating as the same user after repeated recent
failures suggests that a guessing attempt succeeded.

#### ATT&CK
**T1078.003 — Valid Accounts: Local Accounts** (Initial Access, Defense Evasion, Persistence,
Privilege Escalation).

#### Data
Normalized SSH events with `source_ip`, `user`, `status`, `timestamp`, and
`source`. Failures are keyed by `(source_ip, user)`.

#### Logic
Keep failures for each IP/user pair for 300 seconds. On a success, alert when
at least five failures remain in that window, then clear that pair's history.

#### False positives
Users who forget a password, keyboard-layout errors, SSO retries, and a shared
egress IP can all produce a successful login after many failures.

#### Tuning
Set `threshold` and `window_seconds` in `rules/native.yml`; runtime overrides
are `SIEM_SUCCESS_AFTER_FAILURES` and `SIEM_FAILURE_CORRELATION_WINDOW`.
Consider user-specific service accounts and trusted automation when tuning.

#### Fixture
[`tests/detections/success_after_many_failures`](../tests/detections/success_after_many_failures)
contains the failure burst followed by a success.

#### Gaps
Only SSH events handled by the configured source are considered; distributed
attempts, password spraying across users, and MFA outcomes are not correlated.

### OFF_HOURS_LOGIN

#### Hypothesis
A successful login outside the organization's normal operating hours may
indicate use of stolen credentials or unauthorized access.

#### ATT&CK
**T1078.003 — Valid Accounts: Local Accounts** (Initial Access, Defense Evasion, Persistence,
Privilege Escalation).

#### Data
Successful normalized SSH events and their `timestamp`, `source_ip`, `user`,
and `source`. The hour is read from the timestamp as logged.

#### Logic
Ignore failures, then compare the event hour with the configured interval.
The default interval is 22:00 through 06:00 and correctly crosses midnight.

#### False positives
On-call staff, maintenance windows, cron jobs, global teams, backups, and
servers logging in UTC while the policy is expressed in local time.

#### Tuning
Set `start` and `end` in `rules/native.yml`, or use
`SIEM_OFF_HOURS_START` and `SIEM_OFF_HOURS_END`. Align log timezone and
business calendars before changing the window.

#### Fixture
[`tests/detections/off_hours_login`](../tests/detections/off_hours_login)
contains a successful login in the configured off-hours period.

#### Gaps
There is no per-user, holiday, maintenance-calendar, timezone, or device
baseline; a timestamp alone cannot establish that access was malicious.

### IMPOSSIBLE_TRAVEL

#### Hypothesis
Two successful logins for one user from locations requiring travel faster than
800 km/h within 24 hours are inconsistent with a single human session.

#### ATT&CK
**T1078,T1133 — Valid Accounts, External Remote Services** (Initial Access, Defense Evasion, Persistence,
Privilege Escalation).

#### Data
Successful SSH events (`user`, `timestamp`, `source_ip`) plus latitude and
longitude returned by the GeoIP enricher. The last successful location is
tracked per user.

#### Logic
Compute great-circle distance between consecutive locations, divide by elapsed
time, and alert when speed exceeds the configured maximum. Missing coordinates,
non-positive elapsed time, and events outside the 24-hour window are ignored.

#### False positives
VPNs, proxies, cloud egress, mobile networks, stale GeoIP databases, shared
accounts, and clock skew can make one user appear to travel.

#### Tuning
Set `max_speed_kmh` and `window_seconds` in `rules/native.yml`; runtime
overrides are `SIEM_IMPOSSIBLE_TRAVEL_KMH` and
`SIEM_IMPOSSIBLE_TRAVEL_WINDOW`. Prefer a trusted geolocation provider and
account/device-aware exceptions over a very high global speed.

#### Fixture
[`tests/detections/impossible_travel`](../tests/detections/impossible_travel)
uses deterministic London/Tokyo enrichment data and expects the rule.

#### Gaps
GeoIP is approximate, no device or VPN context is consulted, and only the most
recent location per user is retained in memory.

## Correlation rules

### CORR_COMPROMISE_SUSPECTED

#### Hypothesis
An SSH brute-force alert and a successful-authentication signal from the same
attacker IP in a short period indicate that credentials may have been obtained.

#### ATT&CK
**T1110.001,T1078 — Brute Force: Password Guessing -> Valid Accounts**
(Credential Access, Initial Access, Defense Evasion, Persistence,
Privilege Escalation).

#### Data
Persisted or in-stream alerts with `rule_name`, `timestamp`, `attacker_ip`,
and success status (`status`, `event_status`, or a success rule name).

#### Logic
Within `SIEM_CORR_COMPROMISE_WINDOW` (600 seconds by default), pair
`SSH_BRUTE_FORCE` with a success signal in either order and emit a critical
correlation alert.

#### False positives
- **Shared NAT egress:** A VPN concentrator can carry an attacker's brute-force
  traffic and an unrelated employee's successful login on the same public IP,
  while the correlation keys only on IP rather than session or channel.
- **Legitimate recovery after user error:** An employee can mistype a password
  five times and then authenticate successfully; an unrelated brute-force burst
  from that shared egress IP makes the two genuine alerts look causally linked.
- **Service-account overlap:** A scheduled job can successfully authenticate
  from an IP after a different user was targeted there, because the detector
  does not require the source alert and success alert to share a user.
- **Alert timing distortion:** The correlation uses alert timestamps, so queued,
  delayed, or replayed alerts can enter the window even when their source events
  were not close in time.

#### Tuning
Tune `SIEM_CORR_COMPROMISE_WINDOW` and ensure upstream detectors provide
accurate `attacker_ip` and success status. Suppress known scanners only with
care because they can also be compromised.

#### Fixture
[`tests/detections/corr_compromise_suspected`](../tests/detections/corr_compromise_suspected)
combines brute force and success alerts within the correlation window.

#### Gaps
The engine correlates IPs rather than identities or devices and does not
validate that the two alerts belong to the same authentication session.

### CORR_MULTI_STAGE_ATTACK

#### Hypothesis
An endpoint/network alert and a host rule alert from the same IP in a short
period are evidence of a multi-stage intrusion.

#### ATT&CK
**T1190,T1071 — Exploit Public-Facing Application -> Application Layer Protocol**
(Initial Access, Command and Control).

#### Data
Alerts with `timestamp`, `attacker_ip`, `source`, and `rule_name`; a Suricata
alert is identified by `source == "suricata"`.

#### Logic
Within 900 seconds (`SIEM_CORR_MULTI_STAGE_WINDOW`), correlate two alerts from
the same IP when exactly one is a Suricata alert.

#### False positives
- **Shared cloud egress:** A Suricata signature from a cloud region can share
  an IP with a legitimate host event from another tenant or user, creating a
  pairing with no causal relationship.
- **Authorized vulnerability scanning:** A scanner can legitimately trigger a
  network signature and then cause a host-side authentication or audit alert;
  the expected test sequence is indistinguishable from an intrusion here.
- **Clock skew between sources:** Drift between Suricata and host clocks can
  move events that were hours apart into the 900-second correlation window.
- **Alert-source misclassification:** A host sensor incorrectly labeled as
  non-Suricata, or a network event carrying the wrong source field, can satisfy
  the one-network/one-host test without representing two attack stages.

#### Tuning
Adjust the correlation window and require stronger source/rule combinations
in the upstream stream for high-volume environments. Preserve source fields.

#### Fixture
[`tests/detections/corr_multi_stage_attack`](../tests/detections/corr_multi_stage_attack)
provides one host and one Suricata alert from the same IP.

#### Gaps
No kill-chain ordering, asset criticality, payload verification, or campaign
deduplication is applied; it is a proximity signal rather than attribution.

### CORR_ACCOUNT_TAKEOVER

#### Hypothesis
Off-hours access and impossible travel for the same user and IP within an hour
are stronger evidence of account takeover than either signal alone.

#### ATT&CK
**T1078,T1133 — Valid Accounts, External Remote Services** (Initial Access, Defense Evasion, Persistence,
Privilege Escalation).

#### Data
Alerts with `rule_name`, `attacker_ip`, `target_user`, and `timestamp` from
`OFF_HOURS_LOGIN` and `IMPOSSIBLE_TRAVEL`.

#### Logic
Within `SIEM_CORR_ACCOUNT_TAKEOVER_WINDOW` (3600 seconds), require both rule
names, the same IP, and the same target user, then emit a high-severity alert.

#### False positives
- **Rotating VPN egress:** A legitimate user moving between VPN exits can
  produce an off-hours login and an impossible-travel alert for the same
  account/IP pairing because the correlation lacks device and VPN context.
- **Shift work and travel:** An on-call engineer can log in late from a hotel
  and then connect from another location; both inputs are valid, but their
  combination does not establish takeover.
- **Shared or delegated accounts:** Multiple authorized operators can use one
  account from different locations, causing impossible travel and off-hours
  signals that belong to different people.
- **Clock and GeoIP errors:** NTP skew or stale geolocation can independently
  create both input alerts from one legitimate access pattern, making the
  correlation amplify an enrichment error.

#### Tuning
Tune the one-hour window and maintain trusted VPN ranges, user schedules, and
service-account exclusions in the surrounding workflow.

#### Fixture
[`tests/detections/corr_account_takeover`](../tests/detections/corr_account_takeover)
contains matching off-hours and impossible-travel alerts.

#### Gaps
The in-memory history is IP-based and bounded; no MFA, device identity,
session continuity, or user risk history is evaluated.

## IOC rule

### IOC_MATCH

#### Hypothesis
An event containing a locally maintained malicious IP, domain, or hash is
associated with known threat infrastructure or an investigated incident.

#### ATT&CK
**T1588.006 — Vulnerability Research** (Resource Development), as the
project's static ATT&CK mapping for local threat-intelligence matches.

#### Data
The event's `source_ip`, `hostname`, `user`, `raw`, and `description` fields,
plus indicators loaded by `IOCMatcher` from the local IOC file.

#### Logic
Extract IPv4 addresses, 32–64 character hashes, and domain names from those
fields; normalize indicator type/value and emit a high-severity alert for an
exact local match. No network lookup is performed.

#### False positives
Stale or over-broad feeds, benign documentation/example values, shared hosting,
and an indicator that is valid but unrelated to this event.

#### Tuning
Review and expire `threat_intel/iocs.txt` entries, separate feed confidence
levels, and use fixture-local IOC files for tests. Keep matching exact rather
than broadening extraction without validation.

#### Fixture
[`tests/detections/ioc_match`](../tests/detections/ioc_match) supplies a
fixture-local indicator and an event containing that indicator.

#### Gaps
IPv4-only extraction, no indicator confidence or expiry handling, no URL/path
context, and no remote feed refresh are currently implemented.

## ML rule

### ML_ANOMALOUS_BEHAVIOR

#### Hypothesis
An IP whose authentication volume, failure rate, username spread, or timing
profile differs materially from learned peer behavior may be automated abuse.

#### ATT&CK
No dedicated ATT&CK mapping is currently assigned. The rule is intentionally
tracked in coverage as an unmapped ML capability.

#### Data
Events grouped by source IP produce five features: total attempts, failure
rate, unique users, mean interval, and standard-deviation interval. A trained
Isolation Forest model scores the feature vector.

#### Logic
Track the last 50 events per IP, begin scoring at three attempts, and flag a
model score below its threshold. Severity is CRITICAL at `<= -0.2`, HIGH below
zero, and MEDIUM below the default threshold `0.05`; a five-minute per-IP
cooldown suppresses repeats.

#### False positives
Shared egress, backup jobs, login storms, new deployments, sparse baselines,
and legitimate administrators changing behavior can be outliers.

#### Tuning
Retrain on representative `events` data (at least five IP profiles), review
contamination and threshold in `ml_engine.py`, and set
`SIEM_ML_ALERT_COOLDOWN` only with an alert-volume objective. Validate model
drift before changing severity cutoffs.

#### Fixture
No deterministic fixture is provided: `docs/COVERAGE.md` marks this rule
uncovered because it depends on a trained model and runtime state.

#### Gaps
The model is unsupervised, has no deterministic explainability or ATT&CK
mapping, is process-local, and can drift as traffic patterns change. Model
health and feature/data quality are not yet surfaced in the alert.

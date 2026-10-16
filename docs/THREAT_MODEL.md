# SIEM Dashboard Threat Model

This document describes the security assumptions, trust boundaries, and
abuse cases for the SIEM Dashboard. It uses the STRIDE model and is intended
to be read with the [detection runbook](DETECTIONS.md) and
[coverage matrix](COVERAGE.md). The model covers the log-ingestion agent,
detectors, enrichment providers, SQLite storage, API, and dashboard as
deployed by this repository.

## 1. Security objectives and assets

The primary security objectives are:

- preserve the integrity and provenance of normalized events and alerts;
- keep credentials, tokens, raw logs, and threat-intelligence data
  confidential;
- keep ingestion, detection, and API availability within operational limits;
- provide enough evidence for an analyst to investigate an alert without
  treating an alert as proof of compromise.

Assets include raw authentication and network logs, normalized events,
detector state, alert history and status, SQLite and model files, IOC files,
GeoIP/reputation requests and responses, the optional API token, and the
dashboard's browser storage. Alert integrity and timestamps are especially
important because analysts may use them to decide whether to contain an
account or host.

## 2. System, data flows, and trust boundaries

The agent tails configured log files, parses supported records, writes events
to SQLite, and passes them to native, Sigma, correlation, IOC, and ML
detections. The covered rules are `SSH_BRUTE_FORCE`,
`SUCCESS_AFTER_MANY_FAILURES`, `OFF_HOURS_LOGIN`, `IMPOSSIBLE_TRAVEL`,
`CORR_COMPROMISE_SUSPECTED`, `CORR_MULTI_STAGE_ATTACK`,
`CORR_ACCOUNT_TAKEOVER`, `IOC_MATCH`, `ML_ANOMALOUS_BEHAVIOR`, the
`Sigma` failed-SSH rule, and MITRE ATT&CK metadata. The deterministic fixture
status for each is recorded in [COVERAGE.md](COVERAGE.md); in particular,
`ML_ANOMALOUS_BEHAVIOR` has no deterministic fixture.

The main flows are:

1. **Log source → parser:** an attacker or operator can influence log
   contents, timestamps, source addresses, usernames, and event ordering.
2. **Parser → SQLite and detectors:** normalized fields feed the
   `SSH_BRUTE_FORCE`, `SUCCESS_AFTER_MANY_FAILURES`, `OFF_HOURS_LOGIN`, and
   `IMPOSSIBLE_TRAVEL` rules, the three `CORR_*` rules, `IOC_MATCH`, Sigma,
   and `ML_ANOMALOUS_BEHAVIOR`.
3. **Enrichment boundary:** public IPs may be sent to the configured GeoIP
   provider and, when configured, AbuseIPDB. Returned coordinates and
   reputation are untrusted inputs to alert context and impossible-travel
   analysis.
4. **Alert/state → API:** the API reads SQLite and exposes events, alerts,
   incidents, metrics, and workflow actions. The optional shared token is the
   authentication boundary; `/metrics` is intentionally unauthenticated.
5. **API → browser:** the dashboard receives JSON and stores a supplied token
   in browser `localStorage`. A reverse proxy/TLS boundary is expected for
   non-local deployments.

The principal trust boundaries are the host log files, the agent process,
third-party enrichment services, the SQLite/data directory, the API client,
and the browser. A local process with write access to the data directory or
log source is inside the deployment's host trust boundary and can alter
evidence; this design does not provide tamper-proof logging.

## 3. STRIDE analysis

### Spoofing

- A caller without the configured token can impersonate an API client if the
  application is deployed without token protection; a leaked token also
  permits impersonation.
- Forged log lines can spoof source IPs, usernames, timestamps, and sources,
  causing `SSH_BRUTE_FORCE`, `SUCCESS_AFTER_MANY_FAILURES`, `OFF_HOURS_LOGIN`,
  `IMPOSSIBLE_TRAVEL`, or any `CORR_*` alert to be attributed incorrectly.
- A malicious or stale enrichment response can spoof location or reputation.

Use TLS and a reverse proxy, prefer the authorization header over
`?token=`, restrict log-file ownership, and treat provider data as advisory.
The shared token is not identity, role, or session management.

### Tampering

- Writable logs, SQLite files, model files, IOC files, or environment
  variables can change events, thresholds, detector state, or alert status.
- An attacker can reorder, replay, truncate, or delete records to evade
  `SUCCESS_AFTER_MANY_FAILURES`, correlation rules, `IOC_MATCH`, Sigma, or
  `ML_ANOMALOUS_BEHAVIOR`, or to manufacture an incident.
- A browser or API caller authorized to acknowledge/suppress alerts can alter
  analyst workflow state.

Use least-privilege file permissions, read-only mounts where possible,
backups/integrity monitoring, and an external append-only audit trail for
production evidence.

### Repudiation

The system records event and alert data but does not establish an independent
cryptographic chain of custody. Process-local metrics and in-memory
correlation/ML state reset on restart, and timestamps may be timezone-naive.
An operator can therefore dispute event origin, detector state, or alert
timing. Preserve source logs, synchronized clocks, API access logs, and
immutable exports when investigations require attribution.

### Information disclosure

- Raw logs and alerts may contain usernames, addresses, and authentication
  details; anyone with SQLite, API, dashboard, or browser-storage access may
  read them.
- Public IPs are sent to third-party enrichment providers by default.
- Query-string tokens can enter proxy/server logs and browser history, while
  `localStorage` exposes the token to same-origin JavaScript.
- Error messages, exported data, and the unauthenticated metrics endpoint can
  reveal operational details.

Minimize retention and fields, protect the data directory, use HTTPS and
headers, restrict CORS/proxy access, and select a self-hosted enrichment
provider when IP disclosure is unacceptable.

### Denial of service

- High-volume or malformed logs can consume parser, SQLite, detector, and
  dashboard resources.
- Slow enrichment can block ingestion up to its timeout; provider failure or
  network abuse can amplify this effect.
- Alert storms, repeated IPs, large exports, or API polling can exhaust
  storage or CPU. ML history and model scoring are process-local.

Use log rotation and quotas, bounded queues/windows, rate limits, provider
timeouts/caching, database monitoring, and operational alert suppression.
Alert deduplication and ML cooldown reduce noise but are not a complete
resource-isolation control.

### Elevation of privilege

- The shared API token grants the same broad access to every bearer; it does
  not separate read, acknowledge, suppress, export, or administrative roles.
- A compromised agent, data-directory writer, or host account can modify
  thresholds, rules, model, IOC data, or alert status and influence analyst
  decisions.
- Dashboard XSS or a malicious same-origin integration could read the token
  from `localStorage`.

Run the agent/API as separate least-privilege accounts, protect configuration
and model files, use a secret manager and short-lived scoped credentials, and
place the service behind authenticated TLS access controls.

## 4. Explicit cannot-detect list

The dashboard must not be treated as detecting the following without other
controls or telemetry:

- distributed password spraying or attacks spread across source IPs;
- key-based SSH authentication, non-supported services, or arbitrary SSH
  protocol activity;
- valid credentials used through MFA bypass, session theft, or a compromised
  device when no matching log signal exists;
- malicious intent behind a single off-hours login, impossible-travel result,
  IOC match, or ML outlier;
- identity/device continuity, VPN/proxy use, NAT ownership, asset criticality,
  or kill-chain ordering;
- tampering, deletion, replay, or forgery of logs, SQLite, models, IOC files,
  enrichment responses, or in-memory detector state;
- attacks during ingestion outages, after process restart, or outside bounded
  correlation/history windows;
- encrypted payload contents, endpoint malware behavior, lateral movement
  without a supported event, or data exfiltration;
- reliable anomaly explanations, model drift, or a complete production
  baseline from `ML_ANOMALOUS_BEHAVIOR`;
- third-party provider correctness, availability, or confidentiality.

## 5. Assumptions and operational mitigations

This model assumes the host, Python dependencies, and deployment pipeline are
trusted; log files are readable but protected from untrusted writers; system
clocks are reasonably synchronized; configuration and secrets are supplied
securely; SQLite and model backups are protected; and analysts validate alerts
against independent evidence. Public-IP enrichment is optional and
best-effort. The documented limitations in the README remain in force,
including narrow log coverage, timezone behavior, synchronous enrichment,
shared-token authentication, recent-alert UI views, and incomplete ML
fixtures.

Recommended controls are least-privilege service accounts, TLS/reverse-proxy
authentication, secret rotation, file and container isolation, immutable
central log shipping, database backups and integrity monitoring, provider
allowlisting, rate limiting, clock synchronization, and review of detector
false positives before response.

## 6. Residual risk and review

Residual risk is highest where a single untrusted field drives attribution,
where state is process-local, and where the API token is shared. Detection
reduces triage time; it does not prove compromise or replace endpoint,
identity, network, or audit controls. Revisit this model when a new source,
rule, API action, enrichment provider, deployment boundary, or data-retention
policy is added. Keep this document and [COVERAGE.md](COVERAGE.md) aligned
when detection coverage changes.

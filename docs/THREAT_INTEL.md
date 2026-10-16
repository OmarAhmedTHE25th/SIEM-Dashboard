# Threat Intelligence

## Overview

The SIEM supports local indicators of compromise (IOCs) for IP addresses,
domains, hashes, URLs, and email addresses. IOCs can be loaded from
`threat_intel/iocs.txt` or stored in SQLite through the API. Matching is exact
for IP addresses and case-insensitive substring matching for other indicator
types. Expired indicators never produce matches.

## IOC lifecycle

Database IOCs record `first_seen`, `last_seen`, optional `expires_at`, `source`,
`verified`, `confidence`, and the derived `weight`. Confidence is a number from
0 to 1 and defaults to 0.5. `POST /api/iocs/{id}/expire` sets `expires_at` to
the current time without deleting historical match records. The database
migration is idempotent and preserves existing IOC rows.

## Weighting

An IOC weight is `confidence * type weight`. The type weights are:

| Type | Weight |
|---|---:|
| hash | 1.0 |
| ip | 0.3 |
| domain | 0.7 |
| url | 0.6 |
| email | 0.5 |

`IOCMatcher.match(event, min_weight=0.0)` excludes indicators below the
threshold. IOC alerts are `HIGH` for weights at least 0.7, `MEDIUM` for
weights at least 0.4, and `LOW` otherwise.

## File format

Each non-comment line contains one `type:value` entry:

```text
ip:203.0.113.10
domain:malicious.example
hash:0123456789abcdef0123456789abcdef
```

File indicators use the default confidence of 0.5. Use the database API when
confidence, verification, timestamps, tags, or expiry must be retained.

## API

`POST /api/iocs` accepts `value`, `type`, `source`, `confidence`, `tags`,
`first_seen`, `expires_at`, and `verified`. If `expires_at` is omitted, the
indicator receives a 90-day expiry from creation. `GET /api/iocs` supports the
optional `active=true|false` and `min_weight` filters. `POST
/api/iocs/match/{event_id}?min_weight=0.7` records and returns matching
indicators for an event.

## Operational guidance

Use `source` and `verified` to record feed provenance and analyst review.
Prefer short expiries for rapidly changing feeds, and review low-confidence
matches before taking action. IOC matching is local and makes no network
requests; enrichment remains a separate optional operation.

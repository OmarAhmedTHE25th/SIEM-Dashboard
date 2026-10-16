# Sigma support

The loader implements a deliberately small, explicit Sigma subset. Rules are
loaded from `rules/` (and from the directory in `SIEM_SIGMA_DIR`) and are
evaluated against normalized event fields.

## Supported

- Selection equality, for example `status: failed`.
- Selection values expressed as lists (any listed value may match).
- The `contains` modifier, for example `raw|contains: "Failed password"`.
- The `startswith` modifier.
- The `endswith` modifier.
- A simple `condition` that names a selection, for example
  `condition: selection`.

The current example is
[`rules/sigma-auth.yml`](../rules/sigma-auth.yml). Keep field names aligned
with the normalized event model (`status`, `event_type`, `source_ip`, `user`,
`raw`, and related fields).

## Unsupported

The following features are intentionally rejected by the loader:

- Aggregation expressions.
- The `|count` modifier.
- `1 of` and `all of` conditions.
- Sigma correlation rules.

Unsupported syntax is an error, not a silently weakened rule. Add a native or
correlation detector when the desired behavior needs state, counting, windows,
or relationships between events.

## Rule authoring guidance

Use a stable `title`, a unique `id`, an appropriate `level`, and a narrow
selection over normalized fields. Prefer exact equality for categorical fields
and use a modifier only when the field semantics require it. Keep a rule's
condition explicit and simple, then add a fixture under
[`tests/detections`](../tests/detections) with both expected and forbidden
alerts where appropriate. Run:

```bash
python -m unittest tests.test_sigma -v
python -m unittest tests.test_detections -v
```

Do not encode thresholds or cross-event state in Sigma selections. Those
requirements belong in native/correlation rules and should document their
window, grouping key, false positives, tuning, and gaps in
[`docs/DETECTIONS.md`](DETECTIONS.md).

## Known gaps

Sigma evaluation is event-local and does not aggregate events, correlate
events, or maintain a time window. It does not implement the unsupported
constructs listed above, and the project does not claim full Sigma
specification compatibility. Rules should therefore be tested against the
project's normalized parser output rather than copied from a SIEM that exposes
a different schema or backend.

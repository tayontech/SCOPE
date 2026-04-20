# SCOPE -- SPL Query Patterns and Best Practices

## Overview

**What this enables:** SCOPE agents (`scope-hunt`, `scope-defend-splunk`) read this document before generating SPL queries. It establishes the command selection rules, behavioral patterns, and anti-patterns that govern every query the agents write. Following these patterns produces queries that run correctly at scale, avoid common performance traps, and return accurate results across any data source.

**When to consult this document:** Before writing any SPL query — at the beginning of an investigation session, when selecting between `tstats`, `stats`, or `streamstats`, and when generating composite detection rules.

**Research sources:** Splunk official documentation, the PEAK (Prepare-Execute-Act-Know) framework documented by Splunk Security, Splunk community performance threads, and Splunk Enterprise Security installation documentation. All patterns have been verified against Splunk 9.x behavior.

---

## Command Selection Rules

The three primary aggregation commands serve different purposes. Using the wrong command produces either incorrect results (tstats for payload fields) or poor performance (transaction for composite detections).

### tstats — High-Speed Metadata Queries

`tstats` operates on `.tsidx` index metadata files, not raw events. It reads only fields that were indexed at ingest time: `host`, `source`, `sourcetype`, `_time`, and any explicitly indexed custom fields.

**Use tstats for:**
- Rapid data availability checks: does this index have data in this time window?
- Volume anomaly detection: did event count drop or spike versus a historical baseline?
- Counting event classes by sourcetype for coverage analysis
- IOC lookup speed when the IOC appears in an indexed field (e.g., `host`, `source`)

**Hard limit:** tstats CANNOT access event payload fields like `eventName`, `sourceIPAddress`, `userIdentity.arn`, `actor.alternateId`, or any other search-time extracted field. Queries using tstats for payload fields return empty or incorrect results — this is a silent failure, not an error.

Data availability check:

```spl
| tstats count where index=cloudtrail earliest=-24h latest=now by sourcetype
```

Volume anomaly detection (spike/drop vs. baseline):

```spl
| tstats count AS hourly_count dc(host) AS host_count
    where index=cloudtrail
    by _time span=1h
| eventstats median(hourly_count) AS median_count
| where hourly_count < (median_count * 0.5)
```

### stats — Primary Event Analysis Command

`stats` aggregates raw events after search-time field extraction. It has access to all fields in every event. Use `stats` for all normal detection queries, frequency counting, and rare event detection.

**Use stats for:**
- All detection queries referencing CloudTrail or application log fields (eventName, userIdentity.*, requestParameters)
- Frequency counting of events by principal or resource
- Rare event detection: count by actor, where count is below a threshold
- Distinct value counting with `dc()`
- Behavioral deviation analysis with `eventstats`

IAM escalation detection:

```spl
index=cloudtrail earliest=-24h latest=now
    eventName IN ("CreateAccessKey","AttachUserPolicy","CreatePolicyVersion")
| rename userIdentity.arn AS actor_arn
| stats count values(eventName) AS events_seen dc(eventName) AS distinct_events
    by actor_arn sourceIPAddress
| sort - count
```

### streamstats — Temporal Sliding Window Correlation

`streamstats` calculates running statistics as events stream sequentially. The `time_window` parameter creates a true sliding window — each event sees the aggregated state of all events within the preceding window. Use `streamstats` for all composite (multi-step) detections.

**Use streamstats for:**
- Multi-step TTP detection within a time window
- Detecting bursts: more than N distinct actions within 1 hour from the same actor
- Correlation of events that share an actor identity but not a session ID

See the Composite Detection section for the full pattern.

---

## Behavioral Baseline Patterns

Behavioral baselines establish what "normal" looks like for a principal or resource over a historical window. Deviations from baseline indicate anomalous activity. This approach is formalized in the PEAK (Prepare-Execute-Act-Know) framework documented by Splunk Security.

**Recommended baseline window:** 30-90 days of historical data. 30 days is the practical minimum. Shorter windows may not capture low-frequency legitimate activity (monthly batch jobs, quarterly access patterns).

**Two-query approach:** Run the baseline query first, store results (lookup or join), then query the hunt window and compare.

Baseline query (30-day history):

```spl
index=cloudtrail earliest=-30d latest=-1d
    eventName=AssumeRole
| stats count AS baseline_count by userIdentity.arn requestParameters.roleArn
| eval normal_threshold = baseline_count * 1.5
```

Hunt window query with deviation detection:

```spl
index=cloudtrail earliest=-24h latest=now
    eventName=AssumeRole
| stats count AS current_count by userIdentity.arn requestParameters.roleArn
| join type=left userIdentity.arn [ | inputlookup baseline_assumerole.csv ]
| where current_count > normal_threshold OR isnull(normal_threshold)
```

---

## Frequency Analysis and Stack Counting

Frequency analysis finds rare events (potential outliers) and high-frequency events (potential automation or attack tooling). Stack counting sorts events by frequency to surface both extremes.

Rare event detection — AssumeRole with unusual role targets:

```spl
index=cloudtrail earliest=-7d latest=now
    eventName=AssumeRole
| stats count by userIdentity.arn requestParameters.roleArn
| sort count
| head 20
```

Behavioral baseline deviation using `eventstats` for percentage of activity:

```spl
index=cloudtrail earliest=-7d latest=now
| stats count by userIdentity.arn eventName
| eventstats sum(count) AS total_by_actor by userIdentity.arn
| eval pct = round(count/total_by_actor * 100, 1)
| where pct > 80
| sort - pct
```

The `eventstats` pattern preserves individual rows while computing group-level aggregates, enabling per-event deviation scoring without losing the event-level detail needed for investigation.

---

## Composite Detection (Sliding Window)

Composite detections identify multi-step attack sequences within a time window. The canonical pattern uses `streamstats` with `time_window` — this is the mandated replacement for `transaction`.

**Why streamstats over transaction:**
- `transaction` runs entirely on the search head with no map-reduce: no distributed processing, RAM explodes with event count, no event is discarded until the transaction closes
- `streamstats` runs as a streaming command: events are processed sequentially, only the aggregation state is held in memory, distributed processing remains intact up to the `streamstats` stage

Multi-step IAM escalation composite detection:

```spl
index=cloudtrail earliest=-1h latest=now
    (eventName="ListRoles" OR eventName="ListUsers" OR eventName="CreateAccessKey" OR eventName="AttachUserPolicy")
| rename userIdentity.arn AS src_user_arn
| streamstats time_window=1h count values(eventName) AS events_seen dc(eventName) AS distinct_ops
    by src_user_arn
| where distinct_ops >= 3
| eval detection="[COMPOSITE] Multi-step IAM escalation"
| table _time src_user_arn events_seen distinct_ops sourceIPAddress
```

The `time_window=1h` parameter means each event's `count` reflects all matching events within the preceding 1 hour from the same `src_user_arn`. When `distinct_ops >= 3`, the actor has performed 3 or more distinct IAM operations within a 1-hour sliding window.

Composite detections must have higher severity than their atomic component detections. A single `CreateAccessKey` event is informational; a `CreateAccessKey` following `ListRoles` and `AttachUserPolicy` within an hour is high severity.

---

## Lazy Field Sampling Protocol

Before querying a new index for the first time in a session, the agent samples field names with a bounded `head 1` query. This returns one real event with all extracted fields, enabling accurate field references without requiring a pre-loaded schema.

**Why lazy sampling over pre-loaded schemas:**
1. Most investigations use only 1-2 indexes — avoiding round-trips to unused indexes
2. The operator's Splunk instance controls field extraction — a template cannot be fully accurate for custom add-ons
3. `head 1` is the lightest possible query: finds the first matching event and stops

Sampling query with required time bounds (see Pitfall 4 below):

```spl
index=<target_index> earliest=-30d latest=now | head 1
```

If no event in the last 30 days, retry with `-365d`:

```spl
index=<target_index> earliest=-365d latest=now | head 1
```

If still no event, the index may be inactive — report to the operator. Do not proceed with assumptions about field names on an inactive index.

Cache the sampled field names in session memory. Do not re-run the sampling query within the same session for an index that has already been sampled.

---

## Multi-Index Query Structure

Different indexes have different field schemas. Combining them in a single query produces field name collisions and ambiguous results.

**Rule:** Write separate SPL queries per index. The agent correlates results in the investigation narrative (`investigation_findings` accumulator), not in SPL.

**Do not write:** `(index=cloudtrail OR index=okta) | stats ...` — user identity fields are named differently in each index (e.g., `userIdentity.arn` in CloudTrail vs `actor.alternateId` in Okta).

**Do write:** Two separate queries, correlate by IP address or timestamp in the narrative.

Query 1: CloudTrail — identify the AWS actor:

```spl
/* Query 1: CloudTrail — identify the AWS actor */
index=cloudtrail earliest=-1h latest=now
    eventName=CreateAccessKey
| rename userIdentity.arn AS aws_actor
| table _time aws_actor sourceIPAddress userAgent
```

Query 2: Okta — same source IP around the same time:

```spl
/* Query 2: Okta — same source IP around the same time */
index=okta earliest=-1h latest=now
    client.ipAddress="<ip_from_query1>"
| table _time actor.alternateId displayMessage outcome.result client.ipAddress
```

Store results from each query and build the correlation narrative: "The same IP address `203.0.113.47` appears in both the CloudTrail `CreateAccessKey` event at 14:23 UTC and the Okta authentication failure at 14:19 UTC — a 4-minute gap consistent with credential harvesting before key creation."

---

## Anti-Patterns

Avoid these patterns in all generated SPL. The `scope-spl-lint.sh` hook enforces the BLOCK-level items automatically.

| Anti-Pattern | Why Bad | What to Use Instead |
|---|---|---|
| `\| transaction` in composite detections | Runs entirely on search head, no map-reduce, RAM explosion at scale | `\| streamstats time_window=... by actor_field` |
| Leading wildcards: `eventName=*CreateUser*` | Forces full raw-text scan of every event | Exact match: `eventName=CreateUser` or `OR` list |
| No time bounds: `index=cloudtrail eventName=...` | Unbounded scan — may scan months of data and timeout | Always specify `earliest=` and `latest=` |
| `index=*` or omitting `index=` | Scans all indexes including internal ones | Always specify `index=<name>` from `config/index.json` |
| `\| join` for cross-index correlation | Resource-intensive, 50k row cap, search head only | Separate queries; agent correlates results |
| `\| append` for cross-index merging | 50k row cap, runs secondary search sequentially | Separate queries; agent correlates results |
| tstats for event payload fields | tstats can only read indexed metadata — returns wrong or empty results | Use `stats` or `search` for eventName, userIdentity, etc. |
| `eventSource="iam"` (shorthand) | Incorrect — CloudTrail uses full service endpoint | `eventSource="iam.amazonaws.com"` |
| Verbose mode in automated searches | Returns all raw event data, floods network from indexers | Default or fast mode only |
| High-cardinality `by` clause in tstats | Groups by fields with millions of distinct values causes memory pressure | Add additional filter terms to reduce cardinality first |

---

## Index Discovery

When `config/index.json` does not exist, the agent enumerates available Splunk indexes using the `get_indexes` MCP tool, reasons about security relevance, and presents discovered groupings to the operator for confirmation before writing the file.

**Internal indexes to exclude during discovery.** These are Splunk Enterprise Security platform indexes — not operator data sources. Never group them as security-relevant data:

- `notable` — ES finding events
- `notable_summary` — ES stats summaries
- `risk` — ES risk modifier events
- `threat_activity` — ES threat list matches
- `ioc` — ES threat intelligence
- `ers` — entity risk scoring
- `ueba` — user behavior analytics
- `ueba_summaries` — UEBA summaries
- `endpoint_summary` — endpoint protection summary
- `audit_summary` — audit data protection
- `_internal` — Splunk platform internal
- `_audit` — Splunk audit trail
- `_introspection` — Splunk health metrics
- `summary` — summary index (Splunk default)
- `history` — Splunk search history

**`main` index handling:** The `main` index is not automatically excluded — operators may route security data there. Flag it to the operator: "The 'main' index appears to contain data. Would you like to include it in a group?" Do not silently include or exclude it.

**ES internal indexes in SPL are always valid.** The `scope-spl-lint.sh` index allowlist check must skip ES internal indexes (notably `index=notable` used by `scope-hunt-investigate.md`). These are correct uses, not allowlist violations.

---

## MCP Tool Reference

The Splunkbase app 7931 (MCP Server for Splunk Platform, version 1.0.2+) exposes these tools relevant to SCOPE query generation:

### get_indexes

Enumerates all available Splunk indexes. Use at startup when `config/index.json` does not exist to drive the index discovery flow. Filter internal indexes (see Index Discovery section) before presenting to the operator.

When the tool is unavailable (older app version): fall back to `search_oneshot` with:

```spl
| rest /services/data/indexes | fields title
```

### validate_spl

Validates SPL syntax before execution. Use before running complex or expensive queries to catch syntax errors without consuming Splunk resources. Does not check semantic correctness — a syntactically valid query may still return incorrect results for the wrong index.

### saia_optimize_spl

Splunk's own SPL optimizer. Optional — useful for complex queries, not required for routine detection queries. The optimizer knows the target instance's configuration and can improve query performance based on actual index structure. Use for multi-stage pipelines or queries with high expected result counts.

**Primary query execution:** Use `search_oneshot` or `search_splunk` for all actual query execution. The existing 4-tool probe sequence in `scope-hunt.md` already determines which tool to use based on connectivity.

---

## Time Bounds Standard

All SPL queries generated by SCOPE agents must include both `earliest` and `latest` time bounds. Unbounded queries scan the full index and may time out or consume excessive search head resources.

ISO 8601 absolute bounds:

```spl
index=<name> earliest="2026-04-19T00:00:00" latest="2026-04-20T00:00:00"
```

Relative bounds (preferred for hunt queries):

```spl
index=<name> earliest=-24h latest=now
```

Lazy field sampling with bounded fallback:

```spl
index=<target_index> earliest=-30d latest=now | head 1
```

**Exception:** The `index=notable` query in `scope-hunt-investigate.md` operates without explicit time bounds by design — the notable index is always queried for recent unresolved findings, and Splunk ES manages its own retention. This is the only acceptable exception.

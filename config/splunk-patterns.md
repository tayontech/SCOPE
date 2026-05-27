# SCOPE -- SPL Query Patterns and Best Practices

## Overview

**What this enables:** SCOPE agents (`scope-investigate`, `scope-controls-detections`) read this document before generating SPL queries. It establishes the command selection rules, behavioral patterns, and anti-patterns that govern every query the agents write. Following these patterns produces queries that run correctly at scale, avoid common performance traps, and return accurate results across any data source.

**When to consult this document:** Before writing any SPL query — at the beginning of an investigation session, when selecting between `stats`, `eventstats`, `streamstats`, `bin`, or `timechart`, and when generating composite detection rules.

**Research sources:** Splunk Cloud Platform Search Reference, Splunk MCP Server for Splunk Platform docs, and Splunk security detection engineering guidance. These patterns target Splunk Cloud as the SIEM for SCOPE investigations and controls detections.

---

## Command Selection Rules

The primary detection commands serve different purposes. Use `stats` for aggregation, `eventstats` for inline baselines, `streamstats` for sliding windows, `bin` + `stats` for fixed windows, and `timechart` for trend or dashboard searches. Avoid commands that depend on accelerated data models or indexed-only fields unless the operator explicitly confirms that environment.

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

## Detection Building Blocks

Use these Splunk Cloud SPL commands and functions when they improve fidelity, normalization, or operator usefulness. Do not add a command because it is available; each stage must support a detection objective.

| Command or function | Detection use | Caveat |
|---|---|---|
| `search` with exact filters and `IN (...)` | Start every production detection with tight index, sourcetype, time, and action filters. | Use explicit field filters. Avoid raw string search unless the target field is unknown. |
| `where` | Filter on computed predicates, thresholds, field-to-field comparisons, `cidrmatch`, `match`, and multivalue checks. | Quote literal strings. Field names with dots can require single quotes in expressions. |
| `eval` with `case`, `if`, `coalesce`, `lower`, `replace` | Normalize actor, IP, account, resource, and result fields before aggregation. | Do not overwrite raw fields. Write normalized fields such as `normalized_actor`. |
| `cidrmatch()` | Classify source IPs against private, VPN, scanner, corporate, cloud, or approved network ranges. | Keep inline CIDR sets small and operator-confirmed. |
| `match()` | Detect regex-shaped values such as generated role names, encoded command strings, temp paths, suspicious user agents, or malformed resource IDs. | Anchor regexes when full-string matching matters. |
| `rex field=<field>` | Extract missing fields from semi-structured payloads after initial filtering. | Filter first and target a specific field. Avoid broad `_raw` extraction. |
| `spath input=<field>` | Extract nested JSON values from request parameters, payload fields, or vendor logs. | Use only when extraction is not already available through Splunk field extraction. |
| `json_extract` / `json_extract_exact` | Pull JSON values inside an already-extracted string field from an `eval` expression. | Prefer `spath` when command-stage extraction is clearer. |
| `fields + ...` | Keep only detection inputs before expensive stages. | Use `table` for final display, not mid-pipeline projection. |
| Final `table` | Show alert evidence fields such as `_time`, actor, src, action, resource, reason, first_seen, and last_seen. | Keep it at the end so later commands do not lose fields. |
| `fillnull value=<value> <field-list>` | Stabilize optional fields such as `errorCode`, `mfaUsed`, `userAgent`, or `src_ip`. | Always specify a field list. |
| `dedup <entity> sortby -_time` | Keep latest event per entity for investigation views or evidence samples. | Do not use `dedup` as the detection threshold. |
| `mvcount`, `mvfind`, `mvfilter`, `mvdedup` | Score aggregated action lists, check required sequence steps, and filter suspicious values inside arrays. | Handle null multivalue fields explicitly. |
| `mvexpand <field> limit=<n>` | Expand arrays when each value needs independent matching. | Set `limit` where possible to avoid memory pressure. |
| `bin _time span=<window>` + `stats` | Build fixed-window detections that preserve actor/resource rows. | Prefer this over `timechart` for alert rows. |
| `timechart span=<window>` | Build coverage checks, volume baselines, and dashboard/trend searches. | Do not use as the core alert query when row-level evidence is required. |
| `sort <limit> -<field>` | Rank final aggregate rows by count, latest event, or distinct action count. | Use `sort 0` only when the result set is already bounded. |

Blocked by default:

- Expensive correlation or fan-out commands: `join`, `append`, `appendcols`, `selfjoin`, `map`, and `transaction`.
- Side-effect commands: `collect`, `mcollect`, `tscollect`, `outputcsv`, `outputlookup`, `delete`, `sendemail`, `sendalert`, `script`, and `run`.
Use environment-dependent commands such as `rest`, `lookup`, `inputlookup`, and `tstats` only when the operator confirms the required Splunk Cloud permissions, lookup assets, or acceleration/indexed-field assumptions. Do not make generated detections depend on them by default.

---

## Behavioral Baseline Patterns

Behavioral baselines establish what "normal" looks like for a principal or resource over a historical window. Deviations from baseline indicate anomalous activity. This approach is formalized in the PEAK (Prepare-Execute-Act-Know) framework documented by Splunk Security.

**Recommended baseline window:** 30-90 days of historical data. 30 days is the practical minimum. Shorter windows may not capture low-frequency legitimate activity (monthly batch jobs, quarterly access patterns).

**Preferred approach:** Use `eventstats` for inline baselines when the current result set contains enough history. Do not generate detections that depend on lookup tables unless the operator explicitly provides the lookup name and fields.

Baseline query (30-day history):

```spl
index=cloudtrail earliest=-30d latest=-1d
    eventName=AssumeRole
| stats count AS baseline_count by userIdentity.arn requestParameters.roleArn
| eval normal_threshold = baseline_count * 1.5
```

Inline deviation detection with `eventstats`:

```spl
index=cloudtrail earliest=-30d latest=now
    eventName=AssumeRole
| bin _time span=1d
| stats count AS daily_count by _time userIdentity.arn requestParameters.roleArn
| eventstats median(daily_count) AS median_count perc95(daily_count) AS p95_count by userIdentity.arn requestParameters.roleArn
| where daily_count > p95_count AND daily_count > (median_count * 2)
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

Avoid these patterns in all generated SPL. The `scope-spl-lint.sh` hook enforces mechanical safety rules such as named indexes, time bounds, blocked side-effect commands, blocked environment-dependent commands, and blocked fan-out commands. Sequence-correlation choices such as `streamstats` versus `transaction` remain design guidance because regex lint cannot classify composite detection intent reliably.

| Anti-Pattern | Why Bad | What to Use Instead |
|---|---|---|
| `\| transaction` in composite detections | Runs entirely on search head, no map-reduce, RAM explosion at scale | `\| streamstats time_window=... by actor_field` |
| Leading wildcards: `eventName=*CreateUser*` | Forces full raw-text scan of every event | Exact match: `eventName=CreateUser` or `OR` list |
| No time bounds: `index=cloudtrail eventName=...` | Unbounded scan — may scan months of data and timeout | Always specify `earliest=` and `latest=` |
| `index=*` or omitting `index=` | Scans all indexes and can cross unrelated data sources | Always specify `index=<name>` from the MCP-discovered or operator-provided `index_catalog` |
| `\| join` for cross-index correlation | Resource-intensive, 50k row cap, search head only | Separate queries; agent correlates results |
| `\| append` for cross-index merging | 50k row cap, runs secondary search sequentially | Separate queries; agent correlates results |
| `eventSource="iam"` (shorthand) | Incorrect — CloudTrail uses full service endpoint | `eventSource="iam.amazonaws.com"` |
| Verbose mode in automated searches | Returns all raw event data, floods network from indexers | Default or fast mode only |

---

## Index Discovery

When Splunk MCP is connected, the agent enumerates available Splunk indexes with `splunk_get_indexes`, reasons about security relevance, and keeps the approved grouping in session memory as `index_catalog`. Do not discover indexes with SPL `rest` commands. If `splunk_get_indexes` is unavailable, ask the operator to provide a temporary index list for the session.

`index_catalog` is the only SCOPE index-selection contract. It can come from Splunk MCP discovery or direct operator input. There is no static index configuration file.

Exclude Splunk platform indexes that start with `_` from normal security-data grouping unless the operator explicitly selects one. Do not assume any prebuilt alert index or field schema exists in Splunk Cloud.

Treat the `main` index as operator-owned. If it appears during discovery, ask whether it contains security data. Do not silently include or exclude it.

---

## MCP Tool Reference

Splunk MCP Server for Splunk Platform 1.1 exposes these tools relevant to SCOPE query generation:

### splunk_get_indexes

Lists Splunk indexes. Use this for connected-mode runtime discovery before generating SPL.

### saia_optimize_spl

Splunk's own SPL optimizer. Optional — useful for complex queries, not required for routine detection queries. The optimizer knows the target instance's configuration and can improve query performance based on actual index structure. Use for multi-stage pipelines or queries with high expected result counts.

### splunk_run_query

Primary SPL execution tool for Splunk MCP 1.1. SCOPE also probes older local tool names for backwards compatibility, then stores one `working_tool` for the session.

### splunk_run_saved_search

Runs saved searches when the beta saved-search tool is enabled by the Splunk MCP admin.

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

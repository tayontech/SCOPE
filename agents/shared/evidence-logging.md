## Evidence Logging Protocol

Maintain `$RUN_DIR/agent-log.jsonl` — one JSON line per evidence event.

**Log:** every AWS API call, every policy evaluation, every claim, every coverage checkpoint.

**Evidence IDs:** Sequential ev-001, ev-002, etc. Claims: claim-{type}-{seq} (e.g., claim-scp-001, claim-ioc-001).

**Record types:**
- `api_call` — service, action, parameters, response_status, response_summary, duration_ms
- `policy_eval` — principal_arn, action_tested, 7-step evaluation_chain, source_evidence_ids
- `claim` — statement, classification (guaranteed/conditional/speculative), confidence_pct, confidence_reasoning, gating_conditions, source_evidence_ids
- `coverage_check` — scope_area, checked[], not_checked[], not_checked_reason, coverage_pct

**On write failure:** log warning and continue. Evidence logging must never block the primary agent workflow.

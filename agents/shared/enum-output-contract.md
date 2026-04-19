## Output Contract

Before this section runs, each enum agent sets:
- `$MODULE` — service name (e.g., "iam", "s3", "kms")
- `$OUTPUT_FILE` — full output path (e.g., `$RUN_DIR/iam.json`)
- `$AGENT_NAME` — agent identifier (e.g., "scope-enum-iam")
- `$REGION` — region value (e.g., "global", "multi-region", or `$AWS_REGION`)
- `$FINDINGS_JSON` — assembled findings array (JSON string)
- `$STATUS` — "complete", "partial", or "error"

**Write this file:** `$OUTPUT_FILE`
Write via Bash redirect (you do NOT have Write tool access):
```bash
jq -n \
  --arg module "$MODULE" \
  --arg account_id "$ACCOUNT_ID" \
  --arg region "$REGION" \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$STATUS" \
  --argjson findings "$FINDINGS_JSON" \
  '{
    module: $module,
    account_id: $account_id,
    region: $region,
    timestamp: $ts,
    status: $status,
    findings: $findings
  }' > "$OUTPUT_FILE"
```

**Append to agent log:**
```bash
jq -n \
  --arg agent "$AGENT_NAME" \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$STATUS" \
  --arg file "$OUTPUT_FILE" \
  '{agent: $agent, timestamp: $ts, status: $status, file: $file}' \
  >> "$RUN_DIR/agent-log.jsonl"
```

## Post-Write Validation

```bash
node bin/validate-enum-output.js "$OUTPUT_FILE"
VALIDATION_EXIT=$?
if [ "$VALIDATION_EXIT" -ne 0 ]; then
  ERRORS+=("[VALIDATION] $MODULE.json failed schema validation (exit $VALIDATION_EXIT)")
  STATUS="error"
fi
```

Do NOT report STATUS: complete if any validation step fails.

#!/bin/bash
# SCOPE Schema Validation — PostToolUse / AfterTool hook
# Runs after Write|Edit on results.json files and dashboard public JSON files.
# Validates required fields using jq against the canonical schemas in .scope/schemas/.
# Returns decision: "block" with reason if required fields are missing.
#
# Canonical JSON Schema files are in .scope/schemas/{audit,defend,exploit}.schema.json
# and can be used with any JSON Schema validator (ajv, python jsonschema, etc.) for CI.
# This hook does lightweight jq-based validation for real-time enforcement.

set -euo pipefail

INPUT=$(cat /dev/stdin)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

if [ -z "$FILE_PATH" ]; then
  exit 0
fi

# Only validate results.json files, dashboard public JSON files, and module envelope files
case "$FILE_PATH" in
  */results.json|*/dashboard/public/*.json)
    ;; # fall through to existing results validation
  */iam.json|*/sts.json|*/s3.json|*/kms.json|*/secrets.json|*/lambda.json|*/ec2.json|\
*/rds.json|*/sns.json|*/sqs.json|*/apigateway.json|*/codebuild.json)
    # Module envelope validation — validate required fields per module-envelope.schema.json
    # NOTE: Enum subagents write via Bash redirect (not Write tool), so this hook
    # does NOT fire on their output during normal operation. This case block catches
    # if any agent writes a module file via Write tool directly.
    ERRORS=()
    check_field() {
      local field="$1"
      local label="$2"
      if [ "$(jq "has(\"$field\")" "$FILE_PATH")" != "true" ]; then
        ERRORS+=("Missing required field: '$field' ($label)")
      fi
    }
    check_field_type() {
      local field="$1"
      local expected_type="$2"
      local label="$3"
      local actual_type
      actual_type=$(jq -r ".$field | type" "$FILE_PATH" 2>/dev/null || echo "null")
      if [ "$actual_type" != "$expected_type" ]; then
        ERRORS+=("Field '$field' should be $expected_type but is $actual_type ($label)")
      fi
    }
    check_field "module" "service module name"
    check_field "account_id" "12-digit AWS account ID"
    check_field "region" "AWS region or 'global'"
    check_field "timestamp" "ISO8601 timestamp"
    check_field "status" "complete|partial|error"
    check_field "findings" "findings array"
    check_field_type "findings" "array" "findings must be an array"

    # Validate status enum
    STATUS_VAL=$(jq -r '.status // empty' "$FILE_PATH")
    if [ -n "$STATUS_VAL" ]; then
      case "$STATUS_VAL" in
        complete|partial|error) ;;
        *) ERRORS+=("Field 'status' must be one of: complete, partial, error (got: $STATUS_VAL)") ;;
      esac
    fi

    # Validate module name matches known services
    MODULE_VAL=$(jq -r '.module // empty' "$FILE_PATH")
    if [ -n "$MODULE_VAL" ]; then
      case "$MODULE_VAL" in
        iam|sts|s3|kms|secrets|lambda|ec2|rds|sns|sqs|apigateway|codebuild) ;;
        *) ERRORS+=("Field 'module' must be one of: iam, sts, s3, kms, secrets, lambda, ec2, rds, sns, sqs, apigateway, codebuild (got: $MODULE_VAL)") ;;
      esac
    fi

    # Validate account_id format
    ACCT_ID=$(jq -r '.account_id // empty' "$FILE_PATH")
    if [ -n "$ACCT_ID" ]; then
      if ! echo "$ACCT_ID" | grep -qE '^\d{12}$'; then
        ERRORS+=("account_id '$ACCT_ID' is not a valid 12-digit AWS account ID")
      fi
    fi

    if [ ${#ERRORS[@]} -gt 0 ]; then
      REASON=$(printf '  - %s\n' "${ERRORS[@]}")
      jq -n --arg reason "$REASON" --arg file "$FILE_PATH" '{
        decision: "block",
        reason: ("SCOPE Module Envelope Validation FAILED (" + $file + "):\n" + $reason + "\n\nFix the missing/invalid fields and rewrite. Schema reference: .scope/schemas/module-envelope.schema.json")
      }'
    fi
    exit 0
    ;;
  *)
    exit 0
    ;;
esac

# Skip index.json — it's a registry, not a results file
case "$FILE_PATH" in
  */index.json)
    exit 0
    ;;
esac

# Skip if file doesn't exist (deleted or not yet written)
if [ ! -f "$FILE_PATH" ]; then
  exit 0
fi

# Skip if file is not valid JSON
if ! jq empty "$FILE_PATH" 2>/dev/null; then
  jq -n --arg file "$FILE_PATH" '{
    decision: "block",
    reason: ("Schema validation: " + $file + " is not valid JSON. Fix the JSON syntax and rewrite.")
  }'
  exit 0
fi

# Detect the source phase from the file content
SOURCE=$(jq -r '.source // empty' "$FILE_PATH")

# If no source field, try to infer from filename
if [ -z "$SOURCE" ]; then
  case "$FILE_PATH" in
    *audit*) SOURCE="audit" ;;
    *defend*) SOURCE="defend" ;;
    *exploit*) SOURCE="exploit" ;;
    *) exit 0 ;;  # Can't determine phase — skip validation
  esac
fi

ERRORS=()

# --- Common fields (all phases) ---
check_field() {
  local field="$1"
  local label="$2"
  if [ "$(jq "has(\"$field\")" "$FILE_PATH")" != "true" ]; then
    ERRORS+=("Missing required field: '$field' ($label)")
  fi
}

check_field_type() {
  local field="$1"
  local expected_type="$2"
  local label="$3"
  local actual_type
  actual_type=$(jq -r ".$field | type" "$FILE_PATH" 2>/dev/null || echo "null")
  if [ "$actual_type" != "$expected_type" ]; then
    ERRORS+=("Field '$field' should be $expected_type but is $actual_type ($label)")
  fi
}

check_array_item_fields() {
  local array_field="$1"
  local required_fields="$2"  # comma-separated
  local label="$3"
  local array_len
  array_len=$(jq ".$array_field | length" "$FILE_PATH" 2>/dev/null || echo "0")
  if [ "$array_len" -gt 0 ]; then
    IFS=',' read -ra FIELDS <<< "$required_fields"
    for field in "${FIELDS[@]}"; do
      field=$(echo "$field" | xargs)  # trim whitespace
      local missing
      missing=$(jq "[.$array_field[] | select(has(\"$field\") | not)] | length" "$FILE_PATH" 2>/dev/null || echo "0")
      if [ "$missing" -gt 0 ]; then
        ERRORS+=("$missing item(s) in '$array_field' missing required field '$field' ($label)")
      fi
    done
  fi
}

# Common required fields
check_field "account_id" "12-digit AWS account ID"
check_field "source" "phase identifier: audit, defend, or exploit"
check_field "timestamp" "ISO8601 timestamp"

# Validate account_id format (12 digits) — allow "unknown" for defend fallback
ACCOUNT_ID=$(jq -r '.account_id // empty' "$FILE_PATH")
if [ -n "$ACCOUNT_ID" ] && [ "$ACCOUNT_ID" != "unknown" ]; then
  if ! echo "$ACCOUNT_ID" | grep -qE '^\d{12}$'; then
    ERRORS+=("account_id '$ACCOUNT_ID' is not a valid 12-digit AWS account ID")
  fi
fi

# --- Phase-specific validation ---
case "$SOURCE" in
  audit)
    check_field "summary" "audit summary object"
    check_field "graph" "attack graph with nodes and edges"
    check_field "attack_paths" "array of attack paths"
    check_field "principals" "array of IAM principals"
    check_field "trust_relationships" "array of trust relationships"

    # summary.risk_score is required
    if [ "$(jq 'has("summary")' "$FILE_PATH")" = "true" ]; then
      if [ "$(jq '.summary | has("risk_score")' "$FILE_PATH")" != "true" ]; then
        ERRORS+=("Missing required field: 'summary.risk_score' (critical|high|medium|low)")
      fi
    fi

    # graph must have nodes and edges arrays
    if [ "$(jq 'has("graph")' "$FILE_PATH")" = "true" ]; then
      if [ "$(jq '.graph | has("nodes")' "$FILE_PATH")" != "true" ]; then
        ERRORS+=("Missing required field: 'graph.nodes' (array of graph nodes)")
      fi
      if [ "$(jq '.graph | has("edges")' "$FILE_PATH")" != "true" ]; then
        ERRORS+=("Missing required field: 'graph.edges' (array of graph edges)")
      fi
    fi

    # attack_paths items must have name, severity, category
    check_array_item_fields "attack_paths" "name,severity,category" "attack path entries"

    # principals items must have id, type, arn
    check_array_item_fields "principals" "id,type,arn" "principal entries"

    # trust_relationships items must have role_id, role_arn, principal, trust_type
    check_array_item_fields "trust_relationships" "role_id,role_arn,principal,trust_type" "trust relationship entries"

    # --- Enum value validation (SCHM-01, SCHM-02, SCHM-03) ---

    # SCHM-01: Validate attack_paths[].severity -- lowercase only
    if [ "$(jq 'has("attack_paths")' "$FILE_PATH")" = "true" ]; then
      INVALID_SEV=$(jq -r '[.attack_paths[] | select(.severity != null) | .severity | select(. != "critical" and . != "high" and . != "medium" and . != "low")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_SEV" ]; then
        ERRORS+=("attack_paths[].severity contains invalid values (must be lowercase: critical|high|medium|low): $INVALID_SEV")
      fi
    fi

    # SCHM-02: Validate graph.edges[].edge_type -- known types only
    if [ "$(jq 'has("graph") and (.graph | has("edges"))' "$FILE_PATH")" = "true" ]; then
      INVALID_ET=$(jq -r '[.graph.edges[] | select(.edge_type != null) | .edge_type | select(. != "priv_esc" and . != "trust" and . != "data_access" and . != "network" and . != "service" and . != "public_access" and . != "cross_account" and . != "membership")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_ET" ]; then
        ERRORS+=("graph.edges[].edge_type contains invalid values (must be one of: priv_esc, trust, data_access, network, service, public_access, cross_account, membership): $INVALID_ET")
      fi
    fi

    # SCHM-03: Validate attack_paths[].category -- known categories only
    if [ "$(jq 'has("attack_paths")' "$FILE_PATH")" = "true" ]; then
      INVALID_CAT=$(jq -r --argjson valid '["privilege_escalation","trust_misconfiguration","data_exposure","credential_risk","excessive_permission","network_exposure","persistence","post_exploitation","lateral_movement"]' '[.attack_paths[] | select(.category != null) | .category | select(. as $c | $valid | index($c) | not)] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_CAT" ]; then
        ERRORS+=("attack_paths[].category contains invalid values (must be one of: privilege_escalation, trust_misconfiguration, data_exposure, credential_risk, excessive_permission, network_exposure, persistence, post_exploitation, lateral_movement): $INVALID_CAT")
      fi
    fi
    ;;

  defend)
    check_field "region" "AWS region or 'global' (defend is always 'global')"
    check_field "summary" "defend summary object"
    check_field "audit_runs_analyzed" "array of consumed audit run IDs"
    check_field "scps" "array of SCPs"
    check_field "rcps" "array of RCPs"
    check_field "detections" "array of SPL detections"
    check_field "security_controls" "array of security control recommendations"
    check_field "prioritization" "prioritized remediation actions"

    # summary required subfields
    if [ "$(jq 'has("summary")' "$FILE_PATH")" = "true" ]; then
      for subfield in scps_generated rcps_generated detections_generated controls_recommended risk_score; do
        if [ "$(jq ".summary | has(\"$subfield\")" "$FILE_PATH")" != "true" ]; then
          ERRORS+=("Missing required field: 'summary.$subfield'")
        fi
      done
    fi

    # audit_runs_analyzed must be non-empty array
    if [ "$(jq 'has("audit_runs_analyzed")' "$FILE_PATH")" = "true" ]; then
      ara_len=$(jq '.audit_runs_analyzed | length' "$FILE_PATH" 2>/dev/null || echo "0")
      if [ "$ara_len" -eq 0 ]; then
        ERRORS+=("'audit_runs_analyzed' must contain at least one audit run ID")
      fi
    fi

    # scps items must have name, file, policy_json, source_attack_paths, source_run_ids, impact_analysis
    check_array_item_fields "scps" "name,file,policy_json,source_attack_paths,source_run_ids,impact_analysis" "SCP entries"

    # rcps items must have same fields
    check_array_item_fields "rcps" "name,file,policy_json,source_attack_paths,source_run_ids,impact_analysis" "RCP entries"

    # detections items must have name, spl, severity, category, mitre_technique, source_attack_paths, source_run_ids
    check_array_item_fields "detections" "name,spl,severity,category,mitre_technique,source_attack_paths,source_run_ids" "detection entries"

    # security_controls items must have service, recommendation, priority, effort, source_attack_paths
    check_array_item_fields "security_controls" "service,recommendation,priority,effort,source_attack_paths" "security control entries"

    # prioritization items must have rank, action, risk, effort, category
    check_array_item_fields "prioritization" "rank,action,risk,effort,category" "prioritization entries"

    # SCHM-01 (defend): Validate detections[].severity -- lowercase only
    if [ "$(jq 'has("detections")' "$FILE_PATH")" = "true" ]; then
      INVALID_DET_SEV=$(jq -r '[.detections[] | select(.severity != null) | .severity | select(. != "critical" and . != "high" and . != "medium" and . != "low")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_DET_SEV" ]; then
        ERRORS+=("detections[].severity contains invalid values (must be lowercase: critical|high|medium|low): $INVALID_DET_SEV")
      fi
    fi

    # --- Type and consistency validation (SCHM-04, SCHM-05) ---

    # SCHM-04: Validate scps[].policy_json and rcps[].policy_json are objects (not strings)
    for ARRAY in scps rcps; do
      if [ "$(jq "has(\"$ARRAY\")" "$FILE_PATH")" = "true" ]; then
        INVALID_POLICY=$(jq -r --arg arr "$ARRAY" '[.[$arr][] | select(has("policy_json")) | select(.policy_json | type != "object") | .name // "unnamed"] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
        if [ -n "$INVALID_POLICY" ]; then
          ERRORS+=("${ARRAY}[].policy_json must be an object (not a string) — invalid items: $INVALID_POLICY")
        fi
      fi
    done

    # SCHM-05: Validate defend summary counts match actual array lengths
    if [ "$(jq 'has("summary")' "$FILE_PATH")" = "true" ]; then
      for PAIR in "detections_generated:detections" "scps_generated:scps" "rcps_generated:rcps" "controls_recommended:security_controls"; do
        SUMMARY_FIELD="${PAIR%%:*}"
        ARRAY_FIELD="${PAIR##*:}"
        if [ "$(jq ".summary | has(\"$SUMMARY_FIELD\")" "$FILE_PATH")" = "true" ] && [ "$(jq "has(\"$ARRAY_FIELD\")" "$FILE_PATH")" = "true" ]; then
          SUMMARY_VAL=$(jq ".summary.${SUMMARY_FIELD} // 0" "$FILE_PATH" 2>/dev/null || echo "0")
          ACTUAL_LEN=$(jq ".${ARRAY_FIELD} | length" "$FILE_PATH" 2>/dev/null || echo "0")
          if [ "$SUMMARY_VAL" -ne "$ACTUAL_LEN" ] 2>/dev/null; then
            ERRORS+=("summary.${SUMMARY_FIELD} (${SUMMARY_VAL}) does not match actual ${ARRAY_FIELD} array length (${ACTUAL_LEN})")
          fi
        fi
      done
    fi
    ;;

  exploit)
    check_field "target_arn" "principal ARN analyzed"
    check_field "summary" "exploit summary object"
    check_field "attack_paths" "array of attack paths"

    # attack_paths items must have name, steps
    check_array_item_fields "attack_paths" "name,steps" "attack path entries"
    ;;

  *)
    # Unknown phase — skip validation
    exit 0
    ;;
esac

# --- Report results ---

if [ ${#ERRORS[@]} -gt 0 ]; then
  REASON=$(printf '  - %s\n' "${ERRORS[@]}")
  jq -n --arg reason "$REASON" --arg file "$FILE_PATH" --arg source "$SOURCE" '{
    decision: "block",
    reason: ("SCOPE Schema Validation FAILED for " + $source + " results (" + $file + "):\n" + $reason + "\n\nFix the missing/invalid fields and rewrite. Schema reference: .scope/schemas/" + $source + ".schema.json")
  }'
  exit 0
fi

# All checks passed
exit 0

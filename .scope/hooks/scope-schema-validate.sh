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

# Only validate results.json files and dashboard public JSON files
case "$FILE_PATH" in
  */results.json|*/dashboard/public/*.json)
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
        ERRORS+=("Missing required field: 'summary.risk_score' (CRITICAL|HIGH|MEDIUM|LOW)")
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
    ;;

  defend)
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
    ;;

  exploit)
    check_field "target_arn" "principal ARN analyzed"
    check_field "risk_score" "CRITICAL|HIGH|MEDIUM|LOW"
    check_field "escalation_paths" "array of escalation paths"

    # escalation_paths items must have rank, name, steps
    check_array_item_fields "escalation_paths" "rank,name,steps" "escalation path entries"
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

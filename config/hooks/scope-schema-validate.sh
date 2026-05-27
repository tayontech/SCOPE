#!/bin/bash
# SCOPE Schema Validation — PostToolUse / AfterTool hook
# Runs after Write|Edit on results.json files and dashboard public JSON files.
# Validates required fields using jq against the canonical schemas in config/schemas/.
# Returns decision: "block" with reason if required fields are missing.
#
# Canonical JSON Schema files are in config/schemas/{audit,controls,exploit}.schema.json
# and can be used with any JSON Schema validator (ajv, python jsonschema, etc.) for CI.
# This hook does lightweight jq-based validation for real-time enforcement.

set -euo pipefail

INPUT=$(cat /dev/stdin)
HOOK_CWD=$(echo "$INPUT" | jq -r '.cwd // .toolCall.args.Cwd // .workspacePaths[0] // empty' 2>/dev/null || true)
if [ -z "$HOOK_CWD" ]; then
  HOOK_CWD="$(pwd)"
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

audit_schema_edge_types_json() {
  local schema
  for schema in "$HOOK_CWD/config/schemas/audit.schema.json" "$SCRIPT_DIR/../../config/schemas/audit.schema.json"; do
    if [ -f "$schema" ]; then
      jq -c '.properties.graph.properties.edges.items.properties.edge_type.enum' "$schema"
      return
    fi
  done
  printf '%s\n' '["priv_esc","trust","data_access","network","service","public_access","cross_account","membership","executes_as","invokes","authenticates_to","resource_policy_allows","resource_policy_statement","event_source","encrypted_by"]'
}

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // .toolCall.args.TargetFile // empty')

if [ -z "$FILE_PATH" ]; then
  COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // .toolCall.args.CommandLine // empty' 2>/dev/null || true)
  if grep -qE 'results\.json|dashboard/public/[A-Za-z0-9_.-]+\.json|/(apigateway|bedrock|cloudfront|codebuild|cognito|dynamodb|ec2|ecs|iam|kms|lambda|rds|route53|s3|secrets|sns|sqs|ssm|sts)\.json' <<<"$COMMAND"; then
    FILE_PATH=$(
      {
        find "$HOOK_CWD/runs" "$HOOK_CWD/exploit" "$HOOK_CWD/investigations" -name "results.json" -mmin -5 -type f 2>/dev/null
        find "$HOOK_CWD/dashboard/public" -maxdepth 1 -name "*.json" ! -name "index.json" -mmin -5 -type f 2>/dev/null
        find "$HOOK_CWD/runs" -path "*/modules/*/*.json" -mmin -5 -type f 2>/dev/null
      } | sort -r | sed -n '1p'
    )
  fi

  if [ -z "$FILE_PATH" ]; then
    exit 0
  fi
fi

# Only validate results.json files, dashboard public JSON files, and module envelope files
case "$FILE_PATH" in
  */results.json|*/controls-results.json|*/dashboard/public/*.json)
    ;; # fall through to existing results validation
  */apigateway.json|*/bedrock.json|*/cloudfront.json|*/codebuild.json|*/cognito.json|*/dynamodb.json|\
*/ec2.json|*/ecs.json|*/iam.json|*/kms.json|*/lambda.json|*/rds.json|*/route53.json|*/s3.json|*/secrets.json|\
*/sns.json|*/sqs.json|*/ssm.json|*/sts.json)
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
    check_field "resources" "resources array"
    check_field_type "resources" "array" "resources must be an array"

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
        apigateway|bedrock|cloudfront|codebuild|cognito|dynamodb|ec2|ecs|iam|kms|lambda|rds|route53|s3|secrets|sns|sqs|ssm|sts) ;;
        *) ERRORS+=("Field 'module' must be one of: apigateway, bedrock, cloudfront, codebuild, cognito, dynamodb, ec2, ecs, iam, kms, lambda, rds, route53, s3, secrets, sns, sqs, ssm, sts (got: $MODULE_VAL)") ;;
      esac
    fi

    # Validate account_id format
    # Allow "unknown" only when status is "error" (crash envelope from base-enum.js).
    ACCT_ID=$(jq -r '.account_id // empty' "$FILE_PATH")
    if [ -n "$ACCT_ID" ]; then
      if [ "$ACCT_ID" = "unknown" ]; then
        if [ -z "$STATUS_VAL" ]; then
          ERRORS+=("account_id 'unknown' is only allowed when status is 'error' (status field is missing)")
        elif [ "$STATUS_VAL" != "error" ]; then
          ERRORS+=("account_id 'unknown' is only allowed when status is 'error' (got status: $STATUS_VAL)")
        fi
      elif ! grep -qE '^[0-9]{12}$' <<<"$ACCT_ID"; then
        ERRORS+=("account_id '$ACCT_ID' is not a valid 12-digit AWS account ID")
      fi
    fi

    if [ ${#ERRORS[@]} -gt 0 ]; then
      REASON=$(printf '  - %s\n' "${ERRORS[@]}")
      jq -n --arg reason "$REASON" --arg file "$FILE_PATH" '{
        decision: "block",
        reason: ("SCOPE Module Envelope Validation FAILED (" + $file + "):\n" + $reason + "\n\nFix the missing/invalid fields and rewrite. Schema reference: config/schemas/module-envelope.schema.json")
      }'
    fi
    exit 0
    ;;
  *)
    exit 0
    ;;
esac

# Skip dashboard run registries, not results payloads.
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
    *controls*) SOURCE="controls" ;;
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

check_array_item_fields() {
  local array_field="$1"
  local required_fields="$2"  # comma-separated
  local label="$3"
  local array_len
  array_len=$(jq ".$array_field | length" "$FILE_PATH" 2>/dev/null || echo "0")
  if [ "$array_len" -gt 0 ]; then
    IFS=',' read -ra FIELDS <<< "$required_fields"
    for field in "${FIELDS[@]}"; do
      field=$(xargs <<<"$field")  # trim whitespace
      local missing
      missing=$(jq "[.${array_field}[] | select(has(\"$field\") | not)] | length" "$FILE_PATH" 2>/dev/null || echo "0")
      if [ "$missing" -gt 0 ]; then
        ERRORS+=("$missing item(s) in '$array_field' missing required field '$field' ($label)")
      fi
    done
  fi
}

check_public_entrypoint_seed_quality() {
  local weak_seed_count
  weak_seed_count=$(jq '[.public_entrypoints[]? | select(.attack_path_seed == true) | select(((.invokes // []) | length) == 0 and ((.execution_roles // []) | length) == 0 and ((.reachable_resources // []) | length) == 0)] | length' "$FILE_PATH" 2>/dev/null || echo "0")
  if [ "$weak_seed_count" -gt 0 ]; then
    ERRORS+=("$weak_seed_count item(s) in 'public_entrypoints' set attack_path_seed true without invokes, execution_roles, or reachable_resources")
  fi

  local missing_reason_count
  missing_reason_count=$(jq '[.public_entrypoints[]? | select(.attack_path_seed == true) | select((.seed_reason // "" | strings | gsub("^\\s+|\\s+$"; "")) == "")] | length' "$FILE_PATH" 2>/dev/null || echo "0")
  if [ "$missing_reason_count" -gt 0 ]; then
    ERRORS+=("$missing_reason_count item(s) in 'public_entrypoints' set attack_path_seed true without non-empty seed_reason")
  fi
}

# Common required fields
check_field "account_id" "12-digit AWS account ID"
check_field "source" "phase identifier: audit, controls, or exploit"
check_field "timestamp" "ISO8601 timestamp"

# Validate account_id format (12 digits) — allow "unknown" for controls fallback
ACCOUNT_ID=$(jq -r '.account_id // empty' "$FILE_PATH")
if [ -n "$ACCOUNT_ID" ] && [ "$ACCOUNT_ID" != "unknown" ]; then
  if ! grep -qE '^[0-9]{12}$' <<<"$ACCOUNT_ID"; then
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

    # summary.severity is required
    if [ "$(jq 'has("summary")' "$FILE_PATH")" = "true" ]; then
      if [ "$(jq '.summary | has("severity")' "$FILE_PATH")" != "true" ]; then
        ERRORS+=("Missing required field: 'summary.severity' (critical|high|medium|low)")
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

    # public_entrypoints are optional but must be structured when present
    if [ "$(jq 'has("public_entrypoints")' "$FILE_PATH")" = "true" ]; then
      check_array_item_fields "public_entrypoints" "id,service,resource,public_access,auth_type,starting_position,attack_path_seed,risk,evidence" "public entrypoint entries"
      check_public_entrypoint_seed_quality
    fi

    # --- Enum value validation (SCHM-01, SCHM-02, SCHM-03) ---

    # SCHM-01: Validate attack_paths[].severity -- lowercase only
    if [ "$(jq 'has("attack_paths")' "$FILE_PATH")" = "true" ]; then
      INVALID_SEV=$(jq -r '[.attack_paths[] | select(.severity != null) | .severity | select(. != "critical" and . != "high" and . != "medium" and . != "low")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_SEV" ]; then
        ERRORS+=("attack_paths[].severity contains invalid values (must be lowercase: critical|high|medium|low): $INVALID_SEV")
      fi

      MISSING_AWSCLI_FIELDS=$(jq -r '[.attack_paths[] | .name as $path_name | (.aws_cli_commands // [])[] | select(has("step") | not or has("description") | not or has("command") | not or has("requires_operator_approval") | not or has("mutates_aws") | not or has("prerequisites") | not or has("cleanup") | not or has("source_basis") | not) | $path_name] | unique | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$MISSING_AWSCLI_FIELDS" ]; then
        ERRORS+=("attack_paths[].aws_cli_commands[] entries must include step, description, command, requires_operator_approval, mutates_aws, prerequisites, cleanup, and source_basis: $MISSING_AWSCLI_FIELDS")
      fi

      INVALID_AWSCLI_COMMANDS=$(jq -r '[.attack_paths[] | .name as $path_name | (.aws_cli_commands // [])[] | select((.command // "") | test("^aws\\s+") | not) | $path_name] | unique | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_AWSCLI_COMMANDS" ]; then
        ERRORS+=("attack_paths[].aws_cli_commands[].command must start with 'aws ': $INVALID_AWSCLI_COMMANDS")
      fi
    fi

    # SCHM-02: Validate graph.edges[].edge_type -- known types only
    if [ "$(jq 'has("graph") and (.graph | has("edges"))' "$FILE_PATH")" = "true" ]; then
      ALLOWED_EDGE_TYPES_JSON=$(audit_schema_edge_types_json)
      ALLOWED_EDGE_TYPES=$(jq -r 'join(", ")' <<<"$ALLOWED_EDGE_TYPES_JSON")
      INVALID_ET=$(jq -r --argjson valid "$ALLOWED_EDGE_TYPES_JSON" '[.graph.edges[] | select(.edge_type != null) | .edge_type | select(. as $edge_type | $valid | index($edge_type) | not)] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_ET" ]; then
        ERRORS+=("graph.edges[].edge_type contains invalid values (must be one of: $ALLOWED_EDGE_TYPES): $INVALID_ET")
      fi
    fi

    # SCHM-03: Validate attack_paths[].category -- known categories only
    if [ "$(jq 'has("attack_paths")' "$FILE_PATH")" = "true" ]; then
      INVALID_CAT=$(jq -r --argjson valid '["privilege_escalation","trust_misconfiguration","data_exposure","credential_risk","excessive_permission","network_exposure","persistence","post_exploitation","lateral_movement"]' '[.attack_paths[] | select(.category != null) | .category | select(. as $c | $valid | index($c) | not)] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_CAT" ]; then
        ERRORS+=("attack_paths[].category contains invalid values (must be one of: privilege_escalation, trust_misconfiguration, data_exposure, credential_risk, excessive_permission, network_exposure, persistence, post_exploitation, lateral_movement): $INVALID_CAT")
      fi
    fi

    if [ "$(jq 'has("candidate_attack_paths") or has("attack_validation") or has("security_observations")' "$FILE_PATH")" = "true" ]; then
      if ! ATTACK_LINTER_OUTPUT=$(uv run python -m scope.attack.lint --results "$FILE_PATH" --stage auto 2>&1); then
        ERRORS+=("attack linter failed for audit results: ${ATTACK_LINTER_OUTPUT:-no output}")
      fi
    fi
    ;;

  controls)
    check_field "region" "AWS region or 'global' (controls is always 'global')"
    check_field "summary" "controls summary object"
    check_field "audit_runs_analyzed" "array of consumed audit run IDs"
    check_field "org_wide_issues" "array of advisory org-wide issues"
    check_field "detections" "array of SPL detections"
    check_field "dashboards" "array of monitoring dashboard ideas"
    check_field "policy_replacements" "array of IAM replacement policies"
    check_field "remediation" "remediation plan summary object"
    check_field "validation" "validation results object"

    # summary required subfields
    if [ "$(jq 'has("summary")' "$FILE_PATH")" = "true" ]; then
      for subfield in org_wide_issues detections dashboards policy_replacements remediation_items validation_status severity; do
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

    # org_wide_issues items must include evidence, source mapping, and advisory next steps.
    check_array_item_fields "org_wide_issues" "name,severity,scope,evidence,source_attack_paths,source_run_ids,widespread_rationale,recommended_next_step" "org-wide issue entries"

    # detections items must include production-readiness fields, not just SPL text
    check_array_item_fields "detections" "name,type,objective,spl,severity,category,mitre_technique,source_attack_paths,source_run_ids,promotion_decision,fidelity_rationale,noise_controls,expected_volume,validation_status" "detection entries"

    # dashboard ideas must include monitoring rationale, source mappings, and review guidance.
    check_array_item_fields "dashboards" "name,type,objective,why_dashboard_not_detection,severity,category,source_attack_paths,source_run_ids,suggested_panels,required_data_sources,useful_fields,refresh_cadence,owner,coverage_caveats,promotion_triggers" "dashboard idea entries"

    # policy_replacements items must have role_name, file, original_policy_arn, replacement_policy_json, source_attack_paths, staleness_reasoning
    check_array_item_fields "policy_replacements" "role_name,file,original_policy_arn,replacement_policy_json,source_attack_paths,staleness_reasoning" "policy replacement entries"

    # SCHM-01 (controls): Validate detections[].severity -- lowercase only
    if [ "$(jq 'has("detections")' "$FILE_PATH")" = "true" ]; then
      INVALID_DET_SEV=$(jq -r '[.detections[] | select(.severity != null) | .severity | select(. != "critical" and . != "high" and . != "medium" and . != "low")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_DET_SEV" ]; then
        ERRORS+=("detections[].severity contains invalid values (must be lowercase: critical|high|medium|low): $INVALID_DET_SEV")
      fi

      INVALID_DET_TYPE=$(jq -r '[.detections[] | select(.type != null) | .type | select(. != "atomic" and . != "composite" and . != "hunt_query" and . != "coverage_gap")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_DET_TYPE" ]; then
        ERRORS+=("detections[].type contains invalid values (must be one of: atomic|composite|hunt_query|coverage_gap): $INVALID_DET_TYPE")
      fi

      INVALID_PROMOTION=$(jq -r '[.detections[] | select(.promotion_decision != null) | .promotion_decision | select(. != "alert" and . != "hunt_query" and . != "coverage_gap" and . != "reject")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_PROMOTION" ]; then
        ERRORS+=("detections[].promotion_decision contains invalid values (must be one of: alert|hunt_query|coverage_gap|reject): $INVALID_PROMOTION")
      fi

      INVALID_VOLUME=$(jq -r '[.detections[] | select(.expected_volume != null) | .expected_volume | select(. != "low" and . != "medium" and . != "high" and . != "unknown")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_VOLUME" ]; then
        ERRORS+=("detections[].expected_volume contains invalid values (must be one of: low|medium|high|unknown): $INVALID_VOLUME")
      fi

      INVALID_VALIDATION=$(jq -r '[.detections[] | select(.validation_status != null) | .validation_status | select(. != "not_validated" and . != "validated" and . != "too_noisy" and . != "failed")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_VALIDATION" ]; then
        ERRORS+=("detections[].validation_status contains invalid values (must be one of: not_validated|validated|too_noisy|failed): $INVALID_VALIDATION")
      fi

      UNKNOWN_ALERTS=$(jq -r '[.detections[] | select(.promotion_decision == "alert" and (.expected_volume == "unknown" or .expected_volume == "high")) | .name // "unnamed"] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$UNKNOWN_ALERTS" ]; then
        ERRORS+=("detections with expected_volume unknown/high cannot be promoted to alert: $UNKNOWN_ALERTS")
      fi

      WEAK_ATOMICS=$(jq -r '[.detections[] | select(.type == "atomic" and .promotion_decision == "alert" and (((.noise_controls // []) | length) == 0 or ((.fidelity_rationale // "") | length) < 20)) | .name // "unnamed"] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$WEAK_ATOMICS" ]; then
        ERRORS+=("atomic alert detections require non-empty noise_controls and a concrete fidelity_rationale: $WEAK_ATOMICS")
      fi
    fi

    if [ "$(jq 'has("dashboards")' "$FILE_PATH")" = "true" ]; then
      DASHBOARDS_TYPE=$(jq -r '.dashboards | type' "$FILE_PATH" 2>/dev/null || echo "unknown")
      if [ "$DASHBOARDS_TYPE" != "array" ]; then
        ERRORS+=("'dashboards' must be an array")
      fi

      INVALID_DASH_SEV=$(jq -r '[.dashboards[] | select(.severity != null) | .severity | select(. != "critical" and . != "high" and . != "medium" and . != "low")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_DASH_SEV" ]; then
        ERRORS+=("dashboards[].severity contains invalid values (must be lowercase: critical|high|medium|low): $INVALID_DASH_SEV")
      fi

      INVALID_DASH_TYPE=$(jq -r '[.dashboards[] | select(.type != null) | .type | select(. != "monitoring_dashboard" and . != "review_dashboard" and . != "coverage_dashboard" and . != "trend_dashboard")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_DASH_TYPE" ]; then
        ERRORS+=("dashboards[].type contains invalid values (must be one of: monitoring_dashboard|review_dashboard|coverage_dashboard|trend_dashboard): $INVALID_DASH_TYPE")
      fi

      INVALID_REFRESH=$(jq -r '[.dashboards[] | select(.refresh_cadence != null) | .refresh_cadence | select(. != "hourly" and . != "daily" and . != "weekly" and . != "monthly" and . != "on_demand")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_REFRESH" ]; then
        ERRORS+=("dashboards[].refresh_cadence contains invalid values (must be one of: hourly|daily|weekly|monthly|on_demand): $INVALID_REFRESH")
      fi

      EMPTY_PANELS=$(jq -r '[.dashboards[] | select(((.suggested_panels // []) | length) == 0) | .name // "unnamed"] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$EMPTY_PANELS" ]; then
        ERRORS+=("dashboard ideas require at least one suggested panel: $EMPTY_PANELS")
      fi

      MISSING_PANEL_FIELDS=$(jq -r '[.dashboards[]? | .name as $dashboard_name | (.suggested_panels // [])[]? | select((has("title") | not) or (has("visualization") | not) or (has("question") | not) or (has("fields") | not)) | $dashboard_name // "unnamed"] | unique | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$MISSING_PANEL_FIELDS" ]; then
        ERRORS+=("dashboards[].suggested_panels[] entries must include title, visualization, question, and fields: $MISSING_PANEL_FIELDS")
      fi

      INVALID_PANEL_VIS=$(jq -r '[.dashboards[]? | (.suggested_panels // [])[]? | select(.visualization != null) | .visualization | select(. != "table" and . != "timechart" and . != "bar" and . != "single_value" and . != "heatmap")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_PANEL_VIS" ]; then
        ERRORS+=("dashboards[].suggested_panels[].visualization contains invalid values (must be one of: table|timechart|bar|single_value|heatmap): $INVALID_PANEL_VIS")
      fi
    fi

    # --- Type and consistency validation (SCHM-04, SCHM-05) ---

    if [ "$(jq 'has("org_wide_issues")' "$FILE_PATH")" = "true" ]; then
      INVALID_OWI_SEV=$(jq -r '[.org_wide_issues[] | select(.severity != null) | .severity | select(. != "critical" and . != "high" and . != "medium" and . != "low")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_OWI_SEV" ]; then
        ERRORS+=("org_wide_issues[].severity contains invalid values (must be lowercase: critical|high|medium|low): $INVALID_OWI_SEV")
      fi

      INVALID_OWI_SCOPE=$(jq -r '[.org_wide_issues[] | select(.scope != null) | .scope | select(. != "account" and . != "multi-account" and . != "service" and . != "identity" and . != "region" and . != "unknown")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_OWI_SCOPE" ]; then
        ERRORS+=("org_wide_issues[].scope contains invalid values (must be one of: account|multi-account|service|identity|region|unknown): $INVALID_OWI_SCOPE")
      fi

      DEPLOYABLE_POLICY_FIELDS=$(jq -r '[.org_wide_issues[] | select(has("policy_json") or has("file") or has("type")) | .name // "unnamed"] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$DEPLOYABLE_POLICY_FIELDS" ]; then
        ERRORS+=("org_wide_issues[] must not include deployable policy fields (type, file, policy_json): $DEPLOYABLE_POLICY_FIELDS")
      fi
    fi

    # SCHM-04 (policy_replacements): Validate policy_replacements[].replacement_policy_json is an object
    if [ "$(jq 'has("policy_replacements")' "$FILE_PATH")" = "true" ]; then
      INVALID_POLICY=$(jq -r '[.policy_replacements[] | select(has("replacement_policy_json")) | select(.replacement_policy_json | type != "object") | .role_name // "unnamed"] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_POLICY" ]; then
        ERRORS+=("policy_replacements[].replacement_policy_json must be an object (not a string) — invalid items: $INVALID_POLICY")
      fi
    fi

    # SCHM-05: Validate controls summary counts match actual array lengths
    if [ "$(jq 'has("summary")' "$FILE_PATH")" = "true" ]; then
      for PAIR in "detections:detections" "dashboards:dashboards" "org_wide_issues:org_wide_issues" "policy_replacements:policy_replacements"; do
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

    # SCHM-05 (remediation): Validate summary.remediation_items matches remediation.items
    if [ "$(jq '.summary | has("remediation_items")' "$FILE_PATH")" = "true" ] && [ "$(jq 'has("remediation")' "$FILE_PATH")" = "true" ]; then
      SUMMARY_VAL=$(jq '.summary.remediation_items // 0' "$FILE_PATH" 2>/dev/null || echo "0")
      ACTUAL_VAL=$(jq '.remediation.items // 0' "$FILE_PATH" 2>/dev/null || echo "0")
      if [ "$SUMMARY_VAL" -ne "$ACTUAL_VAL" ] 2>/dev/null; then
        ERRORS+=("summary.remediation_items (${SUMMARY_VAL}) does not match remediation.items (${ACTUAL_VAL})")
      fi
    fi
    ;;

  exploit)
    check_field "target_arn" "principal ARN analyzed"
    check_field "summary" "exploit summary object"
    check_field "discovery_mode" "standalone or audit"
    check_field "attack_paths" "array of final exploit attack paths"

    # exploit attack_paths items must use the shared downstream contract
    check_array_item_fields "attack_paths" "name,severity,category,description,steps,validation_status,runtime_assumptions,coverage_caveats" "exploit attack path entries"

    if [ "$(jq 'has("paths")' "$FILE_PATH")" = "true" ]; then
      ERRORS+=("Exploit results must expose final paths in 'attack_paths', not legacy 'paths'")
    fi

    if [ "$(jq 'has("attack_paths")' "$FILE_PATH")" = "true" ]; then
      INVALID_SEV=$(jq -r '[.attack_paths[] | select(.severity != null) | .severity | select(. != "critical" and . != "high" and . != "medium" and . != "low")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_SEV" ]; then
        ERRORS+=("attack_paths[].severity contains invalid values (must be lowercase: critical|high|medium|low): $INVALID_SEV")
      fi

      INVALID_CAT=$(jq -r --argjson valid '["privilege_escalation","trust_misconfiguration","data_exposure","credential_risk","excessive_permission","network_exposure","persistence","post_exploitation","lateral_movement"]' '[.attack_paths[] | select(.category != null) | .category | select(. as $c | $valid | index($c) | not)] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_CAT" ]; then
        ERRORS+=("attack_paths[].category contains invalid values (must be one of: privilege_escalation, trust_misconfiguration, data_exposure, credential_risk, excessive_permission, network_exposure, persistence, post_exploitation, lateral_movement): $INVALID_CAT")
      fi

      INVALID_STATUS=$(jq -r '[.attack_paths[] | select(.validation_status != null) | .validation_status | select(. != "validated" and . != "conditional")] | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_STATUS" ]; then
        ERRORS+=("attack_paths[].validation_status contains invalid values (must be one of: validated|conditional): $INVALID_STATUS")
      fi

      MISSING_AWSCLI_FIELDS=$(jq -r '[.attack_paths[] | .name as $path_name | (.aws_cli_commands // [])[] | select(has("step") | not or has("description") | not or has("command") | not or has("requires_operator_approval") | not or has("mutates_aws") | not or has("prerequisites") | not or has("cleanup") | not or has("source_basis") | not) | $path_name] | unique | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$MISSING_AWSCLI_FIELDS" ]; then
        ERRORS+=("attack_paths[].aws_cli_commands[] entries must include step, description, command, requires_operator_approval, mutates_aws, prerequisites, cleanup, and source_basis: $MISSING_AWSCLI_FIELDS")
      fi

      INVALID_AWSCLI_COMMANDS=$(jq -r '[.attack_paths[] | .name as $path_name | (.aws_cli_commands // [])[] | select((.command // "") | test("^aws\\s+") | not) | $path_name] | unique | join(", ")' "$FILE_PATH" 2>/dev/null || echo "")
      if [ -n "$INVALID_AWSCLI_COMMANDS" ]; then
        ERRORS+=("attack_paths[].aws_cli_commands[].command must start with 'aws ': $INVALID_AWSCLI_COMMANDS")
      fi
    fi

    # summary.severity is required
    if [ "$(jq 'has("summary")' "$FILE_PATH")" = "true" ]; then
      if [ "$(jq '.summary | has("severity")' "$FILE_PATH")" != "true" ]; then
        ERRORS+=("Missing required field: 'summary.severity' (critical|high|medium|low)")
      fi
    fi
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
    reason: ("SCOPE Schema Validation FAILED for " + $source + " results (" + $file + "):\n" + $reason + "\n\nFix the missing/invalid fields and rewrite. Schema reference: config/schemas/" + $source + ".schema.json")
  }'
  exit 0
fi

# All checks passed
exit 0

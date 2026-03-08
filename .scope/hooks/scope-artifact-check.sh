#!/bin/bash
# SCOPE Artifact Completeness Check — Stop / AfterAgent hook
# Before the agent finishes, verify that mandatory artifacts exist.
# Checks both audit and defend run directories.
#
# For Claude Code: fires on Stop event, exit 2 prevents stopping.
# For Gemini CLI: fires on AfterAgent event, exit 2 blocks completion.

set -euo pipefail

INPUT=$(cat /dev/stdin)
CWD=$(echo "$INPUT" | jq -r '.cwd // empty')

if [ -z "$CWD" ]; then
  CWD="$(pwd)"
fi

ERRORS=()

# --- Check for recent audit runs ---
# Find the most recent audit run directory (modified in the last 30 minutes)
LATEST_AUDIT=$(find "$CWD/audit" -maxdepth 1 -type d -name "audit-*" -mmin -30 2>/dev/null | sort -r | head -1 || true)

if [ -n "$LATEST_AUDIT" ]; then
  if [ -f "$LATEST_AUDIT/results.json" ]; then
    # results.json exists — check if any module reported partial/error (indicates interrupted run)
    PARTIAL_MODULES=$(find "$LATEST_AUDIT" -maxdepth 1 -name "*.json" ! -name "results.json" ! -name "enumeration.json" -exec jq -r 'select(.status == "partial" or .status == "error") | .module' {} \; 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
    if [ -n "$PARTIAL_MODULES" ]; then
      # Interrupted run — downgrade findings.md and dashboard export to warnings
      if [ ! -f "$LATEST_AUDIT/agent-log.jsonl" ]; then
        ERRORS+=("WARNING: $LATEST_AUDIT/agent-log.jsonl missing (run had partial modules: $PARTIAL_MODULES)")
      fi
      if [ ! -f "$LATEST_AUDIT/findings.md" ]; then
        ERRORS+=("WARNING: $LATEST_AUDIT/findings.md missing (run had partial modules: $PARTIAL_MODULES)")
      fi
    else
      # Clean run — enforce mandatory artifacts
      if [ ! -f "$LATEST_AUDIT/agent-log.jsonl" ]; then
        ERRORS+=("MISSING: $LATEST_AUDIT/agent-log.jsonl (mandatory audit artifact)")
      fi
      if [ ! -f "$LATEST_AUDIT/findings.md" ]; then
        ERRORS+=("MISSING: $LATEST_AUDIT/findings.md (mandatory audit artifact)")
      fi
    fi
  else
    # No results.json — run may not have started or crashed before Gate 4
    # Downgrade to warnings only
    if [ ! -f "$LATEST_AUDIT/findings.md" ]; then
      ERRORS+=("WARNING: $LATEST_AUDIT/findings.md missing (run may not have completed)")
    fi
    if [ ! -f "$LATEST_AUDIT/agent-log.jsonl" ]; then
      ERRORS+=("WARNING: $LATEST_AUDIT/agent-log.jsonl missing (run may not have completed)")
    fi
  fi

  # Check dashboard export
  RUN_ID=$(basename "$LATEST_AUDIT")
  if [ -f "$LATEST_AUDIT/results.json" ] && [ ! -f "$CWD/dashboard/public/$RUN_ID.json" ]; then
    if [ -n "$PARTIAL_MODULES" ]; then
      ERRORS+=("WARNING: dashboard/public/$RUN_ID.json missing (run had partial modules: $PARTIAL_MODULES)")
    else
      ERRORS+=("MISSING: dashboard/public/$RUN_ID.json — results.json exists but dashboard export was not written.")
    fi
  fi

  # Check for per-module JSON output (at least one module file expected in orchestrated runs)
  MODULE_FILES=$(find "$LATEST_AUDIT" -maxdepth 1 -name "*.json" ! -name "results.json" ! -name "enumeration.json" -type f 2>/dev/null | head -1)
  # Note: module JSON files are only present in orchestrated (Phase 3+) runs.
  # Do not block on this — just warn if results.json exists but no module files.
  if [ -f "$LATEST_AUDIT/results.json" ] && [ -z "$MODULE_FILES" ]; then
    ERRORS+=("WARNING: No per-module JSON files found in $LATEST_AUDIT/ — expected in orchestrated audit runs.")
  fi
fi

# --- Check for recent defend runs ---
LATEST_DEFEND=$(find "$CWD/defend" -maxdepth 1 -type d -name "defend-*" -mmin -30 2>/dev/null | sort -r | head -1 || true)

if [ -n "$LATEST_DEFEND" ]; then
  if [ ! -f "$LATEST_DEFEND/executive-summary.md" ]; then
    ERRORS+=("MISSING: $LATEST_DEFEND/executive-summary.md (mandatory defend artifact)")
  fi
  if [ ! -f "$LATEST_DEFEND/technical-remediation.md" ]; then
    ERRORS+=("MISSING: $LATEST_DEFEND/technical-remediation.md (mandatory defend artifact)")
  fi
  if [ ! -d "$LATEST_DEFEND/policies" ]; then
    ERRORS+=("MISSING: $LATEST_DEFEND/policies/ directory (mandatory defend artifact — SCP/RCP JSON files)")
  fi
fi

# --- Check for recent exploit runs ---
LATEST_EXPLOIT=$(find "$CWD/exploit" -maxdepth 1 -type d -name "exploit-*" -mmin -30 2>/dev/null | sort -r | head -1 || true)

if [ -n "$LATEST_EXPLOIT" ]; then
  if [ ! -f "$LATEST_EXPLOIT/playbook.md" ]; then
    ERRORS+=("MISSING: $LATEST_EXPLOIT/playbook.md (mandatory exploit artifact)")
  fi
  if [ ! -f "$LATEST_EXPLOIT/agent-log.jsonl" ]; then
    ERRORS+=("MISSING: $LATEST_EXPLOIT/agent-log.jsonl (mandatory exploit artifact)")
  fi

  # Check dashboard export
  RUN_ID_EX=$(basename "$LATEST_EXPLOIT")
  if [ -f "$LATEST_EXPLOIT/results.json" ] && [ ! -f "$CWD/dashboard/public/$RUN_ID_EX.json" ]; then
    ERRORS+=("MISSING: dashboard/public/$RUN_ID_EX.json — results.json exists but dashboard export was not written.")
  fi
fi

# --- Report results ---

# If no recent runs found, nothing to check
if [ -z "$LATEST_AUDIT" ] && [ -z "$LATEST_DEFEND" ] && [ -z "$LATEST_EXPLOIT" ]; then
  exit 0
fi

if [ ${#ERRORS[@]} -gt 0 ]; then
  # Separate hard errors (MISSING) from warnings
  HARD_ERRORS=()
  WARNINGS=()
  for err in "${ERRORS[@]}"; do
    if [[ "$err" == MISSING:* ]]; then
      HARD_ERRORS+=("$err")
    else
      WARNINGS+=("$err")
    fi
  done

  if [ ${#HARD_ERRORS[@]} -gt 0 ]; then
    REASON=$(printf '%s\n' "${HARD_ERRORS[@]}")
    if [ ${#WARNINGS[@]} -gt 0 ]; then
      WARN_TEXT=$(printf '%s\n' "${WARNINGS[@]}")
      REASON="$REASON"$'\n\n'"Warnings:\n$WARN_TEXT"
    fi
    echo "SCOPE Artifact Check: Mandatory files missing. Go back and create them before completing." >&2
    echo "$REASON" >&2
    exit 2
  fi

  # Warnings only — don't block, just inform
  WARN_TEXT=$(printf '%s\n' "${WARNINGS[@]}")
  jq -n --arg warn "$WARN_TEXT" '{
    systemMessage: ("SCOPE Artifact Check warnings:\n" + $warn)
  }'
  exit 0
fi

# All checks passed
exit 0

#!/usr/bin/env bash
# tests/codx-01-mirror-sync.sh
# Structural grep test for CODX-01, CODX-02, CODX-03, CODX-04
# Verifies Codex mirror sync (Phase 15) requirements

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0

check() {
  local desc="$1"
  local actual="$2"
  local expected="$3"
  if [ "$actual" = "$expected" ]; then
    echo "PASS: $desc"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $desc (got $actual, expected $expected)"
    FAIL=$((FAIL + 1))
  fi
}

check_grep() {
  local desc="$1"
  local pattern="$2"
  local file="$3"
  if grep -q "$pattern" "$file" 2>/dev/null; then
    echo "PASS: $desc"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $desc"
    FAIL=$((FAIL + 1))
  fi
}

check_grep_absent() {
  local desc="$1"
  local pattern="$2"
  local glob="$3"
  local count
  count=$(grep -rl "$pattern" $glob 2>/dev/null | wc -l | tr -d ' ')
  if [ "$count" -eq 0 ]; then
    echo "PASS: $desc"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $desc ($count files have pattern)"
    FAIL=$((FAIL + 1))
  fi
}

# ─── CODX-01: 14 enum mirrors have Post-Write Validation ─────────────────────
count=$(grep -rl "Post-Write Validation" .codex/agents/scope-enum-*.md 2>/dev/null | wc -l | tr -d ' ')
check "CODX-01: all 14 enum mirrors have Post-Write Validation" "$count" "14"

# ─── CODX-01: 14 enum mirrors have [VALIDATION] prefix ───────────────────────
count=$(grep -rl "\[VALIDATION\]" .codex/agents/scope-enum-*.md 2>/dev/null | wc -l | tr -d ' ')
check "CODX-01: all 14 enum mirrors have [VALIDATION] prefix" "$count" "14"

# ─── CODX-01: 14 enum mirrors have ENABLED_REGIONS handling ──────────────────
count=$(grep -rl "ENABLED_REGIONS" .codex/agents/scope-enum-*.md 2>/dev/null | wc -l | tr -d ' ')
check "CODX-01: all 14 enum mirrors have ENABLED_REGIONS handling" "$count" "14"

# ─── CODX-04: no Codex mirror contains model: or tools: frontmatter fields ───
check_grep_absent "CODX-04: no Codex mirror has model:/tools: fields" "^model:\|^tools:" ".codex/agents/*.md"

# ─── CODX-02: AGENTS.md has escalation connectivity rule ─────────────────────
check_grep "CODX-02: AGENTS.md has incoming priv_esc edge rule" "incoming priv_esc edge" "AGENTS.md"

# ─── CODX-03: AGENTS.md has severity lowercase enum ─────────────────────────
check_grep "CODX-03: AGENTS.md has severity lowercase enum" "critical, high, medium, low" "AGENTS.md"

# ─── CODX-03: AGENTS.md has edge_type 8-value enum ──────────────────────────
check_grep "CODX-03: AGENTS.md has edge_type 8-value enum" "priv_esc, trust, data_access, network, service, public_access, cross_account, membership" "AGENTS.md"

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0

---
phase: 53-permission-state-model-fixes
reviewed: 2026-04-14T04:05:06Z
depth: standard
files_reviewed: 1
files_reviewed_list:
  - agents/scope-exploit.md
findings:
  critical: 0
  warning: 3
  info: 0
  total: 3
status: issues_found
---

# Phase 53: Code Review Report

**Reviewed:** 2026-04-14T04:05:06Z
**Depth:** standard
**Files Reviewed:** 1
**Status:** issues_found

## Summary

Reviewed `agents/scope-exploit.md` for workflow correctness and instruction consistency. No source-code security issues were in scope for this file type, but the agent contract has three correctness problems: path-qualified IAM ARNs are parsed incorrectly, explicit `federated-user` support is documented but unreachable, and run-index persistence is inconsistent across stop/skip branches.

## Warnings

### WR-01: IAM ARN parsing breaks principals that include paths

**File:** `agents/scope-exploit.md:436-437`
**Issue:** The file derives `PRINCIPAL_NAME` with `cut -d/ -f2`, and repeats the same pattern for normalized user/role ARNs at lines `519` and `537`. That works only for pathless principals. IAM ARNs commonly include paths, for example `arn:aws:iam::123456789012:role/team/DevOps` or `...:user/division/alice`; this logic resolves `team` or `division` instead of the actual principal name. Downstream calls such as `get-role`, `list-attached-role-policies`, and `get-user` will then target the wrong principal or fail outright.
**Fix:**
```bash
# Always take the final path segment as the friendly name
PRINCIPAL_NAME="${TARGET_ARN##*/}"
PRINCIPAL_TYPE=$(echo "$TARGET_ARN" | cut -d: -f6 | cut -d/ -f1)
TARGET_SLUG="${PRINCIPAL_TYPE%-*}-${PRINCIPAL_NAME,,}"
```

### WR-02: Explicit federated-user targets are rejected before the documented handler can run

**File:** `agents/scope-exploit.md:408-410`
**Issue:** ARN validation accepts only `user`, `role`, and `assumed-role`, but the normalization section later includes a dedicated `federated-user` branch at lines `522-531` and Gate 1 advertises `federated-user` as a supported principal type at line `276`. As written, an explicit `arn:aws:sts::...:federated-user/...` input is always rejected, so that branch is dead and the documented support never works.
**Fix:**
```bash
# Include federated-user in the accepted explicit-ARN forms
^arn:aws:(iam|sts)::[0-9]{12}:(user|role|assumed-role|federated-user)/
```
Or, if explicit federated-user targeting is intentionally unsupported, remove the later branch and the Gate 1 copy so the contract is consistent.

### WR-03: Stop/skip branches can omit `exploit/index.json`, leaving completed runs invisible to machine readers

**File:** `agents/scope-exploit.md:91-93`
**Issue:** The zero-path and Gate 4 skip exceptions say only `agent-log.jsonl` and `INDEX.md` are required, while the session-isolation contract later says every run also updates `./exploit/index.json` (`agents/scope-exploit.md:225-238`) and "after each run" append/update behavior is required. A run that stops on those exception paths can satisfy the earlier section while never being written to `exploit/index.json`, which breaks downstream consumers that rely on the JSON index rather than the markdown table.
**Fix:** Require `./exploit/index.json` updates in every terminal branch, including zero-path, `skip`, and `stop` at Gate 4. If markdown-only indexing is the intended behavior, remove the unconditional `index.json` contract from the session-isolation section.

---

_Reviewed: 2026-04-14T04:05:06Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_

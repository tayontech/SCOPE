---
phase: 41
plan: "41-01"
name: "Hunt Techniques — Create config/hunt-techniques.json (HUNT-01)"
status: complete
completed: "2026-03-30"
---

# Plan 41-01 Summary

## What Was Done

Created `config/hunt-techniques.json` — the data layer for HUNT-01. The file is the sole source of truth for hunt technique patterns referenced by `<hunt_technique_patterns>` in scope-hunt.md.

## Outcome

- **File created:** `config/hunt-techniques.json` (428 lines)
- **13 patterns** across 5 categories
- **All 9 required fields** present on every pattern
- **JSON valid:** `jq .` returns clean output

## Pattern Counts by Category

| Category | Patterns |
|---|---|
| credential_abuse | 3 (cred-abuse-new-access-key, cred-abuse-role-chaining, cred-abuse-token-replay) |
| data_exfiltration | 3 (exfil-s3-bulk-read, exfil-secrets-bulk-read, exfil-snapshot-share) |
| persistence | 3 (persist-backdoor-role, persist-ghost-user, persist-lambda-implant) |
| lateral_movement | 2 (lateral-cross-account-pivot, lateral-ssm-remote-exec) |
| defense_evasion | 3 (evasion-cloudtrail-blind, evasion-guardduty-disable, evasion-config-suppression) |

## Verification Results

- V1 — Valid JSON: PASS
- V2 — Five category keys present: PASS (`["credential_abuse", "data_exfiltration", "defense_evasion", "lateral_movement", "persistence"]`)
- V3 — Each category has ≥2 patterns: PASS (min: 2 lateral_movement, max: 3 others)
- V4 — data_event_caveat=true on S3-dependent pattern: PASS (`exfil-s3-bulk-read` only)
- V5 — All cloudtrail_signals have confirm_refute: PASS (no signals missing the field)
- V6 — All SPL uses index=cloudtrail: PASS (no macros used)

## Commit

`feat(41-01): Create config/hunt-techniques.json — hunt technique catalogue`

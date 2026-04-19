---
phase: 71-migration-testing-enum-agent-removal
plan: "02"
subsystem: sdk-enum-scripts
tags: [refactor, testing, dependency-injection, s3, kms, secrets, rds, lambda]
dependency_graph:
  requires: []
  provides:
    - scripts/enum/s3.js exports run() with DI
    - scripts/enum/kms.js exports run() with DI
    - scripts/enum/secrets.js exports run() with DI
    - scripts/enum/rds.js exports run() with DI
    - scripts/enum/lambda.js exports run() with DI
    - test/enum-s3.test.js fixture-based test
    - test/enum-kms.test.js fixture-based test
    - test/enum-secrets.test.js fixture-based test
    - test/enum-rds.test.js fixture-based test
    - test/enum-lambda.test.js fixture-based test
  affects:
    - Phase 71 plan 03 (IAM/STS/EC2/CodeBuild scripts — same DI pattern)
tech_stack:
  added: []
  patterns:
    - Dependency injection via opts.clients for AWS SDK clients
    - makeMockClient helper for command-level mock routing
    - Fixture-based testing with api-responses.json + expected.json
key_files:
  created:
    - test/enum-s3.test.js
    - test/enum-kms.test.js
    - test/enum-secrets.test.js
    - test/enum-rds.test.js
    - test/enum-lambda.test.js
    - test/fixtures/enum/s3/api-responses.json
    - test/fixtures/enum/s3/expected.json
    - test/fixtures/enum/kms/api-responses.json
    - test/fixtures/enum/kms/expected.json
    - test/fixtures/enum/secrets/api-responses.json
    - test/fixtures/enum/secrets/expected.json
    - test/fixtures/enum/rds/api-responses.json
    - test/fixtures/enum/rds/expected.json
    - test/fixtures/enum/lambda/api-responses.json
    - test/fixtures/enum/lambda/expected.json
  modified:
    - scripts/enum/s3.js
    - scripts/enum/kms.js
    - scripts/enum/secrets.js
    - scripts/enum/rds.js
    - scripts/enum/lambda.js
decisions:
  - Refactored run() to accept opts.clients for both service client and STS client injection
  - S3 script uses single client for both global ListBuckets and regional bucket ops in test context
  - Fixture null values used for date fields (LastRotatedDate, LastAccessedDate) to avoid toISOString() on strings from JSON
  - KMS fixture includes 1 CUSTOMER key and 1 AWS key to exercise the KeyManager filter path
metrics:
  duration: "~15 minutes"
  completed: "2026-04-19"
  tasks_completed: 2
  files_created: 15
  files_modified: 5
---

# Phase 71 Plan 02: Data/Compute Enum Script Refactor and Tests Summary

Refactored 5 existing enum scripts (S3, KMS, Secrets Manager, RDS, Lambda) for dependency injection and created fixture-based tests for each — enabling deterministic unit testing without live AWS credentials by injecting mock SDK clients via opts.clients.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Refactor S3, KMS, Secrets, RDS, Lambda for DI | e258a7a | 5 scripts modified |
| 2 | Create fixture data and test files | d4b09e3 | 15 files created |

## What Was Done

**Task 1 — Dependency injection refactor (5 scripts):**

Applied the same transformation to all 5 scripts:
- Renamed `main()` to `run(opts = {})` with client injection via `opts.clients?.{service} ?? new ServiceClient(...)` and `opts.clients?.sts ?? new STSClient(...)`
- Replaced all `args.*` references with `opts.*` inside `run()`
- Removed all `process.exit()` calls from `run()` — replaced with `throw new Error(...)` on fatal paths
- Added new `main()` wrapper for CLI use that calls `run()` and handles exit codes
- Added `if (require.main === module) { main(); }` guard to prevent auto-execution on `require()`
- Added `module.exports = { run }` to each script

**Task 2 — Fixture-based tests (5 services, 15 files):**

For each service: `api-responses.json` (mock AWS SDK command responses keyed by command constructor name), `expected.json` (expected envelope output without timestamp), and `test/enum-{service}.test.js` (test runner using `makeMockClient` pattern).

All 5 tests pass with `assert.deepStrictEqual`.

## Verification

```
for s in s3 kms secrets rds lambda; do node test/enum-$s.test.js || exit 1; done
# All 5 tests pass

for s in s3 kms secrets rds lambda; do node -e "const m = require('./scripts/enum/$s'); if (typeof m.run !== 'function') { process.exit(1); }"; done
# All 5 scripts export run()

grep "module.exports" scripts/enum/{s3,kms,secrets,rds,lambda}.js
# All show: module.exports = { run };
```

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None.

## Threat Flags

None — no new network endpoints, auth paths, or trust boundary changes. Test fixtures use synthetic account ID (123456789012) per T-71-04 disposition.

## Self-Check: PASSED

- scripts/enum/s3.js: FOUND, exports run()
- scripts/enum/kms.js: FOUND, exports run()
- scripts/enum/secrets.js: FOUND, exports run()
- scripts/enum/rds.js: FOUND, exports run()
- scripts/enum/lambda.js: FOUND, exports run()
- test/enum-s3.test.js: FOUND, exits 0
- test/enum-kms.test.js: FOUND, exits 0
- test/enum-secrets.test.js: FOUND, exits 0
- test/enum-rds.test.js: FOUND, exits 0
- test/enum-lambda.test.js: FOUND, exits 0
- Commit e258a7a: FOUND
- Commit d4b09e3: FOUND

# Compute Domain Coverage Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the three Compute domain enum modules (`lambda`, `codebuild`, `ec2`) to use `CoverageTracker` with per-finding `<field>_status` annotations — following the s3 worked example and Plans D-Network/D-Data precedent.

**Architecture:** Same as Plans D-Network and D-Data. Each module declares `PRIMARY_CHECKS` / `REQUIRED_CHECKS`, instantiates a `CoverageTracker`, records per-resource events, annotates findings with `<field>_status` siblings (defaulting to `null`), returns `{findings, status, coverage, errors}`. `classifyError()` is already in `scripts/lib/coverage.js` (lifted in commit `a9d0377`). No schema, hook, lib, or consumer-agent changes — those landed in Plans A/B/C/D-Data.

**Tech Stack:** Node test runner, custom assertion style, JSON fixtures driven by mocked AWS SDK clients (`@aws-sdk/client-lambda`, `@aws-sdk/client-codebuild`, `@aws-sdk/client-ec2`, `@aws-sdk/client-elastic-load-balancing-v2`, `@aws-sdk/client-elastic-load-balancing`).

---

## Source spec and precedent

- **Spec:** `docs/superpowers/specs/2026-05-17-module-envelope-coverage-design.md`. AccessDenied disposition table is operative.
- **Worked examples (best-fit by shape):**
  - `caacb6d` (s3 pilot) — canonical reference for per-finding `<field>_status` annotation discipline.
  - `672ae85` / `a446e09` (sns) — simplest single-resource-call module.
  - `e6e24ea` (apigateway) — multi-call module with two primary list ops + sub-enum early-return pattern.
  - `07e86da` (rds) — two list ops with one primary + one secondary required.
  - `054fa33` (dynamodb) — optional-heavy shape with three best-effort calls recorded as `'skipped'`.
- **Lessons baked in:**
  - All `<field>_status` defaults are `null`, never `'absent'`. Emitted values are `'present' | 'access_denied' | 'error'` (and `'absent'` only when the API explicitly signals "no data exists" — e.g., `ResourceNotFoundException` from `GetFunctionUrlConfig` / `GetPolicy`).
  - Optional check AccessDenied records as `status: 'skipped', reason: 'access_denied'` (module stays 'complete'). Required check AccessDenied records as `status: 'failed'` (module degrades to 'partial').
  - `classifyError(err)` from `../lib/coverage` returns `'access_denied'` when `err.name` is `AccessDenied`/`AccessDeniedException`, else `'error'`. Used only for the `<field>_status` annotation value — the tracker gets the raw `err.name || 'Error'` as `errorCode`.

## Important context

- **Project root:** `/Users/tayvionp/claude-code/SCOPE`. Branch: `feature/v1.14-sdk-architecture`.
- **Plan D-Data's last commit:** `efc7f6a`. This plan builds on top.
- **Test pattern:** Custom Node runner. Each module has `test/enum-<module>.test.js` + `test/fixtures/enum/<module>/{api-responses,expected}.json`. Migration includes regenerating `expected.json` via capture-verify-copy discipline.
- **Single commit per task, all tests green.** Fixture regen happens in the same commit as the code migration.
- **Other domains deferred:**
  - Identity (cognito, iam) — separate plan.
  - STS migration — separate plan (deprecation window for the existing fields).

## Migration template (six-step pattern)

This is the canonical six-step pattern shared by every Plan D module. Each task below follows it, with task-specific deviations called out inline.

1. **Read** the existing `scripts/enum/<module>.js`.
2. **Decide** `PRIMARY_CHECKS` (list ops — failure → `'error'`) and `REQUIRED_CHECKS` (per-resource details that are load-bearing — failure → `'partial'`). Anything not load-bearing is **optional** (failure → `'skipped'`).
3. **Import** `{ CoverageTracker, classifyError }` from `../lib/coverage`.
4. **Declare** classification constants near the top.
5. **Remove** local `errors`/`let status` — tracker owns both.
6. **Wire** each call site:
   - success → `tracker.record({ check, resource, status: 'ok' })`
   - required failure → `tracker.record({ check, resource, status: 'failed', operation, errorCode: err.name || 'Error', errorMessage: err.message })`
   - optional failure → `tracker.record({ check, resource, status: 'skipped', reason: classifyError(err) === 'access_denied' ? 'access_denied' : 'error', ... })`
   - primary list failure → `tracker.recordModuleFailure({ check, operation, errorCode, errorMessage })`, then derive/build/early-return.
7. **Annotate** findings with `<field>_status` siblings (default `null`, set to `'present'`/`'absent'`/`'access_denied'`/`'error'` per the call result).
8. **Return** `{ findings, status: tracker.deriveModuleStatus({ primaryChecks, requiredChecks }), ...tracker.toEnvelopeFields() }`.
9. **Regenerate** the expected fixture via capture → verify-by-eye → copy → remove debug print. One commit with all tests green.

---

## Task 1: Migrate `scripts/enum/lambda.js`

**Module shape:** `ListFunctions` (paginated, `Marker`/`NextMarker`) → per function: `GetFunctionUrlConfig`, `GetPolicy`. Both per-function calls use the existing `safeGetResource()` helper which swallows `ResourceNotFoundException` (returned as `null`).

**Classification:**
- `PRIMARY_CHECKS = ['list_functions']`
- `REQUIRED_CHECKS = ['function_url', 'resource_policy']` — both are load-bearing for attack-path reasoning (URL exposure, invocation permissions).

**Per-finding annotations:** `function_url_status`, `resource_policy_status` (default `null`).

**Special case:** `ResourceNotFoundException` from `GetFunctionUrlConfig` or `GetPolicy` is an explicit "no data exists" signal — the API succeeded but the resource has no URL config / no resource policy. The existing `safeGetResource()` helper returns `null` in that case. Record as `status: 'ok'` (the API call succeeded) and set the per-finding `<field>_status` to `'absent'`.

**Files:**
- Modify: `scripts/enum/lambda.js`
- Modify: `test/enum-lambda.test.js`
- Modify: `test/fixtures/enum/lambda/expected.json`

- [ ] **Step 1: Add coverage assertions to the test**

Open `test/enum-lambda.test.js`. Locate the block:

```js
    try {
      assert.strictEqual(result.status, expected.status);
      assert.deepStrictEqual(result.findings, expected.findings);
      console.log('  PASS: lambda enum output matches expected');
      passed++;
    } catch (err) {
```

Replace with:

```js
    try {
      assert.strictEqual(result.status, expected.status);
      assert.deepStrictEqual(result.findings, expected.findings);

      // Coverage assertions (Plan D-Compute Task 1)
      assert.ok(Array.isArray(result.coverage), 'expected result.coverage to be an array');
      assert.ok(Array.isArray(result.errors), 'expected result.errors to be an array');
      const listEntry = result.coverage.find((c) => c.check === 'list_functions');
      assert.ok(listEntry, 'expected list_functions entry in coverage');
      assert.strictEqual(listEntry.status, 'complete', 'list_functions should be complete in happy-path fixture');

      console.log('  PASS: lambda enum output matches expected');
      passed++;
    } catch (err) {
```

- [ ] **Step 2: Run test — confirm it fails**

Run: `cd /Users/tayvionp/claude-code/SCOPE && node test/enum-lambda.test.js`

Expected: FAIL on `result.coverage` (currently `undefined`, not an array).

- [ ] **Step 3: Migrate `scripts/enum/lambda.js`**

Replace the entire file contents with:

```js
'use strict';

const {
  LambdaClient,
  ListFunctionsCommand,
  GetFunctionUrlConfigCommand,
  GetPolicyCommand,
} = require('@aws-sdk/client-lambda');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { extractPolicyPrincipals } = require('../lib/policy-parser');
const { CoverageTracker, classifyError } = require('../lib/coverage');

// Check classification.
const PRIMARY_CHECKS = ['list_functions'];
const REQUIRED_CHECKS = ['function_url', 'resource_policy'];

// --- Constants ---

const SECRET_PATTERNS = /password|secret|token|key|credential|api.?key|auth/i;

// --- Helpers ---

/**
 * Safely calls an API that may throw ResourceNotFoundException.
 * Returns null when the resource doesn't exist (expected, not an error).
 * Re-throws all other errors.
 */
async function safeGetResource(fn) {
  try {
    return await withRetry(fn);
  } catch (err) {
    const code = err.name || err.Code || '';
    if (code === 'ResourceNotFoundException') {
      return null;
    }
    throw err;
  }
}

// --- Run (dependency-injectable) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const lambda = opts.clients?.lambda ?? new LambdaClient({ region });

  const logger = opts.logger || createLogger(runDir, 'lambda');
  logger.log('info', 'Lambda_Enumeration_Start', { region });

  const tracker = new CoverageTracker();

  // List all functions (paginated via Marker/NextMarker) — PRIMARY
  logger.log('api_call', 'ListFunctions', { service: 'lambda' });
  let functions;
  try {
    functions = await paginate(lambda, ListFunctionsCommand, 'Functions', {
      tokenKey: 'Marker',
      responseTokenKey: 'NextMarker',
    });
    tracker.record({ check: 'list_functions', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'ListFunctions', { error: err.message });
    tracker.recordModuleFailure({
      check: 'list_functions',
      operation: 'ListFunctions',
      errorCode: err.name || 'Error',
      errorMessage: err.message,
    });
    await logger.flush();
    const status = tracker.deriveModuleStatus({
      primaryChecks: PRIMARY_CHECKS,
      requiredChecks: REQUIRED_CHECKS,
    });
    const { coverage, errors } = tracker.toEnvelopeFields();
    return { findings: [], status, coverage, errors };
  }

  const findings = [];

  for (const func of functions) {
    const fnArn = func.FunctionArn;
    let functionUrl = null;
    let functionUrlStatus = null;
    let resourcePolicyPrincipals = [];
    let resourcePolicyStatus = null;

    // GetFunctionUrlConfig (required) — null on RNF means "no URL configured".
    try {
      logger.log('api_call', 'GetFunctionUrlConfig', { function: func.FunctionName });
      const urlResp = await safeGetResource(() =>
        lambda.send(new GetFunctionUrlConfigCommand({ FunctionName: func.FunctionName }))
      );
      if (urlResp) {
        functionUrl = urlResp.FunctionUrl || null;
        functionUrlStatus = 'present';
      } else {
        functionUrlStatus = 'absent';
      }
      tracker.record({ check: 'function_url', resource: fnArn, status: 'ok' });
    } catch (err) {
      logger.log('warning', 'GetFunctionUrlConfig', { function: func.FunctionName, error: err.message });
      functionUrlStatus = classifyError(err);
      tracker.record({
        check: 'function_url',
        resource: fnArn,
        status: 'failed',
        operation: 'GetFunctionUrlConfig',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    // GetPolicy (required) — null on RNF means "no resource policy attached".
    try {
      logger.log('api_call', 'GetPolicy', { function: func.FunctionName });
      const policyResp = await safeGetResource(() =>
        lambda.send(new GetPolicyCommand({ FunctionName: func.FunctionName }))
      );
      if (policyResp && policyResp.Policy) {
        resourcePolicyPrincipals = extractPolicyPrincipals(policyResp.Policy);
        resourcePolicyStatus = 'present';
      } else {
        resourcePolicyStatus = 'absent';
      }
      tracker.record({ check: 'resource_policy', resource: fnArn, status: 'ok' });
    } catch (err) {
      logger.log('warning', 'GetPolicy', { function: func.FunctionName, error: err.message });
      resourcePolicyStatus = classifyError(err);
      tracker.record({
        check: 'resource_policy',
        resource: fnArn,
        status: 'failed',
        operation: 'GetPolicy',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    // Environment variable analysis (names only, never values)
    const envVarNames = Object.keys(func.Environment?.Variables || {});
    const secretPatternNames = envVarNames.filter((n) => SECRET_PATTERNS.test(n));

    // Layers
    const layers = (func.Layers || []).map((l) => ({
      arn: l.Arn,
      code_size: l.CodeSize || null,
    }));

    const finding = {
      resource_type: 'lambda_function',
      resource_id: func.FunctionName,
      arn: fnArn,
      runtime: func.Runtime || null,
      role: func.Role || null,
      handler: func.Handler || null,
      code_size: func.CodeSize || null,
      timeout: func.Timeout || null,
      memory_size: func.MemorySize || null,
      last_modified: func.LastModified || null,
      layers,
      function_url: functionUrl,
      function_url_status: functionUrlStatus,
      resource_policy_principals: resourcePolicyPrincipals,
      resource_policy_status: resourcePolicyStatus,
      env_var_names: envVarNames,
      secret_pattern_names: secretPatternNames,
      findings: [],
    };

    // Findings
    if (secretPatternNames.length > 0) {
      finding.findings.push({
        type: 'secret_env_vars',
        severity: 'high',
        detail: `Function has ${secretPatternNames.length} env var(s) matching secret patterns: ${secretPatternNames.join(', ')}`,
      });
    }

    if (functionUrl) {
      finding.findings.push({
        type: 'function_url_enabled',
        severity: 'info',
        detail: `Function URL enabled: ${functionUrl}`,
      });
    }

    if (resourcePolicyPrincipals.includes('*')) {
      finding.findings.push({
        type: 'wildcard_resource_policy',
        severity: 'high',
        detail: 'Resource policy allows wildcard (*) principal',
      });
    }

    findings.push(finding);
  }

  await logger.flush();
  const status = tracker.deriveModuleStatus({
    primaryChecks: PRIMARY_CHECKS,
    requiredChecks: REQUIRED_CHECKS,
  });
  const { coverage, errors } = tracker.toEnvelopeFields();
  return { findings, status, coverage, errors };
}

if (require.main === module) {
  baseEnum({ module: 'lambda', run });
}

module.exports = { run };
```

- [ ] **Step 4: Capture the new expected fixture**

The expected fixture's `findings[].function_url_status` and `findings[].resource_policy_status` are new fields that need to be added. The mock returns `null` for both `GetFunctionUrlConfigCommand` and `GetPolicyCommand`, so both should be `'absent'` for the existing fixture.

Add a temporary debug print at the bottom of `runTests()` in `test/enum-lambda.test.js`, just after the `try` block closes (after `failed++` line), insert before the `} finally {` line:

```js
    console.log('--- CAPTURE BEGIN ---');
    console.log(JSON.stringify({
      status: result.status,
      findings: result.findings,
    }, null, 2));
    console.log('--- CAPTURE END ---');
```

Wait — this needs to run regardless of pass/fail. Place the capture call right before the outer `try { ... } catch (err) { ... } finally { ... }` block's `finally`. Actually the simplest is to put it directly after the `result` assignment, before the assertions:

Find:

```js
    const result = await run({
      runDir: tmpDir,
      region: 'us-east-1',
      accountId: '123456789012',
      clients: { lambda: mockLambda },
    });

    try {
```

Insert between them:

```js
    const result = await run({
      runDir: tmpDir,
      region: 'us-east-1',
      accountId: '123456789012',
      clients: { lambda: mockLambda },
    });

    console.log('--- CAPTURE BEGIN ---');
    console.log(JSON.stringify({
      module: 'lambda',
      account_id: '123456789012',
      region: 'us-east-1',
      status: result.status,
      findings: result.findings,
    }, null, 2));
    console.log('--- CAPTURE END ---');

    try {
```

Run: `node test/enum-lambda.test.js`

The output between `--- CAPTURE BEGIN ---` and `--- CAPTURE END ---` is the new `expected.json`.

- [ ] **Step 5: Verify the captured output by eye**

Expected output should match this shape exactly (one function, two `*_status` fields both = `'absent'`, no other behavioral changes):

```json
{
  "module": "lambda",
  "account_id": "123456789012",
  "region": "us-east-1",
  "status": "complete",
  "findings": [
    {
      "resource_type": "lambda_function",
      "resource_id": "my-test-function",
      "arn": "arn:aws:lambda:us-east-1:123456789012:function:my-test-function",
      "runtime": "nodejs20.x",
      "role": "arn:aws:iam::123456789012:role/lambda-basic-execution",
      "handler": "index.handler",
      "code_size": 1024,
      "timeout": 30,
      "memory_size": 128,
      "last_modified": "2024-01-15T10:00:00.000+0000",
      "layers": [],
      "function_url": null,
      "function_url_status": "absent",
      "resource_policy_principals": [],
      "resource_policy_status": "absent",
      "env_var_names": ["LOG_LEVEL", "DB_HOST"],
      "secret_pattern_names": [],
      "findings": []
    }
  ]
}
```

If the captured output drifts in any field that wasn't planned, STOP — the migration has an unintended side-effect. Investigate before proceeding.

Note: the mock returns `null` for both `GetFunctionUrlConfigCommand` and `GetPolicyCommand`. The mock client's `if (val !== undefined) return Promise.resolve(val);` branch resolves with `null`. The `safeGetResource()` helper only catches `ResourceNotFoundException` — a `null` resolution is *not* caught, but `urlResp` ends up `null`, and the `if (urlResp)` branch goes to the `else`, setting status to `'absent'`. End-to-end correct.

- [ ] **Step 6: Copy the captured output into `test/fixtures/enum/lambda/expected.json`**

Overwrite the file with the captured JSON. Preserve the existing top-level fields (`module`, `account_id`, `region` — these are metadata that the test doesn't currently assert, but the fixture has them).

- [ ] **Step 7: Remove the debug capture print**

Revert the insertion from Step 4 in `test/enum-lambda.test.js`. The test file should look exactly like the pre-Step-4 state plus the Step 1 coverage assertions.

- [ ] **Step 8: Run the lambda test — expect green**

Run: `node test/enum-lambda.test.js`

Expected: `1 passed, 0 failed`.

- [ ] **Step 9: Run full suite — expect green**

Run: `node test/run-all.js`

Expected: green across all 25 test files. If anything else fails, STOP — diagnose before committing.

- [ ] **Step 10: Commit**

```bash
git add scripts/enum/lambda.js test/enum-lambda.test.js test/fixtures/enum/lambda/expected.json

git commit -m "feat(lambda): migrate to CoverageTracker

Lambda has a single list operation (ListFunctions, primary) plus two
per-function calls that are load-bearing for attack-path reasoning:
GetFunctionUrlConfig and GetPolicy.

- PRIMARY_CHECKS=['list_functions'] — ListFunctions failure becomes
  status=error via recordModuleFailure + early return.
- REQUIRED_CHECKS=['function_url', 'resource_policy'] — either
  failure degrades module to 'partial'.

Per-function annotations: function_url_status and resource_policy_status.
ResourceNotFoundException from either call is treated as a successful
'absent' signal — the API succeeded; the function just doesn't have
that optional config. Other errors set the per-field status via
classifyError() and record the call as 'failed'.

Local errors[] / let status removed; tracker is the source of truth."
```

---

## Task 2: Migrate `scripts/enum/codebuild.js`

**Module shape:** `ListProjects` (paginated, `nextToken`) → `BatchGetProjects` (chunks of 100). The current code also surfaces `projectsNotFound` entries from BatchGetProjects responses as errors.

**Classification:**
- `PRIMARY_CHECKS = ['list_projects']`
- `REQUIRED_CHECKS = ['batch_get_projects']` — without project detail, the security story (env vars, service role, privileged mode, VPC) is unknowable.

**Per-finding annotations:** No `<field>_status` fields needed on the project finding — every detail is hydrated in the same `BatchGetProjects` call. If that call fails, the project never makes it into `findings[]`. If it succeeds, all fields are populated. The coverage envelope alone communicates batch failures.

**Special case: `projectsNotFound`.** BatchGetProjects returns a `projectsNotFound` array for names that exist in ListProjects but couldn't be fetched (usually deleted between the two calls). Record each as a per-project `'failed'` event under the `batch_get_projects` check with `errorCode: 'ProjectNotFound'`. This degrades the module to `'partial'`, which is correct — we have a list of N projects but data on only N - K of them.

**Files:**
- Modify: `scripts/enum/codebuild.js`
- Modify: `test/enum-codebuild.test.js`
- Modify: `test/fixtures/enum/codebuild/expected.json` (only if the new code produces drift; the current findings shape is unchanged)

- [ ] **Step 1: Add coverage assertions to the test**

Open `test/enum-codebuild.test.js`. Find the assertion block (around `assert.strictEqual(result.status, expected.status);` followed by `assert.deepStrictEqual(result.findings, expected.findings);` and `console.log('  PASS: ...')`).

Insert immediately after `assert.deepStrictEqual(result.findings, expected.findings);`:

```js
    // Coverage assertions (Plan D-Compute Task 2)
    assert.ok(Array.isArray(result.coverage), 'expected result.coverage to be an array');
    assert.ok(Array.isArray(result.errors), 'expected result.errors to be an array');
    const listEntry = result.coverage.find((c) => c.check === 'list_projects');
    assert.ok(listEntry, 'expected list_projects entry in coverage');
    assert.strictEqual(listEntry.status, 'complete', 'list_projects should be complete in happy-path fixture');
    const batchEntry = result.coverage.find((c) => c.check === 'batch_get_projects');
    assert.ok(batchEntry, 'expected batch_get_projects entry in coverage');
```

- [ ] **Step 2: Run test — confirm it fails**

Run: `cd /Users/tayvionp/claude-code/SCOPE && node test/enum-codebuild.test.js`

Expected: FAIL on `result.coverage` (currently `undefined`).

- [ ] **Step 3: Migrate `scripts/enum/codebuild.js`**

Replace the entire file contents with:

```js
'use strict';

const {
  CodeBuildClient,
  ListProjectsCommand,
  BatchGetProjectsCommand,
} = require('@aws-sdk/client-codebuild');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { CoverageTracker, classifyError } = require('../lib/coverage');

// Check classification.
const PRIMARY_CHECKS = ['list_projects'];
const REQUIRED_CHECKS = ['batch_get_projects'];

// --- Constants ---

const SECRET_PATTERNS = /password|secret|token|key|credential|api.?key|auth/i;

// --- Helpers ---

/**
 * Chunk an array into groups of a given size.
 */
function chunk(arr, size) {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}

// --- Exported run() for testing ---

async function run(opts = {}) {
  const { runDir, region } = opts;
  const accountId = opts.accountId;

  if (!runDir || !region) {
    throw new Error('runDir and region are required');
  }

  const codebuild = opts.clients?.codebuild ?? new CodeBuildClient({ region });

  const logger = opts.logger || createLogger(runDir, 'codebuild');
  logger.log('info', 'CodeBuild_Enumeration_Start', { region });

  const tracker = new CoverageTracker();

  // List all project names (paginated) — PRIMARY
  logger.log('api_call', 'ListProjects', { service: 'codebuild' });
  let projectNames;
  try {
    projectNames = await paginate(codebuild, ListProjectsCommand, 'projects', {
      tokenKey: 'nextToken',
      responseTokenKey: 'nextToken',
    });
    tracker.record({ check: 'list_projects', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'ListProjects', { error: err.message });
    tracker.recordModuleFailure({
      check: 'list_projects',
      operation: 'ListProjects',
      errorCode: err.name || 'Error',
      errorMessage: err.message,
    });
    await logger.flush();
    const status = tracker.deriveModuleStatus({
      primaryChecks: PRIMARY_CHECKS,
      requiredChecks: REQUIRED_CHECKS,
    });
    const { coverage, errors } = tracker.toEnvelopeFields();
    return { findings: [], status, coverage, errors };
  }

  if (!projectNames || projectNames.length === 0) {
    await logger.flush();
    const status = tracker.deriveModuleStatus({
      primaryChecks: PRIMARY_CHECKS,
      requiredChecks: REQUIRED_CHECKS,
    });
    const { coverage, errors } = tracker.toEnvelopeFields();
    return { findings: [], status, coverage, errors };
  }

  // BatchGetProjects — up to 100 per call (required)
  const findings = [];
  const batches = chunk(projectNames, 100);

  for (const batch of batches) {
    const batchLabel = `batch(${batch.length})`;
    try {
      logger.log('api_call', 'BatchGetProjects', { service: 'codebuild', count: batch.length });
      const resp = await withRetry(() =>
        codebuild.send(new BatchGetProjectsCommand({ names: batch }))
      );

      for (const project of resp.projects || []) {
        // Extract env var NAMES only — NEVER include values
        const envVars = project.environment?.environmentVariables || [];
        const envVarNames = envVars.map((v) => v.name);
        const secretPatternNames = envVarNames.filter((n) => SECRET_PATTERNS.test(n));

        const finding = {
          resource_type: 'codebuild_project',
          resource_id: project.name,
          arn: project.arn || null,
          region,
          service_role: project.serviceRole || null,
          source_type: project.source?.type || null,
          source_location: project.source?.location || null,
          source_buildspec: project.source?.buildspec ? true : false,
          environment_type: project.environment?.type || null,
          environment_image: project.environment?.image || null,
          environment_compute_type: project.environment?.computeType || null,
          privileged_mode: project.environment?.privilegedMode || false,
          vpc_config: project.vpcConfig
            ? {
                vpc_id: project.vpcConfig.vpcId || null,
                subnets: project.vpcConfig.subnets || [],
                security_group_ids: project.vpcConfig.securityGroupIds || [],
              }
            : null,
          env_var_names: envVarNames,
          secret_pattern_names: secretPatternNames,
          encryption_key: project.encryptionKey || null,
          last_modified: project.lastModified ? project.lastModified.toISOString() : null,
          findings: [],
        };

        // Findings
        if (secretPatternNames.length > 0) {
          finding.findings.push({
            type: 'secret_env_vars',
            severity: 'high',
            detail: `Project has ${secretPatternNames.length} env var(s) matching secret patterns: ${secretPatternNames.join(', ')}`,
          });
        }

        if (project.environment?.privilegedMode) {
          finding.findings.push({
            type: 'privileged_mode',
            severity: 'medium',
            detail: 'Build environment runs in privileged mode (Docker daemon access)',
          });
        }

        if (!project.vpcConfig) {
          finding.findings.push({
            type: 'no_vpc',
            severity: 'info',
            detail: 'Project builds do not run inside a VPC',
          });
        }

        findings.push(finding);
        tracker.record({ check: 'batch_get_projects', resource: project.arn || project.name, status: 'ok' });
      }

      // Track projects that failed to load (listed but missing from response)
      for (const name of resp.projectsNotFound || []) {
        logger.log('warning', 'BatchGetProjects_NotFound', { project: name });
        tracker.record({
          check: 'batch_get_projects',
          resource: name,
          status: 'failed',
          operation: 'BatchGetProjects',
          errorCode: 'ProjectNotFound',
          errorMessage: `Project '${name}' was listed but not returned in BatchGetProjects response`,
        });
      }
    } catch (err) {
      logger.log('error', 'BatchGetProjects', { error: err.message });
      tracker.record({
        check: 'batch_get_projects',
        resource: batchLabel,
        status: 'failed',
        operation: 'BatchGetProjects',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }
  }

  await logger.flush();
  const status = tracker.deriveModuleStatus({
    primaryChecks: PRIMARY_CHECKS,
    requiredChecks: REQUIRED_CHECKS,
  });
  const { coverage, errors } = tracker.toEnvelopeFields();
  return { findings, status, coverage, errors };
}

if (require.main === module) {
  baseEnum({ module: 'codebuild', run });
}

module.exports = { run };
```

- [ ] **Step 4: Capture the new expected fixture**

The findings shape is unchanged (no new `<field>_status` annotations). Coverage/errors are computed but not stored in `expected.json` (only asserted via `result.coverage.find(...)` in the test).

Even so, capture and verify by eye to confirm `result.status` and `result.findings` are byte-identical to the old fixture. Add a temporary capture print to `test/enum-codebuild.test.js`. Find the line:

```js
    const result = await run({
```

Insert before it nothing; instead, insert *after* the run completes. Find the line with `assert.strictEqual(result.status, expected.status);` and insert the capture print immediately before it:

```js
    console.log('--- CAPTURE BEGIN ---');
    console.log(JSON.stringify({
      module: 'codebuild',
      account_id: '123456789012',
      region: 'us-east-1',
      status: result.status,
      findings: result.findings,
    }, null, 2));
    console.log('--- CAPTURE END ---');

```

Run: `node test/enum-codebuild.test.js`

The output between `--- CAPTURE BEGIN ---` and `--- CAPTURE END ---` is the candidate `expected.json`.

- [ ] **Step 5: Verify the captured output by eye**

The captured output must be byte-identical to the current `test/fixtures/enum/codebuild/expected.json` (no new fields, no field reordering). Compare visually. If anything differs other than expected drift, STOP and diagnose.

- [ ] **Step 6: Copy the captured output (if drift exists)**

If the capture matches the existing fixture exactly, skip this step. If there is unavoidable drift (e.g., field order changed because of how `tracker.record` reorders execution), overwrite `test/fixtures/enum/codebuild/expected.json` with the captured JSON.

Note: existing fixture top-level fields are `module`, `account_id`, `region`, `status`, `findings`. The capture print uses the same shape, so a direct overwrite is safe if needed.

- [ ] **Step 7: Remove the debug capture print**

Revert the insertion from Step 4.

- [ ] **Step 8: Run the codebuild test — expect green**

Run: `node test/enum-codebuild.test.js`

Expected: `1 tests: 1 passed, 0 failed` (or whatever the existing pass-count is; codebuild may run multiple scenarios).

- [ ] **Step 9: Run full suite — expect green**

Run: `node test/run-all.js`

Expected: green across all 25 test files.

- [ ] **Step 10: Commit**

```bash
git add scripts/enum/codebuild.js test/enum-codebuild.test.js test/fixtures/enum/codebuild/expected.json

git commit -m "feat(codebuild): migrate to CoverageTracker

CodeBuild has a single list operation (ListProjects, primary) and one
batch detail call (BatchGetProjects, required). Without project detail
the security story — service role, env vars, privileged mode, VPC
config — is unknowable.

- PRIMARY_CHECKS=['list_projects'] — ListProjects failure becomes
  status=error via recordModuleFailure + early return.
- REQUIRED_CHECKS=['batch_get_projects'] — batch failure or per-project
  not-found degrades module to 'partial'.

projectsNotFound entries from BatchGetProjects (projects that were
listed but disappeared by the time we fetched detail) are recorded as
per-project 'failed' events with errorCode='ProjectNotFound'. Batch-wide
exceptions are recorded against a 'batch(N)' resource label.

Findings shape unchanged — every project detail is hydrated in the
single BatchGetProjects call, so no per-finding <field>_status
annotations were needed. Coverage envelope alone tells the gap story.

Local errors[] / let status removed; tracker is the source of truth."
```

---

## Task 3: Migrate `scripts/enum/ec2.js`

**Module shape:** Six independent sub-enumerations that share the same EC2 + ELB clients:
1. `DescribeInstances` → per-instance fields (no per-resource follow-up calls)
2. `DescribeSecurityGroups` → no per-resource follow-up
3. `DescribeVpcs` → no per-resource follow-up
4. `DescribeSnapshots` → per-snapshot `DescribeSnapshotAttribute` (the only per-resource detail call)
5. `DescribeLoadBalancers` (ELBv2) → per-LB `DescribeListeners`
6. `DescribeLoadBalancers` (Classic ELB) → no per-resource follow-up

Each sub-enum is wrapped in its own try/catch in the existing code and continues on failure. EC2 doesn't have a single "primary" — losing one sub-enum doesn't make the others worthless.

**Classification (design decision):**
- `PRIMARY_CHECKS = []` — no single list op is fatal; each sub-domain is independently valuable.
- `REQUIRED_CHECKS = ['describe_instances', 'describe_security_groups', 'describe_vpcs', 'describe_snapshots', 'snapshot_attributes', 'describe_load_balancers_v2', 'describe_listeners', 'describe_load_balancers_classic']`
- Any failure → module degrades to `'partial'`. If every sub-enum fails, status is still `'partial'` (not `'error'`) — the spec accepts this. The Coverage Gaps narrative in `findings.md` will surface the breadth of failures regardless.

**Rationale (record in commit message):** Treating any single sub-enum as `PRIMARY` (with `recordModuleFailure`) would force the whole module to `'error'` on one sub-enum's AccessDenied, which would hide the partial data we *did* collect from the other five. EC2's value isn't tied to any single sub-enum, so `PRIMARY_CHECKS=[]` is correct.

**Per-finding annotations:**
- Instances, SGs, VPCs, Classic LBs: no per-resource follow-up calls → no `<field>_status` annotations needed.
- Snapshots: add `snapshot_attributes_status` (default `null`) tracking the per-snapshot `DescribeSnapshotAttribute` call.
- ELBv2 LBs: add `listeners_status` (default `null`) tracking the per-LB `DescribeListeners` call.

**Files:**
- Modify: `scripts/enum/ec2.js`
- Modify: `test/enum-ec2.test.js`
- Modify: `test/fixtures/enum/ec2/expected.json`

- [ ] **Step 1: Add coverage assertions to the test**

Open `test/enum-ec2.test.js`. Find the assertion block after `const result = await run({ ... });`. After `assert.deepStrictEqual(result.findings, expected.findings);` insert:

```js
    // Coverage assertions (Plan D-Compute Task 3)
    assert.ok(Array.isArray(result.coverage), 'expected result.coverage to be an array');
    assert.ok(Array.isArray(result.errors), 'expected result.errors to be an array');
    const instancesEntry = result.coverage.find((c) => c.check === 'describe_instances');
    assert.ok(instancesEntry, 'expected describe_instances entry in coverage');
    assert.strictEqual(instancesEntry.status, 'complete', 'describe_instances should be complete in happy-path fixture');
    const sgEntry = result.coverage.find((c) => c.check === 'describe_security_groups');
    assert.ok(sgEntry, 'expected describe_security_groups entry in coverage');
    const vpcEntry = result.coverage.find((c) => c.check === 'describe_vpcs');
    assert.ok(vpcEntry, 'expected describe_vpcs entry in coverage');
    const snapEntry = result.coverage.find((c) => c.check === 'describe_snapshots');
    assert.ok(snapEntry, 'expected describe_snapshots entry in coverage');
```

- [ ] **Step 2: Run test — confirm it fails**

Run: `cd /Users/tayvionp/claude-code/SCOPE && node test/enum-ec2.test.js`

Expected: FAIL on `result.coverage` (currently `undefined`).

- [ ] **Step 3: Migrate `scripts/enum/ec2.js`**

The current file has six sub-enum helper functions. Two architectural changes:
1. Each sub-enum function gains a `tracker` parameter (passed by `run()`).
2. Each list call records `ok` or `failed` against the tracker. Per-resource detail calls (`DescribeSnapshotAttribute`, `DescribeListeners`) record per-resource events and set `<field>_status` annotations.

Replace the entire file contents with:

```js
'use strict';

const {
  EC2Client,
  DescribeInstancesCommand,
  DescribeSecurityGroupsCommand,
  DescribeVpcsCommand,
  DescribeSnapshotsCommand,
  DescribeSnapshotAttributeCommand,
} = require('@aws-sdk/client-ec2');

const {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand: DescribeALBsCommand,
  DescribeListenersCommand,
} = require('@aws-sdk/client-elastic-load-balancing-v2');

const {
  ElasticLoadBalancingClient,
  DescribeLoadBalancersCommand: DescribeClassicLBsCommand,
} = require('@aws-sdk/client-elastic-load-balancing');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { CoverageTracker, classifyError } = require('../lib/coverage');

// Check classification.
// No single list op is fatal — each sub-enum is independently useful.
const PRIMARY_CHECKS = [];
const REQUIRED_CHECKS = [
  'describe_instances',
  'describe_security_groups',
  'describe_vpcs',
  'describe_snapshots',
  'snapshot_attributes',
  'describe_load_balancers_v2',
  'describe_listeners',
  'describe_load_balancers_classic',
];

// --- Instance enumeration ---

async function enumerateInstances(ec2, region, logger, tracker) {
  logger.log('api_call', 'DescribeInstances', { service: 'ec2' });
  let reservations;
  try {
    reservations = await paginate(ec2, DescribeInstancesCommand, 'Reservations');
    tracker.record({ check: 'describe_instances', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'DescribeInstances', { error: err.message });
    tracker.record({
      check: 'describe_instances',
      resource: null,
      status: 'failed',
      operation: 'DescribeInstances',
      errorCode: err.name || 'Error',
      errorMessage: err.message,
    });
    return [];
  }

  const findings = [];
  for (const reservation of reservations) {
    for (const instance of reservation.Instances || []) {
      const imdsVersion = instance.MetadataOptions?.HttpTokens === 'required' ? 'v2' : 'v1';
      const isImdsV1 = imdsVersion === 'v1';

      const nameTag = (instance.Tags || []).find((t) => t.Key === 'Name');
      const sgIds = (instance.SecurityGroups || []).map((sg) => sg.GroupId);

      const finding = {
        resource_type: 'ec2_instance',
        resource_id: instance.InstanceId,
        arn: `arn:aws:ec2:${region}:*:instance/${instance.InstanceId}`,
        region,
        name: nameTag ? nameTag.Value : null,
        state: instance.State?.Name || null,
        instance_type: instance.InstanceType || null,
        platform: instance.Platform || 'linux',
        public_ip: instance.PublicIpAddress || null,
        private_ip: instance.PrivateIpAddress || null,
        vpc_id: instance.VpcId || null,
        subnet_id: instance.SubnetId || null,
        iam_instance_profile: instance.IamInstanceProfile
          ? { arn: instance.IamInstanceProfile.Arn, id: instance.IamInstanceProfile.Id }
          : null,
        security_groups: sgIds,
        imds_version: imdsVersion,
        metadata_options: {
          http_tokens: instance.MetadataOptions?.HttpTokens || null,
          http_endpoint: instance.MetadataOptions?.HttpEndpoint || null,
          http_put_response_hop_limit: instance.MetadataOptions?.HttpPutResponseHopLimit || null,
        },
        findings: [],
      };

      if (isImdsV1) {
        finding.findings.push({
          type: 'imds_v1_enabled',
          severity: 'critical',
          detail: 'Instance uses IMDSv1 (HttpTokens=optional) — credential theft via SSRF',
        });
      }

      if (instance.PublicIpAddress) {
        finding.findings.push({
          type: 'public_ip',
          severity: 'info',
          detail: `Instance has public IP: ${instance.PublicIpAddress}`,
        });
      }

      if (!instance.IamInstanceProfile) {
        finding.findings.push({
          type: 'no_instance_profile',
          severity: 'info',
          detail: 'No IAM instance profile attached',
        });
      }

      findings.push(finding);
    }
  }

  logger.log('info', 'DescribeInstances_Complete', { count: findings.length });
  return findings;
}

// --- Security Groups ---

async function enumerateSecurityGroups(ec2, region, logger, tracker) {
  logger.log('api_call', 'DescribeSecurityGroups', { service: 'ec2' });
  let groups;
  try {
    groups = await paginate(ec2, DescribeSecurityGroupsCommand, 'SecurityGroups');
    tracker.record({ check: 'describe_security_groups', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'DescribeSecurityGroups', { error: err.message });
    tracker.record({
      check: 'describe_security_groups',
      resource: null,
      status: 'failed',
      operation: 'DescribeSecurityGroups',
      errorCode: err.name || 'Error',
      errorMessage: err.message,
    });
    return [];
  }

  const findings = [];
  for (const sg of groups) {
    const inboundRules = (sg.IpPermissions || []).map((perm) => {
      const sources = [
        ...(perm.IpRanges || []).map((r) => r.CidrIp),
        ...(perm.Ipv6Ranges || []).map((r) => r.CidrIpv6),
        ...(perm.PrefixListIds || []).map((p) => p.PrefixListId),
        ...(perm.UserIdGroupPairs || []).map((g) => g.GroupId),
      ];
      return {
        protocol: perm.IpProtocol || null,
        from_port: perm.FromPort ?? null,
        to_port: perm.ToPort ?? null,
        sources,
      };
    });

    const openToWorld = inboundRules.some((rule) =>
      rule.sources.some((s) => s === '0.0.0.0/0' || s === '::/0')
    );

    const finding = {
      resource_type: 'ec2_security_group',
      resource_id: sg.GroupId,
      arn: `arn:aws:ec2:${region}:*:security-group/${sg.GroupId}`,
      region,
      name: sg.GroupName || null,
      description: sg.Description || null,
      vpc_id: sg.VpcId || null,
      inbound_rules: inboundRules,
      findings: [],
    };

    if (openToWorld) {
      finding.findings.push({
        type: 'open_to_world',
        severity: 'high',
        detail: 'Security group has inbound rule(s) open to 0.0.0.0/0 or ::/0',
      });
    }

    findings.push(finding);
  }

  logger.log('info', 'DescribeSecurityGroups_Complete', { count: findings.length });
  return findings;
}

// --- VPCs ---

async function enumerateVpcs(ec2, region, logger, tracker) {
  logger.log('api_call', 'DescribeVpcs', { service: 'ec2' });
  let vpcs;
  try {
    vpcs = await paginate(ec2, DescribeVpcsCommand, 'Vpcs');
    tracker.record({ check: 'describe_vpcs', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'DescribeVpcs', { error: err.message });
    tracker.record({
      check: 'describe_vpcs',
      resource: null,
      status: 'failed',
      operation: 'DescribeVpcs',
      errorCode: err.name || 'Error',
      errorMessage: err.message,
    });
    return [];
  }

  const findings = [];
  for (const vpc of vpcs) {
    const nameTag = (vpc.Tags || []).find((t) => t.Key === 'Name');
    findings.push({
      resource_type: 'ec2_vpc',
      resource_id: vpc.VpcId,
      arn: `arn:aws:ec2:${region}:*:vpc/${vpc.VpcId}`,
      region,
      name: nameTag ? nameTag.Value : null,
      cidr_block: vpc.CidrBlock || null,
      is_default: vpc.IsDefault || false,
      state: vpc.State || null,
      findings: [],
    });
  }

  logger.log('info', 'DescribeVpcs_Complete', { count: findings.length });
  return findings;
}

// --- Snapshots ---

async function enumerateSnapshots(ec2, accountId, region, logger, tracker) {
  logger.log('api_call', 'DescribeSnapshots', { service: 'ec2', owner: 'self' });
  let snapshots;
  try {
    snapshots = await paginate(ec2, DescribeSnapshotsCommand, 'Snapshots', {
      params: { OwnerIds: ['self'] },
    });
    tracker.record({ check: 'describe_snapshots', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'DescribeSnapshots', { error: err.message });
    tracker.record({
      check: 'describe_snapshots',
      resource: null,
      status: 'failed',
      operation: 'DescribeSnapshots',
      errorCode: err.name || 'Error',
      errorMessage: err.message,
    });
    return [];
  }

  const findings = [];
  for (const snap of snapshots) {
    const snapArn = `arn:aws:ec2:${region}:${accountId}:snapshot/${snap.SnapshotId}`;
    let isPublic = false;
    let snapshotAttributesStatus = null;

    try {
      logger.log('api_call', 'DescribeSnapshotAttribute', { snapshot: snap.SnapshotId });
      const attrResp = await withRetry(() =>
        ec2.send(new DescribeSnapshotAttributeCommand({
          SnapshotId: snap.SnapshotId,
          Attribute: 'createVolumePermission',
        }))
      );
      const perms = attrResp.CreateVolumePermissions || [];
      isPublic = perms.some((p) => p.Group === 'all');
      snapshotAttributesStatus = 'present';
      tracker.record({ check: 'snapshot_attributes', resource: snapArn, status: 'ok' });
    } catch (err) {
      logger.log('warning', 'DescribeSnapshotAttribute', {
        snapshot: snap.SnapshotId,
        error: err.message,
      });
      snapshotAttributesStatus = classifyError(err);
      tracker.record({
        check: 'snapshot_attributes',
        resource: snapArn,
        status: 'failed',
        operation: 'DescribeSnapshotAttribute',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    const finding = {
      resource_type: 'ec2_snapshot',
      resource_id: snap.SnapshotId,
      arn: snapArn,
      region,
      volume_id: snap.VolumeId || null,
      volume_size_gb: snap.VolumeSize || null,
      encrypted: snap.Encrypted || false,
      state: snap.State || null,
      is_public: isPublic,
      snapshot_attributes_status: snapshotAttributesStatus,
      findings: [],
    };

    if (isPublic) {
      finding.findings.push({
        type: 'public_snapshot',
        severity: 'critical',
        detail: 'Snapshot is publicly shared (createVolumePermission includes "all")',
      });
    }

    if (!snap.Encrypted) {
      finding.findings.push({
        type: 'unencrypted_snapshot',
        severity: 'medium',
        detail: 'Snapshot is not encrypted',
      });
    }

    findings.push(finding);
  }

  logger.log('info', 'DescribeSnapshots_Complete', { count: findings.length });
  return findings;
}

// --- ELBv2 (ALB/NLB) ---

async function enumerateELBv2(elbv2, region, logger, tracker) {
  logger.log('api_call', 'DescribeLoadBalancers_v2', { service: 'elbv2' });
  let lbs;
  try {
    lbs = await paginate(elbv2, DescribeALBsCommand, 'LoadBalancers', {
      tokenKey: 'Marker',
      responseTokenKey: 'NextMarker',
    });
    tracker.record({ check: 'describe_load_balancers_v2', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'DescribeLoadBalancers_v2', { error: err.message });
    tracker.record({
      check: 'describe_load_balancers_v2',
      resource: null,
      status: 'failed',
      operation: 'DescribeLoadBalancers',
      errorCode: err.name || 'Error',
      errorMessage: err.message,
    });
    return [];
  }

  const findings = [];
  for (const lb of lbs) {
    const lbArn = lb.LoadBalancerArn;
    let listeners = [];
    let listenersStatus = null;
    try {
      logger.log('api_call', 'DescribeListeners', { lb_arn: lbArn });
      listeners = await paginate(elbv2, DescribeListenersCommand, 'Listeners', {
        params: { LoadBalancerArn: lbArn },
        tokenKey: 'Marker',
        responseTokenKey: 'NextMarker',
      });
      listenersStatus = 'present';
      tracker.record({ check: 'describe_listeners', resource: lbArn, status: 'ok' });
    } catch (err) {
      logger.log('warning', 'DescribeListeners', { lb_arn: lbArn, error: err.message });
      listenersStatus = classifyError(err);
      tracker.record({
        check: 'describe_listeners',
        resource: lbArn,
        status: 'failed',
        operation: 'DescribeListeners',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    const finding = {
      resource_type: 'ec2_load_balancer',
      resource_id: lb.LoadBalancerName,
      arn: lbArn,
      region,
      type: lb.Type || null,
      scheme: lb.Scheme || null,
      state: lb.State?.Code || null,
      dns_name: lb.DNSName || null,
      vpc_id: lb.VpcId || null,
      availability_zones: (lb.AvailabilityZones || []).map((az) => az.ZoneName),
      listeners: listeners.map((l) => ({
        port: l.Port,
        protocol: l.Protocol,
        ssl_policy: l.SslPolicy || null,
      })),
      listeners_status: listenersStatus,
      findings: [],
    };

    if (lb.Scheme === 'internet-facing') {
      finding.findings.push({
        type: 'internet_facing',
        severity: 'info',
        detail: `Load balancer is internet-facing: ${lb.DNSName}`,
      });
    }

    findings.push(finding);
  }

  logger.log('info', 'DescribeLoadBalancers_v2_Complete', { count: findings.length });
  return findings;
}

// --- Classic ELB ---

async function enumerateClassicELB(elb, region, logger, tracker) {
  logger.log('api_call', 'DescribeLoadBalancers_classic', { service: 'elb' });
  let lbs;
  try {
    lbs = await paginate(elb, DescribeClassicLBsCommand, 'LoadBalancerDescriptions', {
      tokenKey: 'Marker',
      responseTokenKey: 'NextMarker',
    });
    tracker.record({ check: 'describe_load_balancers_classic', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'DescribeLoadBalancers_classic', { error: err.message });
    tracker.record({
      check: 'describe_load_balancers_classic',
      resource: null,
      status: 'failed',
      operation: 'DescribeLoadBalancers',
      errorCode: err.name || 'Error',
      errorMessage: err.message,
    });
    return [];
  }

  const findings = [];
  for (const lb of lbs) {
    const finding = {
      resource_type: 'ec2_load_balancer',
      resource_id: lb.LoadBalancerName,
      arn: null, // Classic ELBs don't have ARN in describe response
      region,
      type: 'classic',
      scheme: lb.Scheme || null,
      dns_name: lb.DNSName || null,
      vpc_id: lb.VPCId || null,
      availability_zones: lb.AvailabilityZones || [],
      listeners: (lb.ListenerDescriptions || []).map((ld) => ({
        port: ld.Listener?.LoadBalancerPort || null,
        protocol: ld.Listener?.Protocol || null,
        instance_port: ld.Listener?.InstancePort || null,
        instance_protocol: ld.Listener?.InstanceProtocol || null,
      })),
      findings: [],
    };

    if (lb.Scheme === 'internet-facing') {
      finding.findings.push({
        type: 'internet_facing',
        severity: 'info',
        detail: `Classic load balancer is internet-facing: ${lb.DNSName}`,
      });
    }

    findings.push(finding);
  }

  logger.log('info', 'DescribeLoadBalancers_classic_Complete', { count: findings.length });
  return findings;
}

// --- Run (dependency-injectable) ---

async function run(opts = {}) {
  const { runDir, region } = opts;
  const accountId = opts.accountId;

  if (!runDir || !region) {
    throw new Error('runDir and region are required');
  }

  const ec2 = opts.clients?.ec2 ?? new EC2Client({ region });
  const elbv2 = opts.clients?.elbv2 ?? new ElasticLoadBalancingV2Client({ region });
  const elb = opts.clients?.elb ?? new ElasticLoadBalancingClient({ region });

  const logger = opts.logger || createLogger(runDir, 'ec2');
  logger.log('info', 'EC2_Enumeration_Start', { region });

  const tracker = new CoverageTracker();
  const allFindings = [];

  // 1. Instances
  allFindings.push(...(await enumerateInstances(ec2, region, logger, tracker)));

  // 2. Security Groups
  allFindings.push(...(await enumerateSecurityGroups(ec2, region, logger, tracker)));

  // 3. VPCs
  allFindings.push(...(await enumerateVpcs(ec2, region, logger, tracker)));

  // 4. Snapshots
  allFindings.push(...(await enumerateSnapshots(ec2, accountId, region, logger, tracker)));

  // 5. ELBv2 (ALB/NLB)
  allFindings.push(...(await enumerateELBv2(elbv2, region, logger, tracker)));

  // 6. Classic ELB
  allFindings.push(...(await enumerateClassicELB(elb, region, logger, tracker)));

  await logger.flush();
  const status = tracker.deriveModuleStatus({
    primaryChecks: PRIMARY_CHECKS,
    requiredChecks: REQUIRED_CHECKS,
  });
  const { coverage, errors } = tracker.toEnvelopeFields();
  return { findings: allFindings, status, coverage, errors };
}

if (require.main === module) {
  baseEnum({ module: 'ec2', run });
}

module.exports = { run };
```

- [ ] **Step 4: Capture the new expected fixture**

The expected fixture's snapshot findings now have `snapshot_attributes_status`, and ELBv2 LB findings now have `listeners_status`. Both are new fields.

Add a temporary capture print to `test/enum-ec2.test.js`. Find the line `const result = await run({ ... });` (the run completion). Immediately after the `await run({...})` call resolves and before `assert.strictEqual(result.status, expected.status);`, insert:

```js
    console.log('--- CAPTURE BEGIN ---');
    console.log(JSON.stringify({
      module: 'ec2',
      account_id: '123456789012',
      region: 'us-east-1',
      status: result.status,
      findings: result.findings,
    }, null, 2));
    console.log('--- CAPTURE END ---');

```

Run: `node test/enum-ec2.test.js`

The output between the capture markers is the candidate `expected.json`.

- [ ] **Step 5: Verify the captured output by eye**

The expected drift from the current fixture:
- Every `ec2_snapshot` finding gains a new field: `"snapshot_attributes_status": "present"` (if the mock returns a valid response) or `null` (if there are no snapshots in the fixture).
- Every `ec2_load_balancer` finding with `type !== 'classic'` gains a new field: `"listeners_status": "present"` (if the mock returns listener data) or `null` (if no LBs in the fixture).
- Classic ELB findings should be unchanged.
- All other findings (instances, SGs, VPCs) should be byte-identical to the current fixture.

If the test fixture has no snapshots and no ELBv2 LBs, the only change is none — `findings[]` is byte-identical. Read `test/fixtures/enum/ec2/expected.json` first to know what to expect.

If the captured output drifts in any field that isn't either of the two new annotations, STOP — the migration has an unintended side-effect.

- [ ] **Step 6: Copy the captured output into `test/fixtures/enum/ec2/expected.json`**

Overwrite the file with the captured JSON. Preserve the top-level metadata fields (`module`, `account_id`, `region`).

- [ ] **Step 7: Remove the debug capture print**

Revert the insertion from Step 4.

- [ ] **Step 8: Run the ec2 test — expect green**

Run: `node test/enum-ec2.test.js`

Expected: `1 tests: 1 passed, 0 failed`.

- [ ] **Step 9: Run full suite — expect green**

Run: `node test/run-all.js`

Expected: green across all 25 test files.

- [ ] **Step 10: Commit**

```bash
git add scripts/enum/ec2.js test/enum-ec2.test.js test/fixtures/enum/ec2/expected.json

git commit -m "feat(ec2): migrate to CoverageTracker

EC2 has six independent sub-enumerations: DescribeInstances,
DescribeSecurityGroups, DescribeVpcs, DescribeSnapshots (+ per-snapshot
DescribeSnapshotAttribute), DescribeLoadBalancers (ELBv2, + per-LB
DescribeListeners), DescribeLoadBalancers (Classic). Each sub-enum is
independently useful — losing one doesn't invalidate the others.

- PRIMARY_CHECKS=[] — no single list op is fatal. Treating any single
  sub-enum as primary would force the whole module to 'error' on one
  AccessDenied, hiding the partial data we did collect from the other
  five.
- REQUIRED_CHECKS=['describe_instances', 'describe_security_groups',
  'describe_vpcs', 'describe_snapshots', 'snapshot_attributes',
  'describe_load_balancers_v2', 'describe_listeners',
  'describe_load_balancers_classic'] — any failure degrades to
  'partial', surfaced via the Coverage Gaps narrative.

Per-resource annotations:
- ec2_snapshot.snapshot_attributes_status — tracks per-snapshot
  DescribeSnapshotAttribute (drives is_public determination).
- ec2_load_balancer (v2 only).listeners_status — tracks per-LB
  DescribeListeners (drives port/protocol enrichment).

Instance, SG, VPC, and Classic LB findings have no per-resource
follow-up calls and no <field>_status annotations.

Local errors[] / let status removed; tracker is the source of truth."
```

---

## Self-review

**Spec coverage:**
- Lambda primary list op covered ✓
- Lambda per-function required calls (URL, policy) covered with annotations ✓
- Codebuild list + batch detail covered ✓
- Codebuild `projectsNotFound` quirk explicitly handled ✓
- EC2 six sub-enumerations all classified ✓
- EC2 per-resource detail calls (snapshot attributes, ELBv2 listeners) annotated ✓
- All three modules return `{findings, status, coverage, errors}` ✓
- `<field>_status` defaults are `null`, never `'absent'` ✓
- AccessDenied disposition: required → `'failed'`, optional → `'skipped'` (no optionals in this plan, but the rule is acknowledged in the migration template) ✓
- `classifyError()` imported from lib, not redefined ✓

**Placeholder scan:** none found. Every step has concrete code or commands.

**Type consistency:** every check name used in tracker.record / deriveModuleStatus / test assertions matches the `PRIMARY_CHECKS` / `REQUIRED_CHECKS` declarations:
- lambda: `list_functions`, `function_url`, `resource_policy` ✓
- codebuild: `list_projects`, `batch_get_projects` ✓
- ec2: `describe_instances`, `describe_security_groups`, `describe_vpcs`, `describe_snapshots`, `snapshot_attributes`, `describe_load_balancers_v2`, `describe_listeners`, `describe_load_balancers_classic` ✓

Field-name consistency:
- lambda: `function_url_status`, `resource_policy_status` ✓
- ec2: `snapshot_attributes_status`, `listeners_status` ✓
- codebuild: no per-finding annotation (deliberate — single batch call hydrates everything) ✓

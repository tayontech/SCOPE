# Cognito Coverage Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate `scripts/enum/cognito.js` to use `CoverageTracker` with per-finding `<field>_status` annotations.

**Architecture:** Same migration pattern as Plans D-Network/D-Data/D-Compute. Cognito has two independent sub-domains (identity pools, user pools+clients), so `PRIMARY_CHECKS = []` — same design as EC2. List-op failures must use `tracker.record({status: 'failed'})` (NOT `recordModuleFailure`) due to the known lib bug: `deriveModuleStatus` filters required-check failures with `!e.moduleWide`, so module-wide failures on required-only checks are silently treated as 'complete'. Per-resource detail-call failures use `tracker.record({status: 'failed'})` with the resource ARN.

**Tech Stack:** Node test runner, custom assertion style, JSON fixtures driven by mocked AWS SDK clients (`@aws-sdk/client-cognito-identity`, `@aws-sdk/client-cognito-identity-provider`).

---

## Source spec and precedent

- **Spec:** `docs/superpowers/specs/2026-05-17-module-envelope-coverage-design.md`.
- **Closest worked examples:**
  - `25576b1` / `d61d99b` (ec2) — multi-sub-enum, `PRIMARY_CHECKS = []`. Read `git show 25576b1 -- scripts/enum/ec2.js` for the canonical multi-sub-enum pattern with the lib-bug workaround.
  - `f8ad8c3` (lambda) — single primary + per-finding `<field>_status` annotations on the fallback-when-detail-fails pattern.
- **Lessons baked in:**
  - `<field>_status` defaults are `null`.
  - `classifyError(err)` returns `'access_denied'` or `'error'` — used only for per-finding annotation values.
  - `errorCode` on tracker events is raw (`err.name || 'Error'`), not classified.
  - **Lib-bug workaround:** with `PRIMARY_CHECKS = []`, list-op failures use `tracker.record({status: 'failed'})`, accepting the slightly misleading `scope: 'per_resource'` label in the coverage entry. `recordModuleFailure` would break module status derivation in this configuration.

## Important context

- **Project root:** `/Users/tayvionp/claude-code/SCOPE`. Branch: `feature/v1.14-sdk-architecture`.
- **Last commit:** `25576b1` (Plan D-Compute revert). This plan builds on top.
- **Test:** `node test/enum-cognito.test.js` for module; `node test/run-all.js` for full suite.
- **Cognito's structure:**
  - Identity-pool sub-domain: `ListIdentityPools` (paginated) → per-pool `DescribeIdentityPool`.
  - User-pool sub-domain: `ListUserPools` (paginated) → per-pool `DescribeUserPool` → per-pool `ListUserPoolClients` (paginated) → per-client `DescribeUserPoolClient`.
  - Two sub-domains are independent (one can fail without invalidating the other).
- **Existing fallback behavior to preserve:** when `DescribeIdentityPool` / `DescribeUserPool` / `DescribeUserPoolClient` fails, the existing code still pushes a minimal finding (with fewer fields). Keep that fallback shape but add a `describe_status` annotation. The fallback shape is what consumers expect when detail is unavailable.

---

## Migration template

Same six-step pattern from prior plans. The deviation from EC2:
- Cognito has paginated list ops with sub-list calls (`ListUserPoolClients` per user pool). Track each `ListUserPoolClients` call as a per-resource event keyed by the parent user pool ARN.
- User-pool findings gain TWO annotations: `describe_status` (tracking DescribeUserPool) and `clients_status` (tracking ListUserPoolClients for that pool).

---

## Task 1: Migrate `scripts/enum/cognito.js`

**Classification:**
- `PRIMARY_CHECKS = []` — identity pools and user pools are independent sub-domains.
- `REQUIRED_CHECKS = ['list_identity_pools', 'describe_identity_pool', 'list_user_pools', 'describe_user_pool', 'list_user_pool_clients', 'describe_user_pool_client']`

**Per-finding annotations:**
- `cognito_identity_pool`: `describe_status` (default `null`; `'present'` on success, `classifyError(err)` on failure).
- `cognito_user_pool`: `describe_status` (default `null`) AND `clients_status` (default `null`; tracks the per-pool `ListUserPoolClients` call).
- `cognito_user_pool_client`: `describe_status` (default `null`).

**Behavior preservation:**
- Identity-pool sub-enum: if `ListIdentityPools` throws, record `tracker.record({check: 'list_identity_pools', resource: null, status: 'failed', ...})` and return `[]` from the sub-enum (matches existing try/catch in run()).
- Similarly for `ListUserPools` and the inner `ListUserPoolClients` (per pool).
- On `DescribeIdentityPool` failure: push the existing fallback finding shape PLUS `describe_status: classifyError(err)`.
- On `DescribeUserPool` failure: push fallback finding shape PLUS `describe_status: classifyError(err)`, and skip the inner client enumeration for that pool (consistent with existing behavior — there's no client info if we can't describe the pool).
- On `DescribeUserPoolClient` failure: push fallback finding shape PLUS `describe_status: classifyError(err)`.

**Files:**
- Modify: `scripts/enum/cognito.js`
- Modify: `test/enum-cognito.test.js`
- Modify: `test/fixtures/enum/cognito/expected.json`

- [ ] **Step 1: Add coverage assertions to the test**

Open `test/enum-cognito.test.js`. Find the assertion block:

```js
    assert.strictEqual(result.status, expected.status);
    assert.deepStrictEqual(result.findings, expected.findings);
    console.log('  PASS: cognito basic scenario');
```

Insert immediately after `assert.deepStrictEqual(result.findings, expected.findings);`:

```js
    // Coverage assertions (Cognito coverage rollout Task 1)
    assert.ok(Array.isArray(result.coverage), 'expected result.coverage to be an array');
    assert.ok(Array.isArray(result.errors), 'expected result.errors to be an array');
    const idListEntry = result.coverage.find((c) => c.check === 'list_identity_pools');
    assert.ok(idListEntry, 'expected list_identity_pools entry in coverage');
    assert.strictEqual(idListEntry.status, 'complete', 'list_identity_pools should be complete in happy-path fixture');
    const idDescribeEntry = result.coverage.find((c) => c.check === 'describe_identity_pool');
    assert.ok(idDescribeEntry, 'expected describe_identity_pool entry in coverage');
    const upListEntry = result.coverage.find((c) => c.check === 'list_user_pools');
    assert.ok(upListEntry, 'expected list_user_pools entry in coverage');
    const upDescribeEntry = result.coverage.find((c) => c.check === 'describe_user_pool');
    assert.ok(upDescribeEntry, 'expected describe_user_pool entry in coverage');
    const clientsListEntry = result.coverage.find((c) => c.check === 'list_user_pool_clients');
    assert.ok(clientsListEntry, 'expected list_user_pool_clients entry in coverage');
    const clientDescribeEntry = result.coverage.find((c) => c.check === 'describe_user_pool_client');
    assert.ok(clientDescribeEntry, 'expected describe_user_pool_client entry in coverage');
```

- [ ] **Step 2: Run test — confirm it fails**

Run: `cd /Users/tayvionp/claude-code/SCOPE && node test/enum-cognito.test.js`

Expected: FAIL on `result.coverage` (currently undefined).

- [ ] **Step 3: Migrate `scripts/enum/cognito.js`**

Replace the entire file contents with:

```js
'use strict';

const {
  CognitoIdentityClient,
  ListIdentityPoolsCommand,
  DescribeIdentityPoolCommand,
} = require('@aws-sdk/client-cognito-identity');

const {
  CognitoIdentityProviderClient,
  ListUserPoolsCommand,
  DescribeUserPoolCommand,
  ListUserPoolClientsCommand,
  DescribeUserPoolClientCommand,
} = require('@aws-sdk/client-cognito-identity-provider');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { CoverageTracker, classifyError } = require('../lib/coverage');

// Check classification.
// PRIMARY_CHECKS = [] because identity pools and user pools are independent
// sub-domains — losing one shouldn't elevate module status above 'partial'.
// List-op failures use tracker.record({status:'failed'}) rather than
// recordModuleFailure: the current deriveModuleStatus filters required-check
// failures with !moduleWide, so a moduleWide failure on a required-only check
// is silently treated as 'complete'. Using regular record preserves the
// correct 'partial' module status. (Same workaround as ec2.js.)
const PRIMARY_CHECKS = [];
const REQUIRED_CHECKS = [
  'list_identity_pools',
  'describe_identity_pool',
  'list_user_pools',
  'describe_user_pool',
  'list_user_pool_clients',
  'describe_user_pool_client',
];

// --- Identity Pools (CognitoIdentityClient) ---

async function enumerateIdentityPools(client, region, logger, tracker) {
  logger.log('api_call', 'ListIdentityPools', {});

  const pools = [];
  try {
    let nextToken = undefined;
    do {
      const params = { MaxResults: 60 };
      if (nextToken) params.NextToken = nextToken;
      const resp = await withRetry(() => client.send(new ListIdentityPoolsCommand(params)));
      if (resp.IdentityPools) pools.push(...resp.IdentityPools);
      nextToken = resp.NextToken;
    } while (nextToken);
    tracker.record({ check: 'list_identity_pools', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'ListIdentityPools', { error: err.message });
    tracker.record({
      check: 'list_identity_pools',
      resource: null,
      status: 'failed',
      operation: 'ListIdentityPools',
      errorCode: err.name || 'Error',
      errorMessage: err.message,
    });
    return [];
  }

  const findings = [];
  for (const pool of pools) {
    const poolArn = `arn:aws:cognito-identity:${region}:unknown:identitypool/${pool.IdentityPoolId}`;
    try {
      logger.log('api_call', 'DescribeIdentityPool', { poolId: pool.IdentityPoolId });
      const detail = await withRetry(() =>
        client.send(new DescribeIdentityPoolCommand({ IdentityPoolId: pool.IdentityPoolId }))
      );

      const allowUnauth = detail.AllowUnauthenticatedIdentities === true;
      const poolFindings = [];

      if (allowUnauth) {
        poolFindings.push(
          'CRITICAL: AllowUnauthenticatedIdentities is TRUE — anyone can call GetId + GetCredentialsForIdentity and receive temporary AWS credentials without authentication'
        );
      }

      const roles = detail.Roles || {};

      findings.push({
        resource_type: 'cognito_identity_pool',
        resource_id: detail.IdentityPoolName || pool.IdentityPoolId,
        arn: poolArn,
        pool_id: pool.IdentityPoolId,
        pool_name: detail.IdentityPoolName || null,
        region,
        allow_unauthenticated: allowUnauth,
        authenticated_role_arn: roles.authenticated || null,
        unauthenticated_role_arn: roles.unauthenticated || null,
        supported_login_providers: detail.SupportedLoginProviders || {},
        open_id_connect_provider_arns: detail.OpenIdConnectProviderARNs || [],
        cognito_identity_providers: (detail.CognitoIdentityProviders || []).map((p) => ({
          provider_name: p.ProviderName,
          client_id: p.ClientId,
          server_side_token_check: p.ServerSideTokenCheck || false,
        })),
        saml_provider_arns: detail.SamlProviderARNs || [],
        describe_status: 'present',
        findings: poolFindings,
      });
      tracker.record({ check: 'describe_identity_pool', resource: poolArn, status: 'ok' });
    } catch (err) {
      logger.log('warning', 'DescribeIdentityPool', { poolId: pool.IdentityPoolId, error: err.message });
      findings.push({
        resource_type: 'cognito_identity_pool',
        resource_id: pool.IdentityPoolId,
        arn: poolArn,
        pool_id: pool.IdentityPoolId,
        pool_name: pool.IdentityPoolName || null,
        region,
        allow_unauthenticated: null,
        describe_status: classifyError(err),
        findings: [],
      });
      tracker.record({
        check: 'describe_identity_pool',
        resource: poolArn,
        status: 'failed',
        operation: 'DescribeIdentityPool',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }
  }

  return findings;
}

// --- User Pools (CognitoIdentityProviderClient) ---

async function enumerateUserPools(providerClient, region, logger, tracker) {
  logger.log('api_call', 'ListUserPools', {});

  const pools = [];
  try {
    let nextToken = undefined;
    do {
      const params = { MaxResults: 60 };
      if (nextToken) params.NextToken = nextToken;
      const resp = await withRetry(() => providerClient.send(new ListUserPoolsCommand(params)));
      if (resp.UserPools) pools.push(...resp.UserPools);
      nextToken = resp.NextToken;
    } while (nextToken);
    tracker.record({ check: 'list_user_pools', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'ListUserPools', { error: err.message });
    tracker.record({
      check: 'list_user_pools',
      resource: null,
      status: 'failed',
      operation: 'ListUserPools',
      errorCode: err.name || 'Error',
      errorMessage: err.message,
    });
    return { userPoolFindings: [], clientFindings: [] };
  }

  const userPoolFindings = [];
  const clientFindings = [];

  for (const pool of pools) {
    const poolArn = `arn:aws:cognito-idp:${region}:unknown:userpool/${pool.Id}`;
    let describeStatus = null;
    let clientsStatus = null;

    let detail = null;
    try {
      logger.log('api_call', 'DescribeUserPool', { userPoolId: pool.Id });
      const resp = await withRetry(() =>
        providerClient.send(new DescribeUserPoolCommand({ UserPoolId: pool.Id }))
      );
      detail = resp.UserPool || {};
      describeStatus = 'present';
      tracker.record({ check: 'describe_user_pool', resource: poolArn, status: 'ok' });
    } catch (err) {
      logger.log('warning', 'DescribeUserPool', { userPoolId: pool.Id, error: err.message });
      describeStatus = classifyError(err);
      tracker.record({
        check: 'describe_user_pool',
        resource: poolArn,
        status: 'failed',
        operation: 'DescribeUserPool',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    if (detail !== null) {
      const selfRegistrationEnabled =
        !(detail.AdminCreateUserConfig?.AllowAdminCreateUserOnly === true);
      const mfaConfig = detail.MfaConfiguration || 'OFF';
      const passwordPolicy = detail.Policies?.PasswordPolicy || {};
      const schemaAttributes = detail.SchemaAttributes || [];
      const customAttributes = schemaAttributes.filter((a) => a.Name && a.Name.startsWith('custom:'));

      const poolFindings = [];
      if (selfRegistrationEnabled) {
        poolFindings.push('Self-registration enabled — anyone can create an account');
      }
      if (mfaConfig === 'OFF') {
        poolFindings.push('MFA is OFF — no multi-factor authentication enforced');
      }

      // Enumerate clients for this user pool (per-pool list op, required).
      let clients = [];
      try {
        clients = await listUserPoolClients(providerClient, pool.Id, logger);
        clientsStatus = 'present';
        tracker.record({ check: 'list_user_pool_clients', resource: poolArn, status: 'ok' });
      } catch (err) {
        logger.log('warning', 'ListUserPoolClients', { userPoolId: pool.Id, error: err.message });
        clientsStatus = classifyError(err);
        tracker.record({
          check: 'list_user_pool_clients',
          resource: poolArn,
          status: 'failed',
          operation: 'ListUserPoolClients',
          errorCode: err.name || 'Error',
          errorMessage: err.message,
        });
      }

      userPoolFindings.push({
        resource_type: 'cognito_user_pool',
        resource_id: detail.Name || pool.Id,
        arn: detail.Arn || poolArn,
        pool_id: pool.Id,
        pool_name: detail.Name || null,
        region,
        self_registration_enabled: selfRegistrationEnabled,
        mfa_configuration: mfaConfig,
        password_policy: {
          minimum_length: passwordPolicy.MinimumLength || null,
          require_uppercase: passwordPolicy.RequireUppercase || false,
          require_lowercase: passwordPolicy.RequireLowercase || false,
          require_numbers: passwordPolicy.RequireNumbers || false,
          require_symbols: passwordPolicy.RequireSymbols || false,
          temporary_password_validity_days: passwordPolicy.TemporaryPasswordValidityDays || null,
        },
        custom_attributes_count: customAttributes.length,
        estimated_users: detail.EstimatedNumberOfUsers || 0,
        creation_date: detail.CreationDate || null,
        last_modified_date: detail.LastModifiedDate || null,
        describe_status: describeStatus,
        clients_status: clientsStatus,
        findings: poolFindings,
      });

      // Per-client describe loop.
      for (const c of clients) {
        const clientArn = `arn:aws:cognito-idp:${region}:unknown:userpool/${pool.Id}/client/${c.ClientId}`;
        try {
          logger.log('api_call', 'DescribeUserPoolClient', { clientId: c.ClientId });
          const resp = await withRetry(() =>
            providerClient.send(
              new DescribeUserPoolClientCommand({ UserPoolId: pool.Id, ClientId: c.ClientId })
            )
          );
          const cDetail = resp.UserPoolClient || {};

          const cFindings = [];
          const oauthFlows = cDetail.AllowedOAuthFlows || [];
          if (oauthFlows.includes('implicit')) {
            cFindings.push('Implicit OAuth flow enabled — tokens exposed in URL fragment');
          }

          clientFindings.push({
            resource_type: 'cognito_user_pool_client',
            resource_id: cDetail.ClientName || c.ClientId,
            arn: clientArn,
            client_id: c.ClientId,
            client_name: cDetail.ClientName || null,
            user_pool_id: pool.Id,
            region,
            allowed_oauth_flows: oauthFlows,
            allowed_oauth_flows_user_pool_client: cDetail.AllowedOAuthFlowsUserPoolClient || false,
            allowed_oauth_scopes: cDetail.AllowedOAuthScopes || [],
            callback_urls: cDetail.CallbackURLs || [],
            logout_urls: cDetail.LogoutURLs || [],
            explicit_auth_flows: cDetail.ExplicitAuthFlows || [],
            token_validity: {
              access_token: cDetail.AccessTokenValidity || null,
              id_token: cDetail.IdTokenValidity || null,
              refresh_token: cDetail.RefreshTokenValidity || null,
            },
            prevent_user_existence_errors: cDetail.PreventUserExistenceErrors || null,
            describe_status: 'present',
            findings: cFindings,
          });
          tracker.record({ check: 'describe_user_pool_client', resource: clientArn, status: 'ok' });
        } catch (err) {
          logger.log('warning', 'DescribeUserPoolClient', { clientId: c.ClientId, error: err.message });
          clientFindings.push({
            resource_type: 'cognito_user_pool_client',
            resource_id: c.ClientId,
            arn: clientArn,
            client_id: c.ClientId,
            user_pool_id: pool.Id,
            region,
            describe_status: classifyError(err),
            findings: [],
          });
          tracker.record({
            check: 'describe_user_pool_client',
            resource: clientArn,
            status: 'failed',
            operation: 'DescribeUserPoolClient',
            errorCode: err.name || 'Error',
            errorMessage: err.message,
          });
        }
      }
    } else {
      // DescribeUserPool failed — push minimal fallback. Don't attempt
      // ListUserPoolClients (no point without describe context); leave
      // clients_status as null to signal "not attempted".
      userPoolFindings.push({
        resource_type: 'cognito_user_pool',
        resource_id: pool.Id,
        arn: poolArn,
        pool_id: pool.Id,
        pool_name: pool.Name || null,
        region,
        describe_status: describeStatus,
        clients_status: null,
        findings: [],
      });
    }
  }

  return { userPoolFindings, clientFindings };
}

// --- User Pool Clients (list only) ---

async function listUserPoolClients(providerClient, userPoolId, logger) {
  logger.log('api_call', 'ListUserPoolClients', { userPoolId });

  const clients = [];
  let nextToken = undefined;
  do {
    const params = { UserPoolId: userPoolId, MaxResults: 60 };
    if (nextToken) params.NextToken = nextToken;
    const resp = await withRetry(() => providerClient.send(new ListUserPoolClientsCommand(params)));
    if (resp.UserPoolClients) clients.push(...resp.UserPoolClients);
    nextToken = resp.NextToken;
  } while (nextToken);

  return clients;
}

// --- Run (dependency-injectable) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const logger = opts.logger || createLogger(runDir, 'cognito');
  logger.log('info', 'Cognito_Enumeration_Start', { region });

  const identityClient = opts.clients?.cognitoIdentity ?? new CognitoIdentityClient({ region });
  const providerClient = opts.clients?.cognitoIdp ?? new CognitoIdentityProviderClient({ region });

  const tracker = new CoverageTracker();
  const findings = [];

  // Identity pools sub-domain
  findings.push(...(await enumerateIdentityPools(identityClient, region, logger, tracker)));

  // User pools + clients sub-domain
  const { userPoolFindings, clientFindings } = await enumerateUserPools(
    providerClient,
    region,
    logger,
    tracker,
  );
  findings.push(...userPoolFindings);
  findings.push(...clientFindings);

  await logger.flush();
  const status = tracker.deriveModuleStatus({
    primaryChecks: PRIMARY_CHECKS,
    requiredChecks: REQUIRED_CHECKS,
  });
  const { coverage, errors } = tracker.toEnvelopeFields();
  return { findings, status, coverage, errors };
}

if (require.main === module) {
  baseEnum({ module: 'cognito', run });
}

module.exports = { run };
```

Key changes from the original:
- Removed `partialErrors` array and `let status` (tracker owns both).
- Each sub-enum takes `tracker` as last parameter.
- `enumerateUserPoolClients` (the old name) is split: the list portion becomes a standalone `listUserPoolClients` helper (no tracker access). The per-client describe loop moves inline into `enumerateUserPools` so client tracking events happen alongside their parent pool. This is cleaner because each client's tracking event needs the parent pool context.
- New `describe_status` field on all three resource types.
- New `clients_status` field on `cognito_user_pool` findings.
- DescribeUserPool failure → minimal fallback (matching original behavior) + skip the inner client list (no client info without pool describe). `clients_status` stays `null` to signal "not attempted".

- [ ] **Step 4: Capture the new expected fixture**

Add a temporary capture print to `test/enum-cognito.test.js`. Find:

```js
    const result = await run({
      runDir: tmpDir,
      region: 'us-east-1',
      accountId: 'unknown',
      clients: { cognitoIdentity: mockCognitoIdentity, cognitoIdp: mockCognitoIdp },
    });

    assert.strictEqual(result.status, expected.status);
```

Insert between the `run({...})` call's closing `});` and the assert:

```js
    console.log('--- CAPTURE BEGIN ---');
    console.log(JSON.stringify({
      module: 'cognito',
      account_id: 'unknown',
      region: 'us-east-1',
      status: result.status,
      findings: result.findings,
    }, null, 2));
    console.log('--- CAPTURE END ---');

```

Run: `node test/enum-cognito.test.js`

The output between the capture markers is the candidate `expected.json`.

- [ ] **Step 5: Verify the captured output by eye**

Expected drift from the current `expected.json`:
- Every `cognito_identity_pool` finding gains `describe_status: 'present'` (or `'access_denied'`/`'error'` if the mock returns a failure, but for the happy-path fixture it should be `'present'`).
- Every `cognito_user_pool` finding gains `describe_status: 'present'` AND `clients_status: 'present'`.
- Every `cognito_user_pool_client` finding gains `describe_status: 'present'`.
- No other field changes.

Read the existing fixture (`test/fixtures/enum/cognito/expected.json`) first to confirm the resources present. If the captured output drifts in any field that's not one of the three new annotations, STOP — investigate before proceeding.

- [ ] **Step 6: Copy the captured output into `test/fixtures/enum/cognito/expected.json`**

Overwrite the file with the captured JSON. Preserve top-level metadata fields (`module`, `account_id`, `region`).

- [ ] **Step 7: Remove the debug capture print**

Revert the Step 4 insertion.

- [ ] **Step 8: Run the cognito test — expect green**

Run: `node test/enum-cognito.test.js`

Expected: `1 tests: 1 passed, 0 failed`.

- [ ] **Step 9: Run full suite — expect green**

Run: `node test/run-all.js`

Expected: 25 files green.

- [ ] **Step 10: Commit**

```bash
git add scripts/enum/cognito.js test/enum-cognito.test.js test/fixtures/enum/cognito/expected.json

git commit -m "feat(cognito): migrate to CoverageTracker

Cognito has two independent sub-domains: identity pools (ListIdentityPools
→ DescribeIdentityPool) and user pools (ListUserPools → DescribeUserPool
→ ListUserPoolClients → DescribeUserPoolClient). Either can fail
without invalidating the other.

- PRIMARY_CHECKS=[] — same design as ec2.js. No single sub-domain
  failure should elevate module status above 'partial'.
- REQUIRED_CHECKS=['list_identity_pools', 'describe_identity_pool',
  'list_user_pools', 'describe_user_pool', 'list_user_pool_clients',
  'describe_user_pool_client'].
- List-op failures use tracker.record({status:'failed'}) per the
  lib-bug workaround (recordModuleFailure would silently drop the
  failure since deriveModuleStatus filters required-check failures
  with !moduleWide).

Per-finding annotations added:
- cognito_identity_pool.describe_status (default null).
- cognito_user_pool.describe_status (default null).
- cognito_user_pool.clients_status (default null; tracks per-pool
  ListUserPoolClients).
- cognito_user_pool_client.describe_status (default null).

Structural changes:
- enumerateUserPoolClients (old name) split into a standalone
  listUserPoolClients helper (no tracker access) + inline per-client
  describe loop in enumerateUserPools. Each client tracking event
  now happens alongside its parent pool, simplifying coverage
  attribution.
- DescribeUserPool failure → minimal fallback finding + skip the
  inner client list (no useful client enumeration without pool
  describe context). clients_status stays null to signal 'not
  attempted'.

Local errors[] / let status removed; tracker is the source of truth."
```

No Co-Authored-By, no "Generated with Claude Code" footer.

---

## Self-review

**Spec coverage:**
- Both sub-domains classified ✓
- All four list ops and three describe ops in REQUIRED_CHECKS ✓
- Per-finding annotations on all three resource types ✓
- `clients_status` annotation on user_pool finding (load-bearing for "did we enumerate clients for this pool?") ✓
- Lib-bug workaround applied (list-op failures use `tracker.record`) ✓
- `<field>_status` defaults are `null`, never `'absent'` ✓
- Imports `{ CoverageTracker, classifyError }` from `'../lib/coverage'` ✓
- Returns `{findings, status, coverage, errors}` ✓

**Placeholder scan:** none — every step has concrete code.

**Type consistency:** all check names in tracker.record / deriveModuleStatus / test assertions match REQUIRED_CHECKS entries:
- `list_identity_pools`, `describe_identity_pool`, `list_user_pools`, `describe_user_pool`, `list_user_pool_clients`, `describe_user_pool_client` ✓

Field-name consistency:
- `describe_status` used on all three resource types ✓
- `clients_status` only on `cognito_user_pool` ✓

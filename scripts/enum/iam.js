'use strict';

const {
  IAMClient,
  GetAccountAuthorizationDetailsCommand,
  ListUsersCommand,
  ListRolesCommand,
  ListGroupsCommand,
  ListPoliciesCommand,
  ListUserPoliciesCommand,
  GetUserPolicyCommand,
  ListAttachedUserPoliciesCommand,
  ListGroupsForUserCommand,
  ListAccessKeysCommand,
  GetAccessKeyLastUsedCommand,
  ListMFADevicesCommand,
  GetLoginProfileCommand,
  GetRoleCommand,
  ListRolePoliciesCommand,
  GetRolePolicyCommand,
  ListAttachedRolePoliciesCommand,
  GetGroupCommand,
  ListAttachedGroupPoliciesCommand,
  ListGroupPoliciesCommand,
  GetGroupPolicyCommand,
  GetPolicyCommand,
  GetPolicyVersionCommand,
  GenerateCredentialReportCommand,
  GetCredentialReportCommand,
  GenerateServiceLastAccessedDetailsCommand,
  GetServiceLastAccessedDetailsCommand,
} = require('@aws-sdk/client-iam');

const { withRetry, paginate, createEnvelope, writeEnvelope, createLogger } = require('../lib');

// --- Trust Classification ---

function classifyPrincipal(principal, accountId) {
  if (principal === '*' || principal === 'arn:aws:iam::*:root') {
    return { principal, trust_type: 'wildcard', is_wildcard: true };
  }
  if (/^arn:aws:iam::\d+:root$/.test(principal)) {
    const isSameAccount = principal.includes(`:${accountId}:`);
    return { principal, trust_type: isSameAccount ? 'same-account' : 'cross-account', is_wildcard: false };
  }
  if (/\.amazonaws\.com$/.test(principal)) {
    return { principal, trust_type: 'service', is_wildcard: false };
  }
  if (/^arn:aws:iam::\d+:/.test(principal)) {
    const isSameAccount = principal.includes(`:${accountId}:`);
    return { principal, trust_type: isSameAccount ? 'same-account' : 'cross-account', is_wildcard: false };
  }
  if (/^arn:aws:iam::.*:(saml-provider|oidc-provider)\/|cognito-identity\.amazonaws\.com/.test(principal)) {
    return { principal, trust_type: 'federated', is_wildcard: false };
  }
  return { principal, trust_type: 'same-account', is_wildcard: false };
}

function normalizePrincipals(principalBlock) {
  if (typeof principalBlock === 'string') return [principalBlock];
  if (typeof principalBlock === 'object' && principalBlock !== null) {
    const results = [];
    for (const key of ['AWS', 'Service', 'Federated']) {
      const val = principalBlock[key];
      if (!val) continue;
      if (typeof val === 'string') results.push(val);
      else if (Array.isArray(val)) results.push(...val);
    }
    return results;
  }
  return [];
}

function hasConditionKey(conditions, key) {
  if (!conditions || typeof conditions !== 'object') return false;
  for (const operator of Object.values(conditions)) {
    if (operator && typeof operator === 'object' && key in operator) return true;
  }
  return false;
}

function deriveRisk(trustEntry) {
  if (trustEntry.trust_type === 'wildcard') return 'critical';
  if (trustEntry.trust_type === 'cross-account') {
    if (trustEntry.has_external_id && trustEntry.has_mfa_condition) return 'low';
    if (trustEntry.has_external_id) return 'medium';
    return 'high';
  }
  if (trustEntry.trust_type === 'federated') {
    return trustEntry.has_mfa_condition ? 'low' : 'medium';
  }
  if (trustEntry.trust_type === 'service') return 'low';
  if (trustEntry.trust_type === 'same-account') return 'low';
  return 'medium';
}

function parseTrustPolicy(trustPolicyDoc, accountId) {
  let doc;
  if (typeof trustPolicyDoc === 'string') {
    try {
      doc = JSON.parse(decodeURIComponent(trustPolicyDoc));
    } catch {
      try { doc = JSON.parse(trustPolicyDoc); } catch { return []; }
    }
  } else {
    doc = trustPolicyDoc;
  }

  const statements = Array.isArray(doc.Statement) ? doc.Statement : [];
  const trustRelationships = [];

  for (const stmt of statements) {
    if (stmt.Effect !== 'Allow') continue;
    const principals = normalizePrincipals(stmt.Principal);
    const conditions = stmt.Condition || null;
    const hasExternalId = hasConditionKey(conditions, 'sts:ExternalId');
    const hasMfa = hasConditionKey(conditions, 'aws:MultiFactorAuthPresent') ||
      hasConditionKey(conditions, 'aws:MultiFactorAuthAge');

    for (const p of principals) {
      const classified = classifyPrincipal(p, accountId);
      const entry = {
        ...classified,
        has_external_id: hasExternalId,
        has_mfa_condition: hasMfa,
      };
      entry.risk = deriveRisk(entry);
      trustRelationships.push(entry);
    }
  }

  return trustRelationships;
}

// --- Staleness ---

function computeStaleness(lastActivityDate) {
  if (!lastActivityDate) return { last_activity: null, is_stale: true, stale_days: null };
  const days = Math.floor((Date.now() - new Date(lastActivityDate).getTime()) / (1000 * 60 * 60 * 24));
  return { last_activity: lastActivityDate, is_stale: days >= 90, stale_days: days };
}

// --- CLI ---

function parseArgs(argv) {
  const args = { runDir: null, accountId: null };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--run-dir' && argv[i + 1]) {
      args.runDir = argv[++i];
    } else if (argv[i] === '--account-id' && argv[i + 1]) {
      args.accountId = argv[++i];
    } else if (argv[i] === '--help' || argv[i] === '-h') {
      console.log('Usage: node scripts/enum/iam.js --run-dir <dir> --account-id <id>');
      console.log('');
      console.log('Options:');
      console.log('  --run-dir     Path to the run output directory (required)');
      console.log('  --account-id  AWS account ID for trust classification (required)');
      console.log('  --help        Show this help message');
      process.exit(0);
    }
  }
  return args;
}

// --- GAAD Path ---

async function enumerateViaGAAD(client, accountId, logger) {
  logger.log('api_call', 'GetAccountAuthorizationDetails', { path: 'gaad' });

  const filters = ['User', 'Role', 'Group', 'LocalManagedPolicy'];
  const allUsers = [];
  const allRoles = [];
  const allGroups = [];
  const allPolicies = [];
  let marker;

  do {
    const params = { Filter: filters };
    if (marker) params.Marker = marker;

    const resp = await withRetry(() => client.send(new GetAccountAuthorizationDetailsCommand(params)));

    if (resp.UserDetailList) allUsers.push(...resp.UserDetailList);
    if (resp.RoleDetailList) allRoles.push(...resp.RoleDetailList);
    if (resp.GroupDetailList) allGroups.push(...resp.GroupDetailList);
    if (resp.Policies) allPolicies.push(...resp.Policies);

    marker = resp.IsTruncated ? resp.Marker : undefined;
  } while (marker);

  // Build user findings
  const userFindings = allUsers.map((u) => ({
    resource_type: 'iam_user',
    resource_id: u.UserName,
    arn: u.Arn,
    region: 'global',
    groups: (u.GroupList || []),
    attached_policies: (u.AttachedManagedPolicies || []).map((p) => p.PolicyArn),
    inline_policies: (u.UserPolicyList || []).map((p) => p.PolicyName),
    has_console_access: false, // enriched later
    mfa_enabled: false, // enriched later
    access_keys: [], // enriched later
    password_last_used: null, // enriched later from credential report
    has_boundary: !!u.PermissionsBoundary,
    permission_boundary_arn: u.PermissionsBoundary?.PermissionsBoundaryArn || null,
    last_activity: null,
    is_stale: true,
    stale_days: null,
    findings: [],
  }));

  // Build role findings
  const roleFindings = allRoles.map((r) => {
    const trustDoc = r.AssumeRolePolicyDocument;
    const trustRelationships = parseTrustPolicy(trustDoc, accountId);
    const isServiceLinked = (r.Path || '').startsWith('/aws-service-role/');

    return {
      resource_type: 'iam_role',
      resource_id: r.RoleName,
      arn: r.Arn,
      region: 'global',
      is_service_linked: isServiceLinked,
      trust_relationships: trustRelationships,
      attached_policies: (r.AttachedManagedPolicies || []).map((p) => p.PolicyArn),
      inline_policies: (r.RolePolicyList || []).map((p) => p.PolicyName),
      has_boundary: !!r.PermissionsBoundary,
      permission_boundary_arn: r.PermissionsBoundary?.PermissionsBoundaryArn || null,
      last_activity: r.RoleLastUsed?.LastUsedDate?.toISOString() || null,
      is_stale: true,
      stale_days: null,
      service_last_accessed: null,
      findings: [],
    };
  });

  // Compute role staleness from RoleLastUsed
  for (const role of roleFindings) {
    const staleness = computeStaleness(role.last_activity);
    Object.assign(role, staleness);
  }

  // Build group findings
  const groupFindings = allGroups.map((g) => ({
    resource_type: 'iam_group',
    resource_id: g.GroupName,
    arn: g.Arn,
    region: 'global',
    members: [], // enriched via GetGroup later
    attached_policies: (g.AttachedManagedPolicies || []).map((p) => p.PolicyArn),
    inline_policies: (g.GroupPolicyList || []).map((p) => p.PolicyName),
    findings: [],
  }));

  return { userFindings, roleFindings, groupFindings };
}

// --- Fallback Path ---

async function enumerateViaFallback(client, accountId, logger) {
  logger.log('info', 'GAAD_fallback', { reason: 'AccessDenied on GetAccountAuthorizationDetails' });

  // List users
  logger.log('api_call', 'ListUsers', { path: 'fallback' });
  const users = await paginate(client, ListUsersCommand, 'Users', {
    tokenKey: 'Marker',
    responseTokenKey: 'Marker',
  });

  // List roles
  logger.log('api_call', 'ListRoles', { path: 'fallback' });
  const roles = await paginate(client, ListRolesCommand, 'Roles', {
    tokenKey: 'Marker',
    responseTokenKey: 'Marker',
  });

  // List groups
  logger.log('api_call', 'ListGroups', { path: 'fallback' });
  const groups = await paginate(client, ListGroupsCommand, 'Groups', {
    tokenKey: 'Marker',
    responseTokenKey: 'Marker',
  });

  const errors = [];

  // Build user findings with per-user details
  const userFindings = [];
  for (const u of users) {
    try {
      const inlinePolicies = await paginate(client, ListUserPoliciesCommand, 'PolicyNames', {
        params: { UserName: u.UserName },
        tokenKey: 'Marker',
        responseTokenKey: 'Marker',
      });

      const attachedPolicies = await paginate(client, ListAttachedUserPoliciesCommand, 'AttachedPolicies', {
        params: { UserName: u.UserName },
        tokenKey: 'Marker',
        responseTokenKey: 'Marker',
      });

      const userGroups = await paginate(client, ListGroupsForUserCommand, 'Groups', {
        params: { UserName: u.UserName },
        tokenKey: 'Marker',
        responseTokenKey: 'Marker',
      });

      userFindings.push({
        resource_type: 'iam_user',
        resource_id: u.UserName,
        arn: u.Arn,
        region: 'global',
        groups: userGroups.map((g) => g.GroupName),
        attached_policies: attachedPolicies.map((p) => p.PolicyArn),
        inline_policies: inlinePolicies,
        has_console_access: false,
        mfa_enabled: false,
        access_keys: [],
        password_last_used: u.PasswordLastUsed?.toISOString() || null,
        has_boundary: !!u.PermissionsBoundary,
        permission_boundary_arn: u.PermissionsBoundary?.PermissionsBoundaryArn || null,
        last_activity: null,
        is_stale: true,
        stale_days: null,
        findings: [],
      });
    } catch (err) {
      errors.push({ resource: u.UserName, error: err.message });
      logger.log('error', 'UserDetailFetch', { user: u.UserName, error: err.message });
    }
  }

  // Build role findings with per-role details
  const roleFindings = [];
  for (const r of roles) {
    try {
      logger.log('api_call', 'GetRole', { role: r.RoleName });
      const roleResp = await withRetry(() => client.send(new GetRoleCommand({ RoleName: r.RoleName })));
      const roleDetail = roleResp.Role;

      const inlinePolicies = await paginate(client, ListRolePoliciesCommand, 'PolicyNames', {
        params: { RoleName: r.RoleName },
        tokenKey: 'Marker',
        responseTokenKey: 'Marker',
      });

      const attachedPolicies = await paginate(client, ListAttachedRolePoliciesCommand, 'AttachedPolicies', {
        params: { RoleName: r.RoleName },
        tokenKey: 'Marker',
        responseTokenKey: 'Marker',
      });

      const trustDoc = roleDetail.AssumeRolePolicyDocument;
      const trustRelationships = parseTrustPolicy(trustDoc, accountId);
      const isServiceLinked = (roleDetail.Path || '').startsWith('/aws-service-role/');
      const lastUsed = roleDetail.RoleLastUsed?.LastUsedDate?.toISOString() || null;
      const staleness = computeStaleness(lastUsed);

      roleFindings.push({
        resource_type: 'iam_role',
        resource_id: r.RoleName,
        arn: roleDetail.Arn,
        region: 'global',
        is_service_linked: isServiceLinked,
        trust_relationships: trustRelationships,
        attached_policies: attachedPolicies.map((p) => p.PolicyArn),
        inline_policies: inlinePolicies,
        has_boundary: !!roleDetail.PermissionsBoundary,
        permission_boundary_arn: roleDetail.PermissionsBoundary?.PermissionsBoundaryArn || null,
        ...staleness,
        service_last_accessed: null,
        findings: [],
      });
    } catch (err) {
      errors.push({ resource: r.RoleName, error: err.message });
      logger.log('error', 'RoleDetailFetch', { role: r.RoleName, error: err.message });
    }
  }

  // Build group findings
  const groupFindings = [];
  for (const g of groups) {
    try {
      logger.log('api_call', 'GetGroup', { group: g.GroupName });
      const groupResp = await withRetry(() => client.send(new GetGroupCommand({ GroupName: g.GroupName })));

      const attachedPolicies = await paginate(client, ListAttachedGroupPoliciesCommand, 'AttachedPolicies', {
        params: { GroupName: g.GroupName },
        tokenKey: 'Marker',
        responseTokenKey: 'Marker',
      });

      const inlinePolicies = await paginate(client, ListGroupPoliciesCommand, 'PolicyNames', {
        params: { GroupName: g.GroupName },
        tokenKey: 'Marker',
        responseTokenKey: 'Marker',
      });

      groupFindings.push({
        resource_type: 'iam_group',
        resource_id: g.GroupName,
        arn: g.Arn,
        region: 'global',
        members: (groupResp.Users || []).map((u) => u.UserName),
        attached_policies: attachedPolicies.map((p) => p.PolicyArn),
        inline_policies: inlinePolicies,
        findings: [],
      });
    } catch (err) {
      errors.push({ resource: g.GroupName, error: err.message });
      logger.log('error', 'GroupDetailFetch', { group: g.GroupName, error: err.message });
    }
  }

  return { userFindings, roleFindings, groupFindings, errors };
}

// --- Staleness Enrichment ---

async function enrichStaleness(client, userFindings, roleFindings, logger) {
  const errors = [];

  // 1. Credential report (bulk)
  let credentialReportMap = null;
  try {
    logger.log('api_call', 'GenerateCredentialReport', {});
    let reportReady = false;
    for (let attempt = 0; attempt < 10; attempt++) {
      const genResp = await withRetry(() => client.send(new GenerateCredentialReportCommand({})));
      if (genResp.State === 'COMPLETE') {
        reportReady = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 2000));
    }

    if (reportReady) {
      logger.log('api_call', 'GetCredentialReport', {});
      const reportResp = await withRetry(() => client.send(new GetCredentialReportCommand({})));
      const csvContent = Buffer.from(reportResp.Content).toString('utf8');
      credentialReportMap = parseCredentialReport(csvContent);
    } else {
      logger.log('warning', 'CredentialReportTimeout', { message: 'Report not ready after polling' });
    }
  } catch (err) {
    errors.push({ resource: 'credential_report', error: err.message });
    logger.log('warning', 'CredentialReportFailed', { error: err.message });
  }

  // 2. Per-user enrichment: access keys, MFA, login profile, staleness
  for (const user of userFindings) {
    try {
      // Access keys
      logger.log('api_call', 'ListAccessKeys', { user: user.resource_id });
      const keys = await paginate(client, ListAccessKeysCommand, 'AccessKeyMetadata', {
        params: { UserName: user.resource_id },
        tokenKey: 'Marker',
        responseTokenKey: 'Marker',
      });

      const accessKeys = [];
      for (const key of keys) {
        try {
          const lastUsedResp = await withRetry(() =>
            client.send(new GetAccessKeyLastUsedCommand({ AccessKeyId: key.AccessKeyId }))
          );
          const lastUsed = lastUsedResp.AccessKeyLastUsed?.LastUsedDate?.toISOString() || null;
          accessKeys.push({
            key_id: key.AccessKeyId,
            status: key.Status,
            last_used: lastUsed,
          });
        } catch (err) {
          accessKeys.push({ key_id: key.AccessKeyId, status: key.Status, last_used: null });
          logger.log('warning', 'GetAccessKeyLastUsed', { key: key.AccessKeyId, error: err.message });
        }
      }
      user.access_keys = accessKeys;

      // MFA devices
      try {
        logger.log('api_call', 'ListMFADevices', { user: user.resource_id });
        const mfaDevices = await paginate(client, ListMFADevicesCommand, 'MFADevices', {
          params: { UserName: user.resource_id },
          tokenKey: 'Marker',
          responseTokenKey: 'Marker',
        });
        user.mfa_enabled = mfaDevices.length > 0;
      } catch (err) {
        logger.log('warning', 'ListMFADevices', { user: user.resource_id, error: err.message });
      }

      // Login profile (console access)
      try {
        await withRetry(() => client.send(new GetLoginProfileCommand({ UserName: user.resource_id })));
        user.has_console_access = true;
      } catch (err) {
        if (err.name === 'NoSuchEntityException' || err.name === 'NoSuchEntity') {
          user.has_console_access = false;
        } else {
          logger.log('warning', 'GetLoginProfile', { user: user.resource_id, error: err.message });
        }
      }

      // Merge credential report data
      if (credentialReportMap && credentialReportMap.has(user.resource_id)) {
        const cred = credentialReportMap.get(user.resource_id);
        if (cred.password_last_used && cred.password_last_used !== 'N/A' && cred.password_last_used !== 'no_information') {
          user.password_last_used = cred.password_last_used;
        }
        if (cred.mfa_active === 'true') {
          user.mfa_enabled = true;
        }
      }

      // Compute user staleness: max of password_last_used and any key last_used
      const activityDates = [];
      if (user.password_last_used) activityDates.push(user.password_last_used);
      for (const k of user.access_keys) {
        if (k.last_used) activityDates.push(k.last_used);
      }
      const latestActivity = activityDates.length > 0
        ? activityDates.sort().reverse()[0]
        : null;
      const staleness = computeStaleness(latestActivity);
      Object.assign(user, staleness);

    } catch (err) {
      errors.push({ resource: user.resource_id, error: err.message });
      logger.log('error', 'UserStalenessEnrichment', { user: user.resource_id, error: err.message });
    }
  }

  // 3. ServiceLastAccessed for stale principals only
  const stalePrincipals = [
    ...userFindings.filter((u) => u.is_stale).map((u) => ({ type: 'user', arn: u.arn, finding: u })),
    ...roleFindings.filter((r) => r.is_stale).map((r) => ({ type: 'role', arn: r.arn, finding: r })),
  ];

  for (const { type, arn, finding } of stalePrincipals) {
    try {
      logger.log('api_call', 'GenerateServiceLastAccessedDetails', { arn });
      const genResp = await withRetry(() =>
        client.send(new GenerateServiceLastAccessedDetailsCommand({ Arn: arn }))
      );
      const jobId = genResp.JobId;

      // Poll for completion
      let serviceData = null;
      for (let attempt = 0; attempt < 15; attempt++) {
        const statusResp = await withRetry(() =>
          client.send(new GetServiceLastAccessedDetailsCommand({ JobId: jobId }))
        );
        if (statusResp.JobStatus === 'COMPLETED') {
          serviceData = (statusResp.ServicesLastAccessed || []).map((s) => ({
            service_name: s.ServiceName,
            service_namespace: s.ServiceNamespace,
            last_authenticated: s.LastAuthenticated?.toISOString() || null,
            total_entities: s.TotalAuthenticatedEntities || 0,
          }));
          break;
        }
        if (statusResp.JobStatus === 'FAILED') {
          logger.log('warning', 'ServiceLastAccessedFailed', { arn, status: 'FAILED' });
          break;
        }
        await new Promise((r) => setTimeout(r, 1000));
      }

      finding.service_last_accessed = serviceData;
    } catch (err) {
      finding.service_last_accessed = null;
      errors.push({ resource: arn, error: err.message });
      logger.log('warning', 'ServiceLastAccessed', { arn, error: err.message });
    }
  }

  return errors;
}

// --- Credential Report Parser ---

function parseCredentialReport(csv) {
  const lines = csv.trim().split('\n');
  if (lines.length < 2) return new Map();

  const headers = lines[0].split(',');
  const userIdx = headers.indexOf('user');
  const pwdLastUsedIdx = headers.indexOf('password_last_used');
  const mfaIdx = headers.indexOf('mfa_active');
  const key1LastUsedIdx = headers.indexOf('access_key_1_last_used_date');
  const key2LastUsedIdx = headers.indexOf('access_key_2_last_used_date');

  const map = new Map();
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(',');
    const userName = cols[userIdx];
    if (!userName || userName === '<root_account>') continue;

    map.set(userName, {
      password_last_used: normalizeDate(cols[pwdLastUsedIdx]),
      mfa_active: cols[mfaIdx] || 'false',
      access_key_1_last_used: normalizeDate(cols[key1LastUsedIdx]),
      access_key_2_last_used: normalizeDate(cols[key2LastUsedIdx]),
    });
  }
  return map;
}

function normalizeDate(val) {
  if (!val || val === 'N/A' || val === 'no_information' || val === 'not_supported') return null;
  return val;
}

// --- Group member enrichment ---

async function enrichGroupMembers(client, groupFindings, logger) {
  for (const group of groupFindings) {
    try {
      logger.log('api_call', 'GetGroup', { group: group.resource_id });
      const resp = await withRetry(() => client.send(new GetGroupCommand({ GroupName: group.resource_id })));
      group.members = (resp.Users || []).map((u) => u.UserName);
    } catch (err) {
      logger.log('warning', 'GetGroupMembers', { group: group.resource_id, error: err.message });
    }
  }
}

// --- Run (DI-injectable) ---

async function run(opts = {}) {
  const { runDir, accountId } = opts;
  const client = opts.clients && opts.clients.iam ? opts.clients.iam : new IAMClient({});

  const logger = createLogger(runDir);
  logger.log('info', 'IAM_Enumeration_Start', { accountId });

  let userFindings = [];
  let roleFindings = [];
  let groupFindings = [];
  let status = 'complete';
  let partialErrors = [];

  // Attempt GAAD path first
  try {
    const gaadResult = await enumerateViaGAAD(client, accountId, logger);
    userFindings = gaadResult.userFindings;
    roleFindings = gaadResult.roleFindings;
    groupFindings = gaadResult.groupFindings;

    // GAAD groups don't include members — enrich
    await enrichGroupMembers(client, groupFindings, logger);
  } catch (err) {
    const code = err.name || err.Code || '';
    if (code === 'AccessDeniedException' || code === 'AccessDenied' || code === 'UnauthorizedAccess') {
      // Fallback to per-resource enumeration
      try {
        const fallbackResult = await enumerateViaFallback(client, accountId, logger);
        userFindings = fallbackResult.userFindings;
        roleFindings = fallbackResult.roleFindings;
        groupFindings = fallbackResult.groupFindings;
        if (fallbackResult.errors && fallbackResult.errors.length > 0) {
          partialErrors.push(...fallbackResult.errors);
          status = 'partial';
        }
      } catch (fallbackErr) {
        logger.log('error', 'FallbackFailed', { error: fallbackErr.message });
        status = 'error';
        const envelope = createEnvelope({
          module: 'iam',
          account_id: accountId,
          region: 'global',
          status: 'error',
          findings: [],
        });
        writeEnvelope(runDir, envelope);
        await logger.flush();
        return;
      }
    } else {
      // Unexpected error
      logger.log('error', 'GAAD_UnexpectedError', { error: err.message });
      status = 'error';
      const envelope = createEnvelope({
        module: 'iam',
        account_id: accountId,
        region: 'global',
        status: 'error',
        findings: [],
      });
      writeEnvelope(runDir, envelope);
      await logger.flush();
      return;
    }
  }

  // Enrich staleness
  try {
    const stalenessErrors = await enrichStaleness(client, userFindings, roleFindings, logger);
    if (stalenessErrors.length > 0) {
      partialErrors.push(...stalenessErrors);
      if (status === 'complete') status = 'partial';
    }
  } catch (err) {
    logger.log('warning', 'StalenessEnrichmentFailed', { error: err.message });
    if (status === 'complete') status = 'partial';
  }

  // Set final status
  if (partialErrors.length > 0 && status === 'complete') {
    status = 'partial';
  }

  // Build and write envelope
  const findings = [...userFindings, ...roleFindings, ...groupFindings];
  const envelope = createEnvelope({
    module: 'iam',
    account_id: accountId,
    region: 'global',
    status,
    findings,
  });

  const outputPath = writeEnvelope(runDir, envelope);
  logger.log('info', 'IAM_Enumeration_Complete', {
    status,
    users: userFindings.length,
    roles: roleFindings.length,
    groups: groupFindings.length,
    errors: partialErrors.length,
    output: outputPath,
  });

  await logger.flush();
}

// --- Main (CLI entrypoint) ---

async function main() {
  const args = parseArgs(process.argv);
  if (!args.runDir || !args.accountId) {
    console.error('Error: --run-dir and --account-id are required');
    console.error('Usage: node scripts/enum/iam.js --run-dir <dir> --account-id <id>');
    process.exit(1);
  }
  try {
    await run({ runDir: args.runDir, accountId: args.accountId });
    process.exit(0);
  } catch (err) {
    console.error(`Fatal error: ${err.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}
module.exports = { run };

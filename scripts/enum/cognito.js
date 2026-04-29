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

// --- Identity Pools (CognitoIdentityClient) ---

async function enumerateIdentityPools(client, region, logger) {
  logger.log('api_call', 'ListIdentityPools', {});

  const pools = [];
  let nextToken = undefined;

  do {
    const params = { MaxResults: 60 };
    if (nextToken) params.NextToken = nextToken;

    const resp = await withRetry(() => client.send(new ListIdentityPoolsCommand(params)));
    if (resp.IdentityPools) pools.push(...resp.IdentityPools);
    nextToken = resp.NextToken;
  } while (nextToken);

  const findings = [];
  for (const pool of pools) {
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

      // Extract role ARNs from CognitoIdentityRoles if available
      const roles = detail.Roles || {};

      findings.push({
        resource_type: 'cognito_identity_pool',
        resource_id: detail.IdentityPoolName || pool.IdentityPoolId,
        arn: `arn:aws:cognito-identity:${region}:unknown:identitypool/${pool.IdentityPoolId}`,
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
        findings: poolFindings,
      });
    } catch (err) {
      logger.log('warning', 'DescribeIdentityPool', { poolId: pool.IdentityPoolId, error: err.message });
      findings.push({
        resource_type: 'cognito_identity_pool',
        resource_id: pool.IdentityPoolId,
        arn: `arn:aws:cognito-identity:${region}:unknown:identitypool/${pool.IdentityPoolId}`,
        pool_id: pool.IdentityPoolId,
        pool_name: pool.IdentityPoolName || null,
        region,
        allow_unauthenticated: null,
        findings: [],
      });
    }
  }

  return findings;
}

// --- User Pools (CognitoIdentityProviderClient) ---

async function enumerateUserPools(providerClient, region, logger) {
  logger.log('api_call', 'ListUserPools', {});

  const pools = [];
  let nextToken = undefined;

  do {
    const params = { MaxResults: 60 };
    if (nextToken) params.NextToken = nextToken;

    const resp = await withRetry(() => providerClient.send(new ListUserPoolsCommand(params)));
    if (resp.UserPools) pools.push(...resp.UserPools);
    nextToken = resp.NextToken;
  } while (nextToken);

  const userPoolFindings = [];
  const clientFindings = [];

  for (const pool of pools) {
    try {
      logger.log('api_call', 'DescribeUserPool', { userPoolId: pool.Id });
      const resp = await withRetry(() =>
        providerClient.send(new DescribeUserPoolCommand({ UserPoolId: pool.Id }))
      );
      const detail = resp.UserPool || {};

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

      userPoolFindings.push({
        resource_type: 'cognito_user_pool',
        resource_id: detail.Name || pool.Id,
        arn: detail.Arn || `arn:aws:cognito-idp:${region}:unknown:userpool/${pool.Id}`,
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
        findings: poolFindings,
      });

      // Enumerate clients for this user pool
      try {
        const clients = await enumerateUserPoolClients(providerClient, pool.Id, region, logger);
        clientFindings.push(...clients);
      } catch (err) {
        logger.log('warning', 'UserPoolClients', { userPoolId: pool.Id, error: err.message });
      }

    } catch (err) {
      logger.log('warning', 'DescribeUserPool', { userPoolId: pool.Id, error: err.message });
      userPoolFindings.push({
        resource_type: 'cognito_user_pool',
        resource_id: pool.Id,
        arn: `arn:aws:cognito-idp:${region}:unknown:userpool/${pool.Id}`,
        pool_id: pool.Id,
        pool_name: pool.Name || null,
        region,
        findings: [],
      });
    }
  }

  return { userPoolFindings, clientFindings };
}

// --- User Pool Clients ---

async function enumerateUserPoolClients(providerClient, userPoolId, region, logger) {
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

  const findings = [];
  for (const c of clients) {
    try {
      logger.log('api_call', 'DescribeUserPoolClient', { clientId: c.ClientId });
      const resp = await withRetry(() =>
        providerClient.send(
          new DescribeUserPoolClientCommand({ UserPoolId: userPoolId, ClientId: c.ClientId })
        )
      );
      const detail = resp.UserPoolClient || {};

      const clientFindings = [];
      const oauthFlows = detail.AllowedOAuthFlows || [];
      if (oauthFlows.includes('implicit')) {
        clientFindings.push('Implicit OAuth flow enabled — tokens exposed in URL fragment');
      }

      findings.push({
        resource_type: 'cognito_user_pool_client',
        resource_id: detail.ClientName || c.ClientId,
        arn: `arn:aws:cognito-idp:${region}:unknown:userpool/${userPoolId}/client/${c.ClientId}`,
        client_id: c.ClientId,
        client_name: detail.ClientName || null,
        user_pool_id: userPoolId,
        region,
        allowed_oauth_flows: oauthFlows,
        allowed_oauth_flows_user_pool_client: detail.AllowedOAuthFlowsUserPoolClient || false,
        allowed_oauth_scopes: detail.AllowedOAuthScopes || [],
        callback_urls: detail.CallbackURLs || [],
        logout_urls: detail.LogoutURLs || [],
        explicit_auth_flows: detail.ExplicitAuthFlows || [],
        token_validity: {
          access_token: detail.AccessTokenValidity || null,
          id_token: detail.IdTokenValidity || null,
          refresh_token: detail.RefreshTokenValidity || null,
        },
        prevent_user_existence_errors: detail.PreventUserExistenceErrors || null,
        findings: clientFindings,
      });
    } catch (err) {
      logger.log('warning', 'DescribeUserPoolClient', { clientId: c.ClientId, error: err.message });
      findings.push({
        resource_type: 'cognito_user_pool_client',
        resource_id: c.ClientId,
        arn: `arn:aws:cognito-idp:${region}:unknown:userpool/${userPoolId}/client/${c.ClientId}`,
        client_id: c.ClientId,
        user_pool_id: userPoolId,
        region,
        findings: [],
      });
    }
  }

  return findings;
}

// --- Run (exported for testing) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const logger = opts.logger || createLogger(runDir, 'cognito');
  logger.log('info', 'Cognito_Enumeration_Start', { region });

  const identityClient = opts.clients?.cognitoIdentity ?? new CognitoIdentityClient({ region });
  const providerClient = opts.clients?.cognitoIdp ?? new CognitoIdentityProviderClient({ region });

  let findings = [];
  let status = 'complete';
  const partialErrors = [];

  // Identity pools
  try {
    const identityPoolFindings = await enumerateIdentityPools(identityClient, region, logger);
    findings.push(...identityPoolFindings);
  } catch (err) {
    partialErrors.push({ resource: 'identity_pools', error: err.message });
    logger.log('warning', 'IdentityPools', { error: err.message });
  }

  // User pools + clients
  try {
    const { userPoolFindings, clientFindings } = await enumerateUserPools(
      providerClient,
      region,
      logger
    );
    findings.push(...userPoolFindings);
    findings.push(...clientFindings);
  } catch (err) {
    partialErrors.push({ resource: 'user_pools', error: err.message });
    logger.log('warning', 'UserPools', { error: err.message });
  }

  if (partialErrors.length > 0) {
    status = 'partial';
  }

  await logger.flush();
  return { findings, status };
}

if (require.main === module) {
  baseEnum({ module: 'cognito', run });
}

module.exports = { run };

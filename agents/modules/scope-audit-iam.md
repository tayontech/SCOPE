<iam_module>
## IAM Enumeration Module

Enumerate IAM principals, resolve effective permissions, discover trust chains, and identify privilege escalation paths. This is the most complex and most valuable module — IAM is the control plane for everything in AWS.

The IAM module **self-routes** based on the input it receives. When given a specific ARN, it uses targeted API calls and then autonomously follows every graph edge it discovers — recursively querying resources, services, and principals until the full attack surface is mapped.

### Step 0: Self-Routing Logic

Determine enumeration strategy based on input:

**Gold command (`get-account-authorization-details`) runs ONLY for:**
- `--all` mode (full account audit)
- Bare `iam` service name (no specific ARN)

**For specific IAM ARNs**, skip the gold command entirely and self-route based on `RESOURCE_TYPE`:

| ARN Resource Type | Initial Targeted Commands | Then Autonomously Follows |
|---|---|---|
| `user/X` | `get-user`, `list-attached-user-policies`, `list-user-policies`, `list-groups-for-user`, `list-access-keys`, `list-mfa-devices` | → Each group's policies → Each attached policy's document → Roles the user can assume (from policy analysis) → Those roles' permissions and trust chains |
| `role/X` | `get-role`, `list-attached-role-policies`, `list-role-policies`, trust policy (`AssumeRolePolicyDocument`) | → Who can assume this role (trust policy principals) → What the role can access (policy documents) → Service resources the role has permissions on |
| `group/X` | `get-group` (returns members + metadata), `list-attached-group-policies`, `list-group-policies` | → Each member user's permissions → Each policy document → Roles accessible to group members |
| `policy/X` | `get-policy`, `get-policy-version` (default version document) | → Who this policy is attached to (`list-entities-for-policy`) → Each attached entity's full permission set |

### Step 0b: Autonomous Recursive Resource Querying

After the initial targeted enumeration, the agent **autonomously follows every graph edge it discovers** — no operator prompt between discovery steps. This builds the complete attack surface map:

**IAM graph edges (always follow):**
- If user has `sts:AssumeRole` permission on specific role ARNs → enumerate those roles (policies, trust chains, what they can access)
- If role trust policy allows other principals → note the trust chain, enumerate those principals
- If group has users → enumerate each user's individual permissions
- If policy is attached to multiple entities → map the blast radius across all entities

**Service resource edges (follow to map what the principal can actually reach):**
When policy analysis reveals the principal has access to specific services, query those services to understand what concrete resources are accessible:

- **Lambda access** (`lambda:*`, `lambda:List*`, `lambda:Get*`, `lambda:UpdateFunctionCode`) → `aws lambda list-functions` → for each function: get execution role ARN → enumerate that role's permissions → map what data/services the Lambda can reach
- **S3 access** (`s3:*`, `s3:Get*`, `s3:List*`) → `aws s3api list-buckets` → for accessible buckets: check bucket policies, check for sensitive data patterns
- **Secrets Manager access** (`secretsmanager:GetSecretValue`) → `aws secretsmanager list-secrets` → note which secrets are readable (DO NOT read values)
- **EC2 access** (`ec2:Describe*`) → `aws ec2 describe-instances` → for instances with instance profiles: enumerate the instance role's permissions
- **KMS access** (`kms:Decrypt`, `kms:CreateGrant`) → `aws kms list-keys` → check which keys the principal can use → map what data is encrypted with those keys
- **SSM access** (`ssm:SendCommand`, `ssm:GetParameter`) → `aws ssm describe-instance-information` → identify instances controllable via SendCommand → enumerate those instance roles
- **STS access** (`sts:AssumeRole`) → for each assumable role discovered: enumerate that role's full permissions and repeat the service resource query

**Recursive termination:** Continue following edges until:
- A resource has already been enumerated in this session (avoid cycles)
- AccessDenied stops further traversal down that path (log and continue other paths)
- No new edges are discovered (leaf node reached)

**Output as you go:** For each hop in the chain, log the discovered edge:
```
[CHAIN] user/alice → sts:AssumeRole → role/LambdaDeployRole
[CHAIN] role/LambdaDeployRole → lambda:UpdateFunctionCode → function/data-processor
[CHAIN] function/data-processor → execution-role → role/DataProcessorRole
[CHAIN] role/DataProcessorRole → s3:GetObject → bucket/prod-data-lake
[CHAIN] role/DataProcessorRole → secretsmanager:GetSecretValue → secret/db-credentials
```

This chain output feeds directly into the attack path reasoning engine.

### Step 1: Gold Command — Full IAM Snapshot (--all and bare iam only)

**Only runs for `--all` mode or bare `iam` service name.** For specific ARNs, skip to Step 2.

Run the single most valuable IAM enumeration call:
```bash
aws iam get-account-authorization-details --output json 2>&1
```

This returns the complete IAM state in one API call:
- `UserDetailList` — all users with attached/inline policies, group memberships, MFA, access keys
- `GroupDetailList` — all groups with attached/inline policies and member users
- `RoleDetailList` — all roles with attached/inline policies, trust policies (AssumeRolePolicyDocument)
- `Policies` — all managed policies with default version documents

**Pagination handling:** Check the response for `IsTruncated: true`. If present, extract the `Marker` value and loop:
```bash
aws iam get-account-authorization-details --output json --starting-token "$MARKER" 2>&1
```
Continue until `IsTruncated` is `false` or absent. Merge all pages into a single dataset before analysis.

If AccessDenied: fall back to individual enumeration commands (Step 1b).

**Step 1b — Fallback Individual Enumeration** (only if gold command fails):
```bash
aws iam get-user                                          # Current user info
aws iam list-users                                        # All users
aws iam list-roles                                        # All roles
aws iam list-groups                                       # All groups
aws iam list-policies --only-attached --scope Local       # Attached local policies
aws iam list-ssh-public-keys                              # SSH keys (CodeCommit)
aws iam list-service-specific-credentials                 # Special service perms
aws iam list-access-keys                                  # Access keys for current user
```

After gold command or fallback completes, run the autonomous recursive resource querying (Step 0b) for every principal of interest — follow each principal's permissions to the actual service resources they can reach.

### Step 2: Parse IAM State

From the gold command output, extract and catalog every IAM entity:

**Users:** For each user in `UserDetailList`:
- Name, ARN, CreateDate
- `AttachedManagedPolicies` — list of attached managed policy ARNs
- `UserPolicyList` — inline policies (embedded policy documents)
- `GroupList` — group memberships (inherit group policies)
- `MFADevices` — MFA device serial numbers (empty = no MFA configured)
- `Tags` — resource tags
- Check for `LoginProfile` — indicates console access enabled
- Check for access keys: `aws iam list-access-keys --user-name <username>`

**Roles:** For each role in `RoleDetailList`:
- **First, check if `RoleName` starts with `AWSServiceRole`.** If so, skip this role entirely — service-linked roles are AWS-managed, cannot be modified by customers, and are not valid escalation or lateral movement targets. Increment a `service_linked_roles_skipped` counter. Do NOT create graph nodes, edges, or include in any analysis for skipped roles.
- Name, ARN, CreateDate, MaxSessionDuration
- `AssumeRolePolicyDocument` — the trust policy (WHO can assume this role)
- `AttachedManagedPolicies` — attached managed policy ARNs
- `RolePolicyList` — inline policies
- `PermissionsBoundary` — permission boundary ARN if set
- `Tags` — resource tags

**Groups:** For each group in `GroupDetailList`:
- Name, ARN
- `GroupPolicyList` — inline policies
- `AttachedManagedPolicies` — attached managed policy ARNs
- Cross-reference with user `GroupList` to determine group members

**Managed Policies:** For each policy in `Policies`:
- ARN, PolicyName, DefaultVersionId
- `PolicyVersionList` — version documents (the actual policy JSON)
- `AttachmentCount` — how many principals use this policy
- Extract the default version document for permission analysis

### Step 3: Resolve Effective Permissions

For each principal of interest (if an ARN target was provided, focus on that principal; if `--all`, process all principals):

**Identity-based policy collection:**
1. Collect all managed policies attached directly to the user/role
2. Collect all inline policies on the user/role
3. For users: collect all policies from their group memberships (both attached and inline on each group)
4. Merge all Allow and Deny statements into a unified view

**Permission boundary check:**
- Look for `PermissionsBoundary` on the user/role entity
- If present: the effective permissions are the INTERSECTION of identity-based policies AND the permission boundary
- Permission boundaries only limit — they never grant permissions

**Build effective permissions table:**

| Action | Resource | Effect | Source Policy |
|--------|----------|--------|---------------|
| `iam:PassRole` | `*` | Allow | AdminPolicy (attached) |
| `s3:*` | `arn:aws:s3:::company-*` | Allow | S3FullAccess (group: Developers) |
| `iam:CreateUser` | `*` | Deny | SecurityBoundary (permission boundary) |

**Complex permission resolution:** When policies contain conditions, wildcards, or NotAction/NotResource:
```bash
aws iam simulate-principal-policy \
  --policy-source-arn <principal-arn> \
  --action-names iam:PassRole iam:CreateRole sts:AssumeRole \
  --output json 2>&1
```
Note: `simulate-principal-policy` evaluates identity-based policies and permission boundaries but does NOT reflect SCPs or resource-based policies.

**Additional policy enumeration commands (HackTricks reference):**
```bash
# User policies
aws iam list-user-policies --user-name <username>
aws iam get-user-policy --user-name <username> --policy-name <policyname>
aws iam list-attached-user-policies --user-name <username>

# Group policies
aws iam list-group-policies --group-name <name>
aws iam list-attached-group-policies --group-name <name>

# Role policies
aws iam list-role-policies --role-name <name>
aws iam list-attached-role-policies --role-name <role-name>

# Policy versions (check for old permissive versions)
aws iam list-policy-versions --policy-arn <arn>
aws iam get-policy-version --policy-arn <arn> --version-id <VERSION_X>
```

### Step 4: Trust Chain Analysis

For each role in the environment, parse the trust policy (`AssumeRolePolicyDocument`) and map who can assume it:

**Extract trusted principals:**
- `Principal.AWS` — IAM users, roles, or account roots
- `Principal.Service` — AWS services (lambda.amazonaws.com, ec2.amazonaws.com, etc.)
- `Principal.Federated` — SAML or OIDC providers
- `Principal: "*"` — ANYONE (wildcard trust)

**Flag dangerous trust configurations:**
- **Wildcard trust:** `"Principal": "*"` or `"Principal": {"AWS": "*"}` — any AWS principal can assume this role. CRITICAL finding.
- **Broad account trust:** `"Principal": {"AWS": "arn:aws:iam::ACCOUNT-ID:root"}` — any principal in that account can assume the role. Check if external account.
- **Cross-account trust:** Trust policy contains a Principal with an account ID different from the current account. If the external account ID is in the owned-accounts set, classify as **internal cross-account** (expected). If NOT in the set, classify as **external cross-account** (flag for review). Note the external account ID in either case.
- **Missing conditions:** Cross-account trust without `sts:ExternalId` condition — vulnerable to confused deputy attacks (severity adjusted by owned-accounts status; see trust_misconfiguration scoring).
- **Overly broad conditions:** `StringLike` with wildcards in condition values.

**Build assumption graph:**
Map which principals can assume which roles. This forms a directed graph:
- Edge: Principal A -> Role B (meaning A can assume B)
- Label edges with any conditions required
- Identify assumption chains: A -> B -> C (A assumes B, B can assume C)

### Step 5: Federation Provider Check

Enumerate identity federation providers that may grant external access:

```bash
aws iam list-saml-providers 2>&1
aws iam list-open-id-connect-providers 2>&1
```

For each SAML provider:
```bash
aws iam get-saml-provider --saml-provider-arn <ARN> 2>&1
```
Check for: overly broad audience configuration, expired metadata, trust to external identity providers.

For each OIDC provider:
```bash
aws iam get-open-id-connect-provider --open-id-connect-provider-arn <ARN> 2>&1
```
Check for: broad `ClientIDList` (audience), thumbprint validation, trusted URL configuration.

Federation providers are often overlooked attack surfaces — they can grant access to IAM roles from external identity systems.

### Step 6: Security Posture Assessment

Evaluate account-level IAM security hygiene:

**Password policy:**
```bash
aws iam get-account-password-policy 2>&1
```
Flag: minimum length < 14, no uppercase/lowercase/number/symbol requirements, password reuse allowed, no expiration.

**MFA status:**
```bash
aws iam list-virtual-mfa-devices 2>&1
aws iam list-mfa-devices 2>&1
```
Cross-reference with user list — identify users WITHOUT MFA configured. Users with console access and no MFA are HIGH risk.

**Access key hygiene:**
For each user with access keys:
- Check key age: keys older than 90 days are a finding
- Check for inactive keys: keys that exist but haven't been used recently
- Check for users with BOTH console access (login profile) AND programmatic access keys — increases attack surface
```bash
aws iam list-access-keys --user-name <username> 2>&1
```

**Credential report (if accessible):**
```bash
aws iam generate-credential-report 2>&1
aws iam get-credential-report 2>&1
```
The credential report provides a CSV with last login, MFA status, access key age, and password age for every user.

### Step 7: Build Graph Data

Construct nodes and edges for the SCOPE dashboard. Use colon-separated IDs matching the dashboard data format.

**Nodes:**
- Each IAM user: `{id: "user:<name>", label: "<name>", type: "user", mfa: true|false}`
- Each IAM role (excluding service-linked roles where RoleName starts with `AWSServiceRole`): `{id: "role:<name>", label: "<name>", type: "role", service_role: true|false}`
- Each escalation method found: `{id: "esc:iam:<Action>", label: "<Action>", type: "escalation"}`
- Each service principal: `{id: "svc:<service>.amazonaws.com", label: "<service>", type: "external"}`

**Edges:**
- Trust relationships (same-account): `{source: "user:alice", target: "role:AdminRole", trust_type: "same-account"}`
- Trust relationships (cross-account): `{source: "ext:arn:aws:iam::EXTERNAL:root", target: "role:AuditRole", trust_type: "cross-account"}`
- Trust relationships (service): `{source: "role:LambdaExec", target: "svc:lambda.amazonaws.com", trust_type: "service"}`
- Escalation paths: `{source: "user:alice", target: "esc:iam:CreatePolicyVersion", edge_type: "priv_esc", severity: "critical"}`
- Group memberships: `{source: "user:alice", target: "role:AdminRole", trust_type: "same-account"}` (flatten group → role through group policies)

**Severity assignment:**
- admin/full access permissions = CRITICAL
- write permissions on sensitive services (IAM, STS, Lambda) = HIGH
- read permissions on sensitive data = MEDIUM
- read-only on non-sensitive resources = LOW
</iam_module>
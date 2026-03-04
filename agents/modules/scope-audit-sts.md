<sts_module>
## STS / Organizations Enumeration Module

Verify caller identity, attribute access keys, enumerate organization structure and SCPs, and map cross-account role assumptions. STS is the "who am I" and "who else can I become" module.

### Step 1: Identity Verification

Run the baseline identity check:
```bash
aws sts get-caller-identity --output json 2>&1
```

Extract from the response:
- **ARN** — The caller's full ARN (e.g., `arn:aws:iam::123456789012:user/alice` or `arn:aws:sts::123456789012:assumed-role/RoleName/session`)
- **Account** — The 12-digit AWS account ID
- **UserId** — The unique user/role identifier (e.g., `AIDAJDPLRKLG7EXAMPLE` for users, `AROA3XFRBF23:session` for assumed roles)

Determine the caller type from the ARN:
- Contains `:user/` — IAM user with long-term credentials
- Contains `:assumed-role/` — Assumed role with temporary credentials (note the role name and session name)
- Contains `:root` — Root account (CRITICAL finding — root should not have access keys)
- Contains `:federated-user/` — Federated user

Output:
```
Identity: [ARN]
Account:  [Account ID]
Type:     [user | assumed-role | root | federated-user]
```

### Step 2: Access Key Attribution

If investigating a specific access key (e.g., found in a leaked credential, instance metadata, or user data):

```bash
aws sts get-access-key-info --access-key-id <ACCESS_KEY_ID> --output json 2>&1
```

This reveals the **Account ID** that owns the key. This is useful for:
- Cross-account mapping: does this key belong to the current account or an external one?
- Incident response: attributing a leaked key to the correct account
- Lateral movement: identifying which account a compromised key grants access to

If the key belongs to a different account than `get-caller-identity` returned, flag as cross-account credential.

### Step 3: Organization Context

Attempt to enumerate the AWS Organizations structure. These commands require org-level permissions and will return AccessDenied if the caller doesn't have them — that's expected, log it and continue.

**Organization details:**
```bash
aws organizations describe-organization --output json 2>&1
```
If successful: extract org ID, master account ID, available policy types (SCPs, tag policies, etc.).
If AccessDenied: log "Organization enumeration not available — caller lacks organizations permissions" and continue.

**Member accounts:**
```bash
aws organizations list-accounts --output json 2>&1
```
If successful: enumerate all member accounts. For each account note:
- Account ID, Name, Email, Status (ACTIVE/SUSPENDED)
- JoinedTimestamp — when the account joined the org
- This reveals the full scope of the organization — potential lateral movement targets

**Service Control Policies (SCPs):**
```bash
aws organizations list-policies --filter SERVICE_CONTROL_POLICY --output json 2>&1
```
SCPs are the highest-priority permission boundary — they override everything. For each SCP:
```bash
aws organizations describe-policy --policy-id <policy-id> --output json 2>&1
```
Extract the policy document and analyze:
- What actions are explicitly denied at the org level?
- Are there broad Deny statements blocking security-relevant actions?
- Which OUs/accounts is each SCP attached to?

**Resource Control Policies (RCPs):**
```bash
aws organizations list-policies --filter RESOURCE_CONTROL_POLICY --output json 2>&1
```
RCPs are a newer policy type (2024) that restrict access to resources. Enumerate if available.

**OU structure (if accessible):**
```bash
aws organizations list-roots --output json 2>&1
aws organizations list-organizational-units-for-parent --parent-id <root-id> --output json 2>&1
```
Map the OU hierarchy to understand which accounts share which SCPs.

**Merge with config SCPs:**

After live SCP enumeration completes (or fails with AccessDenied), merge with pre-loaded config SCPs:

- **Live succeeded:** Union config SCPs by `PolicyId`. On collision, keep the live version (tag `_source: "config+live"`). Config-only SCPs get `_source: "config"`. Live-only get `_source: "live"`.
- **Live denied:** Use config SCPs as the full dataset (all tagged `_source: "config"`). Log a `config_fallback` evidence record.
- **Neither available:** Proceed without SCP data — flag "SCP status unknown" during analysis.

Display merged count:
```
SCPs: [N] total ([L] live, [C] config-only, [O] merged/collision)
```

### Step 4: Cross-Account Role Mapping

Identify roles that can be assumed from external accounts. This is the key lateral movement surface.

**From IAM module data (preferred):** If the IAM module has already run (e.g., in `--all` mode), use the trust policy data from `get-account-authorization-details`. Parse each role's `AssumeRolePolicyDocument` for external principals.

**Standalone enumeration (if IAM module hasn't run):**
```bash
aws iam list-roles --output json 2>&1
```
For each role, parse the `AssumeRolePolicyDocument`.

**For each role trust relationship found:**
1. Note the account ID from the Principal ARN (if applicable)
2. Note any conditions on the trust (ExternalId, MFA, source IP, etc.)
3. Note what permissions the role grants (from its attached/inline policies)
4. Categorize the trust:
   - **Service trust** — trusted by an AWS service (lambda, ec2, etc.)
   - **Same-account trust** — trusted by a principal in the same account
   - **Internal cross-account trust** — trusted by a principal in a different account that IS in the owned-accounts set
   - **External cross-account trust** — trusted by a principal in a different account that is NOT in the owned-accounts set
   - **Wildcard trust** — trusted by `*` or overly broad principal

**Probe cross-account trust paths (non-invasive):**
For each discovered cross-account role, attempt assumption to verify the trust path exists:
```bash
aws sts assume-role --role-arn <ROLE_ARN> --role-session-name scope-probe 2>&1
```

**IMPORTANT:** Do NOT proceed with the assumed credentials. Only check if the assumption succeeds or fails. This confirms whether the trust path is live.

Interpret the result:
- **Success** — Trust path is live. The caller CAN assume this role. Log the temporary credentials expiration but do not use them. Severity follows trust-misconfiguration scoring rules (see Part 6A) — use owned-accounts context to determine whether this is CRITICAL, HIGH, MEDIUM, or LOW.
- **AccessDenied** — Trust exists in the policy but conditions are not met (ExternalId required, MFA required, source IP restriction, etc.). Note the specific condition that blocked it.
- **MalformedPolicyDocument** — Trust policy has syntax errors. Note for reporting.
- **RegionDisabledException** — Role is in a disabled region. Note for completeness.

### Step 5: Session Token Analysis

If the current caller is using temporary credentials (assumed role), decode additional context:

```bash
aws sts get-session-token 2>&1
```

For authorization errors, attempt to decode the encoded message for more detail:
```bash
aws sts decode-authorization-message --encoded-message <encoded-message> 2>&1
```
This reveals the full authorization context including which policy denied the action, useful for understanding permission boundaries.

### Step 6: Build Graph Data

Add STS-specific nodes and edges to the SCOPE dashboard graph:

**Nodes:**
- Owned external accounts (in owned-accounts set): `{id: "ext:arn:aws:iam::<account-id>:root", label: "<name> (<id>)", type: "external", owned: true, account_name: "<name from accounts.json>"}`
- Unknown external accounts (NOT in owned-accounts set): `{id: "ext:arn:aws:iam::<account-id>:root", label: "External <id>", type: "external", owned: false, account_name: null}`
- Organization master account: `{id: "ext:arn:aws:iam::<master-id>:root", label: "Org Master", type: "external", owned: true, account_name: "Org Master"}`

**Edges:**
- Cross-account trust: `{source: "ext:arn:aws:iam::<external-id>:root", target: "role:<role-name>", trust_type: "cross-account"}`
- Verified assumption (caller can assume): `{source: "<principal_type>:<caller>", target: "role:<role-name>", trust_type: "same-account"}` (or `edge_type: "priv_esc"` if the role is high-privilege). Use the caller's principal type from Gate 1: `user:<name>` for IAM users, `role:<role-name>` for assumed roles, `user:<federated-name>` for federated users, `user:root` for root. Match the source node type to the actual caller identity — do not hardcode `user:`.

**Cross-reference with IAM module:** If both modules run, merge the graph data:
- Connect external account nodes to the roles they can assume
- Mark verified assumption paths as priv_esc edges
- Highlight assumption chains that cross account boundaries
</sts_module>

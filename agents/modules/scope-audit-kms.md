<kms_module>
## KMS Enumeration Module

Enumerate KMS customer-managed keys, analyze key policies and grants, detect cross-account access, and map encryption dependency chains. KMS grants are the most commonly overlooked IAM bypass — they grant cryptographic permissions outside of IAM policy and are rarely audited.

### Step 1: Key Discovery

**Current region:**
```bash
aws kms list-keys --output json 2>&1
```
This returns all KMS key IDs and ARNs in the current region.

**Multi-region sweep (for --all mode):**
Sweep all AWS regions to find keys that may exist outside the default region:
```bash
for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo -e "\n### Region: $region ###"
    aws kms list-keys --region $region --query "Keys[].KeyId" --output text 2>&1 | tr '\t' '\n'
done
```
This verbatim loop from HackTricks ensures no region is missed. KMS keys are regional — a key in ap-southeast-1 won't appear in us-east-1 enumeration.

If `list-keys` returns AccessDenied: log "PARTIAL: Cannot list KMS keys — caller lacks kms:ListKeys permission" and continue to next module.

### Step 2: Per-Key Analysis

For each key ID returned, gather key metadata and access configuration:

**Key description:**
```bash
aws kms describe-key --key-id KEY_ID --output json 2>&1
```
Extract from the response:
- `KeyMetadata.KeyManager` — "AWS" (AWS-managed) or "Customer" (customer-managed)
- `KeyMetadata.KeyState` — Enabled, Disabled, PendingDeletion, PendingImport
- `KeyMetadata.KeyUsage` — ENCRYPT_DECRYPT, SIGN_VERIFY, GENERATE_VERIFY_MAC
- `KeyMetadata.Origin` — AWS_KMS, EXTERNAL, AWS_CLOUDHSM, EXTERNAL_KEY_STORE
- `KeyMetadata.KeyRotationStatus` — whether automatic rotation is enabled
- `KeyMetadata.Description` — may reveal the key's purpose (e.g., "RDS encryption key", "S3 SSE key")

**Skip AWS-managed keys:** If `KeyManager` is "AWS", skip further analysis for this key. AWS-managed keys (alias prefix `aws/`) are managed by AWS services and cannot have their policies modified. Focus analysis on customer-managed keys where misconfigurations can occur.

**Key policy:**
```bash
aws kms get-key-policy --key-id KEY_ID --policy-name default --output json 2>&1
```
The default policy name is always `default` — this is the only policy name KMS supports. The policy controls who can manage and use the key.

If AccessDenied: log "PARTIAL: Could not read key policy for [KEY_ID] — AccessDenied" and continue.

**CRITICAL — Grants check:**
```bash
aws kms list-grants --key-id KEY_ID --output json 2>&1
```
**This is the most important KMS enumeration step.** KMS grants bypass IAM policy entirely. A grant can give a principal `Decrypt`, `Encrypt`, `GenerateDataKey`, or `CreateGrant` permissions on a key WITHOUT any IAM policy allowing it. Grants are:
- Not visible in IAM policy analysis
- Not visible in `get-key-policy` output
- Often created programmatically by AWS services (EBS, RDS, Secrets Manager) and forgotten
- The primary vector for KMS permission escalation

After getting the key policy, ALWAYS check grants. For each grant, note:
- `GranteePrincipal` — who received the grant
- `Operations` — what cryptographic operations are allowed
- `RetiringPrincipal` — who can retire (revoke) the grant
- `Constraints` — any encryption context constraints
- `IssuingAccount` — the account that issued the grant

### Step 3: Policy and Grant Analysis

**Key policy analysis:**
- Check if the key policy grants `kms:*` to the account root (`arn:aws:iam::ACCOUNT-ID:root`). This is the DEFAULT policy — it means IAM policies in the account control key access. Not inherently risky, but means any IAM user/role with `kms:*` in their IAM policy can use this key.
- Check for cross-account principals — external account IDs in the Principal field. Flag as HIGH: "Cross-account KMS access: account [EXTERNAL-ID] can use key [KEY_ID]"
- Check for `Principal: "*"` — wildcard access to the key. CRITICAL finding.
- Check for `kms:CreateGrant` in the policy — this allows the grantee to create NEW grants, enabling grant chaining.

**Grant analysis:**
- Check for grants to unexpected principals — principals outside the owning account
- Check for grants with overly broad operations: `["Decrypt", "Encrypt", "GenerateDataKey", "ReEncryptFrom", "ReEncryptTo", "CreateGrant"]`
- **Flag `CreateGrant` grants to non-admin principals:** This enables a KMS grant abuse attack chain. If a principal has `CreateGrant`, they can create a new grant giving themselves (or anyone) `Decrypt` permission, bypassing all IAM controls. This is a HIGH or CRITICAL finding depending on the principal.
- Check for grants without constraints — grants without `EncryptionContextSubset` or `EncryptionContextEquals` constraints are broadly applicable

**Grant abuse attack chain:**
If a principal has `kms:CreateGrant` on a key:
1. They can create a grant giving themselves `kms:Decrypt` and `kms:GenerateDataKey`
2. They can then decrypt any data encrypted with that key
3. If the key encrypts Secrets Manager secrets, EBS volumes, or S3 objects, the blast radius expands to all that data
4. Document this chain as an attack path

### Step 4: Encryption Dependency Mapping

Map which AWS services and resources depend on each customer-managed key:

- **Secrets Manager:** Secrets encrypted with this key — if the key is compromised (attacker can Decrypt), all secret values are readable
- **EBS:** Volumes encrypted with this key — snapshots can be copied and decrypted
- **S3:** Buckets using SSE-KMS with this key — all objects in those buckets are decryptable
- **RDS:** Database instances encrypted with this key — snapshots and automated backups are decryptable
- **Lambda:** Environment variables encrypted with this key
- **CloudWatch Logs:** Log groups encrypted with this key

For each dependency found, assess blast radius: "If an attacker gains Decrypt permission on key [KEY_ID], the following data becomes accessible: [list of dependent resources]"

Cross-reference with the IAM module: which IAM principals currently have `kms:Decrypt` on this key (via policy or grants)? Map the full chain from principal -> key -> encrypted data.

### Step 4b: Recursive Policy-Following

After analyzing key policies and grants, **recursively follow specific ARN grants** to map the full access chain.

**When to recurse:** When a key policy or grant gives access to a specific principal ARN (not `*` or the account root with default policy).

**When NOT to recurse:** When the grant is admin-level (`kms:*` to account root) — this is the standard default policy. Log it and move on.

**Recursion logic:**
1. For each specific principal ARN found in key policies or grants:
   - If the ARN is a role → check what that role can access beyond KMS (S3, Secrets Manager, EC2, etc.)
   - If the ARN has `kms:CreateGrant` → trace the grant chain: who can they delegate access to?
   - If a grant gives `Decrypt` on a key that encrypts Secrets Manager secrets → follow to those secrets → who else can read them?
2. For each resource discovered through encryption dependencies:
   - If the key encrypts S3 buckets → follow bucket policies to see who else has access
   - If the key encrypts Secrets Manager → follow to the secret's resource policy
   - If the key encrypts EBS volumes → follow to the instances using those volumes → what roles do those instances have?
3. Continue until:
   - A resource has already been visited (cycle detection)
   - AccessDenied stops further traversal
   - No new specific ARN edges are discovered

**Chain output:**
```
[CHAIN] role:DataProcessor → kms:Decrypt → key/data-key-001
[CHAIN] key/data-key-001 → encrypts → secret/db-credentials
[CHAIN] key/data-key-001 → encrypts → bucket/encrypted-data
[CHAIN] role:DataProcessor → kms:CreateGrant → can delegate Decrypt to any principal
```

### Step 5: Build Graph Data

Construct nodes and edges for the SCOPE dashboard:

**Nodes:**
- Each customer-managed key: `{id: "data:kms:KEY_ID", label: "KMS: KEY_DESCRIPTION or KEY_ID", type: "data"}`

**Edges:**
- Key policy/IAM access: `{source: "user:<name>", target: "data:kms:KEY_ID", edge_type: "data_access", access_level: "read|write|admin"}` or `{source: "role:<name>", target: "data:kms:KEY_ID", edge_type: "data_access", access_level: "read|write|admin"}`
- Grant-based access: `{source: "role:<grantee>", target: "data:kms:KEY_ID", edge_type: "data_access", access_level: "read|write|admin"}` — grants bypass IAM, note in attack paths
- Encryption dependency: `{source: "data:kms:KEY_ID", target: "data:s3:BUCKET_NAME", edge_type: "data_access", access_level: "read"}` — connects keys to resources they encrypt

**access_level classification for KMS:**
- `"read"` — principal has only kms:Decrypt, kms:DescribeKey, kms:ListGrants (consume encrypted data)
- `"write"` — principal has kms:Encrypt, kms:GenerateDataKey, kms:CreateGrant (create encrypted data or delegate access)
- `"admin"` — principal has kms:* or kms:PutKeyPolicy (full key control, can lock out other principals)

**Error handling:** On AccessDenied or any error for a specific key:
1. Log: "PARTIAL: Could not read [policy/grants] for key [KEY_ID] — [error message]"
2. Continue to the next key
3. At the end of the module, report how many keys were fully analyzed vs. partially analyzed vs. skipped
</kms_module>

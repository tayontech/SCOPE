<lambda_module>
## Lambda Enumeration Module

Lambda is a high-value target for privilege escalation — execution roles often have overly broad permissions, environment variables leak secrets, resource-based policies can grant external or public invocation, and layers enable code injection. This module enumerates functions, execution roles, resource policies, layers, and event source mappings.

### Step 1: Function Discovery

```bash
aws lambda list-functions --output json 2>&1
```

**ARN-targeted mode:** Extract the function name from the ARN, skip to Step 2 for that function only.
**--all mode:** Process all functions returned.
**AccessDenied:** Log `"PARTIAL: lambda:ListFunctions denied — cannot enumerate functions"`, continue to Step 5 (layers) and Step 6 (event sources) which use separate permissions.

### Step 2: Per-Function Analysis

For each function discovered:

```bash
# Full function details including code location
aws lambda get-function --function-name FUNCTION_NAME --output json 2>&1

# Configuration details including env vars, VPC, layers
aws lambda get-function-configuration --function-name FUNCTION_NAME --output json 2>&1
```

Extract and flag for each function:
- **Execution role ARN** — cross-reference with IAM module data (if available). Flag admin-level roles: `"Lambda [FUNCTION_NAME] has admin-level role [ROLE_ARN]"`
- **Environment variables** — check for secret patterns: `PASSWORD`, `SECRET`, `KEY`, `TOKEN`, `API_KEY`, `DB_`, `CREDENTIALS`, `AUTH`. **DO NOT output secret values** — only flag existence: `"ENV VAR FLAG: [FUNCTION_NAME] has environment variable [VAR_NAME] matching secret pattern"`
- **VPC configuration** — note subnet IDs and security groups (indicates internal network access)
- **Layers** — list layer ARNs (analyzed in Step 5)
- **Runtime** — note deprecated runtimes (security risk)
- **Timeout and memory** — unusually high values may indicate crypto mining or abuse

### Step 3: Resource-Based Policy Check (HIGH VALUE)

```bash
aws lambda get-policy --function-name FUNCTION_NAME --output json 2>&1
```

Parse the resource policy JSON. Check for:
- **`Principal: "*"`** → CRITICAL: publicly invocable function. Any AWS account or anonymous caller can invoke this function.
- **Cross-account principals** (`Principal: {"AWS": "arn:aws:iam::EXTERNAL_ACCT:root"}`) → HIGH: external account can invoke the function.
- **`lambda:InvokeFunction` granted broadly** → enables Method 45 bypass (lambda:AddPermission escalation path).
- **`lambda:UpdateFunctionCode` in resource policy** → code injection vector — external account can modify function code.
- **`lambda:AddPermission`** → allows modifying the resource policy itself, enabling further access grants.

If `get-policy` returns `ResourceNotFoundException`, the function has no resource-based policy (default — only the execution role's account can invoke it).

### Step 4: Execution Role Assessment

Cross-reference each function's Role ARN with IAM module data (if available):
- Flag functions with admin-level execution roles: `"CRITICAL: Lambda [FUNCTION_NAME] has admin-level role [ROLE_ARN] — Methods 23-25, 45 target"`
- Flag roles whose trust policy allows `lambda.amazonaws.com` — these are PassRole targets for Methods 23-25, 45
- Check if the role has permissions beyond what the function needs (overly permissive)
- Flag roles that also trust other services (multi-service trust) — broadens the attack surface

### Step 5: Layer Analysis

```bash
# List all layers in the account
aws lambda list-layers --output json 2>&1

# For each layer, list versions
aws lambda list-layer-versions --layer-name LAYER_NAME --output json 2>&1
```

Layers can inject code into functions at runtime — Method 34 (Lambda Layer injection).
- Flag layers shared cross-account (layer policy allows external accounts)
- Flag functions using layers from external accounts (layer ARN contains a different account ID)
- Note layer runtimes and compatibility

### Step 6: Event Source Mappings

```bash
aws lambda list-event-source-mappings --output json 2>&1
```

Maps DynamoDB streams, SQS queues, Kinesis streams → Lambda functions.
- Relevant for Method 24 (Lambda + EventSource escalation — `lambda:CreateEventSourceMapping`)
- Flag event sources from external accounts
- Note which functions are triggered by which data sources (for attack chain analysis)

### Step 6b: Recursive Policy-Following

After analyzing resource policies and execution roles, **recursively follow the access chains** to map the full blast radius.

**When to recurse:** When a function's execution role has access to specific resource ARNs, or when a resource policy grants invocation to a specific principal.

**When NOT to recurse:** When the execution role is admin-level (`*:*` or `AdministratorAccess`) — the blast radius is already "everything." Log it as CRITICAL and move on.

**Recursion logic:**
1. For each Lambda execution role:
   - Evaluate the role's IAM policies — what specific resources can it access?
   - If it can access specific S3 buckets → follow those buckets' policies
   - If it can access specific Secrets Manager secrets → follow those secrets' resource policies
   - If it can `sts:AssumeRole` to specific roles → follow those roles' permissions
   - If it can `lambda:InvokeFunction` on other functions → follow those functions' execution roles
2. For each principal in the function's resource policy:
   - If a specific external account can invoke this function → note the cross-account invocation chain
   - If the invoker can also modify function code (`lambda:UpdateFunctionCode`) → trace the code injection → execution role chain
3. For event source mappings:
   - If the event source is in another account → note the cross-account trigger chain
   - Follow the data path: event source → Lambda → execution role → downstream resources
4. Continue until:
   - A resource has already been visited (cycle detection)
   - AccessDenied stops further traversal
   - No new specific ARN edges are discovered

**Chain output:**
```
[CHAIN] function/data-processor → execution role → role:DataProcessorRole
[CHAIN] role:DataProcessorRole → s3:GetObject → bucket/prod-data-lake
[CHAIN] role:DataProcessorRole → secretsmanager:GetSecretValue → secret/db-credentials
[CHAIN] role:DataProcessorRole → sts:AssumeRole → role:CrossAccountRole
[CHAIN] role:CrossAccountRole → s3:* → bucket/external-data
```

### Step 7: Build Graph Data

**Nodes:**
- Each function: `{id: "data:lambda:FUNCTION_NAME", label: "FUNCTION_NAME", type: "data"}`

**Edges:**
- Execution role: `{source: "data:lambda:FUNCTION_NAME", target: "role:ROLE_NAME", trust_type: "service", label: "exec_role"}` — connects function to its execution role. For reachability: compromise function = get role permissions.
- Resource policy (external): `{source: "ext:arn:aws:iam::EXTERNAL_ID:root", target: "data:lambda:FUNCTION_NAME", trust_type: "cross-account"}`
- Resource policy (public): `{source: "ext:internet", target: "data:lambda:FUNCTION_NAME", edge_type: "data_access", access_level: "read"}`
- Code injection vector: `{source: "user:ATTACKER", target: "data:lambda:FUNCTION_NAME", edge_type: "priv_esc", severity: "critical"}` — if principal has `lambda:UpdateFunctionCode` on a function with admin role
- Lambda invoke: `{source: "user:<name>", target: "data:lambda:FUNCTION_NAME", edge_type: "data_access", access_level: "read"}` or `{source: "role:<name>", target: "data:lambda:FUNCTION_NAME", edge_type: "data_access", access_level: "read"}` — principals that can invoke the function
- Lambda code modification: `{source: "user:<name>", target: "data:lambda:FUNCTION_NAME", edge_type: "data_access", access_level: "write"}` — principals with lambda:UpdateFunctionCode or lambda:UpdateFunctionConfiguration

**access_level classification for Lambda:**
- `"read"` — principal can only lambda:InvokeFunction (execute existing code)
- `"write"` — principal has lambda:UpdateFunctionCode or lambda:UpdateFunctionConfiguration (modify function behavior)

**Service integration edges (from event source mappings and environment variable references):**
- Event source → Lambda: `{source: "data:EVENT_SOURCE_SERVICE:EVENT_SOURCE_ID", target: "data:lambda:FUNCTION_NAME", edge_type: "data_access", access_level: "write", label: "triggers"}` — for each event source mapping discovered in Step 5 (SQS queues, DynamoDB streams, Kinesis streams, etc.). The event source triggers Lambda execution, making the function a downstream consumer.
- Lambda → Secrets/SSM (environment variable references): If the function's environment variables reference Secrets Manager ARNs or SSM parameter names AND the execution role has the corresponding read permissions (secretsmanager:GetSecretValue or ssm:GetParameter), emit: `{source: "data:lambda:FUNCTION_NAME", target: "data:secrets:SECRET_NAME", edge_type: "data_access", access_level: "read", label: "env_ref"}` or `{source: "data:lambda:FUNCTION_NAME", target: "data:ssm:PARAM_NAME", edge_type: "data_access", access_level: "read", label: "env_ref"}`. Only emit these edges when the execution role's permissions confirm the function can actually access the referenced secret/parameter.

**Error handling:** On AccessDenied or any error for a specific function:
1. Log: `"PARTIAL: Could not read [configuration/policy/code] for function [FUNCTION_NAME] — [error message]"`
2. Continue to the next function
3. NEVER stop the Lambda module because a single function fails
4. At the end of the module, report how many functions were fully analyzed vs. partially analyzed vs. skipped
</lambda_module>

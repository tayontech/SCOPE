<ec2_module>
## EC2/VPC/EBS/ELB/SSM Enumeration Module

This is the largest enumeration module — it covers EC2 instances, EBS volumes and snapshots, VPC networking, VPN connections, ELB load balancers, and SSM Systems Manager. These services form the compute and network infrastructure layer where misconfigurations lead to credential exposure, lateral movement, and data exfiltration.

### EC2 Instances Sub-section

#### Step 1: Instance Discovery

```bash
aws ec2 describe-instances --output json 2>&1
```

This returns all EC2 instances with full metadata:
- Instance ID, state (running/stopped/terminated), instance type
- Security groups attached
- IAM instance profile (linked to an IAM role)
- Network interfaces, VPC, subnet, public/private IP addresses
- Tags (may reveal purpose, environment, owner)
- Launch time

Also enumerate instance profiles to map instance-to-role associations:
```bash
aws iam list-instance-profiles --output json 2>&1
```

If AccessDenied: log "PARTIAL: Cannot enumerate EC2 instances — AccessDenied" and continue to next sub-section.

#### Step 2: User Data Credential Exposure (HIGH VALUE)

This is one of the highest-value enumeration checks. EC2 user data scripts are executed at instance launch and frequently contain hardcoded credentials, API keys, database passwords, and bootstrap secrets.

For each running instance:
```bash
aws ec2 describe-instance-attribute --instance-id INSTANCE_ID --attribute userData --query 'UserData.Value' --output text 2>&1
```

If the result is not empty, `None`, or an error:

**Decode the base64-encoded user data:**
```bash
echo "BASE64_VALUE" | base64 --decode 2>&1
```

**Search the decoded output for credential patterns:**
```bash
echo "DECODED_OUTPUT" | grep -iE 'password|secret|key|token|credential|AWS_ACCESS|AWS_SECRET|api[_-]?key|db[_-]?pass|mysql|postgres|mongo|redis|PRIVATE.KEY|BEGIN.RSA|BEGIN.OPENSSH'
```

If ANY credential patterns are found: flag as CRITICAL finding: "Credential exposure in user data for instance [INSTANCE_ID]: found patterns matching [list of matched patterns]". Include the line numbers but NOT the actual credential values.

**Console output check:**
```bash
aws ec2 get-console-output --instance-id INSTANCE_ID --output json 2>&1
```
Boot logs may contain embedded credentials, connection strings, or error messages revealing infrastructure details. Search the output for the same credential patterns.

#### Step 3: Instance Profile Privilege Assessment

Map each instance to its IAM role and assess the role's permissions:

1. From `describe-instances`, extract `IamInstanceProfile.Arn` for each instance
2. Map the instance profile ARN to its associated IAM role
3. Cross-reference with IAM module data (if available): what permissions does each instance's role have?
4. Flag instances with admin-level instance profiles: "Instance [INSTANCE_ID] has admin-level permissions via instance profile [PROFILE_NAME] -> role [ROLE_NAME]"

**IMDS version check:**
```bash
aws ec2 describe-instances --query "Reservations[].Instances[].{Id:InstanceId,IMDS:MetadataOptions.HttpTokens,IMDSHops:MetadataOptions.HttpPutResponseHopLimit}" --output json 2>&1
```
- `HttpTokens: "optional"` — IMDSv1 enabled. This means the instance metadata service is vulnerable to SSRF-based credential theft. An attacker with SSRF on the instance can reach `http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME` and steal temporary credentials. Flag as HIGH finding.
- `HttpTokens: "required"` — IMDSv2 only. Requires a session token for metadata access, significantly reducing SSRF credential theft risk.
- `HttpPutResponseHopLimit: 1` — prevents credential theft from containers on the instance. Hop limit > 1 allows containers to reach IMDS.

#### Step 4: Launch Template and Configuration Check

Launch templates and legacy launch configurations may contain persistent credential exposure — every new instance launched from these templates inherits the secrets.

**Launch templates:**
```bash
aws ec2 describe-launch-templates --output json 2>&1
```

For each launch template:
```bash
aws ec2 describe-launch-template-versions --launch-template-id TEMPLATE_ID --output json 2>&1
```
Check the `UserData` field in each version — decode from base64 and search for credential patterns (same as Step 2). Launch template user data is particularly dangerous because it persists: every new instance from this template gets the embedded credentials.

**Legacy launch configurations:**
```bash
aws autoscaling describe-launch-configurations --output json 2>&1
```
Check the `UserData` field — legacy launch configs are often older and more likely to contain hardcoded secrets from before secrets management best practices were adopted.

### EBS Sub-section

#### Step 5: Volume and Snapshot Discovery

**Volumes:**
```bash
aws ec2 describe-volumes --output json 2>&1
```
For each volume:
- Check `Encrypted` field — unencrypted volumes attached to instances with sensitive roles are a finding
- Note attachment info (which instance uses this volume)
- Check volume type and size for context

**Snapshots:**
```bash
aws ec2 describe-snapshots --owner-ids self --output json 2>&1
```
Snapshots are a major data exposure vector. For each snapshot:
- Check if the snapshot is shared with other accounts: the `CreateVolumePermissions` may include external account IDs
- Check if the snapshot is public: if `CreateVolumePermission` includes `Group: all`, the snapshot is publicly accessible — CRITICAL finding
- Flag unencrypted snapshots — they can be copied and mounted by anyone with access
- Note the source volume and description for context on what data the snapshot contains

If snapshots are shared with external accounts, flag: "EBS snapshot [SNAPSHOT_ID] shared with account [EXTERNAL-ID] — snapshot data is accessible cross-account"

### VPC Networking Sub-section

#### Step 6: Network Exposure Assessment

**VPCs:**
```bash
aws ec2 describe-vpcs --output json 2>&1
```
Note VPC IDs, CIDR blocks, and whether default VPC is in use.

**Security Groups (critical for network exposure):**
```bash
aws ec2 describe-security-groups --output json 2>&1
```
For each security group, analyze inbound rules (`IpPermissions`). Flag rules with dangerous exposure:

| Source CIDR | Port | Risk | Finding |
|------------|------|------|---------|
| 0.0.0.0/0 | 22 (SSH) | CRITICAL | SSH exposed to internet |
| 0.0.0.0/0 | 3389 (RDP) | CRITICAL | RDP exposed to internet |
| 0.0.0.0/0 | 3306 (MySQL) | CRITICAL | Database exposed to internet |
| 0.0.0.0/0 | 5432 (PostgreSQL) | CRITICAL | Database exposed to internet |
| 0.0.0.0/0 | 27017 (MongoDB) | CRITICAL | Database exposed to internet |
| 0.0.0.0/0 | -1 (ALL) | CRITICAL | ALL ports exposed to internet |
| 0.0.0.0/0 | 443 (HTTPS) | LOW | Web traffic — expected for public services |
| 0.0.0.0/0 | 80 (HTTP) | MEDIUM | Unencrypted web traffic exposed |

Any rule with `IpRanges` containing `0.0.0.0/0` or `Ipv6Ranges` containing `::/0` on sensitive ports is a finding.

**VPC Peering (lateral movement paths):**
```bash
aws ec2 describe-vpc-peering-connections --output json 2>&1
```
For each peering connection:
- Check if the peer is in a different account — cross-account peering enables lateral movement
- Note the CIDR blocks on both sides — what network ranges are reachable?
- Flag active cross-account peering: "VPC peering [PEERING_ID] connects to account [PEER-ACCOUNT-ID] — lateral movement path exists"

**Internet and NAT Gateways:**
```bash
aws ec2 describe-internet-gateways --output json 2>&1
aws ec2 describe-nat-gateways --output json 2>&1
```
Map which VPCs have internet connectivity (internet gateways) and which have outbound-only access (NAT gateways). VPCs with internet gateways have directly internet-connected resources.

### VPN Sub-section

#### Step 7: VPN Assessment

**Site-to-site VPN:**
```bash
aws ec2 describe-vpn-connections --output json 2>&1
```
Note VPN tunnel details, remote gateway IPs, and status. VPN connections reveal the organization's on-premises network connectivity.

**Client VPN endpoints:**
```bash
aws ec2 describe-client-vpn-endpoints --output json 2>&1
```
Client VPN endpoints allow individual users to connect to the VPC. For each endpoint:

**Authorization rules:**
```bash
aws ec2 describe-client-vpn-authorization-rules --client-vpn-endpoint-id ENDPOINT_ID --output json 2>&1
```
Check for overly broad authorization:
- `DestinationCidr: 0.0.0.0/0` with `AccessAll: true` — any authenticated VPN user can reach any network. Flag as HIGH finding.
- `GroupId` restrictions — check if group-based access control is properly configured

### ELB Sub-section

#### Step 8: Load Balancer Discovery

**Application and Network Load Balancers (ALB/NLB):**
```bash
aws elbv2 describe-load-balancers --output json 2>&1
```

For each ALB/NLB:
```bash
aws elbv2 describe-listeners --load-balancer-arn LB_ARN --output json 2>&1
```
Check listener configuration:
- HTTP listeners (port 80) without HTTPS redirect — data transmitted in plaintext. Flag as MEDIUM finding.
- HTTPS listeners (port 443) — check certificate ARN and TLS policy
- Note the target groups and their health for understanding which backends are active

**Classic Load Balancers (legacy):**
```bash
aws elb describe-load-balancers --output json 2>&1
```
Classic ELBs are legacy and may have older, less secure configurations. Check for:
- HTTP-only listeners without SSL termination
- Outdated SSL policies
- Backend instance health

### SSM Sub-section

#### Step 9: Systems Manager Assessment

**Managed instances:**
```bash
aws ssm describe-instance-information --output json 2>&1
```
Lists instances reachable via SSM Run Command. For each managed instance:
- Check the instance's IAM role permissions (cross-reference with Step 3)
- Flag instances reachable via SSM Run Command that have high-privilege instance profiles: "Instance [INSTANCE_ID] is SSM-managed with high-privilege role [ROLE_NAME] — `ssm:SendCommand` can execute arbitrary commands with [ROLE_NAME] permissions"
- This enables the `ssm:SendCommand` escalation: if an attacker has `ssm:SendCommand` permission, they can run commands on any SSM-managed instance as that instance's IAM role

**Parameter Store (potential secret storage):**
```bash
aws ssm describe-parameters --output json 2>&1
```
SSM Parameter Store is frequently used for secrets without proper encryption. For each parameter:
- Check `Type` — `SecureString` parameters are encrypted, `String` and `StringList` are plaintext
- Note that `ssm:GetParameter --with-decryption` can expose SecureString parameter values
- Flag plaintext parameters with names suggesting secrets: parameters matching patterns like `password`, `secret`, `key`, `token`, `credential`, `db_`, `api_`
- Do NOT attempt to read parameter values during reconnaissance — only note their existence and type

**Active sessions:**
```bash
aws ssm describe-sessions --state Active --output json 2>&1
```
Active SSM sessions show who is currently connected to instances. Note session owners and target instances — this reveals current administrative access patterns.

### Step 9b: Recursive Policy-Following

After analyzing instance profiles and SSM access, **recursively follow the access chains** to map the full blast radius from each compute resource.

**When to recurse:** When an instance profile role has access to specific resource ARNs, or when SSM-managed instances have high-privilege roles.

**When NOT to recurse:** When the instance profile role is admin-level (`AdministratorAccess` or `*:*`) — the blast radius is already "everything." Log it as CRITICAL and move on.

**Recursion logic:**
1. For each instance profile role:
   - Evaluate the role's IAM policies — what specific resources can it access?
   - If it can access specific S3 buckets → follow those buckets' policies
   - If it can access specific Secrets Manager secrets → follow those secrets' resource policies
   - If it can `sts:AssumeRole` to specific roles → follow those roles' permissions
   - If it can `lambda:InvokeFunction` or `lambda:UpdateFunctionCode` → follow those Lambda functions
   - If it can `ssm:SendCommand` on other instances → follow those instances' roles (lateral movement)
   - If it can `kms:Decrypt` on specific keys → follow the encryption dependency chain
2. For instances with IMDSv1 enabled:
   - The SSRF → credential theft → role permission chain: trace what the stolen credentials can access
   - Follow the instance role's full permission set from Step 1
3. For VPC peering connections:
   - Cross-account peering → note which resources in the peer account are reachable
   - Same-account peering → note lateral movement paths between VPCs
4. For shared EBS snapshots:
   - Follow to the external account that can access the snapshot data
   - If the snapshot came from an instance with credentials in user data → the chain extends to those credentials
5. Continue until:
   - A resource has already been visited (cycle detection)
   - AccessDenied stops further traversal
   - No new specific ARN edges are discovered

**Chain output:**
```
[CHAIN] instance/i-abc123 → instance profile → role:WebServerRole
[CHAIN] role:WebServerRole → s3:GetObject → bucket/app-config
[CHAIN] role:WebServerRole → secretsmanager:GetSecretValue → secret/rds-credentials
[CHAIN] role:WebServerRole → ssm:SendCommand → instance/i-def456 (lateral movement)
[CHAIN] instance/i-def456 → instance profile → role:DBAdminRole → rds:* (admin DB access)
```

### Step 10: Build Graph Data

Construct nodes and edges for the SCOPE dashboard across all sub-sections:

**Nodes:**
- EC2 instances: `{id: "data:ec2:INSTANCE_ID", label: "INSTANCE_NAME or INSTANCE_ID", type: "data"}`
- SSM parameters: `{id: "data:ssm:PARAM_NAME", label: "PARAM_NAME", type: "data"}`

Note: Security groups, VPCs, and load balancers are infrastructure context — include them in findings but do NOT add them as graph nodes. The graph focuses on principals, escalation methods, and data stores to avoid visual clutter.

**Edges:**
- Instance profile linkage: `{source: "data:ec2:INSTANCE_ID", target: "role:ROLE_NAME", trust_type: "service", label: "instance_profile"}` — connects instances to their IAM roles. For reachability: compromise instance = get role permissions (same pattern as Lambda exec_role).
- Internet exposure (instance with sensitive role): `{source: "ext:internet", target: "data:ec2:INSTANCE_ID", edge_type: "data_access", access_level: "read"}` — for instances reachable from internet with high-privilege roles
- SSM command vector: `{source: "user:ATTACKER", target: "data:ec2:INSTANCE_ID", edge_type: "priv_esc", severity: "high"}` — if principal has ssm:SendCommand on instance with admin role
- SSM parameter access: `{source: "role:<name>", target: "data:ssm:PARAM_NAME", edge_type: "data_access", access_level: "read|write|admin"}` — roles with ssm:GetParameter/PutParameter permissions

**access_level classification for EC2/SSM:**
- `"read"` — principal has ssm:GetParameter, ssm:DescribeInstanceInformation, ec2:Describe* (observe but not modify)
- `"write"` — principal has ssm:PutParameter, ssm:SendCommand, ec2:RunInstances (modify state or execute commands)
- `"admin"` — principal has ssm:* or ec2:* with broad resource scope

**Error handling:** Every AWS CLI call in this module MUST be wrapped with error handling. On AccessDenied or any error:
1. Log: "PARTIAL: Could not read [operation] for [resource] — [error message]"
2. Continue to the next command or resource
3. NEVER stop the EC2/VPC module because a single command fails
4. At the end of the module, report coverage: how many instances/security groups/VPCs/load balancers were fully analyzed vs. partially analyzed vs. skipped
</ec2_module>

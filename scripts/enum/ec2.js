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

const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');

const { withRetry, paginate, createEnvelope, writeEnvelope, createLogger } = require('../lib');

// --- CLI ---

function parseArgs(argv) {
  const args = { runDir: null, region: null, regions: null };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--run-dir' && argv[i + 1]) {
      args.runDir = argv[++i];
    } else if (argv[i] === '--region' && argv[i + 1]) {
      args.region = argv[++i];
    } else if (argv[i] === '--regions' && argv[i + 1]) {
      args.regions = argv[++i];
    } else if (argv[i] === '--help' || argv[i] === '-h') {
      console.log('Usage: node scripts/enum/ec2.js --run-dir <dir> --region <region>');
      console.log('       node scripts/enum/ec2.js --run-dir <dir> --regions <r1,r2,...>');
      console.log('');
      console.log('Options:');
      console.log('  --run-dir  Path to the run output directory (required)');
      console.log('  --region   AWS region to enumerate (required, or use --regions)');
      console.log('  --regions  Comma-separated list of regions to enumerate');
      console.log('  --help     Show this help message');
      process.exit(0);
    }
  }
  return args;
}

// --- Instance enumeration ---

async function enumerateInstances(ec2, region, logger) {
  logger.log('api_call', 'DescribeInstances', { service: 'ec2' });
  const reservations = await paginate(ec2, DescribeInstancesCommand, 'Reservations');

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

async function enumerateSecurityGroups(ec2, region, logger) {
  logger.log('api_call', 'DescribeSecurityGroups', { service: 'ec2' });
  const groups = await paginate(ec2, DescribeSecurityGroupsCommand, 'SecurityGroups');

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

async function enumerateVpcs(ec2, region, logger) {
  logger.log('api_call', 'DescribeVpcs', { service: 'ec2' });
  const vpcs = await paginate(ec2, DescribeVpcsCommand, 'Vpcs');

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

async function enumerateSnapshots(ec2, accountId, region, logger) {
  logger.log('api_call', 'DescribeSnapshots', { service: 'ec2', owner: 'self' });
  const snapshots = await paginate(ec2, DescribeSnapshotsCommand, 'Snapshots', {
    params: { OwnerIds: ['self'] },
  });

  const findings = [];
  for (const snap of snapshots) {
    let isPublic = false;

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
    } catch (err) {
      logger.log('warning', 'DescribeSnapshotAttribute', {
        snapshot: snap.SnapshotId,
        error: err.message,
      });
    }

    const finding = {
      resource_type: 'ec2_snapshot',
      resource_id: snap.SnapshotId,
      arn: `arn:aws:ec2:${region}:${accountId}:snapshot/${snap.SnapshotId}`,
      region,
      volume_id: snap.VolumeId || null,
      volume_size_gb: snap.VolumeSize || null,
      encrypted: snap.Encrypted || false,
      state: snap.State || null,
      is_public: isPublic,
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

async function enumerateELBv2(elbv2, region, logger) {
  logger.log('api_call', 'DescribeLoadBalancers_v2', { service: 'elbv2' });
  const lbs = await paginate(elbv2, DescribeALBsCommand, 'LoadBalancers', {
    tokenKey: 'Marker',
    responseTokenKey: 'NextMarker',
  });

  const findings = [];
  for (const lb of lbs) {
    let listeners = [];
    try {
      logger.log('api_call', 'DescribeListeners', { lb_arn: lb.LoadBalancerArn });
      listeners = await paginate(elbv2, DescribeListenersCommand, 'Listeners', {
        params: { LoadBalancerArn: lb.LoadBalancerArn },
        tokenKey: 'Marker',
        responseTokenKey: 'NextMarker',
      });
    } catch (err) {
      logger.log('warning', 'DescribeListeners', { lb_arn: lb.LoadBalancerArn, error: err.message });
    }

    const finding = {
      resource_type: 'ec2_load_balancer',
      resource_id: lb.LoadBalancerName,
      arn: lb.LoadBalancerArn,
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

async function enumerateClassicELB(elb, region, logger) {
  logger.log('api_call', 'DescribeLoadBalancers_classic', { service: 'elb' });
  const lbs = await paginate(elb, DescribeClassicLBsCommand, 'LoadBalancerDescriptions', {
    tokenKey: 'Marker',
    responseTokenKey: 'NextMarker',
  });

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

// --- Exported run() for testing ---

async function run(opts = {}) {
  const { runDir, region } = opts;

  if (!runDir || !region) {
    throw new Error('runDir and region are required');
  }

  const stsClient = opts.clients?.sts ?? new STSClient({ region });
  const ec2 = opts.clients?.ec2 ?? new EC2Client({ region });
  const elbv2 = opts.clients?.elbv2 ?? new ElasticLoadBalancingV2Client({ region });
  const elb = opts.clients?.elb ?? new ElasticLoadBalancingClient({ region });

  const logger = createLogger(runDir);
  logger.log('info', 'EC2_Enumeration_Start', { region });

  // Get account ID via STS
  let accountId;
  try {
    const identity = await withRetry(() => stsClient.send(new GetCallerIdentityCommand({})));
    accountId = identity.Account;
  } catch (err) {
    logger.log('error', 'GetCallerIdentity', { error: err.message });
    await logger.flush();
    throw new Error(`GetCallerIdentity failed: ${err.message}`);
  }

  const allFindings = [];
  let status = 'complete';
  const errors = [];

  // 1. Instances
  try {
    const instances = await enumerateInstances(ec2, region, logger);
    allFindings.push(...instances);
  } catch (err) {
    errors.push({ resource_type: 'ec2_instance', error: err.message });
    logger.log('error', 'DescribeInstances', { error: err.message });
  }

  // 2. Security Groups
  try {
    const sgs = await enumerateSecurityGroups(ec2, region, logger);
    allFindings.push(...sgs);
  } catch (err) {
    errors.push({ resource_type: 'ec2_security_group', error: err.message });
    logger.log('error', 'DescribeSecurityGroups', { error: err.message });
  }

  // 3. VPCs
  try {
    const vpcs = await enumerateVpcs(ec2, region, logger);
    allFindings.push(...vpcs);
  } catch (err) {
    errors.push({ resource_type: 'ec2_vpc', error: err.message });
    logger.log('error', 'DescribeVpcs', { error: err.message });
  }

  // 4. Snapshots
  try {
    const snaps = await enumerateSnapshots(ec2, accountId, region, logger);
    allFindings.push(...snaps);
  } catch (err) {
    errors.push({ resource_type: 'ec2_snapshot', error: err.message });
    logger.log('error', 'DescribeSnapshots', { error: err.message });
  }

  // 5. ELBv2 (ALB/NLB)
  try {
    const elbv2Findings = await enumerateELBv2(elbv2, region, logger);
    allFindings.push(...elbv2Findings);
  } catch (err) {
    errors.push({ resource_type: 'ec2_load_balancer_v2', error: err.message });
    logger.log('error', 'DescribeLoadBalancers_v2', { error: err.message });
  }

  // 6. Classic ELB
  try {
    const classicFindings = await enumerateClassicELB(elb, region, logger);
    allFindings.push(...classicFindings);
  } catch (err) {
    errors.push({ resource_type: 'ec2_load_balancer_classic', error: err.message });
    logger.log('error', 'DescribeLoadBalancers_classic', { error: err.message });
  }

  if (errors.length > 0) status = 'partial';

  if (opts.returnOnly) {
    await logger.flush();
    return allFindings;
  }

  const envelope = createEnvelope({
    module: 'ec2',
    account_id: accountId,
    region,
    status,
    findings: allFindings,
  });

  const outPath = writeEnvelope(runDir, envelope);

  const counts = {};
  for (const f of allFindings) {
    counts[f.resource_type] = (counts[f.resource_type] || 0) + 1;
  }

  logger.log('info', 'EC2_Enumeration_Complete', {
    status,
    total_findings: allFindings.length,
    resource_counts: counts,
    errors: errors.length,
    output: outPath,
  });

  await logger.flush();
  console.log(`EC2 enumeration complete: ${outPath} (${allFindings.length} resources, status: ${status})`);
}

// --- CLI entry point ---

async function main() {
  const args = parseArgs(process.argv);

  if (!args.runDir || (!args.region && !args.regions)) {
    console.error('Error: --run-dir and --region (or --regions) are required');
    console.error('Usage: node scripts/enum/ec2.js --run-dir <dir> --region <region>');
    console.error('       node scripts/enum/ec2.js --run-dir <dir> --regions <r1,r2,...>');
    process.exit(1);
  }

  const regionList = args.regions ? args.regions.split(',') : [args.region];

  try {
    if (regionList.length === 1) {
      await run({ runDir: args.runDir, region: regionList[0].trim() });
    } else {
      const allFindings = [];
      for (const region of regionList) {
        const findings = await run({ runDir: args.runDir, region: region.trim(), returnOnly: true });
        allFindings.push(...findings);
      }
      const envelope = createEnvelope({ module: 'ec2', account_id: null, region: 'multi', status: 'complete', findings: allFindings });
      writeEnvelope(args.runDir, envelope);
    }
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

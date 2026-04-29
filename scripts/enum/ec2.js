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

  await logger.flush();
  return { findings: allFindings, status };
}

if (require.main === module) {
  baseEnum({ module: 'ec2', run });
}

module.exports = { run };

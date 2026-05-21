from __future__ import annotations

import json
from typing import Any

from scope_core.coverage import CoverageTracker
from scope_core.models import ModuleEnvelope


def derive_principal_type(arn: str | None) -> str:
    if not arn:
        return "unknown"
    if ":assumed-role/" in arn:
        return "assumed-role"
    if ":role/" in arn:
        return "role"
    if ":user/" in arn:
        return "user"
    if ":federated-user/" in arn:
        return "federated-user"
    if arn.endswith(":root"):
        return "root"
    return "unknown"


def _client_error_code(err: Exception) -> str:
    response = getattr(err, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict) and error.get("Code"):
            return str(error["Code"])
    return err.__class__.__name__ or "Error"


def _parse_policy_document(content: str | None) -> dict[str, Any]:
    if not content:
        return {}
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        return {"raw": content}
    if isinstance(parsed, dict):
        return parsed
    return {"raw": parsed}


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=["get_caller_identity"], required=["scp_policy", "scp_policy_detail", "scp_targets"])
    sts = factory.client("sts")
    findings: list[dict[str, Any]] = []

    try:
        identity = sts.get_caller_identity()
        tracker.record_ok("get_caller_identity")
    except Exception as err:
        tracker.record_module_failure("get_caller_identity", operation="sts.GetCallerIdentity", err=err)
        coverage, errors = tracker.to_envelope_fields()
        return ModuleEnvelope(
            module="sts",
            account_id="unknown",
            region=region,
            status=tracker.derive_status(),
            resources=[],
            coverage=coverage,
            errors=errors,
        )

    account_id = str(identity["Account"])
    caller_arn = identity.get("Arn")
    identity_finding: dict[str, Any] = {
        "resource_type": "sts_identity",
        "resource_id": "caller",
        "arn": caller_arn,
        "region": "global",
        "account_id": account_id,
        "user_id": identity.get("UserId"),
        "principal_type": derive_principal_type(caller_arn),
        # DEPRECATED: keep for one release while Organizations state moves into coverage[]; remove in v1.16.
        "org_accessible": False,
        "org_status": "unknown",
        "org_error_code": None,
        "findings": [],
    }
    findings.append(identity_finding)

    org_accessible = False
    organizations = None
    try:
        organizations = factory.client("organizations")
        org_response = organizations.describe_organization()
        tracker.record_ok("organizations")
        org = org_response.get("Organization", {})
        org_accessible = True
        identity_finding["org_accessible"] = True
        identity_finding["org_status"] = "accessible"
        findings.append(
            {
                "resource_type": "sts_organization",
                "resource_id": org.get("Id"),
                "arn": org.get("Arn"),
                "region": "global",
                "master_account_id": org.get("MasterAccountId"),
                "available_policy_types": [
                    policy_type.get("Type")
                    for policy_type in org.get("AvailablePolicyTypes", [])
                    if policy_type.get("Status") == "ENABLED"
                ],
                "findings": [],
            }
        )
    except Exception as err:
        code = _client_error_code(err)
        identity_finding["org_error_code"] = code
        if code == "AWSOrganizationsNotInUseException":
            identity_finding["org_status"] = "not_in_use"
            tracker.record_skipped("organizations", reason=code)
        elif code in {"AccessDeniedException", "AccessDenied"}:
            identity_finding["org_status"] = "not_accessible"
            tracker.record_skipped("organizations", reason=code)
        else:
            identity_finding["org_status"] = "error"
            tracker.record_resource_failure(
                "organizations",
                resource=account_id,
                operation="organizations.DescribeOrganization",
                err=err,
            )

    if org_accessible:
        try:
            policies = factory.paginate(
                organizations,
                "list_policies",
                "Policies",
                Filter="SERVICE_CONTROL_POLICY",
            )
            tracker.record_ok("scp_policy")
        except Exception as err:
            tracker.record_module_failure(
                "scp_policy",
                operation="organizations.ListPolicies",
                err=err,
            )
            policies = []

        for policy_summary in policies:
            policy_id = policy_summary.get("Id")
            try:
                policy_response = organizations.describe_policy(PolicyId=policy_id)
                policy = policy_response.get("Policy", {})
                tracker.record_ok("scp_policy_detail", resource=policy_id)
            except Exception as err:
                tracker.record_resource_failure(
                    "scp_policy_detail",
                    resource=policy_id,
                    operation="organizations.DescribePolicy",
                    err=err,
                )
                continue

            try:
                targets = factory.paginate(
                    organizations,
                    "list_targets_for_policy",
                    "Targets",
                    PolicyId=policy_id,
                )
                tracker.record_ok("scp_targets", resource=policy_id)
            except Exception as err:
                tracker.record_resource_failure(
                    "scp_targets",
                    resource=policy_id,
                    operation="organizations.ListTargetsForPolicy",
                    err=err,
                )
                targets = []

            findings.append(
                {
                    "resource_type": "sts_scp",
                    "resource_id": policy_id,
                    "arn": policy_summary.get("Arn"),
                    "region": "global",
                    "name": policy_summary.get("Name"),
                    "description": policy_summary.get("Description") or "",
                    "policy_document": _parse_policy_document(policy.get("Content")),
                    "targets": [
                        {
                            "target_id": target.get("TargetId"),
                            "type": target.get("Type"),
                            "name": target.get("Name"),
                        }
                        for target in targets
                    ],
                    "findings": [],
                }
            )

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="sts",
        account_id=account_id,
        region=region,
        status=tracker.derive_status(),
        resources=findings,
        coverage=coverage,
        errors=errors,
    )

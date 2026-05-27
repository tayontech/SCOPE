from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from io import StringIO
from typing import Any
from urllib.parse import unquote

from scope.core.models import ErrorRecord, ModuleEnvelope


def run(factory: Any, region: str) -> ModuleEnvelope:
    iam = factory.client("iam")
    status = "complete"
    errors: list[ErrorRecord] = []

    try:
        users, roles, groups = _enumerate_gaad(iam, factory.account_id)
        _enrich_group_members(iam, groups)
    except Exception as err:
        if _error_code(err) in {"AccessDeniedException", "AccessDenied", "UnauthorizedAccess"}:
            try:
                users, roles, groups, fallback_errors = _enumerate_fallback(factory, iam, factory.account_id)
                errors.extend(fallback_errors)
                if fallback_errors:
                    status = "partial"
            except Exception as fallback_err:
                return _envelope(factory.account_id, region, [], "error", [_error("iam.fallback", None, fallback_err)])
        else:
            return _envelope(factory.account_id, region, [], "error", [_error("iam.GetAccountAuthorizationDetails", None, err)])

    enrichment_errors = _enrich_staleness(factory, iam, users, roles)
    if enrichment_errors:
        errors.extend(enrichment_errors)
        status = "partial"

    oidc_resources, oidc_errors = _oidc_providers(iam, roles)
    if oidc_errors:
        errors.extend(oidc_errors)
        status = "partial"

    resources = [*users, *roles, *groups, *oidc_resources]
    return _envelope(factory.account_id, region, resources, status, errors)


def _envelope(account_id: str, region: str, resources: list[dict[str, Any]], status: str, errors: list[ErrorRecord]):
    return ModuleEnvelope(
        module="iam",
        account_id=account_id,
        region=region,
        status=status,
        resources=resources,
        coverage=[],
        errors=errors,
    )


def _enumerate_gaad(iam: Any, account_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    users_raw: list[dict[str, Any]] = []
    roles_raw: list[dict[str, Any]] = []
    groups_raw: list[dict[str, Any]] = []
    policies_raw: list[dict[str, Any]] = []
    marker = None
    while True:
        kwargs = {"Filter": ["User", "Role", "Group", "LocalManagedPolicy"]}
        if marker:
            kwargs["Marker"] = marker
        response = iam.get_account_authorization_details(**kwargs)
        users_raw.extend(response.get("UserDetailList") or [])
        roles_raw.extend(response.get("RoleDetailList") or [])
        groups_raw.extend(response.get("GroupDetailList") or [])
        policies_raw.extend(response.get("Policies") or [])
        if not response.get("IsTruncated"):
            break
        marker = response.get("Marker")

    roles_raw = [role for role in roles_raw if not _is_service_linked_role(role)]
    managed_docs = _customer_managed_policy_docs(iam, users_raw, roles_raw, groups_raw, policies_raw)
    users = [_user_from_gaad(user, managed_docs) for user in users_raw]
    roles = [_role_from_gaad(role, account_id, managed_docs) for role in roles_raw]
    groups = [_group_from_gaad(group, managed_docs) for group in groups_raw]
    return users, roles, groups


def _customer_managed_policy_docs(
    iam: Any,
    users: list[dict[str, Any]],
    roles: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    policies: list[dict[str, Any]],
) -> dict[str, Any]:
    attached = set()
    for principal in [*users, *roles, *groups]:
        for policy in principal.get("AttachedManagedPolicies") or []:
            arn = policy.get("PolicyArn")
            if arn:
                attached.add(arn)
        boundary_arn = (principal.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
        if boundary_arn:
            attached.add(boundary_arn)

    docs: dict[str, Any] = {}
    for policy in policies:
        arn = policy.get("Arn")
        if not arn or arn not in attached or _is_aws_managed_policy_arn(arn):
            continue
        try:
            response = iam.get_policy_version(PolicyArn=arn, VersionId=policy.get("DefaultVersionId"))
            document = (response.get("PolicyVersion") or {}).get("Document")
            if document:
                docs[arn] = _decode_policy(document)
        except Exception:
            continue
    return docs


def _user_from_gaad(user: dict[str, Any], managed_docs: dict[str, Any]) -> dict[str, Any]:
    finding = {
        "resource_type": "iam_user",
        "resource_id": user.get("UserName"),
        "arn": user.get("Arn"),
        "region": "global",
        "groups": user.get("GroupList") or [],
        "attached_policies": [
            {"name": policy.get("PolicyName"), "arn": policy.get("PolicyArn"), "document": managed_docs.get(policy.get("PolicyArn"))}
            for policy in user.get("AttachedManagedPolicies") or []
        ],
        "inline_policies": [
            {"name": policy.get("PolicyName"), "document": _decode_policy(policy.get("PolicyDocument"))}
            for policy in user.get("UserPolicyList") or []
        ],
        "has_console_access": False,
        "mfa_enabled": False,
        "access_keys": [],
        "password_last_used": None,
        "has_boundary": bool(user.get("PermissionsBoundary")),
        "permission_boundary_arn": (user.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
        "last_activity": None,
        "is_stale": True,
        "stale_days": None,
    }
    if finding["permission_boundary_arn"]:
        finding["permission_boundary_document"] = managed_docs.get(finding["permission_boundary_arn"])
    return finding


def _role_from_gaad(role: dict[str, Any], account_id: str, managed_docs: dict[str, Any]) -> dict[str, Any]:
    finding = {
        "resource_type": "iam_role",
        "resource_id": role.get("RoleName"),
        "arn": role.get("Arn"),
        "region": "global",
        "is_service_linked": (role.get("Path") or "").startswith("/aws-service-role/"),
        "trust_relationships": _parse_trust_policy(role.get("AssumeRolePolicyDocument"), account_id),
        "attached_policies": [
            {"name": policy.get("PolicyName"), "arn": policy.get("PolicyArn"), "document": managed_docs.get(policy.get("PolicyArn"))}
            for policy in role.get("AttachedManagedPolicies") or []
        ],
        "inline_policies": [
            {"name": policy.get("PolicyName"), "document": _decode_policy(policy.get("PolicyDocument"))}
            for policy in role.get("RolePolicyList") or []
        ],
        "has_boundary": bool(role.get("PermissionsBoundary")),
        "permission_boundary_arn": (role.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
        "last_activity": _safe_iso((role.get("RoleLastUsed") or {}).get("LastUsedDate")),
        "is_stale": True,
        "stale_days": None,
        "service_last_accessed": None,
    }
    if finding["permission_boundary_arn"]:
        finding["permission_boundary_document"] = managed_docs.get(finding["permission_boundary_arn"])
    finding.update(_compute_staleness(finding["last_activity"]))
    return finding


def _group_from_gaad(group: dict[str, Any], managed_docs: dict[str, Any]) -> dict[str, Any]:
    return {
        "resource_type": "iam_group",
        "resource_id": group.get("GroupName"),
        "arn": group.get("Arn"),
        "region": "global",
        "members": [],
        "attached_policies": [
            {"name": policy.get("PolicyName"), "arn": policy.get("PolicyArn"), "document": managed_docs.get(policy.get("PolicyArn"))}
            for policy in group.get("AttachedManagedPolicies") or []
        ],
        "inline_policies": [
            {"name": policy.get("PolicyName"), "document": _decode_policy(policy.get("PolicyDocument"))}
            for policy in group.get("GroupPolicyList") or []
        ],
    }


def _enrich_group_members(iam: Any, groups: list[dict[str, Any]]) -> None:
    for group in groups:
        try:
            response = iam.get_group(GroupName=group["resource_id"])
            group["members"] = [user.get("UserName") for user in response.get("Users") or []]
        except Exception:
            continue


def _enrich_staleness(factory: Any, iam: Any, users: list[dict[str, Any]], roles: list[dict[str, Any]]) -> list[ErrorRecord]:
    errors: list[ErrorRecord] = []
    credential_report = _credential_report(iam, errors)

    for user in users:
        try:
            keys = factory.paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=user["resource_id"])
            access_keys = []
            for key in keys:
                try:
                    last_used = iam.get_access_key_last_used(AccessKeyId=key.get("AccessKeyId")).get("AccessKeyLastUsed") or {}
                    key_last_used = _safe_iso(last_used.get("LastUsedDate"))
                except Exception:
                    key_last_used = None
                access_keys.append({"key_id": key.get("AccessKeyId"), "status": key.get("Status"), "last_used": key_last_used})
            user["access_keys"] = access_keys

            try:
                mfa_devices = factory.paginate(iam, "list_mfa_devices", "MFADevices", UserName=user["resource_id"])
                user["mfa_enabled"] = len(mfa_devices) > 0
            except Exception:
                pass

            try:
                iam.get_login_profile(UserName=user["resource_id"])
                user["has_console_access"] = True
            except Exception as err:
                if _error_code(err) not in {"NoSuchEntityException", "NoSuchEntity"}:
                    raise

            if user["resource_id"] in credential_report:
                report = credential_report[user["resource_id"]]
                if report.get("password_last_used"):
                    user["password_last_used"] = report["password_last_used"]
                if report.get("mfa_active") == "true":
                    user["mfa_enabled"] = True

            dates = [user["password_last_used"], *[key["last_used"] for key in access_keys]]
            latest = sorted([date for date in dates if date], reverse=True)
            user.update(_compute_staleness(latest[0] if latest else None))
        except Exception as err:
            errors.append(_error("iam.user_staleness", user.get("arn"), err))

    for finding in [*users, *roles]:
        if not finding.get("is_stale"):
            continue
        try:
            job = iam.generate_service_last_accessed_details(Arn=finding["arn"]).get("JobId")
            if not job:
                continue
            response = iam.get_service_last_accessed_details(JobId=job)
            if response.get("JobStatus") == "COMPLETED":
                finding["service_last_accessed"] = [
                    {
                        "service_name": service.get("ServiceName"),
                        "service_namespace": service.get("ServiceNamespace"),
                        "last_authenticated": _safe_iso(service.get("LastAuthenticated")),
                        "total_entities": service.get("TotalAuthenticatedEntities") or 0,
                    }
                    for service in response.get("ServicesLastAccessed") or []
                ]
        except Exception as err:
            errors.append(_error("iam.service_last_accessed", finding.get("arn"), err))
            finding["service_last_accessed"] = None

    return errors


def _credential_report(iam: Any, errors: list[ErrorRecord]) -> dict[str, dict[str, Any]]:
    try:
        ready = False
        for _attempt in range(10):
            if iam.generate_credential_report().get("State") == "COMPLETE":
                ready = True
                break
        if not ready:
            return {}
        content = iam.get_credential_report().get("Content") or ""
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        return _parse_credential_report(content)
    except Exception as err:
        errors.append(_error("iam.credential_report", "credential_report", err))
        return {}


def _parse_credential_report(content: str) -> dict[str, dict[str, Any]]:
    report: dict[str, dict[str, Any]] = {}
    for row in csv.DictReader(StringIO(content)):
        user = row.get("user")
        if not user or user == "<root_account>":
            continue
        report[user] = {
            "password_last_used": _normalize_report_date(row.get("password_last_used")),
            "mfa_active": row.get("mfa_active") or "false",
        }
    return report


def _oidc_providers(iam: Any, roles: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[ErrorRecord]]:
    try:
        providers = iam.list_open_id_connect_providers().get("OpenIDConnectProviderList") or []
    except Exception as err:
        return [], [_error("iam.ListOpenIDConnectProviders", None, err)]

    role_map: dict[str, list[dict[str, Any]]] = {}
    for role in roles:
        for trust in role.get("trust_relationships") or []:
            if trust.get("trust_type") == "federated" and trust.get("principal"):
                role_map.setdefault(trust["principal"], []).append({"arn": role.get("arn"), "conditions": trust})

    resources: list[dict[str, Any]] = []
    errors: list[ErrorRecord] = []
    for provider_ref in providers:
        arn = provider_ref.get("Arn")
        try:
            detail = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
            assumed_roles = role_map.get(arn) or []
            resources.append(
                {
                    "resource_type": "oidc_provider",
                    "resource_id": arn,
                    "arn": arn,
                    "region": "global",
                    "url": detail.get("Url"),
                    "client_ids": detail.get("ClientIDList") or [],
                    "thumbprints": detail.get("ThumbprintList") or [],
                    "create_date": _safe_iso(detail.get("CreateDate")),
                    "assumed_role_arns": [role["arn"] for role in assumed_roles],
                    "trust_conditions": [role["conditions"] for role in assumed_roles],
                }
            )
        except Exception as err:
            errors.append(_error("iam.GetOpenIDConnectProvider", arn, err))
    return resources, errors


def _enumerate_fallback(factory: Any, iam: Any, account_id: str):
    errors: list[ErrorRecord] = []
    users = factory.paginate(iam, "list_users", "Users")
    roles = [role for role in factory.paginate(iam, "list_roles", "Roles") if not _is_service_linked_role(role)]
    groups = factory.paginate(iam, "list_groups", "Groups")

    user_resources = [_fallback_user(factory, iam, user, errors) for user in users]
    role_resources = [_fallback_role(factory, iam, role, account_id, errors) for role in roles]
    group_resources = [_fallback_group(factory, iam, group, errors) for group in groups]

    return user_resources, role_resources, group_resources, errors


def _fallback_user(factory: Any, iam: Any, user: dict[str, Any], errors: list[ErrorRecord]) -> dict[str, Any]:
    name = user.get("UserName")
    inline = []
    attached = []
    groups = []
    try:
        inline_names = factory.paginate(iam, "list_user_policies", "PolicyNames", UserName=name)
        inline = [
            {"name": policy_name, "document": _fallback_get_user_policy(iam, name, policy_name)}
            for policy_name in inline_names
        ]
        attached_raw = factory.paginate(iam, "list_attached_user_policies", "AttachedPolicies", UserName=name)
        attached = [
            {
                "name": policy.get("PolicyName"),
                "arn": policy.get("PolicyArn"),
                "document": _managed_policy_document(iam, policy.get("PolicyArn")),
            }
            for policy in attached_raw
        ]
        groups = [group.get("GroupName") for group in factory.paginate(iam, "list_groups_for_user", "Groups", UserName=name)]
    except Exception as err:
        errors.append(_error("iam.UserDetailFetch", name, err))

    finding = _user_from_gaad(
        {
            "UserName": name,
            "Arn": user.get("Arn"),
            "GroupList": groups,
            "AttachedManagedPolicies": [],
            "UserPolicyList": [],
            "PermissionsBoundary": user.get("PermissionsBoundary"),
        },
        {},
    )
    finding["attached_policies"] = attached
    finding["inline_policies"] = inline
    if finding.get("permission_boundary_arn"):
        finding["permission_boundary_document"] = _managed_policy_document(iam, finding.get("permission_boundary_arn"))
    finding["password_last_used"] = _safe_iso(user.get("PasswordLastUsed"))
    return finding


def _fallback_get_user_policy(iam: Any, user_name: str, policy_name: str) -> Any:
    try:
        return _decode_policy(iam.get_user_policy(UserName=user_name, PolicyName=policy_name).get("PolicyDocument"))
    except Exception:
        return None


def _fallback_role(factory: Any, iam: Any, role: dict[str, Any], account_id: str, errors: list[ErrorRecord]) -> dict[str, Any]:
    name = role.get("RoleName")
    try:
        detail = (iam.get_role(RoleName=name).get("Role") or role)
    except Exception as err:
        errors.append(_error("iam.RoleDetailFetch", name, err))
        detail = role

    inline = []
    attached = []
    try:
        inline_names = factory.paginate(iam, "list_role_policies", "PolicyNames", RoleName=name)
        inline = [
            {"name": policy_name, "document": _fallback_get_role_policy(iam, name, policy_name)}
            for policy_name in inline_names
        ]
        attached_raw = factory.paginate(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name)
        attached = [
            {
                "name": policy.get("PolicyName"),
                "arn": policy.get("PolicyArn"),
                "document": _managed_policy_document(iam, policy.get("PolicyArn")),
            }
            for policy in attached_raw
        ]
    except Exception as err:
        errors.append(_error("iam.RolePolicyFetch", name, err))

    finding = _role_from_gaad(
        {
            "RoleName": name,
            "Arn": detail.get("Arn"),
            "Path": detail.get("Path"),
            "AssumeRolePolicyDocument": detail.get("AssumeRolePolicyDocument"),
            "AttachedManagedPolicies": [],
            "RolePolicyList": [],
            "PermissionsBoundary": detail.get("PermissionsBoundary"),
            "RoleLastUsed": detail.get("RoleLastUsed"),
        },
        account_id,
        {},
    )
    finding["attached_policies"] = attached
    finding["inline_policies"] = inline
    if finding.get("permission_boundary_arn"):
        finding["permission_boundary_document"] = _managed_policy_document(iam, finding.get("permission_boundary_arn"))
    return finding


def _fallback_get_role_policy(iam: Any, role_name: str, policy_name: str) -> Any:
    try:
        return _decode_policy(iam.get_role_policy(RoleName=role_name, PolicyName=policy_name).get("PolicyDocument"))
    except Exception:
        return None


def _fallback_group(factory: Any, iam: Any, group: dict[str, Any], errors: list[ErrorRecord]) -> dict[str, Any]:
    name = group.get("GroupName")
    members = []
    inline = []
    attached = []
    try:
        members = [user.get("UserName") for user in (iam.get_group(GroupName=name).get("Users") or [])]
        attached_raw = factory.paginate(iam, "list_attached_group_policies", "AttachedPolicies", GroupName=name)
        attached = [
            {
                "name": policy.get("PolicyName"),
                "arn": policy.get("PolicyArn"),
                "document": _managed_policy_document(iam, policy.get("PolicyArn")),
            }
            for policy in attached_raw
        ]
        inline_names = factory.paginate(iam, "list_group_policies", "PolicyNames", GroupName=name)
        inline = [
            {"name": policy_name, "document": _fallback_get_group_policy(iam, name, policy_name)}
            for policy_name in inline_names
        ]
    except Exception as err:
        errors.append(_error("iam.GroupDetailFetch", name, err))

    return {
        "resource_type": "iam_group",
        "resource_id": name,
        "arn": group.get("Arn"),
        "region": "global",
        "members": members,
        "attached_policies": attached,
        "inline_policies": inline,
    }


def _fallback_get_group_policy(iam: Any, group_name: str, policy_name: str) -> Any:
    try:
        return _decode_policy(iam.get_group_policy(GroupName=group_name, PolicyName=policy_name).get("PolicyDocument"))
    except Exception:
        return None


def _managed_policy_document(iam: Any, policy_arn: str | None) -> Any:
    if not policy_arn or _is_aws_managed_policy_arn(policy_arn):
        return None
    try:
        policy = iam.get_policy(PolicyArn=policy_arn).get("Policy") or {}
        version_id = policy.get("DefaultVersionId")
        if not version_id:
            return None
        version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id).get("PolicyVersion") or {}
        return _decode_policy(version.get("Document"))
    except Exception:
        return None


def _is_aws_managed_policy_arn(policy_arn: str) -> bool:
    return re.match(r"^arn:[^:]+:iam::aws:policy/", policy_arn) is not None


def _parse_trust_policy(policy: Any, account_id: str) -> list[dict[str, Any]]:
    document = _decode_policy(policy)
    statements = document.get("Statement", []) if isinstance(document, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    relationships: list[dict[str, Any]] = []
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        actions = _normalize_actions(statement.get("Action"))
        if not _has_sts_trust_action(actions):
            continue
        conditions = statement.get("Condition")
        has_external_id = _has_condition_key(conditions, "sts:ExternalId")
        has_mfa = _has_condition_key(conditions, "aws:MultiFactorAuthPresent") or _has_condition_key(
            conditions, "aws:MultiFactorAuthAge"
        )
        for principal in _normalize_principals(statement.get("Principal")):
            entry = {
                **_classify_principal(principal, account_id),
                "has_external_id": has_external_id,
                "has_mfa_condition": has_mfa,
                "actions": actions,
                "conditions": conditions if isinstance(conditions, dict) else {},
            }
            relationships.append(entry)
    return relationships


def _normalize_actions(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _has_sts_trust_action(actions: list[str]) -> bool:
    allowed = {
        "sts:assumerole",
        "sts:assumerolewithsaml",
        "sts:assumerolewithwebidentity",
        "sts:*",
        "*",
    }
    return any(action.lower() in allowed for action in actions)


def _normalize_principals(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        principals: list[str] = []
        for key in ("AWS", "Service", "Federated"):
            item = value.get(key)
            if isinstance(item, str):
                principals.append(item)
            elif isinstance(item, list):
                principals.extend(str(part) for part in item)
        return principals
    return []


def _classify_principal(principal: str, account_id: str) -> dict[str, Any]:
    if principal in {"*", "arn:aws:iam::*:root"}:
        return {"principal": principal, "trust_type": "wildcard", "is_wildcard": True}
    if principal.endswith(".amazonaws.com"):
        return {"principal": principal, "trust_type": "service", "is_wildcard": False}
    if principal.startswith("arn:aws:iam::") and principal.endswith(":root"):
        trust_type = "same-account" if f":{account_id}:" in principal else "cross-account"
        return {"principal": principal, "trust_type": trust_type, "is_wildcard": False}
    if principal.startswith("arn:aws:iam::") and (":saml-provider/" in principal or ":oidc-provider/" in principal):
        return {"principal": principal, "trust_type": "federated", "is_wildcard": False}
    if principal == "cognito-identity.amazonaws.com":
        return {"principal": principal, "trust_type": "federated", "is_wildcard": False}
    if principal.startswith("arn:aws:iam::"):
        trust_type = "same-account" if f":{account_id}:" in principal else "cross-account"
        return {"principal": principal, "trust_type": trust_type, "is_wildcard": False}
    return {"principal": principal, "trust_type": "same-account", "is_wildcard": False}


def _has_condition_key(conditions: Any, key: str) -> bool:
    if not isinstance(conditions, dict):
        return False
    for operator in conditions.values():
        if isinstance(operator, dict) and key in operator:
            return True
    return False


def _is_service_linked_role(role: dict[str, Any]) -> bool:
    name = str(role.get("RoleName") or "")
    path = str(role.get("Path") or "")
    arn = str(role.get("Arn") or "")
    return (
        name.startswith("AWSServiceRoleFor")
        or path.startswith("/aws-service-role/")
        or ":role/aws-service-role/" in arn
    )


def _decode_policy(policy: Any) -> Any:
    if policy is None:
        return None
    if isinstance(policy, dict):
        return policy
    try:
        return json.loads(unquote(str(policy)))
    except json.JSONDecodeError:
        return policy


def _compute_staleness(last_activity: str | None) -> dict[str, Any]:
    if not last_activity:
        return {"last_activity": None, "is_stale": True, "stale_days": None}
    days = (datetime.now(timezone.utc) - _parse_date(last_activity)).days
    return {"last_activity": last_activity, "is_stale": days >= 90, "stale_days": days}


def _parse_date(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _safe_iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


def _normalize_report_date(value: str | None) -> str | None:
    if value in {None, "", "N/A", "no_information", "not_supported"}:
        return None
    return value


def _error(operation: str, resource: str | None, err: Exception) -> ErrorRecord:
    return ErrorRecord(operation=operation, resource=resource, code=_error_code(err), message=str(err))


def _error_code(err: Exception) -> str:
    response = getattr(err, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict) and error.get("Code"):
            return str(error["Code"])
    code = getattr(err, "Code", None)
    if code:
        return str(code)
    return err.__class__.__name__ or "Error"

from botocore.exceptions import ClientError

from scope.enumerators.sts import derive_principal_type, run


class FakeFactory:
    account_id = "123456789012"

    def __init__(self, sts, organizations):
        self._clients = {"sts": sts, "organizations": organizations}

    def client(self, service):
        return self._clients[service]

    def paginate(self, client, operation_name, result_key, **kwargs):
        return client.paginate(operation_name, result_key, **kwargs)


class OrgClientFailureFactory(FakeFactory):
    def client(self, service):
        if service == "organizations":
            raise RuntimeError("organizations client unavailable")
        return super().client(service)


class FakeSts:
    def get_caller_identity(self):
        return {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/TestUser",
            "UserId": "AIDATEST123456789",
        }


class FakeStsFailure:
    def get_caller_identity(self):
        raise ClientError(
            {"Error": {"Code": "InvalidClientTokenId", "Message": "bad token"}},
            "GetCallerIdentity",
        )


class FakeOrganizationsDenied:
    def describe_organization(self):
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "DescribeOrganization",
        )


class FakeOrganizationsAccessible:
    list_policies_error = None
    describe_policy_error = None
    targets_error = None

    def describe_organization(self):
        return {
            "Organization": {
                "Id": "o-example",
                "Arn": "arn:aws:organizations::123456789012:organization/o-example",
                "MasterAccountId": "123456789012",
                "AvailablePolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}],
            }
        }

    def paginate(self, operation_name, result_key, **kwargs):
        if operation_name == "list_policies":
            if self.list_policies_error:
                raise self.list_policies_error
            assert result_key == "Policies"
            assert kwargs == {"Filter": "SERVICE_CONTROL_POLICY"}
            return [
                {
                    "Id": "p-example",
                    "Arn": "arn:aws:organizations::123456789012:policy/o-example/service_control_policy/p-example",
                    "Name": "DenyDanger",
                    "Description": "Example",
                }
            ]
        if operation_name == "list_targets_for_policy":
            if self.targets_error:
                raise self.targets_error
            assert result_key == "Targets"
            assert kwargs == {"PolicyId": "p-example"}
            return [{"TargetId": "123456789012", "Type": "ACCOUNT", "Name": "Example"}]
        return []

    def describe_policy(self, PolicyId):
        if self.describe_policy_error:
            raise self.describe_policy_error
        return {
            "Policy": {
                "PolicySummary": {
                    "Id": PolicyId,
                    "Name": "DenyDanger",
                },
                "Content": '{"Version":"2012-10-17","Statement":[]}',
            }
        }


class FakeOrganizationsListPoliciesFailure(FakeOrganizationsAccessible):
    list_policies_error = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
        "ListPolicies",
    )


class FakeOrganizationsDescribePolicyFailure(FakeOrganizationsAccessible):
    describe_policy_error = ClientError(
        {"Error": {"Code": "PolicyNotFoundException", "Message": "missing"}},
        "DescribePolicy",
    )


class FakeOrganizationsTargetsFailure(FakeOrganizationsAccessible):
    targets_error = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
        "ListTargetsForPolicy",
    )


def test_derive_principal_type():
    assert derive_principal_type("arn:aws:sts::123456789012:assumed-role/Admin/session") == "assumed-role"
    assert derive_principal_type("arn:aws:iam::123456789012:role/Admin") == "role"
    assert derive_principal_type("arn:aws:iam::123456789012:user/Test") == "user"
    assert derive_principal_type("arn:aws:iam::123456789012:root") == "root"
    assert derive_principal_type("arn:aws:sts::123456789012:federated-user/Test") == "federated-user"
    assert derive_principal_type(None) == "unknown"
    assert derive_principal_type("arn:aws:iam::123456789012:group/Example") == "unknown"


def test_sts_org_access_denied_is_complete_with_skipped_coverage():
    envelope = run(FakeFactory(FakeSts(), FakeOrganizationsDenied()), "global")

    assert envelope.status == "complete"
    assert envelope.resources[0]["resource_type"] == "sts_identity"
    assert envelope.resources[0]["org_accessible"] is False
    assert envelope.resources[0]["org_status"] == "not_accessible"
    assert envelope.resources[0]["org_error_code"] == "AccessDeniedException"
    org_coverage = next(entry for entry in envelope.coverage if entry.check == "organizations")
    assert org_coverage.status == "skipped"


def test_sts_org_client_failure_is_complete_identity_with_error_coverage():
    envelope = run(OrgClientFailureFactory(FakeSts(), FakeOrganizationsDenied()), "global")

    assert envelope.status == "complete"
    assert [finding["resource_type"] for finding in envelope.resources] == ["sts_identity"]
    assert envelope.resources[0]["org_status"] == "error"
    org_coverage = next(entry for entry in envelope.coverage if entry.check == "organizations")
    assert org_coverage.status == "partial"
    assert org_coverage.reasons[0].code == "RuntimeError"


def test_sts_org_accessible_emits_org_and_scp_findings():
    envelope = run(FakeFactory(FakeSts(), FakeOrganizationsAccessible()), "global")
    resource_types = [finding["resource_type"] for finding in envelope.resources]
    scp_policy = next(entry for entry in envelope.coverage if entry.check == "scp_policy")
    scp_policy_detail = next(entry for entry in envelope.coverage if entry.check == "scp_policy_detail")

    assert envelope.status == "complete"
    assert resource_types == ["sts_identity", "sts_organization", "sts_scp"]
    assert envelope.resources[0]["org_accessible"] is True
    assert envelope.resources[0]["org_status"] == "accessible"
    assert envelope.resources[2]["policy_document"] == {"Version": "2012-10-17", "Statement": []}
    assert envelope.resources[2]["targets"] == [
        {"target_id": "123456789012", "type": "ACCOUNT", "name": "Example"}
    ]
    assert scp_policy.scope == "module_wide"
    assert scp_policy.succeeded == 1
    assert scp_policy_detail.scope == "per_resource"
    assert scp_policy_detail.succeeded == 1


def test_sts_list_policies_failure_is_partial_with_required_error():
    envelope = run(FakeFactory(FakeSts(), FakeOrganizationsListPoliciesFailure()), "global")

    assert envelope.status == "partial"
    assert [finding["resource_type"] for finding in envelope.resources] == ["sts_identity", "sts_organization"]
    assert any(error.operation == "organizations.ListPolicies" for error in envelope.errors)
    coverage = next(entry for entry in envelope.coverage if entry.check == "scp_policy")
    assert coverage.status == "error"
    assert coverage.failed == 1


def test_sts_describe_policy_failure_is_partial_with_resource_error():
    envelope = run(FakeFactory(FakeSts(), FakeOrganizationsDescribePolicyFailure()), "global")

    assert envelope.status == "partial"
    assert [finding["resource_type"] for finding in envelope.resources] == ["sts_identity", "sts_organization"]
    assert any(error.operation == "organizations.DescribePolicy" for error in envelope.errors)
    coverage = next(entry for entry in envelope.coverage if entry.check == "scp_policy_detail")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_sts_list_targets_failure_is_partial_but_emits_scp_without_targets():
    envelope = run(FakeFactory(FakeSts(), FakeOrganizationsTargetsFailure()), "global")

    assert envelope.status == "partial"
    assert [finding["resource_type"] for finding in envelope.resources] == ["sts_identity", "sts_organization", "sts_scp"]
    assert envelope.resources[2]["targets"] == []
    assert any(error.operation == "organizations.ListTargetsForPolicy" for error in envelope.errors)
    coverage = next(entry for entry in envelope.coverage if entry.check == "scp_targets")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_sts_get_caller_identity_failure_returns_error_envelope():
    envelope = run(FakeFactory(FakeStsFailure(), FakeOrganizationsDenied()), "global")

    assert envelope.status == "error"
    assert envelope.account_id == "unknown"
    assert envelope.resources == []
    assert len(envelope.errors) == 1
    assert envelope.errors[0].operation == "sts.GetCallerIdentity"
    assert envelope.errors[0].code == "InvalidClientTokenId"

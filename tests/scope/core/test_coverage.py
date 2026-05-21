import pytest

from scope.core.coverage import CoverageTracker
from scope.core.models import ErrorRecord


class FakeAwsError(Exception):
    def __init__(self, code: str, message: str = "failed"):
        super().__init__(message)
        self.response = {"Error": {"Code": code, "Message": message}}


def test_optional_access_denied_is_skipped_and_module_complete():
    tracker = CoverageTracker(primary=["get_caller_identity"], required=[])

    tracker.record_ok("get_caller_identity")
    tracker.record_skipped("organizations", reason="access_denied")

    coverage, errors = tracker.to_envelope_fields()

    assert tracker.derive_status() == "complete"
    assert errors == []
    assert [entry.model_dump() for entry in coverage] == [
        {
            "check": "get_caller_identity",
            "scope": "module_wide",
            "status": "complete",
            "succeeded": 1,
            "failed": 0,
            "skipped": 0,
            "reasons": [],
        },
        {
            "check": "organizations",
            "scope": "module_wide",
            "status": "skipped",
            "succeeded": 0,
            "failed": 0,
            "skipped": 1,
            "reasons": [{"code": "access_denied", "count": 1, "sample_resource": None}],
        },
    ]


def test_required_resource_failure_makes_module_partial():
    tracker = CoverageTracker(primary=["list_buckets"], required=["bucket_policy"])

    tracker.record_ok("list_buckets")
    tracker.record_ok("bucket_policy", resource="arn:aws:s3:::visible")
    tracker.record_resource_failure(
        "bucket_policy",
        resource="arn:aws:s3:::hidden",
        operation="s3.GetBucketPolicy",
        err=FakeAwsError("AccessDenied"),
    )

    coverage, errors = tracker.to_envelope_fields()
    bucket_policy = next(entry for entry in coverage if entry.check == "bucket_policy")

    assert tracker.derive_status() == "partial"
    assert bucket_policy.status == "partial"
    assert bucket_policy.succeeded == 1
    assert bucket_policy.failed == 1
    assert errors[0].operation == "s3.GetBucketPolicy"
    assert errors[0].resource == "arn:aws:s3:::hidden"
    assert errors[0].code == "AccessDenied"


def test_primary_module_failure_makes_module_error():
    tracker = CoverageTracker(primary=["list_buckets"], required=["bucket_policy"])

    tracker.record_module_failure("list_buckets", operation="s3.ListBuckets", err=FakeAwsError("AccessDenied"))

    coverage, errors = tracker.to_envelope_fields()

    assert tracker.derive_status() == "error"
    assert coverage[0].check == "list_buckets"
    assert coverage[0].status == "error"
    assert coverage[0].failed == 1
    assert errors[0].code == "AccessDenied"


def test_required_module_failure_makes_module_partial():
    tracker = CoverageTracker(primary=["list_buckets"], required=["bucket_policy"])

    tracker.record_ok("list_buckets")
    tracker.record_module_failure("bucket_policy", operation="s3.GetBucketPolicy", err=FakeAwsError("AccessDenied"))

    coverage, errors = tracker.to_envelope_fields()
    bucket_policy = next(entry for entry in coverage if entry.check == "bucket_policy")

    assert tracker.derive_status() == "partial"
    assert bucket_policy.status == "error"
    assert bucket_policy.failed == 1
    assert errors[0].operation == "s3.GetBucketPolicy"
    assert errors[0].code == "AccessDenied"


def test_resource_failures_without_successes_are_partial_entries():
    tracker = CoverageTracker(primary=["list_buckets"], required=["bucket_policy"])

    tracker.record_ok("list_buckets")
    tracker.record_resource_failure(
        "bucket_policy",
        resource="arn:aws:s3:::hidden",
        operation="s3.GetBucketPolicy",
        err=FakeAwsError("AccessDenied"),
    )

    coverage, errors = tracker.to_envelope_fields()
    bucket_policy = next(entry for entry in coverage if entry.check == "bucket_policy")

    assert tracker.derive_status() == "partial"
    assert bucket_policy.status == "partial"
    assert bucket_policy.succeeded == 0
    assert bucket_policy.failed == 1
    assert errors[0].code == "AccessDenied"


def test_resource_failure_accepts_error_record_from_parallel_result():
    tracker = CoverageTracker(primary=["list_tables"], required=["table_policy"])
    error = ErrorRecord(
        operation="dynamodb.DescribeTable",
        resource="arn:aws:dynamodb:us-east-1:123456789012:table/hidden",
        code="AccessDeniedException",
        message="denied",
    )

    tracker.record_ok("list_tables")
    tracker.record_resource_failure(
        "table_policy",
        resource=error.resource,
        operation=error.operation,
        err=error,
    )

    coverage, errors = tracker.to_envelope_fields()
    table_policy = next(entry for entry in coverage if entry.check == "table_policy")

    assert tracker.derive_status() == "partial"
    assert table_policy.reasons[0].code == "AccessDeniedException"
    assert errors[0].code == "AccessDeniedException"
    assert errors[0].message == "denied"


def test_module_failure_replaces_prior_events_for_same_check():
    tracker = CoverageTracker(primary=["list_buckets"], required=["bucket_policy"])

    tracker.record_ok("list_buckets", resource="arn:aws:s3:::visible")
    tracker.record_resource_failure(
        "list_buckets",
        resource="arn:aws:s3:::hidden",
        operation="s3.ListBuckets",
        err=FakeAwsError("AccessDenied"),
    )
    tracker.record_module_failure("list_buckets", operation="s3.ListBuckets", err=FakeAwsError("Throttling"))

    coverage, errors = tracker.to_envelope_fields()

    assert coverage[0].check == "list_buckets"
    assert coverage[0].scope == "module_wide"
    assert coverage[0].status == "error"
    assert coverage[0].succeeded == 0
    assert coverage[0].failed == 1
    assert [error.model_dump() for error in errors] == [
        {
            "operation": "s3.ListBuckets",
            "resource": None,
            "code": "Throttling",
            "message": "failed",
        }
    ]


@pytest.mark.parametrize("check", ["get_caller_identity", "required_check"])
def test_only_optional_checks_may_be_skipped(check):
    tracker = CoverageTracker(primary=["get_caller_identity"], required=["required_check"])

    with pytest.raises(ValueError, match="Only optional checks may be skipped"):
        tracker.record_skipped(check, reason="access_denied")


def test_coverage_entries_reasons_and_samples_are_deterministic():
    tracker = CoverageTracker(primary=["primary"], required=[])

    tracker.record_resource_failure("zeta", resource=None, operation="svc.Zeta", err=FakeAwsError("Throttling"))
    tracker.record_resource_failure("alpha", resource=None, operation="svc.Alpha", err=FakeAwsError("AccessDenied"))
    tracker.record_resource_failure(
        "zeta",
        resource="arn:aws:example:::zeta",
        operation="svc.Zeta",
        err=FakeAwsError("Throttling"),
    )
    tracker.record_resource_failure(
        "zeta",
        resource="arn:aws:example:::denied",
        operation="svc.Zeta",
        err=FakeAwsError("AccessDenied"),
    )

    coverage, _ = tracker.to_envelope_fields()
    zeta = next(entry for entry in coverage if entry.check == "zeta")

    assert [entry.check for entry in coverage] == ["alpha", "zeta"]
    assert [reason.model_dump() for reason in zeta.reasons] == [
        {"code": "AccessDenied", "count": 1, "sample_resource": "arn:aws:example:::denied"},
        {"code": "Throttling", "count": 2, "sample_resource": "arn:aws:example:::zeta"},
    ]

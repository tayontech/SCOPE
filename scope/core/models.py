from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator


ModuleName = Literal[
    "apigateway",
    "bedrock",
    "cloudfront",
    "codebuild",
    "cognito",
    "dynamodb",
    "ec2",
    "ecs",
    "iam",
    "kms",
    "lambda",
    "rds",
    "route53",
    "s3",
    "secrets",
    "sns",
    "sqs",
    "ssm",
    "sts",
]
ModuleStatus = Literal["complete", "partial", "error"]
CoverageStatus = Literal["complete", "partial", "skipped", "error"]
CoverageScope = Literal["module_wide", "per_resource"]


class CoverageReason(BaseModel):
    code: str
    count: int = Field(ge=1)
    sample_resource: str | None = None


class CoverageEntry(BaseModel):
    check: str
    scope: CoverageScope
    status: CoverageStatus
    succeeded: int = Field(ge=0)
    failed: int = Field(ge=0)
    skipped: int = Field(ge=0)
    reasons: list[CoverageReason] = Field(default_factory=list)


class ErrorRecord(BaseModel):
    operation: str
    resource: str | None = None
    code: str
    message: str | None = None


class TaskResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    index: int
    item: Any
    ok: bool
    value: Any | None = None
    error: ErrorRecord | None = None
    exception: Exception | None = None


class ModuleEnvelope(BaseModel):
    model_config = ConfigDict(extra="allow")

    module: ModuleName
    account_id: str
    region: str
    status: ModuleStatus
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resources: list[dict[str, Any]]
    coverage: list[CoverageEntry] = Field(default_factory=list)
    errors: list[ErrorRecord] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def strip_legacy_findings(cls, data: Any) -> Any:
        if isinstance(data, dict) and "findings" in data:
            data = data.copy()
            data.pop("findings", None)
        return data

    @model_validator(mode="after")
    def validate_account_id(self) -> "ModuleEnvelope":
        if self.account_id == "unknown":
            if self.status != "error":
                raise ValueError("account_id='unknown' is only valid when status='error'")
            return self

        if len(self.account_id) != 12 or not self.account_id.isdigit():
            raise ValueError("account_id must be a 12-digit AWS account ID")
        return self

    @field_serializer("timestamp", when_used="json")
    def serialize_timestamp(self, value: datetime) -> str:
        normalized = value.astimezone(timezone.utc)
        return normalized.isoformat().replace("+00:00", "Z")

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator


Severity = Literal["critical", "high", "medium", "low"]
Category = Literal[
    "privilege_escalation",
    "trust_misconfiguration",
    "data_exposure",
    "credential_risk",
    "excessive_permission",
    "network_exposure",
    "persistence",
    "post_exploitation",
    "lateral_movement",
]
Transition = Literal[
    "invoke",
    "execute_as",
    "assume_role",
    "pass_role",
    "create_compute",
    "mutate_policy",
    "resource_policy_access",
    "data_access",
    "decrypt",
    "event_injection",
]
ValidationType = Literal[
    "graph",
    "iam",
    "resource_policy",
    "runtime_assumption",
    "coverage_caveat",
]
EvidenceType = Literal[
    "graph_edge",
    "module_resource",
    "policy_document",
    "runtime_assumption",
    "coverage_caveat",
]
ImpactType = Literal[
    "admin_access",
    "data_access",
    "persistence",
    "lateral_movement",
    "exfiltration",
    "defense_evasion",
]
ValidationStatus = Literal["validated", "conditional", "rejected"]
PromotionDecision = Literal["promote", "observe", "drop"]
FinalValidationStatus = Literal["validated", "conditional"]
NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class AttackBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceRef(AttackBaseModel):
    type: EvidenceType
    id: NonEmptyStr | None = None
    source_path: NonEmptyStr | None = None
    arn: NonEmptyStr | None = None
    field: NonEmptyStr | None = None

    @model_validator(mode="after")
    def require_handle(self) -> EvidenceRef:
        if not any([self.id, self.source_path, self.arn]):
            raise ValueError("evidence must include id, source_path, or arn")
        return self


class AttackContext(AttackBaseModel):
    principal: NonEmptyStr | None = None
    capabilities: list[NonEmptyStr] = Field(default_factory=list)


class StartingPosition(AttackBaseModel):
    type: Literal["external", "principal", "resource", "public_endpoint"]
    id: NonEmptyStr
    arn: NonEmptyStr | None = None


class Hop(AttackBaseModel):
    id: NonEmptyStr
    transition: Transition
    from_context: NonEmptyStr
    action: NonEmptyStr
    target: NonEmptyStr
    resulting_context: NonEmptyStr
    capability_gained: NonEmptyStr
    required: bool = True
    validation_type: ValidationType
    evidence: list[EvidenceRef] = Field(default_factory=list)
    assumptions: list[NonEmptyStr] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_evidence_or_assumption(self) -> Hop:
        if self.validation_type == "runtime_assumption":
            if not self.assumptions:
                raise ValueError("runtime_assumption hops require assumptions")
            return self
        if not self.evidence:
            raise ValueError("non-runtime hops require evidence")
        return self


class Impact(AttackBaseModel):
    type: ImpactType
    resource: NonEmptyStr
    action: NonEmptyStr


class AttackCandidate(AttackBaseModel):
    id: NonEmptyStr
    name: NonEmptyStr
    category: Category
    severity: Severity
    starting_position: StartingPosition
    initial_context: AttackContext
    hops: list[Hop]
    impact: Impact
    affected_resources: list[NonEmptyStr] = Field(default_factory=list)
    detection_opportunities: list[NonEmptyStr] = Field(default_factory=list)
    mitre_techniques: list[NonEmptyStr] = Field(default_factory=list)
    remediation: list[NonEmptyStr] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_hops(self) -> AttackCandidate:
        if not self.hops:
            raise ValueError("candidate attack paths require at least one hop")
        return self


class SecurityObservation(AttackBaseModel):
    id: NonEmptyStr
    severity: Severity
    description: NonEmptyStr
    affected_resources: list[NonEmptyStr] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    reason_not_path: NonEmptyStr


class AttackValidation(AttackBaseModel):
    candidate_id: NonEmptyStr
    status: ValidationStatus
    promotion_decision: PromotionDecision
    reason: NonEmptyStr
    validated_hops: list[NonEmptyStr] = Field(default_factory=list)
    conditional_hops: list[NonEmptyStr] = Field(default_factory=list)
    failed_hops: list[NonEmptyStr] = Field(default_factory=list)
    untested_hops: list[NonEmptyStr] = Field(default_factory=list)
    runtime_assumptions: list[NonEmptyStr] = Field(default_factory=list)
    coverage_caveats: list[NonEmptyStr] = Field(default_factory=list)
    final_context: NonEmptyStr | None = None
    validated_impact: Impact | None = None

    @model_validator(mode="after")
    def align_status_and_promotion(self) -> AttackValidation:
        allowed_decisions = {
            "validated": "promote",
            "conditional": "promote",
            "rejected": "drop",
        }
        if self.promotion_decision != allowed_decisions[self.status]:
            raise ValueError("validation status and promotion decision are inconsistent")
        if self.status == "validated" and self.failed_hops:
            raise ValueError("validated candidates cannot have failed hops")
        if self.status == "conditional" and not (
            self.conditional_hops or self.runtime_assumptions or self.coverage_caveats
        ):
            raise ValueError(
                "conditional validation requires conditional hops, runtime assumptions, or caveats"
            )
        return self


class FinalAttackPath(AttackBaseModel):
    id: NonEmptyStr
    source_candidate_id: NonEmptyStr
    validation_status: FinalValidationStatus
    name: NonEmptyStr
    severity: Severity
    category: Category
    description: NonEmptyStr
    hops: list[Hop]
    runtime_assumptions: list[NonEmptyStr] = Field(default_factory=list)
    coverage_caveats: list[NonEmptyStr] = Field(default_factory=list)
    affected_resources: list[NonEmptyStr] = Field(default_factory=list)
    detection_opportunities: list[NonEmptyStr] = Field(default_factory=list)
    mitre_techniques: list[NonEmptyStr] = Field(default_factory=list)
    remediation: list[NonEmptyStr] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_consistent_final_path(self) -> FinalAttackPath:
        if not self.hops:
            raise ValueError("final attack paths require structured hops")
        if self.validation_status == "conditional" and not (
            self.runtime_assumptions or self.coverage_caveats
        ):
            raise ValueError(
                "conditional final paths require runtime assumptions or coverage caveats"
            )
        return self

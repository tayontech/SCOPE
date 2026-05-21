from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Literal

from .models import CoverageEntry, CoverageReason, ErrorRecord


EventKind = Literal["ok", "skipped", "resource_failure", "module_failure"]


@dataclass(frozen=True)
class CoverageEvent:
    check: str
    kind: EventKind
    resource: str | None
    operation: str | None
    code: str | None
    message: str | None


def error_code(err: Exception | ErrorRecord) -> str:
    if isinstance(err, ErrorRecord):
        return err.code

    response = getattr(err, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict) and error.get("Code"):
            return str(error["Code"])
    return err.__class__.__name__ or "Error"


def error_message(err: Exception | ErrorRecord) -> str | None:
    if isinstance(err, ErrorRecord):
        return err.message

    response = getattr(err, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict) and error.get("Message"):
            return str(error["Message"])
    return str(err)


class CoverageTracker:
    def __init__(self, primary: list[str], required: list[str]):
        self.primary = set(primary)
        self.required = set(required)
        self._events: list[CoverageEvent] = []

    def record_ok(self, check: str, resource: str | None = None) -> None:
        self._events.append(CoverageEvent(check, "ok", resource, None, None, None))

    def record_skipped(self, check: str, resource: str | None = None, reason: str = "skipped") -> None:
        if check in self.primary or check in self.required:
            raise ValueError("Only optional checks may be skipped")
        self._events.append(CoverageEvent(check, "skipped", resource, None, reason, reason))

    def record_resource_failure(
        self,
        check: str,
        resource: str | None,
        operation: str,
        err: Exception | ErrorRecord,
    ) -> None:
        self._events.append(
            CoverageEvent(check, "resource_failure", resource, operation, error_code(err), error_message(err))
        )

    def record_module_failure(self, check: str, operation: str, err: Exception | ErrorRecord) -> None:
        self._events = [event for event in self._events if event.check != check]
        self._events.append(
            CoverageEvent(check, "module_failure", None, operation, error_code(err), error_message(err))
        )

    def derive_status(self) -> Literal["complete", "partial", "error"]:
        for event in self._events:
            if event.kind == "module_failure" and event.check in self.primary:
                return "error"

        for event in self._events:
            if event.kind == "module_failure" and event.check in self.required:
                return "partial"

        for event in self._events:
            if event.kind == "resource_failure" and event.check in self.required:
                return "partial"

        return "complete"

    def to_envelope_fields(self) -> tuple[list[CoverageEntry], list[ErrorRecord]]:
        by_check: dict[str, list[CoverageEvent]] = defaultdict(list)
        for event in self._events:
            by_check[event.check].append(event)

        coverage = [self._entry_for(check, by_check[check]) for check in sorted(by_check)]
        errors = [
            ErrorRecord(
                operation=event.operation or event.check,
                resource=event.resource,
                code=event.code or "Error",
                message=event.message,
            )
            for event in self._events
            if event.kind in {"resource_failure", "module_failure"}
        ]
        return coverage, errors

    def _entry_for(self, check: str, events: list[CoverageEvent]) -> CoverageEntry:
        succeeded = sum(1 for event in events if event.kind == "ok")
        failed = sum(1 for event in events if event.kind in {"resource_failure", "module_failure"})
        skipped = sum(1 for event in events if event.kind == "skipped")
        module_failed = any(event.kind == "module_failure" for event in events)

        if module_failed:
            status = "error"
        elif failed and succeeded:
            status = "partial"
        elif failed:
            status = "partial"
        elif skipped and not succeeded:
            status = "skipped"
        else:
            status = "complete"

        reason_counts: Counter[str] = Counter()
        reason_samples: dict[str, str | None] = {}
        for event in events:
            if event.kind in {"resource_failure", "module_failure", "skipped"}:
                code = event.code or "unknown"
                reason_counts[code] += 1
                if code not in reason_samples or reason_samples[code] is None:
                    reason_samples[code] = event.resource

        reasons = [
            CoverageReason(code=code, count=count, sample_resource=reason_samples[code])
            for code, count in sorted(reason_counts.items())
        ]

        scope = "per_resource" if any(event.resource is not None for event in events) else "module_wide"
        return CoverageEntry(
            check=check,
            scope=scope,
            status=status,
            succeeded=succeeded,
            failed=failed,
            skipped=skipped,
            reasons=reasons,
        )

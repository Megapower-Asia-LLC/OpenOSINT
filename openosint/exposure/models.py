"""Immutable data model for the exposure report. The JSON shape is built by to_dict()."""

from __future__ import annotations

from dataclasses import asdict, dataclass

STATUS_OK, STATUS_ERROR, STATUS_SKIPPED = "ok", "error", "skipped"


class CheckError(Exception):
    """A check could not complete; reported as status=error and excluded from the score."""


class DomainNotRegistered(ValueError):
    """The registrable domain does not exist (RDAP 404): the whole report would be meaningless."""


class CheckSkipped(Exception):
    """A check does not apply (e.g. TLD without RDAP); reported as status=skipped."""


@dataclass(frozen=True)
class Finding:
    id: str  # stable snake_case, see scoring.SEVERITY_BY_ID
    category: str  # email | registration | tls | http_headers
    severity: str  # critical | high | medium | low | info
    title: str
    evidence: str  # the raw value observed
    recommendation: str  # one sentence


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str  # ok | error | skipped
    noise: str  # tool_policy.Noise value: "passive" (DNS/registry only) or "touches target"
    reason: str | None = None  # short human reason for error / skipped (<= 80 chars)
    detail: str | None = None  # full technical message; only in --json
    findings: tuple[Finding, ...] = ()
    notes: tuple[str, ...] = ()  # non-finding remarks, e.g. "www has no DNS record"


@dataclass(frozen=True)
class ExposureReport:
    domain: str  # the host as given
    registrable_domain: str  # eTLD+1, used for RDAP and DMARC organizational fallback
    checked_at: str  # UTC ISO 8601
    duration_ms: int
    checks: tuple[CheckResult, ...]
    score: int | None  # None when no check completed
    grade: str | None  # A-F, "incomplete" (email or TLS missing), or None
    score_is_partial: bool  # True when grade is "incomplete"
    grade_capped_by_critical: bool
    excluded_checks: tuple[str, ...]  # every check with status error/skipped
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "registrable_domain": self.registrable_domain,
            "checked_at": self.checked_at,
            "duration_ms": self.duration_ms,
            "grade": self.grade,
            "score": self.score,
            "score_is_partial": self.score_is_partial,
            "grade_capped_by_critical": self.grade_capped_by_critical,
            "excluded_checks": list(self.excluded_checks),
            "checks": {
                c.name: {"status": c.status, "reason": c.reason, "detail": c.detail, "noise": c.noise, "notes": list(c.notes)}
                for c in self.checks
            },
            "findings": [asdict(f) for f in self.findings],
        }

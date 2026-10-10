"""Immutable data model for the exposure report. The JSON shape is built by to_dict()."""

from __future__ import annotations

from dataclasses import asdict, dataclass

STATUS_OK, STATUS_ERROR, STATUS_SKIPPED = "ok", "error", "skipped"


# Stable codes for why a check errored or was skipped. Each needs IT and EN text in the report
# catalogs (a test enforces it); the raw English detail stays in --json only.
REASON_CODES = (
    "no_rdap_for_tld",
    "tls_verification_failed",
    "www_not_in_dns",
    "timeout",
    "dns_error",
    "unreachable",
    "name_not_resolved",
    "rdap_error",
    "unexpected_error",
    "check_failed",
)


def _checked_code(code: str) -> str:
    if code not in REASON_CODES:
        raise ValueError(f"unknown reason code: {code}")
    return code


class CheckError(Exception):
    """A check could not complete; reported as status=error and excluded from the score."""

    def __init__(self, message: str, code: str = "check_failed") -> None:
        super().__init__(message)
        self.code = _checked_code(code)


class DomainNotRegistered(ValueError):
    """The registrable domain does not exist (RDAP 404): the whole report would be meaningless."""


class CheckSkipped(Exception):
    """A check does not apply (e.g. TLD without RDAP); reported as status=skipped."""

    def __init__(self, message: str, code: str = "check_failed") -> None:
        super().__init__(message)
        self.code = _checked_code(code)


@dataclass(frozen=True)
class Finding:
    id: str  # stable snake_case, see scoring.SEVERITY_BY_ID
    category: str  # email | registration | tls | http_headers
    severity: str  # critical | high | medium | low | info
    title: str
    evidence: str  # the raw value observed
    recommendation: str  # one sentence
    days_left: int | None = None  # expiry findings only; used by the HTML report, not in --json


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str  # ok | error | skipped
    noise: str  # tool_policy.Noise value: "passive" (DNS/registry only) or "touches target"
    reason: str | None = None  # short human reason for error / skipped (<= 80 chars)
    detail: str | None = None  # full technical message; only in --json
    reason_code: str | None = None  # one of REASON_CODES; drives the translated report text
    findings: tuple[Finding, ...] = ()
    notes: tuple[str, ...] = ()  # non-finding remarks, e.g. "www has no DNS record"
    note_codes: tuple[str, ...] = ()  # REASON_CODES entries parallel to notes, for the report


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
                c.name: {"status": c.status, "reason": c.reason, "reason_code": c.reason_code, "detail": c.detail, "noise": c.noise, "notes": list(c.notes)}
                for c in self.checks
            },
            "findings": [{k: v for k, v in asdict(f).items() if k != "days_left"} for f in self.findings],
        }

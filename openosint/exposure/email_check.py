"""Email security: MX, SPF, DMARC and best-effort DKIM. DNS only."""

from __future__ import annotations

import dns.exception
import dns.resolver

from openosint.exposure.models import STATUS_OK, CheckError, CheckResult
from openosint.exposure.scoring import finding
from openosint.tool_policy import Noise
from openosint.tools.search_dns import probe_dkim

CAT = "email"
DNS_TIMEOUT = 5.0
DKIM_PROBE_TIMEOUT = 2.0  # 10 sequential probes must fit the command's time budget
SPF_MAX_LOOKUPS = 10  # RFC 7208 4.6.4
# A domain that receives no mail can still be used to send spoofed mail.
NO_MAIL_SPF_FIX = 'This domain has no MX: publish "v=spf1 -all" so nobody can send mail as it.'
NO_MAIL_DMARC_FIX = "This domain has no MX: publish a DMARC record with p=reject so spoofed mail is rejected."
_LOOKUP_MECHS = ("include", "a", "mx", "ptr", "exists")


def _resolver(timeout: float = DNS_TIMEOUT) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = r.lifetime = timeout
    return r


def _txt(name: str) -> list[str]:
    """TXT strings for name, [] if none. Timeouts/SERVFAIL propagate (check -> error)."""
    try:
        answers = _resolver().resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return ["".join(s.decode("utf-8", "replace") for s in r.strings) for r in answers]


def _mx(domain: str) -> list[str]:
    try:
        return [f"{r.preference} {r.exchange}" for r in _resolver().resolve(domain, "MX")]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN as exc:
        raise CheckError(f"{domain} does not exist (NXDOMAIN)", "name_not_resolved") from exc


def _probe_dkim(domain: str) -> tuple[list[str], bool]:
    return probe_dkim(_resolver(DKIM_PROBE_TIMEOUT), domain)


def _spf_records(name: str) -> list[str]:
    return [r for r in _txt(name) if r.lower().startswith("v=spf1")]


def count_spf_lookups(spf: str, depth: int = 0) -> int:
    """DNS-lookup terms in an SPF record, following include/redirect (depth-limited)."""
    count = 0
    for term in spf.split()[1:]:
        t = term.lstrip("+-~?").lower()
        mech = t.split(":", 1)[0].split("/", 1)[0].split("=", 1)[0]
        if mech not in _LOOKUP_MECHS and mech != "redirect":
            continue
        count += 1
        if mech in ("include", "redirect") and depth < SPF_MAX_LOOKUPS:
            target = t.split(":", 1)[-1] if ":" in t else t.split("=", 1)[-1]
            sub = _spf_records(target)
            if sub:
                count += count_spf_lookups(sub[0], depth + 1)
        if count > SPF_MAX_LOOKUPS:
            break
    return count


def _spf_findings(domain: str, has_mail: bool) -> list:
    records = _spf_records(domain)
    if not records:
        return [finding("spf_missing", CAT, "No SPF record", f"no v=spf1 TXT record at {domain}",
                        "Publish an SPF record listing the servers allowed to send mail for the domain."
                        if has_mail else NO_MAIL_SPF_FIX)]
    spf, out = records[0], []
    terms = spf.lower().split()
    qualifier = next((t[0] if t[0] in "+-~?" else "+" for t in terms if t.lstrip("+-~?") == "all"), None)
    if qualifier == "+":
        out.append(finding("spf_plus_all", CAT, "SPF allows any sender (+all)", spf,
                           "Replace +all with -all (or ~all while testing) so only listed senders pass."))
    elif qualifier == "~":
        out.append(finding("spf_softfail", CAT, "SPF soft-fail (~all)", spf,
                           "Move from ~all to -all once all legitimate senders are listed."))
    elif qualifier == "?":
        out.append(finding("spf_neutral", CAT, "SPF neutral (?all) gives no protection", spf,
                           "Replace ?all with -all so spoofed mail is rejected."))
    lookups = count_spf_lookups(spf)
    if lookups > SPF_MAX_LOOKUPS:
        out.append(finding("spf_too_many_lookups", CAT, f"SPF needs more than {SPF_MAX_LOOKUPS} DNS lookups",
                           f"{lookups}{'+' if lookups > SPF_MAX_LOOKUPS else ''} lookups in: {spf}",
                           "Flatten or trim include: entries; receivers treat >10 lookups as a permanent error."))
    return out


def _dmarc_findings(host: str, registrable: str, has_mail: bool) -> list:
    """DMARC at _dmarc.<host>, else the organizational domain (RFC 7489 6.6.3)."""
    checked = [host] if host == registrable else [host, registrable]
    for name in checked:
        records = [r for r in _txt(f"_dmarc.{name}") if r.lower().startswith("v=dmarc1")]
        if records:
            source = f"_dmarc.{name}"
            break
    else:
        return [finding("dmarc_missing", CAT, "No DMARC record",
                        "no v=DMARC1 TXT at " + " or ".join(f"_dmarc.{n}" for n in checked),
                        "Publish a DMARC record, starting with p=none and a rua= address, then move to reject."
                        if has_mail else NO_MAIL_DMARC_FIX)]
    raw = f"{records[0]} (found at {source})"
    records_text = records[0]
    tags = {k.strip().lower(): v.strip() for k, _, v in (p.partition("=") for p in records_text.split(";")) if k.strip()}
    out = []
    if tags.get("p", "none").lower() == "none":
        out.append(finding("dmarc_policy_none", CAT, "DMARC policy is p=none (monitoring only)", raw,
                           "Move to p=quarantine, then p=reject, once reports show legitimate mail passes."))
    pct = tags.get("pct")
    if pct is not None and pct.isdigit() and int(pct) < 100:
        out.append(finding("dmarc_pct_below_100", CAT, f"DMARC applies to only {pct}% of mail", raw,
                           "Raise pct to 100 so the policy covers all mail."))
    if "rua" not in tags:
        out.append(finding("dmarc_no_rua", CAT, "DMARC has no aggregate report address", raw,
                           "Add rua=mailto:... so you receive reports on who sends mail as your domain."))
    return out


def run(domain: str, registrable: str) -> CheckResult:
    mx = _mx(domain)
    findings = []
    if not mx:
        findings.append(finding("mx_missing", CAT, "No MX record", "no MX records",
                                "If the domain should receive mail, add MX records; otherwise publish a null MX."))
    findings += _spf_findings(domain, has_mail=bool(mx))
    findings += _dmarc_findings(domain, registrable, has_mail=bool(mx))
    # Always probed here (DNS-only, info-only, never scored); search_dns keeps its own active-tools gate.
    found, wildcard = _probe_dkim(domain)
    if not found:
        why = "wildcard DKIM DNS answers every selector" if wildcard else "none of the common selectors answered"
        findings.append(finding(
            "dkim_not_found_common_selectors", CAT, "DKIM not found on common selectors (best-effort, not conclusive)",
            why, "Confirm DKIM signing is enabled; a custom selector would not be found by this check."))
    return CheckResult("email", STATUS_OK, Noise.PASSIVE.value, findings=tuple(findings))

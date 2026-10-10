"""TLS on port 443 of the apex and www: validity, expiry, issuer, hostname match, version."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

from openosint.exposure.models import STATUS_OK, CheckError, CheckResult
from openosint.exposure.scoring import finding
from openosint.tool_policy import Noise

CAT = "tls"
TIMEOUT = 10
PORT = 443
# OpenSSL verify codes (X509_V_ERR_*)
_VERIFY_EXPIRED, _VERIFY_HOSTNAME = 10, 62
_OLD_VERSIONS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


def _connect(host: str, verify: bool) -> tuple[bytes, str]:
    """Handshake on 443; return (DER certificate, negotiated version)."""
    ctx = ssl.create_default_context()
    if not verify:  # only used to read cert details after verification failed
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1  # so a legacy server shows its version, not a handshake error
    except (ValueError, ssl.SSLError):
        pass  # ponytail: OpenSSL builds that refuse TLS<1.2 report such servers as a failed handshake instead
    with socket.create_connection((host, PORT), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True), tls.version() or "unknown"


def _describe(der: bytes) -> tuple[datetime, str, list[str]]:
    cert = x509.load_der_x509_certificate(der)
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    issuer = next((a.value for a in cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)), None) or \
        cert.issuer.rfc4514_string()
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    return not_after, str(issuer), list(sans)


def _check_host(host: str) -> list:
    """Findings for one host. gaierror/OSError propagate to the caller."""
    failure: ssl.SSLCertVerificationError | None = None
    try:
        try:
            der, version = _connect(host, verify=True)
        except ssl.SSLCertVerificationError as exc:
            failure = exc
            der, version = _connect(host, verify=False)
        except ssl.SSLError:  # handshake itself failed; retry unverified before giving up
            der, version = _connect(host, verify=False)
    except ssl.SSLError as exc:
        return [finding("tls_handshake_failed", CAT, f"TLS handshake with {host} failed",
                        f"{host}: port 443 accepts connections but no TLS handshake succeeded: {exc}",
                        "Enable TLS 1.2 or 1.3 with a valid certificate on the server.")]
    not_after, issuer, sans = _describe(der)
    days = (not_after - datetime.now(timezone.utc)).days
    evidence = f"{host}: {version}, issuer {issuer}, expires {not_after.date()} ({days} days), SANs {', '.join(sans) or 'none'}"
    out = []
    code = getattr(failure, "verify_code", None)
    if code == _VERIFY_HOSTNAME:
        out.append(finding("tls_hostname_mismatch", CAT, f"Certificate does not match {host}", evidence,
                           "Install a certificate that covers this hostname."))
    elif failure is not None and code != _VERIFY_EXPIRED and days >= 0:
        reason = getattr(failure, "verify_message", None) or str(failure)
        out.append(finding("tls_cert_invalid_chain", CAT, f"Certificate for {host} failed verification",
                           f"{evidence}; {reason}", "Serve the full intermediate chain from a trusted CA."))
    if code == _VERIFY_EXPIRED or days < 0:  # an expired cert yields only this finding, never the lt_N windows
        out.append(finding("tls_cert_expired", CAT, f"Certificate for {host} has expired", evidence,
                           "Renew the certificate immediately and automate renewal."))
    elif 0 <= days < 14:
        out.append(finding("tls_cert_expires_lt_14d", CAT, f"Certificate for {host} expires in under 14 days",
                           evidence, "Renew the certificate now and automate renewal.", days))
    elif 0 <= days < 30:
        out.append(finding("tls_cert_expires_lt_30d", CAT, f"Certificate for {host} expires in under 30 days",
                           evidence, "Renew the certificate soon and automate renewal.", days))
    if version in _OLD_VERSIONS:
        out.append(finding("tls_version_below_1_2", CAT, f"{host} negotiated {version}", evidence,
                           "Disable TLS versions below 1.2 on the server."))
    return out


def run(domain: str, registrable: str) -> CheckResult:
    findings, notes, note_codes = [], [], []
    # www.<input> only for an apex input; a subdomain input checks just that host.
    for host in (domain, f"www.{domain}") if domain == registrable else (domain,):
        try:
            findings += _check_host(host)
        except socket.gaierror as exc:
            if host == domain:
                raise CheckError(f"{host} does not resolve: {exc}", "name_not_resolved") from exc
            notes.append(f"{host} skipped: no DNS record")
            note_codes.append("www_not_in_dns")
        except OSError as exc:  # refused, timeout, reset: no usable HTTPS service
            findings.append(finding("tls_unreachable_443", CAT, f"No HTTPS service on {host}:443",
                                    f"{host}: {type(exc).__name__}: {exc}",
                                    "If the site should serve HTTPS, check the firewall and listener."))
    return CheckResult("tls", STATUS_OK, Noise.TOUCHES_TARGET.value, findings=tuple(findings), notes=tuple(notes),
                       note_codes=tuple(note_codes))

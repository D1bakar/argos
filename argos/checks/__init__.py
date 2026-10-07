"""Checks package: importing this module registers all check plugins."""

from argos.checks.active import (  # noqa: F401
    cmdi,
    cors,
    default_creds,
    forced_browse,
    idor,
    jwt,
    methods,
    sqli,
    ssrf,
    ssti,
    traversal,
    xss,
    xxe,
)
from argos.checks.deps import osv  # noqa: F401
from argos.checks.passive import (  # noqa: F401
    cookies,
    csrf,
    fingerprint,
    info_disclosure,
    security_headers,
    target_info,
    tls,
)

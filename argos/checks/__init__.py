"""Checks package: importing this module registers all check plugins."""

from argos.checks.active import (  # noqa: F401
    cache_poison,
    cmdi,
    cors,
    default_creds,
    forced_browse,
    idor,
    jwt,
    methods,
    smuggling,
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
    secrets,
    security_headers,
    takeover,
    target_info,
    tls,
)

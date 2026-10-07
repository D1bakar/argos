"""Checks package: importing this module registers all check plugins."""

from argos.checks.deps import osv  # noqa: F401
from argos.checks.passive import (  # noqa: F401
    cookies,
    fingerprint,
    info_disclosure,
    security_headers,
    target_info,
    tls,
)

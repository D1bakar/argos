"""CVSS v3.1 base score calculation (for normalizing severity across checks)."""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _pr_value(privileges: str, scope_changed: bool) -> float:
    if privileges == "N":
        return 0.85
    if privileges == "L":
        return 0.68 if scope_changed else 0.62
    return 0.5 if scope_changed else 0.27  # H


def _roundup(value: float) -> float:
    return math.ceil(value * 10.0) / 10.0


def cvss31_base_score(vector: str) -> float | None:
    """Parse a CVSS:3.1 vector string and return the base score (0-10).

    Returns None if the vector can't be parsed.
    """
    if not vector or not vector.startswith("CVSS:3"):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" not in part:
            return None
        key, _, value = part.partition(":")
        metrics[key.upper()] = value.upper()
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = _pr_value(metrics["PR"], metrics["S"] == "C")
        ui = _UI[metrics["UI"]]
        conf = _CIA[metrics["C"]]
        integ = _CIA[metrics["I"]]
        auth = _CIA[metrics["A"]]
        scope_changed = metrics["S"] == "C"
    except KeyError:
        return None

    exploitability = 8.22 * av * ac * pr * ui
    iss = 1.0 - (1.0 - conf) * (1.0 - integ) * (1.0 - auth)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0
    return _roundup(min(impact + exploitability, 10.0))

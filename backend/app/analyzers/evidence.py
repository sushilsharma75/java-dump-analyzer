"""Shared evidence identifiers and capture compatibility checks."""

import hashlib
from datetime import datetime


def stamp(findings):
    for f in findings:
        f.evidence_id = (
            "E-"
            + hashlib.sha256(
                (f.category + f.title + "|".join(f.evidence)).encode()
            ).hexdigest()[:12]
        )
        if not f.verification:
            f.verification = [
                "Repeat the capture under comparable load and check whether this observation persists."
            ]
    return findings


def compatibility(a, b, ordered=False):
    """Missing provenance reduces confidence; explicit conflicts prevent comparison."""
    if (
        ordered
        and a.get("analysis_id")
        and a.get("analysis_id") == b.get("analysis_id")
    ):
        return False, ["The same analysis is not an independent capture."]
    ca, cb = a.get("capture") or {}, b.get("capture") or {}
    warnings = []
    for k in ("process_id", "process_start", "build_id"):
        if ca.get(k) and cb.get(k) and ca[k] != cb[k]:
            return False, [f"Incompatible captures: {k} differs."]
        if not ca.get(k) or not cb.get(k):
            warnings.append(f"Capture {k} is unverified.")
    if a.get("truncated") or b.get("truncated"):
        return False, [
            "A capture is a partial dump; numerical comparison is not valid."
        ]
    if (
        a.get("sizing_model")
        and b.get("sizing_model")
        and a["sizing_model"] != b["sizing_model"]
    ):
        return False, ["Object sizing models differ."]
    if not ordered and ca.get("captured_at") and cb.get("captured_at"):
        try:
            gap = abs(
                (
                    datetime.fromisoformat(ca["captured_at"])
                    - datetime.fromisoformat(cb["captured_at"])
                ).total_seconds()
            )
            if gap > 300:
                return False, [
                    "Capture times differ by more than five minutes; temporal correlation is not valid."
                ]
        except (ValueError, TypeError):
            warnings.append("Capture timestamps cannot be aligned.")
    if ordered:
        try:
            ta = datetime.fromisoformat(ca["captured_at"])
            tb = datetime.fromisoformat(cb["captured_at"])
            if tb <= ta:
                return False, ["The second capture must be later than the first."]
        except (KeyError, ValueError, TypeError):
            warnings.append("Capture interval is unknown.")
    return True, warnings

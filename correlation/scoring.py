"""
Risk / severity scoring for reconstructed incidents.

Plan §3/§6: "Risk/severity scoring (aggregate + pattern-match boost)". This is
a transparent, explainable scoring function — not a learned model — so it can
be justified line-by-line in a viva.

score = base_severity(template)              # pattern-match boost: a matched
                                             #   chain is inherently more severe
                                             #   than a lone flagged event
      + aggregate signal from member events  # mean anomaly/severity
      + volume factor                        # more corroborating events = higher
clamped to [0, 1].
"""

from statistics import mean
from typing import List


SEVERITY_BANDS = [
    (0.85, "critical"),
    (0.65, "high"),
    (0.45, "medium"),
    (0.0, "low"),
]

# Lookup table: recommended response keyed on (attack_type, severity band).
# Plan §7 scopes "recommended response" to exactly this — a lookup table, not a
# generative model.
_PLAYBOOK = {
    "brute_force": {
        "critical": "Disable the targeted account, force password reset, and block the source IP at the edge. Review all actions taken in the compromised session.",
        "high": "Lock the account, require MFA re-enrolment, and rate-limit the source IP.",
        "default": "Alert the account owner and monitor for further failed-login bursts.",
    },
    "data_exfiltration": {
        "critical": "Revoke the session token immediately, quarantine the affected data store, and open a data-loss incident. Preserve logs for forensics.",
        "high": "Suspend the user's data-export privileges and review the downloaded objects.",
        "default": "Flag the transfer for analyst review and confirm business justification.",
    },
    "port_scan": {
        "critical": "Block the source IP at the firewall and check whether any probed service responded as open.",
        "high": "Block the source IP and raise the IDS sensitivity for the targeted subnet.",
        "default": "Add the source IP to the watchlist and monitor for follow-on connections.",
    },
    "api_abuse": {
        "critical": "Throttle and then block the API key/IP, and check for data scraping in the response logs.",
        "high": "Apply aggressive rate limiting to the source and alert the API owner.",
        "default": "Enforce standard rate limits and monitor the request pattern.",
    },
}


def _band(score: float) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "low"


def _signal(ev: dict) -> float:
    """Per-event signal strength: prefer the detector's anomaly_score, fall
    back to the event's severity."""
    s = ev.get("anomaly_score")
    if s is None:
        s = ev.get("severity", 0.0) or 0.0
    return float(s)


def score_incident(base_severity: float, member_events: List[dict]) -> dict:
    """Return {severity_score, severity, confidence} for a matched chain."""
    signals = [_signal(e) for e in member_events] or [0.0]
    agg = mean(signals)
    n = len(member_events)
    volume_factor = min(0.10, 0.02 * max(0, n - 3))  # up to +0.10 for long chains

    score = base_severity + 0.15 * (agg - 0.3) + volume_factor
    score = max(0.0, min(1.0, score))

    severity = _band(score)
    # Confidence blends chain completeness (a full template match is implied by
    # being here) with the mean detector signal.
    confidence = max(0.0, min(0.99, 0.55 + 0.45 * agg))

    return {
        "severity_score": round(score, 3),
        "severity": severity,
        "confidence": round(confidence, 3),
    }


def recommended_action(attack_type: str, severity: str) -> str:
    table = _PLAYBOOK.get(attack_type, {})
    return table.get(severity, table.get("default", "Escalate to a security analyst for review."))

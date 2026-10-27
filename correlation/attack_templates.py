"""
Attack-chain templates for the correlation engine.

Each template is a sequence (or burst) of event types, linked by shared
entities within a time window. The matcher (matcher.py) walks flagged events
and stitches a template match into one incident.

Scope (project plan §5, §7): exactly four templates, one per signal class.
The port_scan and api_abuse templates — previously blocked pending a schema
decision — are unblocked now that the schema carries a primitive
`connection_attempt` event type and the injectors emit api_call bursts.

Fields on the canonical event each template assumes (see
p2-pipeline/schema/event_schema.json): event_type, timestamp, user, ip,
session, severity, metadata. Correlation only ever runs over events the
detection engine has flagged, so these templates do not re-check severity.
"""

from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass
class TemplateStep:
    event_type: str
    max_gap_seconds: int
    min_count: int = 1
    # Optional extra predicate on the event dict, beyond its type — e.g.
    # "a file_access that is a download, not a read."
    event_filter: Optional[Callable[[dict], bool]] = None


@dataclass
class AttackTemplate:
    name: str                 # internal id
    display_name: str         # shown in the UI / incident.attack_pattern
    attack_type: str          # one of the scoped attack labels
    description: str
    steps: List[TemplateStep]
    link_by: List[str]
    window_seconds: int
    base_severity: float = 0.6   # floor severity before scoring adjustments


def _is_download(e: dict) -> bool:
    return e.get("metadata", {}).get("action") == "download"


# 1. Brute force -> credential compromise -> exfiltration (auth signal class)
BRUTE_FORCE = AttackTemplate(
    name="brute_force_compromise",
    display_name="Credential Brute Force",
    attack_type="brute_force",
    description=(
        "A burst of failed logins, then a successful login, then access to a "
        "database and a file download — all tied to the same user."
    ),
    steps=[
        TemplateStep("auth_login_failure", max_gap_seconds=120, min_count=5),
        TemplateStep("auth_login_success", max_gap_seconds=60),
        TemplateStep("db_query", max_gap_seconds=180),
        TemplateStep("file_access", max_gap_seconds=180, event_filter=_is_download),
    ],
    link_by=["user", "session"],
    window_seconds=900,
    base_severity=0.85,
)

# 2. Data exfiltration without a brute-force precursor (volume signal class)
DATA_EXFILTRATION = AttackTemplate(
    name="data_exfiltration",
    display_name="Data Exfiltration",
    attack_type="data_exfiltration",
    description="A login followed by a large database read and a bulk file download, same session.",
    steps=[
        TemplateStep("auth_login_success", max_gap_seconds=0),
        TemplateStep("db_query", max_gap_seconds=300),
        TemplateStep("file_access", max_gap_seconds=300, event_filter=_is_download),
    ],
    link_by=["user", "session"],
    window_seconds=900,
    base_severity=0.8,
)

# 3. Port / network scan (network signal class)
PORT_SCAN = AttackTemplate(
    name="port_scan",
    display_name="Port Scan",
    attack_type="port_scan",
    description="Many connection attempts to different ports from one source IP in a short window.",
    steps=[
        TemplateStep("connection_attempt", max_gap_seconds=30, min_count=15),
    ],
    link_by=["ip"],
    window_seconds=180,
    base_severity=0.6,
)

# 4. API abuse / rate burst (rate signal class)
API_ABUSE = AttackTemplate(
    name="api_abuse",
    display_name="API Abuse / Rate Burst",
    attack_type="api_abuse",
    description="A burst of API calls from one source IP far above the normal request rate.",
    steps=[
        TemplateStep("api_call", max_gap_seconds=10, min_count=25),
    ],
    link_by=["ip"],
    window_seconds=180,
    base_severity=0.55,
)

# Order matters for dedupe: more specific / longer chains first so that when an
# attack matches both BRUTE_FORCE and DATA_EXFILTRATION, the richer one wins.
ALL_TEMPLATES = [BRUTE_FORCE, DATA_EXFILTRATION, PORT_SCAN, API_ABUSE]
TEMPLATES_BY_NAME = {t.name: t for t in ALL_TEMPLATES}

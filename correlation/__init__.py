"""Nexora correlation & reconstruction engine.

Public API:
    from correlation import reconstruct_incidents
    incidents = reconstruct_incidents(events)   # events: list[canonical event dict]
"""

from .engine import reconstruct_incidents, CorrelationEngine  # noqa: F401
from .attack_templates import ALL_TEMPLATES, TEMPLATES_BY_NAME  # noqa: F401

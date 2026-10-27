"""
Builds an entity-linked event graph: events are nodes, and edges connect
events that share an entity (user, ip, session) within a sliding time
window. This is the structure the template matcher (matcher.py) walks to
find attack chains.

WEEK 2 FIX: link field was "source_ip", the canonical schema
(p2-pipeline/schema/event_schema.json) calls it "ip". Also: add_event() now
accepts a timestamp as either a datetime or an ISO 8601 string, because
that's what P2's simulator actually emits (Event.timestamp is a string) --
Week 1's version assumed datetime objects and would have broken on real data.
"""

import networkx as nx
from datetime import datetime, timedelta, timezone

LINK_FIELDS = ["user", "ip", "session"]
DEFAULT_WINDOW = timedelta(minutes=10)


def _as_datetime(ts):
    """Accept either a datetime or an ISO 8601 string (P2's simulator emits strings)."""
    dt = ts if isinstance(ts, datetime) else datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class EventGraph:
    def __init__(self, window: timedelta = DEFAULT_WINDOW):
        self.graph = nx.DiGraph()
        self.window = window

    def add_event(self, event: dict, link: bool = True):
        """
        event must contain at least: id, event_type, timestamp,
        plus whichever entity fields it has (user / ip / session).
        timestamp can be a datetime or an ISO 8601 string.
        """
        event = dict(event)  # don't mutate caller's dict
        event["timestamp"] = _as_datetime(event["timestamp"])
        self.graph.add_node(event["id"], **event)
        if link:
            self._link_related_events(event)

    def _link_related_events(self, event: dict):
        event_time = event["timestamp"]
        for node_id, data in list(self.graph.nodes(data=True)):
            if node_id == event["id"]:
                continue
            if abs(event_time - data["timestamp"]) > self.window:
                continue
            shared_fields = [
                f for f in LINK_FIELDS
                if event.get(f) and event[f] != "unknown" and event[f] == data.get(f)
            ]
            if shared_fields:
                # directed edge: earlier event -> later event
                if data["timestamp"] <= event_time:
                    self.graph.add_edge(node_id, event["id"], shared=shared_fields)
                else:
                    self.graph.add_edge(event["id"], node_id, shared=shared_fields)

    def get_entity_events(self, entity_field: str, entity_value):
        """All events tied to one entity value (e.g. one specific user), sorted by time."""
        events = [
            data for _, data in self.graph.nodes(data=True)
            if data.get(entity_field) == entity_value
        ]
        return sorted(events, key=lambda e: e["timestamp"])

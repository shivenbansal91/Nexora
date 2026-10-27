"""
Matches attack-chain templates against sequences of flagged events in the
event graph. Deliberately simple, greedy sequential matcher -- not a
general subgraph-isomorphism solver -- which is the right level of
complexity for this project and is easy to explain in a viva.

Known simplification (fine for now, revisit if it becomes a problem):
if two templates could plausibly overlap on the same events, this matcher
doesn't backtrack to try alternate groupings.
"""

from datetime import timedelta

try:  # works both as a package (backend) and as a script (python matcher.py)
    from .attack_templates import AttackTemplate, ALL_TEMPLATES
except ImportError:  # pragma: no cover
    from attack_templates import AttackTemplate, ALL_TEMPLATES


def match_template(graph, template: AttackTemplate, flagged_event_ids):
    matches = []
    flagged_events = [graph.graph.nodes[eid] for eid in flagged_event_ids]
    flagged_events.sort(key=lambda e: e["timestamp"])

    groups = {}
    for e in flagged_events:
        key = tuple(e.get(f) for f in template.link_by)
        if any(v in (None, "", "unknown") for v in key):
            continue
        groups.setdefault(key, []).append(e)

    for key, events in groups.items():
        if len(template.steps) == 1:
            step = template.steps[0]
            bursts = [[]]
            for event in events:
                if event["event_type"] != step.event_type or (step.event_filter and not step.event_filter(event)):
                    continue
                burst = bursts[-1]
                if burst and (event["timestamp"] - burst[-1]["timestamp"] > timedelta(seconds=step.max_gap_seconds)
                              or event["timestamp"] - burst[0]["timestamp"] > timedelta(seconds=template.window_seconds)):
                    bursts.append([])
                bursts[-1].append(event)
            for burst in bursts:
                if len(burst) >= step.min_count:
                    matches.append({
                        "template_name": template.name, "display_name": template.display_name,
                        "attack_type": template.attack_type, "description": template.description,
                        "matched_events": [event["id"] for event in burst],
                        "entity": dict(zip(template.link_by, key)),
                        "start_time": burst[0]["timestamp"], "end_time": burst[-1]["timestamp"],
                    })
            continue
        step_idx = 0
        step_matches = []
        matched_steps = []
        last_event_time = None

        for e in events:
            if last_event_time is not None and (
                e["timestamp"] - last_event_time > timedelta(seconds=template.steps[step_idx].max_gap_seconds)
                or e["timestamp"] - (matched_steps[0][0]["timestamp"] if matched_steps else step_matches[0]["timestamp"]) > timedelta(seconds=template.window_seconds)
            ):
                step_idx, step_matches, matched_steps, last_event_time = 0, [], [], None
            step = template.steps[step_idx]

            if e["event_type"] != step.event_type:
                continue
            if step.event_filter is not None and not step.event_filter(e):
                continue

            step_matches.append(e)
            last_event_time = e["timestamp"]

            if len(step_matches) >= step.min_count:
                matched_steps.append(step_matches)
                step_idx += 1
                step_matches = []

            if step_idx == len(template.steps):
                all_matched = [ev for group in matched_steps for ev in group]
                matches.append({
                    "template_name": template.name,
                    "display_name": template.display_name,
                    "attack_type": template.attack_type,
                    "description": template.description,
                    "matched_events": [e["id"] for e in all_matched],
                    "entity": dict(zip(template.link_by, key)),
                    "start_time": all_matched[0]["timestamp"],
                    "end_time": all_matched[-1]["timestamp"],
                })
                step_idx, step_matches, matched_steps, last_event_time = 0, [], [], None

    return matches


def run_all_templates(graph, flagged_event_ids):
    incidents = []
    for template in ALL_TEMPLATES:
        incidents.extend(match_template(graph, template, flagged_event_ids))
    return incidents

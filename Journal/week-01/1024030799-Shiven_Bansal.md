# Week 1 — P3: Correlation & Reconstruction

## Objective

Set up the initial correlation and reconstruction engine using NetworkX and define the initial attack-chain templates.

## Work Completed

- Set up the `correlation/` module.
- Added a directed NetworkX event graph.
- Implemented entity-based event linking using:
  - user
  - source IP
  - session
- Added a sliding time-window constraint for related events.
- Defined initial attack-chain templates.
- Implemented the initial sequential pattern matcher.
- Added a synthetic credential-compromise scenario for validation.
- Verified that related flagged events can be reconstructed into a single incident.

## Files Added

- `attack_templates.py`
- `graph_builder.py`
- `matcher.py`
- `example_run.py`

## Validation

The synthetic credential-compromise scenario successfully matched the corresponding attack-chain template and produced a reconstructed incident.

## Key Concepts Learned

- NetworkX `DiGraph`
- Nodes and node attributes
- Directed edges and edge attributes
- Entity-based event correlation
- Sliding time windows
- Sequential attack-pattern matching

## Current Limitations

- Matcher currently uses sequential/greedy template matching.
- Testing currently uses synthetic/mock events.
- Severity scoring and integration with the real detection pipeline are future tasks.

## Next Week

- Expand testing with additional attack scenarios.
- Refine entity-linked graph behavior.
- Test attack templates against more varied event sequences.
- Prepare the correlation engine for integration with the event pipeline.
"""
Manual integration check: feed the FULL pipeline (simulator -> detection ->
correlation) real output and confirm:

  1. Normal traffic alone produces ZERO incidents (false-positive check).
  2. Each scoped attack is reconstructed into exactly one correctly-typed
     incident.

This mirrors tests/test_pipeline.py but prints a human-readable summary. Run
from the repo root:

    python -m correlation.integration_check
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "p2-pipeline")):
    if p not in sys.path:
        sys.path.insert(0, p)

from simulator.generator import NormalTrafficGenerator, iso  # noqa: E402
from simulator.injectors import AttackInjector, ATTACK_TYPES  # noqa: E402
from detection import Detector  # noqa: E402
from correlation import reconstruct_incidents  # noqa: E402


def _spread(events, base, step=1.5):
    t = base
    for e in events:
        e.timestamp = iso(t)
        t += timedelta(seconds=step)
    return events


def main():
    det = Detector.load()
    print(f"Detection models loaded: {det.ml_loaded}\n")

    gen = NormalTrafficGenerator(seed=7)
    inj = AttackInjector(seed=7)
    base = datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc)

    # 1. normal only
    normal = [e.to_dict() for e in _spread(list(gen.stream_sessions(40)), base)]
    det.annotate(normal)
    incs = reconstruct_incidents(normal)
    print(f"[normal] {len(normal)} events, {sum(e['flagged'] for e in normal)} flagged "
          f"-> {len(incs)} incidents (expected 0)")

    # 2. each attack
    for atk in ATTACK_TYPES:
        n = [e.to_dict() for e in _spread(list(gen.stream(25)), base)]
        a = [e.to_dict() for e in inj.inject(atk, start_time=base + timedelta(seconds=20))]
        window = n + a
        det.annotate(window)
        incs = reconstruct_incidents(window)
        summary = ", ".join(f"{i['attack_pattern']}[{i['severity']},conf={i['confidence']}]" for i in incs)
        print(f"[{atk}] -> {len(incs)} incident(s): {summary}")


if __name__ == "__main__":
    main()

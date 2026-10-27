"""Root pytest config: put the simulator package (under the hyphenated
p2-pipeline folder) and the repo-root packages on sys.path so tests can
`import simulator`, `import detection`, `import correlation`."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for p in (ROOT, ROOT / "p2-pipeline"):
    sp = str(p)
    if sp not in sys.path:
        sys.path.insert(0, sp)

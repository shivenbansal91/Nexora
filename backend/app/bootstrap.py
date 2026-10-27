"""
Path bootstrap. The simulator lives under p2-pipeline/ (a folder whose hyphen
makes it an invalid Python package name), and detection/ + correlation/ are
repo-root packages. Importing this module first puts both on sys.path so the
backend can `import simulator`, `import detection`, `import correlation`.

In Docker this is also handled by PYTHONPATH, but importing here keeps local
`uvicorn backend.app.main:app` working with no extra env setup.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
P2_PIPELINE = REPO_ROOT / "p2-pipeline"

for p in (REPO_ROOT, P2_PIPELINE):
    sp = str(p)
    if sp not in sys.path:
        sys.path.insert(0, sp)

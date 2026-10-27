# Nexora verification — 7 October 2026

## Assessment

The project is a useful, working incident-reconstruction prototype. Its four
scoped attack scenarios now work through generation, detection, correlation,
storage, REST and WebSocket delivery. It is suitable for a local or protected
demonstration. It is not yet an operational security product: it generates
simulated telemetry, has no authentication or real log ingestion, and its
offline anomaly detector still misses some attacks. The intended deployment
for this semester project is local, using SQLite and a loopback-only server.

## Fixed

- Removed fabricated 1,240,000-event and 14-anomaly offsets and the hardcoded
  dashboard growth percentage. Counts recover from persisted data on restart.
- Read uploaded CICIDS2017 CSVs directly from `data/raw` and nested folders;
  bounded random sampling avoids concatenating the entire dataset in memory.
- Generated `data/processed/metrics_real.json` from the uploaded data and wired
  Analytics to prefer it. Real offline benchmarks and simulated correlation
  checks are explicitly distinguished. Models fit training data; anomaly
  thresholds and preprocessing use a separate labelled validation split,
  and the displayed benign FPR belongs to the anomaly detector being evaluated.
- Removed unnecessary pairwise graph construction during template matching.
  Expired partial chains reset; later chains for the same entity can match;
  missing entities are excluded; credential chains stay within their session.
- Keep a burst as one incident, update its evidence as further events arrive,
  and use longer hashed incident IDs to reduce collisions.
- Persist and broadcast earlier events when a burst subsequently flags them.
  Detector rules no longer flag unrelated old calls/probes merely because a
  newer burst shares their IP.
- Retain failed event writes for retry, report degraded pipeline health, move
  detection/storage work off the async event loop, and bound slow-client sends.
- Remove delayed decorative graph choreography from the visible graph. The
  graph uses actual incident evidence, supports mouse/keyboard node selection,
  displays named IP/user/authentication/API/database/file/host entities with
  glowing icons and curved shared-evidence links. Selecting a node shows its
  related event descriptions and metadata, and links to the
  corresponding incident. Correlation cards select their own incident.
- Notifications now show actual incidents and link to their expanded evidence.
  Removed the unused search bar, inert Settings button and fake profile control.
- Refresh snapshots on WebSocket reconnection and merge updates by ID, keeping
  the newest event first and preventing duplicate rows. Failed injection shows
  an error. Development API routing also works when Vite changes its port.
- Add keyboard focus, reduced-motion styling, compact navigation, clearer
  metric labels, and a descriptive page title. Preserve the visual theme.
- Use reproducible frontend dependency installation, exclude raw data/secrets
  from Docker context, run the container as a non-root user, add health checks,
  require a configured database password, and bind Compose to localhost.
  SPA file serving cannot return files outside the frontend directory.

## Measured uploaded-data evaluation

Seed 42; 99,900 training, 39,961 validation and 59,941 test rows after cleaning a random
sample of up to 200,000 flows. The classifier and IsolationForest in this
benchmark use network-flow features; they are separate from the model scoring
the live simulator's application events.

| Measurement | Result |
| --- | ---: |
| Classifier accuracy | 0.9975 |
| Classifier macro F1 | 0.8817 |
| Classifier binary attack recall | 0.9926 |
| Classifier binary attack F1 | 0.9942 |
| Anomaly precision | 0.6885 |
| Anomaly recall | 0.4504 |
| Anomaly F1 | 0.5445 |
| Anomaly benign false-positive rate | 0.0498 |

These are offline row-split results, not a guarantee on unseen organisations
or future traffic. Rare classes have very small support or are absent from
the sample. The anomaly model uses signed-log flow features and 4,096 samples
per tree, selected from six candidates on validation F1 with a 5% validation
false-positive budget. Training fits benign flows only; threshold calibration
is semi-supervised because validation labels are used. Test data is excluded
from model/threshold selection. Recall increased from 0.0856 to 0.4504, with
benign FPR increasing from 0.0101 to 0.0498. This remains an offline benchmark,
and random row splits can benefit from duplicate/similar flows across splits.

## Verification completed

- `python -m pytest -q`: **33 passed**.
  Covers all four attacks, benign traffic, schema consistency, incremental
  flags, persisted complete burst evidence, restart counts, repeated/expired
  chains, isolation of older calls, failed-write retry, tied-score threshold
  calibration and normal pacing without delaying injected attacks.
- `npm run lint --prefix frontend`: passed.
- `npm run build --prefix frontend`: passed.
- `node tests/test_event_display.mjs`: passed. High model scores on unflagged
  events remain suspicious; they are not displayed as confirmed threats.
- Live integration against the running backend: injected each of the four
  attacks through REST, received the matching new incident over WebSocket,
  and fetched persisted evidence through the incident API. Health, metrics,
  events and entities endpoints also responded correctly.
- Browser checks: live connection and event updates, node description changes,
  incident deep link and expanded evidence, notification dropdown, real-data
  Analytics table, and infrastructure entities. The backend was restarted and
  the browser reconnected with persisted incidents intact.
- Updated UI verified on desktop and a 390px phone viewport: named entity
  selection, database metadata, threat filtering, expanded event rows,
  notification-to-incident navigation and correlation-card selection work.
  Fixed mobile horizontal overflow and accessible names on icon navigation.
  Browser console reported no errors; live backend health reports models loaded.
- `git diff --check`: passed.
- Docker CLI is unavailable on this machine; image build, Compose startup,
  container health and Postgres integration have **not** been executed here.

## Deployment requirements and limits

See README for launch commands. Use one application process/worker. The
simulator, queue, rolling window and WebSocket clients are process-local.
Remote access requires an authenticated TLS reverse proxy with WebSocket
support and an appropriate CORS origin. There is no built-in account system.
Historical database rows and ID sets grow with runtime; long-running operation
needs retention planning. Injected attacks are simulation commands, and
recommended actions do not automatically block or remediate anything.

Events really are generated and delivered continuously at runtime. They are
simulated organisation events, not a replay of the uploaded CSVs or live
monitoring of this computer. Normal traffic defaults to one event every three
seconds, independently of the faster attack queue. The default tick waits
0.6 seconds after processing;
actual delivery cadence also includes processing, storage and transport time.

# Nexora ML, correlation and interface review

Review date: 2 November 2026. Scope: local semester-project deployment.
Follow-up implementation: [rotating-IP and model update](ML_UPGRADE.md).
That document supersedes the original live-model parameters and measurements below.
Source was inspected and baseline checks ran before product code was changed.
No model was retrained, no benchmark was replaced, and no historical database
records were deleted or migrated during this review.

## Overall assessment

Nexora is a working simulation of event monitoring and incident reconstruction.
It is a hybrid system: ML supplies an anomaly score; hand-written rules flag
events; templates reconstruct four known attack patterns. It is not an ML-only
attack detector, an automatic incident responder, or a collector of real device
logs. The frontend is functional, but calling it perfect would be unsupported.

## What actually runs

| Component | Live behavior | Important distinction |
| --- | --- | --- |
| Simulator | Generates normal application events and four injected scenarios | CSV uploads do not become live events |
| Application Isolation Forest | Scores a 17-column engineered feature matrix | Score does not by itself set `flagged=True` |
| Detector rules | Set flags and attack labels | The rule thresholds decide which events enter incident matching |
| Correlation engine | Groups events by identity and matches time-ordered templates | Not a learned graph model; only four patterns are defined |
| Simulated Random Forest | Trained and saved by the baseline training script | Not loaded or invoked by the live pipeline |
| CICIDS Isolation Forest / Random Forest | Offline evaluation using numeric network-flow columns | Different features and models; results are not live alert accuracy |
| Incident evidence score | Template and signal-strength formula | Not a calibrated probability, even when its stored field is called `confidence` |

## Confirmed bugs and changes

1. **Rules inflated the ML score.** A rule raised `anomaly_score` to at least
   0.8, concealing the model's output. Reproduced on an API burst: its first
   score changed from about 0.342 to 0.8. Rules now leave the ML score intact.
2. **Ground-truth labels leaked into live output.** A single injected login
   retained `data_exfiltration` even though it was unflagged and no attack chain
   existed. Unflagged events now receive the detector label `benign`; rules
   must establish the attack label. Training labels remain in training data.
3. **Repeated retries counted as a scan.** Twenty-five connections to one
   host and port produced a scan incident. Detection and matching now require
   at least 15 distinct host/port destinations.
4. **Missing sessions linked unrelated accounts.** Empty, null or `unknown`
   sessions could attach other users' logins to an exfiltration. Context now
   requires a valid user/session pair; missing IPs are not grouped as one source.
5. **Session context was unbounded or looked forward.** Brute-force rules
   flagged old activity in a reused session; exfiltration rules could flag
   future logins and other accounts. Brute-force context is now bounded after
   actual failure bursts; exfiltration context is same-user/session and within
   the preceding 600 seconds.
6. **The exfiltration template did not check its own description.** A three-row
   query could satisfy a supposedly large database read. The template now
   requires a SELECT of at least 50,000 rows and a download of at least
   10,000,000 bytes.
7. **A model without normalization was reported as loaded.** Scores could
   silently depend on each batch's minimum and maximum. Loading now requires
   the expected feature count and finite, increasing normalization bounds;
   incompatible artifacts fall back to rules-only mode.
8. **Simulated classifier FPR was labelled as anomaly FPR.** Future training
   outputs calculate the two separately. Legacy simulated metrics lacking the
   anomaly FPR now show it as unavailable rather than displaying classifier FPR.
9. **Reconnect snapshots could preserve stale events/incidents.** Cached
   records previously won over new REST snapshots. Snapshots now replace old
   records while preserving WebSocket updates arriving during the fetch;
   responses from an earlier reconnect are ignored.
10. **Failed writes could inflate the anomaly counter.** Flagged IDs now enter
    the saved count only after a successful database commit.
11. **Infrastructure included invented service names.** The fixed list of
    production-looking hosts was removed. Event sources now reflect observed
    authentication/API/database/file/network event types.
12. **Presentation copy overstated the system.** Removed the quote, sidebar
    slogan, mountain-card slogan and promotional heading. The overview now
    uses factual monitoring copy. Percentage confidence is presented as a
    heuristic evidence score; four-scenario checks are not called general
    correlation accuracy. Dashboard counts display actual values immediately.
    Secondary text is darker, and event review uses the evaluation threshold
    of 0.6 rather than a separate 0.4 threshold.

Earlier saved event scores and incident payloads remain historical data. The
corrected scoring/linking behavior applies to newly processed events; this
review does not retroactively certify old incidents.

## Parameters inspected

| Parameter | Actual value | Assessment |
| --- | --- | --- |
| Live IF trees | 200 | Reasonable baseline; more trees alone will not fix data leakage |
| Live IF `max_samples` | `auto`, fitted as 256 | Different from the 4,096-sample offline flow model |
| Live IF contamination | `auto` | Does not determine this app's flags; code calls `score_samples`, not `predict` |
| Live IF seed | 42 | Reproducible model fit |
| Live score normalization | training p1=0.4248593, p99=0.6237653 | Linear clipping, not probability calibration |
| Application score review threshold | normalized 0.6 | Approximate raw score 0.544203; used for evaluation/UI review, not rule flagging |
| Simulated RF | 200 trees, balanced class weights, unlimited depth, leaf size 1 | Can exploit easy generator signals and correlated rows |
| Brute force | 5 failures in 120 seconds, same user/session | Misses distributed and multi-session attacks |
| Scan | 15 distinct host/port targets in 60 seconds, same IP | Low-and-slow scans can remain below the threshold |
| API burst | 25 calls in 30 seconds, same IP | Needs workload-specific calibration; normal batch jobs/NAT can look suspicious |
| Bulk download trigger | 10 MB | Volume alone does not prove theft |
| Exfiltration template | login, SELECT >=50,000 rows, download >=10 MB | Explicit local-demo heuristic, not an industry-wide threshold |
| Pipeline | tick 0.6s, one normal event about every 3s, attack spread 6s | Demo timing; compressed attacks differ from training-time spacing |
| Rolling state | 15 minutes, maximum 800 events | High rates shorten effective context |

Changing contamination is not a substitute for calibrating an operating
threshold: the code uses continuous scores and its own decisions. See the
[official Isolation Forest API](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html).

## Evaluation weaknesses and measurements

### Simulated classifier

Rebuilt the existing default feature dataset and reproduced the seed-42
70/30 stratified event-row split: 13,962 training and 5,984 test rows.
**5,429 of 5,984 test feature vectors (90.73%) are identical to at least one
training feature vector.** Identical features need not mean duplicate raw
events; the low-dimensional generator naturally repeats patterns. Nevertheless,
this test set provides weak evidence of generalisation to new behavior.
Session members can also occur in both splits because rows are split after
window feature extraction.

The saved classifier gives generator-supplied **severity 31.01% of impurity-based
feature importance**, the largest individual feature. Importance is not proof
of causation, but severity is an easy generator shortcut: ordinary events are
assigned low severity and injected attacks higher severity. In real logs, an
equivalent reliable severity field may not exist. Its reported perfect simulated
classification therefore must not be presented as real-world detection accuracy.

### Loaded live Isolation Forest diagnostic

Without retraining, evaluated the loaded model on a separate generator sample:
seed 142, 100 benign windows and 30 windows for each of four attack types,
4,915 total events, normalized threshold 0.6.

| Measurement | Result |
| --- | ---: |
| Precision | 0.8195 |
| Recall | 0.6418 |
| F1 | 0.7198 |
| Benign false-positive rate | 0.1316 |

These are score-only diagnostic results from generated data, not live rule-alert
accuracy or a new held-out benchmark. The sample size, time-of-day distribution
and generator mix differ from the original training evaluation. They expose
sensitivity to evaluation conditions; they do not establish deployment accuracy.

### Existing uploaded-flow benchmark

The stored CICIDS result is dated **7 October 2026**, not this review date.
It was inspected rather than rerun or tuned:

- Isolation Forest: precision 0.6885, recall 0.4504, F1 0.5445, benign FPR 0.0498.
- Random Forest: binary attack recall 0.9926; multiclass macro-F1 0.8817.
- Weak classes remain: Bot recall 0.6047 (43 test examples), web brute-force
  recall 0.5526 (38), and XSS recall 0.2727 (11).
- The flow benchmark uses 50/20/30 train/validation/test splits. Signed-log
  preprocessing, sample count and threshold were chosen on validation data
  under a 5% benign FPR budget, not on the test split.
- Random row splits can put related or duplicate flows in multiple partitions.
  The loader does not preserve source-day/group IDs for a stronger split.
  Rare labels can be absent from the sampled data.
- The optional UNSW loader concatenates its provided train/test files and
  resplits them. It should preserve the official test boundary before its
  results are compared with published UNSW benchmarks.
- Offline flow models are not saved/deployed by this benchmark. Copying their
  thresholds into the application detector would be invalid: feature schemas
  and score distributions differ.

## Improvements in priority order

1. **Repair evaluation before tuning.** Split generated windows/sessions
   before extracting features; use unseen generator seeds/scenarios for test
   data. Preserve flow file/day IDs and use held-out days or groups. Audit exact
   duplicates and conflicting labels without allowing test data to guide fitting.
   Keep a final untouched test set. See scikit-learn guidance on
   [data leakage](https://scikit-learn.org/stable/common_pitfalls.html)
   and [group/time-aware validation](https://scikit-learn.org/stable/modules/cross_validation.html).
2. **Remove shortcuts in a separate training experiment.** Compare with/without
   generator severity and time-of-day. Include hard benign examples: legitimate
   exports, batch API clients, auth mistakes, backups and retry storms. Measure
   the cost of each feature using ablations, not feature importance alone.
3. **Match live traffic to training assumptions.** Use session-shaped normal
   traffic, realistic inter-arrival times, and both compressed and uncompressed
   attack scenarios. The current runtime uses independent normal events while
   training uses session-shaped events. Train on real application logs only
   after a consistent event schema and trustworthy labels are available.
4. **Calibrate the actual live operating point.** Select an acceptable benign
   FPR on independent validation traffic, report precision/recall/FPR per attack,
   and keep ML review signals distinct from rule alerts. If ML-driven alerts are
   required, introduce an explicitly validated ML alert policy; do not silently
   assign one of four known attack labels to every unusual event.
5. **Tune modestly after the split is fixed.** Compare IF sample counts 256,
   1,024 and 4,096 and choose on validation performance/latency. Test RF depth
   and leaf-size limits. Do not optimise for aggregate accuracy on imbalanced
   data; use macro-F1, per-class recall, PR curves, FPR and uncertainty intervals.
6. **Strengthen correlation evaluation.** Add benign lookalikes, overlapping
   attacks, missing events, delays, shared IPs, reused accounts and slow attacks.
   Measure incident precision/recall and evidence completeness, not only four
   generator examples. Greedy matching can still miss alternative chains;
   missing required steps prevent a full incident even when isolated alerts exist.
7. **Calibrate probabilities only if needed.** The evidence score is deliberately
   a heuristic. A probability claim needs independent labels and a calibration
   assessment; renaming a number or multiplying it by 100 cannot supply one.

## Frontend assessment

Code checks cover routes, snapshot handling, graph selection, factual copy,
incident expansion state, responsive rules and the production build. The
decorative quotes are removed; the requested named graph and existing visual
theme are preserved. Default services are no longer presented as observed hosts.

Remaining limitations:

- **Rendered verification did not run in this review.** Windows browser
  automation stopped because it could not verify the current browser URL.
  No new desktop/mobile screenshots, keyboard traversal, measured rendered
  contrast, 200% zoom or physical touch-device checks were completed.
- The Impeccable context/detector executable was unavailable; manual source
  inspection was used. No invented UI health score is reported.
- Dense graph labels, small metadata and breakpoint behavior need a rendered
  pass before calling the interface polished for every device.
- The graph shows incident co-membership/shared evidence, not proof of causal
  traffic between every displayed pair of nodes.
- Dashboard incident totals are historical records, despite the legacy API
  name `active_threats`; there is no resolve/acknowledge workflow.
- REST snapshot failures are still swallowed in LiveContext; the socket can
  be connected while historical fetches fail. This needs a dedicated error
  state for full offline/error robustness.
- Some stale frontend scenario/choreography code remains unused. It was traced;
  it does not supply the current graph or Analytics results.

## Verification

- Before changes: **33 Python tests passed**, frontend lint/build passed.
- Added negative regression cases: nine initially failed; the fixes made them
  pass. Also reproduced and fixed the failed-write anomaly counter separately.
- After changes: **45 Python tests passed**; frontend lint and production build
  passed; Node event-display and reconnect-snapshot checks passed.
- Restarted the local backend with the fixes: health OK, ML model loaded,
  all four correlation self-check scenarios passed, observed event sources
  returned correctly, and the built dashboard returned HTTP 200.
- Trained-model parameters, feature importance, simulated feature overlap and
  existing benchmark provenance were inspected without retraining.
- No visual perfection, real-log effectiveness, public production readiness,
  or statistically calibrated attack probability is claimed.

Local deployment still requires one application process. There is no built-in
authentication, ingestion adapter, retention job or automatic attack prevention.
Those are future operational work, not prerequisites for the local semester demo.

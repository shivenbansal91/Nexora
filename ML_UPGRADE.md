# Rotating-IP detection and application-model update

2 November 2026. Supersedes the live-model parameters in ML_REVIEW.md;
the separate stored CICIDS benchmark has not been retrained or changed.

## Changing IP addresses

An IP address is a source attribute, not a reliable person identifier. Failures
targeting the same known account are now counted across IPs and sessions: five
failures within 120 seconds trigger a rule alert and an Account login attack
incident. It explicitly does not claim successful compromise.

If a successful login and subsequent database/file activity follow, the fuller
Credential Brute Force incident links failures by account and follows access
within the successful login's session. The evidence graph includes the source
IPs actually present; failures and compromise can upgrade the same incident.
Other users' failures are not combined just to reach the threshold.

Limits: a legitimate user repeatedly failing authentication can trigger the
same rule. Low-and-slow attempts and attacks changing all accounts/sessions/IPs
can evade these rules. Device identifiers, reliable authentication outcomes,
target endpoints, and independently evaluated campaign-level patterns would be
needed to strengthen coverage. IP geolocation alone cannot prove identity.

## Training changes

- Removed generator severity and hour-of-day from application features.
- Added account failure source diversity over 120 seconds and distinct
  connection destinations over 60 seconds. There are 17 features with a stored
  name/order manifest; incompatible model artifacts fall back to rules-only.
- Generated complete independent windows before feature extraction. Training
  seed 42 has 25,218 rows; validation seed 43 has 9,480. Final test seed 45 has
  9,484. Test data is never used in the parameter/threshold selection function.
- Development seed 44 exposed missing destination diversity before the feature
  schema was frozen. Seed 45 was reserved as the fresh final holdout; results
  have not been used for further tuning.
- Included independent and session-shaped normal traffic, legitimate bulk
  exports, repeated connection retries, rotating-IP login failures, and both
  compressed and original attack timings.
- Isolation Forest fits benign training data only. Sample counts 256, 1,024
  and 4,096 are compared on validation F1 under a 2% benign FPR budget.
  Selected: 200 trees, 4,096 samples per tree; raw threshold 0.5860126289.
- Display scores are monotonically scaled so 0.6 represents the selected
  review threshold. These scores remain non-probabilistic.
- Offline application Random Forest uses 200 trees, depth 16, minimum leaf 3,
  balanced class weights. It remains separate from live rule flagging.
- Previous model artifacts are retained in `detection/models/backups/`.
  Rollback must restore the corresponding feature implementation as well as
  artifacts; older models cannot be mixed with the changed feature schema.

## Final synthetic holdout results

The backed-up previous application model was evaluated on the same final
scenario generation using its original feature extractor and old threshold.
This is a trade-off comparison, not a claim of real-log performance.

| Isolation Forest score-only metric | Previous | Updated |
| --- | ---: | ---: |
| Precision | 72.70% | 94.82% |
| Recall | 85.77% | 60.73% |
| F1 | 78.69% | 74.04% |
| Benign false-positive rate | 19.31% | 1.99% |

The updated operating point reduces false positives and improves precision,
while sacrificing recall and aggregate F1. It is not a universal improvement.
Results are synthetic and depend on the generator and its prevalence of attacks.

Updated score-only recall per attack:

| Attack | Recall |
| --- | ---: |
| Brute force | 91.31% |
| API abuse | 92.56% |
| Data exfiltration | 30.37% |
| Port scan | 0.00% |

The Isolation Forest should not be deployed alone: its current selected
operating point misses scans and most exfiltration events. Distinct-destination
scan rules and volume/sequence rules provide the corresponding live coverage;
the four rule/template scenarios still pass their independent checks.

The application Random Forest achieved accuracy 89.07%, macro-F1 79.48%, scan
F1 96.73%, but exfiltration precision only 14.44%. Legitimate exports and theft
can be nearly indistinguishable in the available features. Raising volume
thresholds or collecting more examples of the same generator cannot establish
permission or business justification. Reliable authorization/resource context
and real held-out application logs are the next meaningful improvements.

Analytics now shows application-model evaluation, including per-attack recall,
separately from the uploaded network-flow benchmark. Neither is live rule-alert
precision/recall. No automatic blocking was added.

## Reproduce and verify

From the project root:

```powershell
python -m detection.train_baseline
python -m pytest -q
npm run lint --prefix frontend
npm run build --prefix frontend
node tests/test_event_display.mjs
node tests/test_live_snapshot.mjs
```

Regression checks cover rotating IPs/sessions for one account, a failure-only
incident, successful-session continuity, separation of unrelated accounts,
feature invariance to severity, deterministic generation, saved incident
upgrade, and the existing four attack scenarios.

To reach operational quality next: collect trustworthy labelled application
traffic, use identity/authorization/resource context, hold out environments or
days, measure false alerts per day and per-attack recall, test low-and-slow and
distributed campaigns, and then validate the complete hybrid alert policy.
No system can guarantee attribution when its input logs contain no stable
linking evidence. There is no production-grade effectiveness claim here.

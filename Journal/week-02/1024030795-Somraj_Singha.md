# Nexora --- Week 2 Journal
**Week:** 02\
**Dataset:** UNSW-NB15\
**Notebook:** `notebooks/week2_unsw_eda.ipynb`

## 1. Objective

The objective of Week 2 was to extend Nexora's security-event analysis
from the Week 1 CICIDS2017 work to UNSW-NB15, perform exploratory data
analysis and preprocessing, and establish a first real-data
anomaly-detection baseline using Isolation Forest.

## 2. Dataset Loading

The UNSW-NB15 training and testing datasets were loaded from:

``` text
data/raw/UNSW-NB15/
├── UNSW_NB15_training-set.csv
└── UNSW_NB15_testing-set.csv
```

Dataset sizes:

-   Training set: **175,341 rows × 45 columns**
-   Testing set: **82,332 rows × 45 columns**

The training and testing datasets were checked to confirm matching
columns.

## 3. Initial Data Analysis

The dataset structure, data types, categorical fields, target labels,
and attack categories were inspected.

The non-numerical columns identified were:

-   `proto`
-   `service`
-   `state`
-   `attack_cat`

The binary `label` column was used as the target:

-   `0` = Normal
-   `1` = Attack

### Training label distribution

-   Normal: **56,000**
-   Attack: **119,341**
-   Normal: **31.94%**
-   Attack: **68.06%**

The training data is therefore attack-heavy, which is important when
interpreting anomaly-detection results.

## 4. Attack Category Distribution

  Attack Category     Records
  ----------------- ---------
  Normal               56,000
  Generic              40,000
  Exploits             33,393
  Fuzzers              18,184
  DoS                  12,264
  Reconnaissance       10,491
  Analysis              2,000
  Backdoor              1,746
  Shellcode             1,133
  Worms                   130

The distribution is highly uneven, with Generic, Exploits, and Fuzzers
much more represented than smaller categories.

## 5. Data Quality Checks

Results:

-   Missing values: **0**
-   Duplicate rows: **0**
-   Duplicate percentage: **0%**
-   Infinite values: **0**

No missing-value or duplicate-row cleaning was required.

## 6. Categorical Feature Analysis

The categorical features were:

-   `proto`
-   `service`
-   `state`

One-Hot Encoding was applied using:

``` python
OneHotEncoder(handle_unknown="ignore")
```

The three categorical features produced **155 encoded columns**.

`handle_unknown="ignore"` ensures unseen test categories do not cause
transformation failure.

## 7. Numerical Feature Analysis

Numerical features were examined using descriptive statistics and
skewness analysis.

Highly positively skewed features included:

-   `trans_depth`
-   `response_body_len`
-   `sbytes`
-   `sloss`
-   `dloss`
-   `spkts`
-   `dbytes`
-   `dpkts`
-   `dinpkt`
-   `djit`

Many IQR-based outliers were also identified, including high counts for
features such as `dload`, `ct_dst_sport_ltm`, `ct_src_dport_ltm`,
`synack`, `dloss`, `dbytes`, and `spkts`.

## 8. Correlation Analysis

A correlation matrix was generated for numerical features. Feature pairs
with absolute correlation of at least **0.8** were inspected.

Examples included:

  Feature 1        Feature 2        Correlation
  ---------------- -------------- -------------
  `is_ftp_login`   `ct_ftp_cmd`        1.000000
  `dbytes`         `dloss`             0.996504
  `sbytes`         `sloss`             0.996109
  `swin`           `dwin`              0.990140
  `ct_srv_src`     `ct_srv_dst`        0.980323

These strong correlations indicate redundancy in parts of the raw
numerical feature space.

## 9. Preprocessing

The target columns `label` and `attack_cat` were excluded from the
feature matrix.

The preprocessing pipeline was:

1.  Separate numerical and categorical features.
2.  One-hot encode categorical features.
3.  Scale numerical features using `StandardScaler`.
4.  Fit the encoder and scaler on training data only.
5.  Apply the fitted encoder and scaler to testing data.

Final feature representation:

**195 features**

Final sizes:

-   Training: **175,341 × 195**
-   Testing: **82,332 × 195**

Validation confirmed no missing values and no non-numerical columns
remained in the processed matrix.

## 10. Isolation Forest Baseline

A representative stratified subset of **50,000 training samples** was
used for the first prototype.

The baseline model was:

``` python
IsolationForest(
    n_estimators=100,
    contamination="auto",
    random_state=42,
    n_jobs=-1
)
```

Isolation Forest predictions were converted to the dataset convention:

-   `0` = predicted normal
-   `1` = predicted attack/anomaly

### Baseline confusion matrix

``` text
[[15969  2941]
 [33811  2201]]
```

Therefore:

-   True Negatives: **15,969**
-   False Positives: **2,941**
-   False Negatives: **33,811**
-   True Positives: **2,201**

### Baseline metrics

  Metric                    Score
  ------------------ ------------
  Attack Precision     **0.4280**
  Attack Recall        **0.0065**
  Attack F1            **0.0127**

The baseline detected very few actual attacks, with attack recall of
only **0.65%**.

## 11. Contamination Experiment

A second Isolation Forest experiment used:

``` python
contamination=0.10
```

### Confusion matrix

``` text
[[14038  1931]
 [28962  5069]]
```

### Model comparison

  -------------------------------------------------------------------------
  Model                     Precision             Recall           F1 Score
  ---------------- ------------------ ------------------ ------------------
  Isolation Forest             0.4280             0.0065             0.0127
  (`auto`)                                               

  Isolation Forest         **0.6138**         **0.0902**         **0.1573**
  (10%                                                   
  contamination)                                         
  -------------------------------------------------------------------------

The 10% contamination configuration improved:

-   Precision: **42.80% → 61.38%**
-   Recall: **0.65% → 9.02%**
-   F1: **0.0127 → 0.1573**

However, the recall remains low, so this remains a baseline rather than
a production-ready detector.

## 12. Key Findings

1.  UNSW-NB15 contains **175,341 training records and 82,332 testing
    records**.
2.  The training data contains **68.06% attacks and 31.94% normal
    traffic**.
3.  No missing values, duplicate rows, or infinite numerical values were
    found.
4.  Categorical features were successfully transformed using One-Hot
    Encoding.
5.  Numerical features were standardized using a training-only fitted
    `StandardScaler`.
6.  The final processed feature space contains **195 features**.
7.  Several numerical features show strong skewness and substantial
    IQR-based outliers.
8.  Several numerical feature pairs are highly correlated, indicating
    redundancy.
9.  Isolation Forest with `contamination="auto"` performed poorly as an
    attack detector.
10. Setting contamination to **0.10** substantially improved the
    baseline, but attack recall remains insufficient.

## 13. Week 2 Conclusion

Week 2 established a complete UNSW-NB15 exploratory-analysis and
preprocessing pipeline and produced the first real-data Isolation Forest
baseline for Nexora.

The experiment shows that anomaly-detection performance is sensitive to
the contamination setting. The 10% configuration provides a better
starting point than the default `auto` configuration, but its low attack
recall shows that further model development is required.

These results provide a baseline for future work involving improved
anomaly detection, feature selection, threshold tuning, and integration
into Nexora's broader event-detection pipeline.

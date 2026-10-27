    # Week 1 — P1 Detection/ML Exploration

## 1. Objective

The objective of Week 1 was to set up the ML environment and perform
initial exploration of the CICIDS2017 and UNSW-NB15 datasets.

## 2. Environment

Python virtual environment (`venv`) was created.

Libraries used:

- Pandas
- NumPy
- Scikit-learn
- Matplotlib
- Seaborn
- Jupyter

## 3. CICIDS2017

### 3.1 Dataset

The official CICIDS2017 MachineLearningCSV dataset was used.

The dataset was loaded from the `MachineLearningCVE` directory.

### 3.2 Dataset Shape

(2830743, 79)

### 3.3 Features

The dataset contains 79 columns:

- 78 input features
- 1 label column: `Label`

### 3.4 Class Distribution

Attack_Type	              Count	                       Percentage
0	BENIGN	             2273097	                   80.3004
1	DoS Hulk	          231073	                   8.1630
2	PortScan	          158930	                   5.6144
3	DDoS	              128027	                   4.5227
4	DoS GoldenEye	       10293	                   0.3636
5	FTP-Patator	             938	                   0.2804
6	SSH-Patator	            5897	                   0.2083
7	DoS slowloris	        5796	                   0.2048
8	DoS Slowhttptest	    5499                       0.1943
9	Bot	                    1966	                   0.0695
10	Web Attack � Brute Force	1507	              0.0532
11	Web Attack � XSS	    652	                      0.0230
12	Infiltration	          36 	                   0.0013
13	Web Attack � Sql Injection	21	                  0.0007
14	Heartbleed	11	                                   0.0004

### 3.5 Observations

- The dataset contains both benign and attack traffic.
- `BENIGN` is the dominant class.
- The dataset is strongly class-imbalanced.
- Multiple attack categories are present.
- Column names required whitespace stripping before analysis.

### 3.6 Data Quality

Missing values:

Total missing values: 1358

Infinite values:

Positive infinity: 4376
Negative infinity: 0

Duplicate rows:

Duplicate rows: 308381

### 3.7 Feature Types

Numerical columns: 78
Non-numerical columns: 1
## 4. Attack Categories

The observed CICIDS2017 labels include:

- BENIGN
- DoS Hulk
- PortScan
- DDoS
- DoS GoldenEye
- FTP-Patator
- SSH-Patator
- DoS slowloris
- DoS Slowhttptest
- Bot
- Web Attack
- Infiltration
- Heartbleed

## 5. Preliminary Observations

The dataset shows significant class imbalance, which will need to be
considered during later model training and evaluation.

The dataset contains a large number of network-flow features that can
potentially be used for anomaly detection and attack classification.

## 6. Week 2 Plan

The next stage will focus on preprocessing the datasets and preparing
the first Isolation Forest prototype.
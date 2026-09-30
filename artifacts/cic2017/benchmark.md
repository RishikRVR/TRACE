Dataset: CIC-IDS2017 (corrected release, Engelen et al. 2022) · window 30 s · horizon K=10

**Infiltration within K windows (every window)**

| Model | F1 | Precision | Recall | FPR | PR-AUC |
|---|---|---|---|---|---|
| TRACE world model | 0.000 | 0.000 | 0.000 | 0.0865 | 0.022 |
| Logistic regression (S_t) | 0.039 | 0.023 | 0.155 | 0.1308 | 0.021 |
| Logistic regression (last 20 windows) | 0.169 | 0.098 | 0.615 | 0.1106 | 0.385 |

**Before compromise only (early warning)**

| Model | F1 | Precision | Recall | FPR | PR-AUC |
|---|---|---|---|---|---|
| TRACE world model | 0.010 | 0.005 | 0.333 | 0.2449 | 0.004 |
| Logistic regression (S_t) | 0.000 | 0.000 | 0.000 | 0.0485 | 0.005 |
| Logistic regression (last 20 windows) | 0.023 | 0.012 | 0.167 | 0.0497 | 0.011 |

**Early warning (test episodes; alarm on the victim within 10 min before compromise)**

| Model | Warned before compromise | Median lead (min) | False alarms / host-hour | Benign episodes with an alarm |
|---|---|---|---|---|
| TRACE world model | 1/1 | 10.0 | 2.077 | 0/0 |
| Logistic regression (S_t) | 0/1 | 0.0 | 4.932 | 0/0 |
| Logistic regression (last 20 windows) | 0/1 | 0.0 | 2.138 | 0/0 |

**Same comparison at an equal false-alarm budget (2.237 per host-hour, set on validation)**

| Model | Warned before compromise | Median lead (min) | False alarms / host-hour (test) |
|---|---|---|---|
| TRACE world model | 1/1 | 10.0 | 2.077 |
| Logistic regression (S_t) | 0/1 | 0.0 | 3.313 |
| Logistic regression (last 20 windows) | 1/1 | 6.0 | 4.031 |

Stage macro-F1 (current window): 0.330
Next-state NLL: world model 0.887 vs persistence 1.655

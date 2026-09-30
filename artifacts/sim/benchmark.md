Dataset: TRACE simulator (labelled kill chains) · window 30 s · horizon K=10

**Infiltration within K windows (every window)**

| Model | F1 | Precision | Recall | FPR | PR-AUC |
|---|---|---|---|---|---|
| TRACE world model | 0.864 | 0.941 | 0.798 | 0.0028 | 0.855 |
| Logistic regression (S_t) | 0.621 | 0.754 | 0.528 | 0.0098 | 0.646 |
| Logistic regression (last 20 windows) | 0.804 | 0.890 | 0.734 | 0.0052 | 0.835 |

**Before compromise only (early warning)**

| Model | F1 | Precision | Recall | FPR | PR-AUC |
|---|---|---|---|---|---|
| TRACE world model | 0.270 | 0.276 | 0.265 | 0.0085 | 0.188 |
| Logistic regression (S_t) | 0.097 | 0.066 | 0.185 | 0.0317 | 0.054 |
| Logistic regression (last 20 windows) | 0.211 | 0.270 | 0.173 | 0.0057 | 0.131 |

**Early warning (test episodes; alarm on the victim within 10 min before compromise)**

| Model | Warned before compromise | Median lead (min) | False alarms / host-hour | Benign episodes with an alarm |
|---|---|---|---|---|
| TRACE world model | 21/31 | 4.5 | 0.187 | 0/17 |
| Logistic regression (S_t) | 23/31 | 9.5 | 2.387 | 17/17 |
| Logistic regression (last 20 windows) | 19/31 | 4.5 | 0.178 | 4/17 |

**Same comparison at an equal false-alarm budget (0.141 per host-hour, set on validation)**

| Model | Warned before compromise | Median lead (min) | False alarms / host-hour (test) |
|---|---|---|---|
| TRACE world model | 21/31 | 4.5 | 0.187 |
| Logistic regression (S_t) | 15/31 | 4.0 | 0.146 |
| Logistic regression (last 20 windows) | 19/31 | 3.0 | 0.094 |

Stage macro-F1 (current window): 0.953
Next-state NLL: world model -1.368 vs persistence 0.796

**Unseen attack family (DNS-tunnel exfiltration, never in training)**
Exfil windows flagged: TRACE world model 100%, Logistic regression (S_t) 1%, Logistic regression (last 20 windows) 28%
Surprise percentile on exfil windows: 99 (benign 50)

**Slow-scan sweep: share of chains warned before compromise (baselines at TRACE's false-alarm budget)**

| Probe gap (s) | TRACE | LR (S_t) | LR (stacked) | Per-window threshold |
|---|---|---|---|---|
| 0.05 | 100% | 100% | 100% | 100% |
| 0.5 | 100% | 100% | 100% | 100% |
| 2 | 100% | 25% | 100% | 0% |
| 5 | 100% | 25% | 100% | 0% |
| 10 | 100% | 62% | 100% | 0% |
| 20 | 100% | 100% | 100% | 0% |
| 40 | 100% | 75% | 50% | 0% |

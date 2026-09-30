# Kaggle parquet copies: not usable for TRACE

`csecicids2018/` and `ctu13/` are the cleaned Kaggle re-publications of
CSE-CIC-IDS2018 and CTU-13. They are kept only so nobody downloads them twice.

They cannot be used here. Both drop the columns TRACE needs to build a
per-host timeline:

| Needed | CSE-CIC-IDS2018 (parquet) | CTU-13 (parquet) |
|---|---|---|
| Timestamp | removed | removed |
| Source / destination IP | removed | removed |
| Source / destination port | removed | removed |

Without a timestamp there is no time axis, and without an IP there is no host,
so no window sequence can be formed. What is left is one row per flow with no
order, which is exactly the "static classification" the problem statement asks
us to move beyond.

Use instead:

- `../cic-ids2017-improved/` — the corrected CIC-IDS2017 release (Engelen et
  al., CNS 2022), which keeps timestamps, IPs and ports.
- `../ctu13-binetflow/` — the original Argus binetflow files from the
  Stratosphere Lab, which also keep them.

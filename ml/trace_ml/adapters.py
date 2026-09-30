"""CSV flow-record adapters (flow-only mode, docs/feature-schema-v1.md).

Map a public dataset's flow records onto the f_* window features, per internal
host and window, and its per-flow labels onto window stages. Every p_* column
is left at zero with has_packet_level = 0, so the model masks that block.

    python -m trace_ml.adapters cic2017 ../data/raw/cic-ids2017-improved ../data/features/cic2017

Approximations, all forced by the flow format: a flow's packets are counted in
the window where it started; CICFlowMeter gives SYN/FIN/ACK totals rather than
per direction, so those are split between the two sides.
"""

from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from .data import PRECEDENCE

ADMIN = [22, 23, 135, 139, 445, 3389, 5985, 5986]

# CIC-IDS2017 label -> stage. "Attempted" flows are relabelled benign, as the
# dataset's authors recommend (Engelen et al., CNS 2022).
CIC_STAGE = {
    "PortScan": 1,
    "Portscan": 1,
    "Infiltration - Portscan": 3,
    "Infiltration": 2,
    "Web Attack - Brute Force": 2,
    "Web Attack - XSS": 2,
    "Web Attack - SQL Injection": 2,
    "FTP-Patator": 2,
    "SSH-Patator": 2,
    "Heartbleed": 2,
    "Botnet": 4,
    "Botnet - Attempted": 0,
    "DoS Hulk": 6,
    "DoS GoldenEye": 6,
    "DoS Slowloris": 6,
    "DoS Slowhttptest": 6,
    "DDoS": 6,
}

CIC_COLS = {
    "Src IP": "src", "Src Port": "sport", "Dst IP": "dst", "Dst Port": "dport", "Protocol": "proto", "Timestamp": "ts",
    "Flow Duration": "dur_us", "Total Fwd Packet": "fp", "Total Bwd packets": "bp", "Total Length of Fwd Packet": "fb",
    "Total Length of Bwd Packet": "bb", "Flow IAT Mean": "iat_mean", "Flow IAT Std": "iat_std", "Flow IAT Max": "iat_max",
    "Fwd PSH Flags": "psh_f", "Bwd PSH Flags": "psh_b", "Fwd URG Flags": "urg_f", "Bwd URG Flags": "urg_b",
    "Fwd RST Flags": "rst_f", "Bwd RST Flags": "rst_b", "FIN Flag Count": "fin", "SYN Flag Count": "syn",
    "ACK Flag Count": "ack", "Label": "label",
}


def stage_of(label: str) -> int:
    if label.endswith("Attempted"):
        return 0
    for k, v in CIC_STAGE.items():
        if label == k or label.startswith(k):
            return v
    return 0 if label.upper() == "BENIGN" else 0


def _internal(ips: pd.Series, nets: list[ipaddress.IPv4Network]) -> pd.Series:
    uniq = ips.unique()
    m = {ip: any(ipaddress.ip_address(ip) in n for n in nets) if _is_v4(ip) else False for ip in uniq}
    return ips.map(m)


def _is_v4(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


def flows_to_windows(df: pd.DataFrame, source: str, window_s: int, nets) -> tuple[pd.DataFrame, pd.DataFrame]:
    """df: one row per flow with the CIC_COLS names. Returns (windows, labels)."""
    wms = window_s * 1000
    df = df.copy()
    df["stage"] = df.label.map(stage_of).astype(int)
    df["w"] = (df.ts // wms) * wms
    si, di = _internal(df.src, nets), _internal(df.dst, nets)
    df["src_in"], df["dst_in"] = si.values, di.values

    def view(orig: bool) -> pd.DataFrame:
        sel = df[df.src_in] if orig else df[df.dst_in]
        v = pd.DataFrame({
            "host": sel.src if orig else sel.dst, "peer": sel.dst if orig else sel.src,
            "peer_in": sel.dst_in if orig else sel.src_in, "w": sel.w, "orig": orig, "dport": sel.dport, "proto": sel.proto,
            "p_out": sel.fp if orig else sel.bp, "p_in": sel.bp if orig else sel.fp,
            "b_out": sel.fb if orig else sel.bb, "b_in": sel.bb if orig else sel.fb,
            "bidir": (sel.fp > 0) & (sel.bp > 0), "dur": sel.dur_us / 1e6, "pk": sel.fp + sel.bp, "by": sel.fb + sel.bb,
            "iat_mean": sel.iat_mean / 1e6, "iat_var": (sel.iat_std / 1e6) ** 2, "iat_max": sel.iat_max / 1e6,
            "syn_out": np.minimum(sel.syn, 1) if orig else np.maximum(sel.syn - 1, 0),
            "syn_in": np.maximum(sel.syn - 1, 0) if orig else np.minimum(sel.syn, 1),
            "fin_out": np.ceil(sel.fin / 2) if orig else np.floor(sel.fin / 2),
            "fin_in": np.floor(sel.fin / 2) if orig else np.ceil(sel.fin / 2),
            "rst_out": sel.rst_f if orig else sel.rst_b, "rst_in": sel.rst_b if orig else sel.rst_f,
            "psh_out": sel.psh_f if orig else sel.psh_b, "psh_in": sel.psh_b if orig else sel.psh_f,
            "urg_out": sel.urg_f if orig else sel.urg_b, "urg_in": sel.urg_b if orig else sel.urg_f,
            "fail": orig & (sel.proto == 6) & ((sel.bp == 0) | (sel.rst_b > 0)),
            "synonly": orig & (sel.syn >= 1) & (sel.bp == 0),
            "admin": sel.dport.isin(ADMIN), "dns": orig & (sel.dport == 53),
            # the host that carries the attack label: the internal source, else the internal victim
            "stage": np.where(sel.src_in, sel.stage, sel.stage) if orig else np.where(sel.src_in, 0, sel.stage),
        })
        tot = v.p_out + v.p_in
        v["ack_out"] = sel.ack.values * np.where(tot > 0, v.p_out / tot.replace(0, 1), 0.5)
        v["ack_in"] = sel.ack.values - v["ack_out"]
        return v

    v = pd.concat([view(True), view(False)], ignore_index=True)
    v["pk_tcp"] = np.where(v.proto == 6, v.pk, 0)
    v["pk_udp"] = np.where(v.proto == 17, v.pk, 0)
    v["pk_icmp"] = np.where(v.proto == 1, v.pk, 0)
    g = v.groupby(["host", "w"], sort=True)
    out = pd.DataFrame({
        "f_pkts_out": g.p_out.sum(), "f_pkts_in": g.p_in.sum(), "f_bytes_out": g.b_out.sum(), "f_bytes_in": g.b_in.sum(),
        "f_flows_active": g.size(), "f_flows_new_out": g.orig.sum(), "f_flows_new_in": g.size() - g.orig.sum(),
        "f_flows_bidir_frac": g.bidir.mean(), "f_flow_dur_mean": g.dur.mean(), "f_flow_dur_max": g.dur.max(),
        "f_flow_pkts_mean": g.pk.mean(), "f_flow_bytes_mean": g.by.mean(), "f_flow_iat_mean": g.iat_mean.mean(),
        "f_flow_iat_var": g.iat_var.mean(), "f_flow_iat_max": g.iat_max.mean(),
    })
    pk = g.pk.sum().replace(0, 1)
    out["f_proto_tcp_frac"] = g.pk_tcp.sum() / pk
    out["f_proto_udp_frac"] = g.pk_udp.sum() / pk
    out["f_proto_icmp_frac"] = g.pk_icmp.sum() / pk
    for fl in ("syn", "ack", "fin", "rst", "psh", "urg"):
        out[f"f_tcp_{fl}_out"] = g[f"{fl}_out"].sum()
        out[f"f_tcp_{fl}_in"] = g[f"{fl}_in"].sum()
    out["f_syn_only_out"] = g.synonly.sum()
    out["f_conn_fail_out"] = g.fail.sum()
    o, i = v[v.orig], v[~v.orig]
    out["f_uniq_peer_out"] = o.groupby(["host", "w"]).peer.nunique()
    out["f_uniq_peer_in"] = i.groupby(["host", "w"]).peer.nunique()
    out["f_uniq_dport_out"] = o.groupby(["host", "w"]).dport.nunique()
    out["f_uniq_lport_in"] = i.groupby(["host", "w"]).dport.nunique()
    out["f_internal_peer_frac"] = v.drop_duplicates(["host", "w", "peer"]).groupby(["host", "w"]).peer_in.mean()
    out["f_admin_conn_out"] = o[o.admin].groupby(["host", "w"]).size()
    out["f_admin_conn_in"] = i[i.admin].groupby(["host", "w"]).size()
    dns = v[v.dns]
    out["f_dns_queries_out"] = dns.groupby(["host", "w"]).p_out.sum()
    out = out.fillna(0.0)
    out["f_bytes_ratio"] = (out.f_bytes_out + 1) / (out.f_bytes_in + 1)
    out["f_dns_qname_entropy_mean"] = 0.0
    out["f_dns_qname_len_max"] = 0.0

    rank = {int(s): r for r, s in enumerate(PRECEDENCE)}
    lab = v[v.stage > 0][["host", "w", "stage"]].copy()
    lab["rank"] = lab.stage.map(rank)
    lab = lab.sort_values("rank").drop_duplicates(["host", "w"])[["host", "w", "stage"]]
    out = out.reset_index().rename(columns={"w": "window_start"})
    lab = lab.rename(columns={"w": "window_start"})
    out.insert(0, "source", source)
    lab.insert(0, "source", source)
    return out, lab


def cic2017(src_dir: str, out_dir: str, window_s: int = 30, internal: str = "192.168.10.0/24") -> None:
    schema_features = json.loads((Path(__file__).resolve().parents[2] / "data" / "features" / "sim" / "schema.json").read_text())["features"]
    nets = [ipaddress.ip_network(n) for n in internal.split(",")]
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    wins, labs = [], []
    for day in ("monday", "tuesday", "wednesday", "thursday", "friday"):
        p = Path(src_dir) / f"{day}.csv"
        df = pd.read_csv(p, usecols=list(CIC_COLS), engine="pyarrow").rename(columns=CIC_COLS)
        df["ts"] = pd.to_datetime(df.ts).astype("int64") // 1_000_000
        df = df.dropna(subset=["src", "dst"])
        parts = [(day, df)]
        if day == "thursday":  # morning: web attacks (validation); afternoon: the infiltration chain (test)
            noon = pd.Timestamp("2017-07-06 15:00:00").value // 1_000_000  # UTC: web attacks end 13:43, infiltration starts 17:00
            parts = [("thursday-am", df[df.ts < noon]), ("thursday-pm", df[df.ts >= noon])]
        for name, part in parts:
            w, lab = flows_to_windows(part, f"cic2017-{name}", window_s, nets)
            print(name, len(part), "flows ->", len(w), "host-windows;", lab.stage.value_counts().to_dict(), flush=True)
            wins.append(w)
            labs.append(lab)
    w = pd.concat(wins, ignore_index=True)
    for f in schema_features:
        if f not in w:
            w[f] = 0.0
    w.insert(0, "schema_version", 1)
    w.insert(3, "window_s", window_s)
    w.insert(4, "has_packet_level", 0)
    key = ["schema_version", "source", "host", "window_start", "window_s", "has_packet_level"]
    w[key + schema_features].to_csv(out / "windows.csv", index=False)
    pd.concat(labs, ignore_index=True).to_csv(out / "labels.csv", index=False)
    schema = {"schema_version": 1, "window_s": window_s, "internal": internal.split(","), "bytes": "l4_payload",
              "flow_level": [f for f in schema_features if f.startswith("f_")],
              "packet_level": [f for f in schema_features if f.startswith("p_")], "features": schema_features,
              "source_dataset": "CIC-IDS2017 (corrected release, Engelen et al. 2022)"}
    (out / "schema.json").write_text(json.dumps(schema, indent=1))
    # real-data split: the Thursday-afternoon infiltration chain is never trained on
    split = {"train": ["cic2017-monday", "cic2017-tuesday", "cic2017-wednesday", "cic2017-friday"], "val": ["cic2017-thursday-am"],
             "test": ["cic2017-thursday-pm"], "unseen": []}
    (out / "split.json").write_text(json.dumps(split))
    print("->", out)


if __name__ == "__main__":
    if sys.argv[1] == "cic2017":
        cic2017(sys.argv[2], sys.argv[3])

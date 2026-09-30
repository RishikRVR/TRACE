"""The hash chain, and the window labelling that defines the forecast target."""

import numpy as np
import pandas as pd

from trace_ml.data import PRECEDENCE, build_sequences, first_infiltration, infiltration_within, label_windows
from trace_ml.ledger import Ledger
from trace_ml.stages import Stage


def test_chain_verifies_and_detects_an_edit(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    for i in range(5):
        led.append("forecast", host="10.0.0.5", p=0.5 + i / 100)
    recs = led.records()
    assert Ledger.verify(recs)["ok"]

    edited = [dict(r) for r in recs]
    edited[2]["p"] = 0.01
    res = Ledger.verify(edited)
    assert res["ok"] is False and res["broken_at"] == 2


def test_each_record_links_to_the_previous(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    a = led.append("forecast", host="h")
    b = led.append("approval", host="h")
    assert b["prev"] == a["hash"]


def test_reordering_records_breaks_the_chain(tmp_path):
    led = Ledger(tmp_path / "l.jsonl")
    for i in range(4):
        led.append("forecast", host=f"h{i}")
    recs = led.records()
    swapped = [recs[0], recs[2], recs[1], recs[3]]
    assert Ledger.verify(swapped)["ok"] is False


def test_infiltration_within_k_looks_forward_only():
    stage = np.array([0, 0, 0, int(Stage.INITIAL_ACCESS), 0, 0])
    y = infiltration_within(stage, k=2)
    # windows 1 and 2 are within 2 of the compromise at index 3; 3 itself is not
    assert list(y) == [0, 1, 1, 0, 0, 0]


def test_infiltration_target_excludes_the_current_window():
    stage = np.array([int(Stage.EXFILTRATION), 0, 0])
    assert infiltration_within(stage, k=1)[0] == 0


def test_benign_traffic_has_no_positive_target():
    assert infiltration_within(np.zeros(10, dtype=int), k=5).sum() == 0


def test_first_infiltration_ignores_reconnaissance():
    stage = np.array([0, int(Stage.RECONNAISSANCE), int(Stage.LATERAL_MOVEMENT), 0])
    assert first_infiltration(stage) == 2
    assert first_infiltration(np.zeros(4, dtype=int)) == 4


def test_overlapping_annotations_take_the_more_decisive_stage():
    """A host that beacons while moving laterally is labelled lateral movement:
    the rarer, more decisive activity wins."""
    iv = pd.DataFrame([
        {"host": "h", "stage": int(Stage.COMMAND_AND_CONTROL), "start_ms": 0, "end_ms": 90_000},
        {"host": "h", "stage": int(Stage.LATERAL_MOVEMENT), "start_ms": 30_000, "end_ms": 60_000},
    ])
    got = label_windows(iv, "h", t0=0, T=3, window_ms=30_000)
    assert list(got) == [int(Stage.COMMAND_AND_CONTROL), int(Stage.LATERAL_MOVEMENT), int(Stage.COMMAND_AND_CONTROL)]
    assert PRECEDENCE.index(Stage.LATERAL_MOVEMENT) < PRECEDENCE.index(Stage.COMMAND_AND_CONTROL)


def test_gaps_between_windows_are_filled_so_sequences_are_dense():
    """The extractor only writes windows that carried traffic; a quiet window
    must still appear, as zeros, or the model's clock skips."""
    w = pd.DataFrame({
        "schema_version": 1, "source": "s", "host": "10.0.0.5",
        "window_start": [0, 90_000],  # 30 s windows: two missing in between
        "window_s": 30, "has_packet_level": 1, "f_pkts_out": [5.0, 7.0],
    })
    seqs = build_sequences(w, ["f_pkts_out"])
    assert len(seqs) == 1
    s = seqs[0]
    assert s.T == 4
    assert list(s.present) == [True, False, False, True]
    assert list(s.X[:, 0]) == [5.0, 0.0, 0.0, 7.0]

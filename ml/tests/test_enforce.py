"""The enforcement safety rules. These are the tests that matter most: a
mistake here takes a network down rather than merely mis-scoring a forecast."""

import pytest

from trace_ml.enforce import Enforcer
from trace_ml.ledger import Ledger


@pytest.fixture
def enf(tmp_path):
    led = Ledger(tmp_path / "ledger.jsonl")
    e = Enforcer(led, enforce=False)
    e.never |= {"10.9.9.1"}  # stand in for a discovered gateway
    return e


def test_dry_run_is_the_default(enf):
    assert enf.mode() == "dry-run"
    r = enf.block("203.0.113.7", reason="test")
    assert r["ok"] and r["applied"] is False


def test_never_blocks_its_own_host(enf):
    for ip in ("127.0.0.1", "10.9.9.1"):
        r = enf.block(ip, reason="test")
        assert r["ok"] is False
        assert "cut TRACE off" in r["refused"]


@pytest.mark.parametrize("ip", ["169.254.1.1", "224.0.0.1", "0.0.0.0", "::1"])
def test_refuses_addresses_that_are_never_a_real_attacker(enf, ip):
    assert enf.block(ip, reason="test")["ok"] is False


@pytest.mark.parametrize("bad", ["", "not-an-ip", "10.0.0.256", "10.0.0.0/8"])
def test_refuses_malformed_input(enf, bad):
    assert enf.block(bad, reason="test")["ok"] is False


def test_refusal_is_recorded_so_the_attempt_is_auditable(enf):
    enf.block("127.0.0.1", reason="test")
    kinds = [r["kind"] for r in enf.ledger.records()]
    assert "block_refused" in kinds


def test_block_and_undo_are_both_in_the_chain(enf):
    enf.block("203.0.113.7", reason="approved", host="10.0.0.5")
    assert "203.0.113.7" in {b["ip"] for b in enf.state()["blocks"]}
    enf.unblock("203.0.113.7")
    assert enf.state()["blocks"] == []

    recs = enf.ledger.records()
    assert [r["kind"] for r in recs] == ["block", "unblock"]
    assert Ledger.verify(recs)["ok"]


def test_blocks_expire(enf):
    enf.block("203.0.113.7", reason="approved", ttl=0)
    assert enf.expire() == ["203.0.113.7"]
    assert enf.state()["blocks"] == []


def test_enforcing_without_root_falls_back_to_dry_run(tmp_path):
    """Asking to enforce must never half-apply: without privileges it degrades
    to recording, and says so."""
    e = Enforcer(Ledger(tmp_path / "l.jsonl"), enforce=True, backend="record")
    assert e.mode() == "dry-run (backend unavailable)"
    assert e.block("203.0.113.7", reason="test")["applied"] is False

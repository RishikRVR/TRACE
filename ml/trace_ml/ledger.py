"""Tamper-evident forecast ledger: an append-only hash chain.

Each record stores the hash of the one before it, and its own hash covers its
content plus that link, so editing any past record breaks every hash after
it. It proves when a forecast was made. It is a hash chain on one machine, not
a distributed blockchain; anchoring the head hash to an external timestamp
authority is the next step.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


def _digest(rec: dict) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Ledger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]

    def append(self, kind: str, **payload) -> dict:
        with self._lock:
            recs = self.records()
            rec = {"seq": len(recs), "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "kind": kind, **payload,
                   "prev": recs[-1]["hash"] if recs else GENESIS}
            rec["hash"] = _digest(rec)
            with self.path.open("a") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
            return rec

    @staticmethod
    def verify(recs: list[dict]) -> dict:
        prev = GENESIS
        for r in recs:
            if r.get("prev") != prev or _digest(r) != r.get("hash"):
                return {"ok": False, "broken_at": r.get("seq"), "count": len(recs)}
            prev = r["hash"]
        return {"ok": True, "broken_at": None, "count": len(recs), "head": prev}

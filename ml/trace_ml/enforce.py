"""Enforcement: turn an approved decision into a firewall rule.

Design rules, in order of importance:

1. **A forecast never enforces by itself.** Only an analyst approval reaches
   this module; the model's output is an input to that decision, not a trigger.
2. **Dry run is the default.** Nothing touches a firewall unless TRACE is
   started with --enforce, and the console always shows which mode is active.
3. **Some addresses are never blocked**, whatever the forecast says: this
   host, loopback, the default gateway and the DNS servers it depends on.
   Cutting those off would take the sensor (or the network) down.
4. **Everything is reversible and expires.** Every rule carries a TTL and can
   be undone from the console, and both actions go in the hash-chained ledger.

Backends: nftables on Linux, pf on macOS, and "record" everywhere else, which
keeps the decision list without touching the system (the honest behaviour when
replaying a capture, where a block cannot un-send a packet that already
happened).
"""

from __future__ import annotations

import ipaddress
import os
import platform
import re
import shutil
import socket
import subprocess
import threading
import time

TABLE = "trace"          # nftables table / pf anchor name
SET = "trace_blocked"    # nftables set / pf table name
DEFAULT_TTL = 1800       # seconds; a block lapses unless renewed

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _run(cmd: list[str], timeout: int = 10) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)


def local_addresses() -> set[str]:
    """Every address this machine answers on, so TRACE cannot block itself."""
    out = {"127.0.0.1", "::1"}
    try:
        host = socket.gethostname()
        for fam in (socket.AF_INET, socket.AF_INET6):
            for info in socket.getaddrinfo(host, None, fam):
                out.add(info[4][0])
    except OSError:
        pass
    ok, txt = _run(["ip", "-o", "addr", "show"]) if shutil.which("ip") else _run(["ifconfig"])
    if ok:
        for m in re.finditer(r"inet6?\s+([0-9a-fA-F:.]+)", txt):
            out.add(m.group(1))
    return out


def default_gateways() -> set[str]:
    out: set[str] = set()
    if shutil.which("ip"):
        ok, txt = _run(["ip", "route", "show", "default"])
        if ok:
            out.update(re.findall(r"via\s+(\S+)", txt))
    ok, txt = _run(["route", "-n", "get", "default"])
    if ok:
        out.update(re.findall(r"gateway:\s*(\S+)", txt))
    return out


def resolvers() -> set[str]:
    out: set[str] = set()
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    out.add(line.split()[1])
    except OSError:
        pass
    return out


class Enforcer:
    """Applies and reverses blocks, or records the intent in dry-run mode."""

    def __init__(self, ledger, enforce: bool = False, backend: str = "auto", ttl: int = DEFAULT_TTL,
                 extra_never_block: set[str] | None = None):
        self.ledger = ledger
        self.ttl = ttl
        self.lock = threading.RLock()
        self.blocks: dict[str, dict] = {}
        self.backend = self._pick(backend)
        self.enforce = bool(enforce)
        self.never = local_addresses() | default_gateways() | resolvers() | (extra_never_block or set())
        self.ready, self.status = (False, "dry run: decisions are recorded, no firewall rule is applied")
        if self.enforce:
            self.ready, self.status = self._setup()

    # --- backend ------------------------------------------------------------

    def _pick(self, backend: str) -> str:
        if backend != "auto":
            return backend
        if platform.system() == "Linux" and shutil.which("nft"):
            return "nftables"
        if platform.system() == "Darwin" and shutil.which("pfctl"):
            return "pf"
        return "record"

    def _setup(self) -> tuple[bool, str]:
        """Create the table/set TRACE owns. It never edits rules it did not create."""
        if self.backend == "record":
            return False, "no firewall backend on this platform: decisions are recorded only"
        if os.geteuid() != 0:
            return False, f"{self.backend} needs root; running in dry run instead"
        if self.backend == "nftables":
            ok, msg = _run(["nft", "add", "table", "inet", TABLE])
            if not ok:
                return False, f"nft add table failed: {msg}"
            _run(["nft", "add", "set", "inet", TABLE, SET,
                  "{ type ipv4_addr; flags timeout; }"])
            _run(["nft", "add", "chain", "inet", TABLE, "input",
                  "{ type filter hook input priority -10; policy accept; }"])
            ok, msg = _run(["nft", "add", "rule", "inet", TABLE, "input",
                            "ip", "saddr", f"@{SET}", "counter", "drop"])
            return (True, f"nftables: inet/{TABLE} ready") if ok else (False, f"nft add rule failed: {msg}")
        # pf: TRACE manages the table's membership; the operator installs the rule once:
        #   table <trace_blocked> persist
        #   block drop in quick from <trace_blocked>
        ok, msg = _run(["pfctl", "-t", SET, "-T", "show"])
        return (True, f"pf: table <{SET}> ready") if ok else (False, f"pf table <{SET}> missing: {msg}")

    # --- checks -------------------------------------------------------------

    def check(self, ip: str) -> str | None:
        """Why this address must not be blocked, or None if it may be."""
        if not IP_RE.match(ip or ""):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return f"{ip!r} is not an IP address"
        if ip in self.never:
            return f"{ip} is this host, its gateway or its DNS server: blocking it would cut TRACE off"
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return f"{ip!r} is not an IP address"
        if a.is_loopback or a.is_multicast or a.is_unspecified or a.is_reserved:
            return f"{ip} is a loopback, multicast or reserved address"
        if a.is_link_local:
            return f"{ip} is link-local"
        return None

    # --- actions ------------------------------------------------------------

    def block(self, ip: str, reason: str, host: str = "", ttl: int | None = None, approved_by: str = "analyst") -> dict:
        refusal = self.check(ip)
        if refusal:
            rec = {"ok": False, "ip": ip, "refused": refusal, "mode": self.mode()}
            self.ledger.append("block_refused", ip=ip, reason=refusal, host=host)
            return rec
        ttl = int(self.ttl if ttl is None else ttl)
        applied, detail = False, "recorded only (dry run)"
        if self.enforce and self.ready:
            if self.backend == "nftables":
                applied, detail = _run(["nft", "add", "element", "inet", TABLE, SET, f"{{ {ip} timeout {ttl}s }}"])
            elif self.backend == "pf":
                applied, detail = _run(["pfctl", "-t", SET, "-T", "add", ip])
            if not applied:
                detail = f"{self.backend} refused: {detail}"
        with self.lock:
            self.blocks[ip] = {"ip": ip, "host": host, "reason": reason, "since": time.time(), "ttl": ttl,
                               "applied": applied, "detail": detail, "backend": self.backend}
        rec = self.ledger.append("block", ip=ip, host=host, reason=reason, ttl_s=ttl, applied=applied,
                                 backend=self.backend, mode=self.mode(), approved_by=approved_by, detail=detail)
        return {"ok": True, "ip": ip, "applied": applied, "detail": detail, "mode": self.mode(), "ledger_seq": rec["seq"]}

    def unblock(self, ip: str, reason: str = "analyst undo") -> dict:
        removed, detail = False, "was not blocked"
        if self.enforce and self.ready:
            if self.backend == "nftables":
                removed, detail = _run(["nft", "delete", "element", "inet", TABLE, SET, f"{{ {ip} }}"])
            elif self.backend == "pf":
                removed, detail = _run(["pfctl", "-t", SET, "-T", "delete", ip])
        with self.lock:
            existed = self.blocks.pop(ip, None) is not None
        self.ledger.append("unblock", ip=ip, reason=reason, removed=removed or existed, backend=self.backend, mode=self.mode())
        return {"ok": True, "ip": ip, "removed": removed or existed, "detail": detail, "mode": self.mode()}

    def expire(self) -> list[str]:
        """Drop blocks whose TTL has passed (nftables does this itself; this
        keeps our own list and pf in step)."""
        now = time.time()
        with self.lock:
            gone = [ip for ip, b in self.blocks.items() if now - b["since"] > b["ttl"]]
        for ip in gone:
            self.unblock(ip, reason="ttl expired")
        return gone

    # --- status -------------------------------------------------------------

    def mode(self) -> str:
        if not self.enforce:
            return "dry-run"
        return "enforcing" if self.ready else "dry-run (backend unavailable)"

    def state(self) -> dict:
        self.expire()
        with self.lock:
            blocks = sorted(self.blocks.values(), key=lambda b: -b["since"])
        return {"mode": self.mode(), "backend": self.backend, "status": self.status, "ttl_s": self.ttl,
                "never_block": sorted(self.never), "blocks": blocks}

// Package flow tracks per-connection state keyed by a direction-agnostic
// 5-tuple, so packets from either side of a conversation map to the same
// flow. It is deliberately separate from the per-rule threshold tracker in
// internal/detect, which aggregates across many different 5-tuples (e.g. a
// port scan touches one 5-tuple per destination port).
package flow

import (
	"bytes"
	"encoding/binary"
	"hash/fnv"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
)

const numShards = 32

// Key identifies a flow independent of packet direction: A->B and B->A
// normalize to the same Key.
type Key struct {
	IPLow, IPHigh     [16]byte
	PortLow, PortHigh uint16
	Protocol          uint8 // IANA protocol number, e.g. 6=TCP, 17=UDP, 1=ICMP
}

// NewKey builds a normalized Key from one packet's addressing. ip1/port1 is
// the packet's source, ip2/port2 its destination; the result is identical
// regardless of which side is "1" and which is "2".
func NewKey(ip1, ip2 net.IP, port1, port2 uint16, protocol uint8) Key {
	a := to16(ip1)
	b := to16(ip2)
	if less(a, port1, b, port2) {
		return Key{IPLow: a, PortLow: port1, IPHigh: b, PortHigh: port2, Protocol: protocol}
	}
	return Key{IPLow: b, PortLow: port2, IPHigh: a, PortHigh: port1, Protocol: protocol}
}

func to16(ip net.IP) [16]byte {
	var out [16]byte
	copy(out[:], ip.To16())
	return out
}

func less(ipA [16]byte, portA uint16, ipB [16]byte, portB uint16) bool {
	if c := bytes.Compare(ipA[:], ipB[:]); c != 0 {
		return c < 0
	}
	return portA < portB
}

// State is the tracked context for one flow.
type State struct {
	ID           string
	Key          Key
	FirstSeen    time.Time
	LastSeen     time.Time
	OriginatorIP [16]byte // the IP that sent the first packet — drives event Direction
	PacketsC2S   uint64
	PacketsS2C   uint64
	BytesC2S     uint64
	BytesS2C     uint64
	Bits         map[string]bool // Snort flowbits set on this flow
	TCPState     string          // "" | "new" | "established" | "closing" | "closed" — best-effort, not a full state machine
}

// Direction reports "C2S" or "S2C" for a packet from srcIP, relative to
// this flow's originator.
func (s *State) Direction(srcIP net.IP) string {
	if to16(srcIP) == s.OriginatorIP {
		return "C2S"
	}
	return "S2C"
}

// Config controls flow timeouts and memory bounds. Zero-value Config is
// invalid; use DefaultConfig().
type Config struct {
	TCPNewTimeout         time.Duration
	TCPEstablishedTimeout time.Duration
	UDPTimeout            time.Duration
	DefaultTimeout        time.Duration
	MaxLifetime           time.Duration
	MaxEntries            int // total across all shards, approximate
}

func DefaultConfig() Config {
	return Config{
		TCPNewTimeout:         60 * time.Second,
		TCPEstablishedTimeout: 300 * time.Second,
		UDPTimeout:            60 * time.Second,
		DefaultTimeout:        30 * time.Second,
		MaxLifetime:           3600 * time.Second,
		MaxEntries:            250_000,
	}
}

type shard struct {
	mu sync.Mutex
	m  map[Key]*State
}

// Table is a sharded flow store. Reads/writes for different flows can
// proceed concurrently; only flows hashing to the same shard contend.
type Table struct {
	cfg         Config
	shards      [numShards]*shard
	maxPerShard int
}

func NewTable(cfg Config) *Table {
	t := &Table{cfg: cfg, maxPerShard: max(1, cfg.MaxEntries/numShards)}
	for i := range t.shards {
		t.shards[i] = &shard{m: make(map[Key]*State)}
	}
	return t
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (t *Table) shardFor(k Key) *shard {
	h := fnv.New32a()
	h.Write(k.IPLow[:])
	h.Write(k.IPHigh[:])
	_ = binary.Write(h, binary.BigEndian, k.PortLow)
	_ = binary.Write(h, binary.BigEndian, k.PortHigh)
	h.Write([]byte{k.Protocol})
	return t.shards[h.Sum32()%numShards]
}

// GetOrCreate returns the State for k, creating it if absent. srcIP is the
// source address of the packet that triggered this lookup, used only when
// creating a new flow (to record its originator). Returns (state, isNew).
func (t *Table) GetOrCreate(k Key, ts time.Time, srcIP net.IP) (*State, bool) {
	sh := t.shardFor(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if s, ok := sh.m[k]; ok {
		s.LastSeen = ts
		return s, false
	}

	if len(sh.m) >= t.maxPerShard {
		evictOldestLocked(sh)
	}

	s := &State{
		ID:           uuid.NewString(),
		Key:          k,
		FirstSeen:    ts,
		LastSeen:     ts,
		OriginatorIP: to16(srcIP),
		Bits:         make(map[string]bool),
	}
	sh.m[k] = s
	return s, true
}

// evictOldestLocked removes the entry with the oldest LastSeen in sh.
// Caller must hold sh.mu. Evicting (rather than rejecting the new flow)
// avoids a blind spot an attacker could exploit by pre-filling flow slots.
func evictOldestLocked(sh *shard) {
	var oldestKey Key
	var oldestTime time.Time
	first := true
	for k, s := range sh.m {
		if first || s.LastSeen.Before(oldestTime) {
			oldestKey, oldestTime, first = k, s.LastSeen, false
		}
	}
	if !first {
		delete(sh.m, oldestKey)
	}
}

func (t *Table) idleTimeout(s *State) time.Duration {
	switch s.Key.Protocol {
	case 6: // TCP
		if s.TCPState == "established" {
			return t.cfg.TCPEstablishedTimeout
		}
		return t.cfg.TCPNewTimeout
	case 17: // UDP
		return t.cfg.UDPTimeout
	default:
		return t.cfg.DefaultTimeout
	}
}

// Sweep removes flows that have exceeded their idle timeout or the hard
// MaxLifetime cap, and returns the number evicted. Intended to run
// periodically (see Config / the sensor's background sweep goroutine).
func (t *Table) Sweep(now time.Time) int {
	evicted := 0
	for _, sh := range t.shards {
		sh.mu.Lock()
		for k, s := range sh.m {
			idle := now.Sub(s.LastSeen) > t.idleTimeout(s)
			tooOld := now.Sub(s.FirstSeen) > t.cfg.MaxLifetime
			if idle || tooOld {
				delete(sh.m, k)
				evicted++
			}
		}
		sh.mu.Unlock()
	}
	return evicted
}

// Len returns the total number of tracked flows across all shards.
func (t *Table) Len() int {
	n := 0
	for _, sh := range t.shards {
		sh.mu.Lock()
		n += len(sh.m)
		sh.mu.Unlock()
	}
	return n
}

// UpdateTCPState applies a best-effort (not a full state machine) update
// based on observed flags, and updates direction-aware counters.
func (s *State) UpdateTCPState(srcIP net.IP, syn, ack, fin, rst bool, payloadLen int) {
	switch {
	case rst:
		s.TCPState = "closed"
	case fin:
		s.TCPState = "closing"
	case syn && !ack && s.TCPState == "":
		s.TCPState = "new"
	case ack && (s.TCPState == "" || s.TCPState == "new"):
		s.TCPState = "established"
	}
	s.CountPacket(srcIP, payloadLen)
}

// Established reports Suricata's meaning of `flow:established`: a TCP flow past
// its handshake (a closing one included — its final segments often carry
// data), or a UDP/ICMP flow that has carried packets in BOTH directions. A
// lone UDP datagram — e.g. an SSDP probe the target never answers — is not.
func (s *State) Established(isTCP bool) bool {
	if isTCP {
		return s.TCPState == "established" || s.TCPState == "closing"
	}
	return s.PacketsC2S > 0 && s.PacketsS2C > 0
}

// CountPacket updates the direction-aware packet and byte counters.
func (s *State) CountPacket(srcIP net.IP, payloadLen int) {
	if s.Direction(srcIP) == "C2S" {
		s.PacketsC2S++
		s.BytesC2S += uint64(payloadLen)
	} else {
		s.PacketsS2C++
		s.BytesS2C += uint64(payloadLen)
	}
}

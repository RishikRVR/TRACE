// Package reassemble performs in-order TCP stream reassembly per flow and
// direction, so a content signature split across TCP segments is matched
// against the reassembled application-layer bytes rather than individual
// packets. Without this, splitting a payload across two segments defeats
// per-packet signature matching (the "tcp-segment" evasion the benchmark
// measures).
//
// Scope and honesty: this handles in-order segments and out-of-order
// segments that eventually become contiguous. It does NOT resolve
// overlapping or retransmitted-with-different-data segments (it keeps the
// first bytes seen for a given sequence range). Those reassembly
// ambiguities are themselves a classic evasion surface (Ptacek & Newsham,
// 1998) and are deliberately left as future work — a real IDS applies a
// target-based reassembly policy there.
package reassemble

import (
	"net"
	"sync"
	"time"

	"github.com/RishikRVR/trace/extractor/internal/event"
)

// StreamMeta identifies a stream and carries the addressing/time needed to
// build a synthetic event for content matching.
type StreamMeta struct {
	FlowID           string
	Dir              string // "C2S" | "S2C"
	Src, Dst         net.IP
	SrcPort, DstPort uint16
	LastTime         time.Time
	// TCPFlags of the segment that most recently extended this stream, carried
	// through so rules combining a flags: constraint with content can still be
	// evaluated against a reassembled stream.
	TCPFlags *event.TCPFlags
}

func (m StreamMeta) key() streamKey { return streamKey{m.FlowID, m.Dir} }

type streamKey struct {
	flowID string
	dir    string
}

// ScanFunc is called with the reassembled buffer whenever it grows. fired is
// a per-stream set the scanner owns; the callback marks rules that have
// already alerted for this stream so a growing buffer does not re-alert.
type ScanFunc func(meta StreamMeta, data []byte, fired map[string]bool) error

type stream struct {
	nextSeq    uint32
	haveSeq    bool
	buf        []byte
	pending    map[uint32][]byte // out-of-order segments keyed by their start seq
	fired      map[string]bool
	meta       StreamMeta
	overflowed bool
}

// Scanner reassembles TCP streams and invokes a ScanFunc over each stream's
// growing buffer. Safe for concurrent use.
type Scanner struct {
	mu        sync.Mutex
	streams   map[streamKey]*stream
	scan      ScanFunc
	maxBuffer int
}

// NewScanner returns a scanner that caps each stream's reassembled buffer at
// maxBuffer bytes.
func NewScanner(scan ScanFunc, maxBuffer int) *Scanner {
	return &Scanner{streams: make(map[streamKey]*stream), scan: scan, maxBuffer: maxBuffer}
}

// Segment feeds one TCP segment (its sequence number and payload) into the
// reassembler, scanning the stream buffer if it grew.
func (s *Scanner) Segment(meta StreamMeta, seq uint32, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}

	s.mu.Lock()
	st, ok := s.streams[meta.key()]
	if !ok {
		st = &stream{pending: make(map[uint32][]byte), fired: make(map[string]bool)}
		s.streams[meta.key()] = st
	}
	st.meta = meta

	grew := st.accept(seq, payload, s.maxBuffer)
	// Snapshot what we need before unlocking so the callback runs lock-free.
	var (
		data  []byte
		fired map[string]bool
	)
	if grew {
		data = st.buf
		fired = st.fired
	}
	s.mu.Unlock()

	if grew {
		return s.scan(meta, data, fired)
	}
	return nil
}

// accept integrates one segment, returning whether the contiguous buffer
// grew. Caller holds the scanner lock.
func (st *stream) accept(seq uint32, payload []byte, maxBuffer int) bool {
	if !st.haveSeq {
		st.nextSeq = seq
		st.haveSeq = true
	}

	switch {
	case seq == st.nextSeq:
		// contiguous
	case seqGreater(seq, st.nextSeq):
		// future segment — queue it (keep first copy seen)
		if _, exists := st.pending[seq]; !exists {
			st.pending[seq] = append([]byte(nil), payload...)
		}
		return false
	default:
		// seq < nextSeq: overlaps already-consumed data. Append only the
		// non-overlapping tail, if any.
		skip := st.nextSeq - seq
		if int(skip) >= len(payload) {
			return false // fully old data
		}
		payload = payload[skip:]
		seq = st.nextSeq
	}

	before := len(st.buf)
	st.appendContiguous(payload, maxBuffer)
	st.drainPending(maxBuffer)
	return len(st.buf) > before
}

func (st *stream) appendContiguous(payload []byte, maxBuffer int) {
	if st.overflowed {
		st.nextSeq += uint32(len(payload))
		return
	}
	room := maxBuffer - len(st.buf)
	if room <= 0 {
		st.overflowed = true
		st.nextSeq += uint32(len(payload))
		return
	}
	if len(payload) > room {
		st.buf = append(st.buf, payload[:room]...)
		st.overflowed = true
	} else {
		st.buf = append(st.buf, payload...)
	}
	st.nextSeq += uint32(len(payload))
}

func (st *stream) drainPending(maxBuffer int) {
	for {
		p, ok := st.pending[st.nextSeq]
		if !ok {
			return
		}
		delete(st.pending, st.nextSeq)
		st.appendContiguous(p, maxBuffer)
	}
}

// seqGreater reports whether a is after b in TCP sequence space, tolerant of
// 32-bit wraparound.
func seqGreater(a, b uint32) bool {
	return int32(a-b) > 0
}

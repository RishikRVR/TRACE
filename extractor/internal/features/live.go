package features

import "time"

// Live switches the extractor to streaming mode for a long-running sensor:
// windows are drained as they close instead of accumulating, and flows idle
// for flowIdle are expired (and handed to Drain) so memory stays bounded.
// Flows() is empty in this mode.
func (x *Extractor) Live(flowIdle time.Duration) *Extractor {
	x.keepAll = false
	x.flowIdle = flowIdle
	return x
}

// Tick closes every window that ended before now and expires idle flows, so
// the sensor keeps emitting while the network is quiet. Call it on a timer.
// maxCatchUp bounds how many empty windows one call will walk through.
func (x *Extractor) Tick(now time.Time) {
	if !x.started {
		// No packet yet: start the clock so the first quiet windows still align.
		ms := now.UnixMilli()
		x.cur, x.started = ms-mod(ms, x.windowMs), true
		return
	}
	target := now.UnixMilli() - mod(now.UnixMilli(), x.windowMs)
	const maxCatchUp = 2880 // one day of 30 s windows
	for n := 0; x.cur < target && n < maxCatchUp; n++ {
		x.flush()
		x.cur += x.windowMs
	}
	if x.cur < target {
		x.cur = target
	}
	x.expireFlows(now)
}

// expireFlows drops flows with no packet for flowIdle, collecting them for
// Drain. A later packet on the same 5-tuple simply starts a new flow.
func (x *Extractor) expireFlows(now time.Time) {
	if x.flowIdle <= 0 {
		return
	}
	for id, f := range x.flows {
		if now.Sub(f.Last) > x.flowIdle {
			x.expired = append(x.expired, f)
			delete(x.flows, id)
		}
	}
}

// Drain returns the window rows completed since the last call, together with
// the flows that expired, and clears both.
func (x *Extractor) Drain() ([]Row, []*Flow) {
	rows, flows := x.rows, x.expired
	x.rows, x.expired = nil, nil
	return rows, flows
}

// Pending reports how many flows and hosts are currently tracked, for the
// sensor's status line.
func (x *Extractor) Pending() (flows int, hosts int) {
	return len(x.flows), len(x.hosts)
}

// ActiveFlows returns the flows currently being tracked, for a live snapshot
// of the connections behind the open window. The returned slice is a copy.
func (x *Extractor) ActiveFlows() []*Flow {
	out := make([]*Flow, 0, len(x.flows))
	for _, f := range x.flows {
		out = append(out, f)
	}
	return out
}

// TTLMeanBwd is the mean TTL seen from the responder, the direction that
// reveals the remote host's OS and distance. Zero when nothing came back.
func (f *Flow) TTLMeanBwd() float64 { return f.ttl[1].mean }

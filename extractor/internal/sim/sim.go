// Package sim generates labelled traffic for a small office network: benign
// background plus multi-stage attack chains. Every episode comes with its
// ground-truth timeline (host, stage, start, end), which stands in for the
// attack schedules public datasets publish, so ml/ derives window labels the
// same way for both. Generation is deterministic for a given Spec.
package sim

import (
	"fmt"
	"math"
	"math/rand"
	"net"
	"sort"
	"time"

	"github.com/RishikRVR/trace/extractor/internal/pktgen"
)

// Stage codes, matching ml/trace_ml/stages.py.
const (
	Benign        = 0
	Recon         = 1
	InitialAccess = 2
	Lateral       = 3
	C2            = 4
	Exfil         = 5
)

// Interval is one ground-truth annotation: host was in stage from Start to End.
type Interval struct {
	Host       string
	Stage      int
	Family     string
	Start, End time.Time
}

// Variant picks how each attack phase is carried out. Empty fields are chosen
// at random by Generate and filled in on the returned Episode.
type Variant struct {
	ReconSpeed string        // fast | medium | slow
	ReconOrder string        // sequential | random
	ProbeGap   time.Duration // fixed gap between probes; overrides ReconSpeed
	Access     string        // ssh_bruteforce | web_exploit (phish episodes: phish_download)
	Lateral    string        // smb | winrm | rdp | ssh
	Exfil      string        // https_bulk | dns_tunnel
}

// Spec describes one episode to generate.
type Spec struct {
	ID      string
	Kind    string // benign | scan_only | full | phish
	Variant Variant
	Seed    int64
	Start   time.Time
}

// Episode is a generated capture: packets in time order plus its timeline.
type Episode struct {
	Spec     Spec
	End      time.Time
	Packets  []pktgen.Packet
	Timeline []Interval
}

// Kinds lists the episode kinds Generate accepts.
var Kinds = []string{"benign", "scan_only", "full", "phish"}

type host struct {
	IP     string
	TTL    uint8 // as seen at the capture point
	Win    uint16
	Subnet int // 1 user LAN, 2 server LAN, 0 external
	Open   map[uint16]bool
	Role   string
	ghost  bool // address with no machine behind it: probes go unanswered
	rtt    time.Duration
}

type gen struct {
	r          *rand.Rand
	spec       Spec
	v          Variant
	start, end time.Time
	pkts       []pktgen.Packet
	tl         []Interval
	err        error

	workstations                           []*host
	admin, dc, file, web, dns, mon, backup *host
	attacker, c2srv, exfilSrv              *host
	webPool                                []*host
	all                                    map[string]*host
}

var (
	fSYN    = pktgen.TCPFlags{SYN: true}
	fSYNACK = pktgen.TCPFlags{SYN: true, ACK: true}
	fACK    = pktgen.TCPFlags{ACK: true}
	fPSHACK = pktgen.TCPFlags{PSH: true, ACK: true}
	fFINACK = pktgen.TCPFlags{FIN: true, ACK: true}
	fRST    = pktgen.TCPFlags{RST: true}
	fRSTACK = pktgen.TCPFlags{RST: true, ACK: true}
)

// Generate builds one episode.
func Generate(spec Spec) (*Episode, error) {
	g := &gen{r: rand.New(rand.NewSource(spec.Seed)), spec: spec, v: spec.Variant, start: spec.Start, all: map[string]*host{}}
	g.network()
	g.fillVariant()

	switch spec.Kind {
	case "benign":
		g.end = g.start.Add(g.minutes(40, 60))
	case "scan_only":
		t := g.recon(g.start.Add(g.minutes(6, 15)), g.web)
		g.end = t.Add(g.minutes(12, 25))
	case "full":
		t := g.recon(g.start.Add(g.minutes(6, 15)), g.web)
		t = g.access(t.Add(g.minutes(1, 6)), g.web)
		g.chain(t, g.web)
	case "phish":
		victim := g.workstations[g.r.Intn(len(g.workstations))]
		t := g.phish(g.start.Add(g.minutes(6, 15)), victim)
		g.chain(t, victim)
	default:
		return nil, fmt.Errorf("sim: unknown episode kind %q", spec.Kind)
	}
	g.background()
	if g.err != nil {
		return nil, g.err
	}
	sort.SliceStable(g.pkts, func(i, j int) bool { return g.pkts[i].Timestamp.Before(g.pkts[j].Timestamp) })
	spec.Variant = g.v
	return &Episode{Spec: spec, End: g.end, Packets: g.pkts, Timeline: g.tl}, nil
}

// --- network ---------------------------------------------------------------

// sortedPorts gives a map of ports a stable order. Go randomises map
// iteration, so generating traffic straight from a map would make the same
// seed produce a different capture on every run.
func sortedPorts(m map[uint16]bool) []uint16 {
	out := make([]uint16, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func ports(ps ...uint16) map[uint16]bool {
	m := map[uint16]bool{}
	for _, p := range ps {
		m[p] = true
	}
	return m
}

func (g *gen) internal(ip string, ttl uint8, win uint16, subnet int, role string, open map[uint16]bool) *host {
	h := &host{IP: ip, TTL: ttl, Win: win, Subnet: subnet, Open: open, Role: role, rtt: g.secs(0.0003, 0.002)}
	g.all[ip] = h
	return h
}

// external makes an Internet host. baseTTL is its OS default; the capture
// point sees it after 8-22 hops.
func (g *gen) external(ip string, baseTTL uint8, win uint16, open map[uint16]bool) *host {
	return &host{IP: ip, TTL: baseTTL - uint8(8+g.r.Intn(15)), Win: win, Open: open, Role: "external", rtt: g.secs(0.015, 0.12)}
}

func (g *gen) network() {
	n := 6 + g.r.Intn(4)
	for i := 0; i < n; i++ {
		open := ports(135, 139, 445)
		if g.r.Float64() < 0.5 {
			open[3389] = true
		}
		if g.r.Float64() < 0.3 {
			open[5985] = true
		}
		g.workstations = append(g.workstations, g.internal(fmt.Sprintf("10.0.1.%d", 10+i), 128, 64240, 1, "workstation", open))
	}
	g.admin = g.internal("10.0.1.5", 128, 64240, 1, "admin", ports(135, 139, 445, 3389, 5985))
	g.dc = g.internal("10.0.2.10", 128, 65535, 2, "dc", ports(53, 88, 135, 389, 445, 3389, 5985))
	g.file = g.internal("10.0.2.11", 128, 65535, 2, "file", ports(135, 139, 445, 5985))
	g.web = g.internal("10.0.2.12", 64, 29200, 2, "web", ports(22, 80, 443))
	g.mon = g.internal("10.0.2.20", 64, 29200, 2, "monitor", ports(22))
	g.backup = g.internal("10.0.2.30", 64, 29200, 2, "backup", ports(22, 873))
	g.dns = g.internal("10.0.2.53", 64, 29200, 2, "dns", ports(53))

	g.attacker = g.external(fmt.Sprintf("185.220.101.%d", 1+g.r.Intn(254)), 64, 64240, ports(8000, 4444))
	g.c2srv = g.external(fmt.Sprintf("91.219.236.%d", 1+g.r.Intn(254)), 64, 29200, ports(443, 8080))
	g.exfilSrv = g.external(fmt.Sprintf("104.21.%d.%d", g.r.Intn(256), 1+g.r.Intn(254)), 64, 65535, ports(443))
	for i := 0; i < 30; i++ {
		ttl := uint8(64)
		if g.r.Float64() < 0.3 {
			ttl = 128
		}
		ip := fmt.Sprintf("%d.%d.%d.%d", []int{93, 151, 142, 13, 52, 104}[g.r.Intn(6)], g.r.Intn(256), g.r.Intn(256), 1+g.r.Intn(254))
		g.webPool = append(g.webPool, g.external(ip, ttl, 65535, ports(80, 443)))
	}
}

func (g *gen) fillVariant() {
	pick := func(cur *string, opts ...string) {
		if *cur == "" {
			*cur = opts[g.r.Intn(len(opts))]
		}
	}
	pick(&g.v.ReconSpeed, "fast", "medium", "slow")
	pick(&g.v.ReconOrder, "sequential", "random")
	if g.spec.Kind == "phish" {
		g.v.Access = "phish_download"
	}
	pick(&g.v.Access, "ssh_bruteforce", "web_exploit")
	pick(&g.v.Lateral, "smb", "winrm", "rdp", "ssh")
	pick(&g.v.Exfil, "https_bulk", "https_bulk", "https_bulk", "https_bulk", "dns_tunnel") // DNS tunnelling: the held-out family
	switch g.spec.Kind {
	case "benign":
		g.v = Variant{}
	case "scan_only":
		g.v.Access, g.v.Lateral, g.v.Exfil = "", "", ""
	}
}

// --- randomness helpers ----------------------------------------------------

func (g *gen) secs(a, b float64) time.Duration {
	return time.Duration((a + g.r.Float64()*(b-a)) * float64(time.Second))
}

func (g *gen) minutes(a, b float64) time.Duration { return g.secs(a*60, b*60) }

func (g *gen) around(d time.Duration, frac float64) time.Duration {
	return time.Duration(float64(d) * (1 + frac*(2*g.r.Float64()-1)))
}

func (g *gen) exp(mean time.Duration) time.Duration {
	return time.Duration(g.r.ExpFloat64() * float64(mean))
}

func (g *gen) between(a, b int) int { return a + g.r.Intn(b-a+1) }

// sizeAround draws a byte count from a log-normal with the given median.
func (g *gen) sizeAround(median float64, capAt int) int {
	n := int(median * math.Exp(0.9*g.r.NormFloat64()))
	if n < 40 {
		n = 40
	}
	if n > capAt {
		n = capAt
	}
	return n
}

func (g *gen) ephemeral() uint16 { return uint16(49152 + g.r.Intn(16383)) }

// --- packet emission -------------------------------------------------------

func (g *gen) rtt(a, b *host) time.Duration {
	if a.rtt > b.rtt {
		return a.rtt
	}
	return b.rtt
}

// segGap is the wire time per full-size segment on the path between a and b.
func (g *gen) segGap(a, b *host) time.Duration {
	if a.Subnet == 0 || b.Subnet == 0 {
		return g.around(700*time.Microsecond, 0.5)
	}
	return g.around(120*time.Microsecond, 0.5)
}

func obsTTL(src, dst *host) uint8 {
	if src.Subnet != 0 && dst.Subnet != 0 && src.Subnet != dst.Subnet {
		return src.TTL - 1 // one router hop between the user and server LANs
	}
	return src.TTL
}

var zeros = make([]byte, 1460)

func (g *gen) emit(t time.Time, src, dst *host, sport, dport uint16, seq uint32, flags pktgen.TCPFlags, plen int, win uint16) {
	if t.After(g.end) && !g.end.IsZero() && t.Sub(g.end) > time.Minute {
		return
	}
	data, err := pktgen.TCPWith(src.IP, dst.IP, sport, dport, seq, flags, zeros[:plen], pktgen.Opts{TTL: obsTTL(src, dst), Window: win, DF: true})
	if err != nil {
		g.err = err
		return
	}
	g.pkts = append(g.pkts, pktgen.Packet{Data: data, Timestamp: t})
}

func (g *gen) dnsLookup(t time.Time, h *host, name string) time.Time {
	sport := g.ephemeral()
	q, err := pktgen.DNSQueryWith(h.IP, g.dns.IP, sport, name, pktgen.Opts{TTL: obsTTL(h, g.dns)})
	if err != nil {
		g.err = err
		return t
	}
	g.pkts = append(g.pkts, pktgen.Packet{Data: q, Timestamp: t})
	t = t.Add(g.rtt(h, g.dns) + g.secs(0.001, 0.03))
	ans := net.IPv4(byte(93+g.r.Intn(60)), byte(g.r.Intn(256)), byte(g.r.Intn(256)), byte(1+g.r.Intn(254)))
	resp, err := pktgen.DNSResponseWith(g.dns.IP, h.IP, sport, name, ans, pktgen.Opts{TTL: obsTTL(g.dns, h)})
	if err != nil {
		g.err = err
		return t
	}
	g.pkts = append(g.pkts, pktgen.Packet{Data: resp, Timestamp: t})
	return t
}

// session emits one complete TCP connection from c to s:dport carrying req
// bytes up and resp bytes down, and returns the time of its last packet.
func (g *gen) session(t time.Time, c, s *host, dport uint16, req, resp int) time.Time {
	return g.sessionFrom(t, c, s, g.ephemeral(), dport, req, resp, true)
}

func (g *gen) sessionFrom(t time.Time, c, s *host, sport, dport uint16, req, resp int, fin bool) time.Time {
	rtt := g.rtt(c, s)
	cs, ss := g.r.Uint32(), g.r.Uint32()
	g.emit(t, c, s, sport, dport, cs, fSYN, 0, c.Win)
	t = t.Add(rtt / 2)
	g.emit(t, s, c, dport, sport, ss, fSYNACK, 0, s.Win)
	t = t.Add(rtt / 2)
	cs, ss = cs+1, ss+1
	g.emit(t, c, s, sport, dport, cs, fACK, 0, c.Win)
	gap := g.segGap(c, s)
	for req > 0 {
		n := min(req, 1460)
		t = t.Add(gap)
		g.emit(t, c, s, sport, dport, cs, fPSHACK, n, c.Win)
		cs += uint32(n)
		req -= n
	}
	if resp > 0 {
		t = t.Add(rtt/2 + g.secs(0.001, 0.05))
	}
	for seg := 1; resp > 0; seg++ {
		n := min(resp, 1460)
		flags := fACK
		if resp <= 1460 {
			flags = fPSHACK
		}
		t = t.Add(gap)
		g.emit(t, s, c, dport, sport, ss, flags, n, s.Win)
		ss += uint32(n)
		resp -= n
		if seg%2 == 0 || resp == 0 {
			g.emit(t.Add(rtt/2), c, s, sport, dport, cs, fACK, 0, c.Win)
		}
	}
	t = t.Add(rtt + g.secs(0, 0.2))
	if fin {
		g.emit(t, c, s, sport, dport, cs, fFINACK, 0, c.Win)
		t = t.Add(rtt / 2)
		g.emit(t, s, c, dport, sport, ss, fFINACK, 0, s.Win)
		t = t.Add(rtt / 2)
		g.emit(t, c, s, sport, dport, cs+1, fACK, 0, c.Win)
	} else {
		g.emit(t, c, s, sport, dport, cs, fRSTACK, 0, 0)
	}
	return t
}

// interactive emits a long-lived shell-like connection: small packets both
// ways at irregular human-scale gaps, for about dur.
func (g *gen) interactive(t time.Time, c, s *host, dport uint16, dur time.Duration, big int) time.Time {
	sport := g.ephemeral()
	rtt := g.rtt(c, s)
	cs, ss := g.r.Uint32(), g.r.Uint32()
	g.emit(t, c, s, sport, dport, cs, fSYN, 0, c.Win)
	g.emit(t.Add(rtt/2), s, c, dport, sport, ss, fSYNACK, 0, s.Win)
	t = t.Add(rtt)
	cs, ss = cs+1, ss+1
	g.emit(t, c, s, sport, dport, cs, fACK, 0, c.Win)
	end := t.Add(dur)
	for t.Before(end) {
		t = t.Add(g.secs(0.2, 4))
		n := g.between(20, 200)
		g.emit(t, c, s, sport, dport, cs, fPSHACK, n, c.Win)
		cs += uint32(n)
		m := g.between(40, big)
		for m > 0 {
			k := min(m, 1460)
			t = t.Add(rtt/2 + g.segGap(c, s))
			g.emit(t, s, c, dport, sport, ss, fPSHACK, k, s.Win)
			ss += uint32(k)
			m -= k
		}
		g.emit(t.Add(rtt/2), c, s, sport, dport, cs, fACK, 0, c.Win)
	}
	g.emit(t.Add(rtt), c, s, sport, dport, cs, fFINACK, 0, c.Win)
	g.emit(t.Add(rtt*3/2), s, c, dport, sport, ss, fFINACK, 0, s.Win)
	g.emit(t.Add(rtt*2), c, s, sport, dport, cs+1, fACK, 0, c.Win)
	return t.Add(rtt * 2)
}

// probe emits one scan probe from a to v:dport and v's answer: SYN/ACK for an
// open port (then RST, or a completed handshake for a connect scan), RST/ACK
// for a closed one, silence for an address with no host.
func (g *gen) probe(t time.Time, a, v *host, sport, dport uint16, win uint16, connect bool) {
	seq := g.r.Uint32()
	g.emit(t, a, v, sport, dport, seq, fSYN, 0, win)
	if v.ghost {
		return
	}
	rtt := g.rtt(a, v)
	if v.Open[dport] {
		g.emit(t.Add(rtt/2), v, a, dport, sport, g.r.Uint32(), fSYNACK, 0, v.Win)
		if connect {
			g.emit(t.Add(rtt), a, v, sport, dport, seq+1, fACK, 0, win)
			g.emit(t.Add(rtt+time.Millisecond), a, v, sport, dport, seq+1, fRSTACK, 0, 0)
		} else {
			g.emit(t.Add(rtt), a, v, sport, dport, seq+1, fRST, 0, 0)
		}
		return
	}
	g.emit(t.Add(rtt/2), v, a, dport, sport, 0, fRSTACK, 0, 0)
}

func (g *gen) mark(h *host, stage int, family string, start, end time.Time) {
	g.tl = append(g.tl, Interval{Host: h.IP, Stage: stage, Family: family, Start: start, End: end})
}

// --- attack phases ---------------------------------------------------------

var popularHigh = []uint16{1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017}

func (g *gen) scanPorts(n int, sequential bool, must map[uint16]bool) []uint16 {
	if sequential {
		first := g.between(1, 20)
		out := make([]uint16, 0, n)
		for p := first; len(out) < n && p < 65536; p++ {
			out = append(out, uint16(p))
		}
		return out
	}
	pool := make([]uint16, 0, 1024+len(popularHigh))
	for p := 1; p <= 1024; p++ {
		pool = append(pool, uint16(p))
	}
	pool = append(pool, popularHigh...)
	g.r.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	if n > len(pool) {
		n = len(pool)
	}
	out := pool[:n]
	for _, p := range sortedPorts(must) { // make sure the real services are among the probed ports
		found := false
		for _, q := range out {
			found = found || q == p
		}
		if !found && len(out) > 0 {
			out[g.r.Intn(len(out))] = p
		}
	}
	return out
}

// recon scans v from the Internet and grabs banners from its open ports.
func (g *gen) recon(t time.Time, v *host) time.Time {
	var gap time.Duration
	var n int
	speed := g.v.ReconSpeed
	switch {
	case g.v.ProbeGap > 0:
		gap = g.v.ProbeGap
		n = max(30, min(1000, int(20*time.Minute/gap)))
		speed = fmt.Sprintf("gap%gs", gap.Seconds())
	case speed == "fast":
		gap, n = g.secs(0.02, 0.06), g.between(600, 1000)
	case speed == "medium":
		gap, n = g.secs(0.25, 0.8), g.between(120, 300)
	default:
		gap = g.secs(8, 25)
		n = max(40, min(120, int(22*time.Minute/gap)))
	}
	connect := gap >= 5*time.Second && g.r.Float64() < 0.5 // slow scans often use full connects
	win := uint16(1024)                                    // nmap-style raw SYN probe
	if connect {
		win = g.attacker.Win
	}
	list := g.scanPorts(n, g.v.ReconOrder == "sequential", v.Open)
	start := t
	sport := g.ephemeral()
	for _, p := range list {
		if connect {
			sport = g.ephemeral()
		}
		g.probe(t, g.attacker, v, sport, p, win, connect)
		t = t.Add(g.around(gap, 0.3))
	}
	for _, p := range sortedPorts(v.Open) {
		t = t.Add(g.secs(1, 5))
		t = g.session(t, g.attacker, v, p, g.between(20, 200), g.between(100, 1500))
	}
	g.mark(v, Recon, "portscan-"+speed, start, t)
	return t
}

// access breaks into v and returns when the attacker has a foothold.
func (g *gen) access(t time.Time, v *host) time.Time {
	start := t
	switch g.v.Access {
	case "ssh_bruteforce":
		n := g.between(80, 250)
		for i := 0; i < n; i++ {
			g.session(t, g.attacker, v, 22, g.between(900, 1600), g.between(1100, 2200))
			t = t.Add(g.secs(0.2, 1.2))
		}
		t = g.interactive(t, g.attacker, v, 22, g.minutes(1, 2.5), 3000)
	default: // web_exploit
		n := g.between(8, 25)
		for i := 0; i < n; i++ {
			t = g.session(t, g.attacker, v, []uint16{80, 443}[g.r.Intn(2)], g.between(1000, 4000), g.between(300, 2000))
			t = t.Add(g.secs(1, 6))
		}
		t = g.interactive(t, v, g.attacker, 4444, g.minutes(1, 3), 2500) // reverse shell
	}
	// the attacker pulls tools onto the foothold
	t = g.session(t.Add(g.secs(5, 20)), v, g.attacker, 8000, g.between(200, 600), g.between(200_000, 800_000))
	g.mark(v, InitialAccess, g.v.Access, start, t)
	return t
}

// phish is the no-recon entry: a user downloads a malicious payload.
func (g *gen) phish(t time.Time, v *host) time.Time {
	start := t
	t = g.dnsLookup(t, v, fmt.Sprintf("invoice-%d.%s", g.between(1000, 9999), []string{"top", "xyz", "click"}[g.r.Intn(3)]))
	srv := g.webPool[g.r.Intn(len(g.webPool))]
	t = g.session(t.Add(g.secs(0.01, 0.2)), v, srv, 443, g.between(400, 900), g.between(300_000, 1_200_000))
	g.mark(v, InitialAccess, "phish_download", start, t)
	return t.Add(g.secs(20, 60))
}

// c2 makes h beacon to the C2 server from start to end.
func (g *gen) c2(h *host, start, end time.Time) {
	period := g.secs(20, 60)
	jitter := 0.05 + 0.1*g.r.Float64()
	port := uint16(443)
	if g.r.Float64() < 0.3 {
		port = 8080
	}
	for t, i := start, 0; t.Before(end); i++ {
		resp := g.between(60, 700)
		if i%10 == 9 {
			resp = g.between(5_000, 30_000) // tasking
		}
		g.session(t, h, g.c2srv, port, g.between(120, 400), resp)
		t = t.Add(g.around(period, jitter))
	}
	g.mark(h, C2, "c2-beacon", start, end)
}

type compromise struct {
	h  *host
	at time.Time
}

// lateral sweeps the internal network from src and takes over 1-3 hosts.
func (g *gen) lateral(t time.Time, src *host) (time.Time, []compromise) {
	start := t
	port := map[string]uint16{"smb": 445, "winrm": 5985, "rdp": 3389, "ssh": 22}[g.v.Lateral]
	var targets []*host
	for i := 1; i <= 40; i++ {
		ip := fmt.Sprintf("10.0.1.%d", i)
		h, ok := g.all[ip]
		if !ok {
			h = &host{IP: ip, Subnet: 1, ghost: true, rtt: time.Millisecond}
		}
		targets = append(targets, h)
	}
	targets = append(targets, g.dc, g.file, g.web, g.backup)
	g.r.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })
	gap := g.secs(0.03, 0.3)
	if g.r.Float64() < 0.4 {
		gap = g.secs(1, 3)
	}
	var candidates []*host
	for _, h := range targets {
		if h == src {
			continue
		}
		for _, p := range []uint16{445, 3389, 22, 5985, 135} {
			g.probe(t, src, h, g.ephemeral(), p, src.Win, true)
			t = t.Add(g.around(gap, 0.3))
		}
		if !h.ghost && h.Open[port] {
			candidates = append(candidates, h)
		}
	}
	g.r.Shuffle(len(candidates), func(i, j int) { candidates[i], candidates[j] = candidates[j], candidates[i] })
	// prefer the file server: it holds the data worth stealing
	for i, h := range candidates {
		if h == g.file {
			candidates[0], candidates[i] = candidates[i], candidates[0]
		}
	}
	var took []compromise
	for i := 0; i < len(candidates) && i < g.between(1, 3); i++ {
		h := candidates[i]
		t = t.Add(g.secs(5, 40))
		s := t
		switch g.v.Lateral {
		case "smb":
			t = g.session(t, src, h, 445, g.between(150_000, 600_000), g.between(5_000, 20_000))
			t = g.session(t.Add(g.secs(0.5, 2)), src, h, 135, g.between(1_000, 3_000), g.between(1_000, 3_000))
		case "winrm":
			for k := g.between(2, 4); k > 0; k-- {
				t = g.session(t.Add(g.secs(0.5, 3)), src, h, 5985, g.between(5_000, 60_000), g.between(5_000, 60_000))
			}
		default: // rdp, ssh: an interactive session
			t = g.interactive(t, src, h, port, g.minutes(1, 3), 6000)
		}
		g.mark(h, Lateral, "lateral_"+g.v.Lateral, s, t)
		took = append(took, compromise{h: h, at: t})
	}
	g.mark(src, Lateral, "lateral_"+g.v.Lateral, start, t)
	return t, took
}

// exfil moves data from src to the outside.
func (g *gen) exfil(t time.Time, src *host) time.Time {
	start := t
	switch g.v.Exfil {
	case "dns_tunnel":
		const alpha = "abcdefghijklmnopqrstuvwxyz234567"
		domain := fmt.Sprintf("%s.net", []string{"cdn-sync", "telemetry-hub", "static-edge"}[g.r.Intn(3)])
		end := t.Add(g.minutes(3, 6))
		for t.Before(end) {
			b := make([]byte, g.between(40, 60))
			for i := range b {
				b[i] = alpha[g.r.Intn(len(alpha))]
			}
			g.dnsLookup(t, src, string(b)+"."+domain)
			t = t.Add(g.secs(0.3, 1.5))
		}
	default: // https_bulk
		total := g.between(3_000_000, 12_000_000)
		parts := g.between(1, 4)
		for i := 0; i < parts; i++ {
			t = g.session(t, src, g.exfilSrv, 443, total/parts, g.between(2_000, 10_000))
			t = t.Add(g.secs(5, 40))
		}
	}
	g.mark(src, Exfil, g.v.Exfil, start, t)
	return t
}

// chain runs the post-compromise stages from a foothold: C2, lateral
// movement, then exfiltration.
func (g *gen) chain(t time.Time, foothold *host) {
	c2Start := t.Add(g.secs(10, 60))
	latEnd, took := g.lateral(c2Start.Add(g.minutes(3, 8)), foothold)
	src := foothold
	for _, c := range took {
		if c.h == g.file {
			src = g.file
		}
	}
	exEnd := g.exfil(latEnd.Add(g.minutes(4, 10)), src)
	g.end = exEnd.Add(g.minutes(3, 6))
	g.c2(foothold, c2Start, g.end)
	for _, c := range took {
		g.c2(c.h, c.at.Add(g.secs(30, 90)), g.end)
	}
}

// --- benign background -----------------------------------------------------

var benignDomains = []string{
	"www.google.com", "mail.office365.com", "teams.microsoft.com", "cdn.jsdelivr.net", "www.wikipedia.org",
	"api.github.com", "www.amazon.in", "outlook.office.com", "update.microsoft.com", "www.youtube.com",
	"accounts.google.com", "slack.com", "zoom.us", "www.linkedin.com", "docs.python.org", "intranet.corp.local",
	"fileserver.corp.local", "dc01.corp.local", "www.nic.in", "www.irctc.co.in", "fonts.gstatic.com",
}

func (g *gen) browse(t time.Time, h *host) time.Time {
	t = g.dnsLookup(t, h, benignDomains[g.r.Intn(len(benignDomains))])
	srv := g.webPool[g.r.Intn(len(g.webPool))]
	port := uint16(443)
	if g.r.Float64() < 0.15 {
		port = 80
	}
	return g.session(t.Add(g.secs(0.001, 0.05)), h, srv, port, g.between(300, 900), g.sizeAround(8_000, 300_000))
}

func (g *gen) userActivity(h *host, meanGap time.Duration) {
	idleFrom, idleTo := time.Time{}, time.Time{}
	if g.r.Float64() < 0.3 {
		idleFrom = g.start.Add(g.minutes(5, 30))
		idleTo = idleFrom.Add(g.minutes(5, 15))
	}
	for t := g.start.Add(g.exp(meanGap)); t.Before(g.end); t = t.Add(g.exp(meanGap)) {
		if t.After(idleFrom) && t.Before(idleTo) {
			continue
		}
		switch x := g.r.Float64(); {
		case x < 0.70:
			g.browse(t, h)
		case x < 0.80:
			g.session(t, h, g.file, 445, g.between(200, 2_000), g.sizeAround(20_000, 400_000))
		case x < 0.88:
			g.session(t, h, g.dc, []uint16{88, 389}[g.r.Intn(2)], g.between(200, 1_500), g.between(200, 3_000))
		case x < 0.985:
			g.dnsLookup(t, h, benignDomains[g.r.Intn(len(benignDomains))])
		default: // software update
			g.session(t, h, g.webPool[g.r.Intn(len(g.webPool))], 443, g.between(400, 800), g.between(1_000_000, 4_000_000))
		}
	}
}

func (g *gen) background() {
	for _, w := range g.workstations {
		g.userActivity(w, g.secs(6, 25))
	}
	g.userActivity(g.admin, g.secs(10, 30))
	// the admin legitimately uses SSH and RDP: benign traffic on lateral-movement ports
	for t := g.start.Add(g.minutes(0.5, 5)); t.Before(g.end); t = t.Add(g.minutes(2, 7)) {
		srv := []*host{g.web, g.backup, g.mon}[g.r.Intn(3)]
		g.interactive(t, g.admin, srv, 22, g.secs(20, 90), 2000)
	}
	if g.r.Float64() < 0.5 {
		w := g.workstations[g.r.Intn(len(g.workstations))]
		if w.Open[3389] {
			g.interactive(g.start.Add(g.minutes(5, 30)), g.admin, w, 3389, g.minutes(1, 4), 8000)
		}
	}
	// the public web server takes Internet traffic all day
	for t := g.start.Add(g.exp(4 * time.Second)); t.Before(g.end); t = t.Add(g.exp(g.secs(2, 8))) {
		c := g.webPool[g.r.Intn(len(g.webPool))]
		g.session(t, c, g.web, 443, g.between(300, 1_200), g.sizeAround(6_000, 80_000))
	}
	// monitoring checks every server's service once a minute: regular, many peers
	for t := g.start.Add(g.secs(1, 60)); t.Before(g.end); t = t.Add(g.around(time.Minute, 0.02)) {
		for i, s := range []*host{g.dc, g.file, g.web, g.dns, g.backup} {
			p := sortedPorts(s.Open)[0]
			g.probe(t.Add(time.Duration(i)*50*time.Millisecond), g.mon, s, g.ephemeral(), p, g.mon.Win, true)
		}
	}
	// nightly-style backup and a user's cloud upload: benign bulk transfers
	if g.r.Float64() < 0.4 {
		g.session(g.start.Add(g.minutes(3, 35)), g.file, g.backup, 873, g.between(4_000_000, 15_000_000), g.between(1_000, 5_000))
	}
	if g.r.Float64() < 0.25 {
		w := g.workstations[g.r.Intn(len(g.workstations))]
		g.session(g.start.Add(g.minutes(3, 35)), w, g.webPool[g.r.Intn(len(g.webPool))], 443, g.between(2_000_000, 8_000_000), g.between(2_000, 8_000))
	}
}

// Package features turns decoded packets into TRACE's two record types
// (docs/feature-schema-v1.md): one row per flow, and one state vector per
// internal host per time window. The window rows are the S_t the world model
// learns P(S_t+1 | S_t) from.
package features

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/RishikRVR/trace/extractor/internal/event"
)

// SchemaVersion is written into every windows.csv row and into schema.json.
const SchemaVersion = 1

// FlowLevel lists the NetFlow/IPFIX-style window features, in column order.
var FlowLevel = []string{
	"f_pkts_out", "f_pkts_in", "f_bytes_out", "f_bytes_in", "f_bytes_ratio",
	"f_flows_active", "f_flows_new_out", "f_flows_new_in", "f_flows_bidir_frac",
	"f_flow_dur_mean", "f_flow_dur_max", "f_flow_pkts_mean", "f_flow_bytes_mean",
	"f_flow_iat_mean", "f_flow_iat_var", "f_flow_iat_max",
	"f_proto_tcp_frac", "f_proto_udp_frac", "f_proto_icmp_frac",
	"f_tcp_syn_out", "f_tcp_ack_out", "f_tcp_fin_out", "f_tcp_rst_out", "f_tcp_psh_out", "f_tcp_urg_out",
	"f_tcp_syn_in", "f_tcp_ack_in", "f_tcp_fin_in", "f_tcp_rst_in", "f_tcp_psh_in", "f_tcp_urg_in",
	"f_syn_only_out", "f_conn_fail_out",
	"f_uniq_peer_out", "f_uniq_peer_in", "f_uniq_dport_out", "f_uniq_lport_in", "f_internal_peer_frac",
	"f_admin_conn_out", "f_admin_conn_in",
	"f_dns_queries_out", "f_dns_qname_entropy_mean", "f_dns_qname_len_max",
}

// PacketLevel lists the PCAP-only window features, in column order. They are
// missing (and masked by ml/) when a window is built from a CSV flow file.
var PacketLevel = []string{
	"p_ttl_in_mean", "p_ttl_in_var", "p_ttl_in_distinct", "p_ttl_out_mean", "p_ttl_out_var", "p_flow_ttl_var_mean",
	"p_tcp_win_mean", "p_tcp_win_var", "p_tcp_win_zero", "p_tcp_syn_win_mean",
	"p_frag_mf", "p_frag_offset", "p_frag_df_frac",
	"p_payload_mean", "p_payload_var",
	"p_payload_bin_0", "p_payload_bin_1_64", "p_payload_bin_65_256", "p_payload_bin_257_512",
	"p_payload_bin_513_1024", "p_payload_bin_1025_1460", "p_payload_bin_gt1460",
	"p_retrans_out", "p_retrans_in",
	"p_dport_seq_frac_out", "p_dport_entropy_out", "p_lport_seq_frac_in", "p_lport_entropy_in",
	"p_iat_out_mean", "p_iat_out_var", "p_iat_out_max", "p_iat_out_cv",
}

// Names is every window feature in column order: FlowLevel then PacketLevel.
var Names = append(append([]string{}, FlowLevel...), PacketLevel...)

var nameIndex = func() map[string]int {
	m := make(map[string]int, len(Names))
	for i, n := range Names {
		m[n] = i
	}
	return m
}()

// adminPorts are the remote-administration ports that lateral movement uses.
var adminPorts = map[uint16]bool{22: true, 23: true, 135: true, 139: true, 445: true, 3389: true, 5985: true, 5986: true}

// Config controls windowing and which addresses count as internal hosts.
type Config struct {
	Window   time.Duration
	Internal []*net.IPNet
	Source   string // value of the source column, usually the input file name
}

// RFC1918 returns the private IPv4 ranges, the default internal set.
func RFC1918() []*net.IPNet {
	nets, _ := ParseCIDRs("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
	return nets
}

// ParseCIDRs parses a comma-separated CIDR list.
func ParseCIDRs(list string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("internal range %q: %w", s, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// Row is one host's state vector for one window.
type Row struct {
	Source      string
	Host        string
	WindowStart int64 // Unix ms, aligned to the window length
	Values      []float64
}

// Flow accumulates the per-flow statistics written to flows.csv and used for
// the window's flow-level aggregates. Index 0 is the originator's direction
// ("fwd"), 1 the responder's ("bwd").
type Flow struct {
	ID               event.FlowID
	First, Last      time.Time
	SrcIP, DstIP     string // originator, responder
	SrcPort, DstPort uint16
	Proto            event.Protocol
	Pkts, Bytes      [2]uint64
	Flags            [2][6]uint32 // SYN ACK FIN RST PSH URG
	Retrans          [2]uint32
	SynWinFwd        float64 // window on the originator's first SYN; -1 if none
	FragMF           uint32

	iat     welford
	iatMax  float64
	ttl     [2]welford
	win     [2]welford
	payload welford
	seqEnd  [2]uint32
	seqSeen [2]bool
}

// State summarises how a TCP flow ended, Zeek-style: S0 (no reply), EST
// (handshake seen), FIN, RST, OTH. Empty for non-TCP flows.
func (f *Flow) State() string {
	if f.Proto != event.ProtoTCP {
		return ""
	}
	switch {
	case f.Flags[0][3]+f.Flags[1][3] > 0:
		return "RST"
	case f.Flags[0][2] > 0 && f.Flags[1][2] > 0:
		return "FIN"
	case f.Flags[0][0] > 0 && f.Flags[1][0] > 0:
		return "EST"
	case f.Flags[0][0] > 0 && f.Pkts[1] == 0:
		return "S0"
	default:
		return "OTH"
	}
}

// update adds one packet in direction d and reports whether it was a TCP
// retransmission (its sequence range was already seen in that direction).
func (f *Flow) update(ev *event.NetworkEvent, d int) bool {
	ts := ev.Timestamp
	if f.Pkts[0]+f.Pkts[1] > 0 {
		gap := ts.Sub(f.Last).Seconds()
		f.iat.add(gap)
		f.iatMax = math.Max(f.iatMax, gap)
	}
	f.Last = ts
	plen := ev.Payload.Length
	f.Pkts[d]++
	f.Bytes[d] += uint64(plen)
	f.payload.add(float64(plen))
	if ev.Header.IPTTL != nil {
		f.ttl[d].add(float64(*ev.Header.IPTTL))
	}
	if fb := ev.Header.FragBits; fb != nil && fb.MoreFragments {
		f.FragMF++
	}
	tf := ev.TCPFlags
	if tf == nil {
		return false
	}
	for i, set := range [6]bool{tf.SYN, tf.ACK, tf.FIN, tf.RST, tf.PSH, tf.URG} {
		if set {
			f.Flags[d][i]++
		}
	}
	if w := ev.Header.TCPWindow; w != nil {
		f.win[d].add(float64(*w))
		if d == 0 && tf.SYN && !tf.ACK && f.SynWinFwd < 0 {
			f.SynWinFwd = float64(*w)
		}
	}
	if plen == 0 {
		return false
	}
	end := ev.TCPSeq + uint32(plen)
	if f.seqSeen[d] && int32(end-f.seqEnd[d]) <= 0 {
		f.Retrans[d]++
		return true
	}
	if !f.seqSeen[d] || int32(end-f.seqEnd[d]) > 0 {
		f.seqEnd[d], f.seqSeen[d] = end, true
	}
	return false
}

// hostWindow accumulates one internal host's packets within one window.
type hostWindow struct {
	pktsOut, pktsIn, bytesOut, bytesIn float64
	tcp, udp, icmp, total              float64
	flagsOut, flagsIn                  [6]float64
	synOnlyOut                         float64
	peersOut, peersIn                  map[string]bool // peer -> is internal
	dportOrder, lportOrder             []uint16
	dportCount, lportCount             map[uint16]int
	active                             map[event.FlowID]*Flow
	newOut, newIn, adminOut, adminIn   float64
	dnsQ, dnsEntSum, dnsLenMax         float64
	ttlIn, ttlOut                      welford
	ttlInSet                           map[uint8]bool
	win, synWin                        welford
	winZero                            float64
	fragMF, fragOff, df, ipv4          float64
	payload                            welford
	bins                               [7]float64
	retransOut, retransIn              float64
	iatOut                             welford
	iatOutMax                          float64
}

func newHostWindow() *hostWindow {
	return &hostWindow{
		peersOut: map[string]bool{}, peersIn: map[string]bool{},
		dportCount: map[uint16]int{}, lportCount: map[uint16]int{},
		active: map[event.FlowID]*Flow{}, ttlInSet: map[uint8]bool{},
	}
}

// Extractor consumes decoded packets in capture order and emits window rows
// and flow records.
type Extractor struct {
	cfg      Config
	windowMs int64
	flows    map[event.FlowID]*Flow
	order    []*Flow
	cur      int64
	started  bool
	hosts    map[string]*hostWindow
	lastSent map[string]time.Time
	rows     []Row
	packets  int

	keepAll  bool          // retain every flow for Flows() (batch mode)
	flowIdle time.Duration // live mode: expire flows idle this long
	expired  []*Flow
}

// New returns an Extractor. cfg.Window must be positive.
func New(cfg Config) *Extractor {
	if cfg.Internal == nil {
		cfg.Internal = RFC1918()
	}
	return &Extractor{
		cfg:      cfg,
		windowMs: cfg.Window.Milliseconds(),
		flows:    map[event.FlowID]*Flow{},
		hosts:    map[string]*hostWindow{},
		lastSent: map[string]time.Time{},
		keepAll:  true,
	}
}

func (x *Extractor) internal(ip net.IP) bool {
	for _, n := range x.cfg.Internal {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (x *Extractor) host(ip string) *hostWindow {
	h, ok := x.hosts[ip]
	if !ok {
		h = newHostWindow()
		x.hosts[ip] = h
	}
	return h
}

// Add processes one decoded packet. Packets must arrive in capture order;
// one that is older than the open window is counted in the open window.
func (x *Extractor) Add(ev *event.NetworkEvent) {
	x.packets++
	ms := ev.Timestamp.UnixMilli()
	ws := ms - mod(ms, x.windowMs)
	if !x.started {
		x.cur, x.started = ws, true
	}
	if ws > x.cur {
		x.flush()
		x.cur = ws
	}

	ft := ev.FiveTuple
	f, ok := x.flows[ev.FlowID]
	isNew := !ok
	if isNew {
		f = &Flow{
			ID: ev.FlowID, First: ev.Timestamp, Last: ev.Timestamp,
			SrcIP: ft.SrcIP.String(), DstIP: ft.DstIP.String(),
			SrcPort: ft.SrcPort, DstPort: ft.DstPort, Proto: ft.Protocol,
			SynWinFwd: -1,
		}
		x.flows[ev.FlowID] = f
		if x.keepAll {
			x.order = append(x.order, f)
		}
	}
	d := 1
	if ev.Direction == "C2S" || isNew {
		d = 0
	}
	retrans := f.update(ev, d)

	src, dst := ft.SrcIP.String(), ft.DstIP.String()
	srcIn, dstIn := x.internal(ft.SrcIP), x.internal(ft.DstIP)
	if srcIn {
		h := x.host(src)
		h.common(ev)
		h.out(ev, f, d, dst, dstIn, isNew, retrans)
		if last, ok := x.lastSent[src]; ok {
			gap := ev.Timestamp.Sub(last).Seconds()
			h.iatOut.add(gap)
			h.iatOutMax = math.Max(h.iatOutMax, gap)
		}
		x.lastSent[src] = ev.Timestamp
	}
	if dstIn && dst != src {
		h := x.host(dst)
		h.common(ev)
		h.in(ev, f, d, src, srcIn, isNew, retrans)
	}
}

// common updates the direction-independent parts of a host's window.
func (h *hostWindow) common(ev *event.NetworkEvent) {
	h.total++
	switch ev.FiveTuple.Protocol {
	case event.ProtoTCP:
		h.tcp++
	case event.ProtoUDP:
		h.udp++
	case event.ProtoICMP:
		h.icmp++
	}
	plen := float64(ev.Payload.Length)
	h.payload.add(plen)
	h.bins[payloadBin(ev.Payload.Length)]++
	if fb := ev.Header.FragBits; fb != nil {
		h.ipv4++
		if fb.MoreFragments {
			h.fragMF++
		}
		if fb.Offset != 0 {
			h.fragOff++
		}
		if fb.DontFragment {
			h.df++
		}
	}
	if tf, w := ev.TCPFlags, ev.Header.TCPWindow; tf != nil && w != nil {
		h.win.add(float64(*w))
		if *w == 0 && !tf.RST {
			h.winZero++
		}
		if tf.SYN && !tf.ACK {
			h.synWin.add(float64(*w))
		}
	}
}

// out updates the host that sent the packet.
func (h *hostWindow) out(ev *event.NetworkEvent, f *Flow, d int, peer string, peerIn, isNew, retrans bool) {
	h.pktsOut++
	h.bytesOut += float64(ev.Payload.Length)
	h.peersOut[peer] = peerIn
	if ttl := ev.Header.IPTTL; ttl != nil {
		h.ttlOut.add(float64(*ttl))
	}
	if tf := ev.TCPFlags; tf != nil {
		addFlags(&h.flagsOut, tf)
		if tf.SYN && !tf.ACK {
			h.synOnlyOut++
		}
	}
	if retrans {
		h.retransOut++
	}
	if isNew {
		h.newOut++
		if adminPorts[f.DstPort] {
			h.adminOut++
		}
	}
	if d == 0 { // this host originated the flow: the responder's port was contacted
		if _, seen := h.active[f.ID]; !seen {
			if _, ok := h.dportCount[f.DstPort]; !ok {
				h.dportOrder = append(h.dportOrder, f.DstPort)
			}
			h.dportCount[f.DstPort]++
		}
	}
	if ev.FiveTuple.DstPort == 53 && ev.DNS != nil {
		h.dnsQ++
		h.dnsEntSum += ev.DNS.EntropyBits
		h.dnsLenMax = math.Max(h.dnsLenMax, float64(ev.DNS.Length))
	}
	h.active[f.ID] = f
}

// in updates the host that received the packet.
func (h *hostWindow) in(ev *event.NetworkEvent, f *Flow, d int, peer string, peerIn, isNew, retrans bool) {
	h.pktsIn++
	h.bytesIn += float64(ev.Payload.Length)
	h.peersIn[peer] = peerIn
	if ttl := ev.Header.IPTTL; ttl != nil {
		h.ttlIn.add(float64(*ttl))
		h.ttlInSet[*ttl] = true
	}
	if tf := ev.TCPFlags; tf != nil {
		addFlags(&h.flagsIn, tf)
	}
	if retrans {
		h.retransIn++
	}
	if isNew {
		h.newIn++
		if adminPorts[f.DstPort] {
			h.adminIn++
		}
	}
	if d == 0 { // a peer originated the flow: this host's local port was contacted
		if _, seen := h.active[f.ID]; !seen {
			if _, ok := h.lportCount[f.DstPort]; !ok {
				h.lportOrder = append(h.lportOrder, f.DstPort)
			}
			h.lportCount[f.DstPort]++
		}
	}
	h.active[f.ID] = f
}

// Close flushes the last open window. Call it once, after the final packet.
func (x *Extractor) Close() {
	if x.started {
		x.flush()
	}
}

// Rows returns the window rows emitted so far, in window then host order.
func (x *Extractor) Rows() []Row { return x.rows }

// Flows returns every flow seen, in order of first packet.
func (x *Extractor) Flows() []*Flow { return x.order }

// Packets returns how many packets were added.
func (x *Extractor) Packets() int { return x.packets }

func (x *Extractor) flush() {
	hosts := make([]string, 0, len(x.hosts))
	for ip := range x.hosts {
		hosts = append(hosts, ip)
	}
	sort.Strings(hosts)
	for _, ip := range hosts {
		x.rows = append(x.rows, Row{Source: x.cfg.Source, Host: ip, WindowStart: x.cur, Values: x.hosts[ip].values(ip)})
	}
	x.hosts = map[string]*hostWindow{}
}

// values computes the host's state vector in Names order.
func (h *hostWindow) values(ip string) []float64 {
	v := make([]float64, len(Names))
	set := func(name string, val float64) {
		if math.IsNaN(val) || math.IsInf(val, 0) {
			val = 0
		}
		v[nameIndex[name]] = val
	}

	set("f_pkts_out", h.pktsOut)
	set("f_pkts_in", h.pktsIn)
	set("f_bytes_out", h.bytesOut)
	set("f_bytes_in", h.bytesIn)
	set("f_bytes_ratio", (h.bytesOut+1)/(h.bytesIn+1))

	var bidir, durSum, durMax, pktSum, byteSum, iatMean, iatVar, iatMax, iatN, ttlVar, ttlN, fail float64
	// Sum over flows in a stable order: floating-point addition is not
	// associative, so map order would otherwise perturb the last digits of a
	// reported feature between runs.
	active := make([]*Flow, 0, len(h.active))
	for _, f := range h.active {
		active = append(active, f)
	}
	sort.Slice(active, func(i, j int) bool { return active[i].ID < active[j].ID })
	for _, f := range active {
		if f.Pkts[0] > 0 && f.Pkts[1] > 0 {
			bidir++
		}
		dur := f.Last.Sub(f.First).Seconds()
		durSum += dur
		durMax = math.Max(durMax, dur)
		pktSum += float64(f.Pkts[0] + f.Pkts[1])
		byteSum += float64(f.Bytes[0] + f.Bytes[1])
		if f.iat.n > 0 {
			iatMean += f.iat.mean
			iatVar += f.iat.variance()
			iatMax += f.iatMax
			iatN++
		}
		for d := 0; d < 2; d++ {
			if f.ttl[d].n >= 2 {
				ttlVar += f.ttl[d].variance()
				ttlN++
			}
		}
		if f.SrcIP == ip && f.Proto == event.ProtoTCP && (f.Pkts[1] == 0 || f.Flags[1][3] > 0) {
			fail++
		}
	}
	n := float64(len(h.active))
	set("f_flows_active", n)
	set("f_flows_new_out", h.newOut)
	set("f_flows_new_in", h.newIn)
	set("f_flows_bidir_frac", div(bidir, n))
	set("f_flow_dur_mean", div(durSum, n))
	set("f_flow_dur_max", durMax)
	set("f_flow_pkts_mean", div(pktSum, n))
	set("f_flow_bytes_mean", div(byteSum, n))
	set("f_flow_iat_mean", div(iatMean, iatN))
	set("f_flow_iat_var", div(iatVar, iatN))
	set("f_flow_iat_max", div(iatMax, iatN))

	set("f_proto_tcp_frac", div(h.tcp, h.total))
	set("f_proto_udp_frac", div(h.udp, h.total))
	set("f_proto_icmp_frac", div(h.icmp, h.total))
	for i, fl := range []string{"syn", "ack", "fin", "rst", "psh", "urg"} {
		set("f_tcp_"+fl+"_out", h.flagsOut[i])
		set("f_tcp_"+fl+"_in", h.flagsIn[i])
	}
	set("f_syn_only_out", h.synOnlyOut)
	set("f_conn_fail_out", fail)

	set("f_uniq_peer_out", float64(len(h.peersOut)))
	set("f_uniq_peer_in", float64(len(h.peersIn)))
	set("f_uniq_dport_out", float64(len(h.dportCount)))
	set("f_uniq_lport_in", float64(len(h.lportCount)))
	peers := map[string]bool{}
	for p, in := range h.peersOut {
		peers[p] = in
	}
	for p, in := range h.peersIn {
		peers[p] = in
	}
	var internalPeers float64
	for _, in := range peers {
		if in {
			internalPeers++
		}
	}
	set("f_internal_peer_frac", div(internalPeers, float64(len(peers))))
	set("f_admin_conn_out", h.adminOut)
	set("f_admin_conn_in", h.adminIn)
	set("f_dns_queries_out", h.dnsQ)
	set("f_dns_qname_entropy_mean", div(h.dnsEntSum, h.dnsQ))
	set("f_dns_qname_len_max", h.dnsLenMax)

	set("p_ttl_in_mean", h.ttlIn.mean)
	set("p_ttl_in_var", h.ttlIn.variance())
	set("p_ttl_in_distinct", float64(len(h.ttlInSet)))
	set("p_ttl_out_mean", h.ttlOut.mean)
	set("p_ttl_out_var", h.ttlOut.variance())
	set("p_flow_ttl_var_mean", div(ttlVar, ttlN))
	set("p_tcp_win_mean", h.win.mean)
	set("p_tcp_win_var", h.win.variance())
	set("p_tcp_win_zero", h.winZero)
	set("p_tcp_syn_win_mean", h.synWin.mean)
	set("p_frag_mf", h.fragMF)
	set("p_frag_offset", h.fragOff)
	set("p_frag_df_frac", div(h.df, h.ipv4))
	set("p_payload_mean", h.payload.mean)
	set("p_payload_var", h.payload.variance())
	for i, name := range []string{"0", "1_64", "65_256", "257_512", "513_1024", "1025_1460", "gt1460"} {
		set("p_payload_bin_"+name, div(h.bins[i], h.total))
	}
	set("p_retrans_out", h.retransOut)
	set("p_retrans_in", h.retransIn)
	set("p_dport_seq_frac_out", seqFrac(h.dportOrder))
	set("p_dport_entropy_out", entropy(h.dportCount))
	set("p_lport_seq_frac_in", seqFrac(h.lportOrder))
	set("p_lport_entropy_in", entropy(h.lportCount))
	set("p_iat_out_mean", h.iatOut.mean)
	set("p_iat_out_var", h.iatOut.variance())
	set("p_iat_out_max", h.iatOutMax)
	set("p_iat_out_cv", div(math.Sqrt(h.iatOut.variance()), h.iatOut.mean))
	return v
}

func addFlags(dst *[6]float64, tf *event.TCPFlags) {
	for i, set := range [6]bool{tf.SYN, tf.ACK, tf.FIN, tf.RST, tf.PSH, tf.URG} {
		if set {
			dst[i]++
		}
	}
}

func payloadBin(n int) int {
	switch {
	case n == 0:
		return 0
	case n <= 64:
		return 1
	case n <= 256:
		return 2
	case n <= 512:
		return 3
	case n <= 1024:
		return 4
	case n <= 1460:
		return 5
	default:
		return 6
	}
}

// seqFrac is the share of consecutive distinct ports (in first-seen order)
// that are the previous port + 1: close to 1 for a sequential scan.
func seqFrac(order []uint16) float64 {
	if len(order) < 2 {
		return 0
	}
	var seq float64
	for i := 1; i < len(order); i++ {
		if order[i] == order[i-1]+1 {
			seq++
		}
	}
	return seq / float64(len(order)-1)
}

// entropy is the Shannon entropy (bits) of a port histogram: high when many
// ports are each touched once, as in a randomised scan.
func entropy(counts map[uint16]int) float64 {
	var total float64
	for _, c := range counts {
		total += float64(c)
	}
	if total == 0 {
		return 0
	}
	var h float64
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / total
			h -= p * math.Log2(p)
		}
	}
	return h
}

func div(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func mod(a, b int64) int64 {
	m := a % b
	if m < 0 {
		m += b
	}
	return m
}

// welford keeps a running mean and population variance.
type welford struct {
	n, mean, m2 float64
}

func (w *welford) add(x float64) {
	w.n++
	d := x - w.mean
	w.mean += d / w.n
	w.m2 += d * (x - w.mean)
}

func (w welford) variance() float64 {
	if w.n < 2 {
		return 0
	}
	return w.m2 / w.n
}

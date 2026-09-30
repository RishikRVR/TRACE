package features

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"time"
)

func ff(v float64) string { return strconv.FormatFloat(v, 'g', 7, 64) }

// WriteWindows writes rows as windows.csv. header controls whether the column
// line is written, so several captures can be appended to one file.
func WriteWindows(w io.Writer, rows []Row, window time.Duration, header bool) error {
	cw := csv.NewWriter(w)
	if header {
		cols := append([]string{"schema_version", "source", "host", "window_start", "window_s", "has_packet_level"}, Names...)
		if err := cw.Write(cols); err != nil {
			return err
		}
	}
	ws := strconv.Itoa(int(window.Seconds()))
	rec := make([]string, 6+len(Names))
	for _, r := range rows {
		rec[0], rec[1], rec[2] = strconv.Itoa(SchemaVersion), r.Source, r.Host
		rec[3], rec[4], rec[5] = strconv.FormatInt(r.WindowStart, 10), ws, "1"
		for i, v := range r.Values {
			rec[6+i] = ff(v)
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// FlowColumns is the flows.csv header (docs/feature-schema-v1.md), with a
// leading source column.
var FlowColumns = []string{
	"source", "flow_id", "first_seen", "last_seen", "src_ip", "src_port", "dst_ip", "dst_port", "proto",
	"pkts_fwd", "pkts_bwd", "bytes_fwd", "bytes_bwd", "duration_s", "iat_mean", "iat_var", "iat_max",
	"syn_fwd", "syn_bwd", "ack_fwd", "ack_bwd", "fin_fwd", "fin_bwd", "rst_fwd", "rst_bwd",
	"psh_fwd", "psh_bwd", "urg_fwd", "urg_bwd",
	"ttl_mean_fwd", "ttl_var_fwd", "ttl_mean_bwd", "ttl_var_bwd",
	"syn_win_fwd", "win_mean_fwd", "frag_mf", "retrans_fwd", "retrans_bwd", "payload_mean", "tcp_state_final",
}

// WriteFlows writes flow records as flows.csv.
func WriteFlows(w io.Writer, source string, flows []*Flow, header bool) error {
	cw := csv.NewWriter(w)
	if header {
		if err := cw.Write(FlowColumns); err != nil {
			return err
		}
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	for _, f := range flows {
		rec := []string{
			source, string(f.ID), strconv.FormatInt(f.First.UnixMilli(), 10), strconv.FormatInt(f.Last.UnixMilli(), 10),
			f.SrcIP, strconv.Itoa(int(f.SrcPort)), f.DstIP, strconv.Itoa(int(f.DstPort)), string(f.Proto),
			u(f.Pkts[0]), u(f.Pkts[1]), u(f.Bytes[0]), u(f.Bytes[1]),
			ff(f.Last.Sub(f.First).Seconds()), ff(f.iat.mean), ff(f.iat.variance()), ff(f.iatMax),
		}
		for i := 0; i < 6; i++ {
			rec = append(rec, u(uint64(f.Flags[0][i])), u(uint64(f.Flags[1][i])))
		}
		rec = append(rec,
			ff(f.ttl[0].mean), ff(f.ttl[0].variance()), ff(f.ttl[1].mean), ff(f.ttl[1].variance()),
			ff(f.SynWinFwd), ff(f.win[0].mean), u(uint64(f.FragMF)),
			u(uint64(f.Retrans[0])), u(uint64(f.Retrans[1])), ff(f.payload.mean), f.State(),
		)
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// Schema is schema.json: everything ml/ needs to read windows.csv.
type Schema struct {
	SchemaVersion int      `json:"schema_version"`
	WindowS       int      `json:"window_s"`
	Internal      []string `json:"internal"`
	Bytes         string   `json:"bytes"`
	FlowLevel     []string `json:"flow_level"`
	PacketLevel   []string `json:"packet_level"`
	Features      []string `json:"features"`
}

// WriteSchema writes schema.json for cfg.
func WriteSchema(path string, cfg Config) error {
	s := Schema{
		SchemaVersion: SchemaVersion,
		WindowS:       int(cfg.Window.Seconds()),
		Bytes:         "l4_payload",
		FlowLevel:     FlowLevel,
		PacketLevel:   PacketLevel,
		Features:      Names,
	}
	for _, n := range cfg.Internal {
		s.Internal = append(s.Internal, n.String())
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

"""Plain-English names for every window feature, and the groups explanations
roll up to. The console never shows raw f_*/p_* names without these."""

# name -> (label, what it means, unit)
FEATURES: dict[str, tuple[str, str, str]] = {
    "f_pkts_out": ("Packets sent", "Packets this host sent in the window", "pkts"),
    "f_pkts_in": ("Packets received", "Packets this host received in the window", "pkts"),
    "f_bytes_out": ("Bytes sent", "Payload bytes this host sent", "bytes"),
    "f_bytes_in": ("Bytes received", "Payload bytes this host received", "bytes"),
    "f_bytes_ratio": ("Upload/download ratio", "Bytes sent vs received; large values mean data leaving", "×"),
    "f_flows_active": ("Active connections", "Connections with traffic in the window", "flows"),
    "f_flows_new_out": ("New outbound connections", "Connections this host opened", "flows"),
    "f_flows_new_in": ("New inbound connections", "Connections others opened to this host", "flows"),
    "f_flows_bidir_frac": ("Answered connections", "Share of connections with traffic both ways", "share"),
    "f_flow_dur_mean": ("Connection duration", "Average age of active connections", "s"),
    "f_flow_dur_max": ("Longest connection", "Longest-running active connection", "s"),
    "f_flow_pkts_mean": ("Packets per connection", "Average packets per active connection", "pkts"),
    "f_flow_bytes_mean": ("Bytes per connection", "Average bytes per active connection", "bytes"),
    "f_flow_iat_mean": ("Packet gap per connection", "Average time between packets within a connection", "s"),
    "f_flow_iat_var": ("Packet gap variability", "Variance of packet gaps within connections", "s²"),
    "f_flow_iat_max": ("Longest packet gap", "Longest pause inside a connection", "s"),
    "f_proto_tcp_frac": ("TCP share", "Share of packets that are TCP", "share"),
    "f_proto_udp_frac": ("UDP share", "Share of packets that are UDP", "share"),
    "f_proto_icmp_frac": ("ICMP share", "Share of packets that are ICMP", "share"),
    "f_tcp_syn_out": ("SYNs sent", "Connection attempts this host sent", "pkts"),
    "f_tcp_ack_out": ("ACKs sent", "Acknowledgements this host sent", "pkts"),
    "f_tcp_fin_out": ("FINs sent", "Connection closes this host sent", "pkts"),
    "f_tcp_rst_out": ("Resets sent", "Connection resets this host sent (refusing or aborting)", "pkts"),
    "f_tcp_psh_out": ("Data pushes sent", "TCP PSH segments this host sent", "pkts"),
    "f_tcp_urg_out": ("URG sent", "TCP URG segments this host sent", "pkts"),
    "f_tcp_syn_in": ("SYNs received", "Connection attempts reaching this host", "pkts"),
    "f_tcp_ack_in": ("ACKs received", "Acknowledgements this host received", "pkts"),
    "f_tcp_fin_in": ("FINs received", "Connection closes this host received", "pkts"),
    "f_tcp_rst_in": ("Resets received", "Resets this host received: its connection attempts refused", "pkts"),
    "f_tcp_psh_in": ("Data pushes received", "TCP PSH segments this host received", "pkts"),
    "f_tcp_urg_in": ("URG received", "TCP URG segments this host received", "pkts"),
    "f_syn_only_out": ("Unfinished connection attempts", "SYNs sent without ACK: typical of scanning", "pkts"),
    "f_conn_fail_out": ("Failed outbound connections", "Connections this host opened that were refused or unanswered", "flows"),
    "f_uniq_peer_out": ("Machines contacted", "Distinct addresses this host talked to", "hosts"),
    "f_uniq_peer_in": ("Machines contacting it", "Distinct addresses that talked to this host", "hosts"),
    "f_uniq_dport_out": ("Ports probed by this host", "Distinct destination ports this host contacted", "ports"),
    "f_uniq_lport_in": ("Ports probed on this host", "Distinct local ports others contacted", "ports"),
    "f_internal_peer_frac": ("Internal (east-west) share", "Share of peers inside the network", "share"),
    "f_admin_conn_out": ("Admin-port connections out", "New connections to SSH/SMB/RDP/WinRM ports: lateral-movement ports", "flows"),
    "f_admin_conn_in": ("Admin-port connections in", "New SSH/SMB/RDP/WinRM connections to this host", "flows"),
    "f_dns_queries_out": ("DNS queries", "DNS lookups this host made", "queries"),
    "f_dns_qname_entropy_mean": ("DNS name randomness", "Entropy of queried names; high means encoded data (tunnelling)", "bits"),
    "f_dns_qname_len_max": ("Longest DNS name", "Longest name looked up", "chars"),
    "p_ttl_in_mean": ("Incoming TTL", "Average TTL of received packets (hints at sender OS and distance)", ""),
    "p_ttl_in_var": ("Incoming TTL spread", "TTL variance of received packets", ""),
    "p_ttl_in_distinct": ("Distinct incoming TTLs", "Number of different TTLs received", ""),
    "p_ttl_out_mean": ("Outgoing TTL", "Average TTL of packets sent", ""),
    "p_ttl_out_var": ("Outgoing TTL spread", "TTL variance of packets sent", ""),
    "p_flow_ttl_var_mean": ("TTL change within sessions", "TTL variance inside connections (spoofing, route changes)", ""),
    "p_tcp_win_mean": ("TCP window size", "Average advertised TCP window", "bytes"),
    "p_tcp_win_var": ("TCP window spread", "Variance of TCP window sizes", ""),
    "p_tcp_win_zero": ("Zero-window segments", "Receiver-full signals", "pkts"),
    "p_tcp_syn_win_mean": ("SYN window size", "Window on connection attempts: scanners use tiny ones (e.g. 1024)", "bytes"),
    "p_frag_mf": ("Fragmented packets", "Packets with more-fragments set", "pkts"),
    "p_frag_offset": ("Fragment pieces", "Packets with a fragment offset", "pkts"),
    "p_frag_df_frac": ("Don't-fragment share", "Share of packets with DF set", "share"),
    "p_payload_mean": ("Payload size", "Average payload per packet", "bytes"),
    "p_payload_var": ("Payload size spread", "Variance of payload sizes", ""),
    "p_payload_bin_0": ("Empty packets", "Share of packets with no payload (control only)", "share"),
    "p_payload_bin_1_64": ("Tiny payloads", "Share of packets carrying 1–64 bytes", "share"),
    "p_payload_bin_65_256": ("Small payloads", "Share carrying 65–256 bytes", "share"),
    "p_payload_bin_257_512": ("Medium payloads", "Share carrying 257–512 bytes", "share"),
    "p_payload_bin_513_1024": ("Large payloads", "Share carrying 513–1024 bytes", "share"),
    "p_payload_bin_1025_1460": ("Full-size payloads", "Share carrying 1025–1460 bytes (bulk transfer)", "share"),
    "p_payload_bin_gt1460": ("Jumbo payloads", "Share carrying more than 1460 bytes", "share"),
    "p_retrans_out": ("Retransmissions sent", "Segments this host sent again", "pkts"),
    "p_retrans_in": ("Retransmissions received", "Segments received again", "pkts"),
    "p_dport_seq_frac_out": ("Sequential port order (out)", "How often this host's next port was previous+1: a sequential scan", "share"),
    "p_dport_entropy_out": ("Port randomness (out)", "Entropy of destination ports: high for randomised scans", "bits"),
    "p_lport_seq_frac_in": ("Sequential probing of this host", "How often the next probed port on this host was previous+1", "share"),
    "p_lport_entropy_in": ("Randomness of probing on this host", "Entropy of this host's ports being contacted", "bits"),
    "p_iat_out_mean": ("Send interval", "Average gap between packets this host sent", "s"),
    "p_iat_out_var": ("Send interval spread", "Variance of those gaps", "s²"),
    "p_iat_out_max": ("Longest send gap", "Longest silence between sent packets", "s"),
    "p_iat_out_cv": ("Send-timing regularity", "Coefficient of variation of send gaps; low = machine-regular (beaconing)", ""),
}

GROUPS: dict[str, list[str]] = {
    "Port scanning": [
        "f_uniq_lport_in", "p_lport_seq_frac_in", "p_lport_entropy_in", "f_uniq_dport_out", "p_dport_seq_frac_out",
        "p_dport_entropy_out", "f_syn_only_out", "f_tcp_syn_in", "f_tcp_syn_out", "f_flows_new_in", "f_flows_new_out",
    ],
    "Failed connections": ["f_conn_fail_out", "f_tcp_rst_in", "f_tcp_rst_out", "f_flows_bidir_frac"],
    "Admin ports / east-west": ["f_admin_conn_out", "f_admin_conn_in", "f_internal_peer_frac", "f_uniq_peer_out", "f_uniq_peer_in"],
    "Traffic volume": [
        "f_pkts_out", "f_pkts_in", "f_bytes_out", "f_bytes_in", "f_bytes_ratio", "f_flows_active", "f_flow_pkts_mean",
        "f_flow_bytes_mean",
    ],
    "Timing and beaconing": [
        "f_flow_dur_mean", "f_flow_dur_max", "f_flow_iat_mean", "f_flow_iat_var", "f_flow_iat_max", "p_iat_out_mean",
        "p_iat_out_var", "p_iat_out_max", "p_iat_out_cv",
    ],
    "Packet fingerprint (TTL, TCP window)": [
        "p_ttl_in_mean", "p_ttl_in_var", "p_ttl_in_distinct", "p_ttl_out_mean", "p_ttl_out_var", "p_flow_ttl_var_mean",
        "p_tcp_win_mean", "p_tcp_win_var", "p_tcp_win_zero", "p_tcp_syn_win_mean", "p_frag_mf", "p_frag_offset",
        "p_frag_df_frac",
    ],
    "DNS behaviour": ["f_dns_queries_out", "f_dns_qname_entropy_mean", "f_dns_qname_len_max", "f_proto_udp_frac"],
}


def label(name: str) -> str:
    return FEATURES.get(name, (name, "", ""))[0]


def group_of(name: str) -> str:
    for g, names in GROUPS.items():
        if name in names:
            return g
    return "Payload and flags"


def level(name: str) -> str:
    return "packet" if name.startswith("p_") else "flow"

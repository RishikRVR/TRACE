package event

// TLSState is a bitmask of the TLS/SSL handshake messages observed in a
// packet, mirroring Snort's ssl_state keyword.
type TLSState uint8

const (
	TLSClientHello TLSState = 1 << iota
	TLSServerHello
	TLSClientKeyExchange
	TLSServerKeyExchange
	// TLSUnknown marks traffic on a TLS record layer whose handshake message we
	// did not recognise (including encrypted post-handshake records).
	TLSUnknown
)

// TLSVersion identifies the protocol version on the wire.
type TLSVersion uint8

const (
	TLSVersionNone TLSVersion = iota
	SSLv2
	SSLv3
	TLS10
	TLS11
	TLS12
	TLS13
)

// TLSMeta carries what the ssl_state and ssl_version rule keywords need. It is
// nil on packets that do not carry a TLS/SSL record.
//
// State reflects the handshake messages present in THIS packet's records
// rather than an accumulated session history: rules pairing ssl_state with a
// content match are inspecting the packet that carries the message, so
// per-packet state is what they mean.
type TLSMeta struct {
	State   TLSState
	Version TLSVersion
	// SNI is the server name from a ClientHello's server_name extension, as a
	// sub-slice of the payload. Thousands of rules key on it (tls.sni), and it
	// is one of the few parts of a TLS session visible without decryption.
	SNI []byte
}

// tls record content types
const (
	recChangeCipherSpec = 20
	recAlert            = 21
	recHandshake        = 22
	recApplicationData  = 23
)

// handshake message types
const (
	hsClientHello       = 1
	hsServerHello       = 2
	hsServerKeyExchange = 12
	hsClientKeyExchange = 16
)

// versionFromWire maps a two-byte TLS version to our enum.
func versionFromWire(major, minor byte) TLSVersion {
	if major != 3 {
		return TLSVersionNone
	}
	switch minor {
	case 0:
		return SSLv3
	case 1:
		return TLS10
	case 2:
		return TLS11
	case 3:
		return TLS12
	case 4:
		return TLS13
	}
	return TLSVersionNone
}

// ParseTLS inspects a TCP payload for TLS/SSL records and returns what the
// ssl_* keywords need, or nil when the payload is not TLS.
//
// It walks the record layer rather than assuming a single record, because a
// packet can carry several (e.g. ServerHello + Certificate + ServerHelloDone).
func ParseTLS(p []byte) *TLSMeta {
	if m := parseSSLv2(p); m != nil {
		return m
	}
	if len(p) < 5 {
		return nil
	}
	// A TLS record starts with a known content type and a 0x03xx version.
	switch p[0] {
	case recChangeCipherSpec, recAlert, recHandshake, recApplicationData:
	default:
		return nil
	}
	if p[1] != 3 {
		return nil
	}

	meta := &TLSMeta{Version: versionFromWire(p[1], p[2])}
	for off := 0; off+5 <= len(p); {
		typ := p[off]
		if typ != recChangeCipherSpec && typ != recAlert && typ != recHandshake && typ != recApplicationData {
			break
		}
		if p[off+1] != 3 {
			break
		}
		recLen := int(p[off+3])<<8 | int(p[off+4])
		body := p[off+5:]
		if recLen < len(body) {
			body = body[:recLen]
		}
		if typ == recHandshake {
			meta.State |= handshakeStates(body, meta)
		} else if meta.State == 0 {
			// Non-handshake records (application data, alerts) carry no
			// recognisable message: Snort calls this "unknown".
			meta.State |= TLSUnknown
		}
		if recLen <= 0 {
			break
		}
		off += 5 + recLen
	}
	if meta.State == 0 {
		meta.State = TLSUnknown
	}
	return meta
}

// handshakeStates walks the handshake messages inside one record body. It also
// promotes the version to the one advertised inside a Hello, which is the
// version the peer actually proposes (record-layer versions are often pinned
// low for compatibility).
func handshakeStates(body []byte, meta *TLSMeta) TLSState {
	var st TLSState
	for off := 0; off+4 <= len(body); {
		msgType := body[off]
		msgLen := int(body[off+1])<<16 | int(body[off+2])<<8 | int(body[off+3])
		switch msgType {
		case hsClientHello:
			st |= TLSClientHello
		case hsServerHello:
			st |= TLSServerHello
		case hsClientKeyExchange:
			st |= TLSClientKeyExchange
		case hsServerKeyExchange:
			st |= TLSServerKeyExchange
		}
		if msgType == hsClientHello || msgType == hsServerHello {
			if off+6 <= len(body) && body[off+4] == 3 {
				if v := versionFromWire(body[off+4], body[off+5]); v != TLSVersionNone {
					meta.Version = v
				}
			}
		}
		if msgType == hsClientHello && off+4+msgLen <= len(body) {
			if sni := parseSNI(body[off+4 : off+4+msgLen]); sni != nil {
				meta.SNI = sni
			}
		}
		if msgLen <= 0 {
			break
		}
		off += 4 + msgLen
	}
	return st
}

// parseSSLv2 recognises an SSLv2 ClientHello, whose framing predates the TLS
// record layer: a 2-byte length with the high bit set, then a message type.
func parseSSLv2(p []byte) *TLSMeta {
	if len(p) < 5 || p[0]&0x80 == 0 {
		return nil
	}
	if p[2] != 1 { // SSLv2 CLIENT-HELLO
		return nil
	}
	// Bytes 3-4 carry the highest version the client supports.
	v := SSLv2
	if p[3] == 3 {
		if got := versionFromWire(p[3], p[4]); got != TLSVersionNone {
			v = got
		}
	}
	return &TLSMeta{State: TLSClientHello, Version: v}
}

// parseSNI walks a ClientHello body to the server_name extension and returns
// the host name. Returns nil on anything malformed — this runs on hostile
// input, so every length is bounds-checked and no error is fatal.
//
// ClientHello layout: client_version(2), random(32), session_id(1+n),
// cipher_suites(2+n), compression_methods(1+n), extensions(2+n).
func parseSNI(b []byte) []byte {
	i := 2 + 32 // past client_version and random
	if i >= len(b) {
		return nil
	}
	i += 1 + int(b[i]) // session_id
	if i+2 > len(b) {
		return nil
	}
	i += 2 + (int(b[i])<<8 | int(b[i+1])) // cipher_suites
	if i >= len(b) {
		return nil
	}
	i += 1 + int(b[i]) // compression_methods
	if i+2 > len(b) {
		return nil
	}
	end := i + 2 + (int(b[i])<<8 | int(b[i+1])) // extensions block
	i += 2
	if end > len(b) {
		end = len(b)
	}

	for i+4 <= end {
		extType := int(b[i])<<8 | int(b[i+1])
		extLen := int(b[i+2])<<8 | int(b[i+3])
		i += 4
		if i+extLen > end {
			return nil
		}
		if extType == 0 { // server_name
			e := b[i : i+extLen]
			// server_name_list(2), name_type(1, 0=host_name), length(2), host
			if len(e) >= 5 && e[2] == 0 {
				n := int(e[3])<<8 | int(e[4])
				if 5+n <= len(e) {
					return e[5 : 5+n]
				}
			}
			return nil
		}
		i += extLen
	}
	return nil
}

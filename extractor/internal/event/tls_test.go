package event

import "testing"

// tlsRecord builds a TLS record: content type, version, length, body.
func tlsRecord(typ byte, maj, min byte, body []byte) []byte {
	rec := []byte{typ, maj, min, byte(len(body) >> 8), byte(len(body))}
	return append(rec, body...)
}

// handshake builds a handshake message: type, 3-byte length, body.
func handshake(msgType byte, body []byte) []byte {
	h := []byte{msgType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(h, body...)
}

func TestParseTLS_ClientHello(t *testing.T) {
	// A ClientHello whose record says TLS1.0 but whose body proposes TLS1.2 —
	// the common compatibility pattern. The body version should win.
	body := append([]byte{3, 3}, make([]byte, 32)...) // client_version + random
	pkt := tlsRecord(recHandshake, 3, 1, handshake(hsClientHello, body))

	m := ParseTLS(pkt)
	if m == nil {
		t.Fatal("expected TLS metadata")
	}
	if m.State&TLSClientHello == 0 {
		t.Errorf("expected client_hello state, got %b", m.State)
	}
	if m.Version != TLS12 {
		t.Errorf("expected the body's TLS1.2, got %v", m.Version)
	}
}

func TestParseTLS_ServerHelloAndKeyExchange(t *testing.T) {
	// One packet carrying ServerHello followed by ServerKeyExchange, which is
	// why the parser must walk every message rather than read only the first.
	body := append([]byte{3, 3}, make([]byte, 32)...)
	inner := append(handshake(hsServerHello, body), handshake(hsServerKeyExchange, []byte{1, 2, 3})...)
	pkt := tlsRecord(recHandshake, 3, 3, inner)

	m := ParseTLS(pkt)
	if m == nil {
		t.Fatal("expected TLS metadata")
	}
	if m.State&TLSServerHello == 0 {
		t.Error("expected server_hello")
	}
	if m.State&TLSServerKeyExchange == 0 {
		t.Error("expected server_keyx in the same packet")
	}
}

func TestParseTLS_ApplicationDataIsUnknown(t *testing.T) {
	pkt := tlsRecord(recApplicationData, 3, 3, []byte{0xde, 0xad, 0xbe, 0xef})
	m := ParseTLS(pkt)
	if m == nil {
		t.Fatal("expected TLS metadata for an application-data record")
	}
	if m.State != TLSUnknown {
		t.Errorf("encrypted application data should be 'unknown', got %b", m.State)
	}
	if m.Version != TLS12 {
		t.Errorf("expected TLS1.2 from the record, got %v", m.Version)
	}
}

func TestParseTLS_SSLv2ClientHello(t *testing.T) {
	// SSLv2 framing: high bit set in the length, then message type 1.
	pkt := []byte{0x80, 0x2e, 0x01, 0x03, 0x01, 0x00}
	m := ParseTLS(pkt)
	if m == nil {
		t.Fatal("expected SSLv2 metadata")
	}
	if m.State&TLSClientHello == 0 {
		t.Error("SSLv2 CLIENT-HELLO should register as client_hello")
	}
}

func TestParseTLS_NotTLS(t *testing.T) {
	for name, p := range map[string][]byte{
		"http":  []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"short": {0x16, 0x03},
		"empty": {},
		"bogus": {0x99, 0x99, 0x99, 0x99, 0x99},
	} {
		if m := ParseTLS(p); m != nil {
			t.Errorf("%s payload should not parse as TLS, got %+v", name, m)
		}
	}
}

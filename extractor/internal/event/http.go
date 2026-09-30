package event

import "bytes"

// HTTPBuffers holds the sub-regions of an HTTP message that Snort's "sticky
// buffer" keywords address (http_uri, http_header, http_user_agent, ...).
//
// Why this exists: a large fraction of Snort/ET rules scope their content to
// one of these buffers. A rule like `content:"HTTP"; http_user_agent` means
// "the User-Agent header contains HTTP" — genuinely suspicious. Matched against
// the whole raw payload instead, it means "this is an HTTP packet", and fires
// on everything. Extracting the real buffers is what makes those rules mean
// what their authors intended.
//
// Every field is a SUB-SLICE of the original payload (no copying, no decoding).
// Keeping them as raw slices matters for two reasons: it avoids per-packet
// allocation, and it keeps the multi-pattern pre-filter valid, since any
// pattern found in a buffer is also literally present in the raw payload.
//
// Deliberate limitation: Snort NORMALIZES http_uri (URL-decoding, path
// collapsing) before matching. We do not. That can cause a miss on an
// obfuscated URI (a false negative) but never a spurious match (a false
// positive) — the safe direction for something that runs inline.
type HTTPBuffers struct {
	IsRequest  bool
	IsResponse bool

	Method     []byte // "GET"
	URI        []byte // "/path?q=1"
	Header     []byte // the whole header block, excluding the request line
	UserAgent  []byte // value of User-Agent
	Cookie     []byte // value of Cookie / Set-Cookie
	Host       []byte // value of Host
	Referer    []byte // value of Referer
	ClientBody []byte // everything after the blank line
	StatCode   []byte // "404" on a response
	StatMsg    []byte // "Not Found" on a response
}

var (
	crlfcrlf  = []byte("\r\n\r\n")
	lflf      = []byte("\n\n")
	crlf      = []byte("\r\n")
	httpSlash = []byte("HTTP/")
)

// knownMethods are the request verbs we accept. Requiring one of these (rather
// than "any token") stops us mis-parsing arbitrary binary payloads as HTTP.
var knownMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("TRACE "),
	[]byte("CONNECT "), []byte("PROPFIND "), []byte("PROPPATCH "), []byte("MKCOL "),
	[]byte("COPY "), []byte("MOVE "), []byte("LOCK "), []byte("UNLOCK "), []byte("SEARCH "),
}

// ParseHTTP extracts the sticky buffers from a payload, or returns nil when the
// payload is not the start of an HTTP message.
func ParseHTTP(p []byte) *HTTPBuffers {
	if len(p) < 12 {
		return nil
	}
	h := &HTTPBuffers{}

	switch {
	case bytes.HasPrefix(p, []byte("HTTP/")):
		h.IsResponse = true
	default:
		for _, m := range knownMethods {
			if bytes.HasPrefix(p, m) {
				h.IsRequest = true
				h.Method = p[:len(m)-1] // without the trailing space
				break
			}
		}
		if !h.IsRequest {
			return nil
		}
	}

	// Split the start line from the rest.
	lineEnd := bytes.Index(p, crlf)
	sep := 2
	if lineEnd < 0 {
		lineEnd = bytes.IndexByte(p, '\n')
		sep = 1
	}
	if lineEnd < 0 {
		lineEnd, sep = len(p), 0
	}
	startLine := p[:lineEnd]

	if h.IsRequest {
		// "GET /path HTTP/1.1" -> URI is between the first and last space.
		rest := startLine[len(h.Method):]
		for len(rest) > 0 && rest[0] == ' ' {
			rest = rest[1:]
		}
		if v := bytes.LastIndex(rest, []byte(" HTTP/")); v > 0 {
			h.URI = rest[:v]
		} else if v := bytes.IndexByte(rest, ' '); v > 0 {
			h.URI = rest[:v]
		} else {
			h.URI = rest
		}
	} else {
		// "HTTP/1.1 404 Not Found"
		f := bytes.SplitN(startLine, []byte(" "), 3)
		if len(f) >= 2 {
			h.StatCode = f[1]
		}
		if len(f) >= 3 {
			h.StatMsg = f[2]
		}
	}

	// Header block runs from after the start line to the blank line.
	hdrStart := lineEnd + sep
	if hdrStart > len(p) {
		hdrStart = len(p)
	}
	rest := p[hdrStart:]
	bodyAt := -1
	if i := bytes.Index(rest, crlfcrlf); i >= 0 {
		h.Header, bodyAt = rest[:i], i+4
	} else if i := bytes.Index(rest, lflf); i >= 0 {
		h.Header, bodyAt = rest[:i], i+2
	} else {
		h.Header = rest
	}
	if bodyAt >= 0 && bodyAt <= len(rest) {
		h.ClientBody = rest[bodyAt:]
	}

	h.UserAgent = headerValue(h.Header, "user-agent")
	h.Host = headerValue(h.Header, "host")
	h.Referer = headerValue(h.Header, "referer")
	if c := headerValue(h.Header, "cookie"); c != nil {
		h.Cookie = c
	} else {
		h.Cookie = headerValue(h.Header, "set-cookie")
	}
	return h
}

// headerValue returns the value of the named header (case-insensitive) as a
// sub-slice of block, or nil when absent.
func headerValue(block []byte, name string) []byte {
	rest := block
	for len(rest) > 0 {
		var line []byte
		if i := bytes.Index(rest, crlf); i >= 0 {
			line, rest = rest[:i], rest[i+2:]
		} else if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i], rest[i+1:]
		} else {
			line, rest = rest, nil
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || colon != len(name) {
			continue
		}
		if !equalFoldASCII(line[:colon], name) {
			continue
		}
		v := line[colon+1:]
		for len(v) > 0 && (v[0] == ' ' || v[0] == '\t') {
			v = v[1:]
		}
		return v
	}
	return nil
}

func equalFoldASCII(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := range b {
		c, d := b[i], s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if d >= 'A' && d <= 'Z' {
			d += 'a' - 'A'
		}
		if c != d {
			return false
		}
	}
	return true
}

// Buffer returns the named sticky buffer, or nil if this message has none.
func (h *HTTPBuffers) Buffer(name string) []byte {
	if h == nil {
		return nil
	}
	switch name {
	case "http_method":
		return h.Method
	case "http_uri", "http_raw_uri":
		return h.URI
	case "http_header", "http_raw_header":
		return h.Header
	case "http_user_agent":
		return h.UserAgent
	case "http_cookie", "http_raw_cookie":
		return h.Cookie
	case "http_host", "http_raw_host":
		return h.Host
	case "http_referer":
		return h.Referer
	case "http_client_body":
		return h.ClientBody
	case "http_stat_code":
		return h.StatCode
	case "http_stat_msg":
		return h.StatMsg
	}
	// Generic header-value buffers (content-type, server, location, ...) are
	// pulled straight out of the header block by name.
	if hdrName, ok := headerBufferNames[name]; ok {
		return headerValue(h.Header, hdrName)
	}
	return nil
}

// headerBufferNames maps a buffer name to the HTTP header it reads. It mirrors
// rule.HeaderNameFor, kept here so this package stays dependency-free.
var headerBufferNames = map[string]string{
	"http_content_type": "content-type",
	"http_server":       "server",
	"http_location":     "location",
	"http_connection":   "connection",
	"http_content_len":  "content-length",
	"http_accept":       "accept",
	"http_accept_enc":   "accept-encoding",
	"http_accept_lang":  "accept-language",
}

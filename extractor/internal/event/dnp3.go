package event

import "strings"

// DNP3IIN is the 16-bit "Internal Indications" field a DNP3 outstation returns
// in every application-layer response, reporting device conditions such as a
// corrupt configuration or an overflowed event buffer. Snort's dnp3_ind
// keyword tests these bits.
type DNP3IIN uint16

// IIN bit assignments (IEEE 1815). The first octet is bits 0-7, the second 8-15.
const (
	IINAllStationsRcvd DNP3IIN = 1 << iota
	IINClass1Events
	IINClass2Events
	IINClass3Events
	IINNeedTime
	IINLocalControl
	IINDeviceTrouble
	IINDeviceRestart
	IINNoFuncCodeSupport
	IINObjectUnknown
	IINParameterError
	IINEventBufferOverflow
	IINAlreadyExecuting
	IINConfigCorrupt
	IINReserved2
	IINReserved1
)

// dnp3IINByName maps Snort's dnp3_ind names to their bits.
var dnp3IINByName = map[string]DNP3IIN{
	"all_stations":          IINAllStationsRcvd,
	"class_1_events":        IINClass1Events,
	"class_2_events":        IINClass2Events,
	"class_3_events":        IINClass3Events,
	"need_time":             IINNeedTime,
	"local_control":         IINLocalControl,
	"device_trouble":        IINDeviceTrouble,
	"device_restart":        IINDeviceRestart,
	"no_func_code_support":  IINNoFuncCodeSupport,
	"object_unknown":        IINObjectUnknown,
	"parameter_error":       IINParameterError,
	"event_buffer_overflow": IINEventBufferOverflow,
	"already_executing":     IINAlreadyExecuting,
	"config_corrupt":        IINConfigCorrupt,
	"reserved_2":            IINReserved2,
	"reserved_1":            IINReserved1,
}

// DNP3IINByName resolves a Snort dnp3_ind flag name, tolerating the quotes the
// rule syntax wraps it in.
func DNP3IINByName(n string) (DNP3IIN, bool) {
	n = strings.Trim(strings.TrimSpace(n), `"`)
	v, ok := dnp3IINByName[strings.ToLower(n)]
	return v, ok
}

// DNP3Meta carries what the dnp3 rule keywords need.
type DNP3Meta struct {
	FuncCode byte
	IIN      DNP3IIN
	HasIIN   bool // responses carry IIN; requests do not
}

// ParseDNP3 decodes the DNP3 framing needed for dnp3_ind: the link-layer
// header, the transport byte, and the application-layer header.
//
// Frame layout: 0x05 0x64, length, control, dest(2), src(2), CRC(2), then
// user data in 16-byte blocks each followed by a 2-byte CRC. The first block
// begins with the transport header, then the application header — control,
// function code, and (for responses) the two IIN octets.
func ParseDNP3(p []byte) *DNP3Meta {
	if len(p) < 11 || p[0] != 0x05 || p[1] != 0x64 {
		return nil
	}
	// 10-byte link header (incl. its CRC), then the first data block.
	body := p[10:]
	if len(body) < 2 {
		return nil
	}
	// body[0] is the transport header; the application header follows.
	app := body[1:]
	if len(app) < 2 {
		return nil
	}
	m := &DNP3Meta{FuncCode: app[1]}

	// Responses (function code 0x81 unsolicited, 0x82 response) carry IIN.
	if m.FuncCode == 0x81 || m.FuncCode == 0x82 {
		if len(app) < 4 {
			return nil
		}
		m.IIN = DNP3IIN(app[2]) | DNP3IIN(app[3])<<8
		m.HasIIN = true
	}
	return m
}

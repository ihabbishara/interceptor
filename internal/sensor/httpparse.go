package sensor

import "bytes"

// SplitHTTPBody splits a reassembled HTTP/1.1 message at the first blank
// line (CRLFCRLF), returning headers and body. This is intentionally
// minimal — enough to extract an LLM request/response body for the capture
// spike, not a conforming HTTP parser. Chunked/SSE decoding is a later,
// separate concern (see spec testing §5.1).
func SplitHTTPBody(raw []byte) (headers, body []byte, ok bool) {
	sep := []byte("\r\n\r\n")
	i := bytes.Index(raw, sep)
	if i < 0 {
		return nil, nil, false
	}
	return raw[:i], raw[i+len(sep):], true
}

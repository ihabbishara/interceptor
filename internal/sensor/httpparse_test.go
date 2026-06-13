package sensor

import "testing"

func TestSplitBodyAfterHeaders(t *testing.T) {
	raw := []byte("POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\n\r\n{\"model\":\"gpt-4\"}")
	headers, body, ok := SplitHTTPBody(raw)
	if !ok {
		t.Fatal("expected to find header/body boundary")
	}
	if string(body) != `{"model":"gpt-4"}` {
		t.Fatalf("body = %q", body)
	}
	if len(headers) == 0 || string(body) == string(headers) {
		t.Fatal("headers not separated from body")
	}
}

func TestSplitBodyNoBoundaryReturnsFalse(t *testing.T) {
	if _, _, ok := SplitHTTPBody([]byte("partial headers only")); ok {
		t.Fatal("expected ok=false when no boundary present")
	}
}

func TestSplitBodyEmptyBody(t *testing.T) {
	_, body, ok := SplitHTTPBody([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if !ok || len(body) != 0 {
		t.Fatalf("expected ok with empty body, got ok=%v body=%q", ok, body)
	}
}

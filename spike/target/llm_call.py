"""Target program for the eBPF capture spike. Makes one HTTPS POST shaped
like an OpenAI chat-completions call. We do NOT need a real API key or a
real response — we only need genuine TLS traffic whose plaintext request
body the eBPF uprobe should surface. httpbin echoes the body back, giving
us a real TLS response to capture on SSL_read too.
"""
import json
import requests

PAYLOAD = {
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "SPIKE_MARKER_REQUEST_BODY"}],
}

resp = requests.post("https://httpbin.org/post", json=PAYLOAD, timeout=30)
print("status:", resp.status_code)
print("echoed marker present:", "SPIKE_MARKER_REQUEST_BODY" in resp.text)
print(json.dumps(resp.json().get("json", {}), indent=2))

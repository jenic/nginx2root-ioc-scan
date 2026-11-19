package analyzer

import "testing"

func TestParseCombinedExtended(t *testing.T) {
	line := []byte(`192.0.2.4 - - [19/Nov/2026:02:03:04 +0000] "HEAD /asset.bin HTTP/2.0" 200 0 "-" "-" request_length=50331672 request_time=0.250 conn=17`)
	record, err := ParseLine(line, "access.log", 7)
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	if record.Method != "HEAD" || record.Path != "/asset.bin" || record.Status != 200 {
		t.Fatalf("unexpected record: %+v", record)
	}
	if !record.HasRequestLength || record.RequestLength != 50331672 {
		t.Fatalf("request length not parsed: %+v", record)
	}
}

func TestParseJSON(t *testing.T) {
	line := []byte(`{"time_iso8601":"2026-11-19T02:03:04+00:00","remote_addr":"2001:db8::1","request":"GET /video HTTP/2.0","status":206,"body_bytes_sent":0,"request_length":91}`)
	record, err := ParseLine(line, "access.json", 1)
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	if record.RemoteAddr != "2001:db8::1" || record.Method != "GET" || record.Status != 206 {
		t.Fatalf("unexpected record: %+v", record)
	}
}

func TestParseCommonLogWithoutRefererAndUserAgent(t *testing.T) {
	line := []byte(`192.0.2.5 - - [19/Nov/2026:02:03:04 +0000] "HEAD /asset.bin HTTP/2.0" 200 0 request_length=2097152`)
	record, err := ParseLine(line, "access.log", 8)
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	if record.Method != "HEAD" || !record.HasRequestLength || record.RequestLength != 2097152 {
		t.Fatalf("unexpected record: %+v", record)
	}
}

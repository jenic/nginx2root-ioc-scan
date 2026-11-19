package analyzer

import (
	"fmt"
	"testing"
	"time"
)

func TestAnalyzeCorrelatesDistributedBursts(t *testing.T) {
	start := time.Date(2026, 11, 19, 2, 0, 0, 0, time.UTC)
	var records []Record
	for index := 0; index < 6; index++ {
		records = append(records, Record{
			Timestamp:        start.Add(time.Duration(index) * time.Second),
			RemoteAddr:       fmt.Sprintf("192.0.2.%d", index+1),
			Method:           "HEAD",
			Path:             fmt.Sprintf("/object/%d", index),
			Status:           200,
			RequestLength:    2 << 20,
			HasRequestLength: true,
			Source:           "distributed.log",
			Line:             index + 1,
		})
	}
	for index := 0; index < 5; index++ {
		records = append(records, Record{
			Timestamp:  start.Add(time.Duration(10+index) * time.Second),
			RemoteAddr: fmt.Sprintf("198.51.100.%d", index+1),
			Method:     "GET",
			Path:       fmt.Sprintf("/range/%d", index),
			Status:     206,
			Source:     "distributed.log",
			Line:       index + 7,
		})
	}
	result := Analyze(records, Config{
		Window:              30 * time.Second,
		CorrelationWindow:   time.Minute,
		HeadCount:           5,
		LargeHeadCount:      3,
		LargeRequestBytes:   1 << 20,
		PartialContentCount: 4,
	})
	wanted := map[string]bool{
		"head_burst":                         false,
		"large_head_burst":                   false,
		"partial_content_burst":              false,
		"http2_flow_control_exploit_pattern": false,
	}
	for _, alert := range result.Alerts {
		if _, ok := wanted[alert.Rule]; ok {
			wanted[alert.Rule] = true
		}
		if alert.Rule == "http2_flow_control_exploit_pattern" && alert.DistinctClients < 10 {
			t.Fatalf("composite alert did not aggregate clients: %+v", alert)
		}
	}
	for rule, seen := range wanted {
		if !seen {
			t.Errorf("expected alert %q, got %+v", rule, result.Alerts)
		}
	}
}

func TestAnalyzeDoesNotGroupByClient(t *testing.T) {
	start := time.Date(2026, 11, 19, 2, 0, 0, 0, time.UTC)
	records := []Record{
		{Timestamp: start, RemoteAddr: "192.0.2.1", Method: "HEAD", Path: "/a", Status: 200},
		{Timestamp: start.Add(time.Second), RemoteAddr: "192.0.2.2", Method: "HEAD", Path: "/b", Status: 200},
		{Timestamp: start.Add(2 * time.Second), RemoteAddr: "192.0.2.3", Method: "HEAD", Path: "/c", Status: 200},
	}
	result := Analyze(records, Config{
		Window:              10 * time.Second,
		CorrelationWindow:   time.Minute,
		HeadCount:           3,
		LargeHeadCount:      3,
		LargeRequestBytes:   1 << 20,
		PartialContentCount: 3,
	})
	if len(result.Alerts) != 1 || result.Alerts[0].Rule != "head_burst" {
		t.Fatalf("expected aggregate HEAD alert, got %+v", result.Alerts)
	}
	if result.Alerts[0].DistinctClients != 3 || result.Alerts[0].DistinctPaths != 3 {
		t.Fatalf("unexpected cardinalities: %+v", result.Alerts[0])
	}
}

func TestAnalyzeIgnoresKnownHTTP1Traffic(t *testing.T) {
	start := time.Date(2026, 11, 19, 2, 0, 0, 0, time.UTC)
	records := []Record{
		{Timestamp: start, Method: "HEAD", Status: 206, Protocol: "HTTP/1.1"},
		{Timestamp: start.Add(time.Second), Method: "HEAD", Status: 206, Protocol: "HTTP/1.1"},
		{Timestamp: start.Add(2 * time.Second), Method: "HEAD", Status: 206, Protocol: "HTTP/1.1"},
	}
	result := Analyze(records, Config{
		Window:              10 * time.Second,
		CorrelationWindow:   time.Minute,
		HeadCount:           2,
		LargeHeadCount:      2,
		LargeRequestBytes:   1 << 20,
		PartialContentCount: 2,
	})
	if len(result.Alerts) != 0 || result.HEADRecords != 0 || result.PartialContentResponses != 0 {
		t.Fatalf("known HTTP/1 traffic should not contribute: %+v", result)
	}
}

func TestAnalyzeStoresRuleSpecificMatches(t *testing.T) {
	start := time.Date(2026, 11, 19, 2, 0, 0, 0, time.UTC)
	records := []Record{
		{Timestamp: start, Method: "HEAD", Path: "/small", Protocol: "HTTP/2", Status: 200, Source: "a.log", Line: 1},
		{Timestamp: start.Add(time.Second), Method: "HEAD", Path: "/large", Protocol: "HTTP/2", Status: 200, RequestLength: 2 << 20, HasRequestLength: true, Source: "b.log", Line: 2},
		{Timestamp: start.Add(2 * time.Second), Method: "GET", Path: "/first", Protocol: "HTTP/2", Status: 206, Source: "c.log", Line: 3},
		{Timestamp: start.Add(3 * time.Second), Method: "GET", Path: "/second", Protocol: "HTTP/2", Status: 206, Source: "c.log", Line: 4},
	}
	result := Analyze(records, Config{
		Window:              10 * time.Second,
		CorrelationWindow:   time.Minute,
		HeadCount:           2,
		LargeHeadCount:      1,
		LargeRequestBytes:   1 << 20,
		PartialContentCount: 2,
	})
	alerts := make(map[string]Alert)
	for _, alert := range result.Alerts {
		alerts[alert.Rule] = alert
	}
	if got := alerts["head_burst"].Matches; len(got) != 2 || got[0].Method != "HEAD" || got[1].Method != "HEAD" {
		t.Fatalf("unexpected HEAD matches: %+v", got)
	}
	if got := alerts["large_head_burst"].Matches; len(got) != 1 || got[0].Path != "/large" {
		t.Fatalf("unexpected large HEAD matches: %+v", got)
	}
	if got := alerts["partial_content_burst"].Matches; len(got) != 2 || got[0].Status != 206 || got[1].Status != 206 {
		t.Fatalf("unexpected partial-content matches: %+v", got)
	}
	wantSources := []string{"a.log", "b.log"}
	if got := alerts["head_burst"].Sources; fmt.Sprint(got) != fmt.Sprint(wantSources) {
		t.Fatalf("HEAD sources = %v, want %v", got, wantSources)
	}
}

func TestAnalyzeBoundsVerboseMatches(t *testing.T) {
	start := time.Date(2026, 11, 19, 2, 0, 0, 0, time.UTC)
	records := make([]Record, maxAlertMatches+5)
	for index := range records {
		records[index] = Record{
			Timestamp: start.Add(time.Duration(index) * time.Millisecond),
			Method:    "HEAD",
			Path:      fmt.Sprintf("/%d", index),
			Status:    200,
			Source:    fmt.Sprintf("source-%d.log", index%2),
			Line:      index + 1,
		}
	}
	result := Analyze(records, Config{
		Window:              time.Minute,
		CorrelationWindow:   time.Minute,
		HeadCount:           len(records),
		LargeHeadCount:      len(records) + 1,
		LargeRequestBytes:   1 << 20,
		PartialContentCount: len(records) + 1,
	})
	if len(result.Alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(result.Alerts))
	}
	alert := result.Alerts[0]
	if len(alert.Matches) != maxAlertMatches || alert.MatchesTruncated != 5 {
		t.Fatalf("matches = %d, truncated = %d", len(alert.Matches), alert.MatchesTruncated)
	}
	if len(alert.Sources) != 2 {
		t.Fatalf("sources = %v, want both contributing files", alert.Sources)
	}
}

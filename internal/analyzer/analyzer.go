package analyzer

import (
	"sort"
	"strings"
	"time"
)

const maxAlertMatches = 100

// Config controls aggregate time-window detection thresholds.
type Config struct {
	Window              time.Duration
	CorrelationWindow   time.Duration
	HeadCount           int
	LargeHeadCount      int
	LargeRequestBytes   int64
	PartialContentCount int
}

// Alert describes a threshold crossing and its aggregate evidence.
type Alert struct {
	Rule             string     `json:"rule"`
	Severity         string     `json:"severity"`
	Description      string     `json:"description"`
	Start            time.Time  `json:"start"`
	End              time.Time  `json:"end"`
	HeadRequests     int        `json:"head_requests"`
	LargeHeads       int        `json:"large_head_requests"`
	PartialResponses int        `json:"partial_responses"`
	RequestBytes     int64      `json:"request_bytes"`
	DistinctClients  int        `json:"distinct_clients"`
	DistinctPaths    int        `json:"distinct_paths"`
	Evidence         []Evidence `json:"evidence,omitempty"`
	Sources          []string   `json:"sources,omitempty"`
	Matches          []Match    `json:"matches,omitempty"`
	MatchesTruncated int        `json:"matches_truncated,omitempty"`
}

// Result contains alerts and metadata about the analyzed records.
type Result struct {
	Alerts                  []Alert `json:"alerts"`
	Records                 int     `json:"records"`
	HEADRecords             int     `json:"head_records"`
	HEADRecordsWithLength   int     `json:"head_records_with_length"`
	PartialContentResponses int     `json:"partial_content_responses"`
}

type windowStats struct {
	start             time.Time
	end               time.Time
	heads             int
	largeHeads        int
	partials          int
	requestBytes      int64
	largeRequestBytes int64
	clients           map[string]struct{}
	paths             map[string]struct{}
	evidence          []Evidence
	records           []Record
}

// Analyze detects bursts globally across all clients and paths.
func Analyze(records []Record, config Config) Result {
	sorted := append([]Record(nil), records...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})
	result := Result{Records: len(sorted)}
	for _, record := range sorted {
		if !isHTTP2OrUnknown(record.Protocol) {
			continue
		}
		if strings.EqualFold(record.Method, "HEAD") {
			result.HEADRecords++
			if record.HasRequestLength {
				result.HEADRecordsWithLength++
			}
		}
		if record.Status == 206 {
			result.PartialContentResponses++
		}
	}

	left := 0
	headActive := false
	largeHeadActive := false
	partialActive := false
	compositeActive := false
	var lastHead *Alert
	var lastPartial *Alert
	for right, record := range sorted {
		if !isHTTP2OrUnknown(record.Protocol) {
			continue
		}
		for left <= right && record.Timestamp.Sub(sorted[left].Timestamp) > config.Window {
			left++
		}
		stats := summarize(sorted[left:right+1], config.LargeRequestBytes)

		headCondition := stats.heads >= config.HeadCount
		if headCondition && !headActive {
			alert := makeAlert("head_burst", "medium",
				"rapid aggregate burst of HEAD requests", stats)
			result.Alerts = append(result.Alerts, alert)
			lastHead = &result.Alerts[len(result.Alerts)-1]
		}
		headActive = headCondition

		largeHeadCondition := stats.largeHeads >= config.LargeHeadCount
		if largeHeadCondition && !largeHeadActive {
			alert := makeAlert("large_head_burst", "high",
				"rapid aggregate burst of oversized HEAD requests", stats)
			result.Alerts = append(result.Alerts, alert)
			lastHead = &result.Alerts[len(result.Alerts)-1]
		}
		largeHeadActive = largeHeadCondition

		partialCondition := stats.partials >= config.PartialContentCount
		if partialCondition && !partialActive {
			alert := makeAlert("partial_content_burst", "medium",
				"rapid aggregate burst of HTTP 206 responses", stats)
			result.Alerts = append(result.Alerts, alert)
			lastPartial = &result.Alerts[len(result.Alerts)-1]
		}
		partialActive = partialCondition

		compositeCondition := alertsCorrelate(lastHead, lastPartial, config.CorrelationWindow)
		if compositeCondition && !compositeActive {
			correlationStart := lastHead.Start
			if lastPartial.Start.Before(correlationStart) {
				correlationStart = lastPartial.Start
			}
			first := sort.Search(right+1, func(index int) bool {
				return !sorted[index].Timestamp.Before(correlationStart)
			})
			correlatedStats := summarize(sorted[first:right+1], config.LargeRequestBytes)
			alert := makeAlert("http2_flow_control_exploit_pattern", "critical",
				"HEAD-request and partial-content bursts occurred close together", correlatedStats)
			result.Alerts = append(result.Alerts, alert)
		}
		compositeActive = compositeCondition
		if compositeActive && lastHead != nil && lastPartial != nil {
			latest := lastHead.End
			if lastPartial.End.After(latest) {
				latest = lastPartial.End
			}
			if record.Timestamp.Sub(latest) > config.CorrelationWindow {
				compositeActive = false
				lastHead = nil
				lastPartial = nil
			}
		}
	}
	return result
}

func summarize(records []Record, largeRequestBytes int64) windowStats {
	stats := windowStats{
		largeRequestBytes: largeRequestBytes,
		clients:           make(map[string]struct{}),
		paths:             make(map[string]struct{}),
		records:           records,
	}
	if len(records) > 0 {
		stats.start = records[0].Timestamp
		stats.end = records[len(records)-1].Timestamp
	}
	for _, record := range records {
		if !isHTTP2OrUnknown(record.Protocol) {
			continue
		}
		interesting := false
		if strings.EqualFold(record.Method, "HEAD") {
			stats.heads++
			interesting = true
			if record.HasRequestLength && record.RequestLength >= largeRequestBytes {
				stats.largeHeads++
				stats.requestBytes += record.RequestLength
			}
		}
		if record.Status == 206 {
			stats.partials++
			interesting = true
		}
		if !interesting {
			continue
		}
		if record.RemoteAddr != "" {
			stats.clients[record.RemoteAddr] = struct{}{}
		}
		if record.Path != "" {
			stats.paths[record.Path] = struct{}{}
		}
		if len(stats.evidence) < 8 {
			stats.evidence = append(stats.evidence, Evidence{Source: record.Source, Line: record.Line})
		}
	}
	return stats
}

func isHTTP2OrUnknown(protocol string) bool {
	if protocol == "" {
		return true
	}
	normalized := strings.ToUpper(protocol)
	return normalized == "HTTP/2" || normalized == "HTTP/2.0" || normalized == "H2"
}

func makeAlert(rule, severity, description string, stats windowStats) Alert {
	sources, matches, truncated := matchingRequests(rule, stats.records, stats.largeRequestBytes)
	return Alert{
		Rule:             rule,
		Severity:         severity,
		Description:      description,
		Start:            stats.start,
		End:              stats.end,
		HeadRequests:     stats.heads,
		LargeHeads:       stats.largeHeads,
		PartialResponses: stats.partials,
		RequestBytes:     stats.requestBytes,
		DistinctClients:  len(stats.clients),
		DistinctPaths:    len(stats.paths),
		Evidence:         append([]Evidence(nil), stats.evidence...),
		Sources:          sources,
		Matches:          matches,
		MatchesTruncated: truncated,
	}
}

func matchingRequests(rule string, records []Record, largeRequestBytes int64) ([]string, []Match, int) {
	sourceSet := make(map[string]struct{})
	matches := make([]Match, 0, min(len(records), maxAlertMatches))
	total := 0
	for _, record := range records {
		if !recordMatchesRule(rule, record, largeRequestBytes) {
			continue
		}
		total++
		if record.Source != "" {
			sourceSet[record.Source] = struct{}{}
		}
		if len(matches) == maxAlertMatches {
			continue
		}
		matches = append(matches, Match{
			Timestamp:        record.Timestamp,
			Source:           record.Source,
			Line:             record.Line,
			Method:           record.Method,
			Path:             record.Path,
			Protocol:         record.Protocol,
			Status:           record.Status,
			RequestLength:    record.RequestLength,
			HasRequestLength: record.HasRequestLength,
		})
	}
	sources := make([]string, 0, len(sourceSet))
	for source := range sourceSet {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	return sources, matches, total - len(matches)
}

func recordMatchesRule(rule string, record Record, largeRequestBytes int64) bool {
	if !isHTTP2OrUnknown(record.Protocol) {
		return false
	}
	isHead := strings.EqualFold(record.Method, "HEAD")
	switch rule {
	case "head_burst":
		return isHead
	case "large_head_burst":
		return isHead && record.HasRequestLength && record.RequestLength >= largeRequestBytes
	case "partial_content_burst":
		return record.Status == 206
	case "http2_flow_control_exploit_pattern":
		return isHead || record.Status == 206
	default:
		return false
	}
}

func alertsCorrelate(head, partial *Alert, window time.Duration) bool {
	if head == nil || partial == nil {
		return false
	}
	delta := head.End.Sub(partial.End)
	if delta < 0 {
		delta = -delta
	}
	return delta <= window
}

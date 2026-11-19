package analyzer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	combinedPattern = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^]]+)]\s+"([^"]*)"\s+(\d{3})\s+(\d+|-)(?:\s+"[^"]*"\s+"[^"]*")?(.*)$`)
	extraPattern    = regexp.MustCompile(`(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|(\S+))`)
)

// ParseLine parses a combined, extended-combined, or JSON nginx access-log line.
func ParseLine(line []byte, source string, lineNumber int) (Record, error) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return Record{}, errors.New("empty line")
	}
	if line[0] == '{' {
		return parseJSON(line, source, lineNumber)
	}
	return parseCombined(string(line), source, lineNumber)
}

func parseCombined(line, source string, lineNumber int) (Record, error) {
	match := combinedPattern.FindStringSubmatch(line)
	if match == nil {
		return Record{}, errors.New("line does not match nginx combined format")
	}
	timestamp, err := parseTime(match[2])
	if err != nil {
		return Record{}, fmt.Errorf("timestamp: %w", err)
	}
	method, path, protocol := splitRequest(match[3])
	status, _ := strconv.Atoi(match[4])
	bodyBytes, _ := strconv.ParseInt(strings.TrimSpace(match[5]), 10, 64)
	record := Record{
		Timestamp:  timestamp,
		RemoteAddr: match[1],
		Method:     method,
		Path:       path,
		Protocol:   protocol,
		Status:     status,
		BodyBytes:  bodyBytes,
		Source:     source,
		Line:       lineNumber,
	}
	for _, item := range extraPattern.FindAllStringSubmatch(match[6], -1) {
		value := item[2]
		if value == "" {
			value = item[3]
		}
		if isRequestLengthKey(item[1]) {
			if parsed, parseErr := strconv.ParseInt(value, 10, 64); parseErr == nil && parsed >= 0 {
				record.RequestLength = parsed
				record.HasRequestLength = true
			}
		}
	}
	return record, nil
}

func parseJSON(line []byte, source string, lineNumber int) (Record, error) {
	var values map[string]any
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()
	if err := decoder.Decode(&values); err != nil {
		return Record{}, fmt.Errorf("JSON: %w", err)
	}
	timestampText := firstString(values, "time_iso8601", "timestamp", "time", "@timestamp", "time_local")
	timestamp, err := parseTime(timestampText)
	if err != nil {
		return Record{}, fmt.Errorf("timestamp: %w", err)
	}
	method := strings.ToUpper(firstString(values, "request_method", "method"))
	path := firstString(values, "request_uri", "uri", "path")
	protocol := firstString(values, "server_protocol", "protocol")
	if request := firstString(values, "request"); request != "" {
		requestMethod, requestPath, requestProtocol := splitRequest(request)
		if method == "" {
			method = requestMethod
		}
		if path == "" {
			path = requestPath
		}
		if protocol == "" {
			protocol = requestProtocol
		}
	}
	status, ok := firstInt64(values, "status")
	if !ok {
		return Record{}, errors.New("JSON entry has no numeric status")
	}
	bodyBytes, _ := firstInt64(values, "body_bytes_sent", "bytes_sent")
	requestLength, hasRequestLength := firstInt64(values, "request_length", "length", "rl")
	return Record{
		Timestamp:        timestamp,
		RemoteAddr:       firstString(values, "remote_addr", "client_ip", "source_ip"),
		Method:           method,
		Path:             path,
		Protocol:         protocol,
		Status:           int(status),
		BodyBytes:        bodyBytes,
		RequestLength:    requestLength,
		HasRequestLength: hasRequestLength && requestLength >= 0,
		Source:           source,
		Line:             lineNumber,
	}, nil
}

func splitRequest(request string) (string, string, string) {
	fields := strings.Fields(request)
	if len(fields) < 2 {
		return "", "", ""
	}
	method := strings.ToUpper(fields[0])
	path := fields[1]
	protocol := ""
	if len(fields) > 2 {
		protocol = fields[len(fields)-1]
	}
	return method, path, protocol
}

func parseTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("missing timestamp")
	}
	formats := []string{
		"02/Jan/2006:15:04:05 -0700",
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05-07:00",
	}
	for _, format := range formats {
		if parsed, err := time.Parse(format, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported value %q", value)
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			switch typed := value.(type) {
			case string:
				return typed
			case json.Number:
				return typed.String()
			}
		}
	}
	return ""
}

func firstInt64(values map[string]any, keys ...string) (int64, bool) {
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case json.Number:
			parsed, err := typed.Int64()
			return parsed, err == nil
		case string:
			parsed, err := strconv.ParseInt(typed, 10, 64)
			return parsed, err == nil
		case float64:
			return int64(typed), true
		}
	}
	return 0, false
}

func isRequestLengthKey(key string) bool {
	switch strings.ToLower(key) {
	case "request_length", "length", "rl", "request_bytes":
		return true
	default:
		return false
	}
}

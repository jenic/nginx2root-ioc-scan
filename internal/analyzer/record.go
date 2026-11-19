// Package analyzer parses nginx access logs and detects aggregate exploit-like behavior.
package analyzer

import "time"

// Record is the normalized subset of an nginx access-log entry used for detection.
type Record struct {
	Timestamp        time.Time
	RemoteAddr       string
	Method           string
	Path             string
	Protocol         string
	Status           int
	BodyBytes        int64
	RequestLength    int64
	HasRequestLength bool
	Source           string
	Line             int
}

// Evidence identifies an input line that contributed to an alert.
type Evidence struct {
	Source string `json:"source"`
	Line   int    `json:"line"`
}

// Match describes a request that contributed to an alert.
type Match struct {
	Timestamp        time.Time `json:"timestamp"`
	Source           string    `json:"source"`
	Line             int       `json:"line"`
	Method           string    `json:"method"`
	Path             string    `json:"path"`
	Protocol         string    `json:"protocol,omitempty"`
	Status           int       `json:"status"`
	RequestLength    int64     `json:"request_length,omitempty"`
	HasRequestLength bool      `json:"has_request_length"`
}

// Package cfg defines detector defaults shared by the CLI and analyzer.
package cfg

import "time"

const (
	// DefaultHeadCount is the number of HEAD requests that triggers a burst.
	DefaultHeadCount = 20
	// DefaultLargeHeadCount is the number of large HEAD requests that triggers a burst.
	DefaultLargeHeadCount = 3
	// DefaultLargeRequestBytes is the default minimum size of a large request.
	DefaultLargeRequestBytes int64 = 1 << 20
	// DefaultPartialCount is the number of 206 responses that triggers a burst.
	DefaultPartialCount = 10
)

const (
	// DefaultWindow is the sliding detection window.
	DefaultWindow = 30 * time.Second
	// DefaultCorrelationWindow is the maximum separation between related bursts.
	DefaultCorrelationWindow = 5 * time.Minute
)

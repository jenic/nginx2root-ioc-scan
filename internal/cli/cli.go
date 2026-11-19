// Package cli implements the nginx-ioc-scan command-line interface.
package cli

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jenic/nginx2root-ioc-scan/internal/analyzer"
	"github.com/jenic/nginx2root-ioc-scan/internal/build"
	"github.com/jenic/nginx2root-ioc-scan/internal/cfg"
)

const maxLogLineBytes = 1024 * 1024

// Run parses arguments, scans inputs, and returns a process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("nginx-ioc-scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	window := flags.Duration("window", cfg.DefaultWindow, "sliding burst-detection window")
	correlation := flags.Duration("correlation-window", cfg.DefaultCorrelationWindow, "maximum separation between related bursts")
	headCount := flags.Int("head-count", cfg.DefaultHeadCount, "HEAD requests required for a burst")
	largeHeadCount := flags.Int("large-head-count", cfg.DefaultLargeHeadCount, "oversized HEAD requests required for a burst")
	largeBytes := flags.Int64("large-request-bytes", cfg.DefaultLargeRequestBytes, "minimum request length considered oversized")
	partialCount := flags.Int("partial-count", cfg.DefaultPartialCount, "HTTP 206 responses required for a burst")
	output := flags.String("output", "text", "output format: text or json")
	verbose := flags.Bool("verbose", false, "show filenames and matching requests for each alert")
	showVersion := flags.Bool("version", false, "print version information")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: nginx-ioc-scan [flags] [access.log ...]")
		fmt.Fprintln(stderr, "Reads stdin when no files are supplied. Files ending in .gz are decompressed.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "nginx-ioc-scan %s (%s)\n", build.Version, build.Commit)
		return 0
	}
	if err := validateFlags(*window, *correlation, *headCount, *largeHeadCount, *largeBytes, *partialCount, *output); err != nil {
		fmt.Fprintf(stderr, "nginx-ioc-scan: %v\n", err)
		return 2
	}

	var records []analyzer.Record
	stats := scanStats{}
	paths := flags.Args()
	if len(paths) == 0 {
		if err := scanReader(stdin, "<stdin>", &records, &stats); err != nil {
			fmt.Fprintf(stderr, "nginx-ioc-scan: %v\n", err)
			return 2
		}
	} else {
		for _, path := range paths {
			if err := scanFile(path, &records, &stats); err != nil {
				fmt.Fprintf(stderr, "nginx-ioc-scan: %v\n", err)
				return 2
			}
		}
	}
	if len(records) == 0 && stats.nonEmpty > 0 {
		fmt.Fprintf(stderr, "nginx-ioc-scan: no parseable nginx access-log records (%d malformed lines)\n", stats.malformed)
		return 2
	}

	result := analyzer.Analyze(records, analyzer.Config{
		Window:              *window,
		CorrelationWindow:   *correlation,
		HeadCount:           *headCount,
		LargeHeadCount:      *largeHeadCount,
		LargeRequestBytes:   *largeBytes,
		PartialContentCount: *partialCount,
	})
	if *output == "json" {
		outputResult := resultForOutput(result, *verbose)
		if err := json.NewEncoder(stdout).Encode(struct {
			analyzer.Result
			MalformedLines int `json:"malformed_lines"`
		}{Result: outputResult, MalformedLines: stats.malformed}); err != nil {
			fmt.Fprintf(stderr, "nginx-ioc-scan: encode output: %v\n", err)
			return 2
		}
	} else {
		writeText(stdout, result, stats.malformed, *verbose)
	}
	if result.HEADRecords > 0 && result.HEADRecordsWithLength == 0 {
		fmt.Fprintln(stderr, "warning: HEAD records have no request_length field; oversized-request detection was unavailable")
	}
	if stats.malformed > 0 {
		fmt.Fprintf(stderr, "warning: skipped %d malformed non-empty lines\n", stats.malformed)
	}
	if len(result.Alerts) > 0 {
		return 1
	}
	return 0
}

type scanStats struct {
	nonEmpty  int
	malformed int
}

func scanFile(path string, records *[]analyzer.Record, stats *scanStats) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	var reader io.Reader = file
	var compressed *gzip.Reader
	if strings.EqualFold(filepath.Ext(path), ".gz") {
		compressed, err = gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("open gzip %s: %w", path, err)
		}
		defer compressed.Close()
		reader = compressed
	}
	return scanReader(reader, path, records, stats)
}

func scanReader(reader io.Reader, source string, records *[]analyzer.Record, stats *scanStats) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), maxLogLineBytes)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		stats.nonEmpty++
		record, err := analyzer.ParseLine(line, source, lineNumber)
		if err != nil {
			stats.malformed++
			continue
		}
		*records = append(*records, record)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", source, err)
	}
	return nil
}

func validateFlags(window, correlation time.Duration, headCount, largeHeadCount int, largeBytes int64, partialCount int, output string) error {
	if window <= 0 || correlation <= 0 {
		return errors.New("time windows must be positive")
	}
	if headCount <= 0 || largeHeadCount <= 0 || largeBytes <= 0 || partialCount <= 0 {
		return errors.New("detection thresholds must be positive")
	}
	if output != "text" && output != "json" {
		return fmt.Errorf("unsupported output format %q", output)
	}
	return nil
}

func resultForOutput(result analyzer.Result, verbose bool) analyzer.Result {
	if verbose {
		return result
	}
	result.Alerts = append([]analyzer.Alert(nil), result.Alerts...)
	for index := range result.Alerts {
		result.Alerts[index].Sources = nil
		result.Alerts[index].Matches = nil
		result.Alerts[index].MatchesTruncated = 0
	}
	return result
}

func writeText(writer io.Writer, result analyzer.Result, malformed int, verbose bool) {
	fmt.Fprintf(writer, "Scanned %d records (%d malformed); %d alert(s)\n",
		result.Records, malformed, len(result.Alerts))
	if len(result.Alerts) == 0 {
		return
	}
	sort.SliceStable(result.Alerts, func(i, j int) bool {
		return result.Alerts[i].Start.Before(result.Alerts[j].Start)
	})
	for _, alert := range result.Alerts {
		fmt.Fprintf(writer, "[%s] %s %s to %s: %s; HEAD=%d large_HEAD=%d 206=%d request_bytes=%d clients=%d paths=%d\n",
			strings.ToUpper(alert.Severity), alert.Rule,
			alert.Start.Format(time.RFC3339), alert.End.Format(time.RFC3339),
			alert.Description, alert.HeadRequests, alert.LargeHeads,
			alert.PartialResponses, alert.RequestBytes,
			alert.DistinctClients, alert.DistinctPaths)
		if verbose {
			writeVerboseAlert(writer, alert)
		}
	}
}

func writeVerboseAlert(writer io.Writer, alert analyzer.Alert) {
	if len(alert.Sources) > 0 {
		quoted := make([]string, 0, len(alert.Sources))
		for _, source := range alert.Sources {
			quoted = append(quoted, fmt.Sprintf("%q", source))
		}
		fmt.Fprintf(writer, "  files: %s\n", strings.Join(quoted, ", "))
	}
	for _, match := range alert.Matches {
		source := match.Source
		if source == "" {
			source = "<unknown>"
		}
		request := strings.Join(nonEmpty(match.Method, match.Path, match.Protocol), " ")
		fmt.Fprintf(writer, "  match: %q:%d %s %q status=%d",
			source, match.Line, match.Timestamp.Format(time.RFC3339Nano), request, match.Status)
		if match.HasRequestLength {
			fmt.Fprintf(writer, " request_length=%d", match.RequestLength)
		}
		fmt.Fprintln(writer)
	}
	if alert.MatchesTruncated > 0 {
		fmt.Fprintf(writer, "  ... %d additional matching request(s) omitted\n", alert.MatchesTruncated)
	}
}

func nonEmpty(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

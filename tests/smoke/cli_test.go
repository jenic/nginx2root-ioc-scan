package smoke

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sfewer-r7/nginx2root-ioc-scan/internal/cli"
)

func TestCombinedLogFromStdin(t *testing.T) {
	input := strings.Join([]string{
		`192.0.2.1 - - [19/Nov/2026:02:03:01 +0000] "HEAD /a HTTP/2.0" 200 0 "-" "-"`,
		`192.0.2.2 - - [19/Nov/2026:02:03:02 +0000] "HEAD /b HTTP/2.0" 200 0 "-" "-"`,
		`192.0.2.3 - - [19/Nov/2026:02:03:03 +0000] "GET /c HTTP/2.0" 206 0 "-" "-"`,
	}, "\n")
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run([]string{"-head-count=2", "-partial-count=1"}, strings.NewReader(input), &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("Run() exit code = %d, stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "http2_flow_control_exploit_pattern") {
		t.Fatalf("missing composite alert: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "request_length") {
		t.Fatalf("missing request-length warning: %q", stderr.String())
	}
}

func TestVerboseOutputShowsMatchingRequestsAndFiles(t *testing.T) {
	directory := t.TempDir()
	headLog := filepath.Join(directory, "heads.log")
	partialLog := filepath.Join(directory, "partials.log")
	if err := os.WriteFile(headLog, []byte(strings.Join([]string{
		`192.0.2.1 - - [19/Nov/2026:02:03:01 +0000] "HEAD /a HTTP/2.0" 200 0 "-" "-"`,
		`192.0.2.2 - - [19/Nov/2026:02:03:02 +0000] "HEAD /b HTTP/2.0" 200 0 "-" "-"`,
	}, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(partialLog, []byte(
		`192.0.2.3 - - [19/Nov/2026:02:03:03 +0000] "GET /range HTTP/2.0" 206 0 "-" "-"`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run([]string{
		"-verbose", "-head-count=2", "-partial-count=1", headLog, partialLog,
	}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("Run() exit code = %d, stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
	output := stdout.String()
	for _, wanted := range []string{"files:", headLog, partialLog, "match:", `"HEAD /a HTTP/2.0"`, `"GET /range HTTP/2.0"`} {
		if !strings.Contains(output, wanted) {
			t.Errorf("verbose output missing %q: %s", wanted, output)
		}
	}
}

func TestVerboseJSONIsOptIn(t *testing.T) {
	input := `192.0.2.1 - - [19/Nov/2026:02:03:01 +0000] "HEAD /a HTTP/2.0" 200 0 "-" "-"`
	for _, test := range []struct {
		name    string
		args    []string
		present bool
	}{
		{name: "default", args: []string{"-output=json", "-head-count=1"}},
		{name: "verbose", args: []string{"-output=json", "-verbose", "-head-count=1"}, present: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exitCode := cli.Run(test.args, strings.NewReader(input), &stdout, &stderr)
			if exitCode != 1 {
				t.Fatalf("Run() exit code = %d, stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
			}
			hasMatches := strings.Contains(stdout.String(), `"matches"`)
			hasSources := strings.Contains(stdout.String(), `"sources"`)
			if hasMatches != test.present || hasSources != test.present {
				t.Fatalf("verbose fields present = (%t, %t), want %t: %s", hasMatches, hasSources, test.present, stdout.String())
			}
		})
	}
}

# nginx2root IOC scanner

This IOC scanner was written by OpenAI's Daybreak Blue.

`nginx-ioc-scan` looks for access-log behavior associated with CVE-2026-123007
HTTP/2 flow-control exploitation without relying on one client address or one
request path. It detects:

- aggregate bursts of `HEAD` requests;
- aggregate bursts of oversized `HEAD` requests when request length is logged;
- bursts of HTTP `206 Partial Content` responses; and
- a higher-confidence composite when HEAD and 206 bursts occur close together.

## Build and test

The Makefile keeps Go build and module caches inside the repository:

```sh
make test
make build
```

## Releases

Pushes and pull requests run the test suite, native builds, cross-platform
release builds, release-automation tests, and a reproducibility check in GitHub
Actions. Pushing a `v`-prefixed SemVer tag such as `v1.2.3` automatically
creates a GitHub Release after all CI checks pass.

Each release contains Linux and macOS archives for amd64 and arm64, Windows zip
archives for amd64 and arm64, and `SHA256SUMS`. GitHub Actions also attaches a
SLSA provenance bundle and keyless Sigstore bundles for every downloadable
asset. Release archives can be built locally with:

```sh
make release-all VERSION=v1.2.3
```

Verify a downloaded archive against the checksum manifest with:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

The release page includes `*.sigstore.json` bundles for verification with
Cosign and `provenance.sigstore.json` for verification with GitHub CLI.

## Usage

Scan one or more logs, gzip archives, or standard input:

```sh
nginx-ioc-scan /var/log/nginx/access.log /var/log/nginx/access.log.1.gz
zcat /var/log/nginx/access.log.*.gz | nginx-ioc-scan
nginx-ioc-scan -output json -window 45s -head-count 30 access.json
nginx-ioc-scan -verbose /var/log/nginx/access.log*
```

Use `-verbose` to list the contributing filenames and rule-specific matching
requests beneath each alert. Each match includes its source line, timestamp,
request, response status, and request length when available. Verbose JSON adds
structured `sources` and `matches` fields. Request details are capped at 100 per
alert, with an omitted count reported when the cap is reached.

Exit status is `0` when no alerts are found, `1` when alerts are found, and `2`
for invalid arguments or input failures. Thresholds are deliberately configurable;
run `nginx-ioc-scan -h` for all options.

The stock `combined` format is enough to detect method and status bursts, but it
does not contain request size. Add request length and connection context to make
the strongest rule available:

```nginx
log_format incident '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" '
                    'request_length=$request_length request_time=$request_time '
                    'connection=$connection connection_requests=$connection_requests';
```

JSON logs are also accepted. Common nginx field names such as `time_iso8601`,
`remote_addr`, `request`, `request_method`, `request_uri`, `server_protocol`,
`status`, `body_bytes_sent`, and `request_length` are recognized. Client address
and path cardinalities are reported as context only; detection thresholds apply
across the complete log stream so distributed traffic is not split into harmless
per-source groups. Records explicitly marked as HTTP/1.x or HTTP/3 are excluded;
HTTP/2 records and records whose format omits the protocol are analyzed.

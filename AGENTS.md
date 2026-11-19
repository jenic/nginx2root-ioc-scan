# Repository Guidelines

## Project Structure

- `cmd/nginx-ioc-scan/`: entrypoint for the nginx access-log detector.
- `internal/analyzer/`: access-log parsing and time-window detection logic.
- `internal/cfg/`: detector configuration and defaults.
- `internal/cli/`: command-line parsing, input handling, and reporting.
- `internal/build/`: version information populated at build time.
- `exploit/`: the Python RCE proof of concept and its tests.
- `tests/`: CLI, smoke, and optional end-to-end tests.
- `docs/`: generated Go package documentation.

## Build and Test Commands

- `make build`: format, vet, verify modules, and build `bin/nginx-ioc-scan`.
- `make test`: run all Go tests with workspace-local caches.
- `make release`: create a reproducible archive for the current OS and architecture.
- `make verify-repro`: build twice and compare output hashes.
- Prefer Makefile targets. When invoking Go directly, set `GOCACHE` and
  `GOMODCACHE` to directories inside this repository.

## Coding and Testing

- Use standard-library Go unless a dependency is clearly justified.
- Keep detection logic independent of client IP and request path unless a rule
  explicitly documents otherwise.
- Use `gofmt`; exported names require complete Go documentation comments.
- Add table-driven unit tests for parsing and detection changes.
- Keep tests offline and deterministic. Use `t.TempDir()` for filesystem work.

## Security and Documentation

- Treat log contents as untrusted input and bound scanner buffers and memory.
- Do not print request headers or other potentially sensitive fields unless
  they are necessary evidence.
- Document new flags and detection behavior in `README.md`.
- Use Conventional Commits 1.0.0 when asked to propose commit messages.
- Do not write Git metadata; Git operations in this environment are read-only.

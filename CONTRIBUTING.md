# Contributing

Thanks for your interest in improving wtfi3.

## Project layout

`main` is a thin wire-up; the domain logic lives in `internal/` packages so it stays testable and decoupled.

```text
cmd/wtfi3/main.go        entry point: parse config, wire packages, run(ctx)
internal/config          Config struct and flag parsing (no globals)
internal/netinfo         interface, subnet, and gateway resolution
internal/capture         libpcap live/offline loop feeding a Consumer
internal/aggregator      domain core: devices, flows, DNS, throughput, snapshot
internal/spoof           ARP-spoof MITM, context-driven, reports into a Store
internal/oui             embedded IEEE OUI vendor database
internal/tlsmeta         TLS ClientHello SNI parser
internal/web             *http.Server dashboard with graceful shutdown
```

Dependency direction: `capture` and `web` depend on `aggregator`; `spoof` reports into `aggregator` through a small `Store` interface; `aggregator` depends only on `netinfo`, `oui`, and `tlsmeta`. There are no import cycles, and lifecycle is driven by a single `context.Context` cancelled on SIGINT/SIGTERM.

## Development setup

wtfi3 depends on `libpcap` (via cgo).

- macOS: the Command Line Tools ship the pcap headers; nothing extra is needed.
- Debian/Ubuntu: `sudo apt-get install -y libpcap-dev`.

Common tasks:

```bash
make build        # build ./wtfi3 with a version stamp
make test         # run unit tests
make lint         # run golangci-lint
```

Live capture needs root. For iteration without root, replay a saved capture:

```bash
go run hack/gensample.go /tmp/sample.pcap
./wtfi3 -r /tmp/sample.pcap
```

## Commit messages

This project follows [Conventional Commits](https://www.conventionalcommits.org/). The type prefix drives the changelog and the next version number.

```text
feat(dashboard): add per-device sparkline
fix(spoof): restore ARP cache when gateway MAC is unknown
docs: explain the double-counting filter
chore(ci): bump actions/checkout to v4
```

- `feat:` a new feature (minor version bump).
- `fix:` a bug fix (patch version bump).
- `docs:`, `chore:`, `refactor:`, `test:`, `ci:` no release on their own.
- A `!` after the type or a `BREAKING CHANGE:` footer signals a major bump.

Keep one logical change per commit. Do not mix refactors with behavior changes.

## Versioning and releases

wtfi3 uses [Semantic Versioning](https://semver.org/). Releases are cut from signed, annotated git tags:

```bash
git tag -s v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

Pushing a `v*` tag triggers the release workflow, which builds per-OS binaries and attaches them to the GitHub release. Update `CHANGELOG.md` in the same commit that prepares the release.

## Pull requests

- Run `make lint test` before opening a PR; CI runs the same checks.
- Include tests for behavior changes where practical.
- Keep the README and docs in sync (both the English and Japanese versions).

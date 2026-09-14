# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-09-14

### Added

- TCP/IP primer documentation (English and Japanese) for readers new to networking.

### Changed

- Removed hard-wrapping and em dashes from all Markdown docs.
- Bumped CI actions: `checkout`, `setup-go`, `upload-artifact`, `download-artifact`, and `golangci-lint-action` to their latest major versions.

## [0.1.0] - 2026-09-13

### Added

- Passive capture mode: your own traffic plus broadcast/multicast.
- ARP-spoof MITM mode (`-spoof`) to capture every LAN device's flows, with automatic IP-forwarding toggle and ARP-cache restoration on exit.
- Real-time dashboard with devices, top flows, DNS lookups, and a live throughput graph.
- Device attribution by LAN IP (correct under MITM MAC rewriting).
- Vendor identification from the embedded IEEE OUI database (~52k prefixes).
- Destination hostname resolution from DNS responses and TLS SNI.
- Offline replay of `.pcap` files (`-r`) with no root required.
- Optional packet dump to `.pcap` (`-w`) for analysis in Wireshark.
- Dashboard internationalization: English default with a Japanese toggle.

[Unreleased]: https://github.com/kanywst/wtfi3/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/kanywst/wtfi3/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kanywst/wtfi3/releases/tag/v0.1.0

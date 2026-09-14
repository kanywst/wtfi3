# wtfi3

[![CI](https://github.com/kanywst/wtfi3/actions/workflows/ci.yml/badge.svg)](https://github.com/kanywst/wtfi3/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/kanywst/wtfi3?sort=semver)](https://github.com/kanywst/wtfi3/releases/latest) [![Go version](https://img.shields.io/github/go-mod/go-version/kanywst/wtfi3)](go.mod) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**wtfi3** shows you who is talking to whom on a WiFi network you administer. Connect to your own network, run one binary, open a browser, and watch every device's flows, DNS lookups, destination hostnames, and bandwidth in real time.

It is a passive/metadata visualizer, not a wiretap: TLS payloads are never decrypted. What you get is the shape of the traffic: endpoints, volume, protocols, DNS names, and TLS SNI hostnames.

[日本語版 README](README.ja.md) · [TCP/IP primer](docs/tcp-ip-primer.md) · [How it works (network internals)](docs/how-it-works.md)

## What you can see

- **Devices**: every host on the LAN with IP, MAC, vendor (from the embedded IEEE OUI database), and up/down byte counts.
- **Top flows**: source to destination, protocol, port, destination hostname (SNI), bytes, and packet counts.
- **DNS lookups**: which client resolved which name, and the answer.
- **Throughput**: a live bandwidth graph of the last two minutes.

## What you cannot see

- **Encrypted payloads.** HTTPS/TLS content stays encrypted. You can tell that a device is watching YouTube (from SNI/DNS), not which video.
- **Other devices' traffic without MITM.** On a switched network you only receive your own unicast plus broadcast/multicast. Seeing other devices requires the `-spoof` mode described below.

New to networking? Start with the [TCP/IP primer](docs/tcp-ip-primer.md), then read [how wtfi3 works](docs/how-it-works.md) for the full explanation with diagrams.

## Requirements

- macOS or Linux with `libpcap` available.
- Go 1.25+ to build.
- Root privileges for live capture (raw packet access). Offline replay needs no root.

## Install

### Homebrew

```bash
brew install kanywst/tap/wtfi3
```

### From source

```bash
git clone https://github.com/kanywst/wtfi3.git
cd wtfi3
make build
```

Or with the Go toolchain directly:

```bash
go build -o wtfi3 ./cmd/wtfi3
```

## Usage

```bash
# Passive: your own Mac's traffic plus broadcast/multicast only.
sudo ./wtfi3 -i en0

# ARP-spoof MITM: relay the LAN through this host to capture every device's flows.
# Use ONLY on a network you own or are authorized to test.
sudo ./wtfi3 -i en0 -spoof

# Also dump raw packets for later analysis in Wireshark.
sudo ./wtfi3 -i en0 -spoof -w capture.pcap

# Offline replay of a saved capture (no root required).
./wtfi3 -r capture.pcap
```

Then open <http://localhost:8080>. The header has two toggles: a view toggle and a language toggle (English default, Japanese available).

- **Simple view** (default) groups each device's traffic into plain-language services and activity categories (video, shopping, email, social, AI, search, news, maps, finance, food, and so on), so you can see at a glance what a device is doing and which services it is reaching. You can give each device a nickname, and every card shows a recent-activity timeline of what it was doing over the last minute.
- **Detailed view** shows the raw devices, top flows, and DNS tables.

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-i` | `en0` | Capture interface. |
| `-spoof` | `false` | ARP-spoof the LAN to capture other devices (own network only). |
| `-w` | (off) | Also write captured packets to this `.pcap` file. |
| `-r` | (off) | Read packets from a `.pcap` file instead of a live interface (no root). |
| `-listen` | `:8080` | Dashboard listen address. |
| `-scan` | (auto) | Override the LAN CIDR scanned when spoofing. |
| `-snaplen` | `262144` | Capture snap length. |
| `-version` | | Print version and exit. |

## Legal and ethical use

ARP spoofing is an active man-in-the-middle attack. Run `-spoof` only on networks you own or have explicit written authorization to test. Intercepting traffic on networks you do not control is illegal in most jurisdictions. The authors accept no liability for misuse.

## Development

```bash
make test         # run unit tests
make lint         # run golangci-lint
make build        # build with version stamp

# Regenerate a synthetic capture for offline testing:
go run hack/gensample.go /tmp/sample.pcap
./wtfi3 -r /tmp/sample.pcap

# Refresh the embedded MAC-vendor database (web/oui.tsv):
hack/update-oui.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the commit convention and release process.

## License

[MIT](LICENSE)

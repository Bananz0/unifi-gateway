# UniFi Gateway Emulator  [![Build & Release](https://github.com/amd989/unifi-gateway/actions/workflows/release.yml/badge.svg)](https://github.com/amd989/unifi-gateway/actions/workflows/release.yml)

A Python 3 daemon that emulates a Ubiquiti UniFi Gateway (UGW3) to a UniFi Controller. This allows non-Ubiquiti routers (OpenWRT, OPNSense, pfSense, or any Linux/FreeBSD router) to appear in the UniFi Controller UI and report network statistics.

## How It Works

The daemon runs alongside your non-Ubiquiti router and periodically sends "inform" packets to your UniFi Controller — the same binary protocol that real UniFi devices use. The controller sees a UGW3 gateway and displays its stats (interfaces, traffic, connected clients, routes, etc.) in the dashboard.

Your UniFi APs, switches, and other devices continue connecting to the controller normally. This project fills the "gateway" slot so the controller has a complete view of your network topology.

```
┌──────────────────┐     inform (HTTP POST)     ┌───────────────────┐
│  This Daemon     │ ─────────────────────────► │  UniFi Controller │
│  (emulates UGW3) │                            │                   │
└────────┬─────────┘                            │  Sees complete    │
         │ reads stats from                     │  network topology │
┌────────▼─────────┐                            │                   │
│  Your Router     │     UniFi APs/Switches ──► │                   │
│  (OPNSense/etc)  │     also inform normally   └───────────────────┘
└──────────────────┘
```

## Requirements

- A running UniFi Controller (self-hosted or Cloud Key)
- Network access from the daemon to the controller's `/inform` endpoint

## Installation

### Debian / Ubuntu (apt)

```bash
curl -fsSL https://amd989.github.io/unifi-gateway/setup-apt.sh | sudo bash
sudo apt install unifi-gateway
```

### RHEL / Rocky / Fedora (dnf)

```bash
curl -fsSL https://amd989.github.io/unifi-gateway/setup-rpm.sh | sudo bash
sudo dnf install unifi-gateway
```

### OpenWRT

The OpenWRT packages ship pure Python source and depend on `python3`, `python3-psutil`, and `python3-pycryptodome` from the OpenWRT feeds — keeping the package tiny for flash-constrained devices.

```bash
# Auto-detects apk (25.12+) or opkg (older)
curl -fsSL https://amd989.github.io/unifi-gateway/setup-openwrt.sh | sh
```

Then install with whichever package manager your version uses:

```bash
# OpenWRT 25.12+ (apk)
apk add unifi-gateway

# OpenWRT pre-25.12 (opkg)
opkg install unifi-gateway
```

### FreeBSD / OPNSense / pfSense (pkg)

```bash
curl -fsSL https://amd989.github.io/unifi-gateway/setup-pkg.sh | sudo sh
sudo pkg install unifi-gateway
```

### Docker

```bash
docker pull ghcr.io/amd989/unifi-gateway:latest
docker compose up -d
```

See the [Docker section](#docker) below for details.

### Standalone Binaries

Pre-built binaries are also available from [Releases](https://github.com/amd989/unifi-gateway/releases) if you prefer manual installation.

| Platform | Binary |
|---|---|
| Linux x86_64 | `unifi-gateway-linux-amd64` |
| Linux ARM64 | `unifi-gateway-linux-arm64` |
| Linux ARMv7 | `unifi-gateway-linux-armhf` |
| FreeBSD x86_64 | `unifi-gateway-freebsd-amd64` |

### From Source

```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure

Copy the sample config and edit it:

```bash
cp conf/unifi-gateway.sample.conf conf/unifi-gateway.conf
```

Edit `conf/unifi-gateway.conf`:

```ini
[gateway]
# Map UniFi logical ports to your real system interfaces
ports = [ { "ifname": "eth0", "name": "WAN", "type": "wan", "realif": "eth0" }, { "ifname": "eth1", "name": "LAN", "type": "lan", "realif": "br-lan" } ]

# Your LAN-side IP and MAC (how the controller identifies this device)
lan_ip = 192.168.1.1
lan_mac = aa:bb:cc:dd:ee:ff
```

The `realif` values must match your actual system interface names (check with `ip link` on Linux or `ifconfig` on FreeBSD).

### 3. Adopt to controller

```bash
python unifi_gateway.py set-adopt -s http://your-controller:8080/inform
```

The first run sends a discovery inform. Go to the UniFi Controller UI, find the new "USG" device, and click **Adopt**. Then run `set-adopt` again to complete the handshake:

```bash
python unifi_gateway.py set-adopt -s http://your-controller:8080/inform
```

### 4. Run

```bash
# Foreground (recommended for initial testing)
python unifi_gateway.py run

# Background daemon (Linux only)
python unifi_gateway.py start

# Stop / restart
python unifi_gateway.py stop
python unifi_gateway.py restart
```

## Platform Setup

### OpenWRT

The daemon works with OpenWRT's default dnsmasq DHCP server. Typical interface mapping:

```ini
ports = [ { "ifname": "eth0", "name": "WAN", "type": "wan", "realif": "eth0" }, { "ifname": "eth1", "name": "LAN", "type": "lan", "realif": "br-lan" } ]
```

DHCP leases are auto-detected at `/tmp/dhcp.leases`.

### OPNSense (FreeBSD)

With an API key configured, the daemon talks to OPNsense's REST API (tested against 26.7) for both reporting and control. Without one it falls back to plain FreeBSD collection (`arp -an`, `netstat -rn`, lease files).

Create a key under **System → Access → Users → (user) → API keys** and add:

```ini
[gateway]
platform = opnsense

[opnsense]
url = https://127.0.0.1:443        ; webGUI address and port
api_key = ...
api_secret = ...
```

**Reported to the controller**

| Controller view | OPNsense source |
|---|---|
| Interface counters, MAC, IP, link speed, WAN type | `diagnostics/traffic/interface`, `interfaces/overview` |
| Clients (online, hostname, last seen) | ARP table + Host discovery (hostwatch) + DHCP leases |
| Per-client traffic | Persistent byte/packet totals from local five-minute Netflow buckets, restricted to configured LAN interfaces to avoid counting WAN observations twice; reporting is delayed by the exporter. Remote API fallback is coarser; without Netflow, `diagnostics/traffic/top` provides estimates. |
| DHCP leases | ISC (`os-isc-dhcp`), Kea or Dnsmasq — whichever is running |
| WAN latency, gateway, DNS servers | `routes/gateway/status`, Unbound |
| CPU, memory, uptime | `diagnostics/system`, `diagnostics/activity` |
| Speed test results | `os-speedtest-community` plugin |
| Dynamic DNS | `os-ddclient` plugin |

**Applied from the controller**

| Controller feature | OPNsense result |
|---|---|
| Block / unblock client | MAC alias `ufg_blocked` + IP alias `ufg_blocked_ip` + a block rule on the LAN interfaces; existing states are killed |
| Reconnect client (`kick-sta`) | pf states for the client are killed |
| Firewall rules (user rules in `LAN_IN`, `WAN_LOCAL`, …) | MVC filter rules; groups become `ufg_*` aliases |
| Port forwarding | Destination NAT rules with an associated pass rule |
| DHCP static mappings | Kea reservations or Dnsmasq hosts (ISC DHCP has no API for this — a warning is logged) |
| Static DNS host records | Unbound host overrides (Dnsmasq hosts if Unbound is off) |
| Static routes | Routes, plus a gateway when the next hop has none |
| Speed test | Runs the speedtest plugin |
| Reboot | `core/system/reboot`, only with `allow_reboot = true` |

**Mirroring OPNsense into UniFi:** add a `[unifi]` section (`url`, `username`, `password`, optional `site`, `mirror_interval`) with a local controller admin account. Every `mirror_interval` seconds (default 300), the daemon copies OPNsense's own WAN port forwards, aliases (as firewall groups), LAN/WAN firewall rules, DHCP reservations (as client fixed IPs) and static routes into the controller. Mirrored objects are named `[OPNsense] …` (clients get it in their note). OPNsense stays the source: they're refreshed from it and removed when the original goes away. When the controller pushes them back, the gateway skips them, so nothing is duplicated. Anything UniFi can't express (e.g. several ports forwarded to one, LAN-side redirects, rules on other interfaces) is skipped with a log warning.

**DPI / Insights:** if Zenarmor is installed, per-client application stats are read from its reporting database (`dpi = auto`, `zenarmor_db` in `[opnsense]`). Reports include the legacy USG fields and the modern `dpi_stats` format with camel-case counters. Saved client application statistics are confirmed on Network 10.6 for both UXG-Max and USG emulation, including real production USG reports. Visible Insights pages and connection Flows still need separate validation. The UXG configuration translator is not implemented; do not switch production to a UXG identity yet. See [UXG findings](docs/uxg-emulation.md); the retired `stadpi`/`sitedpi` endpoints always return empty results on 10.6.

Zenarmor reports include per-application country byte totals where geography is
known. Inbound connections use the destination client's MAC and reverse the
traffic direction; router interface MACs and invalid MACs are excluded.
Application mapping prefers exact names and explicit aliases, leaving unknown
applications in their category instead of guessing from a brand name. Counters
and database cursors survive daemon restarts in private JSON files alongside
the OPNsense state file. A fresh installation establishes a baseline without
replaying old history. Netflow totals follow observed interface/IP/MAC ownership;
ambiguous address-change buckets remain unattributed. Client counters refresh
each inform and clients are assigned to their observed LAN.

**Running from source on OPNsense:** OPNsense doesn't ship psutil or pycryptodome, and neither is required here — the inform encryption falls back to the `cryptography` package OPNsense already includes, and host stats come from the API. Copy the sources to e.g. `/usr/local/lib/unifi-gateway` and run `python3 unifi_gateway.py run`.

DNS host overrides are created with a 60 s TTL. If AdGuard Home sits in front of Unbound with optimistic caching on, it can still serve a removed record for up to `cache_optimistic_max_age`.

Everything the daemon creates is tagged `unifi-gw:` in its description, and only tagged objects are changed or removed — your own rules and aliases are never touched. The controller's built-in rules (rule numbers 3000–3999 and 6000+, default actions, masquerade NAT) are deliberately not copied: OPNsense already has stateful defaults and automatic outbound NAT. Each section can be switched off in `[opnsense]` (see the reference below).

Typical interface mapping (check your interfaces with `ifconfig`):

```ini
ports = [ { "ifname": "eth0", "name": "WAN", "type": "wan", "realif": "vmx0" }, { "ifname": "eth1", "name": "LAN", "type": "lan", "realif": "vmx1" } ]
dhcp_lease_file = /var/db/kea/kea-leases4.csv
dhcp_lease_format = kea
```

Recommended setup using a Python virtual environment:

```bash
python3 -m venv /opt/unifi-gateway/venv
/opt/unifi-gateway/venv/bin/pip install -r requirements.txt
/opt/unifi-gateway/venv/bin/python unifi_gateway.py set-adopt -s http://your-controller:8080/inform
/opt/unifi-gateway/venv/bin/python unifi_gateway.py run
```

### pfSense (FreeBSD)

Same as OPNSense but uses ISC dhcpd instead of KEA:

```ini
dhcp_lease_file = /var/dhcpd/var/db/dhcpd.leases
dhcp_lease_format = isc
```

### Generic Linux (Debian, Ubuntu, etc.)

Works out of the box. Uses `/proc/net/dev` for multicast counters, `/proc/net/route` for default gateway, and `/etc/resolv.conf` for nameservers.

## Docker

### Build and run

```bash
docker build -t unifi-gateway .
docker run -d --name unifi-gateway --network host \
  -v $(pwd)/conf:/app/conf \
  unifi-gateway
```

### Docker Compose

```bash
docker compose up -d
```

For automatic adoption on first start, set the `UNIFI_ADOPT_URL` environment variable in `docker-compose.yml`:

```yaml
environment:
  - UNIFI_ADOPT_URL=http://your-controller:8080/inform
```

**Note:** `network_mode: host` is required so the daemon can read the host's real network interfaces. This only works on **Linux** — Docker Desktop on Windows/macOS does not support host networking.

## Service Management

Packages automatically install and enable the service. After configuring, just start it:

| Platform | Start | Logs |
|---|---|---|
| systemd (Debian/Ubuntu/RHEL) | `sudo systemctl start unifi-gateway` | `journalctl -u unifi-gateway -f` |
| rc.d (FreeBSD/OPNSense) | `sudo service unifi_gateway start` | `tail -f /var/log/unifi-gateway.log` |
| procd (OpenWRT) | `/etc/init.d/unifi-gateway start` | `logread -e unifi-gateway` |

Updates are handled by your package manager: `apt upgrade`, `dnf upgrade`, `opkg upgrade`, `apk upgrade`, or `pkg upgrade`.

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `UNIFI_GW_CONFIG` | `conf/unifi-gateway.conf` | Path to config file |
| `UNIFI_GW_LOG_LEVEL` | `DEBUG` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `UNIFI_GW_LOG_FILE` | *(stderr)* | Log to file instead of stderr |
| `UNIFI_ADOPT_URL` | *(none)* | Controller inform URL for automatic adoption on start |
| `UNIFI_ADOPT_KEY` | *(none)* | Auth key for auto-adoption (optional, rarely needed) |

### Config File (`conf/unifi-gateway.conf`)

#### `[global]`

| Key | Default | Description |
|---|---|---|
| `pid_file` | `unifi-gateway.pid` | PID file path for daemon mode |
| `disable_broadcast` | `True` | Disable UDP multicast discovery |

#### `[gateway]`

| Key | Default | Description |
|---|---|---|
| `ports` | *(required)* | JSON list mapping UniFi ports to real interfaces |
| `lan_ip` | *(required)* | LAN IP address |
| `lan_mac` | *(required)* | LAN MAC address |
| `firmware` | `4.4.18.5052168` | Reported firmware version |
| `device` | `UGW3` | Device model string |
| `device_display` | `UniFi-Gateway-3` | Display name |
| `use_aes_gcm` | `False` | Use AES-GCM encryption (set by controller) |
| `hostname` | *(auto-detected)* | Override reported hostname |
| `dhcp_lease_file` | *(auto-detected)* | Path to DHCP lease file |
| `dhcp_lease_format` | `dnsmasq` | Lease format: `dnsmasq`, `isc`, or `kea` |
| `ping_target` | `ping.ubnt.com` | Host for latency measurement |
| `speedtest_file` | `./speedtest.json` | Path to speedtest results JSON |
| `platform` | `UNIFI-GW` | Platform string in discovery broadcasts |

#### `[opnsense]`

Used when `platform = opnsense` (or auto-detected on OPNsense).

| Key | Default | Description |
|---|---|---|
| `url` | `https://127.0.0.1` | webGUI URL including port (env `OPNSENSE_URL`) |
| `api_key` / `api_secret` | *(none)* | API credentials (env `OPNSENSE_API_KEY` / `OPNSENSE_API_SECRET`) |
| `verify_ssl` | `false` | Verify the webGUI certificate |
| `timeout` | `30` | API request timeout in seconds |
| `apply_firewall` | `true` | Apply controller firewall rules and groups |
| `apply_port_forward` | `true` | Apply controller port forwards |
| `apply_dhcp` | `true` | Apply DHCP static mappings (Kea/Dnsmasq) |
| `apply_dns` | `true` | Apply static DNS host records |
| `apply_routes` | `true` | Apply static routes |
| `block_clients` | `true` | Act on block/unblock client requests |
| `allow_reboot` | `false` | Let the controller reboot the firewall |
| `traffic_interval` | `30` | Seconds between per-client traffic samples (`0` disables) |
| `host_active_window` | `300` | Seconds a client seen by host discovery stays listed |
| `state_file` | *(next to config)* | Where blocked clients and the last applied config hash are kept |

#### `[provisioned]`

Populated automatically by the controller after adoption. Do not edit manually.

## Speed Test

The controller can trigger speed tests. Install `speedtest-cli` for this to work:

```bash
pip install speedtest-cli
```

Results are saved to `speedtest.json` and reported in the next inform cycle.

## Architecture

| Module | Purpose |
|---|---|
| `unifi_gateway.py` | Entry point, inform loop, controller response handling, adoption |
| `unifi_protocol.py` | TNBU binary protocol: AES-CBC/GCM encryption, zlib/snappy compression, JSON payload construction |
| `collectors/` | Platform collectors (psutil base, Linux, FreeBSD, OpenWRT, OPNsense, pfSense) |
| `collectors/opnsense_api.py` | Stdlib-only OPNsense REST client |
| `collectors/opnsense_sync.py` | Translates controller `system_cfg` and client blocking into OPNsense objects |
| `tools.py` | Helper functions for building `if_table` and `network_table` structures |
| `tlv.py` | TLV encoding for UDP discovery packets |
| `daemon.py` | Unix daemon (double-fork, PID file) |

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

This project builds upon and was inspired by:

- [stephanlascar/unifi-gateway](https://github.com/stephanlascar/unifi-gateway) — original UniFi Gateway emulator
- [qvr/unifi-gateway](https://github.com/qvr/unifi-gateway) — Python 3 port, FreeBSD support, AES-GCM encryption

Protocol documentation:

- [jk-5/unifi-inform-protocol](https://github.com/jk-5/unifi-inform-protocol)
- [fxkr/unifi-protocol-reverse-engineering](https://github.com/fxkr/unifi-protocol-reverse-engineering)

# AGENTS.md

This file provides guidance to Codex (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python 3 daemon that emulates a Ubiquiti UniFi Gateway (UGW3) to a UniFi Controller. It allows non-Ubiquiti routers (OpenWRT, OPNSense, pfSense, etc.) to report network stats to the UniFi Controller UI.

Inspired by [stephanlascar/unifi-gateway](https://github.com/stephanlascar/unifi-gateway) and [qvr/unifi-gateway](https://github.com/qvr/unifi-gateway).

## Running

```bash
# Install dependencies
pip install -r requirements.txt

# First-time adoption to controller
python unifi_gateway.py set-adopt -s http://your.controller/inform

# Run in foreground (for development/debugging)
python unifi_gateway.py run

# Run as background daemon (Linux only)
python unifi_gateway.py start

# Stop / restart daemon
python unifi_gateway.py stop
python unifi_gateway.py restart

# Docker
docker compose up -d
```

## Architecture

The codebase uses psutil for cross-platform data collection (Linux + FreeBSD). Tests live in `tests/` using pytest.

**Core modules:**

- `unifi_gateway.py` — Entry point and main loop. Subclasses `Daemon`, handles the inform loop (periodic POSTs to the controller), processes controller responses (`noop`, `setparam`, `reboot`, `cmd`, `upgrade`, `setdefault`). Manages adoption workflow and config persistence. Supports graceful shutdown via SIGTERM/SIGINT. Configurable via environment variables.
- `unifi_protocol.py` — Implements the UniFi inform binary protocol. Handles AES-CBC and AES-GCM encryption/decryption, zlib/snappy compression, and builds the JSON inform payload (partial for unadopted, complete for adopted devices; a UXG variant with `port_table`/`mac_table`, `udapi_version` and `include_blocks` support when `device` is a UXG model such as `UXGB`). Uses `MASTER_KEY` for unadopted communication, then switches to device-specific authkey after adoption.
- `collectors/` — Platform-aware data collection package with class hierarchy:
  - `base.py` — `BaseCollector`: cross-platform logic via psutil (interface stats, IPs, MACs, CPU/mem, DHCP lease parsing for dnsmasq/ISC/KEA formats, DNS nameservers, latency, speedtest). Subclasses override `_get_default_gateway()` and `_get_neighbors_raw()`.
  - `linux.py` — `LinuxCollector`: `/proc/net/dev` multicast, `/sys/class/net/` MAC fallback, `/proc/net/route` gateway, `ip neigh` neighbor table.
  - `freebsd.py` — `FreeBSDCollector`: `netstat -rn` gateway, `arp -an` neighbor table.
  - `opnsense.py` — `OPNSenseCollector(FreeBSDCollector)`: OPNsense 26.x REST API integration. Reads interfaces, clients (ARP + hostwatch + ISC/Kea/Dnsmasq leases), per-client traffic (background `traffic/top` sampler), gateway latency, speedtest/ddclient plugins. Implements controller actions (block/unblock/kick client, apply `system_cfg`, reboot, speed test). Falls back to FreeBSD collection when the API is unavailable. Config in `[opnsense]`.
  - `opnsense_api.py` — stdlib-only REST client (Basic auth, unwraps configd JSON-in-JSON responses).
  - `opnsense_sync.py` — translates the controller's EdgeOS `system_cfg` into aliases, filter rules, DNAT, Kea/Dnsmasq reservations, Unbound overrides, routes; plus client blocking. Only touches objects tagged `unifi-gw:` (aliases prefixed `ufg_`); skips controller built-in rules (3000-3999, 6000+).
  - `opnsense_udapi.py` — `UDAPIConfigSync(OPNsenseConfigSync)`: translates a UXG `system_cfg` (`{"udapi": {...}}`) into the same objects, reusing the EdgeOS sync's machinery; fails closed on unrecognized rule fields. `OPNSenseCollector.apply_system_cfg` picks it by the shape of `system_cfg`.
  - `openwrt.py` — `OpenWRTCollector(LinuxCollector)`: ubus/LuCI RPC integration (leases, host hints, conntrack).
  - `pfsense.py` — `PfSenseCollector(FreeBSDCollector)`: pfSense API integration.
  - `__init__.py` — `create_collector(config)` factory with auto-detection (`platform = auto | linux | opnsense | openwrt | pfsense | freebsd`).
- `datacollector.py` — Backward-compatibility shim, delegates to `collectors.create_collector()`.
- `tools.py` — Helper functions for building `if_table` and `network_table` structures that the controller expects, plus conversion utilities (MAC/IP string-to-array, netmask-to-CIDR, uptime via psutil).
- `tlv.py` — TLV (Type-Length-Value) encoding for UDP broadcast discovery messages.
- `daemon.py` — Generic Unix daemon class (double-fork, PID file management).

**Config:** `conf/unifi-gateway.conf` — INI format with `[global]`, `[gateway]`, and `[provisioned]` sections. The `ports` field maps emulated UniFi interface names (`eth0`/`eth1`/`eth2`) to real system interfaces via `realif`. Config is modified at runtime by controller responses and saved back. Optional keys: `hostname`, `dhcp_lease_file`, `dhcp_lease_format`, `ping_target`, `speedtest_file`, `platform`.

**Environment variables:** `UNIFI_GW_CONFIG` (config path), `UNIFI_GW_LOG_LEVEL` (DEBUG/INFO/WARNING/ERROR), `UNIFI_GW_LOG_FILE` (log to file).

**Key protocol detail:** The inform packet format is `TNBU` magic + version + MAC + flags + IV + payload version + payload length + encrypted/compressed JSON payload. Flags indicate encryption type (CBC vs GCM) and compression (zlib vs snappy).

**Packaging:** Most platforms (Debian, RHEL, FreeBSD) ship a PyInstaller binary. OpenWRT packages (`pkg/openwrt/`) ship pure Python source instead, depending on `python3`, `python3-psutil`, and `python3-pycryptodome` from the OpenWRT feeds. This keeps `.ipk`/`.apk` packages tiny for flash-constrained devices. A wrapper at `/usr/bin/unifi-gateway` invokes the Python source at `/usr/lib/unifi-gateway/`. Both `opkg` (pre-25.12) and `apk` (25.12+) formats are built.

**Controller actions:** `BaseCollector` defines no-op hooks (`block_client`, `unblock_client`, `set_blocked_clients`, `kick_client`, `apply_system_cfg`, `reboot`, `run_speedtest`) returning False; platform collectors override them. `unifi_gateway.py` dispatches `cmd`/`setparam`/`reboot` responses to them and records anything a platform returns False for as unhandled.

**Unhandled command log:** `conf/unhandled_commands.json` records controller operations we don't act on (unknown response types, commands, setparam keys, mgmt_cfg keys). This serves as a living TODO for missing features.

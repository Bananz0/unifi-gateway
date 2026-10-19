# UXG emulation: findings and next steps

Status as of 2026-10-19. The working USG (UGW3) emulation with OPNsense
integration is on branch `feat/opnsense-api`. This note records what was
learned while investigating a move to emulating a UniFi Gateway Max
(UXG-class) device, so the work can continue elsewhere.

## Why move off the USG

- UniFi Network 10.6 still adopts and provisions a UGW3. Blocking, port
  forwards, firewall rules, clients and stats all work.
- The legacy `stat/stadpi` and `stat/sitedpi` endpoints return hard-coded
  empty results in 10.6. Earlier tests incorrectly used those endpoints to
  conclude that DPI was unsupported. They cannot validate ingestion.
- The USG is end-of-life. UXG-class gateways (UXG-Lite, Pro, Max, Fiber,
  Enterprise) are the current devices an external controller (Cloud Key,
  self-hosted) adopts. UCG/UDM consoles **cannot** be adopted by another
  controller.

## What the controller expects from a UXG (Network 10.6.106)

From the controller's model table (`com.ubnt.i.g.a.WHAegBJnJlFdoTcfZ`):

| Model | type | features |
|---|---|---|
| `UGW3` (current) | UGW | HAS_CLIENTS |
| `UXG` (UXG-Lite) | UXG | HAS_CLIENTS |
| `UXGB` (UXG-Max) | UXG | SWITCH, HAS_CLIENTS, TRAFFIC_FLOWS_ALLOWED_TRAFFIC |
| `UXGA6AA` (UXG-Fiber) | UXG | SWITCH, HAS_CLIENTS, TRAFFIC_FLOWS_ALLOWED_TRAFFIC, SD_WAN_HUB |
| `UXGPRO` | UXG | SMART_OUTLET, SD_WAN_HUB, HAS_CLIENTS, TRAFFIC_FLOWS_ALLOWED_TRAFFIC |

From the UXG-Max firmware (`UXGB` 5.1.26, public on fw-update.ui.com) and a
live test adoption in a lab controller:

- **Same inform protocol** as the USG: TNBU, AES-CBC/GCM, the same master key.
  `unifi_protocol.encode_inform`/`decode_inform` work unchanged. The device
  daemon is `mcad`.
- **Adoption works.** A probe reporting `model: UXGB`,
  `version: 5.1.26.33914` was shown as "Gateway Max" (type `uxg`, supported)
  and adopted. The production controller refused a second gateway in the same
  site (`api.err.NoSecondGateway`), so testing used a separate lab controller.
- **Config format differs.** `setparam.system_cfg` is
  `{"udapi": {...}, "ubntconf": "..."}`, where `udapi` holds the UniFi OS
  router API tree: `interfaces`, `services`, `system`, `unifi`, `version`,
  `firewall/nat`, `firewall/sets`, `firewall/filter`, `firewall/settings`,
  `routes/static`, `services/radius-profiles`. A UXG port needs a
  UDAPI → OPNsense translator alongside the current EdgeOS one in
  `collectors/opnsense_sync.py`.
- **`blocked_sta`** arrives as a string (empty when nothing is blocked).
- **The controller asks for data blocks:** `noop` responses carry
  `include_blocks: ["ipv4_active_leases", "gw_caps"]`.
- It warns `Skip updating capability ... due to empty udapi_version`, so
  send a `udapi_version` object.
- **Clients** for a UXG are not read from `network_table[].host_table` (the
  USG way). The UXG processor (`com.ubnt.service.devmgr.frjFRbSrDCaRuGKgFdo`)
  reads `port_table[].mac_table`, `ipv4_active_leases`, `network_table`,
  `if_table`, `udapi_version`, `uplink`, `speedtest-status`, `ddns-status`,
  `routes`, `vpn`, `pfor-stats`, `upnp-stats` and others.
- **DPI, now verified in the lab:** `mcad` sends `dpi_stats` (underscore) and `fingerprints` in the
  inform. The controller handles `dpi_stats` in
  `com.ubnt.net.i.e.HZHXJRnEDktLxXGDhr` /
  `com.ubnt.service.devmgr.d.BXbf` (entries
  `{mac|ip, initialized, stats: [{app, cat, rxBytes, txBytes, countries?}]}`),
  gated by the site DPI setting. Snake-case byte counters silently produce
  zero deltas. **A second lab site confirmed that UGW3 also ingests these
  modern counters:** migration to UXG is not required for this ingestion path.
  Both experiments' saved synthetic reports are in
  [network-10.6-lab-dpi.json](evidence/network-10.6-lab-dpi.json).
  The camel-case correction was deployed to the existing production UGW3
  emulator. At 23:25 EAT, its controller's saved five-minute user reports
  contained non-zero DPI for 8 real clients, totaling 582560 bytes in the
  first partial reporting window. No production model change was needed.
  The UXG lab now discovers the client using
  `port_table[].mac_table` + `ipv4_active_leases`; each port also needs its
  MAC, num_port, and interface name. The corrected test produced a saved
  five-minute user report with YouTube (112_4) rx=4000000, tx=200000 and
  DNS (61_9) rx=8000, tx=4000. Fetch with POST
  `/api/s/default/stat/report/5minutes.user`, attrs including `time`, `user`,
  and `dpi`, and start/end as Unix milliseconds. These are synthetic lab
  counters, not real client traffic. UI rendering has not yet been verified.
- **Flows remain unverified on a Cloud Key.** The device's
  `unifi-mq-broker` pushes flows to a RabbitMQ the controller provides
  (`messageBroker.rabbitMq` host/port/user/password/TLS); the controller
  consumes queue `unifi_flow_queue`. Cloud Key Gen2+ has no RabbitMQ
  installed in the observed configuration. That observation alone does not
  prove that every UXG/Cloud Key configuration lacks flow support; earlier
  statements claiming impossibility were too strong. Check provisioning and
  feature negotiation before drawing that conclusion.
  The configuration factory additionally checks the Java property
  `unifi.rmq.enabled` and the device's `udapiSupportsMessageBroker()` result;
  external broker provisioning expects a device certificate chain. The
  environment service defaults its broker TLS port to 5671 (`rmq.tls_port`).
  This is a lead for further isolated testing, not a verified flow integration.

## Next steps

### Additional telemetry investigation (2026-10-19)

The UXG inform processor also accepts a `connections` list independently of the
RabbitMQ ingestion path. Its parser reads timestamp, hostnames, source and
destination IP/port/protocol, interfaces, country/region and byte/packet stats.
This path converts entries into allowed conntrack events; it cannot faithfully
carry Zenarmor blocked decisions or application classifications in those fields.
A lab inform containing a synthetic connection received a normal controller
response, but the traffic-flows API remained empty at the initial check.
Receiving an inform response therefore does not establish flow persistence or
UI support. Production does not emit experimental connections.

Production enrichment combines Zenarmor application/country counters with
persistent Netflow client accounting. It preserves the UGW3 identity while
UDAPI provisioning and full flow ingestion remain under investigation.

1. Verify the visible application-usage UI against the populated five-minute
   user reports. Do not use the retired stadpi/sitedpi endpoints as evidence.
   The real UGW3 emulator received the camel-case conversion on 2026-10-19;
   real report ingestion is confirmed. Visual lab inspection was blocked by
   its self-signed TLS certificate.
2. Map the full UDAPI `system_cfg` schema (the probe logs every response to
   `responses.jsonl`) and write a UDAPI → OPNsense translator.
3. Add a UXG payload builder next to `_create_complete_inform`, selected by
   `device = UXGB` in config.
4. Migrate production: forget the USG, adopt the UXG identity (needs the
   controller to accept a model change, or a re-adopt with a new MAC).
   Do this only after UDAPI provisioning parity has been tested. The current
   EdgeOS synchronizer explicitly rejects UDAPI so it cannot delete managed
   rules by treating an unfamiliar format as an empty configuration.

## Lab setup used

UniFi Network 10.6.106 in Docker (`lscr.io/linuxserver/unifi-network-application:10.6.106`
plus `mongo:7.0`). Setup was completed via `/api/cmd/sitemgr add-default-admin`,
`/api/cmd/system set-installed`, then the probe was adopted with
`/api/s/default/cmd/devmgr {"cmd":"adopt","mac":...}`.

```
PROBE_URL=http://<lab-controller>:18080/inform python tools/uxg_probe.py 2
# adopt in the lab controller, then:
PROBE_URL=... python tools/uxg_probe.py 4
PROBE_URL=... python tools/uxg_probe_dpi_test.py
```

State and raw response logs default to ignored `tools/.uxg-probe/`. Override
with `PROBE_STATE_DIR` to resume a previously adopted probe. Logs can contain
device authentication keys and provisioning secrets; never commit them.

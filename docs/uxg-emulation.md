# UXG emulation: findings and next steps

Status as of 2026-10-19. The working USG (UGW3) emulation with OPNsense
integration is on branch `feat/opnsense-api`; UXG mode is on `feat/uxg-mode`. This note records what was
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
- **Flows work through the inform, without RabbitMQ (verified 2026-10-20 in
  production, Cloud Key, Network 10.6.106).** The UXG processor
  (`frjFRbSrDCaRuGKgFdo`) passes the inform's `connections` list to
  `trafficFlowConntrackEventsProcessor` on every inform, gated only by the
  system property `TRAFFIC_FLOWS_ENABLED` (default true). Each entry:
  `{timestamp: "YYYY-MM-DDTHH:MM:SS.sssZ", ip: {saddr, sport, daddr, dport,
  protocol: <IANA number>, version}, hostnames: [...], in: <udapi if>,
  out: <udapi if>, region: {src, dst}, stats: {rxBytes, rxPackets, txBytes,
  txPackets}}`. Flows need IPs, a protocol and (for TCP/UDP) ports. They are
  stored as action=allowed with policy CONNTRACK in `ace_audit.traffic_flow`,
  and the controller resolves the client MAC, the networks and the domain.
  `POST /v2/api/site/default/traffic-flows` returns them. The RabbitMQ path
  (`unifi-mq-broker` → `unifi_flow_queue`) is what a real UXG uses for
  blocked/IPS events; this emulator doesn't need it.

## UXG mode (branch `feat/uxg-mode`)

Set `device = UXGB` (or `UXG`, `UXGPRO`, `UXGA6AA`) in `[gateway]`, with
`device_display = UniFi Gateway Max` and a UXG firmware such as
`5.1.26.33914`. Any other model keeps the unchanged USG code paths.

### Implemented

- **Inform payload** (`unifi_protocol._create_uxg_inform`, chosen by
  `create_inform` from the model): identity fields as in the lab probe plus
  `udapi_version`, `port_table` (one entry per configured port, with
  `port_idx`, `mac`, `num_port`, `ifname`, counters, `is_uplink` on the WAN and
  a `mac_table` built from the collector's host table, assigned to ports by
  `realif` like `network_table` does for the USG), `ipv4_active_leases`
  (with `network` and, for epoch expiries, `expiration`), `if_table`,
  `network_table` (no `host_table`; LAN entries renamed to their UDAPI
  interface: a port's `network` key, else `br0` for the primary LAN),
  `uplink`, `routes`, `speedtest-status`, `ddns-status`, `system-stats`, and
  `dpi_stats` in the camel-case schema only. Ports may carry `"network"`
  and `"vlan"` keys for additional LANs. USG output is byte-identical.
- **include_blocks**: each `noop`'s list is sent with the next inform only.
  `ipv4_active_leases` is always sent; `gw_caps` only when requested.
- **blocked_sta** as a string: empty (nothing blocked, so everyone is
  unblocked), comma/space/newline separated, or a JSON list. Lists still work.
- **system_cfg as an object** is persisted as JSON (it used to be stored as a
  Python repr, which could not be re-applied after a restart).
- **UDAPI translator** (`collectors/opnsense_udapi.py`, `UDAPIConfigSync`),
  picked by `OPNSenseCollector.apply_system_cfg` when `system_cfg` has a
  `udapi` object. It subclasses the EdgeOS sync and reuses `sync_items`,
  tags, alias naming, client blocking and the DHCP/DNS/route backends:
  - chains are bound to interfaces by following jump rules from `INPUT`
    (local) and `FORWARD` (`FORWARD_IN` with `inInterface` = in,
    `FORWARD_OUT` with `outInterface` = out);
  - UDAPI interface ids resolve through the `ports` map, then by subnet
    against OPNsense's interfaces (so `br0` finds `lan`), then through bridge
    members / VLAN / PPPoE parents;
  - rule ids 30000-39999 and 60000+ are controller built-ins (EdgeOS ranges
    scaled by ten, matching the capture); `[OPNsense]` mirrors are skipped,
    also behind the controller's `[LAN_IN]`-style description prefix;
  - targets ACCEPT/RETURN/DROP/REJECT become pass/block/reject; DNAT becomes a
    port forward; MASQUERADE/SNAT and guest-portal DNAT are skipped;
  - only sets a translated rule references become `ufg_` aliases;
  - DHCP `staticLeases`, DNS `hostRecords` (minus setup.ui.com, wildcards and
    the gateway's own name) and `routes/static` are re-expressed in the
    EdgeOS shape and handed to the existing, live-tested backends, so their
    tags (`dhcp-*`, `dns-*`, `route-*`) match what the USG mode created.

  It fails closed because the user-rule schema is inferred: a rule with an
  unknown field, a state-only match, a combined address+set match, mixed
  IPv4/IPv6 literals or an unmapped interface is skipped with a warning and
  its previously created object is kept, never broadened or deleted. A
  section absent from the tree is left alone; a present, empty one is
  authoritative. Rule keys are `ufw-<chain>-<id>-<if>` / `upf-<chain>-<id>-<if>`,
  so the first UXG push replaces the USG-era `fw-*`/`pf-*` objects.
- Tests: `tests/test_opnsense_udapi.py` (real capture + the synthetic
  `tests/fixtures/uxg_system_cfg_synthetic.json`), `tests/test_protocol_uxg.py`,
  and additions to the gateway/collector tests.

### Lab results (2026-10-20, Network 10.6.106)

The daemon ran with `device = UXGB` against a lab controller, reading the live
OPNsense and logging every OPNsense write instead of sending it
(`tests/fixtures/uxg_setparam_10.6.106_objects.json` is the redacted config
the controller pushed).

- **Inform accepted.** 27-29 real clients from `port_table`/leases; WAN, WWW
  and LAN health ok; latency, speed-test and CPU/memory shown. The configured
  `lan_mac` must be the payload MAC: the controller answers HTTP 400
  "mac inconsistent in header and payload" otherwise. Ports use front-panel
  numbering (eth0-3 = ports 1-4, eth4 = port 5); with config-order numbering
  the WAN landed on port 1 and the WAN chains never rendered.
- **UDAPI user objects, as really sent:** rule ids from 20000;
  `connectionState` (singular), `icmpType`/`icmpv6Type`; port forwards are
  flat `firewall/nat` entries with their own `chain` (`PREROUTING` DNAT,
  `POSTROUTING` hairpin MASQUERADE named `PortForward MASQUERADE [name]`), the
  WAN given as the virtual set `ADDRv4_eth4` in `destination.sets`.
  `ADDRv4_<if>`/`NETv4_<if>` are never declared in `firewall/sets`; they map
  to OPNsense `<if>ip` / `<if>`. WAN chains exist only once a WAN network is
  assigned to eth4. Static leases carry no name: the reservation is named
  from a DNS record for the same address, else `host-<mac>`.
- **Translator:** zero warnings on the real config: LAN_IN/LAN_LOCAL block
  rules, WAN_LOCAL ICMP rule, both port forwards (with source restriction
  and port range), DNS records, static route and reservation. Mirrored
  `[OPNsense]` objects, controller built-ins and hairpin NAT are skipped.
- **Blocking:** `block-sta`/`unblock-sta` update the `ufg_blocked` alias and
  kill the client's states; the controller also pushes the blocked set in
  `system_cfg`, which becomes the `ufg_blocked_clients_*` alias and rules.
  `kick-sta` for a wired client answers `api.err.UnknownStation` on the
  controller itself (kicking is an AP function).
- **Speed test:** dispatched; OPNsense's plugin answering `version: none`
  (no backend installed) is now reported as unhandled so the gateway falls
  back to its own test.
- **DPI with real traffic:** with a snapshot of the router's Zenarmor
  database refreshed every two minutes, the first five-minute window held
  per-app DPI for 10 real clients in `stat/report/5minutes.user`
  (e.g. DNS `61_9`, `109_9`, unidentified).
- **Mirror on a UXG site:** rule numbers start at 20000 (else
  `FirewallRuleIndexOutOfRange`) and skip indexes used by rules made in UniFi
  (else `FirewallRuleIndexExisted`).
- **Production migrated 2026-10-20 03:29** (`tools/migrate_usg_to_uxg.py`):
  the USG was forgotten and the same MAC re-adopted as a UXG-Max. The controller
  remembered that MAC used AES-GCM and rejected unadopted CBC informs as a
  downgrade, so unadopted informs now follow `use_aes_gcm`. The first push
  applied cleanly; mirrored rules were renumbered to 20000+; DPI reports
  continued (9 clients in the first window).
- Still open: `gw_caps` schema (`{}` placeholder) and the zone-based
  firewall layout.

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
   `responses.jsonl`) and replace the synthetic fixture with a real capture;
   the translator and UXG payload exist (see above) but are only unit-tested.
3. Migrate production: forget the USG, adopt the UXG identity (needs the
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

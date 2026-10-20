# Full OPNsense translation target

Requested 2026-10-20: every UniFi gateway feature with an OPNsense equivalent
should control the actual OPNsense service and report its observed state.
Adoption, accepting an inform, and passing unit tests do not establish parity.
This is an implementation target; the incomplete entries below are not promises
of current support. Baseline: `feat/uxg-lab-fixes` at `f61a875`.

| Area | Current implementation / gap | Required completion evidence |
|---|---|---|
| Physical ports | Discovery deployed, preserving existing mappings; the missing disabled WAN2 is reported on port 4. UXGB capacity is five. VLANs, bridges, radios and tunnels are separate resources. | More NIC/driver/model combinations and restart coverage remain to be validated. |
| Interfaces / VLAN IDs | Address/counter telemetry exists; VLAN creation, parent assignment, tagging, bridge membership and interface writes are missing. | Create/edit/remove tagged network in lab, verify packet tags, DHCP and isolation; protect management access. |
| IPv4 | Selected firewall, DNAT, DNS records, reservations and routes translate. Full address, gateway, DHCP-client, MTU/MSS and policy routing configuration is missing. | Compare actual interface/routing/filter state with the requested values; connectivity and rollback tests. |
| IPv6 | Selected rule/route handling exists, not a complete IPv6 stack translator. | Static/SLAAC/DHCPv6 WAN, prefix delegation, LAN prefixes, router advertisements, DHCPv6 and DNS, ICMPv6, firewall and routes tested with real clients. |
| DHCP server | Dnsmasq IPv4 pools, lease duration, subnet mask, domain, router/DNS options and scoped cleanup implemented; real OPNsense API lifecycle tested, alongside existing reservations. Unmanaged pool/option conflicts are rejected. Production deployment and real-client validation pending. | Exclusions, NTP, PXE/TFTP, custom options and IPv6 as supported by the actual UniFi schema; verify client leases/options. Keep Dnsmasq as the production backend. |
| DHCP relay | DHCRelay destinations and relay lifecycle implemented in source, including IPv4/IPv6 address-family validation. Self-relay declarations are ignored; unmanaged relays and competing local pools are protected. | Real API and DHCPv4/DHCPv6 packet tests; relay-agent options and role transitions remain incomplete. |
| VPN | Missing translation for tunnel configuration and status. Existing OPNsense OpenVPN configuration is independent. | WireGuard first, then OpenVPN/IPsec mappings where controller schemas exist; peers, keys/certs, routes, DNS, firewall/NAT, handshakes and client data transfer. Teleport/Site Magic are not assumed equivalent. |
| Smart Queues / QoS | Missing. | Map rates/directions/flow isolation to OPNsense traffic shaping; test upload/download throughput, loaded latency and queue counters. Report differences in scheduling semantics. |
| Ethernet flow control | Missing. Distinct from connection Traffic Flows. | Translate supported pause-frame settings through the actual NIC/driver backend and read them back; do not simulate hardware support. |
| Speedtest | Background command and result reporting exist. This branch fixes decimal Mbps and newest-result selection. | Test requested from UniFi completes, results arrive at controller, informs continue, errors do not reuse old results as a new success. |
| MAC cloning | Missing. | Apply/read back interface spoofed MAC; maintain a separate stable emulator identity; reconnect WAN and verify lease/routing recovery. |
| UPnP/NAT-PMP | Missing. | Installed backend, permitted interfaces/ACLs, live lease list, create/delete/expiry and firewall behavior. No automatic broad exposure. |
| Dynamic DNS | Account status reads exist; account/provider configuration is missing. | Translate supported providers, credentials and check-IP methods, trigger update and verify published IPv4/IPv6 record and error status. |
| WAN failover / balancing | Missing. | Gateways/groups, health checks, policy routing, failover and recovery on isolated WANs. |
| Firewall / NAT | Substantial UDAPI translator exists, with skipped-match protection. Not every policy type is supported. | Both address families, local/forward direction, sets, states, zones, hairpin/SNAT and policy restrictions; packet-level permit/deny tests. |
| Application blocking | Zenarmor DPI telemetry is read-only and does not enforce UniFi app blocks. Exact-name ID resolution and explicit Zenarmor policy app-delta writes with readback now exist as primitives; automatic UniFi rule/scope translation remains missing. | Capture `v2/firewall-app-blocks`, traffic rules and app-aware firewall policies; preserve scope, schedules, ownership and manual app controls; test actual denied traffic and unblock recovery. |
| DNS / mDNS / services | Host records exist; full resolver/forwarder/mDNS/NTP/LLDP configuration is incomplete. | Service-specific writes, reloads and observed behavior; preserve current AdGuard/Unbound/Dnsmasq chain. |
| Insights / Flows | DPI, country accounting, Netflow totals, allowed connections and firewall triggers exist in the baseline. | Counter reconciliation, attribution, restarts, retention, interface mapping and UI/API validation. |
| Internet Quality | dpinger latency/loss now populate `uptime_stats`; WAN Insights overview and latency history confirmed on production Network 10.6. | Outage/recovery packet-level exercise and additional WANs; duration starts with actual collector observations. No historical backfill. |
| IDS/IPS / region / ad blocking | Implemented with limits; Suricata interface changes are constrained around inline/netmap conflicts. | Verify requested enforcement, not only enabled rulesets or mirrored configuration. |

Each translator needs captured controller schema, version-specific OPNsense API
models, validation before writes, scoped ownership, rollback, service reload,
readback and an end-to-end test. Unsupported fields must remain explicit.
`untranslated_settings` in provisioning summaries reports paths only, avoiding
credential values. `tools/opnsense_audit.py` inventories the live router with
GET requests and proposes mappings without writing configuration.

## Implementation order

1. Inventory, truthful coverage reporting, physical port discovery, speedtest
   correctness and stable telemetry.
2. Interfaces/VLANs and complete Dnsmasq DHCP/relay behavior, with management
   connectivity and configuration ownership protected.
3. IPv4/IPv6 addressing and routing, DDNS, MAC cloning and WAN failover.
4. WireGuard/OpenVPN/IPsec, UPnP/NAT-PMP, shaping and supported flow control.
5. Remaining firewall/service features and a full controller-to-client test matrix.

No checkbox is complete merely because an equivalent OPNsense service exists.
Some controls need a small local OPNsense extension when REST does not expose
the required operation. No direct config.xml edits should bypass validation.

## DHCP API validation, 2026-10-20

An isolated OPNsense 26.7 nano VM on phastos, with QEMU user networking and a
management port bound to localhost, exercised the new translators against real
REST endpoints. Its credentials and configuration are separate from production.
The official compressed image SHA256 was verified before boot.

On a temporary VLAN assignment, pool creation read back the requested range,
255.255.255.0 subnet mask, 7200-second lease, guest.home domain, router option 3
and DNS option 6. Repeating the same request issued zero POSTs. Cleanup removed
only the managed pool/options and retained both factory LAN ranges. Relay
destination and relay creation, readback, zero-write repeat and ordered cleanup
also passed. Relay service status was red on the inactive test interface, so
these checks establish API lifecycle correctness, not packet forwarding or
successful client leases. IPv6 relay addresses have validation tests, not a
packet-level IPv6 result.

Existing production LAN pools are intentionally not adopted implicitly. A
conflicting manual pool or router/DNS option rejects controller pool writes.
The controller's local-IP-to-itself relay representation creates no relay.
Unsupported server fields reject the pool section rather than disappearing.
DHCP role transitions with an existing local pool are rejected explicitly.
Multi-object API updates are not transactional; rollback and recovery after a
mid-update API failure still need integration coverage.

The base 26.7 assignment API exposes fewer interface fields than the installed
production 26.7.7 model. In the VM, a newly created VLAN also required the
interface inventory cache to refresh before assignment validation accepted it.
An assignment add response UUID differed from the subsequent stable opt1
identifier. Future interface provisioning must read back the assignment and
handle version/cache differences before dependent DHCP/firewall writes.

## Instagram blocking investigation, 2026-10-20

Live controller GETs returned no simple app blocks (`v2/firewall-app-blocks`),
no traffic rules, and no non-mirrored user firewall policies in its sole Default
site. The stored UDAPI payload contained no application matches. Zenarmor's
active Default policy had no app controls. Its installed application catalog
recognized Instagram as 10745, whereas UniFi's catalog uses 1573022. These IDs
are independent and must be mapped rather than copied. This establishes that
Instagram was not configured to be blocked; it does not explain why the user's
attempt did not leave a saved controller rule.

The new API primitive uses the installed plugin's PUT `appControls` operation,
updates explicit apps only, checks policy identity when requested, and reads the
result back. Unit tests cover exact-name mapping, ambiguity rejection, manual
block preservation, idempotence and failed/mismatched backend updates. It is not
connected to automatic controller-rule enforcement or deployed to production.
Device/network scope must come from the actual saved UniFi rule before applying
a block. Additional Zenarmor policy activation is subject to the installed
license checks; the bridge must not bypass them or widen a device-only block
into the Default policy.

## Throughput and quality verification, 2026-10-20

The internal collector's `rx_bps`/`tx_bps` names mean bytes/second. UXG wire
`rx_rate`/`tx_rate` mean bits/second, whereas `rx_bytes-r`/`tx_bytes-r`
mean bytes/second. Network 10.6 divides the rate fields by eight when updating
WAN statistics. Sending identical values in both fields underreported WAN
throughput eightfold. The adapter now multiplies only the bit-rate fields by
eight; counters and directions are unchanged. Live controller readback confirmed
`wan1.rx_rate / 8 == wan1["rx_bytes-r"]` with the corrected actual byte rate.

Internet Quality requires `uptime_stats.WAN.alerting_monitors` rather than just
the uplink's legacy `latency`. The adapter reads the configured gateway monitor,
reports `latency_average` in milliseconds and `availability` as the integer
percentage 100 minus dpinger loss, and includes the same target in `monitors`.
Missing measurements, disabled monitoring, invalid targets and stale API reads
are omitted. Continuous up/down durations are based on observations only and
reset across missing data, long gaps or monitor changes.

Production `/v2/api/site/default/wan/WAN/insights/overview` returned actual
latency, availability and monitor readings after deployment. The corresponding
`insights/history?period=HOUR` contained new average/max latency samples; older
periods still had timestamps without quality values. This verifies ingestion
and the UI's data source; it is not a visual browser validation.

The rollout also exposed a controller-mirroring error: firewall-rule POST
responses lacked object identifiers. These are now isolated and reported as
rejections, so they cannot abort reservation/route/profile mirroring. Full
firewall API compatibility remains incomplete and is not counted as fixed by
making those errors visible.

A production controller-triggered speedtest completed at 21.03 Mbps down and
17.46 Mbps up. The installed speedtest-cli 2.1.3 reported 1800000 ms latency:
its source inserts 3600 seconds per failed HTTP latency probe, so three failed
probes produce `(3600 * 3 / 6) * 1000`, not an RTT measurement. The adapter
rejects these sentinel-contaminated latency values while retaining measured
throughput; `status_ping` remains incomplete. Native CLI fallback uses HTTPS
with `--secure`. The OPNsense plugin's server-selection/probing behavior is
separate and is not claimed repaired by this validation.

The plugin's `showrecent` date preserves the runner's UTC wall-clock text but
drops its timezone suffix. The old adapter interpreted that text as local time,
shifting the UniFi result three hours on the EAT router. It now treats a naive
plugin date as UTC and honors explicit timezone offsets. This corrects the
UniFi timestamp; the third-party plugin's own CSV storage is not rewritten.

## Individual client speeds, 2026-10-20

Network 10.6's UXG client path derives client rates from cumulative counter
deltas; adding a rate field to a MAC-table row alone does not fix this. Netflow
exports arrive in batches, so forwarding an identical total on each ten-second
inform produced zero rates between batches. `ClientTraffic` now publishes each
new confirmed batch gradually over 30-120 seconds (at least the configured
traffic sampling interval). Publications never exceed the confirmed budget and
eventually converge to it. They do not integrate iftop estimates into accounting.

The source Netflow totals remain unchanged. Separate private publication state
preserves released/pending budgets over restart, protects against source
rollback/replay and explicitly rebaselines source epoch changes. The first
publication epoch starts at zero rather than replaying old traffic. UXG MAC-table
bytes/packets are sent in gateway perspective because the controller reverses
them before applying client deltas. Other collectors' wire behavior is unchanged.

These are delayed per-client average rates, including exporter delay and the
publication window. They are not instantaneous radio speeds, Wi-Fi link rates,
or traffic switched entirely within the LAN without crossing the gateway.

Production client API readback showed nonzero rates for the iPhone and other
active clients after rollout (19 of 28 in one snapshot). The zero-rate audit
separated clients with no new confirmed traffic from MAC-only topology entries
with no IP/gateway binding. Such entries cannot receive invented per-IP Internet
accounting. A later snapshot identified two such MAC-only entries; client counts
change as discovery updates. The UI itself was not visually verified.

## Later: OpenWrt AP emulation

This is a separate daemon role per AP, with its own identity/adoption and radio
capabilities. It would translate UniFi WLAN provisioning to UCI/netifd/hostapd,
and report actual radios, BSSIDs, stations, signal, traffic and association events.
SSID/security, VLANs, channel/power, guest policy and 802.11r/k/v require separate
translation and tests. hostapd/usteer provide useful control/status primitives;
they do not themselves implement UniFi adoption or its configuration protocol.
Clients ultimately decide when to roam; an emulator cannot guarantee a roaming
decision or advertise hardware/radio features the AP does not implement.

OPNsense wireless would need a separate FreeBSD wireless backend and hardware
support assessment. Gateway emulation alone does not turn it into an adopted AP.
Keep this theoretical until gateway parity is substantially implemented.

Reference APIs:
- https://docs.opnsense.org/development/api/core/interfaces.html
- https://docs.opnsense.org/development/api/core/dnsmasq.html
- https://docs.opnsense.org/development/api/core/dhcrelay.html
- https://docs.opnsense.org/development/api/core/trafficshaper.html
- https://docs.opnsense.org/development/api/plugins/dyndns.html
- https://openwrt.org/docs/guide-user/network/wifi/usteer

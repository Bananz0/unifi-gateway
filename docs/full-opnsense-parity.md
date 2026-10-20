# Full OPNsense translation target

Requested 2026-10-20: every UniFi gateway feature with an OPNsense equivalent
should control the actual OPNsense service and report its observed state.
Adoption, accepting an inform, and passing unit tests do not establish parity.
This is an implementation target; the incomplete entries below are not promises
of current support. Baseline: `feat/uxg-lab-fixes` at `f61a875`.

| Area | Current implementation / gap | Required completion evidence |
|---|---|---|
| Physical ports | Discovery deployed, preserving existing mappings; the missing disabled WAN2 is reported on port 4. UXGB capacity is five. VLANs, bridges, radios and tunnels are separate resources. | More NIC/driver/model combinations and restart coverage remain to be validated. |
| Interfaces / VLAN IDs | Owned LAN VLAN creation, parent resolution, stable optN assignment, MTU, address writes/readback, rollback and retirement by disabling are implemented in source. Single-member bridge wrappers collapse onto the VLAN; an unchanged native LAN is reused. Lab tagged DHCP lease verified. Not deployed to production. | Multi-port bridge/switch configuration, native-interface edits, safe assignment deletion, full controller captures, firewall defaults and Internet-access validation. |
| IPv4 | Selected firewall, DNAT, DNS records, reservations and routes translate. Owned LAN VLANs now support static/DHCP-client address modes and MTU. Primary WAN/LAN address/gateway/client writes, MSS and full policy routing remain missing. | Compare actual interface/routing/filter state with requested values; full connectivity and recovery tests. |
| IPv6 | Owned VLAN static IPv6 and explicit SLAAC mode writes exist alongside selected rule/route handling. Static address confirmed in the lab kernel. This is not a complete IPv6 stack translator. | DHCPv6 WAN, prefix delegation, LAN prefixes, router advertisements, DHCPv6 and DNS, ICMPv6, firewall and routes tested with real clients. |
| DHCP server | Dnsmasq IPv4 pools, lease duration, subnet mask, domain, router/DNS options, managed listener expansion and scoped cleanup implemented. Real isolated VLAN client received the requested lease/options. Unmanaged conflicts are rejected. Production deployment pending. | Exclusions, NTP, PXE/TFTP, custom options and IPv6 as supported by the actual UniFi schema; controller-driven network defaults and client reachability. Keep Dnsmasq as the production backend. |
| DHCP relay | DHCRelay destinations, scoped lifecycle and ordered owned server/relay transitions implemented in source, including IPv4/IPv6 address-family validation. Self-relay declarations are ignored; unmanaged services are protected. Real API transitions and running service checks passed. | DHCPv4/DHCPv6 relay packet tests and relay-agent options remain incomplete. Mixed IPv4 roles require strict Dnsmasq interface binding. |
| VPN | WireGuard server/peer planning now follows controller serializer fields; direct isolated API application passed real dual-stack tunnel and peer-prefix tests. No provisioning integration or controller VPN status yet. Existing OPNsense OpenVPN configuration is independent. | Complete WireGuard lifecycle, routing, DNS, firewall/NAT, listen binding and status; then OpenVPN/IPsec mappings. Teleport/Site Magic are not assumed equivalent. |
| Smart Queues / QoS | Missing. | Map rates/directions/flow isolation to OPNsense traffic shaping; test upload/download throughput, loaded latency and queue counters. Report differences in scheduling semantics. |
| Ethernet flow control | Missing. Distinct from connection Traffic Flows. | Translate supported pause-frame settings through the actual NIC/driver backend and read them back; do not simulate hardware support. |
| Speedtest | Background command and result reporting exist. This branch fixes decimal Mbps and newest-result selection. | Test requested from UniFi completes, results arrive at controller, informs continue, errors do not reuse old results as a new success. |
| MAC cloning | Missing. | Apply/read back interface spoofed MAC; maintain a separate stable emulator identity; reconnect WAN and verify lease/routing recovery. |
| UPnP/NAT-PMP | Missing. | Installed backend, permitted interfaces/ACLs, live lease list, create/delete/expiry and firewall behavior. No automatic broad exposure. |
| Dynamic DNS | Account status reads exist; account/provider configuration is missing. | Translate supported providers, credentials and check-IP methods, trigger update and verify published IPv4/IPv6 record and error status. |
| WAN failover / balancing | Missing. | Gateways/groups, health checks, policy routing, failover and recovery on isolated WANs. |
| Firewall / NAT | Substantial UDAPI translator exists, with skipped-match protection. Not every policy type is supported. | Both address families, local/forward direction, sets, states, zones, hairpin/SNAT and policy restrictions; packet-level permit/deny tests. |
| Application blocking | Simple app-ID blocks now reconcile via a separate worker into tagged Zenarmor policies for MACs or IPv4 subnets, with ALWAYS schedules. Configure-disabled/readback/activate, ownership, cleanup, inheritance guards and rejection backoff are implemented. Installed API accepted Instagram and a test MAC but rejected scoped activation with `Upgrade to premium`. | Successful licensed activation and actual denied traffic/unblock recovery; categories, schedules, mixed/overlapping scopes, IPv6 interface scopes, custom-policy inheritance and app-aware traffic/firewall-policy sources remain incomplete. |
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
Owned DHCP server/relay role transitions now preflight both roles and stop the
old role before starting the new one. Manual conflicts remain protected.
Multi-object API updates are not transactional; failed operations converge on
retry, with a temporary service interruption rather than simultaneous roles.
Automatic rollback to the old role is not implemented.

The isolated 26.7.7 package VM exercised server -> relay -> server -> removal,
with Dnsmasq running throughout, an active relay reporting green, both factory
LAN ranges retained, and zero writes for identical repeated requests. This is
service/API evidence; a DHCP lease through the relay remains unverified.
The first experiment exposed an orphan process: OPNsense reconfigure stops only
relay UUIDs still in its model. Retirement now disables and applies the relay
before deleting its record or destination. Merely accepting the API's success
response was insufficient: Dnsmasq could fail to bind while returning success.
The coordinator now verifies its running status and retains failed service
applies for retry, including writes whose response was lost. The first
reconciliation after daemon restart reapplies saved service configuration.

Mixed Dnsmasq IPv4 server and relay roles require existing strict interface
binding; requests without it are rejected before writes. This global setting is
not changed implicitly. A separate real VM check confirmed Dnsmasq could restart
while a relay was active with strict binding enabled. See the
[OPNsense DHCRelay documentation](https://docs.opnsense.org/manual/dhcrelay.html).
These changes remain source/lab only and are not deployed to production.

The base 26.7 assignment API exposes fewer interface fields than the installed
production 26.7.7 model. In the VM, a newly created VLAN also required the
interface inventory cache to refresh before assignment validation accepted it.
An assignment add response UUID differed from the subsequent stable opt1
identifier. Future interface provisioning must read back the assignment and
handle version/cache differences before dependent DHCP/firewall writes.

## VLAN, lease and rollback validation, 2026-10-20

The isolated nano VM's `opnsense` package was upgraded from 26.7 to 26.7.7 to
match the production interface API model. This does not claim a full kernel/base
system upgrade. New owned VLAN 208 read back as a stable opt2 assignment with
IPv4 10.208.0.1/24, IPv6 fd00:208::1/64 and MTU 1500. Kernel `ifconfig` confirmed
both addresses, VLAN ID 208, 802.1Q and the parent vtnet1. A second identical
provisioning issued zero POSTs. An edit to 10.208.0.254/24 and MTU 1400 applied
and was restored.

A separate virtual epair trunk and VNET jail exercised VLAN 209 without any
connection to production LANs. The translated Dnsmasq server added only its
managed opt4 listener while retaining LAN and DNS port 53053. The client completed
DISCOVER/OFFER/REQUEST/ACK and received 10.209.0.37/24, router 10.209.0.1,
DNS 1.1.1.1, guest.home and a 7200-second lease. A 748-byte pcap contains the
client DISCOVER and REQUEST frames with explicit 802.1Q VLAN 209 tags. The client
log provides the OFFER/ACK evidence; the pcap does not contain those responses.
An adjacent VLAN 210 client received no offer during an eight-second test.
This is a bounded DHCP segregation test, not a complete firewall isolation matrix.

Injecting an assignment-apply failure exposed a vendor pending-edit behavior:
writing the old values back can leave the newer todo entry intact when those
old values equal the committed configuration. Rollback now first stages a
distinct disabled IPv6 mode, verifies it, applies while disabled, then restores
and verifies the original profile. No temporary global IPv6 address is enabled.
The repeated real API test restored VLAN 208, IPv4/IPv6, MTU and enabled state,
and `/interfaces/assignment/pending` returned `ok`. A regression fake models
the separate committed/todo state rather than assuming immediate API writes.

Removing managed pools before retirement disabled only the owned opt2/opt4
interfaces; the native LAN remained enabled at 192.168.1.1/24. Assignments and
VLAN definitions are retained, because vendor assignment deletion also removes
legacy firewall references without respecting bridge ownership tags. Safe
reference auditing/deletion remains incomplete. Existing unrelated pending
interface changes prevent global apply. Transient provisioning errors now retain
the latest configuration for a serialized retry instead of caching its hash as
success. New controller requests supersede older pending requests.

Evidence is retained on phastos under
`/home/glenm/unifi-opnsense-lab/evidence/`: `vlan209.pcap`, `dhcp209.json`,
`interface208.txt`, `rollback208.json`, and `retirement.json`. These contain lab
data, not production credentials. The new interface pipeline remains source/lab
only until managed-network firewall defaults, Internet access and additional
controller schema captures are validated. Production's app-control worker and
existing LAN were not changed in this phase. The combined suite passes 387 tests;
that count does not establish full gateway parity.

## Instagram blocking investigation, 2026-10-20

Live controller GETs returned no simple app blocks (`v2/firewall-app-blocks`),
no traffic rules, and no non-mirrored user firewall policies in its sole Default
site. The stored UDAPI payload contained no application matches. Zenarmor's
active Default policy had no app controls. Its installed application catalog
recognized Instagram as 10745, whereas UniFi's catalog uses 1573022. These IDs
are independent and must be mapped rather than copied. This establishes that
Instagram was not configured to be blocked; it does not explain why the user's
attempt did not leave a saved controller rule.

The API primitive uses the installed plugin's PUT `appControls` operation,
updates explicit apps only, checks policy identity when requested, and reads the
result back. A separate worker now reconciles saved simple app blocks into
clones of Default, using explicit MAC/subnet selectors. Default app controls are
preserved; stale managed policies are removed after replacements activate.
Unknown rule fields, schedules/categories without translators, mixed/overlapping
scopes and IPv6 network scope are rejected before writes. Existing custom
security policies prevent activation until policy inheritance can be resolved.
If Default security controls change, an old clone is disabled rather than
shadowing the new protections. Failed writes/activation retry after five minutes;
changed rules and removal of all rules bypass the backoff.

A real installed-plugin API exercise used MAC 52:54:00:26:07:02, confirmed absent
from UniFi clients and the production ARP table. A consistent SQLite settings
backup and Default policy snapshot were saved privately under
`/root/unifi-app-control-backup-20261020-161245`. The API accepted app 10745 and
the exact MAC selector, then rejected activation with `Upgrade to premium`.
Readback showed the test policy disabled. Cleanup removed it, leaving zero
managed app policies; Default's active state and app controls were preserved.
This proves API translation and rejection handling, not successful enforcement.
No actual user-device Instagram block was applied. Additional policy activation
is subject to the installed license checks; the bridge must not bypass them or
widen a device-only block into the global Default policy.

The worker was deployed at 19:17 EAT with a source/config rollback backup at
`/root/unifi-app-worker-backup-20261020-161741`. The running daemon logged an
initial zero-rule reconciliation, no managed app policies remained, and the
controller continued receiving adopted UXGB informs. This verifies the live
polling path with an empty rule set, not controller-to-client enforcement.
The combined branch passed 357 tests after merging Claude's Network 11 zone
policy and firewall-trigger attribution fixes. Those production changes were
preserved during deployment; legacy firewall-rule mirroring is skipped for a
zone-based site and its existing mirrored policies provide trigger identities.
Creating/updating all zone-based firewall policy types is still a parity gap.

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

## Scoped firewall compiler: experimental, not deployed

`opnsense_filter_program.py` compiles nested UDAPI calls and RETURN into a
forward-only PF tag program scoped to one ingress. Compilation performs no API
writes. It is not integrated into provisioning or deployed to production.
Meaningful egress-dependent branches and unsupported state-specific actions
raise errors; they must not silently fall back to a permissive approximation.

Isolated OPNsense 26.7.7 package tests exercised the generated rules in the real
PF kernel: a VLAN client passed a WAN HTTP probe, was blocked after a child
RETURN resumed a parent DROP, and passed after that parent became ACCEPT.
A source-conditioned child DROP blocked only the matching test address; changing
back restored access. WAN packet capture confirmed source NAT and a separate
client DNS query through the VLAN router returned NOERROR with answers.
These synthetic policy tests do not establish controller UI integration,
IPv6 parity, existing-state revocation, transactional batch recovery or complete
egress-policy support. The lab evidence remains outside the repository.

Instagram enforcement remains unverified pending a user-created rule. The
installed Zenarmor license rejected scoped policy activation with "Upgrade to
premium"; changing the shared Default policy is not a safe substitute.

## WireGuard foundation and real tunnel validation, 2026-10-20

`opnsense_wireguard.py` is a pure planner, not yet called by the daemon. Server
and peer field names were checked against the controller's WireGuard serializers
and OPNsense MVC models. This is serializer-derived schema evidence, not a
captured UI-created VPN provision. It maps keys, IPv4/IPv6 interface addresses,
allowed prefixes, endpoints, preshared keys, keepalive and MTU. Unsupported scoped
listen addresses, MSS options, client DNS/search-domain settings and WAN policy
reject the plan explicitly. Owned object names are hashes with `ufg_wgs_` and
`ufg_wgp_` prefixes because these models lack a description field. Key material
must never be logged with plans or summaries.

Direct application of its output to the isolated OPNsense VM created one
instance and peer and established a WireGuard handshake with a separate VNET
jail. A temporary lab-only local firewall rule allowed decrypted test traffic.
IPv4 and IPv6 tunnel pings each passed three of three packets. A 768-byte
underlay capture showed UDP/51890 traffic between the underlay addresses.
Removing only the peer's IPv6 allowed prefix left IPv4 working and blocked both
IPv6 probes. Restoring the full translated plan restored both families.
These checks prove tunnel-to-router traffic, not routed LAN/Internet access.

The first peer-edit experiment detached the peer entirely: OPNsense's volatile
`client.servers` field is write-active and omitting it clears instance membership.
The `bind_peers` helper now requires a complete instance UUID map and writes
explicit membership, with tests for missing/invalid/orphan references. The final
restoration test used that helper against the real API.

No routes are installed by this planner; `disableroutes=1` prevents implicit
host/default route replacement. Instance/peer lifecycle, ownership and collision
preflight, persistent retry/rollback, key rotation, firewall/NAT, scoped listen
binding, routing, client DNS and controller status still require implementation.
No production VPN was changed. OpenVPN, IPsec and AP emulation remain separate
unfinished parts of the original parity target.

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

# Full OPNsense translation target

Requested 2026-10-20: every UniFi gateway feature with an OPNsense equivalent
should control the actual OPNsense service and report its observed state.
Adoption, accepting an inform, and passing unit tests do not establish parity.
This is an implementation target; the incomplete entries below are not promises
of current support. Baseline: `feat/uxg-lab-fixes` at `f61a875`.

| Area | Current implementation / gap | Required completion evidence |
|---|---|---|
| Physical ports | Discovery added in this branch, preserving existing mappings; UXGB capacity is five. VLANs, bridges, radios and tunnels are separate resources. | All Ethernet NICs, including disabled ones, represented once; real link state; stable mappings after restart. Controller model capacity is respected. |
| Interfaces / VLAN IDs | Address/counter telemetry exists; VLAN creation, parent assignment, tagging, bridge membership and interface writes are missing. | Create/edit/remove tagged network in lab, verify packet tags, DHCP and isolation; protect management access. |
| IPv4 | Selected firewall, DNAT, DNS records, reservations and routes translate. Full address, gateway, DHCP-client, MTU/MSS and policy routing configuration is missing. | Compare actual interface/routing/filter state with the requested values; connectivity and rollback tests. |
| IPv6 | Selected rule/route handling exists, not a complete IPv6 stack translator. | Static/SLAAC/DHCPv6 WAN, prefix delegation, LAN prefixes, router advertisements, DHCPv6 and DNS, ICMPv6, firewall and routes tested with real clients. |
| DHCP server | Dnsmasq/Kea reservations; pools/options/server configuration not translated. Keep Dnsmasq as the requested production backend. | Pools, lease duration, exclusions, DNS/router/domain, NTP, PXE/TFTP, custom options and reservations, as supported by the actual UniFi schema; verify client leases/options. |
| DHCP relay | Missing. | DHCRelay destinations/interfaces/options, DHCPv4 and DHCPv6 captures. Server/relay roles must be reconciled per interface/subnet; do not accidentally run competing responders. |
| VPN | Missing translation for tunnel configuration and status. Existing OPNsense OpenVPN configuration is independent. | WireGuard first, then OpenVPN/IPsec mappings where controller schemas exist; peers, keys/certs, routes, DNS, firewall/NAT, handshakes and client data transfer. Teleport/Site Magic are not assumed equivalent. |
| Smart Queues / QoS | Missing. | Map rates/directions/flow isolation to OPNsense traffic shaping; test upload/download throughput, loaded latency and queue counters. Report differences in scheduling semantics. |
| Ethernet flow control | Missing. Distinct from connection Traffic Flows. | Translate supported pause-frame settings through the actual NIC/driver backend and read them back; do not simulate hardware support. |
| Speedtest | Background command and result reporting exist. This branch fixes decimal Mbps and newest-result selection. | Test requested from UniFi completes, results arrive at controller, informs continue, errors do not reuse old results as a new success. |
| MAC cloning | Missing. | Apply/read back interface spoofed MAC; maintain a separate stable emulator identity; reconnect WAN and verify lease/routing recovery. |
| UPnP/NAT-PMP | Missing. | Installed backend, permitted interfaces/ACLs, live lease list, create/delete/expiry and firewall behavior. No automatic broad exposure. |
| Dynamic DNS | Account status reads exist; account/provider configuration is missing. | Translate supported providers, credentials and check-IP methods, trigger update and verify published IPv4/IPv6 record and error status. |
| WAN failover / balancing | Missing. | Gateways/groups, health checks, policy routing, failover and recovery on isolated WANs. |
| Firewall / NAT | Substantial UDAPI translator exists, with skipped-match protection. Not every policy type is supported. | Both address families, local/forward direction, sets, states, zones, hairpin/SNAT and policy restrictions; packet-level permit/deny tests. |
| DNS / mDNS / services | Host records exist; full resolver/forwarder/mDNS/NTP/LLDP configuration is incomplete. | Service-specific writes, reloads and observed behavior; preserve current AdGuard/Unbound/Dnsmasq chain. |
| Insights / Flows | DPI, country accounting, Netflow totals, allowed connections and firewall triggers exist in the baseline. | Counter reconciliation, attribution, restarts, retention, interface mapping and UI/API validation. |
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

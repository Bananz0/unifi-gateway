# USG (UGW3) vs UXG-Max (UXGB) emulation on OPNsense

State on 2026-10-20, with production running as UXGB since 03:29 (Network
10.6.106 on a Cloud Key Gen2+, OPNsense 26). "Evidence" points to where each row
was checked; "prod" means the live controller and router.

| Feature | USG mode | UXG mode | Evidence |
|---|---|---|---|
| Adoption and inform | yes | yes (UDAPI payload, front-panel ports, AES-GCM even when unadopted) | prod: state 1, supported, `tools/migrate_usg_to_uxg.py` |
| Clients on the gateway | host_table | port_table mac_table + ipv4_active_leases | prod: 14-29 clients |
| WAN/WWW/LAN health, latency, uptime | yes | yes | prod `stat/health` all ok |
| Dashboard throughput | yes | yes (port `*-r` rates) | UniFi UI: 30.6/48.4 Kbps after fix |
| Speed test | yes (blocking) | yes (off the inform loop) | prod: 42 Mbps result, informs continued |
| DPI / Insights apps | yes (camel-case dpi_stats) | yes | prod 5-minute reports; UI Top Apps |
| Traffic Flows, allowed | **no** | yes (`connections` from Zenarmor) | prod `ace_audit.traffic_flow`, API |
| Traffic Flows, blocked | **no** | yes (`triggers` from the OPNsense firewall log, usg_caps 0x20000000) | prod: 1339 blocked flows in the UI |
| Client block/unblock | yes | yes (blocked set + `blocked_sta` string + state kill) | lab and prod |
| Firewall rules UniFi -> OPNsense | yes (EdgeOS) | yes (UDAPI filter, triggerTag aware) | real 10.6 captures, tests |
| Port forwards UniFi -> OPNsense | yes | yes (flat DNAT, ADDRv4_<wan>) | lab capture |
| DHCP reservations | yes | yes (named from DNS records) | lab |
| DNS host records | yes | yes | lab and prod |
| Static routes | yes | yes | lab |
| Region blocking | no | yes (GeoIP alias or ipdeny URL tables) | prod: KP enabled/disabled end to end |
| Threat Management (IPS) | no | yes, opt-in `ips = true`: Suricata rulesets; interfaces only when Suricata isn't inline | prod run 2026-10-20 08:20: the controller pushed idsIps and the gateway applied it. It added the LAN to an inline (netmap) Suricata, which was reverted by hand within 4 minutes, and the translator now refuses to add interfaces to an inline Suricata |
| Ad blocking | no | shown from AdGuard Home (Content Filtering profile) | prod profile present |
| OPNsense -> UniFi mirror | yes (2000+) | yes (20000+, skips operator indexes, default deny) | prod |
| Reboot | yes (allow_reboot) | yes (same handler) | unit tests |
| Kick client | n/a | n/a: the controller sends kick-sta to the AP, and rejects it for wired clients (`api.err.UnknownStation`) | lab |
| gw_caps | n/a | empty: the only 10.6 flags (`wan_magic`, `slaac_detect`) are UXG-firmware WAN detection | controller code |
| Unhandled controller operations | logged | logged; nothing new since migration | prod `unhandled_commands.json` |

Not translated in either mode, so there's no parity gap: UDAPI `mdns`,
`lldp`, `ntpClient`, `sshServer`, `systemLog`, `wanFailover`, `arpInspection`
and the matching EdgeOS sections. OPNsense configures these itself.

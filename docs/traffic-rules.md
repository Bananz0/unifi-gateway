# Traffic rules, application enforcement and reporting

## Network 11 and the iPhone save failure

On the inspected Cloud Key, Network `11.0.94-37201-1` logs
`Traffic Rules are not supported, 'create' call ... ignored` when the iPhone
Traffic Rules action attempts to save. Inspection of the installed controller
confirms that the deprecated `/v2/api/site/<site>/trafficrules` create, update
and delete handlers unconditionally reject requests. Listing returns an empty
list. This is not a missing gateway capability or an OPNsense write failure.
Changing firmware/capability strings cannot enable that removed API.

The supported simple-app path is:

- `GET /v2/api/site/<site>/firewall-app-blocks`
- `POST /v2/api/site/<site>/firewall-app-blocks/create`
- `PUT` / `DELETE /v2/api/site/<site>/firewall-app-blocks/<id>`

The Cloud Key accepted an Instagram rule for an unused test MAC through that
create endpoint; readback and deletion passed. No real client was targeted.
The current documented web path is **Settings > CyberSecure > Protection >
Simple App Blocking**. See [Ubiquiti's application filtering guide](https://help.ui.com/hc/en-us/articles/28314415752727-Application-Filtering-in-UniFi).
Use a specific app with an ALWAYS schedule for this emulator. Categories,
custom schedules and arbitrary app-aware zone policies remain unsupported.
The old iPhone action remains incompatible until the client uses a supported
API; this repository does not modify the controller or the iPhone app.

If the mobile interface still uses Traffic Rules, the helper can save the same
supported rule, without passing credentials on the command line:

```sh
python3 /usr/local/lib/unifi-gateway/tools/unifi_app_rules.py list
python3 /usr/local/lib/unifi-gateway/tools/unifi_app_rules.py create \
  --name "Block Instagram on test device" --app Instagram --mac 02:00:00:00:00:01
python3 /usr/local/lib/unifi-gateway/tools/unifi_app_rules.py delete RULE_ID
```

Replace the example MAC with the intended device's current MAC. On a source
checkout, use `python tools/unifi_app_rules.py --config /path/to/config ...`.
Names or numeric UniFi app IDs are accepted; `--app`, `--mac` and `--network`
can be repeated. Devices and network scopes are mutually exclusive. A network
argument is its UniFi ID, not a subnet. Creation validates the complete scope,
uses the current API, reads back the returned ID, and reuses an identical rule
with the same name rather than creating a duplicate. Saving alone does not
prove device enforcement. The tool does not translate legacy schedules, allow
rules, bandwidth limits or arbitrary traffic-rule types into simple app blocks.

## Free application enforcement with AdGuard Home

```ini
[unifi]
url = https://controller.example
username = LOCAL_CONTROLLER_ADMIN
password = LOCAL_CONTROLLER_PASSWORD
site = default
verify_ssl = true
app_control = true
app_control_interval = 30
app_control_backend = adguard

[adguard]
url = http://127.0.0.1:3000
username = ADGUARD_ADMIN
password = ADGUARD_PASSWORD
```

Protect the real configuration file and use HTTPS for remote services. The
worker is independent of mirroring. Restart the daemon after changing its
configuration. Remove controller rules before disabling reconciliation if
their managed blocks should also disappear.

Dnsmasq remains the DHCP server. AdGuard cannot resolve MAC identifiers in this
setup: [its MAC client identifiers require AdGuard's own DHCP server](https://adguard-dns.io/kb/adguard-home/clients/).
The worker therefore maps requested MACs to **fresh LAN ARP/NDP** addresses and
creates owned IP selectors. It includes all observed global/ULA IPv6 addresses,
not historical discovery records or expired leases. Ambiguous ownership is
discarded. Offline/unknown devices have no active selector and are reported as
`pending_devices`; reconciliation retries as neighbors appear. IPv6 link-local
addresses cannot be identified safely without an interface scope and are skipped.

Owned entries use `unifi-gw-app-<hash>` names. Device-specific policies inherit
containing network blocks and global blocked services. A more-specific manual
AdGuard client could bypass a network policy, so overlapping manual selectors
reject the complete request before writes. Manual clients are not rewritten.
Obsolete IP selectors are removed before new ones are created so an address
reassigned to another device cannot retain the old device's rule after a failed
add. A partial failure can leave a temporary enforcement gap; the next worker
iteration converges. This is not a transactional API.

This backend blocks DNS domains from AdGuard's service catalog. It does not
classify and drop application packets like a DPI firewall. Existing sessions,
cached DNS, external encrypted DNS, VPNs and hard-coded addresses can bypass it.
Whole-network IPv6 prefix delegation, schedules, category mappings, manual-client
merging and global blocked-service schedule inheritance remain incomplete.
Populated global blocked-service schedules are rejected rather than silently
turning those inherited services into ALWAYS blocks.
Zenarmor remains an alternative backend with its existing scoped-license gate.

## Validation and deployment, 2026-10-21

Tests used a documentation-only IP and unused test MAC, never a real device:

- Network 11 accepted, stored and deleted a current-API Instagram rule.
- AdGuard's filtering engine reported `FilteredBlockedService` for the selected
  IP and `NotFilteredNotFound` for the unselected IP. Moving the selector
  reversed those results; deletion restored both. A repeat issued zero writes.
- Actual UDP DNS queries to the running resolver returned Instagram's normal
  address, then `0.0.0.0` with the block active, then its normal address after
  removal. The temporary loopback source address and managed client were removed.
- The deployed worker retrieved a current-API test rule and reported one pending
  device, correctly creating no selector for its unused MAC. The rule was removed.

Production source and configuration were backed up under
`/root/unifi-gateway-app-rules-backup-<UTC timestamp>` before deployment. Private
readbacks and test results are in `/root/unifi-gw-rule-validation/`, outside Git.
These checks do not prove that the iPhone's Instagram app is blocked, nor that
the deprecated iPhone save action works. A fresh-device DNS/app test is separate.

## ntopng work continued from Claude

Claude's committed ntopng source is active in production. Configure:

```ini
[opnsense]
dpi = ntopng
flows = true

[ntopng]
url = http://127.0.0.1:3001
username = NTOPNG_USER
password = NTOPNG_PASSWORD
interval = 30
```

The collector books growth of observed live nDPI flow counters to per-client app
totals. Its initial poll establishes a baseline; it does not replay old flows.
Flows that disappear from the live listing can become allowed UniFi Traffic
Flows; blocked records come separately from PF logs. Generic or unmatched
classifications remain generic/category entries. Encrypted traffic is not
guaranteed to identify an application. ntopng is a reporting source, not the
AdGuard enforcement backend. Thirty-second polling reduces repeated live-flow
enumeration cost; very short-lived flows and API pagination limits still need
further accounting audits. Per-client total throughput remains sourced from
Netflow rather than synthesizing totals from classified application traffic.

Claude's unfinished Android TV tool is completed separately; see
[TV scanner usage and proof limits](tv-scan.md).

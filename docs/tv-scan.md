# Android TV ADB exposure checks

Run the standalone Python 3.8+ tool on a computer connected to the device's LAN:

```powershell
python tools/tv_scan.py 192.168.1.50
python tools/tv_scan.py 192.168.1.0/24 --shell-check
python tools/tv_scan.py 192.168.1.50 --shell-check --json
```

Without a target, the tool infers the routed private IPv4 address and scans its
`/24`. Specify the target explicitly on computers with VPNs or multiple NICs.
The address limit is 1024, with 32 workers by default. `--timeout` bounds
connection/negotiation and `--shell-timeout` bounds the complete ADB exchange;
both are capped at 30 seconds. TCP fragmentation, truncated frames, oversized
payloads, invalid checksums and trickling connections are bounded.

The default only connects to TCP/5555 and negotiates ADB. `--shell-check` also
opens a legacy shell service, emits a random marker with `echo`, and reads
`ro.product.model` with `getprop`. It supplies no authentication keys, installs
no apps, and writes no device files or settings. It does not start a local ADB
daemon and needs no `adb` executable or third-party Python packages.

| Result | Evidence |
|---|---|
| `AUTH_REQUIRED` | The ADB endpoint requested authentication; the tool does not answer it. |
| `ADB_OPEN` | ADB negotiation succeeded without an authentication challenge; no shell was tested. |
| `SHELL_OPEN` | An unauthenticated shell returned the exact random marker. The next output line is reported as the model. |
| `UNVERIFIED_SHELL` | ADB connected, but the shell exchange was unexpected, incomplete or timed out. Its cause is unknown. |
| `NOT_ADB` | TCP connected but the listener did not complete a valid ADB negotiation. |
| `CLOSED` | TCP connection failed or timed out. Filtering, routing and host availability can also cause this. |

An open unauthenticated shell is an access-control exposure. None of these
results establishes malware infection, model authenticity or device safety.
A missing echo, a vendor MAC prefix or a model name is not an infection verdict.
The scanner does not inspect installed packages, persistence or running malware.
It does not change UniFi or OPNsense block rules. Isolating a device and examining
it further remain separate actions.

Validation uses simulated ADB peers: fragmented TCP, authentication challenges,
successful read-only shells, echoed commands, malformed frames and deadlines.
No live TV was scanned or modified while finishing this tool.

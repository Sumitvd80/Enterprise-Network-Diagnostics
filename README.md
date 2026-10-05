# Enterprise Network Diagnostics Hub

A single-file Flask application that provides a browser-based console for running common Layer 3–7 network and security diagnostics against a target host, with results streamed live to the UI over Server-Sent Events (SSE).

Built for network/security engineers who need a fast, no-install-on-the-target way to validate connectivity, TLS posture, DNS resolution, and path health from a jump box or local workstation.

> ⚠️ **Local diagnostic tool, not a production service.** Runs on `127.0.0.1` with Flask's debug server (`debug=True`). Do not expose this to untrusted networks or run it as-is on a server reachable by others — see [Security Notes](#security-notes).

---

## Features

| Tab | What it does |
|---|---|
| 🔌 **TCP Port Check** | Layer-4 connect test against one or more comma-separated ports, reports handshake time in ms. |
| 🌐 **Non-SSL URL Test** | Sends a raw cleartext `GET /` and captures the HTTP response status line. |
| 🔒 **SSL/TLS Cipher & Cert** | Negotiates TLS (auto, forced TLSv1.2, or forced TLSv1.3), reports negotiated cipher/protocol, parses the X.509 cert (CN, issuer, SANs, expiry), with an option to bypass validation (`-k` style) for internal/self-signed endpoints. |
| 🧬 **Advanced DNS Lookup** | Looks up NS, A, AAAA, CNAME, MX, TXT, SOA records via the local resolver **and** Google Public DNS (`8.8.8.8`) side-by-side for drift comparison. |
| 📋 **WHOIS Registrar** | Queries IANA (port 43) and follows the registrar referral for public domains; falls back to reverse DNS (PTR) for internal/private IPs and `.local`/`.internal` names. |
| 🕵️ **Stealth Range Scan** | Sweeps a subnet octet range on a given port with randomized pacing to avoid tripping simple rate-based firewall alerts. |
| 📊 **Concurrent Monitor** | Polls multiple hosts (ICMP ping or TCP socket check) on an interval for a configurable duration, non-blocking. |
| 📦 **Path MTU Test** | Binary-searches for the largest non-fragmenting payload (`ping -M do` / `ping -f`) to determine the effective path MTU and derived TCP MSS. |
| 🗺️ **MTR Traceroute** | Runs `traceroute`/`tracert` to enumerate hops, then re-probes each hop with multiple pings to compute per-hop loss % and min/avg/max RTT. |
| ⏱️ **Latency & Jitter** | Opens repeated TCP connections to compute min/max/avg RTT and jitter (max − min). |
| 🔑 **SSH Banner Audit** | Connects to a port (default 22) and captures the raw service banner for version fingerprinting. |

All tabs stream output into a single terminal-style log pane, and any long-running job (scan, monitor, MTU, MTR) can be cancelled mid-run with the **Stop** button.

---

## Requirements

- **Python 3.9+** (uses `dict[str, ...]` built-in generic type hints)
- **Flask**
- System networking utilities available on `PATH`:
  - `nslookup` (DNS tab)
  - `ping` (Monitor, MTU, MTR tabs)
  - `traceroute` (Linux/macOS) or `tracert` (Windows) (MTR tab)

These are typically preinstalled on most Linux, macOS, and Windows systems. On minimal Linux containers you may need to install `dnsutils`/`bind-tools`, `iputils-ping`, and `traceroute` packages.

---

## Installation

```bash
# Clone the repo
git clone https://github.com/Sumitvd80/Enterprise-Network-Diagnostics.git
cd Enterprise-Network-Diagnostics

# (Recommended) create a virtual environment
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# Install dependencies
pip install flask
```

---

## Usage

```bash
python Network-Security-Diagnostics-local-app.py
```

Then open **http://127.0.0.1:5000** in a browser.

1. Pick a diagnostic tab (TCP, SSL, DNS, WHOIS, Scan, Monitor, MTU, MTR, Latency, SSH).
2. Fill in the target (hostname, IP, or URL — scheme/path is stripped automatically) and any mode-specific options (ports, timeout, TLS version, subnet range, poll interval, etc.).
3. Click **▶ Run Diagnostic Engine**. Results stream into the terminal pane in real time.
4. Click **⏹ Stop** at any point to cancel a running job (each run uses a unique session ID so stop requests only affect that run).

### Notes on specific tabs

- **SSL/TLS tab**: enabling *Ignore SSL Validation Errors* disables both hostname checking and certificate verification — use only against known/internal endpoints you trust, to inspect servers with self-signed or expired certs.
- **Stealth Range Scan**: scans `start`–`end` on the last octet of the target prefix (e.g. `10.0.0.` → `10.0.0.1`–`10.0.0.20`). Only scan ranges you are authorized to probe.
- **Concurrent Monitor**: accepts a comma-separated list of hosts (optionally `host:port` for the TCP check mode) and runs until the configured duration elapses or Stop is pressed.

---

## Architecture

- **Backend**: Flask, a single `/stream-engine` route that acts as a generator-based SSE endpoint (`text/event-stream`). The diagnostic logic for all 11 modes lives in one generator function, dispatched on a `mode` query parameter.
- **Frontend**: a single inline HTML template (Tailwind via CDN) with vanilla JS. Form submission opens an `EventSource` connection to `/stream-engine` and appends each streamed line to the terminal pane, color-coded by a leading emoji marker (✅ success, ❌ failure, ℹ️ info, 📢 warning).
- **Cancellation**: each run is tagged with a client-generated `session_id`. A `threading.Event` flag per session (`_stop_flags`) is checked throughout the generator loop; `/stop-engine?session_id=...` sets the flag, and `EventSource.close()` is called client-side.

No database, no external API calls beyond DNS/WHOIS/HTTP probes to the target itself (plus an optional comparison query to `8.8.8.8` in the DNS tab).

---

## Security Notes

- **Debug mode is on** (`app.run(..., debug=True)`), which enables the Werkzeug interactive debugger. Never run this with debug mode enabled on anything but a trusted local machine — the debugger allows arbitrary code execution if reachable.
- **Binds to `127.0.0.1` only** by default, so it isn't exposed on the network as shipped. Don't change the bind host to `0.0.0.0` without adding authentication and disabling debug mode.
- **Shells out to system commands** (`nslookup`, `ping`, `traceroute`/`tracert`) with arguments built from user input. Target/host values are not fully sanitized against shell metacharacters beyond basic parsing — treat this as a trusted-operator tool, not something to expose to untrusted input.
- **Active scanning features** (Stealth Range Scan, port sweeps) can trigger IDS/IPS alerts or violate acceptable-use policies if run against networks you don't own or have authorization to test. Use only within your own environment or with explicit permission.

---

## License

No license file is currently included in this repository. 

import socket
import ssl
import time
import sys
import subprocess
import re
import random
import threading
from urllib.parse import urlparse
from flask import Flask, render_template_string, Response, request

app = Flask(__name__)

# ── Global stop-flag registry keyed by session_id ──────────────────────────
_stop_flags: dict[str, threading.Event] = {}
_stop_lock = threading.Lock()

def _get_flag(sid: str) -> threading.Event:
    with _stop_lock:
        if sid not in _stop_flags:
            _stop_flags[sid] = threading.Event()
        return _stop_flags[sid]

def _clear_flag(sid: str):
    with _stop_lock:
        if sid in _stop_flags:
            _stop_flags[sid].clear()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Network Diagnostics Hub</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
    <style>
        .terminal-scrollbar::-webkit-scrollbar { width: 8px; }
        .terminal-scrollbar::-webkit-scrollbar-track { background: #0f172a; }
        .terminal-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
    </style>
</head>
<body class="bg-[#0b0f19] text-slate-100 font-sans min-h-screen flex flex-col justify-between">

    <header class="border-b border-slate-800 bg-slate-900/40 backdrop-blur px-6 py-4 flex items-center justify-between shadow-sm">
        <div class="flex items-center space-x-3">
            <div class="h-3 w-3 rounded-full bg-cyan-500 animate-pulse"></div>
            <h1 class="text-xl font-bold tracking-tight bg-gradient-to-r from-slate-100 via-slate-300 to-slate-500 bg-clip-text text-transparent">
                NetOps Net-Diagnostic Engine
            </h1>
        </div>
        <span class="text-xs font-mono text-slate-400 bg-slate-800/60 px-3 py-1 rounded-md border border-slate-800">Developed by Sumit Deshmukh</span>
    </header>

    <div class="max-w-7xl w-full mx-auto px-6 mt-6">
        <div class="border-b border-slate-800 flex flex-wrap gap-1">
            <button type="button" onclick="switchTab('tcp', '443')" id="btn-tcp" class="tab-btn px-3 py-2 text-xs font-semibold border-b-2 border-cyan-500 text-cyan-400 focus:outline-none transition-all cursor-pointer">
                🔌 TCP Port Check
            </button>
            <button type="button" onclick="switchTab('http', '80')" id="btn-http" class="tab-btn px-3 py-2 text-xs font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200 focus:outline-none transition-all cursor-pointer">
                🌐 Non-SSL URL Test
            </button>
            <button type="button" onclick="switchTab('ssl', '443')" id="btn-ssl" class="tab-btn px-3 py-2 text-xs font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200 focus:outline-none transition-all cursor-pointer">
                🔒 SSL/TLS Cipher & Cert
            </button>
            <button type="button" onclick="switchTab('dns', '53')" id="btn-dns" class="tab-btn px-3 py-2 text-xs font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200 focus:outline-none transition-all cursor-pointer">
                🧬 Advanced DNS Lookup
            </button>
            <button type="button" onclick="switchTab('whois', '43')" id="btn-whois" class="tab-btn px-3 py-2 text-xs font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200 focus:outline-none transition-all cursor-pointer">
                📋 WHOIS Registrar
            </button>
            <button type="button" onclick="switchTab('scan', '443')" id="btn-scan" class="tab-btn px-3 py-2 text-xs font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200 focus:outline-none transition-all cursor-pointer">
                🕵️ Stealth Range Scan
            </button>
            <button type="button" onclick="switchTab('monitor', '0')" id="btn-monitor" class="tab-btn px-3 py-2 text-xs font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200 focus:outline-none transition-all cursor-pointer">
                📊 Concurrent Monitor
            </button>
            <button type="button" onclick="switchTab('mtu', '80')" id="btn-mtu" class="tab-btn px-3 py-2 text-xs font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200 focus:outline-none transition-all cursor-pointer">
                📦 Path MTU Test
            </button>
            <button type="button" onclick="switchTab('mtr', '80')" id="btn-mtr" class="tab-btn px-3 py-2 text-xs font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200 focus:outline-none transition-all cursor-pointer">
                🗺️ MTR Traceroute
            </button>
            <button type="button" onclick="switchTab('latency', '443')" id="btn-latency" class="tab-btn px-3 py-2 text-xs font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200 focus:outline-none transition-all cursor-pointer">
                ⏱️ Latency & Jitter
            </button>
            <button type="button" onclick="switchTab('ssh', '22')" id="btn-ssh" class="tab-btn px-3 py-2 text-xs font-semibold border-b-2 border-transparent text-slate-400 hover:text-slate-200 focus:outline-none transition-all cursor-pointer">
                🔑 SSH Banner Audit
            </button>
        </div>
    </div>

    <main class="flex-1 max-w-7xl w-full mx-auto p-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        <div class="bg-slate-950/50 border border-slate-800/80 p-5 rounded-xl space-y-5 h-fit shadow-2xl backdrop-blur-md">
            <h2 class="text-xs font-semibold text-slate-400 tracking-wider uppercase">Target Node Configurations</h2>
            
            <form id="masterForm" class="space-y-4">
                <input type="hidden" id="active_mode" name="active_mode" value="tcp">

                <div id="wrapper-target">
                    <label id="label-target" class="block text-xs font-medium text-slate-400 mb-1">Hostname, IP, or Domain URL</label>
                    <input type="text" id="target" name="target" required placeholder="e.g., myserver.com or 10.0.0.1" 
                           class="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 text-slate-200 transition font-mono">
                </div>

                <div id="wrapper-monitor-targets" class="hidden">
                    <label class="block text-xs font-medium text-slate-400 mb-1">Multi-Target Hostnames/IPs (Comma Separated)</label>
                    <textarea id="monitor_targets" name="monitor_targets" rows="2" placeholder="10.100.12.4, 10.200.14.5, internalapp.local"
                              class="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 text-slate-200 transition font-mono"></textarea>
                </div>

                <div id="wrapper-subnet-scan" class="hidden grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1">Start IP Host Octet</label>
                        <input type="number" id="scan_start" name="scan_start" value="1" min="1" max="254"
                               class="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 text-slate-200 transition font-mono">
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1">End IP Host Octet</label>
                        <input type="number" id="scan_end" name="scan_end" value="20" min="1" max="254"
                               class="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 text-slate-200 transition font-mono">
                    </div>
                </div>

                <div id="wrapper-ports-timeout" class="grid grid-cols-2 gap-4">
                    <div>
                        <label id="label-port" class="block text-xs font-medium text-slate-400 mb-1">Target Port(s)</label>
                        <input type="text" id="port" name="port" required value="443" placeholder="e.g., 80,443"
                               class="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 text-slate-200 transition font-mono">
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1">Timeout (Sec)</label>
                        <input type="number" id="timeout" name="timeout" required value="5"
                               class="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 text-slate-200 transition font-mono">
                    </div>
                </div>

                <div id="monitor-advanced-options" class="hidden space-y-4 pt-2 border-t border-slate-900">
                    <h3 class="text-xs font-semibold text-cyan-500/90 tracking-wider uppercase">Active Monitoring Window</h3>
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs font-medium text-slate-400 mb-1">Total Duration</label>
                            <select id="monitor_duration" name="monitor_duration" class="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 text-slate-300">
                                <option value="1">1 Minute Run</option>
                                <option value="5">5 Minutes Run</option>
                                <option value="15">15 Minutes Run</option>
                                <option value="30">30 Minutes Run</option>
                                <option value="60">60 Minutes Run</option>
                                <option value="120">120 Minutes Run</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-xs font-medium text-slate-400 mb-1">Check Mechanism</label>
                            <select id="monitor_type" name="monitor_type" class="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 text-slate-300">
                                <option value="PING">ICMP Echo Request (Ping)</option>
                                <option value="TELNET">Layer-4 Socket Check</option>
                            </select>
                        </div>
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1">Polling Interval Rate (Seconds)</label>
                        <input type="number" id="monitor_interval" name="monitor_interval" value="10" min="2" max="60"
                               class="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 text-slate-200 transition font-mono">
                    </div>
                </div>

                <div id="ssl-advanced-options" class="hidden space-y-4 pt-2 border-t border-slate-900">
                    <h3 class="text-xs font-semibold text-cyan-500/90 tracking-wider uppercase">Advanced SSL Engine Context</h3>
                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1">Enforce TLS Protocol Bound</label>
                        <select id="tls_version" name="tls_version" class="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500 text-slate-300">
                            <option value="AUTO">Auto-Negotiate Protocols (Default)</option>
                            <option value="TLSv1.2">Force TLSv1.2 Protocol</option>
                            <option value="TLSv1.3">Force TLSv1.3 Protocol</option>
                        </select>
                    </div>
                    <label class="flex items-start space-x-3 cursor-pointer group">
                        <input type="checkbox" id="insecure" name="insecure" class="mt-1 rounded border-slate-800 bg-slate-900 text-cyan-500 accent-cyan-500">
                        <span class="text-xs text-slate-400 group-hover:text-slate-200 transition">
                            <strong>Ignore SSL Validation Errors (-k)</strong>
                            <span class="block text-slate-500 text-[11px] mt-0.5">Disables x509 verification to extract raw layer-7 state headers over untrusted chains.</span>
                        </span>
                    </label>
                </div>

                <div class="bg-slate-900/60 p-3 rounded-lg border border-slate-800/80 text-[11px] text-slate-400">
                    <p class="font-semibold text-slate-300 mb-1">Active Feature Scope:</p>
                    <div id="desc-tcp" class="tab-desc">Validates standard Layer-4 connectivity. Supports single ports or comma-separated lists (e.g., <code>80,443,8080</code>).</div>
                    <div id="desc-http" class="tab-desc hidden">Connects without encryption to request cleartext HTTP status lines and upstream headers.</div>
                    <div id="desc-ssl" class="tab-desc hidden">Runs explicit cryptographic negotiation mappings, isolates cipher suites, and parses complete X.509 certificate data strings (Expiry, SANs, Issuing Chain).</div>
                    <div id="desc-dns" class="tab-desc hidden">Runs an advanced parallel DNS audit loop across ALL primary record mappings, comparatively evaluating internal paths directly against Google DNS layers.</div>
                    <div id="desc-whois" class="tab-desc hidden">Connects directly to top-level IANA registry lookup systems over port 43 to pull root allocation data records for external assets. Supports local system PTR resolution fallbacks for internal segments.</div>
                    <div id="desc-scan" class="tab-desc hidden">Fires localized sequential socket scans across an octet range. Introduces randomized artificial pacing to avoid firewall rate blocks.</div>
                    <div id="desc-monitor" class="tab-desc hidden">Spawns a continuous asynchronous monitoring matrix. Runs independently without locking the web execution environment.</div>
                    <div id="desc-mtu" class="tab-desc hidden">Executes a smart binary search sweep with the DF flag to find the exact passing MTU, identification of the failure point, and automatic header/MSS overhead calculations.</div>
                    <div id="desc-mtr" class="tab-desc hidden">Performs an enterprise MTR simulation. Maps intermediate route tracking points and fires multiple packet probes to calculate real-time Loss % and latency spreads.</div>
                    <div id="desc-latency" class="tab-desc hidden">Compiles multi-sample data points to calculate Minimum, Maximum, Average Latency, and Jitter variances.</div>
                    <div id="desc-ssh" class="tab-desc hidden">Connects to target node endpoints to pull raw daemon identification headers and version identification strings.</div>
                </div>

                <!-- ── ACTION BUTTONS ROW ─────────────────────────────────── -->
                <div class="flex gap-3 mt-4">
                    <button type="submit" id="submitBtn"
                        class="flex-1 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold py-2.5 px-4 rounded-lg shadow-lg hover:shadow-cyan-900/20 transition-all duration-150 text-sm cursor-pointer">
                        ▶ Run Diagnostic Engine
                    </button>
                    <button type="button" id="stopBtn" onclick="stopEngine()"
                        class="hidden bg-rose-700 hover:bg-rose-600 text-white font-semibold py-2.5 px-4 rounded-lg shadow-lg transition-all duration-150 text-sm cursor-pointer whitespace-nowrap">
                        ⏹ Stop
                    </button>
                </div>
            </form>
        </div>

        <div class="lg:col-span-2 flex flex-col h-[620px] bg-[#070a12] border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
            <div class="bg-slate-900/60 border-b border-slate-800/80 px-4 py-2.5 flex items-center justify-between">
                <span class="text-xs font-mono text-slate-400 flex items-center space-x-2">
                    <span class="inline-block w-2.5 h-2.5 rounded-full bg-slate-700" id="terminalStatusIcon"></span>
                    <span id="terminalStatusText">Engine Standby</span>
                </span>
                <button onclick="clearTerminal()" class="text-xs text-slate-400 hover:text-slate-200 transition font-mono">Clear Workspace</button>
            </div>
            
            <div id="terminal" class="flex-1 p-5 font-mono text-xs overflow-y-auto terminal-scrollbar bg-[#060911] text-cyan-400 space-y-1.5 select-text">
                <div class="text-slate-500 italic">Select any specific network engineering feature tab above and execute the diagnostic block...</div>
            </div>
        </div>
    </main>

    <footer class="border-t border-slate-900 bg-slate-950/40 py-3 px-6 text-center text-[11px] text-slate-600 font-mono tracking-wide">
        11-Feature Advanced Enterprise Network Engineering Diagnostic Subsystem Framework
    </footer>

    <script>
        let eventSource = null;
        let currentSessionId = null;

        // ── Generate a lightweight unique session ID ─────────────────────
        function makeSessionId() {
            return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
        }

        // ── Reset UI to idle state ───────────────────────────────────────
        function setEngineIdle(iconClass, statusMsg) {
            const submitBtn = document.getElementById('submitBtn');
            const stopBtn   = document.getElementById('stopBtn');
            const statusIcon = document.getElementById('terminalStatusIcon');
            const statusText = document.getElementById('terminalStatusText');

            submitBtn.disabled = false;
            submitBtn.classList.remove('opacity-40', 'cursor-not-allowed');
            stopBtn.classList.add('hidden');

            statusIcon.className = 'inline-block w-2.5 h-2.5 rounded-full ' + iconClass;
            statusText.innerText = statusMsg;
        }

        // ── STOP handler ─────────────────────────────────────────────────
        function stopEngine() {
            if (eventSource) {
                eventSource.close();
                eventSource = null;
            }

            // Tell the server to set the stop flag for this session
            if (currentSessionId) {
                fetch('/stop-engine?session_id=' + encodeURIComponent(currentSessionId))
                    .catch(() => {});   // fire-and-forget
            }

            const terminal = document.getElementById('terminal');
            const stopLine = document.createElement('div');
            stopLine.innerHTML = '<span class="text-rose-400 font-bold">⏹ [USER ABORT] Diagnostic stream manually terminated by operator.</span>';
            terminal.appendChild(stopLine);
            terminal.scrollTop = terminal.scrollHeight;

            setEngineIdle('bg-rose-500', 'Stopped by User');
        }

        function switchTab(modeId, defaultPort) {
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('border-cyan-500', 'text-cyan-400');
                btn.classList.add('border-transparent', 'text-slate-400');
            });
            document.querySelectorAll('.tab-desc').forEach(field => field.classList.add('hidden'));

            document.getElementById('btn-' + modeId).classList.add('border-cyan-500', 'text-cyan-400');
            document.getElementById('btn-' + modeId).classList.remove('border-transparent', 'text-slate-400');
            document.getElementById('desc-' + modeId).classList.remove('hidden');
            
            document.getElementById('active_mode').value = modeId;
            document.getElementById('port').value = defaultPort;

            const sslPanel = document.getElementById('ssl-advanced-options');
            const monPanel = document.getElementById('monitor-advanced-options');
            const targetWrap = document.getElementById('wrapper-target');
            const monTargetWrap = document.getElementById('wrapper-monitor-targets');
            const scanRangeWrap = document.getElementById('wrapper-subnet-scan');
            const portsTimeoutWrap = document.getElementById('wrapper-ports-timeout');
            const targetLabel = document.getElementById('label-target');

            sslPanel.classList.add('hidden');
            monPanel.classList.add('hidden');
            targetWrap.classList.remove('hidden');
            monTargetWrap.classList.add('hidden');
            scanRangeWrap.classList.add('hidden');
            portsTimeoutWrap.classList.remove('hidden');
            targetLabel.innerText = "Hostname, IP, or Domain URL";

            if (modeId === 'ssl') {
                sslPanel.classList.remove('hidden');
            } else if (modeId === 'dns') {
                targetLabel.innerText = "Query Domain Node Target (e.g. enterprise.org)";
                document.getElementById('port').value = "53";
            } else if (modeId === 'monitor') {
                monPanel.classList.remove('hidden');
                targetWrap.classList.add('hidden');
                monTargetWrap.classList.remove('hidden');
                portsTimeoutWrap.classList.add('hidden'); 
            } else if (modeId === 'scan') {
                scanRangeWrap.classList.remove('hidden');
                targetLabel.innerText = "Target Subnet Base Prefix (e.g. 10.0.0.1 or 192.168.1.)";
            } else if (modeId === 'whois') {
                targetLabel.innerText = "Target Domain or IP Address Vector";
            }
        }

        function clearTerminal() {
            document.getElementById('terminal').innerHTML = '';
        }

        document.getElementById('masterForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const terminal = document.getElementById('terminal');
            const submitBtn = document.getElementById('submitBtn');
            const stopBtn   = document.getElementById('stopBtn');
            const statusIcon = document.getElementById('terminalStatusIcon');
            const statusText = document.getElementById('terminalStatusText');
            
            terminal.innerHTML = '<div class="text-cyan-500/80 animate-pulse font-bold">[ENGINE_LOG] Mounting async diagnostic pipeline telemetry channel loops...</div>';
            
            // Generate fresh session ID for this run
            currentSessionId = makeSessionId();

            submitBtn.disabled = true;
            submitBtn.classList.add('opacity-40', 'cursor-not-allowed');
            stopBtn.classList.remove('hidden');   // ← show Stop button
            statusIcon.className = "inline-block w-2.5 h-2.5 rounded-full bg-amber-500 animate-ping";
            statusText.innerText = "Streaming Dynamic Context Matrix";

            const target = document.getElementById('target').value;
            const port = document.getElementById('port').value;
            const timeout = document.getElementById('timeout').value;
            const mode = document.getElementById('active_mode').value;
            const tls_version = document.getElementById('tls_version').value;
            const insecure = document.getElementById('insecure').checked ? '1' : '0';
            const scan_start = document.getElementById('scan_start').value;
            const scan_end = document.getElementById('scan_end').value;
            const monitor_targets = document.getElementById('monitor_targets').value;
            const monitor_duration = document.getElementById('monitor_duration').value;
            const monitor_type = document.getElementById('monitor_type').value;
            const monitor_interval = document.getElementById('monitor_interval').value;

            let queryUrl = `/stream-engine?session_id=${encodeURIComponent(currentSessionId)}` +
                           `&target=${encodeURIComponent(target)}&port=${encodeURIComponent(port)}&timeout=${timeout}&mode=${mode}` +
                           `&tls_version=${tls_version}&insecure=${insecure}` +
                           `&scan_start=${scan_start}&scan_end=${scan_end}&monitor_targets=${encodeURIComponent(monitor_targets)}` +
                           `&monitor_duration=${monitor_duration}&monitor_type=${monitor_type}&monitor_interval=${monitor_interval}`;

            if(eventSource) { eventSource.close(); }
            eventSource = new EventSource(queryUrl);

            eventSource.onmessage = function(event) {
                if (event.data === "[STREAM_COMPLETED_SIGNAL]") {
                    eventSource.close();
                    setEngineIdle('bg-emerald-500', 'Engine Idle Ready');
                    return;
                }
                
                let logLine = event.data;
                if(logLine.startsWith('✅')) logLine = `<span class="text-emerald-400 font-medium">${logLine}</span>`;
                else if(logLine.startsWith('❌')) logLine = `<span class="text-rose-400 font-bold">${logLine}</span>`;
                else if(logLine.startsWith('ℹ️')) logLine = `<span class="text-sky-400">${logLine}</span>`;
                else if(logLine.startsWith('📢')) logLine = `<span class="text-amber-300 font-semibold">${logLine}</span>`;
                else if(logLine.startsWith('---')) logLine = `<span class="text-slate-600">${logLine}</span>`;
                
                const lineContainer = document.createElement('div');
                lineContainer.innerHTML = logLine;
                terminal.appendChild(lineContainer);
                terminal.scrollTop = terminal.scrollHeight;
            };

            eventSource.onerror = function(err) {
                eventSource.close();
                setEngineIdle('bg-rose-500', 'Stream Exception Termination');
            };
        });
    </script>
</body>
</html>
"""

def clean_target_hostname(target_input):
    if "://" in target_input:
        try: return urlparse(target_input).hostname
        except: return target_input
    return target_input

def check_is_internal_ip(ip_str):
    try:
        if ip_str.startswith('10.') or ip_str.startswith('192.168.'):
            return True
        if ip_str.startswith('172.'):
            parts = ip_str.split('.')
            if len(parts) >= 2 and 16 <= int(parts[1]) <= 31:
                return True
    except: pass
    return False

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

# ── New: lightweight stop endpoint ──────────────────────────────────────────
@app.route('/stop-engine')
def stop_engine_route():
    sid = request.args.get('session_id', '')
    if sid:
        _get_flag(sid).set()
    return ('', 204)

@app.route('/stream-engine')
def stream_engine():
    session_id   = request.args.get('session_id', 'default')
    target_raw   = request.args.get('target', '')
    port_raw     = request.args.get('port', '443')
    timeout      = float(request.args.get('timeout', 5))
    mode         = request.args.get('mode', 'tcp')
    tls_selection = request.args.get('tls_version', 'AUTO')
    insecure_mode = request.args.get('insecure', '0') == '1'
    
    scan_start         = int(request.args.get('scan_start', 1))
    scan_end           = int(request.args.get('scan_end', 20))
    monitor_targets_raw = request.args.get('monitor_targets', '')
    monitor_duration   = int(request.args.get('monitor_duration', 1))
    monitor_type       = request.args.get('monitor_type', 'PING')
    monitor_interval   = int(request.args.get('monitor_interval', 10))

    host = clean_target_hostname(target_raw)

    ports = []
    for p in port_raw.replace(' ', '').split(','):
        if p.isdigit():
            ports.append(int(p))
    if not ports:
        ports = [443]

    # Prepare the stop flag for this session (clear any previous set)
    stop_flag = _get_flag(session_id)
    stop_flag.clear()

    def stopped():
        """Convenience check used throughout the generator."""
        return stop_flag.is_set()

    def engine_runtime_iterator():
        yield f"data: 🚀 Booting analytical metrics framework context [Mode: {mode.upper()}]...\n\n"
        if mode != 'monitor':
            yield f"data: Target evaluation endpoint base identity evaluated as: {host}\n\n"
        yield f"data: --------------------------------------------------------------------------------\n\n"

        # =========================================================================
        # FEATURE 1: MULTI-PORT TCP CHECK
        # =========================================================================
        if mode == 'tcp':
            yield f"data: Running Multi-Port Layer-4 socket sweeps across targeted array: {ports}\n\n"
            for p in ports:
                if stopped(): break
                start = time.perf_counter()
                try:
                    sock = socket.create_connection((host, p), timeout=timeout)
                    ms = (time.perf_counter() - start) * 1000
                    yield f"data: ✅ SUCCESS: Layer-4 handshake completed on Port {p} in {ms:.2f}ms.\n\n"
                    sock.close()
                except Exception as e:
                    yield f"data: ❌ FAILURE: Connection on Port {p} rejected or timed out: {str(e)}\n\n"
                yield f"data: ---\n\n"

        # =========================================================================
        # FEATURE 2: NON-SSL HTTP URL TESTING
        # =========================================================================
        elif mode == 'http':
            if not stopped():
                p = ports[0]
                try:
                    sock = socket.create_connection((host, p), timeout=timeout)
                    sock.settimeout(3.0)
                    http_payload = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: NetOpsHubEngine/4.3\r\n\r\n"
                    sock.sendall(http_payload.encode('utf-8'))
                    response_data = sock.recv(2048).decode('utf-8', errors='ignore')
                    sock.close()
                    if response_data:
                        lines = response_data.split('\r\n')
                        yield "data: ✅ SUCCESS: Cleartext Layer-7 response captured.\n\n"
                        yield f"data: ℹ️ HTTP Response Status Line: '{lines[0]}'\n\n"
                    else:
                        yield "data: 📢 WARNING: Target node closed descriptor without presenting metrics.\n\n"
                except Exception as e:
                    yield f"data: ❌ FAILURE: Layer-7 pipeline execution aborted: {str(e)}\n\n"

        # =========================================================================
        # FEATURE 3: SSL/TLS CIPHER AUDIT
        # =========================================================================
        elif mode == 'ssl':
            for p in ports:
                if stopped(): break
                yield f"data: 🔍 Starting complete cryptographic profile verification loop for Port {p}...\n\n"
                try:
                    sock = socket.create_connection((host, p), timeout=timeout)
                    yield f"data: ✅ SUCCESS: Layer-4 socket established to facilitate cryptographic exchange.\n\n"
                except Exception as e:
                    yield f"data: ❌ FAILURE: Base layer socket dropped before handshake configuration: {str(e)}\n\n"
                    continue

                if stopped(): break
                yield f"data: --------------------------------------------------------------------------------\n\n"
                yield f"data: [STEP 2] Launching Local Cryptographic Profile Matrix Map...\n\n"
                
                if tls_selection == 'TLSv1.2':
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.maximum_version = ssl.TLSVersion.TLSv1_2
                    yield f"data: ℹ️ Strict Enforcement Override Activated: Enforcing explicit TLSv1.2 configuration mapping.\n\n"
                elif tls_selection == 'TLSv1.3':
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    context.maximum_version = ssl.TLSVersion.TLSv1_3
                    yield f"data: ℹ️ Strict Enforcement Override Activated: Enforcing explicit TLSv1.3 configuration mapping.\n\n"
                else:
                    context = ssl.create_default_context()
                    yield f"data: ℹ️ TLS Profile Mode: Auto-Negotiate modern fallback standard baseline definitions.\n\n"

                if insecure_mode:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    yield f"data: 📢 WARNING: Insecure Validation Intercept Flag (-k) enabled. Disabling all x509 chain verification.\n\n"

                if stopped(): break
                yield f"data: [STEP 3] Running Handshake Exchange Engine Protocol...\n\n"
                
                secure_sock = None
                handshake_passed = False
                try:
                    secure_sock = context.wrap_socket(sock, server_hostname=host)
                    negotiated_cipher, protocol_version, _ = secure_sock.cipher()
                    yield f"data: ✅ SUCCESS: Cryptographic channel handshake mapping negotiated successfully.\n\n"
                    yield f"data: ℹ️ Negotiated Protocol Level: {protocol_version}\n\n"
                    yield f"data: ℹ️ Negotiated Active Cipher Suite: {negotiated_cipher}\n\n"
                    
                    try:
                        cert_data = secure_sock.getpeercert()
                        if cert_data:
                            yield f"data: --------------------------------------------------------------------------------\n\n"
                            yield f"data: 📊 X.509 CERTIFICATE LIFECYCLE & TRUST CHAIN DATA:\n\n"
                            if 'notAfter' in cert_data:
                                yield f"data: 📢 [EXPIRY BOUNDARY]:  {cert_data['notAfter']}\n\n"
                            if 'subject' in cert_data:
                                s_dict = {item[0][0]: item[0][1] for item in cert_data['subject'] if item}
                                yield f"data: ℹ️ [LEAF TARGET CN]:    {s_dict.get('commonName', 'N/A')}\n\n"
                            if 'issuer' in cert_data:
                                i_dict = {item[0][0]: item[0][1] for item in cert_data['issuer'] if item}
                                yield f"data: ℹ️ [INTERMEDIATE CA]:   {i_dict.get('commonName', 'N/A')} [{i_dict.get('organizationName', 'N/A')}]\n\n"
                                yield f"data: ℹ️ [ROOT TRUST TRAIL]:  Root authority anchors validated via local OS crypt chain to -> {i_dict.get('organizationName', 'N/A')} Root Anchoring System\n\n"
                            if 'subjectAltName' in cert_data:
                                sans = [item[1] for item in cert_data['subjectAltName'] if len(item) > 1]
                                yield f"data: ℹ️ [SUBJECT ALT NAMES]: {', '.join(sans)}\n\n"
                        else:
                            yield f"data: 📢 NOTICE: Peer certificate mapping trace empty or bypassed via -k configuration rules.\n\n"
                    except Exception as cert_err:
                        yield f"data: 📢 NOTICE: Extended cert field extraction metrics returned an exception block: {str(cert_err)}\n\n"

                    handshake_passed = True

                except ssl.SSLCertVerificationError as cert_err:
                    yield f"data: ❌ FAILURE: Cryptographic Handshake aborted by Client Engine during verification validation.\n\n"
                    yield f"data: ❌ Certificate Validation Reason: {cert_err.verify_message} (Mnemonic: {cert_err.reason})\n\n"
                except ssl.SSLError:
                    yield f"data: ❌ FAILURE: Handshake dropped due to low-level cryptographic implementation bounds.\n\n"
                except Exception as general_err:
                    yield f"data: ❌ FAILURE: Cryptographic payload pipeline processing aborted: {str(general_err)}\n\n"
                
                if handshake_passed and secure_sock and not stopped():
                    yield f"data: --------------------------------------------------------------------------------\n\n"
                    yield f"data: [STEP 4] Pushing Plain Application Layer HTTP Status Validation...\n\n"
                    try:
                        secure_sock.settimeout(3.0)
                        http_payload = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: NetOpsDiagnosticHub/1.3\r\n\r\n"
                        secure_sock.sendall(http_payload.encode('utf-8'))
                        response_data = secure_sock.recv(512).decode('utf-8', errors='ignore')
                        if response_data:
                            first_line = response_data.split('\r\n')[0]
                            yield f"data: ✅ SUCCESS: Cleartext Layer-7 validation processing completed.\n\n"
                            yield f"data: ℹ️ Raw HTTP Application Layer Status Line: '{first_line}'\n\n"
                    except Exception as http_ex:
                        yield f"data: ❌ FAILURE: Error parsing plain text HTTP payload bytes over target pipeline socket: {str(http_ex)}\n\n"
                    finally:
                        try: secure_sock.close()
                        except: pass
                else:
                    try: sock.close()
                    except: pass
                yield f"data: ---\n\n"

        # =========================================================================
        # FEATURE 4: ADVANCED COMPARATIVE DNS AUDIT
        # =========================================================================
        elif mode == 'dns':
            yield f"data: 🧬 Launching Parallel Comparative DNS Analysis Matrix Framework...\n\n"
            is_win = sys.platform == 'win32'
            
            yield f"data: 🔍 [PHASE 1] Determining Root Domain Name Server (NS) Mappings...\n\n"
            ns_cmd = ["nslookup", "-type=NS", host] if is_win else ["nslookup", "-query=NS", host]
            try:
                ns_res = subprocess.run(ns_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=4)
                for line in ns_res.stdout.splitlines():
                    if any(k in line.lower() for k in ["nameserver", "addresses:", "svr", "name ="]):
                        yield f"data: ℹ️ Authority Trace: {line.strip()}\n\n"
            except: pass

            if stopped():
                yield "data: ⏹ [ABORT] DNS audit halted by user.\n\n"
            else:
                yield f"data: 🔍 [PHASE 2] Initiating Comparative Record Audits [Internal vs. Google 8.8.8.8]...\n\n"
                record_matrix = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
                
                for record in record_matrix:
                    if stopped(): break
                    yield f"data: 📊 Evaluating Record Type: [{record}]\n\n"
                    
                    cmd_internal = ["nslookup", f"-type={record}", host] if is_win else ["nslookup", f"-query={record}", host]
                    int_out = []
                    try:
                        res_i = subprocess.run(cmd_internal, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
                        for line in res_i.stdout.splitlines():
                            if host in line or "address" in line.lower() or "text =" in line.lower() or "mail exchanger" in line.lower() or "canonical name" in line.lower():
                                if "server:" not in line.lower(): int_out.append(line.strip())
                    except Exception as e: int_out.append(f"Query Exception: {str(e)}")
                    
                    cmd_google = ["nslookup", f"-type={record}", host, "8.8.8.8"] if is_win else ["nslookup", f"-query={record}", host, "8.8.8.8"]
                    goo_out = []
                    try:
                        res_g = subprocess.run(cmd_google, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
                        for line in res_g.stdout.splitlines():
                            if host in line or "address" in line.lower() or "text =" in line.lower() or "mail exchanger" in line.lower() or "canonical name" in line.lower():
                                if "server:" not in line.lower(): goo_out.append(line.strip())
                    except Exception as e: goo_out.append(f"Query Exception: {str(e)}")

                    yield f"data:    ↳ Internal DNS Resolver Responses:\n\n"
                    if int_out:
                        for l in int_out: yield f"data:       🔹 {l}\n\n"
                    else: yield f"data:       🔹 [No Record Mapping Returned]\n\n"

                    yield f"data:    ↳ Google Public DNS (8.8.8.8) Responses:\n\n"
                    if goo_out:
                        for l in goo_out: yield f"data:       🔸 {l}\n\n"
                    else: yield f"data:       🔸 [No Record Mapping Returned]\n\n"
                    yield f"data: ---\n\n"

        # =========================================================================
        # FEATURE 5: WHOIS
        # =========================================================================
        elif mode == 'whois':
            if not stopped():
                yield f"data: 📋 Mounting Adaptive WHOIS Core Registry Extraction loop...\n\n"
                
                if check_is_internal_ip(host) or host.endswith('.local') or host.endswith('.internal'):
                    yield f"data: ℹ️ Internal Infrastructure Trace Identified. Executing Local Reverse Infrastructure Mapping...\n\n"
                    try:
                        resolved_name, _, _ = socket.gethostbyaddr(host)
                        yield f"data: ✅ LOCAL SUCCESS: Node maps to infrastructure record descriptor -> {resolved_name}\n\n"
                    except Exception as rdns_err:
                        yield f"data: 📢 NOTICE: Local infrastructure identity reverse lookup unmapped: {str(rdns_err)}\n\n"
                else:
                    parts = host.split('.')
                    clean_domain = ".".join(parts[-2:]) if len(parts) > 1 else host
                    try:
                        s = socket.create_connection(("whois.iana.org", 43), timeout=timeout)
                        s.sendall(f"{clean_domain}\r\n".encode('utf-8'))
                        iana_resp = b""
                        while not stopped():
                            chunk = s.recv(4096)
                            if not chunk: break
                            iana_resp += chunk
                        s.close()
                        
                        if stopped():
                            yield "data: ⏹ [ABORT] WHOIS lookup halted by user.\n\n"
                        else:
                            iana_text = iana_resp.decode('utf-8', errors='ignore')
                            ref_match = re.search(r'whois:\s*([a-zA-Z0-9\.\-]+)', iana_text, re.IGNORECASE)
                            
                            if ref_match:
                                registrar_server = ref_match.group(1).strip()
                                yield f"data: ℹ️ Deep lookup redirect trail identified -> Querying registrar: {registrar_server}...\n\n"
                                s2 = socket.create_connection((registrar_server, 43), timeout=timeout)
                                s2.sendall(f"{clean_domain}\r\n".encode('utf-8'))
                                ref_resp = b""
                                while not stopped():
                                    c = s2.recv(4096)
                                    if not c: break
                                    ref_resp += c
                                s2.close()
                                iana_text = ref_resp.decode('utf-8', errors='ignore')

                            yield f"data: ✅ SUCCESS: Active public registration records retrieved:\n\n"
                            for line in iana_text.splitlines():
                                if any(k in line.lower() for k in ['domain name:', 'registrar:', 'creation date:', 'expiry date:', 'name server:', 'status:', 'netname:', 'organization:']):
                                    yield f"data: 📋 {line.strip()}\n\n"
                    except Exception as ex:
                        yield f"data: ❌ REGISTRY EXCEPTION: Public lookup boundary timeout: {str(ex)}\n\n"

        # =========================================================================
        # FEATURE 6: STEALTH RANGE SCANNER
        # =========================================================================
        elif mode == 'scan':
            p = ports[0]
            yield f"data: 🕵️ Initializing Adaptive Firewall-Safe Stealth Octet Range Sweep across Port {p}...\n\n"
            
            prefix_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)', host.strip())
            subnet_base = prefix_match.group(1) if prefix_match else (host if host.endswith('.') else host + '.')
            
            yield f"data: Calibrated Subnet Prefix Scope: {subnet_base}{scan_start} through {subnet_base}{scan_end}\n\n"
            
            for last_octet in range(scan_start, scan_end + 1):
                if stopped(): break
                target_ip = f"{subnet_base}{last_octet}"
                time.sleep(random.uniform(0.18, 0.42))
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.4) 
                    rc = s.connect_ex((target_ip, p))
                    if rc == 0:
                        yield f"data: ✅ HOST DISCOVERED: {target_ip}:{p} actively responds as OPEN.\n\n"
                    s.close()
                except Exception: pass
            if not stopped():
                yield f"data: ✅ SUCCESS: Stealth sweeping run within targeted bounds finished processing.\n\n"

        # =========================================================================
        # FEATURE 7: MONITOR
        # =========================================================================
        elif mode == 'monitor':
            yield f"data: 📊 Launching Asynchronous Multi-Node Monitor Metrics Channel...\n\n"
            raw_nodes = monitor_targets_raw.replace(' ', '').replace('\\n', ',').replace('\\r', ',').split(',')
            nodes = [n.strip() for n in raw_nodes if n.strip()]
            
            if not nodes:
                yield "data: ❌ MONITOR CONFIG ERROR: Multi-target matrix definition fields are blank.\n\n"
                yield "data: [STREAM_COMPLETED_SIGNAL]\n\n"; return

            end_epoch = time.time() + (monitor_duration * 60)
            yield f"data: ℹ️ Active Nodes Mapped: {nodes}\n\n"
            yield f"data: 📢 CONCURRENCY STATUS: Threaded non-blocking engine running. Use ⏹ Stop to abort at any time.\n\n"
            yield f"data: --------------------------------------------------------------------------------\n\n"
            
            loop_idx = 1
            is_win = sys.platform == 'win32'
            while time.time() < end_epoch and not stopped():
                yield f"data: ⏱️ [POLLING LOOP INTERVAL RUN #{loop_idx}] Trace Telemetry Run...\n\n"
                for node in nodes:
                    if stopped(): break
                    if monitor_type == 'PING':
                        cmd = ["ping", "-n", "1", "-w", "800", node] if is_win else ["ping", "-c", "1", "-W", "1", node]
                        try:
                            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                            if res.returncode == 0 and "unreachable" not in res.stdout.lower() and "timed out" not in res.stdout.lower():
                                yield f"data: ✅ MONITOR STATUS: Node [{node}] -> Reachable via ICMP Echo Matrix.\n\n"
                            else:
                                yield f"data: ❌ MONITOR ALERT: Node [{node}] -> Target Host Unreachable.\n\n"
                        except: yield f"data: ❌ MONITOR ALERT: Node [{node}] -> Query Exception.\n\n"
                    else:
                        try:
                            chk_port = 443 if ":" not in node else int(node.split(':')[1])
                            chk_host = node if ":" not in node else node.split(':')[0]
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(1.0)
                            if s.connect_ex((chk_host, chk_port)) == 0:
                                yield f"data: ✅ MONITOR STATUS: Node [{chk_host}:{chk_port}] -> Handshake OPEN.\n\n"
                            else:
                                yield f"data: ❌ MONITOR ALERT: Node [{chk_host}:{chk_port}] -> Connection REFUSED.\n\n"
                            s.close()
                        except Exception as e: yield f"data: ❌ MONITOR ALERT: Node [{node}] -> Exception: {str(e)}\n\n"
                if not stopped():
                    yield f"data: --------------------------------------------------------------------------------\n\n"
                    loop_idx += 1
                    # Sleep in short chunks so stop_flag is checked promptly
                    for _ in range(monitor_interval * 5):
                        if stopped(): break
                        time.sleep(0.2)

            if stopped():
                yield f"data: ⏹ [ABORT] Monitor loop halted by operator after {loop_idx} polling cycle(s).\n\n"
            else:
                yield f"data: ✅ SUCCESS: Active monitoring window timeline satisfied. Pipeline channel parked.\n\n"

        # =========================================================================
        # FEATURE 8: BINARY SEARCH PMTU
        # =========================================================================
        elif mode == 'mtu':
            yield "data: 📐 Launching Smart Binary Search Path MTU Sweep and Analysis Engine...\n\n"
            is_win = sys.platform == 'win32'
            low, high = 1200, 1472
            exact_max_payload = None
            
            def ping_payload_check(payload_size):
                cmd = ["ping", "-n", "1", "-f", "-l", str(payload_size), host] if is_win else ["ping", "-c", "1", "-M", "do", "-s", str(payload_size), host]
                try:
                    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.5)
                    out = (res.stdout + res.stderr).lower()
                    return res.returncode == 0 and "fragment" not in out and "frag needed" not in out and "too long" not in out
                except: return False

            while low <= high and not stopped():
                mid = (low + high) // 2
                real_test_mtu = mid + 28
                yield f"data: ℹ️ Probing path boundary with unfragmentable payload size: {mid} Bytes (MTU equivalent = {real_test_mtu} Bytes)...\n\n"
                if ping_payload_check(mid):
                    exact_max_payload = mid
                    yield f"data: ✅ Size {real_test_mtu} passed transit validation without packet fragmentation.\n\n"
                    low = mid + 1
                else:
                    yield f"data: 📢 Size {real_test_mtu} dropped or flagged fragmentation block. Narrowing search downwards...\n\n"
                    high = mid - 1

            if stopped():
                yield "data: ⏹ [ABORT] MTU sweep halted by user.\n\n"
            elif exact_max_payload:
                final_passing_mtu = exact_max_payload + 28
                yield f"data: --------------------------------------------------------------------------------\n\n"
                yield f"data: 📊 PATH MTU SUMMARY ANALYTICS CALCULATION REPORT\n\n"
                yield f"data: ✅ Max Functional MTU:      {final_passing_mtu} Bytes (Payload: {exact_max_payload} Bytes)\n\n"
                yield f"data: ❌ Exact Point of Failure:  {final_passing_mtu + 1} Bytes started dropping\n\n"
                yield f"data: 📢 Calculated TCP MSS:      {final_passing_mtu - 40} Bytes (MTU - 40 Header Bytes)\n\n"
            else:
                yield f"data: ❌ FAILURE: Path block tracked. Entire payload search matrix below 1200 bytes dropped.\n\n"

        # =========================================================================
        # FEATURE 9: ENTERPRISE MTR
        # =========================================================================
        elif mode == 'mtr':
            yield "data: 🗺️ Starting Enterprise-Grade MTR Path Discovery Framework...\n\n"
            is_win = sys.platform == 'win32'
            trace_cmd = ["tracert", "-d", "-h", "15", host] if is_win else ["traceroute", "-n", "-m", "15", host]
            discovered_hops = []
            try:
                proc = subprocess.Popen(trace_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, shell=is_win)
                while not stopped():
                    line = proc.stdout.readline()
                    if not line: break
                    match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
                    if match and match.group(0) not in discovered_hops and match.group(0) != "0.0.0.0":
                        discovered_hops.append(match.group(0))
                        yield f"data: 🗺️ Discovered active routing path node: Hop #{len(discovered_hops)} -> {match.group(0)}\n\n"
                if stopped():
                    proc.terminate()
                else:
                    proc.wait()
            except Exception as e:
                yield f"data: ❌ ROUTING ERROR: Base structural traceroute mapping execution dropped: {str(e)}\n\n"
                yield "data: [STREAM_COMPLETED_SIGNAL]\n\n"; return

            if stopped():
                yield "data: ⏹ [ABORT] MTR path discovery halted by user.\n\n"
            else:
                if not discovered_hops: discovered_hops.append(host)
                yield f"data: --------------------------------------------------------------------------------\n\n"
                yield f"data: {'HOP':<5} | {'ROUTING NODE IP':<18} | {'LOSS %':<8} | {'MIN RTT':<10} | {'AVG RTT':<10} | {'MAX RTT':<10}\n\n"
                yield f"data: --------------------------------------------------------------------------------\n\n"

                for index, hop_ip in enumerate(discovered_hops, start=1):
                    if stopped(): break
                    probes_sent, loss_count, latencies = 5, 0, []
                    for _ in range(probes_sent):
                        if stopped(): break
                        time.sleep(0.02)
                        ping_cmd = ["ping", "-n", "1", "-w", "1000", hop_ip] if is_win else ["ping", "-c", "1", "-W", "1", hop_ip]
                        try:
                            p_start = time.perf_counter()
                            res = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                            if res.returncode == 0 and "unreachable" not in res.stdout.lower() and "timed out" not in res.stdout.lower():
                                rtt_match = re.search(r'(?:time[=<])\s*([\d\.]+)\s*ms', res.stdout.lower())
                                latencies.append(float(rtt_match.group(1)) if rtt_match else (time.perf_counter() - p_start) * 1000)
                            else: loss_count += 1
                        except: loss_count += 1

                    loss_pct = (loss_count / probes_sent) * 100
                    min_rtt = f"{min(latencies):.1f}ms" if latencies else "0.0ms"
                    avg_rtt = f"{(sum(latencies)/len(latencies)):.1f}ms" if latencies else "0.0ms"
                    max_rtt = f"{max(latencies):.1f}ms" if latencies else "0.0ms"
                    yield f"data: {index:<5} | {hop_ip:<18} | {loss_pct:<6.1f}% | {min_rtt:<10} | {avg_rtt:<10} | {max_rtt:<10}\n\n"

        # =========================================================================
        # FEATURE 10: LATENCY & JITTER
        # =========================================================================
        elif mode == 'latency':
            p = ports[0]
            yield f"data: Compiling high-frequency data array metrics using Port {p}...\n\n"
            rtts = []
            for i in range(1, 6):
                if stopped(): break
                time.sleep(0.05)
                start_time = time.perf_counter()
                try:
                    s = socket.create_connection((host, p), timeout=timeout)
                    rtts.append((time.perf_counter() - start_time) * 1000)
                    yield f"data: ℹ️ Echo Request Run #{i}: Connection RTT = {rtts[-1]:.2f} ms\n\n"
                    s.close()
                except Exception as ex:
                    yield f"data: ❌ Echo Request Run #{i}: Socket error: {str(ex)}\n\n"

            if rtts and not stopped():
                yield "data: ✅ PERFORMANCE METRICS COMPILED SUCCESSFULLY.\n\n"
                yield f"data: 📢 Metrics Mapped -> Min: {min(rtts):.2f}ms | Max: {max(rtts):.2f}ms | Avg: {sum(rtts)/len(rtts):.2f}ms | Delta Jitter: {max(rtts) - min(rtts):.2f}ms\n\n"

        # =========================================================================
        # FEATURE 11: SSH BANNER AUDIT
        # =========================================================================
        elif mode == 'ssh':
            if not stopped():
                p = ports[0]
                yield f"data: Extracting Layer-7 service identity string over Port {p}...\n\n"
                try:
                    s = socket.create_connection((host, p), timeout=timeout)
                    s.settimeout(2.5)
                    banner = s.recv(1024)
                    s.close()
                    if banner:
                        yield f"data: ✅ SUCCESS: Banner captured: '{banner.decode('utf-8', errors='ignore').strip()}'\n\n"
                    else:
                        yield "data: 📢 NOTICE: TCP channel open but returned empty strings.\n\n"
                except Exception as e:
                    yield f"data: 📢 SYSTEM NOTICE: Layer-7 verification processing bypassed or aborted: {str(e)}\n\n"

        # ── Final footer ─────────────────────────────────────────────────
        if stopped():
            yield f"data: --------------------------------------------------------------------------------\n\n"
            yield "data: ⏹ [ENGINE HALTED] Stream terminated early on operator request.\n\n"
        else:
            yield f"data: --------------------------------------------------------------------------------\n\n"
            yield "data: 🎉 All telemetry diagnostic iterations inside this engine stream scope completed.\n\n"

        yield "data: [STREAM_COMPLETED_SIGNAL]\n\n"

    return Response(engine_runtime_iterator(), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True, threaded=True)

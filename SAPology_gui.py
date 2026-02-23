#!/usr/bin/env python3
"""
SAPology GUI - Native desktop interface for the SAPology SAP Network Topology Scanner.

Uses a local HTTP server (Bottle) for the Python<->JS bridge and pywebview
(or a browser) to display the dashboard.

Launch with: python3 SAPology_gui.py
"""

import sys
import os
import io
import json
import re
import time
import threading
import tempfile
import webbrowser
import socket
from datetime import datetime

from bottle import Bottle, request, response, static_file

# Ensure SAPology.py is importable from the same directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import SAPology


# =============================================================================
# Console line buffer — OutputCapture pushes here, JS polls from here
# =============================================================================

_console_lines = []
_console_lock = threading.Lock()
_console_cursor = 0  # global cursor for the JS poller


def _add_console_line(ts, text, css_class="cl-info"):
    with _console_lock:
        _console_lines.append({"ts": ts, "text": text, "cls": css_class})


# =============================================================================
# OutputCapture — Redirect stdout to collect output lines
# =============================================================================

class OutputCapture(io.TextIOBase):
    """Intercept stdout and push lines to the shared console buffer."""

    def __init__(self, original_stdout):
        self.original = original_stdout
        self.buffer = ""
        self.lock = threading.Lock()

    def write(self, text):
        if self.original:
            try:
                self.original.write(text)
            except Exception:
                pass

        with self.lock:
            self.buffer += text
            while "\r" in self.buffer and "\n" not in self.buffer:
                idx = self.buffer.rfind("\r")
                self.buffer = self.buffer[idx + 1:]
            while "\n" in self.buffer:
                line, self.buffer = self.buffer.split("\n", 1)
                line = line.rstrip("\r")
                if line.strip():
                    self._push_line(line)
        return len(text)

    def _push_line(self, line):
        css_class = "cl-info"
        if line.lstrip().startswith("[+]") or "detected" in line.lower():
            css_class = "cl-ok"
        elif line.lstrip().startswith("[-]") or "error" in line.lower():
            css_class = "cl-err"
        elif line.lstrip().startswith("[!]"):
            css_class = "cl-warn"
        elif line.lstrip().startswith("===") or line.lstrip().startswith("---"):
            css_class = "cl-dim"

        escaped = (line
                   .replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;"))

        ts = datetime.now().strftime("%H:%M:%S")
        _add_console_line(ts, escaped, css_class)

    def flush(self):
        with self.lock:
            stripped = self.buffer.strip().rstrip("\r")
            if stripped:
                self._push_line(stripped)
                self.buffer = ""
        if self.original:
            try:
                self.original.flush()
            except Exception:
                pass

    def isatty(self):
        return False


# =============================================================================
# SAPologyApi — Scan controller (used by Bottle routes)
# =============================================================================

class SAPologyApi:
    """Backend controller for the SAPology scanner."""

    def __init__(self):
        self.scan_thread = None
        self.landscape = []
        self.btp_results = None
        self.scan_running = False
        self.scan_cancelled = False
        self.scan_start_time = 0
        self.scan_duration = 0
        self.scan_params = {}
        self.scan_state = "idle"  # idle, running, complete, cancelled, error
        self.scan_error = ""

    def start_scan(self, config):
        # Wait briefly for previous scan thread to finish if state shows done
        if self.scan_running and self.scan_thread and self.scan_thread.is_alive():
            if self.scan_state in ("complete", "cancelled", "error"):
                self.scan_thread.join(timeout=2)
            else:
                return {"error": "Scan already running"}

        self.scan_cancelled = False
        self.scan_running = True
        self.scan_state = "running"
        self.scan_error = ""
        self.landscape = []
        self.btp_results = None
        self.scan_duration = 0

        # Clear console
        global _console_lines, _console_cursor
        with _console_lock:
            _console_lines = []
            _console_cursor = 0

        self.scan_thread = threading.Thread(
            target=self._run_scan, args=(config,), daemon=True)
        self.scan_thread.start()

        return {"status": "started"}

    def stop_scan(self):
        self.scan_cancelled = True
        return {"status": "cancel_requested"}

    def get_results(self):
        if not self.landscape and not self.btp_results:
            return {"systems": [], "btp_endpoints": [],
                    "btp_summary": None, "summary": self._empty_summary()}

        systems = []
        for s in self.landscape:
            systems.append(s.to_dict())

        btp_endpoints = []
        btp_summary = None
        if self.btp_results:
            btp_endpoints = [ep.to_dict() for ep in self.btp_results.endpoints]
            btp_summary = self.btp_results.summary()

        return {
            "systems": systems,
            "btp_endpoints": btp_endpoints,
            "btp_summary": btp_summary,
            "summary": self._compute_summary(),
            "scan_duration": self.scan_duration,
            "scan_params": self.scan_params,
        }

    def get_status(self):
        elapsed = 0
        if self.scan_running:
            elapsed = time.time() - self.scan_start_time
        elif self.scan_duration > 0:
            elapsed = self.scan_duration

        m = int(elapsed // 60)
        s = int(elapsed % 60)

        return {
            "state": self.scan_state,
            "running": self.scan_running,
            "cancelled": self.scan_cancelled,
            "elapsed": "%02d:%02d" % (m, s),
            "systems_found": len(self.landscape),
            "error": self.scan_error,
        }

    def export_html_report(self):
        if not self.landscape and not self.btp_results:
            return {"error": "No scan results to export"}

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        has_onprem = bool(self.landscape)
        has_btp = bool(self.btp_results and self.btp_results.endpoints)
        if has_onprem and has_btp:
            prefix = "SAPology_Full"
        elif has_btp:
            prefix = "SAPology_BTP"
        else:
            prefix = "SAPology"
        output_path = os.path.join(os.getcwd(), "%s_%s.html" % (prefix, ts))

        SAPology.generate_html_report(
            self.landscape, output_path,
            self.scan_duration, self.scan_params,
            btp_results=self.btp_results)

        return {"path": output_path}

    def export_json(self):
        if not self.landscape and not self.btp_results:
            return {"error": "No scan results to export"}

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        has_onprem = bool(self.landscape)
        has_btp = bool(self.btp_results and self.btp_results.endpoints)
        if has_onprem and has_btp:
            prefix = "SAPology_Full"
        elif has_btp:
            prefix = "SAPology_BTP"
        else:
            prefix = "SAPology"
        output_path = os.path.join(os.getcwd(), "%s_%s.json" % (prefix, ts))

        SAPology.generate_json_export(self.landscape, output_path,
                                      btp_results=self.btp_results)

        return {"path": output_path}

    # --- Internal methods ---

    def _run_scan(self, config):
        capture = OutputCapture(sys.stdout)
        sys.stdout = capture

        original_has_rich = SAPology.HAS_RICH
        SAPology.HAS_RICH = False
        SAPology.VERBOSE = config.get("verbose", False)

        self.scan_start_time = time.time()

        try:
            targets = SAPology.parse_targets(
                config.get("targets", ""),
                config.get("target_file", "") or None)

            # Detect BTP mode
            btp_target = config.get("btp_target", "")
            btp_keyword = config.get("btp_keyword", "")
            btp_domain = config.get("btp_domain", "")
            btp_subaccount = config.get("btp_subaccount", "")
            btp_targets_file = config.get("btp_targets_file", "")
            has_btp = bool(btp_target or btp_keyword or btp_domain
                          or btp_subaccount or btp_targets_file)

            if not targets and not has_btp:
                self.scan_state = "error"
                self.scan_error = "No valid targets specified"
                self.scan_running = False
                return

            instances = SAPology.parse_instance_range(
                config.get("instances", "00-99"))

            timeout_val = int(config.get("timeout", 3))
            threads_val = int(config.get("threads", 20))

            self.scan_params = {
                "targets": targets,
                "instances": ["%02d" % i for i in instances],
                "timeout": timeout_val,
                "threads": threads_val,
                "gw_test_cmd": config.get("gw_cmd", "whoami"),
                "url_scan": config.get("url_scan", True),
                "url_scan_threads": int(config.get("url_scan_threads", 25)),
                "verbose": config.get("verbose", False),
            }

            # On-prem phases (only if targets provided)
            if targets:
                # Phase 1: Discovery
                print("\n" + "=" * 60)
                print(" Phase 1: System Discovery & Fingerprinting")
                print("=" * 60 + "\n")

                self.landscape = SAPology.discover_systems(
                    targets, instances, timeout_val, threads_val,
                    config.get("verbose", False),
                    cancel_check=lambda: self.scan_cancelled)

                if self.scan_cancelled:
                    print("\n[!] Scan cancelled by user")
                    self.scan_state = "cancelled"
                    self.scan_running = False
                    return

                # Phase 2: Vulnerability Assessment
                if config.get("vuln_assess", True) and self.landscape:
                    if self.scan_cancelled:
                        print("\n[!] Scan cancelled by user")
                        self.scan_state = "cancelled"
                        self.scan_running = False
                        return

                    print("\n" + "=" * 60)
                    print(" Phase 2: Vulnerability Assessment")
                    print("=" * 60 + "\n")

                    self.landscape = SAPology.assess_vulnerabilities(
                        self.landscape,
                        gw_cmd=config.get("gw_cmd", "whoami"),
                        timeout=timeout_val + 2,
                        verbose=config.get("verbose", False),
                        url_scan=config.get("url_scan", True),
                        url_scan_threads=int(config.get("url_scan_threads", 25)),
                        cancel_check=lambda: self.scan_cancelled)

                if self.scan_cancelled:
                    print("\n[!] Scan cancelled by user")
                    self.scan_state = "cancelled"
                    self.scan_running = False
                    return

            # BTP Cloud Scanning Phase
            if has_btp and not self.scan_cancelled:
                print("\n" + "=" * 60)
                print(" BTP Cloud Scanning")
                print("=" * 60)
                try:
                    import SAPology_btp
                    from SAPology_btp import BTPScanner
                    SAPology_btp.HAS_RICH = False
                    btp_config = {
                        "target": btp_target,
                        "keyword": btp_keyword,
                        "domain": btp_domain,
                        "subaccount": btp_subaccount,
                        "targets_file": btp_targets_file or None,
                        "regions": config.get("btp_regions", "all"),
                        "skip_ct": config.get("btp_skip_ct", False),
                        "skip_vuln": config.get("btp_skip_vuln", False),
                        "shodan_key": config.get("btp_shodan_key", ""),
                        "censys_id": config.get("btp_censys_id", ""),
                        "censys_secret": config.get("btp_censys_secret", ""),
                        "verbose": config.get("verbose", False),
                        "threads": threads_val,
                        "timeout": timeout_val,
                        "cancel_check": lambda: self.scan_cancelled,
                    }
                    btp_scanner = BTPScanner(btp_config)
                    self.btp_results = btp_scanner.run()
                except ImportError:
                    print("[-] SAPology_btp.py not found - BTP scanning unavailable")
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                    print("[-] BTP scanning error: %s" % e)

            if self.scan_cancelled:
                print("\n[!] Scan cancelled by user")
                self.scan_state = "cancelled"
                self.scan_running = False
                return

            self.scan_duration = time.time() - self.scan_start_time

            dur_m = int(self.scan_duration // 60)
            dur_s = int(self.scan_duration % 60)
            print("\n[+] Scan complete in %d:%02d" % (dur_m, dur_s))

            total_findings = sum(len(s.all_findings()) for s in self.landscape)
            critical = sum(1 for s in self.landscape
                          for f in s.all_findings()
                          if f.severity == SAPology.Severity.CRITICAL)
            print("[+] %d system(s), %d finding(s) (%d critical)" % (
                len(self.landscape), total_findings, critical))

            self.scan_state = "complete"

        except Exception as e:
            import traceback
            traceback.print_exc()
            self.scan_state = "error"
            self.scan_error = str(e)
        finally:
            self.scan_running = False
            sys.stdout = capture.original
            SAPology.HAS_RICH = original_has_rich

    def _compute_summary(self):
        total_systems = len(self.landscape)
        total_ports = sum(
            len(inst.ports) for s in self.landscape for inst in s.instances)
        all_findings = []
        for s in self.landscape:
            all_findings.extend(s.all_findings())

        critical = sum(1 for f in all_findings if f.severity == SAPology.Severity.CRITICAL)
        high = sum(1 for f in all_findings if f.severity == SAPology.Severity.HIGH)
        medium = sum(1 for f in all_findings if f.severity == SAPology.Severity.MEDIUM)
        low = sum(1 for f in all_findings if f.severity == SAPology.Severity.LOW)
        info = sum(1 for f in all_findings if f.severity == SAPology.Severity.INFO)

        btp_endpoints_count = 0
        btp_finding_count = 0
        if self.btp_results:
            btp_endpoints_count = sum(1 for ep in self.btp_results.endpoints if ep.alive)
            for ep in self.btp_results.endpoints:
                for f in ep.findings:
                    btp_finding_count += 1
                    sev = int(f.severity)
                    if sev == 0:
                        critical += 1
                    elif sev == 1:
                        high += 1
                    elif sev == 2:
                        medium += 1
                    elif sev == 3:
                        low += 1
                    else:
                        info += 1

        return {
            "total_systems": total_systems,
            "total_ports": total_ports,
            "total_findings": len(all_findings) + btp_finding_count,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "btp_endpoints": btp_endpoints_count,
        }

    def _empty_summary(self):
        return {
            "total_systems": 0, "total_ports": 0, "total_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "btp_endpoints": 0,
        }


# =============================================================================
# Bottle HTTP Server with API routes
# =============================================================================

api = SAPologyApi()
app = Bottle()


@app.route('/')
def index():
    response.content_type = 'text/html; charset=utf-8'
    return GUI_HTML


@app.post('/api/start_scan')
def route_start_scan():
    response.content_type = 'application/json'
    config = request.json or {}
    return json.dumps(api.start_scan(config))


@app.post('/api/stop_scan')
def route_stop_scan():
    response.content_type = 'application/json'
    return json.dumps(api.stop_scan())


@app.get('/api/results')
def route_results():
    response.content_type = 'application/json'
    return json.dumps(api.get_results(), default=str)


@app.get('/api/status')
def route_status():
    response.content_type = 'application/json'
    return json.dumps(api.get_status())


@app.get('/api/console')
def route_console():
    """Return new console lines since the given cursor."""
    response.content_type = 'application/json'
    cursor = int(request.params.get('cursor', 0))
    with _console_lock:
        lines = _console_lines[cursor:]
        new_cursor = len(_console_lines)
    return json.dumps({"lines": lines, "cursor": new_cursor})


@app.post('/api/open_url')
def route_open_url():
    """Open a URL in the system's default browser."""
    response.content_type = 'application/json'
    data = request.json or {}
    url = data.get("url", "")
    if url:
        import webbrowser
        webbrowser.open(url)
        return json.dumps({"status": "ok"})
    return json.dumps({"error": "no url"})


@app.post('/api/export_html')
def route_export_html():
    response.content_type = 'application/json'
    return json.dumps(api.export_html_report())


@app.post('/api/export_json')
def route_export_json():
    response.content_type = 'application/json'
    return json.dumps(api.export_json())


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


# =============================================================================
# Embedded HTML/CSS/JS GUI
# =============================================================================

GUI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SAPology</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }

  :root {
    --bg: #1a1d23;
    --bg-surface: #22262e;
    --bg-card: #2a2e37;
    --bg-hover: #32363f;
    --border: #3a3e47;
    --border-light: #44485a;
    --accent: #4a9eff;
    --accent-dim: #2a6ecc;
    --accent-glow: rgba(74,158,255,0.15);
    --text: #e8eaed;
    --text-secondary: #9aa0a8;
    --text-dim: #6b7280;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #3b82f6;
    --info: #6b7280;
    --success: #22c55e;
  }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    min-height: 100vh;
    overflow: hidden;
  }

  /* Navbar */
  .navbar {
    background: linear-gradient(180deg, #282c34 0%, #1e2128 100%);
    border-bottom: 1px solid var(--border);
    height: 64px;
    display: flex;
    align-items: center;
    padding: 0 24px;
    gap: 32px;
  }
  .nav-brand {
    display: flex;
    align-items: baseline;
    gap: 0;
    font-size: 20px;
    font-weight: 700;
    white-space: nowrap;
    font-family: 'Consolas', 'JetBrains Mono', 'Courier New', monospace;
  }
  .nav-brand .bracket { color: var(--text-dim); }
  .nav-brand .sap { color: #00ff41; text-shadow: 0 0 12px rgba(0,255,65,0.3); }
  .nav-brand .ology { color: #00ff41; text-shadow: 0 0 12px rgba(0,255,65,0.3); }

  .nav-tagline {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 0;
    font-family: 'Consolas', 'JetBrains Mono', 'Courier New', monospace;
    line-height: 1.2;
  }
  .nav-tagline .tl-top { font-size: 10px; color: var(--text-dim); letter-spacing: 0.5px; }
  .nav-tagline .tl-top .tl-sorry { opacity: 0.4; font-style: italic; }
  .nav-tagline .tl-mid { font-size: 9px; color: #00ff41; opacity: 0.35; }
  .nav-tagline .tl-bot { font-size: 9px; color: var(--text-dim); opacity: 0.3; letter-spacing: 0.3px; }
  .nav-tagline .tl-author { font-size: 9px; color: var(--text-dim); opacity: 0.5; }

  .nav-tab { padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; color: var(--text-secondary); transition: all 0.15s; }
  .nav-tab.active { background: var(--accent); color: white; }
  .nav-tab:hover:not(.active) { background: var(--bg-hover); }

  .nav-spacer { flex: 1; }
  .nav-status { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--text-secondary); }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--success); }

  /* Layout */
  .layout { display: flex; height: calc(100vh - 64px); }

  /* Sidebar */
  .sidebar {
    width: 300px;
    min-width: 300px;
    background: var(--bg-surface);
    border-right: 1px solid var(--border);
    padding: 20px 16px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .section-title { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: var(--text-dim); margin-bottom: 10px; }

  .field-label { font-size: 12px; color: var(--text-secondary); margin-bottom: 4px; }
  .field-input {
    width: 100%;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 12px;
    color: var(--text);
    font-size: 13px;
    outline: none;
    transition: border-color 0.15s;
  }
  .field-input:focus { border-color: var(--accent); }
  .field-input::placeholder { color: var(--text-dim); }
  .field-row { display: flex; gap: 10px; margin-bottom: 10px; }
  .field-group { flex: 1; margin-bottom: 10px; }

  /* Number inputs */
  input[type="number"] { -moz-appearance: textfield; }
  input[type="number"]::-webkit-inner-spin-button,
  input[type="number"]::-webkit-outer-spin-button { opacity: 1; }

  /* Toggle */
  .toggle-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; font-size: 13px; color: var(--text-secondary); }
  .toggle-switch {
    width: 36px; height: 20px; border-radius: 10px;
    background: var(--border); cursor: pointer; position: relative; transition: background 0.2s;
  }
  .toggle-switch::after {
    content: ''; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px;
    border-radius: 50%; background: var(--text-dim); transition: all 0.2s;
  }
  .toggle-switch.on { background: var(--accent); }
  .toggle-switch.on::after { left: 18px; background: white; }

  /* Buttons */
  .btn-scan {
    width: 100%;
    padding: 12px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    border: none;
    background: linear-gradient(135deg, var(--accent) 0%, var(--accent-dim) 100%);
    color: white;
    transition: all 0.15s;
  }
  .btn-scan:hover { filter: brightness(1.1); transform: translateY(-1px); }
  .btn-scan:active { transform: translateY(0); }
  .btn-scan svg { width: 18px; height: 18px; }
  .btn-scan.scanning { background: linear-gradient(135deg, var(--critical) 0%, #dc2626 100%); }

  .btn-export-row { display: flex; gap: 8px; margin-top: 10px; }
  .btn-export {
    flex: 1; padding: 8px; border-radius: 6px;
    font-size: 12px; font-weight: 500; cursor: pointer;
    border: 1px solid var(--border); background: var(--bg-card); color: var(--text-secondary);
    transition: all 0.15s;
  }
  .btn-export:hover { background: var(--bg-hover); border-color: var(--accent); color: var(--text); }

  /* Content area */
  .content {
    flex: 1;
    padding: 20px 24px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  /* Summary cards */
  .summary-cards { display: flex; gap: 12px; }
  .summary-card {
    flex: 1;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px 18px;
    position: relative;
    overflow: hidden;
  }
  .summary-card .sc-value {
    font-size: 28px;
    font-weight: 700;
    font-family: 'Consolas', 'JetBrains Mono', monospace;
    color: var(--text);
  }
  .summary-card .sc-label { font-size: 12px; color: var(--text-secondary); margin-top: 4px; }
  .summary-card .sc-bar { position: absolute; top: 0; left: 0; right: 0; height: 3px; border-radius: 8px 8px 0 0; }
  .sc-blue .sc-bar { background: var(--accent); }
  .sc-green .sc-bar { background: var(--success); }
  .sc-red .sc-bar { background: var(--critical); }
  .sc-orange .sc-bar { background: var(--high); }
  .sc-yellow .sc-bar { background: var(--medium); }
  .sc-low .sc-bar { background: var(--low); }
  .sc-info .sc-bar { background: var(--info); }

  /* Panel */
  .panel { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; }
  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 18px;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
    font-size: 15px;
  }
  .panel-body { padding: 12px 18px; min-height: 100px; }
  .badge { font-size: 11px; padding: 3px 10px; border-radius: 12px; background: var(--bg-surface); color: var(--text-secondary); border: 1px solid var(--border); }

  .empty-state {
    text-align: center;
    color: var(--text-dim);
    padding: 32px;
    font-size: 13px;
  }

  /* Systems */
  .sys-row {
    display: flex;
    align-items: center;
    padding: 10px 12px;
    border-radius: 6px;
    cursor: pointer;
    transition: background 0.1s;
    gap: 12px;
  }
  .sys-row:hover { background: var(--bg-hover); }
  .sys-icon {
    width: 40px;
    height: 40px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 10px;
    font-weight: 700;
    color: white;
    flex-shrink: 0;
  }
  .sys-icon.abap { background: linear-gradient(135deg, #1a6dff 0%, #0050cc 100%); }
  .sys-icon.java { background: linear-gradient(135deg, #f97316 0%, #ea580c 100%); }
  .sys-icon.mdm { background: linear-gradient(135deg, #a855f7 0%, #7c3aed 100%); }
  .sys-icon.unknown { background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%); }
  .sys-icon.btp { background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%); }

  .sys-info { flex: 1; min-width: 0; }
  .sys-name { font-weight: 600; font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .sys-meta { font-size: 11px; color: var(--text-dim); margin-top: 2px; }

  .sys-badges { display: flex; gap: 4px; }
  .mini-badge {
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 8px;
    font-weight: 600;
    color: white;
  }
  .mb-critical { background: var(--critical); }
  .mb-high { background: var(--high); }
  .mb-medium { background: var(--medium); }
  .sys-chevron { color: var(--text-dim); font-size: 18px; padding-left: 8px; }

  /* Severity chart */
  .chart-container { display: flex; flex-direction: column; align-items: center; padding: 12px 16px; }
  #severity-chart {
    width: 120px;
    height: 120px;
    border-radius: 50%;
    background: var(--border);
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
    flex-shrink: 0;
  }
  .ring-inner {
    width: 72px;
    height: 72px;
    border-radius: 50%;
    background: var(--bg-card);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    z-index: 1;
  }
  .ring-inner .ring-num { font-size: 24px; }
  .ring-inner .ring-label { font-size: 9px; color: var(--text-dim); }

  .chart-legend { display: flex; flex-wrap: wrap; gap: 4px 12px; margin-top: 10px; justify-content: center; }
  .legend-item { display: flex; align-items: center; gap: 5px; font-size: 11px; color: var(--text-secondary); }
  .legend-dot { width: 10px; height: 10px; border-radius: 3px; }

  /* Findings */
  .finding-row {
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    transition: background 0.1s;
  }
  .finding-row:last-child { border-bottom: none; }
  .finding-row:hover { background: var(--bg-hover); }
  .finding-row-top { display: flex; align-items: center; gap: 10px; }
  .finding-sev {
    font-size: 10px;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 4px;
    color: white;
    min-width: 56px;
    text-align: center;
  }
  .fs-critical { background: var(--critical); }
  .fs-high { background: var(--high); }
  .fs-medium { background: var(--medium); color: #1a1d23; }
  .fs-low { background: var(--low); }
  .fs-info { background: var(--info); }
  .finding-name { flex: 1; font-size: 13px; font-weight: 500; }
  .finding-target { font-size: 11px; color: var(--text-dim); }
  .finding-arrow { color: var(--text-dim); transition: transform 0.15s; }
  .finding-row.expanded .finding-arrow { transform: rotate(90deg); }

  .finding-details {
    display: none;
    padding: 12px;
    background: var(--bg-surface);
    border-radius: 0 0 6px 6px;
    margin: 0 4px 8px;
  }
  .finding-row.expanded + .finding-details { display: block; }
  .fd-section { margin-bottom: 12px; }
  .fd-section:last-child { margin-bottom: 0; }
  .fd-label { font-size: 11px; font-weight: 600; color: var(--accent); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
  .fd-text { font-size: 12px; color: var(--text-secondary); line-height: 1.5; }

  /* Grid layout for main panels */
  .grid-row { display: flex; gap: 20px; }
  .grid-row .panel { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .grid-row .panel .panel-body { flex: 1; min-height: 0; }
  .grid-row .panel.wide { flex: 1.5; }

  /* Progress bar */
  .progress-bar {
    height: 32px;
    background: var(--bg-surface);
    border-top: 1px solid var(--border);
    display: flex;
    align-items: center;
    padding: 0 16px;
    gap: 12px;
    font-size: 12px;
    color: var(--text-dim);
    position: relative;
  }
  .progress-track { flex: 1; height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; }
  .progress-fill { height: 100%; width: 0%; background: var(--accent); border-radius: 2px; transition: width 0.4s ease; }
  @keyframes pulse-bar { 0%,100% { opacity: 0.7; } 50% { opacity: 1; } }

  /* Console */
  .console-toggle {
    position: fixed;
    bottom: 32px;
    right: 16px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    color: var(--text-secondary);
    padding: 6px 14px;
    border-radius: 6px 6px 0 0;
    cursor: pointer;
    font-size: 12px;
    z-index: 999;
    transition: all 0.15s;
  }
  .console-toggle:hover { color: var(--text); background: var(--bg-hover); }
  .console-toggle.open { bottom: 232px; }

  .console-panel {
    position: fixed;
    bottom: 32px;
    left: 0;
    right: 0;
    height: 200px;
    background: #0d1117;
    border-top: 1px solid var(--border);
    transform: translateY(200px);
    transition: transform 0.25s ease;
    z-index: 998;
    display: flex;
    flex-direction: column;
  }
  .console-panel.open { transform: translateY(0); }
  .console-panel.maximized { height: calc(100vh - 96px); }
  .console-toggle.maximized { bottom: calc(100vh - 64px); }
  .console-header { padding: 6px 16px; font-size: 11px; color: var(--text-dim); border-bottom: 1px solid #1c2333; display: flex; justify-content: space-between; align-items: center; }
  .console-header .console-actions { display: flex; gap: 12px; }
  .console-header .console-actions span { cursor: pointer; opacity: 0.7; transition: opacity 0.15s; font-size: 13px; }
  .console-header .console-actions span:hover { opacity: 1; color: var(--text); }
  .console-header .console-actions span#consoleMaxBtn { font-size: 16px; line-height: 1; padding: 0 2px; }
  .console-body {
    flex: 1;
    overflow-y: auto;
    padding: 8px 16px;
    font-family: 'Consolas', 'JetBrains Mono', 'Courier New', monospace;
    font-size: 12px;
    line-height: 1.6;
  }
  .console-line { white-space: pre-wrap; word-break: break-all; }
  .cl-time { color: #4a5568; }
  .cl-info { color: #9ca3af; }
  .cl-ok { color: #22c55e; }
  .cl-warn { color: #eab308; }
  .cl-err { color: #ef4444; }
  .cl-dim { color: #4a5568; }

  /* Help button */
  .nav-help { width: 26px; height: 26px; border-radius: 50%; background: var(--bg-surface); border: 1px solid var(--border); color: var(--text-dim); font-size: 14px; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; margin-right: 12px; }
  .nav-help:hover { color: var(--accent); border-color: var(--accent); }

  /* Help modal */
  .help-modal .modal-content { width: 900px; max-height: 85vh; }
  .help-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 8px; }
  .help-table th { text-align: left; padding: 6px 8px; border-bottom: 2px solid var(--border); color: var(--accent); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
  .help-table td { padding: 5px 8px; border-bottom: 1px solid var(--border); color: var(--text-secondary); }
  .help-table td:first-child { color: var(--text); font-weight: 500; white-space: nowrap; }
  .help-table .sev-crit { color: #ef4444; font-weight: 600; }
  .help-table .sev-high { color: #f97316; font-weight: 600; }
  .help-table .sev-med { color: #eab308; }
  .help-table .sev-low { color: #3b82f6; }
  .help-table .sev-info { color: #6b7280; }
  .help-note { font-size: 11px; color: var(--text-dim); margin-top: 16px; padding: 10px; border: 1px solid var(--border); border-radius: 6px; }

  /* Modal */
  .modal-overlay {
    display: none;
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.6);
    z-index: 1000;
    align-items: center;
    justify-content: center;
  }
  .modal-overlay.open { display: flex; }
  .modal-content {
    width: 700px;
    max-height: 80vh;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }
  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
  }
  .modal-title { font-weight: 600; font-size: 16px; display: flex; align-items: center; gap: 10px; }
  .modal-close { font-size: 24px; cursor: pointer; color: var(--text-dim); padding: 0 4px; }
  .modal-close:hover { color: var(--text); }
  .modal-body { padding: 20px; overflow-y: auto; flex: 1; }
  .modal-section { margin-bottom: 20px; }
  .modal-section h4 { font-size: 13px; color: var(--accent); margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px; }
  .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .info-item { padding: 8px 12px; background: var(--bg-surface); border-radius: 6px; }
  .ik { font-size: 10px; color: var(--text-dim); display: block; text-transform: uppercase; letter-spacing: 0.5px; }
  .iv { font-size: 13px; color: var(--text); font-weight: 500; }

  .modal-ports { list-style: none; display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 4px; }
  .modal-ports li { display: flex; align-items: center; gap: 8px; padding: 6px 10px; background: var(--bg-surface); border-radius: 4px; font-size: 12px; }
  .mp-port { font-family: monospace; font-weight: 600; color: var(--accent); min-width: 50px; }
  .mp-svc { color: var(--text-secondary); }

  .modal-finding { border: 1px solid var(--border); border-radius: 6px; margin-bottom: 6px; overflow: hidden; }
  .mf-top { display: flex; align-items: center; gap: 10px; padding: 8px 12px; cursor: pointer; }
  .mf-top:hover { background: var(--bg-hover); }

  /* View containers (tab switching) */
  .view-container { display: none; flex-direction: column; gap: 20px; flex: 1; }
  .view-container.active { display: flex; }

  /* URL scan view */
  .url-summary-bar { display: flex; gap: 16px; flex-wrap: wrap; align-items: center; }
  .url-stat { font-size: 13px; color: var(--text-secondary); }
  .url-stat strong { color: var(--text); font-size: 15px; }
  .url-search { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 6px; padding: 6px 12px; color: var(--text); font-size: 12px; width: 220px; outline: none; }
  .url-search:focus { border-color: var(--accent); }
  .url-search::placeholder { color: var(--text-dim); }
  .url-view-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .url-view-table th { text-align: left; padding: 8px 10px; font-size: 10px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); background: var(--bg-surface); position: sticky; top: 0; z-index: 1; }
  .url-view-table td { padding: 6px 10px; border-bottom: 1px solid var(--border); color: var(--text-secondary); }
  .url-view-table tr:hover td { background: var(--bg-hover); }
  .url-view-table td:nth-child(4) { font-family: 'Consolas', 'JetBrains Mono', monospace; word-break: break-all; color: var(--text); }
  .nav-tab .tab-badge { font-size: 11px; opacity: 0.7; font-weight: 400; }

  /* URL scan results table (modal) */
  .url-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .url-table th { text-align: left; padding: 6px 8px; font-size: 10px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); }
  .url-table td { padding: 5px 8px; border-bottom: 1px solid var(--border); color: var(--text-secondary); }
  .url-table tr:last-child td { border-bottom: none; }
  .url-table tr:hover td { background: var(--bg-hover); }
  .url-table .url-path { font-family: monospace; color: var(--text); word-break: break-all; }
  .url-status { display: inline-block; min-width: 28px; text-align: center; padding: 1px 6px; border-radius: 4px; font-weight: 600; font-size: 11px; }
  .url-status.s2xx { background: rgba(34,197,94,0.15); color: var(--success); }
  .url-status.s3xx { background: rgba(74,158,255,0.15); color: var(--accent); }
  .url-status.s401 { background: rgba(249,115,22,0.15); color: var(--high); }
  .url-status.s403 { background: rgba(234,179,8,0.15); color: var(--medium); }
  .url-status.s5xx { background: rgba(239,68,68,0.15); color: var(--critical); }
  .url-tamper { font-size: 10px; padding: 1px 5px; border-radius: 3px; background: rgba(239,68,68,0.2); color: var(--critical); font-weight: 600; }
  .url-filter-row { display: flex; gap: 6px; margin-bottom: 8px; flex-wrap: wrap; }
  .url-filter-btn { padding: 3px 10px; border-radius: 4px; border: 1px solid var(--border); background: var(--bg-surface); color: var(--text-secondary); font-size: 11px; cursor: pointer; }
  .url-filter-btn:hover, .url-filter-btn.active { border-color: var(--accent); color: var(--accent); }
  .url-link { color: var(--accent); text-decoration: none; font-family: 'Consolas', 'JetBrains Mono', monospace; word-break: break-all; cursor: pointer; }
  .url-link:hover { text-decoration: underline; color: #6db3ff; }
  .mf-name { flex: 1; font-size: 13px; font-weight: 500; }
  .mf-body { display: none; padding: 10px 12px; font-size: 12px; color: var(--text-secondary); line-height: 1.6; border-top: 1px solid var(--border); background: var(--bg-surface); }
  .modal-finding.open .mf-body { display: block; }
</style>
</head>
<body>

<!-- Navbar -->
<div class="navbar">
  <div class="nav-brand">
    <span class="bracket">[</span><span class="sap">SAP</span><span class="ology">ology</span><span class="bracket">]</span>
  </div>
  <div class="nav-tab active" onclick="switchTab('dashboard')">Dashboard</div>
  <div class="nav-tab" id="tab-urlscan" onclick="switchTab('urlscan')">URL Scan</div>
  <div class="nav-tab" id="tab-btp" onclick="switchTab('btp')" style="display:none;">BTP Cloud</div>
  <div class="nav-spacer"></div>
  <div class="nav-help" onclick="toggleHelpModal()" title="Vulnerability Checks">?</div>
  <div class="nav-status" id="nav-status">
    <span class="dot" style="background:var(--success);"></span> Ready
  </div>
  <div class="nav-tagline">
    <span class="tl-top">SAP Network Topology <span class="tl-sorry">&middot;&middot;&middot; Sorry for scanning you ;-)</span></span>
    <span class="tl-mid">&#9961; The scanner that speaks SAPanese</span>
    <span class="tl-bot">DIAG &middot; RFC &middot; Gateway &middot; MS &middot; ICM &middot; J2EE &middot; BTP Cloud</span>
    <span class="tl-author">by Joris van de Vis</span>
  </div>
</div>

<div class="layout">

  <!-- Sidebar -->
  <div class="sidebar">
    <div>
      <div class="section-title">TARGETS</div>
      <div class="field-group">
        <div class="field-label">Target(s)</div>
        <input type="text" class="field-input" id="input-targets" placeholder="IP, CIDR, or comma-separated" onkeydown="if(event.key==='Enter')startScan()">
      </div>
      <div class="field-group">
        <div class="field-label">Target File</div>
        <input type="text" class="field-input" id="input-target-file" placeholder="Path to targets file...">
      </div>
      <div class="field-group">
        <div class="field-label">Instance Range</div>
        <input type="text" class="field-input" id="input-instances" value="00-99">
      </div>
    </div>

    <div>
      <div class="section-title">OPTIONS</div>
      <div class="field-row">
        <div class="field-group">
          <div class="field-label">Threads</div>
          <input type="number" class="field-input" id="input-threads" value="20" min="1" max="200">
        </div>
        <div class="field-group">
          <div class="field-label">Timeout (s)</div>
          <input type="number" class="field-input" id="input-timeout" value="3" min="1" max="30">
        </div>
      </div>
      <div class="field-group">
        <div class="field-label">URL Scan Threads</div>
        <input type="number" class="field-input" id="input-url-threads" value="25" min="1" max="100">
      </div>
      <div class="field-group">
        <div class="field-label">GW Test Command</div>
        <input type="text" class="field-input" id="input-gw-cmd" value="whoami">
      </div>
    </div>

    <div>
      <div class="section-title">FEATURES</div>
      <div class="toggle-row">Vulnerability Assessment <div class="toggle-switch on" id="toggle-vuln" onclick="this.classList.toggle('on')"></div></div>
      <div class="toggle-row">URL Scanning <div class="toggle-switch on" id="toggle-url-scan" onclick="this.classList.toggle('on')"></div></div>
      <div class="toggle-row">Verbose Output <div class="toggle-switch" id="toggle-verbose" onclick="this.classList.toggle('on')"></div></div>
    </div>

    <div>
      <div class="section-title" style="cursor:pointer;" onclick="toggleBtpSection()">BTP CLOUD <span id="btp-section-arrow" style="float:right;font-size:9px;opacity:0.5;">&#9660;</span></div>
      <div id="btp-section-body" style="display:none;">
        <div class="field-group">
          <div class="field-label">BTP Target(s)</div>
          <input type="text" class="field-input" id="input-btp-target" placeholder="hostname or URL, comma-separated">
        </div>
        <div class="field-group">
          <div class="field-label">CT Log Keyword</div>
          <input type="text" class="field-input" id="input-btp-keyword" placeholder="org keyword for CT log search">
        </div>
        <div class="field-group">
          <div class="field-label">Custom Domain</div>
          <input type="text" class="field-input" id="input-btp-domain" placeholder="e.g. mycompany.com">
        </div>
        <div class="field-group">
          <div class="field-label">Subaccount ID</div>
          <input type="text" class="field-input" id="input-btp-subaccount" placeholder="Known subaccount identifier">
        </div>
        <div class="field-group">
          <div class="field-label">BTP Targets File</div>
          <input type="text" class="field-input" id="input-btp-targets-file" placeholder="Path to BTP targets file">
        </div>
        <div class="field-group">
          <div class="field-label">Regions</div>
          <input type="text" class="field-input" id="input-btp-regions" value="all" placeholder="all, or eu10,us10,...">
        </div>
        <div class="toggle-row">Skip CT Log Search <div class="toggle-switch" id="toggle-btp-skip-ct" onclick="this.classList.toggle('on')"></div></div>
        <div class="toggle-row">Skip BTP Vuln Check <div class="toggle-switch" id="toggle-btp-skip-vuln" onclick="this.classList.toggle('on')"></div></div>
        <div class="section-title" style="cursor:pointer;margin-top:8px;font-size:10px;opacity:0.6;" onclick="toggleBtpAdvanced()">ADVANCED (Shodan/Censys) <span id="btp-adv-arrow" style="float:right;font-size:9px;">&#9654;</span></div>
        <div id="btp-advanced-body" style="display:none;">
          <div class="field-group">
            <div class="field-label">Shodan API Key</div>
            <input type="text" class="field-input" id="input-btp-shodan" placeholder="Shodan API key">
          </div>
          <div class="field-group">
            <div class="field-label">Censys API ID</div>
            <input type="text" class="field-input" id="input-btp-censys-id" placeholder="Censys API ID">
          </div>
          <div class="field-group">
            <div class="field-label">Censys API Secret</div>
            <input type="text" class="field-input" id="input-btp-censys-secret" placeholder="Censys API secret">
          </div>
        </div>
      </div>
    </div>

    <div>
      <button class="btn-scan" id="btn-start-scan" onclick="startScan()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
        Start Scan
      </button>
      <div class="btn-export-row">
        <button class="btn-export" onclick="exportHtmlReport()">Export HTML</button>
        <button class="btn-export" onclick="exportJson()">Export JSON</button>
      </div>
    </div>
  </div>

  <!-- Main Content -->
  <div class="content">

    <!-- Dashboard View -->
    <div id="view-dashboard" class="view-container active">
      <div class="summary-cards">
        <div class="summary-card sc-blue"><div class="sc-bar"></div><div class="sc-value" id="summary-systems">--</div><div class="sc-label">SAP Systems</div></div>
        <div class="summary-card sc-green"><div class="sc-bar"></div><div class="sc-value" id="summary-ports">--</div><div class="sc-label">Open Ports</div></div>
        <div class="summary-card" id="summary-btp-card" style="display:none;"><div class="sc-bar" style="background:#06b6d4;"></div><div class="sc-value" id="summary-btp-endpoints">--</div><div class="sc-label">BTP Endpoints</div></div>
        <div class="summary-card sc-red"><div class="sc-bar"></div><div class="sc-value" id="summary-critical">--</div><div class="sc-label">Critical</div></div>
        <div class="summary-card sc-orange"><div class="sc-bar"></div><div class="sc-value" id="summary-high">--</div><div class="sc-label">High</div></div>
        <div class="summary-card sc-yellow"><div class="sc-bar"></div><div class="sc-value" id="summary-medium">--</div><div class="sc-label">Medium</div></div>
        <div class="summary-card sc-low"><div class="sc-bar"></div><div class="sc-value" id="summary-low">--</div><div class="sc-label">Low</div></div>
        <div class="summary-card sc-info"><div class="sc-bar"></div><div class="sc-value" id="summary-info">--</div><div class="sc-label">Info</div></div>
      </div>
      <div class="grid-row" style="flex:1;min-height:0;">
        <div class="panel wide">
          <div class="panel-header">Discovered Systems <span class="badge" id="systems-badge">0 systems</span></div>
          <div class="panel-body" id="systems-list" style="overflow-y:auto;max-height:340px;">
            <div class="empty-state">No systems discovered yet. Configure targets and start a scan.</div>
          </div>
        </div>
        <div class="panel">
          <div class="panel-header">Severity Distribution</div>
          <div class="panel-body" style="overflow:hidden;">
            <div class="chart-container">
              <div id="severity-chart" style="background:var(--border);">
                <div class="ring-inner">
                  <span class="ring-num" id="ring-number">0</span>
                  <span class="ring-label">findings</span>
                </div>
              </div>
              <div class="chart-legend" id="chart-legend">
                <div class="legend-item"><span class="legend-dot" style="background:var(--critical)"></span> Critical (0)</div>
                <div class="legend-item"><span class="legend-dot" style="background:var(--high)"></span> High (0)</div>
                <div class="legend-item"><span class="legend-dot" style="background:var(--medium)"></span> Medium (0)</div>
                <div class="legend-item"><span class="legend-dot" style="background:var(--low)"></span> Low (0)</div>
                <div class="legend-item"><span class="legend-dot" style="background:var(--info)"></span> Info (0)</div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-header">Vulnerability Findings <span class="badge" id="findings-badge">0 findings</span></div>
        <div class="panel-body" id="findings-list" style="overflow-y:auto;max-height:300px;">
          <div class="empty-state">No findings yet.</div>
        </div>
      </div>
    </div>

    <!-- URL Scan View -->
    <div id="view-urlscan" class="view-container">
      <div class="url-summary-bar" id="url-summary-bar">
        <div class="url-stat"><strong id="url-total-count">0</strong> URLs scanned</div>
      </div>
      <div class="url-filter-row" id="url-view-filters">
        <span class="url-filter-btn active" onclick="filterUrlView(this,'all')">All</span>
        <div style="flex:1;"></div>
        <input type="text" class="url-search" id="url-search" placeholder="Filter by path..." oninput="searchUrlPaths()">
      </div>
      <div class="panel" style="flex:1;min-height:0;">
        <div class="panel-body" id="url-view-body" style="overflow-y:auto;flex:1;">
          <div class="empty-state" id="url-empty-state">No URL scan results yet. Enable URL Scanning and run a scan.</div>
          <table class="url-view-table" id="url-view-table" style="display:none;">
            <thead><tr><th>System</th><th>Port</th><th>Proto</th><th>Path</th><th>Status</th><th>Size</th><th>Server</th><th>Notes</th></tr></thead>
            <tbody id="url-view-tbody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- BTP Cloud View -->
    <div id="view-btp" class="view-container">
      <div class="url-summary-bar" id="btp-summary-bar">
        <div class="url-stat"><strong id="btp-total-endpoints">0</strong> BTP Endpoints</div>
        <div class="url-stat"><strong id="btp-alive-endpoints">0</strong> Alive</div>
        <div class="url-stat"><strong id="btp-total-findings-count">0</strong> Findings</div>
      </div>
      <div class="grid-row" style="flex:1;min-height:0;">
        <div class="panel wide">
          <div class="panel-header">BTP Endpoints <span class="badge" id="btp-endpoints-badge">0 endpoints</span></div>
          <div class="panel-body" id="btp-endpoints-list" style="overflow-y:auto;max-height:400px;">
            <div class="empty-state">No BTP endpoints discovered yet. Configure BTP Cloud options and start a scan.</div>
          </div>
        </div>
        <div class="panel">
          <div class="panel-header">BTP Findings <span class="badge" id="btp-findings-badge">0 findings</span></div>
          <div class="panel-body" id="btp-findings-list" style="overflow-y:auto;max-height:400px;">
            <div class="empty-state">No BTP findings yet.</div>
          </div>
        </div>
      </div>
    </div>

  </div>
</div>

<!-- Progress / Status bar -->
<div class="progress-bar">
  <span id="progress-label-left">Ready</span>
  <div class="progress-track"><div class="progress-fill" id="progress-fill"></div></div>
  <span id="progress-label-right">--:--</span>

  <!-- Console toggle -->
  <span class="console-toggle" id="consoleToggle" onclick="toggleConsole()">&#9650; Console</span>
</div>

<!-- Console Panel -->
<div class="console-panel" id="consolePanel">
  <div class="console-header">
    <span>Console Output</span>
    <div class="console-actions">
      <span onclick="clearConsole()" title="Clear console">Clear</span>
      <span id="consoleMaxBtn" onclick="toggleConsoleMax()" title="Maximize console">&#9634;</span>
    </div>
  </div>
  <div class="console-body" id="console-body"></div>
</div>

<!-- Modal -->
<div class="modal-overlay" id="modal" onclick="if(event.target===this)toggleModal()">
  <div class="modal-content">
    <div class="modal-header">
      <div class="modal-title" id="modal-title"></div>
      <span class="modal-close" onclick="toggleModal()">&times;</span>
    </div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>

<div class="modal-overlay help-modal" id="helpModal" onclick="if(event.target===this)toggleHelpModal()">
  <div class="modal-content">
    <div class="modal-header">
      <div class="modal-title">SAPology &mdash; Vulnerability Checks</div>
      <span class="modal-close" onclick="toggleHelpModal()">&times;</span>
    </div>
    <div class="modal-body">

      <div class="modal-section">
        <h4>On-Premises Vulnerability Checks</h4>
        <table class="help-table">
          <thead><tr><th>CVE / Check</th><th>CVSS</th><th>Description</th></tr></thead>
          <tbody>
            <tr><td>CVE-2025-31324 / CVE-2025-42999</td><td class="sev-crit">10.0 / 9.1</td><td>Visual Composer unauthenticated file upload + deserialization RCE</td></tr>
            <tr><td>CVE-2022-22536 (ICMAD)</td><td class="sev-crit">10.0</td><td>HTTP request smuggling via ICM memory pipe desynchronization</td></tr>
            <tr><td>CVE-2020-6287 (RECON)</td><td class="sev-crit">10.0</td><td>SAP LM Configuration Wizard missing authorization</td></tr>
            <tr><td>CVE-2020-6207</td><td class="sev-crit">10.0</td><td>Solution Manager EEM missing authentication</td></tr>
            <tr><td>CVE-2010-5326</td><td class="sev-crit">10.0</td><td>Invoker Servlet unauthenticated code execution</td></tr>
            <tr><td>CVE-2022-41272</td><td class="sev-crit">9.9</td><td>SAP P4 service unauthenticated access (PI/PO JMS Connector)</td></tr>
            <tr><td>CVE-2021-33690</td><td class="sev-crit">9.9</td><td>NWDI CBS server-side request forgery</td></tr>
            <tr><td>CVE-2024-41730</td><td class="sev-crit">9.8</td><td>BusinessObjects SSO token theft via REST API</td></tr>
            <tr><td>CVE-2025-0061</td><td class="sev-high">8.7</td><td>BusinessObjects BI Launch Pad session hijacking</td></tr>
            <tr><td>CVE-2020-6308</td><td class="sev-med">5.3</td><td>BusinessObjects server-side request forgery</td></tr>
            <tr><td>CVE-2021-21475</td><td class="sev-med">--</td><td>MDM missing authorization check</td></tr>
            <tr><td>CVE-2021-21482</td><td class="sev-med">--</td><td>MDM information disclosure</td></tr>
            <tr><td>Gateway SAPXPG RCE</td><td class="sev-crit">--</td><td>Unprotected gateway allows OS command execution</td></tr>
            <tr><td>Message Server ACL</td><td class="sev-high">--</td><td>Internal MS port / monitor accessible from network</td></tr>
            <tr><td>SAPControl exposure</td><td class="sev-high">--</td><td>Unprotected SOAP management interface</td></tr>
            <tr><td>BO CMC exposed</td><td class="sev-high">--</td><td>BusinessObjects admin console accessible from network</td></tr>
            <tr><td>BO CMS port exposed</td><td class="sev-high">--</td><td>CMS port reachable (CVE-2026-0485 / CVE-2026-0490)</td></tr>
            <tr><td>Cloud Connector exposed</td><td class="sev-med">--</td><td>Administration port accessible from network</td></tr>
            <tr><td>HANA SQL port exposed</td><td class="sev-high">--</td><td>Database ports accessible from network</td></tr>
            <tr><td>SSL/TLS weaknesses</td><td class="sev-med">--</td><td>SSLv3, TLS 1.0/1.1, self-signed certificates</td></tr>
            <tr><td>HTTP verb tampering</td><td class="sev-med">--</td><td>Authentication bypass via HEAD/OPTIONS methods</td></tr>
            <tr><td>Info disclosure</td><td class="sev-low">--</td><td>/sap/public/info endpoint exposing system details</td></tr>
            <tr><td>MS internal SSL/mTLS</td><td class="sev-info">--</td><td>Secure communications detected (informational)</td></tr>
          </tbody>
        </table>
      </div>

      <div class="modal-section">
        <h4>BTP Cloud Vulnerability Checks</h4>
        <table class="help-table">
          <thead><tr><th>Check ID</th><th>Severity</th><th>Description</th></tr></thead>
          <tbody>
            <tr><td>BTP-SSH-001</td><td class="sev-high">HIGH</td><td>Cloud Foundry SSH enabled (Diego proxy on port 2222)</td></tr>
            <tr><td>BTP-SSH-002</td><td class="sev-med">MEDIUM</td><td>Cloud infrastructure details leaked via reverse DNS</td></tr>
            <tr><td>BTP-SSH-003</td><td class="sev-med">MEDIUM</td><td>Outdated Diego SSH proxy (Terrapin CVE-2023-48795 risk)</td></tr>
            <tr><td>BTP-AUTH-001</td><td class="sev-crit">CRITICAL</td><td>Unauthenticated access to application data</td></tr>
            <tr><td>BTP-AUTH-002</td><td class="sev-high">HIGH</td><td>OData $metadata endpoint exposed without authentication</td></tr>
            <tr><td>BTP-AUTH-003</td><td class="sev-med">MEDIUM</td><td>OAuth token endpoint publicly reachable</td></tr>
            <tr><td>BTP-CFG-001</td><td class="sev-med">MEDIUM</td><td>xs-app.json routing configuration exposed</td></tr>
            <tr><td>BTP-CFG-002</td><td class="sev-low">LOW</td><td>manifest.json application metadata exposed</td></tr>
            <tr><td>BTP-CFG-003</td><td class="sev-high">HIGH</td><td>Spring Boot Actuator endpoints publicly accessible</td></tr>
            <tr><td>BTP-CFG-004</td><td class="sev-crit">CRITICAL</td><td>Spring Boot Actuator /env endpoint leaking secrets</td></tr>
            <tr><td>BTP-CFG-005</td><td class="sev-low">LOW</td><td>Swagger/OpenAPI documentation publicly accessible</td></tr>
            <tr><td>BTP-CORS-001</td><td class="sev-med">MEDIUM</td><td>Wildcard CORS policy (Access-Control-Allow-Origin: *)</td></tr>
            <tr><td>BTP-CORS-002</td><td class="sev-med">MEDIUM</td><td>CORS accepts null origin</td></tr>
            <tr><td>BTP-HDR-001</td><td class="sev-low">LOW</td><td>Missing HSTS header (Strict-Transport-Security)</td></tr>
            <tr><td>BTP-TLS-001</td><td class="sev-med">MEDIUM</td><td>Legacy TLS versions enabled (TLS 1.0/1.1)</td></tr>
            <tr><td>BTP-INFO-001</td><td class="sev-med">MEDIUM</td><td>Error pages leaking stack traces or internal paths</td></tr>
            <tr><td>BTP-INFO-002</td><td class="sev-low">LOW</td><td>Server version information disclosed</td></tr>
            <tr><td>BTP-INFO-003</td><td class="sev-high">HIGH</td><td>Debug/trace mode enabled in production</td></tr>
          </tbody>
        </table>
      </div>

      <div class="help-note">
        This tool is intended for <strong>authorized security testing</strong> only. Only use SAPology against systems you have explicit permission to test.
      </div>

    </div>
  </div>
</div>

<script>
// === State ===
var scanData = null;
var scanRunning = false;
var consoleCursor = 0;
var pollTimer = null;
var scanGeneration = 0;

// === API Helper ===
function apiGet(url) {
    return fetch(url).then(function(r) { return r.json(); });
}
function apiPost(url, data) {
    return fetch(url, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: data ? JSON.stringify(data) : '{}'
    }).then(function(r) { return r.json(); });
}

// === Polling ===
function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(pollUpdates, 500);
}
function stopPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

function pollUpdates() {
    // Poll console lines
    apiGet('/api/console?cursor=' + consoleCursor).then(function(data) {
        data.lines.forEach(function(ln) {
            appendConsoleLine(ln.ts, ln.text, ln.cls);
            // Parse progress and update the progress bar in real-time
            var pctMatch = ln.text.match(/Vulnerability assessment \.\.\. (\d+)%/);
            if (pctMatch) {
                var pct = parseInt(pctMatch[1]);
                // Map 0-100% of Phase 2 to 50-95% of progress bar
                var barPct = 50 + Math.floor(pct * 0.45);
                document.getElementById('progress-fill').style.width = barPct + '%';
                document.getElementById('progress-fill').style.animation = 'none';
                document.getElementById('progress-label-left').textContent =
                    'Phase 2: Vulnerability Assessment \u2014 ' + pct + '%';
            }
            if (ln.text.match(/Phase 1:/)) {
                document.getElementById('progress-fill').style.width = '10%';
                document.getElementById('progress-label-left').textContent = 'Phase 1: Discovery';
            }
            if (ln.text.match(/Phase 2:/)) {
                document.getElementById('progress-fill').style.width = '50%';
                document.getElementById('progress-fill').style.animation = 'none';
                document.getElementById('progress-label-left').textContent = 'Phase 2: Vulnerability Assessment';
            }
            // Show current check activity in progress label
            var checkMatch = ln.text.match(/\[\*\] (.+? - Checking .+)/);
            if (checkMatch) {
                document.getElementById('progress-label-left').textContent = checkMatch[1];
            }
            var urlScanMatch = ln.text.match(/\[\*\] URL scanning (.+)/);
            if (urlScanMatch) {
                document.getElementById('progress-label-left').textContent = 'URL scanning ' + urlScanMatch[1];
            }
            // Phase 1: port scanning progress
            var portScanMatch = ln.text.match(/Port scanning (.+?) \.\.\. (\d+)%/);
            if (portScanMatch) {
                var p1pct = parseInt(portScanMatch[2]);
                document.getElementById('progress-fill').style.width = (5 + Math.floor(p1pct * 0.4)) + '%';
                document.getElementById('progress-label-left').textContent =
                    'Phase 1: Scanning ' + portScanMatch[1] + ' \u2014 ' + p1pct + '%';
            }
            // Phase 1: pre-scanning
            var preScanMatch = ln.text.match(/Pre-scanning/);
            if (preScanMatch) {
                document.getElementById('progress-fill').style.width = '5%';
                document.getElementById('progress-label-left').textContent = 'Phase 1: Pre-scanning hosts';
            }
            // BTP phase tracking
            if (ln.text.match(/BTP Cloud Scanning/)) {
                document.getElementById('progress-fill').style.width = '95%';
                document.getElementById('progress-fill').style.animation = 'none';
                document.getElementById('progress-label-left').textContent = 'BTP Cloud Scanning';
            }
            var btpPhaseMatch = ln.text.match(/BTP Phase (\d): (.+)/);
            if (btpPhaseMatch) {
                document.getElementById('progress-fill').style.width = (95 + parseInt(btpPhaseMatch[1])) + '%';
                document.getElementById('progress-fill').style.animation = 'none';
                document.getElementById('progress-label-left').textContent = 'BTP: ' + btpPhaseMatch[2];
            }
        });
        consoleCursor = data.cursor;
    }).catch(function(){});

    // Poll scan status
    apiGet('/api/status').then(function(st) {
        updateTimer(st.elapsed);

        if (st.state === 'complete' && scanRunning) {
            scanRunning = false;
            onScanComplete();
            stopPolling();
        } else if (st.state === 'cancelled' && scanRunning) {
            scanRunning = false;
            onScanCancelled();
            stopPolling();
        } else if (st.state === 'error' && scanRunning) {
            scanRunning = false;
            onScanError(st.error || 'Unknown error');
            stopPolling();
        }
    }).catch(function(){});
}

// === Scan Control ===
function startScan() {
    if (scanRunning) {
        apiPost('/api/stop_scan').then(function(r) {
            appendConsoleLine(getTimestamp(), '[!] Scan cancellation requested...', 'cl-warn');
        });
        return;
    }

    var targets = document.getElementById('input-targets').value;
    var targetFile = document.getElementById('input-target-file').value;

    var btpTarget = document.getElementById('input-btp-target').value;
    var btpKeyword = document.getElementById('input-btp-keyword').value;
    var btpDomain = document.getElementById('input-btp-domain').value;
    var btpSubaccount = document.getElementById('input-btp-subaccount').value;
    var btpTargetsFile = document.getElementById('input-btp-targets-file').value;
    var hasBtp = btpTarget || btpKeyword || btpDomain || btpSubaccount || btpTargetsFile;

    if (!targets && !targetFile && !hasBtp) {
        alert('Please specify at least one target, a target file, or BTP Cloud options.');
        return;
    }

    var config = {
        targets: targets,
        target_file: targetFile,
        instances: document.getElementById('input-instances').value,
        threads: parseInt(document.getElementById('input-threads').value) || 20,
        timeout: parseInt(document.getElementById('input-timeout').value) || 3,
        url_scan_threads: parseInt(document.getElementById('input-url-threads').value) || 25,
        gw_cmd: document.getElementById('input-gw-cmd').value || 'whoami',
        vuln_assess: document.getElementById('toggle-vuln').classList.contains('on'),
        url_scan: document.getElementById('toggle-url-scan').classList.contains('on'),
        verbose: document.getElementById('toggle-verbose').classList.contains('on'),
        btp_target: btpTarget,
        btp_keyword: btpKeyword,
        btp_domain: btpDomain,
        btp_subaccount: btpSubaccount,
        btp_targets_file: btpTargetsFile,
        btp_regions: document.getElementById('input-btp-regions').value || 'all',
        btp_skip_ct: document.getElementById('toggle-btp-skip-ct').classList.contains('on'),
        btp_skip_vuln: document.getElementById('toggle-btp-skip-vuln').classList.contains('on'),
        btp_shodan_key: document.getElementById('input-btp-shodan').value || '',
        btp_censys_id: document.getElementById('input-btp-censys-id').value || '',
        btp_censys_secret: document.getElementById('input-btp-censys-secret').value || ''
    };

    scanGeneration++;
    stopPolling();
    clearDashboard();
    clearConsole();
    consoleCursor = 0;

    apiPost('/api/start_scan', config).then(function(r) {
        if (r && r.error) { alert(r.error); return; }
        onScanStarted();
        startPolling();
    }).catch(function(err) {
        appendConsoleLine(getTimestamp(), '[-] Failed to start scan: ' + err, 'cl-err');
    });
}

// === Scan State Callbacks ===
function onScanStarted() {
    scanRunning = true;
    var btn = document.getElementById('btn-start-scan');
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="6" width="12" height="12"/></svg> Stop Scan';
    btn.classList.add('scanning');

    document.getElementById('nav-status').innerHTML =
        '<span class="dot" style="background:var(--accent);box-shadow:0 0 6px var(--accent);"></span> Scanning...';
    document.getElementById('nav-status').style.color = 'var(--accent)';

    document.getElementById('progress-label-left').textContent = 'Scanning...';
    document.getElementById('progress-fill').style.width = '5%';
    document.getElementById('progress-fill').style.animation = 'pulse-bar 2s ease-in-out infinite';

    var panel = document.getElementById('consolePanel');
    if (!panel.classList.contains('open')) toggleConsole();
}

function onScanComplete() {
    var btn = document.getElementById('btn-start-scan');
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Start Scan';
    btn.classList.remove('scanning');

    document.getElementById('progress-fill').style.width = '100%';
    document.getElementById('progress-fill').style.animation = 'none';

    var gen = scanGeneration;
    apiGet('/api/results').then(function(results) {
        if (gen !== scanGeneration) return;
        scanData = results;
        renderDashboard(results);
        var n = (results.summary || {}).total_systems || 0;
        var f = (results.summary || {}).total_findings || 0;
        var btpCount = (results.btp_endpoints || []).filter(function(ep){return ep.alive;}).length;
        document.getElementById('nav-status').innerHTML =
            '<span class="dot" style="background:var(--success);box-shadow:0 0 6px var(--success);"></span> Scan complete';
        document.getElementById('nav-status').style.color = 'var(--success)';
        var label = 'Scan complete \u2014 ' + n + ' systems';
        if (btpCount > 0) label += ', ' + btpCount + ' BTP endpoints';
        label += ', ' + f + ' findings';
        document.getElementById('progress-label-left').textContent = label;
    });
}

function onScanCancelled() {
    var btn = document.getElementById('btn-start-scan');
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Start Scan';
    btn.classList.remove('scanning');

    document.getElementById('nav-status').innerHTML =
        '<span class="dot" style="background:var(--medium);box-shadow:0 0 6px var(--medium);"></span> Cancelled';
    document.getElementById('nav-status').style.color = 'var(--medium)';
    document.getElementById('progress-fill').style.animation = 'none';
}

function onScanError(msg) {
    var btn = document.getElementById('btn-start-scan');
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Start Scan';
    btn.classList.remove('scanning');
    appendConsoleLine(getTimestamp(), '[-] Error: ' + msg, 'cl-err');
    document.getElementById('nav-status').innerHTML =
        '<span class="dot" style="background:var(--critical);box-shadow:0 0 6px var(--critical);"></span> Error';
    document.getElementById('nav-status').style.color = 'var(--critical)';
    document.getElementById('progress-fill').style.animation = 'none';
}

// === Dashboard Rendering ===
function renderDashboard(data) {
    if (!data) return;
    var s = data.summary || {};
    document.getElementById('summary-systems').textContent = s.total_systems || 0;
    document.getElementById('summary-ports').textContent = s.total_ports || 0;
    document.getElementById('summary-critical').textContent = s.critical || 0;
    document.getElementById('summary-high').textContent = s.high || 0;
    document.getElementById('summary-medium').textContent = s.medium || 0;
    document.getElementById('summary-low').textContent = s.low || 0;
    document.getElementById('summary-info').textContent = s.info || 0;

    var btpCard = document.getElementById('summary-btp-card');
    if ((data.btp_endpoints || []).length > 0) {
        btpCard.style.display = '';
        var aliveCount = (data.btp_endpoints || []).filter(function(ep){return ep.alive;}).length;
        document.getElementById('summary-btp-endpoints').textContent = aliveCount;
    } else {
        btpCard.style.display = 'none';
    }

    renderSystems(data.systems || []);
    renderSeverityChart(s);
    renderFindings(data.systems || [], data.btp_endpoints || []);
    renderUrlScanView(data.systems || []);
    renderBtpView(data.btp_endpoints || [], data.btp_summary || null);
}

function renderSystems(systems) {
    var container = document.getElementById('systems-list');
    var badge = document.getElementById('systems-badge');
    badge.textContent = systems.length + ' system' + (systems.length !== 1 ? 's' : '');

    if (systems.length === 0) {
        container.innerHTML = '<div class="empty-state">No systems discovered yet.</div>';
        return;
    }

    var html = '';
    systems.forEach(function(sys, idx) {
        var t = (sys.system_type || '').toUpperCase();
        var iconClass = t.indexOf('JAVA') >= 0 ? 'java' : t === 'MDM' ? 'mdm' : t.indexOf('ABAP') >= 0 ? 'abap' : 'unknown';
        var iconLabel = t || 'SAP';

        var portCount = 0;
        var allF = [];
        (sys.instances || []).forEach(function(inst) {
            portCount += Object.keys(inst.ports || {}).length;
            (inst.findings || []).forEach(function(f) { allF.push(f); });
        });

        var crit = allF.filter(function(f){return f.severity==='CRITICAL';}).length;
        var high = allF.filter(function(f){return f.severity==='HIGH';}).length;
        var med = allF.filter(function(f){return f.severity==='MEDIUM';}).length;

        var ip = (sys.instances && sys.instances[0]) ? sys.instances[0].ip : '';
        var meta = ip;
        if (sys.kernel) meta += ' \u00b7 Kernel ' + sys.kernel;
        meta += ' \u00b7 ' + portCount + ' ports';

        var badges = '';
        if (crit > 0) badges += '<span class="mini-badge mb-critical">' + crit + '</span>';
        if (high > 0) badges += '<span class="mini-badge mb-high">' + high + '</span>';
        if (med > 0) badges += '<span class="mini-badge mb-medium">' + med + '</span>';

        html += '<div class="sys-row" onclick="showSystemModal(' + idx + ')">' +
            '<div class="sys-icon ' + iconClass + '">' + esc(iconLabel) + '</div>' +
            '<div class="sys-info">' +
                '<div class="sys-name">' + esc(sys.sid) + ' &mdash; ' + esc(sys.hostname || ip) + '</div>' +
                '<div class="sys-meta">' + esc(meta) + '</div>' +
            '</div>' +
            '<div class="sys-badges">' + badges + '</div>' +
            '<span class="sys-chevron">&#8250;</span>' +
        '</div>';
    });
    container.innerHTML = html;
}

function renderFindings(systems, btpEndpoints) {
    var container = document.getElementById('findings-list');
    var badge = document.getElementById('findings-badge');

    var allF = [];
    systems.forEach(function(sys) {
        (sys.instances || []).forEach(function(inst) {
            (inst.findings || []).forEach(function(f) {
                allF.push({f: f, label: sys.sid + ' \u00b7 :' + f.port});
            });
        });
    });
    (btpEndpoints || []).forEach(function(ep) {
        (ep.findings || []).forEach(function(f) {
            allF.push({f: f, label: 'BTP: ' + (ep.hostname || ep.url)});
        });
    });

    var sevOrder = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4};
    allF.sort(function(a,b) { var sa = sevOrder[a.f.severity], sb = sevOrder[b.f.severity]; return (sa !== undefined ? sa : 5) - (sb !== undefined ? sb : 5); });

    badge.textContent = allF.length + ' finding' + (allF.length !== 1 ? 's' : '');

    if (allF.length === 0) {
        container.innerHTML = '<div class="empty-state">No findings yet.</div>';
        return;
    }

    var html = '';
    allF.forEach(function(item, idx) {
        var f = item.f;
        var sevClass = 'fs-' + f.severity.toLowerCase();
        html += '<div class="finding-row" id="fr-' + idx + '" onclick="toggleFinding(' + idx + ')">' +
            '<div class="finding-row-top">' +
                '<span class="finding-sev ' + sevClass + '">' + f.severity + '</span>' +
                '<span class="finding-name">' + esc(f.name) + '</span>' +
                '<span class="finding-target">' + esc(item.label) + '</span>' +
                '<span class="finding-arrow">&#8250;</span>' +
            '</div>' +
        '</div>' +
        '<div class="finding-details" id="fd-' + idx + '">' +
            '<div class="fd-section"><div class="fd-label">Description</div>' +
                '<div class="fd-text">' + esc(f.description) + '</div></div>' +
            (f.detail ? '<div class="fd-section"><div class="fd-label">Detail</div><div class="fd-text">' + esc(f.detail) + '</div></div>' : '') +
            (f.remediation ? '<div class="fd-section"><div class="fd-label">Remediation</div><div class="fd-text">' + esc(f.remediation) + '</div></div>' : '') +
        '</div>';
    });
    container.innerHTML = html;
}

function renderSeverityChart(s) {
    var total = (s.critical||0) + (s.high||0) + (s.medium||0) + (s.low||0) + (s.info||0);
    document.getElementById('ring-number').textContent = total;

    if (total === 0) {
        document.getElementById('severity-chart').style.background = 'var(--border)';
    } else {
        var c = (s.critical||0)/total*360;
        var h = c + (s.high||0)/total*360;
        var m = h + (s.medium||0)/total*360;
        var l = m + (s.low||0)/total*360;
        document.getElementById('severity-chart').style.background =
            'conic-gradient(var(--critical) 0deg ' + c + 'deg,' +
            'var(--high) ' + c + 'deg ' + h + 'deg,' +
            'var(--medium) ' + h + 'deg ' + m + 'deg,' +
            'var(--low) ' + m + 'deg ' + l + 'deg,' +
            'var(--info) ' + l + 'deg 360deg)';
    }

    document.getElementById('chart-legend').innerHTML =
        '<div class="legend-item"><span class="legend-dot" style="background:var(--critical)"></span> Critical (' + (s.critical||0) + ')</div>' +
        '<div class="legend-item"><span class="legend-dot" style="background:var(--high)"></span> High (' + (s.high||0) + ')</div>' +
        '<div class="legend-item"><span class="legend-dot" style="background:var(--medium)"></span> Medium (' + (s.medium||0) + ')</div>' +
        '<div class="legend-item"><span class="legend-dot" style="background:var(--low)"></span> Low (' + (s.low||0) + ')</div>' +
        '<div class="legend-item"><span class="legend-dot" style="background:var(--info)"></span> Info (' + (s.info||0) + ')</div>';
}

// === Tab Switching ===
function switchTab(name) {
    var tabs = document.querySelectorAll('.nav-tab');
    tabs.forEach(function(t) { t.classList.remove('active'); });
    document.querySelectorAll('.view-container').forEach(function(v) { v.classList.remove('active'); });
    if (name === 'urlscan') {
        document.getElementById('tab-urlscan').classList.add('active');
        document.getElementById('view-urlscan').classList.add('active');
    } else if (name === 'btp') {
        document.getElementById('tab-btp').classList.add('active');
        document.getElementById('view-btp').classList.add('active');
    } else {
        tabs[0].classList.add('active');
        document.getElementById('view-dashboard').classList.add('active');
    }
}

// === URL Scan View ===
function renderUrlScanView(systems) {
    var allUrls = [];
    (systems || []).forEach(function(sys) {
        (sys.instances || []).forEach(function(inst) {
            (inst.url_scan_results || []).forEach(function(u) {
                allUrls.push({sid: sys.sid, ip: inst.ip,
                    port: u.scan_port || '', ssl: u.scan_ssl || false,
                    path: u.path || '', status: u.status_code || 0,
                    size: u.content_length || 0, server: u.server || '',
                    redirect: u.redirect || '', tamper: u.verb_tamper || false,
                    tamper_method: u.tamper_method || ''});
            });
        });
    });

    // Update tab badge
    var tabEl = document.getElementById('tab-urlscan');
    tabEl.innerHTML = 'URL Scan' + (allUrls.length > 0 ? ' <span class="tab-badge">(' + allUrls.length + ')</span>' : '');

    // Update summary
    document.getElementById('url-total-count').textContent = allUrls.length;

    if (allUrls.length === 0) {
        document.getElementById('url-empty-state').style.display = '';
        document.getElementById('url-view-table').style.display = 'none';
        return;
    }
    document.getElementById('url-empty-state').style.display = 'none';
    document.getElementById('url-view-table').style.display = '';

    // Count status groups for summary bar + filter buttons
    var groups = {};
    var tamperCount = 0;
    allUrls.forEach(function(u) {
        var g = Math.floor(u.status / 100) + 'xx';
        if (u.status === 401) g = '401';
        else if (u.status === 403) g = '403';
        groups[g] = (groups[g] || 0) + 1;
        if (u.tamper) tamperCount++;
    });

    // Summary stats
    var statsHtml = '<div class="url-stat"><strong>' + allUrls.length + '</strong> URLs scanned</div>';
    var gk = Object.keys(groups).sort();
    gk.forEach(function(g) {
        statsHtml += '<div class="url-stat">' + g.toUpperCase() + ': <strong>' + groups[g] + '</strong></div>';
    });
    if (tamperCount > 0) statsHtml += '<div class="url-stat" style="color:var(--critical);">Verb Tamper: <strong>' + tamperCount + '</strong></div>';
    document.getElementById('url-summary-bar').innerHTML = statsHtml;

    // Filter buttons
    var filterHtml = '<span class="url-filter-btn active" onclick="filterUrlView(this,\'all\')">All (' + allUrls.length + ')</span>';
    gk.forEach(function(g) {
        filterHtml += '<span class="url-filter-btn" onclick="filterUrlView(this,\'' + g + '\')">' + g.toUpperCase() + ' (' + groups[g] + ')</span>';
    });
    if (tamperCount > 0) {
        filterHtml += '<span class="url-filter-btn" onclick="filterUrlView(this,\'tamper\')">Verb Tamper (' + tamperCount + ')</span>';
    }
    filterHtml += '<div style="flex:1;"></div><input type="text" class="url-search" id="url-search" placeholder="Filter by path..." oninput="searchUrlPaths()">';
    document.getElementById('url-view-filters').innerHTML = filterHtml;

    // Table rows
    var tbody = document.getElementById('url-view-tbody');
    var rows = '';
    allUrls.forEach(function(u) {
        var sc = u.status;
        var sCls = sc >= 500 ? 's5xx' : sc === 403 ? 's403' : sc === 401 ? 's401' : sc >= 300 ? 's3xx' : sc >= 200 ? 's2xx' : '';
        var sg = Math.floor(sc / 100) + 'xx';
        if (sc === 401) sg = '401';
        else if (sc === 403) sg = '403';
        var proto = u.ssl ? 'https' : 'http';
        var fullUrl = proto + '://' + u.ip + ':' + u.port + u.path;
        var tamperBadge = u.tamper ? '<span class="url-tamper" title="Method: ' + esc(u.tamper_method) + '">TAMPER</span> ' : '';
        var redirectNote = u.redirect ? '<span style="opacity:0.5;font-size:11px;" title="' + esc(u.redirect) + '">&#8594; redirect</span>' : '';
        rows += '<tr class="url-view-row" data-status-group="' + sg + '" data-tamper="' + (u.tamper?'1':'0') + '" data-path="' + esc(u.path.toLowerCase()) + '">' +
            '<td>' + esc(u.sid) + '</td>' +
            '<td>' + u.port + '</td>' +
            '<td>' + proto.toUpperCase() + '</td>' +
            '<td><span class="url-link" title="' + esc(fullUrl) + '" onclick="openUrl(\'' + fullUrl.replace(/'/g,"\\'") + '\')">' + esc(u.path) + '</span></td>' +
            '<td><span class="url-status ' + sCls + '">' + sc + '</span></td>' +
            '<td>' + u.size + '</td>' +
            '<td>' + esc(u.server) + '</td>' +
            '<td>' + tamperBadge + redirectNote + '</td>' +
            '</tr>';
    });
    tbody.innerHTML = rows;
}

function filterUrlView(btn, group) {
    var btns = document.getElementById('url-view-filters').querySelectorAll('.url-filter-btn');
    btns.forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    var searchVal = (document.getElementById('url-search').value || '').toLowerCase();
    var rows = document.querySelectorAll('.url-view-row');
    rows.forEach(function(r) {
        var matchGroup = (group === 'all') || (group === 'tamper' ? r.getAttribute('data-tamper') === '1' : r.getAttribute('data-status-group') === group);
        var matchSearch = !searchVal || r.getAttribute('data-path').indexOf(searchVal) >= 0;
        r.style.display = (matchGroup && matchSearch) ? '' : 'none';
    });
}

function searchUrlPaths() {
    var val = (document.getElementById('url-search').value || '').toLowerCase();
    var activeBtn = document.querySelector('#url-view-filters .url-filter-btn.active');
    var group = 'all';
    if (activeBtn) {
        var m = activeBtn.textContent.match(/^(\S+)/);
        if (m) {
            var t = m[1].toLowerCase();
            if (t === 'verb') group = 'tamper';
            else if (t !== 'all') group = t.toLowerCase();
        }
    }
    var rows = document.querySelectorAll('.url-view-row');
    rows.forEach(function(r) {
        var matchGroup = (group === 'all') || (group === 'tamper' ? r.getAttribute('data-tamper') === '1' : r.getAttribute('data-status-group') === group);
        var matchSearch = !val || r.getAttribute('data-path').indexOf(val) >= 0;
        r.style.display = (matchGroup && matchSearch) ? '' : 'none';
    });
}

// === System Modal ===
function showSystemModal(idx) {
    if (!scanData || !scanData.systems || !scanData.systems[idx]) return;
    var sys = scanData.systems[idx];
    var t = (sys.system_type || '').toUpperCase();
    var iconClass = t.indexOf('JAVA') >= 0 ? 'java' : t === 'MDM' ? 'mdm' : t.indexOf('ABAP') >= 0 ? 'abap' : 'unknown';
    var ip = (sys.instances && sys.instances[0]) ? sys.instances[0].ip : '';

    var info = '<div class="info-grid">' +
        '<div class="info-item"><span class="ik">SID</span><span class="iv">' + esc(sys.sid) + '</span></div>' +
        '<div class="info-item"><span class="ik">Hostname</span><span class="iv">' + esc(sys.hostname || '') + '</span></div>' +
        '<div class="info-item"><span class="ik">IP Address</span><span class="iv">' + esc(ip) + '</span></div>' +
        '<div class="info-item"><span class="ik">System Type</span><span class="iv">' + esc(sys.system_type || 'Unknown') + '</span></div>' +
        '<div class="info-item"><span class="ik">Kernel</span><span class="iv">' + esc(sys.kernel || 'N/A') + '</span></div>' +
        '</div>';

    var ports = '<ul class="modal-ports">';
    (sys.instances || []).forEach(function(inst) {
        var ps = inst.ports || {};
        Object.keys(ps).sort(function(a,b){return parseInt(a)-parseInt(b);}).forEach(function(p) {
            ports += '<li><span class="mp-port">' + p + '</span><span class="mp-svc">' + esc(ps[p]) + '</span></li>';
        });
    });
    ports += '</ul>';

    var allF = [];
    (sys.instances || []).forEach(function(inst) {
        (inst.findings || []).forEach(function(f) { allF.push(f); });
    });
    var sevOrder = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4};
    allF.sort(function(a,b) { var sa = sevOrder[a.severity], sb = sevOrder[b.severity]; return (sa !== undefined ? sa : 5) - (sb !== undefined ? sb : 5); });
    var findings = '';
    allF.forEach(function(f) {
        findings += '<div class="modal-finding" onclick="this.classList.toggle(\'open\')">' +
            '<div class="mf-top"><span class="mf-name">' + esc(f.name) + '</span>' +
            '<span class="finding-sev fs-' + f.severity.toLowerCase() + '">' + f.severity + '</span></div>' +
            '<div class="mf-body">' + esc(f.description) +
            (f.remediation ? '<br><br><strong>Remediation:</strong> ' + esc(f.remediation) : '') +
            '</div></div>';
    });

    // Collect URL scan results from all instances
    var allUrls = [];
    (sys.instances || []).forEach(function(inst) {
        (inst.url_scan_results || []).forEach(function(u) {
            allUrls.push({ip: inst.ip, port: u.scan_port || '', ssl: u.scan_ssl || false,
                path: u.path || '', status: u.status_code || 0,
                size: u.content_length || 0, server: u.server || '',
                redirect: u.redirect || '', tamper: u.verb_tamper || false,
                tamper_method: u.tamper_method || ''});
        });
    });
    var urlSection = '';
    if (allUrls.length > 0) {
        // Gather unique status groups for filter buttons
        var statusGroups = {};
        allUrls.forEach(function(u) {
            var g = Math.floor(u.status / 100) + 'xx';
            if (u.status === 401) g = '401';
            else if (u.status === 403) g = '403';
            statusGroups[g] = (statusGroups[g] || 0) + 1;
        });
        var filterBar = '<div class="url-filter-row">' +
            '<span class="url-filter-btn active" onclick="filterUrls(this,\'all\')">All (' + allUrls.length + ')</span>';
        var gKeys = Object.keys(statusGroups).sort();
        gKeys.forEach(function(g) {
            filterBar += '<span class="url-filter-btn" onclick="filterUrls(this,\'' + g + '\')">' + g.toUpperCase() + ' (' + statusGroups[g] + ')</span>';
        });
        if (allUrls.some(function(u){return u.tamper;})) {
            var tc = allUrls.filter(function(u){return u.tamper;}).length;
            filterBar += '<span class="url-filter-btn" onclick="filterUrls(this,\'tamper\')">Verb Tamper (' + tc + ')</span>';
        }
        filterBar += '</div>';
        var urlRows = '';
        allUrls.forEach(function(u) {
            var sc = u.status;
            var sCls = sc >= 500 ? 's5xx' : sc === 403 ? 's403' : sc === 401 ? 's401' : sc >= 300 ? 's3xx' : sc >= 200 ? 's2xx' : '';
            var sg = Math.floor(sc / 100) + 'xx';
            if (sc === 401) sg = '401';
            else if (sc === 403) sg = '403';
            var proto = u.ssl ? 'https' : 'http';
            var fullUrl = proto + '://' + u.ip + ':' + u.port + u.path;
            var tamperBadge = u.tamper ? '<span class="url-tamper" title="Verb tampering: ' + esc(u.tamper_method) + '">TAMPER</span>' : '';
            urlRows += '<tr class="url-row" data-status-group="' + sg + '" data-tamper="' + (u.tamper?'1':'0') + '">' +
                '<td><span class="url-status ' + sCls + '">' + sc + '</span></td>' +
                '<td><span class="url-link" title="' + esc(fullUrl) + '" onclick="openUrl(\'' + fullUrl.replace(/'/g,"\\'") + '\')">' + esc(u.path) + '</span></td>' +
                '<td>' + u.size + '</td>' +
                '<td>' + esc(u.server) + '</td>' +
                '<td>' + tamperBadge + (u.redirect ? '<span style="opacity:0.5;font-size:11px;" title="' + esc(u.redirect) + '">&#8594; redirect</span>' : '') + '</td>' +
                '</tr>';
        });
        urlSection = '<div class="modal-section"><h4>URL Scan Results (' + allUrls.length + ')</h4>' +
            filterBar +
            '<div style="max-height:300px;overflow-y:auto;">' +
            '<table class="url-table"><thead><tr><th>Status</th><th>Path</th><th>Size</th><th>Server</th><th>Notes</th></tr></thead>' +
            '<tbody>' + urlRows + '</tbody></table></div></div>';
    }

    document.getElementById('modal-title').innerHTML =
        '<div class="sys-icon ' + iconClass + '" style="width:32px;height:32px;font-size:10px;">' +
        esc(t || 'SAP') + '</div> ' + esc(sys.sid) + ' &mdash; ' + esc(sys.hostname || ip);
    document.getElementById('modal-body').innerHTML =
        '<div class="modal-section"><h4>System Information</h4>' + info + '</div>' +
        '<div class="modal-section"><h4>Open Ports</h4>' + ports + '</div>' +
        '<div class="modal-section"><h4>Findings (' + allF.length + ')</h4>' + (findings || '<div class="empty-state">No findings for this system.</div>') + '</div>' +
        urlSection;
    document.getElementById('modal').classList.add('open');
}

function filterUrls(btn, group) {
    var btns = btn.parentNode.querySelectorAll('.url-filter-btn');
    btns.forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    var rows = document.querySelectorAll('.url-row');
    rows.forEach(function(r) {
        if (group === 'all') { r.style.display = ''; }
        else if (group === 'tamper') { r.style.display = r.getAttribute('data-tamper') === '1' ? '' : 'none'; }
        else { r.style.display = r.getAttribute('data-status-group') === group ? '' : 'none'; }
    });
}

// === Console ===
function appendConsoleLine(ts, text, cls) {
    var body = document.getElementById('console-body');
    var line = document.createElement('div');
    line.className = 'console-line';
    line.innerHTML = '<span class="cl-time">[' + ts + ']</span> <span class="' + (cls||'cl-info') + '">' + text + '</span>';
    body.appendChild(line);
    body.scrollTop = body.scrollHeight;
    while (body.children.length > 5000) body.removeChild(body.firstChild);
}

function clearConsole() { document.getElementById('console-body').innerHTML = ''; consoleCursor = 0; }

function clearDashboard() {
    scanData = null;
    ['summary-systems','summary-ports','summary-critical','summary-high','summary-medium','summary-low','summary-info'].forEach(function(id) {
        document.getElementById(id).textContent = '--';
    });
    document.getElementById('systems-list').innerHTML = '<div class="empty-state">Scanning...</div>';
    document.getElementById('findings-list').innerHTML = '<div class="empty-state">Scanning...</div>';
    document.getElementById('ring-number').textContent = '0';
    document.getElementById('severity-chart').style.background = 'var(--border)';
    document.getElementById('url-view-tbody').innerHTML = '';
    document.getElementById('url-view-table').style.display = 'none';
    document.getElementById('url-empty-state').style.display = '';
    document.getElementById('url-total-count').textContent = '0';
    document.getElementById('tab-urlscan').innerHTML = 'URL Scan';
    document.getElementById('btp-endpoints-list').innerHTML = '<div class="empty-state">Scanning...</div>';
    document.getElementById('btp-findings-list').innerHTML = '<div class="empty-state">Scanning...</div>';
    document.getElementById('btp-total-endpoints').textContent = '0';
    document.getElementById('btp-alive-endpoints').textContent = '0';
    document.getElementById('btp-total-findings-count').textContent = '0';
    document.getElementById('tab-btp').style.display = 'none';
    document.getElementById('tab-btp').innerHTML = 'BTP Cloud';
    document.getElementById('summary-btp-card').style.display = 'none';
    document.getElementById('summary-btp-endpoints').textContent = '--';
}

function updateTimer(t) { document.getElementById('progress-label-right').textContent = t; }

// === Utility ===
function esc(s) { return s ? String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;') : ''; }
function openUrl(url) { apiPost('/api/open_url', {url: url}); }
function getTimestamp() { var d=new Date(); return ('0'+d.getHours()).slice(-2)+':'+('0'+d.getMinutes()).slice(-2)+':'+('0'+d.getSeconds()).slice(-2); }
function toggleFinding(i) { document.getElementById('fr-'+i).classList.toggle('expanded'); }
function toggleBtpFinding(i) { document.getElementById('bfr-'+i).classList.toggle('expanded'); }
function toggleModal() { document.getElementById('modal').classList.toggle('open'); }
function toggleHelpModal() { document.getElementById('helpModal').classList.toggle('open'); }

// === BTP Section Toggles ===
function toggleBtpSection() {
    var body = document.getElementById('btp-section-body');
    var arrow = document.getElementById('btp-section-arrow');
    if (body.style.display === 'none') {
        body.style.display = '';
        arrow.innerHTML = '&#9650;';
    } else {
        body.style.display = 'none';
        arrow.innerHTML = '&#9660;';
    }
}
function toggleBtpAdvanced() {
    var body = document.getElementById('btp-advanced-body');
    var arrow = document.getElementById('btp-adv-arrow');
    if (body.style.display === 'none') {
        body.style.display = '';
        arrow.innerHTML = '&#9660;';
    } else {
        body.style.display = 'none';
        arrow.innerHTML = '&#9654;';
    }
}

// === BTP Cloud View Rendering ===
function renderBtpView(btpEndpoints, btpSummary) {
    var tabEl = document.getElementById('tab-btp');
    if (!btpEndpoints || btpEndpoints.length === 0) {
        tabEl.style.display = 'none';
        return;
    }
    tabEl.style.display = '';
    var alive = btpEndpoints.filter(function(ep) { return ep.alive; });
    var totalFindings = 0;
    btpEndpoints.forEach(function(ep) { totalFindings += (ep.findings || []).length; });
    tabEl.innerHTML = 'BTP Cloud <span class="tab-badge">(' + alive.length + ')</span>';

    document.getElementById('btp-total-endpoints').textContent = btpEndpoints.length;
    document.getElementById('btp-alive-endpoints').textContent = alive.length;
    document.getElementById('btp-total-findings-count').textContent = totalFindings;

    var epContainer = document.getElementById('btp-endpoints-list');
    var epBadge = document.getElementById('btp-endpoints-badge');
    epBadge.textContent = alive.length + ' endpoint' + (alive.length !== 1 ? 's' : '') + ' alive';

    if (alive.length === 0) {
        epContainer.innerHTML = '<div class="empty-state">No live BTP endpoints found.</div>';
    } else {
        var html = '';
        alive.forEach(function(ep, idx) {
            var svcType = ep.service_type || 'unknown';
            var svcLabel = svcType.replace(/_/g, ' ').toUpperCase();
            if (svcLabel.length > 6) svcLabel = svcLabel.substring(0, 6);
            var badges = '';
            var crit = 0, high = 0, med = 0;
            (ep.findings || []).forEach(function(f) {
                if (f.severity === 'CRITICAL') crit++;
                else if (f.severity === 'HIGH') high++;
                else if (f.severity === 'MEDIUM') med++;
            });
            if (crit > 0) badges += '<span class="mini-badge mb-critical">' + crit + '</span>';
            if (high > 0) badges += '<span class="mini-badge mb-high">' + high + '</span>';
            if (med > 0) badges += '<span class="mini-badge mb-medium">' + med + '</span>';
            var meta = (ep.region || 'unknown') + ' \u00b7 ' + (ep.service_type || 'unknown');
            if (ep.auth_type) meta += ' \u00b7 ' + ep.auth_type;
            if (ep.status_code) meta += ' \u00b7 HTTP ' + ep.status_code;

            html += '<div class="sys-row" onclick="showBtpEndpointModal(' + idx + ')">' +
                '<div class="sys-icon btp">' + esc(svcLabel) + '</div>' +
                '<div class="sys-info">' +
                    '<div class="sys-name">' + esc(ep.hostname) + '</div>' +
                    '<div class="sys-meta">' + esc(meta) + '</div>' +
                '</div>' +
                '<div class="sys-badges">' + badges + '</div>' +
                '<span class="sys-chevron">&#8250;</span>' +
            '</div>';
        });
        epContainer.innerHTML = html;
    }

    var fContainer = document.getElementById('btp-findings-list');
    var fBadge = document.getElementById('btp-findings-badge');
    fBadge.textContent = totalFindings + ' finding' + (totalFindings !== 1 ? 's' : '');
    if (totalFindings === 0) {
        fContainer.innerHTML = '<div class="empty-state">No BTP findings.</div>';
        return;
    }
    var allBtpF = [];
    btpEndpoints.forEach(function(ep) {
        (ep.findings || []).forEach(function(f) { allBtpF.push({f: f, ep: ep}); });
    });
    var sevOrder = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4};
    allBtpF.sort(function(a,b) {
        var sa = sevOrder[a.f.severity], sb = sevOrder[b.f.severity];
        return (sa !== undefined ? sa : 5) - (sb !== undefined ? sb : 5);
    });
    var fHtml = '';
    allBtpF.forEach(function(item, idx) {
        var f = item.f;
        var sevClass = 'fs-' + f.severity.toLowerCase();
        fHtml += '<div class="finding-row" id="bfr-' + idx + '" onclick="toggleBtpFinding(' + idx + ')">' +
            '<div class="finding-row-top">' +
                '<span class="finding-sev ' + sevClass + '">' + f.severity + '</span>' +
                '<span class="finding-name">' + esc(f.name) + '</span>' +
                '<span class="finding-target">' + esc(item.ep.hostname) + '</span>' +
                '<span class="finding-arrow">&#8250;</span>' +
            '</div>' +
        '</div>' +
        '<div class="finding-details" id="bfd-' + idx + '">' +
            '<div class="fd-section"><div class="fd-label">Description</div>' +
                '<div class="fd-text">' + esc(f.description) + '</div></div>' +
            (f.detail ? '<div class="fd-section"><div class="fd-label">Detail</div><div class="fd-text">' + esc(f.detail) + '</div></div>' : '') +
            (f.remediation ? '<div class="fd-section"><div class="fd-label">Remediation</div><div class="fd-text">' + esc(f.remediation) + '</div></div>' : '') +
        '</div>';
    });
    fContainer.innerHTML = fHtml;
}

function showBtpEndpointModal(idx) {
    if (!scanData || !scanData.btp_endpoints) return;
    var alive = scanData.btp_endpoints.filter(function(ep) { return ep.alive; });
    if (!alive[idx]) return;
    var ep = alive[idx];

    var info = '<div class="info-grid">' +
        '<div class="info-item"><span class="ik">Hostname</span><span class="iv">' + esc(ep.hostname) + '</span></div>' +
        '<div class="info-item"><span class="ik">IP Address</span><span class="iv">' + esc(ep.ip || 'N/A') + '</span></div>' +
        '<div class="info-item"><span class="ik">URL</span><span class="iv">' + esc(ep.url) + '</span></div>' +
        '<div class="info-item"><span class="ik">Port</span><span class="iv">' + ep.port + '</span></div>' +
        '<div class="info-item"><span class="ik">Service Type</span><span class="iv">' + esc(ep.service_type || 'Unknown') + '</span></div>' +
        '<div class="info-item"><span class="ik">Region</span><span class="iv">' + esc(ep.region || 'Unknown') + '</span></div>' +
        '<div class="info-item"><span class="ik">Subaccount</span><span class="iv">' + esc(ep.subaccount || 'N/A') + '</span></div>' +
        '<div class="info-item"><span class="ik">Auth Type</span><span class="iv">' + esc(ep.auth_type || 'N/A') + '</span></div>' +
        '<div class="info-item"><span class="ik">HTTP Status</span><span class="iv">' + (ep.status_code || 'N/A') + '</span></div>' +
        '<div class="info-item"><span class="ik">Server</span><span class="iv">' + esc(ep.server_header || 'N/A') + '</span></div>' +
        '<div class="info-item"><span class="ik">Source</span><span class="iv">' + esc(ep.source || 'N/A') + '</span></div>' +
        '</div>';

    var techHtml = '';
    if (ep.technologies && ep.technologies.length > 0) {
        techHtml = '<div class="modal-section"><h4>Technologies</h4><div style="display:flex;gap:6px;flex-wrap:wrap;">';
        ep.technologies.forEach(function(t) { techHtml += '<span class="badge">' + esc(t) + '</span>'; });
        techHtml += '</div></div>';
    }

    var sshHtml = '';
    if (ep.ssh_info && ep.ssh_info.open) {
        sshHtml = '<div class="modal-section"><h4>CF SSH (Port 2222)</h4><div class="info-grid">';
        if (ep.ssh_info.banner) sshHtml += '<div class="info-item"><span class="ik">Banner</span><span class="iv">' + esc(ep.ssh_info.banner) + '</span></div>';
        if (ep.ssh_info.cloud_provider) sshHtml += '<div class="info-item"><span class="ik">Cloud Provider</span><span class="iv">' + esc(ep.ssh_info.cloud_provider) + '</span></div>';
        if (ep.ssh_info.cloud_region) sshHtml += '<div class="info-item"><span class="ik">Cloud Region</span><span class="iv">' + esc(ep.ssh_info.cloud_region) + '</span></div>';
        if (ep.ssh_info.rdns) sshHtml += '<div class="info-item"><span class="ik">rDNS</span><span class="iv">' + esc(ep.ssh_info.rdns) + '</span></div>';
        sshHtml += '</div></div>';
    }

    var findings = '';
    (ep.findings || []).forEach(function(f) {
        findings += '<div class="modal-finding" onclick="this.classList.toggle(\'open\')">' +
            '<div class="mf-top"><span class="mf-name">' + esc(f.name) + '</span>' +
            '<span class="finding-sev fs-' + f.severity.toLowerCase() + '">' + f.severity + '</span></div>' +
            '<div class="mf-body">' + esc(f.description) +
            (f.detail ? '<br><br><strong>Detail:</strong> ' + esc(f.detail) : '') +
            (f.remediation ? '<br><br><strong>Remediation:</strong> ' + esc(f.remediation) : '') +
            '</div></div>';
    });

    document.getElementById('modal-title').innerHTML =
        '<div class="sys-icon btp" style="width:32px;height:32px;font-size:9px;">BTP</div> ' + esc(ep.hostname);
    document.getElementById('modal-body').innerHTML =
        '<div class="modal-section"><h4>Endpoint Information</h4>' + info + '</div>' +
        techHtml + sshHtml +
        '<div class="modal-section"><h4>Findings (' + (ep.findings || []).length + ')</h4>' +
        (findings || '<div class="empty-state">No findings for this endpoint.</div>') + '</div>';
    document.getElementById('modal').classList.add('open');
}
function toggleConsole() {
    var panel = document.getElementById('consolePanel');
    var toggle = document.getElementById('consoleToggle');
    // If maximized and closing, remove maximized too
    if (panel.classList.contains('open') && panel.classList.contains('maximized')) {
        panel.classList.remove('maximized');
        toggle.classList.remove('maximized');
        document.getElementById('consoleMaxBtn').innerHTML = '&#9634;';
    }
    panel.classList.toggle('open');
    toggle.classList.toggle('open');
    toggle.innerHTML = panel.classList.contains('open') ? '&#9660; Console' : '&#9650; Console';
    var body = document.getElementById('console-body');
    body.scrollTop = body.scrollHeight;
}

function toggleConsoleMax() {
    var panel = document.getElementById('consolePanel');
    var toggle = document.getElementById('consoleToggle');
    var btn = document.getElementById('consoleMaxBtn');
    if (!panel.classList.contains('open')) {
        panel.classList.add('open');
        toggle.classList.add('open');
        toggle.innerHTML = '&#9660; Console';
    }
    panel.classList.toggle('maximized');
    toggle.classList.toggle('maximized');
    btn.innerHTML = panel.classList.contains('maximized') ? '&#9635;' : '&#9634;';
    var body = document.getElementById('console-body');
    body.scrollTop = body.scrollHeight;
}

// === Export ===
function exportHtmlReport() {
    apiPost('/api/export_html').then(function(r) {
        if (r.error) alert(r.error);
        else appendConsoleLine(getTimestamp(), '[+] HTML report saved: ' + r.path, 'cl-ok');
    });
}
function exportJson() {
    apiPost('/api/export_json').then(function(r) {
        if (r.error) alert(r.error);
        else appendConsoleLine(getTimestamp(), '[+] JSON exported: ' + r.path, 'cl-ok');
    });
}
</script>
</body>
</html>"""


# =============================================================================
# pywebview compatibility patches for older WebKit2GTK (< 2.40)
# =============================================================================

def _patch_pywebview_gtk():
    """Monkey-patch pywebview's GTK backend for WebKit2GTK 2.38.x compat.

    pywebview 5.x uses APIs that only exist in WebKit2GTK >= 2.40:
      - NavigationAction.get_frame_name()  (removed in newer WebKit2)
      - WebView.evaluate_javascript()      (added in WebKit2GTK 2.40)
    On Ubuntu 20.04 (WebKit2GTK 2.38) these crash at runtime.
    We fall back to run_javascript() + run_javascript_finish().
    """
    try:
        from webview.platforms import gtk as wv_gtk
        from webview.util import inject_pywebview
    except ImportError:
        return

    # Quick check: if evaluate_javascript exists, no patching needed
    try:
        import gi
        gi.require_version('WebKit2', '4.0')
        from gi.repository import WebKit2 as _wk
        if hasattr(_wk.WebView, 'evaluate_javascript'):
            return
    except Exception:
        pass

    BV = wv_gtk.BrowserView

    # --- Patch 1: on_navigation -------------------------------------------
    # get_frame_name() doesn't exist on WebKit2GTK 2.38 NavigationAction.
    _orig_on_nav = BV.on_navigation

    def _compat_on_navigation(self, webview, decision, decision_type):
        try:
            return _orig_on_nav(self, webview, decision, decision_type)
        except AttributeError:
            decision.use()

    BV.on_navigation = _compat_on_navigation

    # --- Patch 2: _set_js_api ---------------------------------------------
    # Fall back to run_javascript() for the JS bridge injection.
    def _compat_set_js_api(self):
        def create_bridge():
            script = inject_pywebview(self.js_bridge.window, wv_gtk.renderer)
            self.webview.run_javascript(script, None, None, None)
            self.loaded.set()

        wv_gtk.glib.idle_add(create_bridge)

    BV._set_js_api = _compat_set_js_api

    # --- Patch 3: evaluate_js ---------------------------------------------
    # evaluate_javascript() / evaluate_javascript_finish() don't exist.
    # Use run_javascript() / run_javascript_finish() + get_js_value().
    from threading import Semaphore
    from uuid import uuid1
    import json as _json

    def _compat_evaluate_js(self, script):
        def _run():
            self.webview.run_javascript(script, None, _callback, None)

        def _callback(webview, task, _user_data=None):
            try:
                js_result = webview.run_javascript_finish(task)
                jsc_value = js_result.get_js_value()
                result = jsc_value.to_string() if jsc_value else None
            except Exception:
                result = None

            if unique_id in self.js_results:
                self.js_results[unique_id]['result'] = result
            result_semaphore.release()

        unique_id = uuid1().hex
        result_semaphore = Semaphore(0)
        self.js_results[unique_id] = {'semaphore': result_semaphore, 'result': None}

        self.loaded.wait()
        wv_gtk.glib.idle_add(_run)
        result_semaphore.acquire()

        result = self.js_results[unique_id]['result']
        result = (
            None
            if result == 'undefined' or result == 'null' or result is None
            else result
            if result == ''
            else _json.loads(result)
        )

        del self.js_results[unique_id]
        return result

    BV.evaluate_js = _compat_evaluate_js


# =============================================================================
# Main Entry Point
# =============================================================================

def create_gui():
    """Start the local HTTP server and open the GUI."""
    port = find_free_port()
    url = 'http://127.0.0.1:%d' % port

    # Start Bottle server in a daemon thread
    server_thread = threading.Thread(
        target=lambda: app.run(host='127.0.0.1', port=port, quiet=True),
        daemon=True)
    server_thread.start()

    # Give the server a moment to start
    time.sleep(0.5)

    # Try pywebview first, fall back to browser
    use_browser = '--browser' in sys.argv
    if not use_browser:
        try:
            import webview
            _patch_pywebview_gtk()
            window = webview.create_window(
                title='[SAP.ology] - SAP Network Topology Scanner',
                url=url,
                width=1400,
                height=900,
                min_size=(1024, 700),
                text_select=True,
            )
            webview.start()
            return
        except Exception as e:
            print("[*] pywebview failed (%s), falling back to browser" % e)

    # Browser fallback
    print("[*] SAPology GUI running at: %s" % url)
    print("[*] Press Ctrl+C to stop the server")
    webbrowser.open(url)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")


if __name__ == '__main__':
    create_gui()

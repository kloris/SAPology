# SAPology Security Audit Report

**Date**: 2026-02-25
**Scope**: Full repository security review of SAPology SAP Network Topology Scanner
**Context**: SAPology is a legitimate SAP security testing/scanning tool. Some findings (e.g., SSL bypass, default credentials lists) are intentional by design. This audit flags them with context.

---

## Summary

| Severity | Count | Categories |
|----------|-------|------------|
| CRITICAL | 3 | SSL/TLS bypass, open URL handler, default credentials in source |
| HIGH | 3 | Path traversal in file writes, unbounded resource allocation, weak ciphers |
| MEDIUM | 8 | Warning suppression, weak RNG, missing input validation, XSS risk, unvalidated URL input, info disclosure, unsafe file permissions, credentials in memory |
| LOW | 5 | Bare exception handlers, verbose error output, TOCTOU race conditions, unbounded splits, port bounds checking |
| **Total** | **19** | |

---

## CRITICAL Findings

### C1. SSL/TLS Certificate Verification Globally Disabled

**Files**: `SAPology.py` (lines 114, 954-955, 1039, 1066, 1404, 1441, 1864, 1908, 2304, 2322, 2363, 2381, 2693, 2736, 2962-2963, 3270, 3293-3294, 3380, 3431, 3479, 3527, 3578, 3635, 3689), `SAPology_btp.py` (lines 60, 634, 665, 972-973, 1022-1023, 1457, 1544, 1617)

**Issue**: Over 25 instances of `verify=False` in `requests` calls, plus `ssl.CERT_NONE` and `ctx.check_hostname = False` in raw SSL contexts. The urllib3 InsecureRequestWarning is globally suppressed.

**Risk**: Man-in-the-middle attacks against the scanner itself. A network attacker could intercept and modify scan results or inject malicious responses.

**Context**: Intentional for a scanner that must probe systems with self-signed certs. However, the tool itself is vulnerable during scanning.

**Recommendation**: Add a `--verify-ssl` flag (default off for target scanning, on for any external API calls like Shodan/Censys). Document the MITM risk. Don't suppress warnings globally - only for target connections.

---

### C2. Open URL Handler Without Validation (`SAPology_gui.py:511-521`)

**File**: `SAPology_gui.py`, lines 511-521

```python
@app.post('/api/open_url')
def route_open_url():
    data = request.json or {}
    url = data.get("url", "")
    if url:
        import webbrowser
        webbrowser.open(url)  # No validation!
```

**Risk**: The `/api/open_url` endpoint accepts any URL and opens it in the system browser via `webbrowser.open()`. While the Bottle server listens on localhost, this is effectively an SSRF/open-redirect: any local process (or XSS in the webview) can trigger arbitrary URL opens, including `file://`, `javascript:`, or malicious links.

**Recommendation**: Validate that the URL scheme is `http` or `https` and optionally restrict to scan-related domains.

---

### C3. Default SAP Credentials Hardcoded in Source (`files/sap_default_creds.py:40-48`)

**File**: `files/sap_default_creds.py`, lines 40-48

```python
DEFAULT_CREDENTIALS = [
    ("CRITICAL", "SAP*",       "06071992",  "ALL"),
    ("CRITICAL", "SAP*",       "PASS",      "ALL"),
    ("CRITICAL", "DDIC",       "19920706",  "ALL"),
    ("HIGH",     "EARLYWATCH", "SUPPORT",   "066"),
    ("MEDIUM",   "TMSADM",    "PASSWORD",  "ALL"),
    ("MEDIUM",   "TMSADM",    "$1Pawd2&",  "ALL"),
    ("MEDIUM",   "SAPCPIC",   "ADMIN",     "ALL"),
]
```

**Risk**: Well-known SAP default credentials are embedded in source code committed to version control. While these are public knowledge (SAP security notes), having them in a public repo lowers the barrier for misuse.

**Context**: This is standard practice for SAP security tools (similar to tools like pySAP). The credentials are publicly documented by SAP.

**Recommendation**: Add a prominent disclaimer and responsible-use notice. Consider loading from an external config file that's .gitignored.

---

## HIGH Findings

### H1. Path Traversal in Packet Dump File Writes (`files/sap_gw_xpg_standalone.py:840-853`)

**File**: `files/sap_gw_xpg_standalone.py`, lines 840-853

```python
if args.dump_packets:
    with open("%s_p1.bin" % args.dump_packets, "wb") as f:
        f.write(p1_data)
```

**Risk**: The `--dump-packets` argument is used directly as a file path prefix without sanitization. An attacker could supply `../../../etc/cron.d/backdoor` to write files to arbitrary locations.

**Recommendation**: Sanitize the path with `os.path.basename()` or restrict output to a specific directory.

---

### H2. Unbounded Range in Instance Parsing - DoS (`SAPology.py:4876-4887`)

**File**: `SAPology.py`, lines 4876-4887

```python
def parse_instance_range(range_str):
    for part in range_str.split(","):
        if "-" in part:
            start, end = part.split("-", 1)
            for i in range(int(start), int(end) + 1):  # No upper bound!
                instances.append(i)
```

**Risk**: A user supplying `0-999999999` would cause excessive memory allocation and CPU usage. SAP instances are typically 00-99.

**Recommendation**: Cap the range to 0-99 (valid SAP instance numbers) and reject values outside that range.

---

### H3. Insecure Cipher Suites Enabled (`SAPology.py:2967`, `SAPology_btp.py:1024`)

**Files**: `SAPology.py` line 2967, `SAPology_btp.py` line 1024

```python
ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
```

**Risk**: Enables weak/deprecated cipher suites including those vulnerable to known attacks (BEAST, POODLE, etc.).

**Context**: Intentional for detecting legacy SSL/TLS versions on target systems.

**Recommendation**: Document that this is for probing only. Ensure the scanner's own outbound connections (Shodan API, etc.) never use weakened contexts.

---

## MEDIUM Findings

### M1. Global Warning Suppression (`SAPology.py:114`, `SAPology_btp.py:60`)

Suppresses all urllib3 security warnings globally, hiding genuine security issues.

### M2. Weak Random Number Generation (`files/sap_client_enum.py:358`, `files/sap_rfc_system_info.py:234`)

Uses `random` module instead of `secrets` for generating strings and connection IDs in security-relevant contexts.

### M3. Missing Input Validation on Thread/Timeout Parameters (`SAPology.py:7103-7106`, `SAPology_btp.py:2450-2451`)

`--threads` and `--timeout` accept any integer without bounds checking. Negative or extremely large values could cause undefined behavior.

### M4. Potential XSS via innerHTML Without Consistent Escaping (`SAPology_gui.py`)

The GUI uses `innerHTML` extensively (~40 instances). While an `esc()` function exists (line 2129), not all dynamic content insertion uses it consistently. Data from scan results (hostnames, SIDs, paths) rendered via `innerHTML` could contain malicious payloads if a target SAP system returns crafted responses.

### M5. Unvalidated URL/Hostname Input - SSRF Potential (`SAPology.py`, `SAPology_btp.py`)

User-supplied targets are used directly in URL construction (`"%s://%s:%d"`) without validation. No checks prevent scanning of localhost, 127.0.0.1, or internal cloud metadata endpoints (169.254.169.254).

### M6. Error Details Stored in Output (`SAPology.py:1839`, `SAPology_gui.py:373-402`)

Exception messages and full tracebacks are captured in output data and printed to console, potentially exposing system internals.

### M7. Files Created Without Explicit Permissions (`files/sap_gw_xpg_standalone.py:842-853`)

Binary packet dump files are created using default `open()` without specifying restrictive permissions. Files inherit umask defaults which may be world-readable.

### M8. API Credentials Stored as Plain-Text Attributes (`SAPology_btp.py:548-550`)

Shodan/Censys API credentials are stored as plain-text object attributes without any protection.

---

## LOW Findings

### L1. Bare Exception Handlers (`SAPology.py` - multiple locations)

Generic `except Exception: pass` blocks silently swallow all errors, potentially masking security issues.

### L2. Verbose Error Messages Expose Internals (`files/sap_gw_xpg_standalone.py:865,877`)

Socket error messages printed directly to console could reveal internal network topology.

### L3. TOCTOU Race Condition in File Operations (`SAPology_gui.py:217,239`)

Output file paths are constructed before files are opened, creating a small window for race conditions.

### L4. Unbounded String Splitting (`SAPology.py:2109,2326-2327`)

Network-derived data split without size limits on results.

### L5. Port/Instance Number Bounds Not Checked (`files/sap_gw_xpg_standalone.py:827`)

Instance number used in port calculation (`3300 + int(args.instance)`) without validating the result is a valid port number (0-65535).

---

## Positive Security Practices Observed

1. **HTML escaping function exists** - `esc()` in `SAPology_gui.py:2129` for XSS prevention
2. **Localhost-only GUI binding** - Bottle server binds to `127.0.0.1` only
3. **Network frame size limits** - `ni_recv()` caps frames at 1MB (`sap_gw_xpg_standalone.py:42`)
4. **Timeouts on network operations** - Socket timeouts are generally set
5. **No `eval()`/`exec()`/`os.system()`** - No command injection via dynamic code execution
6. **No unsafe deserialization** - No `pickle.loads()`, `yaml.load()`, or `marshal.load()`
7. **Good .gitignore coverage** - Secrets (`.env`, `*.pem`, `*.key`), credentials, and reports are excluded
8. **Thread pool usage** - `ThreadPoolExecutor` used instead of raw thread creation
9. **opt-in dangerous features** - Default credential scanning requires explicit `--default-creds` flag with warning about account lockout

---

## Dependency Review

| Package | Version Spec | Notes |
|---------|-------------|-------|
| requests | >=2.22.0 | No pinned upper bound - could pull breaking changes |
| rich | >=12.0.0 | Display library, low risk |
| bottle | >=0.12.0 | Micro web framework - ensure >=0.12.25 for security fixes |
| pywebview | >=4.0.0 | Desktop webview, low risk |

**Recommendations**:
- Pin dependency versions (e.g., `requests>=2.31.0,<3.0`) to prevent supply chain attacks
- `bottle>=0.12.0` is very broad - versions before 0.12.25 have known security issues
- Consider adding a `requirements.lock` or using `pip-compile` for reproducible builds

---

## Recommendations Summary

### Immediate Actions
1. **Validate file paths** in `--dump-packets` argument (H1)
2. **Bound instance range** to 0-99 in `parse_instance_range()` (H2)
3. **Validate URL scheme** in `/api/open_url` endpoint (C2)
4. **Bound `--threads` and `--timeout`** parameters (M3)

### Short-Term Improvements
5. Add `--verify-ssl` option for the scanner's own connections
6. Use `secrets` module for security-relevant random generation
7. Ensure all `innerHTML` assignments use `esc()` for dynamic data
8. Add SSRF protection (block localhost, link-local, metadata IPs)
9. Pin dependency versions in `requirements.txt`

### Long-Term Considerations
10. Add input validation framework for all CLI arguments
11. Implement structured logging instead of print statements
12. Consider moving default credentials to external config
13. Add security headers to Bottle responses (CSP, X-Frame-Options)
14. Add rate limiting to GUI API endpoints

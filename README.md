<p align="center">
  <img src="files/sapology-banner.gif" alt="SAPology Banner" width="600">
</p>

<h1 align="center">[SAPology]</h1>
<p align="center">
  <strong>SAP Network Topology Scanner</strong><br>
  <em>The scanner that speaks SAPanese</em><br>
  Fluent in DIAG &middot; RFC &middot; Gateway &middot; MS &middot; ICM &middot; J2EE &middot; BTP Cloud
</p>

<p align="center">
  <em>by <a href="https://github.com/kloris">Joris van de Vis</a></em>
</p>

---

SAPology is an **SAP security testing tool** for discovering, fingerprinting, and assessing SAP systems on a network. It combines port scanning, protocol-level fingerprinting (DIAG, RFC, Gateway, Message Server, ICM, SAPControl), and vulnerability assessment into a single self-contained scanner. It also includes a **BTP Cloud Scanner** for discovering and assessing SAP Business Technology Platform services exposed on the internet.

## Features

- **Two-phase discovery** - Quick pre-scan identifies SAP hosts, full scan enumerates all services
- **Protocol fingerprinting** - Native parsing of SAP DIAG, RFC, Gateway, Message Server, ICM, P4, and SAP Router protocols
- **SAPControl interrogation** - Extracts SID, kernel version, instance details, and system topology via SOAP
- **System type detection** - Identifies ABAP, Java, ABAP+Java, BusinessObjects, Cloud Connector, Content Server, SAP Router, MDM, and HANA systems
- **Vulnerability assessment** - Checks for 15+ CVEs and misconfigurations including unprotected gateways (SAPXPG), open Message Server ports, HTTP smuggling, exposed admin consoles, SSL/TLS weaknesses, and HTTP verb tampering
- **ICM URL scanning** - Tests 1,600+ SAP-specific URL paths per HTTP port for exposed endpoints
- **Hail Mary mode** - Scans all RFC 1918 private subnets (~17.9M IPs) using async two-phase subnet sweeping
- **BTP Cloud Scanner** - Discovers and assesses SAP BTP subaccounts, Cloud Foundry apps, XSUAA, CPI, and other cloud services via CT logs, DNS, Shodan, Censys, and Wayback Machine
- **HTML & JSON reporting** - Rich interactive HTML reports and structured JSON exports
- **Desktop GUI** - Native desktop interface with real-time dashboard, severity charts, and findings browser
- **Windows standalone** - Pre-built `.exe` that runs without Python

## Quick Start

### Command-Line Scanner

```bash
# Scan a single target
python3 SAPology.py -t 192.168.1.100

# Scan a subnet with verbose output
python3 SAPology.py -t 10.0.0.0/24 -v

# Scan with HTML report output
python3 SAPology.py -t 192.168.1.0/24 -o report.html

# Scan from a target file, export JSON
python3 SAPology.py -T targets.txt --json results.json

# Skip vulnerability checks (discovery only)
python3 SAPology.py -t 192.168.1.100 --skip-vuln

# Hail Mary - scan all private subnets
python3 SAPology.py --hail-mary
```

### BTP Cloud Scanner

```bash
# Scan a known BTP endpoint
python3 SAPology.py --btp-target myapp.cfapps.eu10.hana.ondemand.com

# Discover BTP subdomains via Certificate Transparency logs
python3 SAPology.py --btp-discover mycompany

# Scan a custom domain mapped to BTP
python3 SAPology.py --btp-target portal.mycompany.com

# Scan from a file of BTP endpoints
python3 SAPology.py --btp-targets btp_urls.txt

# BTP standalone mode (no SAPology.py needed)
python3 SAPology_btp.py -t myapp.cfapps.eu10.hana.ondemand.com
python3 SAPology_btp.py -d mycompany -o btp_report.html

# Combined on-prem + BTP scan
python3 SAPology.py -t 10.0.0.0/24 --btp-discover mycompany
```

### Desktop GUI

```bash
# Launch with native window (pywebview)
python3 SAPology_gui.py

# Launch in your default web browser
python3 SAPology_gui.py --browser
```

### Windows Standalone

Download `SAPology.exe` from the [Releases](../../releases) page and run from Command Prompt:

```cmd
SAPology.exe -t 192.168.1.100
SAPology.exe -t 10.0.0.0/24 -v -o report.html
```

No Python installation required.

## Installation

### Command-Line Scanner Prerequisites

| Requirement | Notes |
|---|---|
| **Python** | 3.7 or later |
| **requests** | HTTP library (required) |
| **rich** | Terminal formatting (optional, for progress bars) |

```bash
pip install requests rich
```

That's it. The scanner is a single file with no other dependencies.

### GUI Prerequisites

The GUI requires additional packages on top of the scanner prerequisites:

| Requirement | Notes |
|---|---|
| **bottle** | Lightweight HTTP server for the Python-JS bridge |
| **pywebview** | Native desktop window (optional, falls back to browser) |

```bash
pip install requests rich bottle pywebview
```

**pywebview system dependencies (Linux):**

On Ubuntu/Debian, pywebview requires WebKit2GTK:

```bash
sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.0
```

If pywebview is not installed or fails to load, the GUI automatically falls back to opening in your default web browser. You can also force browser mode:

```bash
python3 SAPology_gui.py --browser
```

### Building the Windows Executable

To build `SAPology.exe` yourself on a Windows machine:

1. Install Python 3.8+ from [python.org](https://python.org)
2. Place `SAPology.py` and `build_windows.bat` in the same folder
3. Double-click `build_windows.bat`
4. The executable will be created in the `dist\` folder

The batch file installs PyInstaller and all dependencies automatically.

## Supported Operating Systems

| OS | CLI Scanner | GUI (native window) | GUI (browser mode) | Standalone .exe |
|---|---|---|---|---|
| **Linux** (Ubuntu 20.04+, Debian, Kali, etc.) | Yes | Yes (with WebKit2GTK) | Yes | - |
| **macOS** | Yes | Yes | Yes | - |
| **Windows 10/11** | Yes (with Python) | Yes | Yes | Yes |
| **Windows** (no Python) | - | - | - | Yes |

## Command-Line Usage

```
usage: SAPology.py [-h] [--target TARGET] [--target-file TARGET_FILE]
                   [--instances INSTANCES] [--timeout TIMEOUT]
                   [--threads THREADS] [--output OUTPUT] [--json JSON_OUTPUT]
                   [--skip-vuln] [--skip-url-scan]
                   [--url-scan-threads URL_SCAN_THREADS]
                   [--gw-test-cmd GW_TEST_CMD] [-v] [--hail-mary]
                   [--hm-offsets HM_OFFSETS]
```

| Flag | Description |
|---|---|
| `-t`, `--target` | Target IP, hostname, or CIDR range (comma-separated) |
| `-T`, `--target-file` | File containing one target per line |
| `--instances` | SAP instance range to scan (default: `00-99`) |
| `--timeout` | Per-connection timeout in seconds (default: `3`) |
| `--threads` | Number of parallel scan threads (default: `20`) |
| `-o`, `--output` | HTML report output path |
| `--json` | JSON export output path |
| `--skip-vuln` | Skip Phase 2 vulnerability assessment |
| `--skip-url-scan` | Skip ICM URL scanning |
| `--url-scan-threads` | Threads for URL scanning (default: `25`) |
| `--gw-test-cmd` | OS command for gateway SAPXPG test (default: `id`) |
| `-v`, `--verbose` | Verbose output |
| `--hail-mary` | Scan all RFC 1918 private subnets |
| `--hm-offsets` | Custom host offsets for hail-mary subnet sampling |

## BTP Cloud Scanning

The BTP Cloud Scanner (`SAPology_btp.py`) discovers and assesses SAP Business Technology Platform services exposed on the internet. It runs as a standalone tool or integrated into SAPology.

### BTP Scan Phases

1. **Discovery** — Find BTP endpoints via Certificate Transparency logs (crt.sh), DNS enumeration, Shodan, Censys, and Wayback Machine
2. **Fingerprinting** — HTTP probing with 25+ SAP-specific paths, header analysis, TLS inspection, Cloud Foundry SSH detection (port 2222)
3. **Vulnerability Assessment** — 17 security checks covering authentication, configuration exposure, CORS, transport security, and information disclosure

### BTP Command-Line Flags

When used via `SAPology.py`:

| Flag | Description |
|---|---|
| `--btp` | Enable BTP cloud scanning mode |
| `--btp-target` | BTP hostname(s) to scan (comma-separated) |
| `--btp-discover` | Search CT logs for organization keyword |
| `--btp-domain` | Target custom domain (e.g., `mycompany.com`) |
| `--btp-subaccount` | Known subaccount identifier |
| `--btp-targets` | File with BTP URLs (one per line) |
| `--btp-regions` | Comma-separated BTP regions (default: `all`) |
| `--btp-skip-ct` | Skip Certificate Transparency log search |
| `--btp-skip-vuln` | Skip BTP vulnerability assessment |
| `--shodan-key` | Shodan API key for infrastructure discovery |
| `--censys-id` | Censys API ID |
| `--censys-secret` | Censys API secret |

When used standalone via `SAPology_btp.py`:

| Flag | Description |
|---|---|
| `-t`, `--target` | BTP hostname(s) to scan (comma-separated) |
| `-d`, `--discover` | Search CT logs for organization keyword |
| `--domain` | Target custom domain |
| `-s`, `--subaccount` | Known subaccount identifier |
| `-T`, `--targets` | File with BTP URLs (one per line) |
| `--regions` | Comma-separated BTP regions (default: `all`) |
| `--skip-ct` | Skip Certificate Transparency log search |
| `--skip-vuln` | Skip BTP vulnerability assessment |
| `-o`, `--output` | HTML report output path |
| `--json` | JSON export output path |
| `-v`, `--verbose` | Verbose output |
| `--threads` | Number of parallel threads (default: `20`) |
| `--timeout` | Per-connection timeout in seconds (default: `5`) |

### BTP Supported Regions

`eu10`, `eu20`, `eu30`, `us10`, `us20`, `us30`, `ap10`, `ap11`, `ap20`, `ap21`, `jp10`, `jp20`, `br10`, `ca10`

### BTP Service Types Detected

Cloud Foundry apps, Neo apps, XSUAA/IAS authentication, Cloud Integration (CPI), Launchpad/Work Zone, Portal, API Management, HANA Cloud, HDI containers, and custom domains mapped to BTP.

## GUI Features

The desktop GUI provides a real-time dashboard with:

- **Target configuration** - IP/CIDR input, instance ranges, threading options
- **Live scan progress** - Real-time console output, progress bar, and timer
- **Dashboard view** - Summary cards, discovered systems list, severity distribution chart, findings browser
- **URL Scan view** - Dedicated tab showing all URL scan results with status code filtering and path search
- **System detail modals** - Click any system to see its ports, findings (sorted by severity), and URL scan results
- **Export** - HTML report and JSON export buttons
- **Cancellation** - Stop a running scan at any point (both Phase 1 and Phase 2)

## Vulnerability Checks

SAPology tests for the following CVEs and misconfigurations during Phase 2 assessment:

| CVE / Check | CVSS | Description |
|---|---|---|
| **CVE-2025-31324 / CVE-2025-42999** | 10.0 / 9.1 | Visual Composer unauthenticated file upload + deserialization RCE |
| **CVE-2022-22536** (ICMAD) | 10.0 | HTTP request smuggling via ICM memory pipe desynchronization |
| **CVE-2020-6287** (RECON) | 10.0 | SAP LM Configuration Wizard missing authorization |
| **CVE-2020-6207** | 10.0 | Solution Manager EEM missing authentication |
| **CVE-2010-5326** | 10.0 | Invoker Servlet unauthenticated code execution |
| **CVE-2022-41272** | 9.9 | SAP P4 service unauthenticated access (PI/PO JMS Connector) |
| **CVE-2021-33690** | 9.9 | NWDI CBS server-side request forgery |
| **CVE-2024-41730** | 9.8 | BusinessObjects SSO token theft via REST API |
| **CVE-2025-0061** | 8.7 | BusinessObjects BI Launch Pad session hijacking |
| **CVE-2020-6308** | 5.3 | BusinessObjects server-side request forgery |
| **CVE-2021-21475** | -- | MDM missing authorization check |
| **CVE-2021-21482** | -- | MDM information disclosure |
| Gateway SAPXPG RCE | -- | Unprotected gateway allows OS command execution |
| Message Server ACL | -- | Internal MS port / monitor accessible from network |
| SAPControl exposure | -- | Unprotected SOAP management interface |
| BO CMC exposed | -- | BusinessObjects admin console accessible from network |
| BO CMS port exposed | -- | CMS port reachable (CVE-2026-0485 / CVE-2026-0490) |
| Cloud Connector exposed | -- | Administration port accessible from network |
| HANA SQL port exposed | -- | Database ports accessible from network |
| SSL/TLS weaknesses | -- | SSLv3, TLS 1.0/1.1, self-signed certificates |
| HTTP verb tampering | -- | Authentication bypass via HEAD/OPTIONS methods |
| Info disclosure | -- | /sap/public/info endpoint exposing system details |

## BTP Vulnerability Checks

The BTP Cloud Scanner tests for the following security issues:

| Check ID | Severity | Description |
|---|---|---|
| BTP-SSH-001 | HIGH | Cloud Foundry SSH enabled (Diego proxy on port 2222) — see [SAP Note 3395594](https://me.sap.com/notes/3395594) |
| BTP-SSH-002 | MEDIUM | Cloud infrastructure details leaked via reverse DNS |
| BTP-AUTH-001 | CRITICAL | Unauthenticated access to application data |
| BTP-AUTH-002 | HIGH | OData $metadata endpoint exposed without authentication |
| BTP-AUTH-003 | MEDIUM | OAuth token endpoint publicly reachable |
| BTP-CFG-001 | MEDIUM | xs-app.json routing configuration exposed |
| BTP-CFG-002 | LOW | manifest.json application metadata exposed |
| BTP-CFG-003 | HIGH | Spring Boot Actuator endpoints publicly accessible |
| BTP-CFG-004 | CRITICAL | Spring Boot Actuator /env endpoint leaking secrets |
| BTP-CFG-005 | LOW | Swagger/OpenAPI documentation publicly accessible |
| BTP-CORS-001 | MEDIUM | Wildcard CORS policy (Access-Control-Allow-Origin: *) |
| BTP-CORS-002 | MEDIUM | CORS accepts null origin |
| BTP-HDR-001 | LOW | Missing HSTS header (Strict-Transport-Security) |
| BTP-TLS-001 | MEDIUM | Legacy TLS versions enabled (TLS 1.0/1.1) |
| BTP-INFO-001 | MEDIUM | Error pages leaking stack traces or internal paths |
| BTP-INFO-002 | LOW | Server version information disclosed |
| BTP-INFO-003 | HIGH | Debug/trace mode enabled in production |

## Disclaimer

This tool is intended for **authorized security testing and assessment only**. Only use SAPology against systems you have explicit permission to test. Unauthorized scanning of computer systems is illegal in most jurisdictions.

## License

Copyright (c) 2025-2026 Joris van de Vis. All rights reserved.

## Credits & Acknowledgments

This tool builds on the work of several SAP security researchers and open-source projects:

| Project | Author(s) | Reference |
|---|---|---|
| [pysap](https://github.com/OWASP/pysap) | Martin Gallo (SecureAuth / OWASP) | SAP protocol dissection library (NI, Diag, MS, RFC, Router) |
| [SAP Gateway RCE](https://github.com/chipik/SAP_GW_RCE_exploit) | Dmitry Chastuhin ([@_chipik](https://github.com/chipik)) | Gateway RCE via misconfigured ACLs (SAPXPG) |
| [SAP Message Server PoC](https://github.com/gelim/sap_ms) | Mathieu Geli & Dmitry Chastuhin | MS attack tools ("SAP Gateway to Heaven", OPCDE 2019) |
| [SAP Nmap Probes](https://github.com/gelim/nmap-sap) | Mathieu Geli & Michael Medvedev (ERPScan) | Nmap service probes for SAP fingerprinting (DIAG, Router, P4) |
| [SAP RECON](https://github.com/chipik/SAP_RECON) | Dmitry Chastuhin, Pablo Artuso, Yvan 'iggy' G | PoC for CVE-2020-6287 (CVSS 10.0) |
| [Onapsis Research Labs](https://onapsis.com/research) | Martin Doyhenard et al. | ICMAD vulnerability research (CVE-2022-22536, CVSS 10.0) |
| [SEC Consult](https://sec-consult.com) | Fabian Hagg | CVE-2022-41272 - SAP P4 service unauthenticated access (CVSS 9.9) |

## Author

**Joris van de Vis** - SAP Security Researcher

- GitHub: [@kloris](https://github.com/kloris)

<img width="1400" height="910" alt="Screenshot 2026-02-11 at 16 45 53" src="https://github.com/user-attachments/assets/5bab7fc9-07e7-4fbb-a928-fe20fa5c52b0" />



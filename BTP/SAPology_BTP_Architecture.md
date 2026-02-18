# SAPology BTP Cloud Scanner — Architecture Design

**Module:** `SAPology_btp.py`
**Integration:** Standalone module + importable by `SAPology.py` and `SAPology_gui.py`
**Author:** Joris van de Vis — SecurityBridge Research Labs

---

## 1. Concept

Extend SAPology with a **BTP (Business Technology Platform) cloud scanning** module that discovers, fingerprints, and assesses SAP BTP subaccounts, applications, and services exposed on the internet. This mirrors SAPology's existing on-prem approach (two-phase discovery → fingerprinting → vuln assessment) but targets SAP's cloud URLs.

### Positioning
- **On-prem SAPology** = network scanner (ports, protocols, internal hosts)
- **BTP SAPology** = cloud surface scanner (URLs, subdomains, APIs, auth configs)

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     SAPology BTP Scanner                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐    │
│  │  PHASE 1     │  │  PHASE 2     │  │  PHASE 3           │    │
│  │  Discovery   │──│  Fingerprint │──│  Vuln Assessment   │    │
│  └──────────────┘  └──────────────┘  └────────────────────┘    │
│         │                  │                    │                │
│    ┌────┴────┐       ┌────┴────┐         ┌────┴────┐           │
│    │ CT Logs │       │ HTTP    │         │ Auth    │           │
│    │ DNS     │       │ Header  │         │ Config  │           │
│    │ Shodan  │       │ Path    │         │ CORS    │           │
│    │ Manual  │       │ Proto   │         │ CVE     │           │
│    └─────────┘       └─────────┘         │ Misconf │           │
│                                          └─────────┘           │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Reporting Engine                       │   │
│  │          (HTML / JSON / merge with on-prem results)      │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Phase 1 — Discovery (Passive + Active)

Goal: Build a list of live BTP endpoints associated with a target organization.

### 3.1 Input Modes

| Mode | Description | Example |
|------|-------------|---------|
| `--btp-domain <domain>` | Known custom domain | `mycompany.com` |
| `--btp-subaccount <name>` | Known subaccount ID | `a1b2c3d4trial` |
| `--btp-discover <keyword>` | Keyword-based CT log search | `acmecorp` |
| `--btp-targets <file>` | File with known BTP URLs | `btp_urls.txt` |

### 3.2 Certificate Transparency (CT) Log Mining

**What are CT Logs?**

Certificate Transparency logs are public, cryptographically verifiable, append-only ledgers maintained by Certificate Authorities. Every TLS certificate issued is recorded. By querying these logs, we can passively discover all subdomains that have had certificates issued — revealing BTP apps, subaccounts, and custom domains without sending a single packet to the target.

**Implementation:**

```python
class CTLogDiscovery:
    """
    Query Certificate Transparency logs for SAP BTP-related certificates.
    Primary source: crt.sh (free, no API key needed)
    """
    CRT_SH_URL = "https://crt.sh/?q={query}&output=json"

    SAP_BTP_PATTERNS = [
        "%.cfapps.{region}.hana.ondemand.com",    # CF apps
        "%.{region}.hana.ondemand.com",            # Neo apps
        "%.hana.ondemand.com",                      # General
        "%.ondemand.com",                            # Broader
        "%.authentication.{region}.hana.ondemand.com",  # XSUAA
        "%.accounts.ondemand.com",                  # Identity Auth
        "%.integrationsuite.cfapps.{region}.hana.ondemand.com",  # CPI
    ]

    BTP_REGIONS = [
        "eu10", "eu20", "eu30",                    # Europe
        "us10", "us20", "us30",                    # US
        "ap10", "ap11", "ap20", "ap21",            # Asia-Pacific
        "jp10", "jp20",                            # Japan
        "br10",                                    # Brazil
        "ca10",                                    # Canada
    ]

    async def search_org(self, keyword: str) -> list[str]:
        """Search CT logs for certificates matching org keyword."""
        # Query: %.keyword%.hana.ondemand.com
        # Also: O=keyword in certificate subject
        ...

    async def search_subaccount(self, subaccount: str) -> list[str]:
        """Search for specific subaccount across all regions."""
        ...

    def deduplicate_and_classify(self, raw_certs: list) -> dict:
        """
        Classify discovered hostnames into:
        - cf_apps: Cloud Foundry applications
        - neo_apps: Neo environment apps
        - xsuaa: Authentication endpoints
        - api_mgmt: API Management instances
        - integration: Integration Suite / CPI
        - portal: Launchpad / Portal sites
        - hdi: HANA HDI containers
        - custom: Custom domain mappings
        - unknown: Unclassified
        """
        ...
```

**crt.sh Query Examples:**
```
https://crt.sh/?q=%25.cfapps.eu10.hana.ondemand.com&output=json
https://crt.sh/?q=%25acmecorp%25.hana.ondemand.com&output=json
https://crt.sh/?q=acmecorp.com&output=json   (custom domains with SAP certs)
```

### 3.3 DNS Enumeration

```python
class DNSDiscovery:
    """Resolve and validate discovered hostnames."""

    async def resolve_batch(self, hostnames: list[str]) -> dict:
        """Async DNS resolution to filter dead/parked entries."""
        ...

    async def reverse_lookup(self, ips: list[str]) -> list[str]:
        """Reverse DNS on resolved IPs to find additional hostnames."""
        ...
```

### 3.4 Shodan / Censys Integration (Optional)

```python
class ShodanDiscovery:
    """
    Optional: Query Shodan for BTP infrastructure.
    Requires: --shodan-key <api_key>
    """
    SHODAN_FILTERS = [
        'ssl.cert.subject.CN:"hana.ondemand.com"',
        'http.title:"SAP" hostname:ondemand.com',
        'http.component:"SAP"',
    ]
```

---

## 4. Phase 2 — Service Fingerprinting

Goal: Identify what's running on each discovered endpoint.

### 4.1 BTP Service Signatures

```python
class BTPFingerprinter:
    """Fingerprint BTP services by probing known paths and analyzing responses."""

    # Service detection probes — ordered by specificity
    PROBES = [
        # Fiori / Launchpad
        {"path": "/cp.portal/site",              "detect": "fiori_launchpad"},
        {"path": "/sap/bc/ui5_ui5/",             "detect": "fiori_launchpad"},
        {"path": "/appconfig/fioriSandbox.html",  "detect": "fiori_launchpad"},

        # XSUAA / Authentication
        {"path": "/oauth/token",                  "detect": "xsuaa"},
        {"path": "/.well-known/openid-configuration", "detect": "xsuaa_oidc"},
        {"path": "/login/callback",               "detect": "xsuaa"},
        {"path": "/saml/SSO",                     "detect": "xsuaa_saml"},

        # OData / API
        {"path": "/sap/opu/odata/",              "detect": "odata_service"},
        {"path": "/v2/",                          "detect": "api_v2"},
        {"path": "/v4/",                          "detect": "api_v4"},
        {"path": "/$metadata",                    "detect": "odata_metadata"},
        {"path": "/api-docs",                     "detect": "swagger"},
        {"path": "/swagger-ui.html",              "detect": "swagger"},
        {"path": "/actuator",                     "detect": "spring_actuator"},
        {"path": "/actuator/health",              "detect": "spring_actuator"},
        {"path": "/actuator/env",                 "detect": "spring_actuator"},

        # SAP Integration Suite / CPI
        {"path": "/api/v1/",                      "detect": "integration_suite"},
        {"path": "/itspaces",                     "detect": "cpi_web_ui"},
        {"path": "/http/",                        "detect": "cpi_http_adapter"},

        # SAP HANA
        {"path": "/sap/hana/xs/",                "detect": "hana_xs"},
        {"path": "/sap/hana/ide/",               "detect": "hana_webide"},

        # SAPControl / Management
        {"path": "/SAPControl",                   "detect": "sapcontrol"},

        # App Router / xs-app.json
        {"path": "/xs-app.json",                  "detect": "approuter_config"},
        {"path": "/manifest.json",                "detect": "ui5_manifest"},

        # Default / error pages
        {"path": "/",                             "detect": "root"},
        {"path": "/healthcheck",                  "detect": "health_endpoint"},
    ]

    async def fingerprint(self, url: str) -> dict:
        """
        Probe endpoint and return service identification.
        Returns: {
            "url": "https://...",
            "status": 200,
            "service_type": "fiori_launchpad",
            "server_header": "SAP NetWeaver Application Server...",
            "auth_type": "xsuaa|basic|none|saml",
            "technologies": ["UI5", "Node.js", "Java"],
            "headers": {...},
            "tls_info": {...}
        }
        """
        ...
```

### 4.2 Cloud Foundry SSH (Port 2222) Detection

Cloud Foundry apps support SSH access via the Diego SSH proxy on **port 2222**. This is enabled by default and many customers never disable it. When open, it exposes:

- Direct container shell access (with valid CF OAuth token)
- Underlying infrastructure details (AWS/Azure/GCP hostnames via rDNS)
- Lateral movement path to internal CF networking and service bindings
- Access to `VCAP_SERVICES` env vars (database credentials, API keys)

**Real-world example:**
```
$ nmap -p 2222 <app>.cfapps.eu10-004.hana.ondemand.com -sV

PORT     STATE SERVICE VERSION
2222/tcp open  ssh     SSH (SSH-2.0-diego-ssh-proxy)

rDNS: ec2-3-70-38-218.eu-central-1.compute.amazonaws.com
```

This reveals: CF SSH enabled, hosted on AWS eu-central-1, specific EC2 instance IPs.

**Implementation:**

```python
class CFSSHScanner:
    """
    Detect Cloud Foundry Diego SSH proxy on port 2222.
    This check runs against every discovered CF app hostname.
    """
    DIEGO_PORT = 2222
    DIEGO_BANNER = "diego-ssh-proxy"

    async def check_ssh(self, hostname: str, timeout: float = 3.0) -> dict:
        """
        TCP connect to port 2222 and read SSH banner.
        Returns:
        {
            "hostname": "myapp-abc123.cfapps.eu10.hana.ondemand.com",
            "port": 2222,
            "open": True,
            "banner": "SSH-2.0-diego-ssh-proxy",
            "is_diego": True,
            "resolved_ips": ["3.70.38.218", "18.196.206.8", "3.65.185.47"],
            "rdns": ["ec2-3-70-38-218.eu-central-1.compute.amazonaws.com"],
            "cloud_provider": "AWS",
            "cloud_region": "eu-central-1",
            "infrastructure_details": {
                "provider": "AWS",
                "region": "eu-central-1",
                "service": "EC2"
            }
        }
        """
        result = {
            "hostname": hostname,
            "port": self.DIEGO_PORT,
            "open": False,
            "banner": None,
            "is_diego": False,
            "resolved_ips": [],
            "rdns": [],
            "cloud_provider": None,
            "cloud_region": None,
        }

        try:
            # Resolve hostname (often returns multiple IPs — CF load balancing)
            ips = await self._resolve(hostname)
            result["resolved_ips"] = ips

            # Reverse DNS on each IP to identify cloud provider
            for ip in ips:
                rdns = await self._reverse_lookup(ip)
                if rdns:
                    result["rdns"].append(rdns)
                    provider_info = self._identify_cloud_provider(rdns)
                    if provider_info:
                        result["cloud_provider"] = provider_info["provider"]
                        result["cloud_region"] = provider_info["region"]
                        result["infrastructure_details"] = provider_info

            # TCP connect and grab SSH banner
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, self.DIEGO_PORT),
                timeout=timeout
            )
            banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
            banner_str = banner.decode().strip()
            writer.close()

            result["open"] = True
            result["banner"] = banner_str
            result["is_diego"] = self.DIEGO_BANNER in banner_str.lower()

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass  # Port closed or filtered

        return result

    def _identify_cloud_provider(self, rdns: str) -> dict | None:
        """Identify cloud provider and region from rDNS hostname."""
        import re

        # AWS: ec2-1-2-3-4.eu-central-1.compute.amazonaws.com
        aws_match = re.search(
            r'ec2-[\d-]+\.([a-z0-9-]+)\.compute\.amazonaws\.com', rdns
        )
        if aws_match:
            return {
                "provider": "AWS",
                "region": aws_match.group(1),
                "service": "EC2"
            }

        # Azure: similar patterns
        if 'cloudapp.azure.com' in rdns or 'azurewebsites.net' in rdns:
            region_match = re.search(r'\.([a-z]+\d?)\.cloudapp', rdns)
            return {
                "provider": "Azure",
                "region": region_match.group(1) if region_match else "unknown",
                "service": "VM"
            }

        # GCP: 1.2.3.4.bc.googleusercontent.com
        if 'googleusercontent.com' in rdns or 'google.com' in rdns:
            return {
                "provider": "GCP",
                "region": "unknown",
                "service": "Compute Engine"
            }

        return None

    async def scan_batch(self, hostnames: list[str]) -> list[dict]:
        """Scan multiple CF app hostnames for SSH concurrently."""
        tasks = [self.check_ssh(h) for h in hostnames]
        return await asyncio.gather(*tasks)
```

### 4.3 Header Analysis

```python
class HeaderAnalyzer:
    """Extract intelligence from HTTP response headers."""

    SAP_HEADERS = {
        "sap-server":       "SAP server identifier",
        "sap-system":       "System ID",
        "sap-client":       "Default client",
        "sap-perf-fesrec":  "Frontend performance record",
        "x-sap-security-session": "Session type",
    }

    def analyze(self, headers: dict) -> dict:
        """
        Returns:
        - sap_specific_headers: dict of SAP-specific header values
        - security_headers: presence/absence of X-Frame-Options, CSP, HSTS, etc.
        - technology_hints: server software, framework indicators
        - cors_config: Access-Control-* header analysis
        """
        ...
```

---

## 5. Phase 3 — Vulnerability Assessment

Goal: Check each endpoint for security misconfigurations and known vulnerabilities.

### 5.1 Check Categories

```python
class BTPVulnAssessor:
    """Assess BTP endpoints for security issues."""

    checks = [
        # ── Cloud Foundry SSH Exposure ──
        "check_cf_ssh_enabled",             # Port 2222 open (diego-ssh-proxy)
        "check_cf_ssh_auth_bypass",         # SSH accepts connections without valid token?
        "check_cf_infrastructure_leak",     # rDNS reveals cloud provider/region/instance

        # ── Authentication & Authorization ──
        "check_unauthenticated_access",     # Can we reach data without auth?
        "check_metadata_exposure",          # $metadata accessible without auth
        "check_xsuaa_grant_types",          # client_credentials open?
        "check_oauth_token_endpoint",       # Token endpoint reachable?
        "check_missing_scope_checks",       # API returns data with any valid token

        # ── Configuration Exposure ──
        "check_xs_app_json_exposed",        # Routing config leaked
        "check_manifest_json_exposed",      # UI5 app config leaked
        "check_actuator_endpoints",         # Spring Boot actuator open
        "check_swagger_ui_exposed",         # API docs public
        "check_env_variables_leaked",       # /actuator/env with secrets
        "check_vcap_services_leaked",       # CF env bindings exposed

        # ── CORS & Transport Security ──
        "check_cors_wildcard",              # Access-Control-Allow-Origin: *
        "check_cors_null_origin",           # Null origin accepted
        "check_missing_hsts",              # No Strict-Transport-Security
        "check_tls_version",               # TLS 1.0/1.1 still accepted
        "check_weak_ciphers",              # Weak cipher suites

        # ── Information Disclosure ──
        "check_error_page_disclosure",      # Stack traces in error responses
        "check_version_disclosure",         # Server version in headers
        "check_directory_listing",          # Directory browsing enabled
        "check_debug_mode",                # Debug/trace mode on

        # ── Known CVEs ──
        "check_cve_database",              # Match service version to known CVEs
    ]
```

### 5.2 Severity Model (matches SAPology on-prem)

| Severity | Color  | Examples |
|----------|--------|----------|
| CRITICAL | 🔴 Red | Unauthenticated data access, leaked credentials |
| HIGH     | 🟠 Orange | Missing auth on APIs, actuator/env exposed |
| MEDIUM   | 🟡 Yellow | CORS wildcard, missing security headers |
| LOW      | 🔵 Blue | Version disclosure, swagger UI public |
| INFO     | ⚪ Gray | Service detected, header analysis |

### 5.3 Example Findings Output

```json
{
  "url": "https://myapp-abc123.cfapps.eu10.hana.ondemand.com",
  "service_type": "cf_application",
  "findings": [
    {
      "id": "BTP-SSH-001",
      "severity": "HIGH",
      "title": "Cloud Foundry SSH enabled (Diego proxy exposed)",
      "description": "Port 2222 is open with SSH-2.0-diego-ssh-proxy banner. An attacker with a stolen CF OAuth token can SSH directly into the application container, accessing environment variables (VCAP_SERVICES with DB credentials), internal CF networking, and potentially pivot to other services.",
      "evidence": "2222/tcp open — SSH-2.0-diego-ssh-proxy",
      "remediation": "Disable SSH at the app level: cf disable-ssh <app-name>. Or disable org-wide: cf disallow-space-ssh <space>. Verify with: cf ssh-enabled <app-name>"
    },
    {
      "id": "BTP-SSH-002",
      "severity": "MEDIUM",
      "title": "Cloud infrastructure details leaked via rDNS",
      "description": "Reverse DNS on the app's IP addresses reveals the underlying cloud provider, region, and instance identifiers. This aids targeted attacks against the infrastructure layer.",
      "evidence": "rDNS: ec2-3-70-38-218.eu-central-1.compute.amazonaws.com → AWS EC2, eu-central-1",
      "remediation": "Infrastructure-level finding. Disabling SSH (BTP-SSH-001) eliminates this exposure vector. Consider requesting SAP to suppress rDNS records."
    },
    {
      "id": "BTP-AUTH-001",
      "severity": "CRITICAL",
      "title": "Unauthenticated OData access",
      "description": "OData entity set /Products returns data without authentication",
      "evidence": "HTTP 200 with 147 records returned",
      "remediation": "Add authentication to xs-app.json route or enforce scopes in XSUAA"
    },
    {
      "id": "BTP-CORS-001",
      "severity": "MEDIUM",
      "title": "Wildcard CORS origin",
      "description": "Access-Control-Allow-Origin: * allows any origin",
      "evidence": "Header: Access-Control-Allow-Origin: *",
      "remediation": "Restrict CORS to specific trusted origins"
    }
  ]
}
```

---

## 6. CLI Integration

### 6.1 New CLI Flags

```
BTP Cloud Scanning:
  --btp                     Enable BTP cloud scanning mode
  --btp-domain DOMAIN       Target custom domain (e.g., mycompany.com)
  --btp-subaccount NAME     Known subaccount identifier
  --btp-discover KEYWORD    Search CT logs for org keyword
  --btp-targets FILE        File with known BTP URLs (one per line)
  --btp-regions REGIONS     Comma-separated BTP regions (default: all)
  --btp-skip-ct             Skip Certificate Transparency log search
  --btp-skip-vuln           Skip BTP vulnerability assessment
  --shodan-key KEY          Shodan API key for infrastructure discovery
```

### 6.2 Usage Examples

```bash
# Discover and scan all BTP assets for an organization
python3 SAPology.py --btp --btp-discover acmecorp -o btp_report.html

# Scan a known subaccount across all regions
python3 SAPology.py --btp --btp-subaccount a1b2c3trial -v

# Scan specific BTP URLs from a file
python3 SAPology.py --btp --btp-targets my_btp_urls.txt --json results.json

# Combined on-prem + BTP scan
python3 SAPology.py -t 10.0.0.0/24 --btp --btp-discover acmecorp -o full_report.html

# Discovery only (no vuln checks)
python3 SAPology.py --btp --btp-discover acmecorp --btp-skip-vuln
```

---

## 7. Module Structure

```
SAPology/
├── SAPology.py              # Main scanner (existing — add --btp flag hook)
├── SAPology_gui.py          # GUI (existing — add BTP tab)
├── SAPology_btp.py          # NEW: BTP cloud scanner module
├── files/
│   ├── sapology-banner.gif
│   ├── btp_paths.txt        # NEW: BTP-specific URL paths to probe
│   ├── btp_cves.json        # NEW: BTP component CVE database
│   └── btp_signatures.json  # NEW: Service fingerprint signatures
├── build_windows.bat
└── README.md
```

### 7.1 Integration Points

**In `SAPology.py`:**
```python
# At argument parsing
parser.add_argument('--btp', action='store_true', help='Enable BTP cloud scanning')
parser.add_argument('--btp-discover', type=str, help='CT log keyword search')
# ... other --btp-* flags

# In main():
if args.btp:
    from SAPology_btp import BTPScanner
    btp_scanner = BTPScanner(args)
    btp_results = await btp_scanner.run()
    # Merge BTP results into overall report
    all_results["btp"] = btp_results
```

**In `SAPology_gui.py`:**
```python
# Add "BTP Cloud" tab alongside existing scan configuration
# Real-time progress for CT log search, fingerprinting, vuln assessment
# BTP-specific dashboard cards and findings browser
```

---

## 8. Key Data Flows

### 8.1 CT Log → Discovery → Fingerprint → Assess

```
crt.sh API ──→ Raw certificates (JSON)
    │
    ▼
Parse & deduplicate hostnames
    │
    ▼
Classify by BTP service type (CF app, Neo, XSUAA, etc.)
    │
    ▼
Async DNS resolution (filter dead/unreachable)
    │
    ▼
Async HTTP fingerprinting (probe known paths, analyze headers)
    │
    ▼
Async vulnerability assessment (per-service check suite)
    │
    ▼
Aggregate findings ──→ HTML Report / JSON Export
```

### 8.2 crt.sh Response Example

```json
[
  {
    "issuer_ca_id": 16418,
    "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "common_name": "*.cfapps.eu10.hana.ondemand.com",
    "name_value": "myapp-x8k2j.cfapps.eu10.hana.ondemand.com",
    "not_before": "2025-01-15T00:00:00",
    "not_after": "2026-01-15T23:59:59",
    "serial_number": "0a1b2c3d4e5f..."
  }
]
```

From this single response, we extract: `myapp-x8k2j.cfapps.eu10.hana.ondemand.com` → CF app in EU10 region.

---

## 9. BTP Port & URL Pattern Reference

### 9.1 BTP Ports to Scan

| Port | Protocol | Service | Risk Level | Notes |
|------|----------|---------|------------|-------|
| 443  | HTTPS    | Application / API | Varies | Primary attack surface |
| 80   | HTTP     | Redirect / Misconfigured | Medium | Should redirect to 443; if serving content = finding |
| 2222 | SSH      | CF Diego SSH Proxy | High | Enabled by default! `cf ssh` access to container |
| 4443 | HTTPS    | CF Diego healthcheck / alt HTTPS | Low | Sometimes used for internal routing |
| 8443 | HTTPS    | Alternative HTTPS (custom apps) | Medium | Java apps sometimes bind here |
| 30015 | TCP     | HANA Cloud SQL (via Cloud Connector) | Critical | Should never be internet-exposed |
| 30013 | TCP     | HANA indexserver | Critical | Should never be internet-exposed |

> **Key insight:** Port 2222 is the highest-value non-HTTP check. CF SSH is enabled by default in most BTP environments, and most SAP customers are unaware it's exposed. A single stolen `cf` OAuth token gives full container access including `VCAP_SERVICES` with bound database credentials, API keys, and internal service URLs.

### 9.2 BTP URL Patterns

| Pattern | Service | Notes |
|---------|---------|-------|
| `<app>-<random>.cfapps.<region>.hana.ondemand.com` | CF Application | Most common |
| `<subaccount>.authentication.<region>.hana.ondemand.com` | XSUAA | Auth endpoints |
| `<subaccount>.<region>.hana.ondemand.com` | Neo Application | Legacy |
| `<tenant>.accounts.ondemand.com` | Identity Authentication (IAS) | SSO/IdP |
| `<subaccount>.integrationsuite.cfapps.<region>.hana.ondemand.com` | Integration Suite | CPI/iFlows |
| `<subaccount>.launchpad.cfapps.<region>.hana.ondemand.com` | Launchpad Service | Fiori |
| `<subaccount>.hana.<region>.hana.ondemand.com` | HANA Cloud | Database |
| `<subaccount>.apimanagement.<region>.hana.ondemand.com` | API Management | API Gateway |
| `<app>.cpp.cfapps.<region>.hana.ondemand.com` | Cloud Portal | Portal service |
| `<subaccount>.workzone.cfapps.<region>.hana.ondemand.com` | SAP Build Work Zone | Digital workspace |

---

## 10. Dependencies

| Package | Purpose | Required? |
|---------|---------|-----------|
| `requests` | HTTP probing (already in SAPology) | Yes |
| `aiohttp` or `httpx` | Async HTTP for bulk scanning | Recommended |
| `rich` | Terminal UI (already in SAPology) | Optional |
| `dnspython` | DNS resolution & enumeration | Recommended |
| `cryptography` | TLS certificate parsing | Optional |

**Design goal:** Keep it possible to run with just `requests` (sync fallback), but async path for performance when aiohttp/httpx is available — same philosophy as SAPology's optional `rich` dependency.

---

## 11. Implementation Roadmap

### Phase A — MVP (1-2 weeks)
- [ ] CT log querying via crt.sh
- [ ] Hostname parsing, deduplication, classification
- [ ] DNS resolution & liveness checks
- [ ] Basic HTTP fingerprinting (top 10 probes)
- [ ] CLI integration (`--btp` flags)
- [ ] JSON output

### Phase B — Full Fingerprinting (1-2 weeks)
- [ ] Complete probe list (all BTP service types)
- [ ] Header analysis engine
- [ ] XSUAA/OAuth detection
- [ ] TLS analysis
- [ ] HTML report generation (BTP section)

### Phase C — Vulnerability Assessment (2-3 weeks)
- [ ] Auth bypass checks
- [ ] CORS analysis
- [ ] Configuration exposure checks
- [ ] CVE matching engine
- [ ] Severity scoring & remediation advice
- [ ] GUI integration (BTP tab)

### Phase D — Advanced Discovery (ongoing)
- [ ] Shodan/Censys integration
- [ ] Passive DNS feeds
- [ ] Wayback Machine URL harvesting
- [ ] JavaScript analysis for leaked API keys/tokens
- [ ] Cloud Connector exposure detection

---

## 12. Legal & Ethical Considerations

| Activity | Legal Status | Notes |
|----------|-------------|-------|
| CT log querying | ✅ Fully legal | Public data, designed to be queried |
| DNS resolution | ✅ Legal | Public protocol |
| Shodan/Censys queries | ✅ Legal | Querying existing index |
| HTTP GET to public URLs | ⚠️ Gray area | Only with authorization |
| Active vulnerability probing | ❌ Requires authorization | Pentest scope needed |

**Default mode should be passive-only** (CT + DNS + Shodan). Active fingerprinting and vuln assessment require `--btp-active` flag with a warning banner, similar to how Nmap and other tools handle this.

```python
if args.btp_active:
    print("[!] ACTIVE SCANNING MODE - Ensure you have authorization")
    print("[!] Press Ctrl+C within 5 seconds to abort...")
    time.sleep(5)
```

---

*SAPology — now fluent in Cloud SAPanese too.*

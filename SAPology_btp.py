#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2026 Joris van de Vis
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
"""
SAPology BTP - SAP Business Technology Platform Cloud Scanner

Discovers, fingerprints, and assesses SAP BTP subaccounts, applications,
and services exposed on the internet. Mirrors SAPology's on-prem approach
but targets SAP cloud URLs and services.

For authorized security testing only.

Original idea & concept: Joris van de Vis

Dependencies: requests (pip install requests)
Optional:     rich (pip install rich) for progress bars
"""

import sys
import os
import socket
import json
import re
import ssl
import time
import warnings
import contextlib
import argparse
from dataclasses import dataclass, field
from enum import IntEnum
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse, quote

import requests
from requests.exceptions import RequestException
requests.packages.urllib3.disable_warnings()

try:
    from rich.console import Console
    from rich.progress import (Progress, SpinnerColumn, BarColumn, TextColumn,
                               TimeElapsedColumn, MofNCompleteColumn)
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Try importing Severity/Finding from SAPology for unified data model
try:
    from SAPology import Severity, Finding, SEVERITY_NAMES, SEVERITY_COLORS
except ImportError:
    class Severity(IntEnum):
        CRITICAL = 0
        HIGH = 1
        MEDIUM = 2
        LOW = 3
        INFO = 4

    SEVERITY_COLORS = {
        Severity.CRITICAL: "#e74c3c",
        Severity.HIGH: "#e67e22",
        Severity.MEDIUM: "#f1c40f",
        Severity.LOW: "#3498db",
        Severity.INFO: "#95a5a6",
    }

    SEVERITY_NAMES = {
        Severity.CRITICAL: "CRITICAL",
        Severity.HIGH: "HIGH",
        Severity.MEDIUM: "MEDIUM",
        Severity.LOW: "LOW",
        Severity.INFO: "INFO",
    }

    @dataclass
    class Finding:
        name: str
        severity: Severity
        description: str
        remediation: str = ""
        detail: str = ""
        port: int = 0

        def to_dict(self):
            return {
                "name": self.name,
                "severity": SEVERITY_NAMES[self.severity],
                "description": self.description,
                "remediation": self.remediation,
                "detail": self.detail,
                "port": self.port,
            }

VERBOSE = False


def log_verbose(msg):
    if VERBOSE:
        print(msg)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: Constants
# ═══════════════════════════════════════════════════════════════════════════════

BTP_REGIONS = [
    "eu10", "eu20", "eu30",
    "us10", "us20", "us30",
    "ap10", "ap11", "ap20", "ap21",
    "jp10", "jp20",
    "br10",
    "ca10",
]

BTP_URL_PATTERNS = {
    "cf_app":       "{app}.cfapps.{region}.hana.ondemand.com",
    "neo_app":      "{sub}.{region}.hana.ondemand.com",
    "xsuaa":        "{sub}.authentication.{region}.hana.ondemand.com",
    "ias":          "{tenant}.accounts.ondemand.com",
    "cpi":          "{sub}.integrationsuite.cfapps.{region}.hana.ondemand.com",
    "launchpad":    "{sub}.launchpad.cfapps.{region}.hana.ondemand.com",
    "hana_cloud":   "{sub}.hana.{region}.hana.ondemand.com",
    "api_mgmt":     "{sub}.apimanagement.{region}.hana.ondemand.com",
    "portal":       "{app}.cpp.cfapps.{region}.hana.ondemand.com",
    "workzone":     "{sub}.workzone.cfapps.{region}.hana.ondemand.com",
}

# Regex patterns to classify discovered hostnames
BTP_CLASSIFY_PATTERNS = [
    # Specific cfapps sub-patterns BEFORE generic cf_app
    (r"\.integrationsuite\.cfapps\.", "cpi"),
    (r"\.launchpad\.cfapps\.", "launchpad"),
    (r"\.workzone\.cfapps\.", "workzone"),
    (r"\.cpp\.cfapps\.", "portal"),
    # Generic cfapps
    (r"\.cfapps\.[a-z]{2}\d+(?:-\d+)?\.hana\.ondemand\.com$", "cf_app"),
    # Authentication and identity
    (r"\.authentication\.[a-z]{2}\d+\.hana\.ondemand\.com$", "xsuaa"),
    (r"\.accounts\.ondemand\.com$", "ias"),
    # Other services
    (r"\.apimanagement\.", "api_mgmt"),
    (r"\.hana\.[a-z]{2}\d+\.hana\.ondemand\.com$", "hana_cloud"),
    (r"\.[a-z]{2}\d+\.hana\.ondemand\.com$", "neo_app"),
    (r"\.ondemand\.com$", "unknown_btp"),
]

BTP_REGION_RE = re.compile(r"\.([a-z]{2}\d+)(?:-\d+)?\.hana\.ondemand\.com")

# HTTP probes for service fingerprinting — ordered by specificity
BTP_SERVICE_PROBES = [
    # Fiori / Launchpad
    ("/cp.portal/site", "fiori_launchpad"),
    ("/sap/bc/ui5_ui5/", "fiori_launchpad"),
    ("/appconfig/fioriSandbox.html", "fiori_launchpad"),

    # XSUAA / Authentication
    ("/.well-known/openid-configuration", "xsuaa_oidc"),
    ("/oauth/token", "xsuaa"),
    ("/login/callback", "xsuaa"),
    ("/saml/SSO", "xsuaa_saml"),

    # OData / API
    ("/sap/opu/odata/", "odata_service"),
    ("/$metadata", "odata_metadata"),
    ("/api-docs", "swagger"),
    ("/swagger-ui.html", "swagger"),

    # Spring Boot Actuator
    ("/actuator", "spring_actuator"),
    ("/actuator/health", "spring_actuator"),
    ("/actuator/env", "spring_actuator_env"),

    # SAP Integration Suite / CPI
    ("/api/v1/", "integration_suite"),
    ("/itspaces", "cpi_web_ui"),
    ("/http/", "cpi_http_adapter"),

    # SAP HANA
    ("/sap/hana/xs/", "hana_xs"),
    ("/sap/hana/ide/", "hana_webide"),

    # SAPControl / Management
    ("/SAPControl", "sapcontrol"),

    # App Router / xs-app.json
    ("/xs-app.json", "approuter_config"),
    ("/manifest.json", "ui5_manifest"),

    # Default / error pages
    ("/healthcheck", "health_endpoint"),
    ("/", "root"),
]

SAP_HEADERS = {
    "sap-server": "SAP server identifier",
    "sap-system": "System ID",
    "sap-client": "Default client",
    "sap-perf-fesrec": "Frontend performance record",
    "x-sap-security-session": "Session type",
}

SECURITY_HEADERS = [
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
]

BTP_PORTS = [443, 80, 2222, 4443, 8443, 30015, 30013]

# Cloud provider rDNS patterns
CLOUD_PROVIDER_RE = {
    "AWS": re.compile(r"ec2-[\d-]+\.([a-z0-9-]+)\.compute\.amazonaws\.com"),
    "Azure": re.compile(r"\.([a-z]+\d?)\.cloudapp\.azure\.com"),
    "GCP": re.compile(r"[\d.]+\.bc\.googleusercontent\.com"),
}


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class BTPEndpoint:
    url: str
    hostname: str
    ip: str = ""
    port: int = 443
    source: str = ""
    service_type: str = ""
    region: str = ""
    subaccount: str = ""
    status_code: int = 0
    server_header: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    auth_type: str = ""
    tls_info: Dict = field(default_factory=dict)
    ssh_info: Dict = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    alive: bool = False
    fingerprint_results: List[dict] = field(default_factory=list)

    def to_dict(self):
        return {
            "url": self.url,
            "hostname": self.hostname,
            "ip": self.ip,
            "port": self.port,
            "source": self.source,
            "service_type": self.service_type,
            "region": self.region,
            "subaccount": self.subaccount,
            "status_code": self.status_code,
            "server_header": self.server_header,
            "technologies": self.technologies,
            "auth_type": self.auth_type,
            "tls_info": self.tls_info,
            "ssh_info": self.ssh_info,
            "findings": [f.to_dict() for f in self.findings],
            "alive": self.alive,
            "fingerprint_results": self.fingerprint_results,
        }


@dataclass
class BTPScanResult:
    scan_time: str = ""
    keyword: str = ""
    domain: str = ""
    subaccount: str = ""
    regions_scanned: List[str] = field(default_factory=list)
    endpoints: List[BTPEndpoint] = field(default_factory=list)
    ct_certificates: int = 0
    dns_resolved: int = 0
    total_findings: int = 0
    scan_duration: float = 0.0
    config: Dict = field(default_factory=dict)

    def summary(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for ep in self.endpoints:
            for f in ep.findings:
                sname = SEVERITY_NAMES.get(f.severity, "info").lower()
                counts[sname] = counts.get(sname, 0) + 1
        counts["total_findings"] = sum(counts.values())
        counts["total_endpoints"] = len(self.endpoints)
        counts["alive_endpoints"] = sum(1 for ep in self.endpoints if ep.alive)
        counts["regions"] = len(set(ep.region for ep in self.endpoints if ep.region))
        return counts

    def to_dict(self):
        return {
            "scan_time": self.scan_time,
            "keyword": self.keyword,
            "domain": self.domain,
            "subaccount": self.subaccount,
            "regions_scanned": self.regions_scanned,
            "endpoints": [ep.to_dict() for ep in self.endpoints],
            "ct_certificates": self.ct_certificates,
            "dns_resolved": self.dns_resolved,
            "total_findings": self.total_findings,
            "scan_duration": self.scan_duration,
            "summary": self.summary(),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: Phase 1 — Discovery
# ═══════════════════════════════════════════════════════════════════════════════

class CTLogDiscovery:
    """Query Certificate Transparency logs for SAP BTP-related certificates."""

    CRT_SH_URL = "https://crt.sh/?q={query}&output=json"
    RATE_LIMIT = 2.0  # seconds between crt.sh queries

    def __init__(self, timeout=30):
        self.timeout = timeout
        self._last_query_time = 0

    def _rate_limit(self):
        elapsed = time.time() - self._last_query_time
        if elapsed < self.RATE_LIMIT:
            time.sleep(self.RATE_LIMIT - elapsed)
        self._last_query_time = time.time()

    def _query_crtsh(self, query):
        """Query crt.sh and return list of certificate entries."""
        self._rate_limit()
        url = self.CRT_SH_URL.format(query=quote(query, safe=""))
        log_verbose("  [CT] Querying: %s" % query)
        try:
            r = requests.get(url, timeout=self.timeout, verify=True)
            if r.status_code == 200 and r.text.strip():
                data = r.json()
                log_verbose("  [CT] Got %d certificate entries" % len(data))
                return data
            elif r.status_code == 429:
                log_verbose("  [CT] Rate limited, waiting 10s...")
                time.sleep(10)
                return self._query_crtsh(query)
        except (RequestException, ValueError) as e:
            log_verbose("  [CT] Query failed: %s" % e)
        return []

    def _extract_hostnames(self, cert_entries):
        """Extract unique hostnames from crt.sh certificate entries."""
        hostnames = set()
        for entry in cert_entries:
            name_value = entry.get("name_value", "")
            for line in name_value.split("\n"):
                h = line.strip().lower()
                if h and not h.startswith("*"):
                    hostnames.add(h)
            cn = entry.get("common_name", "").strip().lower()
            if cn and not cn.startswith("*"):
                hostnames.add(cn)
        return hostnames

    def search_org(self, keyword):
        """Search CT logs for certificates matching org keyword."""
        all_hosts = set()
        queries = [
            "%%.%s%%.hana.ondemand.com" % keyword,
            "%%.%s%%.ondemand.com" % keyword,
            "%s.com" % keyword,
        ]
        total_certs = 0
        for q in queries:
            entries = self._query_crtsh(q)
            total_certs += len(entries)
            all_hosts.update(self._extract_hostnames(entries))
        return all_hosts, total_certs

    def search_subaccount(self, subaccount):
        """Search for specific subaccount across all regions."""
        all_hosts = set()
        total_certs = 0
        queries = [
            "%s.%%.hana.ondemand.com" % subaccount,
            "%s.authentication.%%.hana.ondemand.com" % subaccount,
            "%s.cfapps.%%.hana.ondemand.com" % subaccount,
        ]
        for q in queries:
            entries = self._query_crtsh(q)
            total_certs += len(entries)
            all_hosts.update(self._extract_hostnames(entries))
        return all_hosts, total_certs

    def search_domain(self, domain):
        """Search for certificates issued to custom domain."""
        all_hosts = set()
        total_certs = 0
        queries = [
            "%%.%s" % domain,
            domain,
        ]
        for q in queries:
            entries = self._query_crtsh(q)
            total_certs += len(entries)
            all_hosts.update(self._extract_hostnames(entries))
        return all_hosts, total_certs


def classify_hostname(hostname):
    """Classify a BTP hostname into service type and extract region."""
    service_type = "unknown"
    region = ""

    for pattern, stype in BTP_CLASSIFY_PATTERNS:
        if re.search(pattern, hostname):
            service_type = stype
            break

    m = BTP_REGION_RE.search(hostname)
    if m:
        region = m.group(1)

    return service_type, region


def extract_subaccount(hostname, service_type):
    """Try to extract subaccount identifier from hostname."""
    parts = hostname.split(".")
    if not parts:
        return ""
    if service_type in ("xsuaa", "neo_app", "hana_cloud", "api_mgmt"):
        return parts[0]
    if service_type in ("cpi", "launchpad", "workzone"):
        return parts[0]
    if service_type == "cf_app":
        return parts[0]
    return ""


class DNSResolver:
    """Resolve and validate discovered hostnames."""

    def __init__(self, timeout=5):
        self.timeout = timeout

    def resolve(self, hostname):
        """Resolve a single hostname to IPs."""
        try:
            socket.setdefaulttimeout(self.timeout)
            results = socket.getaddrinfo(hostname, None, socket.AF_INET)
            ips = list(set(r[4][0] for r in results))
            return ips
        except (socket.gaierror, socket.timeout, OSError):
            return []

    def resolve_batch(self, hostnames, threads=50):
        """Parallel DNS resolution. Returns {hostname: [ips]}."""
        resolved = {}
        with ThreadPoolExecutor(max_workers=min(len(hostnames), threads)) as executor:
            futures = {executor.submit(self.resolve, h): h for h in hostnames}
            for future in as_completed(futures):
                h = futures[future]
                try:
                    ips = future.result()
                    if ips:
                        resolved[h] = ips
                except Exception:
                    pass
        return resolved

    def reverse_lookup(self, ip):
        """Reverse DNS lookup."""
        try:
            socket.setdefaulttimeout(self.timeout)
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return ""


class ShodanDiscovery:
    """Query Shodan for BTP infrastructure (requires API key)."""

    SHODAN_API = "https://api.shodan.io"

    def __init__(self, api_key, timeout=30):
        self.api_key = api_key
        self.timeout = timeout

    def search(self, keyword):
        """Search Shodan for SAP BTP-related hosts."""
        hostnames = set()
        queries = [
            'ssl.cert.subject.CN:"hana.ondemand.com" "%s"' % keyword,
            'http.title:"SAP" hostname:ondemand.com "%s"' % keyword,
        ]
        for q in queries:
            try:
                url = "%s/shodan/host/search" % self.SHODAN_API
                r = requests.get(url, params={"key": self.api_key, "query": q},
                                 timeout=self.timeout)
                if r.status_code == 200:
                    data = r.json()
                    for match in data.get("matches", []):
                        for h in match.get("hostnames", []):
                            hostnames.add(h.lower())
                        # Also extract from SSL cert
                        ssl_info = match.get("ssl", {})
                        cert = ssl_info.get("cert", {})
                        cn = cert.get("subject", {}).get("CN", "")
                        if cn and not cn.startswith("*"):
                            hostnames.add(cn.lower())
                elif r.status_code == 401:
                    print("[!] Shodan API key invalid")
                    return set()
            except RequestException as e:
                log_verbose("  [Shodan] Query failed: %s" % e)
        return hostnames


class CensysDiscovery:
    """Query Censys for BTP infrastructure (requires API credentials)."""

    CENSYS_API = "https://search.censys.io/api/v2"

    def __init__(self, api_id, api_secret, timeout=30):
        self.api_id = api_id
        self.api_secret = api_secret
        self.timeout = timeout

    def search(self, keyword):
        """Search Censys for SAP BTP-related hosts."""
        hostnames = set()
        query = 'services.tls.certificates.leaf.names: *%s*.hana.ondemand.com' % keyword
        try:
            url = "%s/hosts/search" % self.CENSYS_API
            r = requests.get(url, params={"q": query, "per_page": 100},
                             auth=(self.api_id, self.api_secret),
                             timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                for hit in data.get("result", {}).get("hits", []):
                    for name in hit.get("names", []):
                        if not name.startswith("*"):
                            hostnames.add(name.lower())
            elif r.status_code == 401:
                print("[!] Censys API credentials invalid")
                return set()
        except RequestException as e:
            log_verbose("  [Censys] Query failed: %s" % e)
        return hostnames


class WaybackDiscovery:
    """Query Wayback Machine CDX API for historical BTP URLs."""

    CDX_API = "https://web.archive.org/cdx/search/cdx"

    def __init__(self, timeout=30):
        self.timeout = timeout

    def search(self, domain):
        """Search Wayback Machine for archived BTP-related URLs."""
        hostnames = set()
        keyword = domain.split(".")[0]
        queries = [
            "*.%s" % domain,
            "*%s*.hana.ondemand.com" % keyword,
        ]
        for q in queries:
            try:
                r = requests.get(self.CDX_API, params={
                    "url": q,
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": 5000,
                }, timeout=self.timeout)
                if r.status_code == 200 and r.text.strip():
                    data = r.json()
                    for row in data[1:]:  # Skip header row
                        if row:
                            try:
                                parsed = urlparse(row[0])
                                h = parsed.hostname
                                if h and ("ondemand.com" in h or domain in h):
                                    hostnames.add(h.lower())
                            except Exception:
                                pass
            except (RequestException, ValueError) as e:
                log_verbose("  [Wayback] Query failed: %s" % e)
        return hostnames


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: Phase 2 — Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════════

class BTPFingerprinter:
    """Fingerprint BTP services by probing known paths and analyzing responses."""

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.header_analyzer = HeaderAnalyzer()

    def fingerprint(self, endpoint):
        """Probe endpoint with service detection paths."""
        base_url = endpoint.url.rstrip("/")

        # First, check if the endpoint is alive with a root request
        try:
            r = requests.get(base_url + "/", timeout=self.timeout, verify=False,
                             allow_redirects=False)
            endpoint.alive = True
            endpoint.status_code = r.status_code
            endpoint.server_header = r.headers.get("server", "")
            endpoint.headers = dict(r.headers)
        except RequestException:
            endpoint.alive = False
            return endpoint

        # Analyze headers from root response
        header_info = self.header_analyzer.analyze(endpoint.headers)
        endpoint.technologies = header_info.get("technologies", [])
        endpoint.auth_type = header_info.get("auth_type", "")

        # Probe service-specific paths
        detected_services = []
        for path, service_name in BTP_SERVICE_PROBES:
            if path == "/":
                # Already fetched root
                if r.status_code < 400:
                    detected_services.append({
                        "path": path,
                        "service": service_name,
                        "status": r.status_code,
                        "size": len(r.content),
                    })
                continue

            try:
                pr = requests.get(base_url + path, timeout=self.timeout,
                                  verify=False, allow_redirects=False)
                if pr.status_code < 400 or pr.status_code == 401:
                    detected_services.append({
                        "path": path,
                        "service": service_name,
                        "status": pr.status_code,
                        "size": len(pr.content),
                    })
                    log_verbose("    [FP] %s %s -> %d" % (endpoint.hostname, path, pr.status_code))
            except RequestException:
                pass

        endpoint.fingerprint_results = detected_services

        # Determine primary service type from probes
        if not endpoint.service_type or endpoint.service_type in ("unknown", "unknown_btp"):
            for result in detected_services:
                svc = result["service"]
                if svc not in ("root", "health_endpoint"):
                    endpoint.service_type = svc
                    break

        return endpoint

    def fingerprint_batch(self, endpoints, threads=20, cancel_check=None):
        """Parallel fingerprinting of multiple endpoints."""
        with ThreadPoolExecutor(max_workers=min(len(endpoints), threads)) as executor:
            futures = {executor.submit(self.fingerprint, ep): ep
                       for ep in endpoints if ep.alive}
            for future in as_completed(futures):
                if cancel_check and cancel_check():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    future.result()
                except Exception as e:
                    log_verbose("  [FP] Error: %s" % e)


class HeaderAnalyzer:
    """Extract intelligence from HTTP response headers."""

    def analyze(self, headers):
        """Analyze headers and return structured intelligence."""
        result = {
            "sap_headers": {},
            "security_headers": {},
            "technologies": [],
            "cors_config": {},
            "auth_type": "",
        }

        headers_lower = {k.lower(): v for k, v in headers.items()}

        # SAP-specific headers
        for hdr, desc in SAP_HEADERS.items():
            val = headers_lower.get(hdr)
            if val:
                result["sap_headers"][hdr] = val

        # Security headers
        for hdr in SECURITY_HEADERS:
            result["security_headers"][hdr] = hdr in headers_lower

        # CORS analysis
        acao = headers_lower.get("access-control-allow-origin", "")
        if acao:
            result["cors_config"]["allow_origin"] = acao
            result["cors_config"]["wildcard"] = acao == "*"
        acac = headers_lower.get("access-control-allow-credentials", "")
        if acac:
            result["cors_config"]["allow_credentials"] = acac.lower() == "true"

        # Technology detection
        server = headers_lower.get("server", "")
        powered_by = headers_lower.get("x-powered-by", "")
        cf_error = headers_lower.get("x-cf-routererror", "")

        if "sap" in server.lower():
            result["technologies"].append("SAP NetWeaver")
        if "nginx" in server.lower():
            result["technologies"].append("nginx")
        if "envoy" in server.lower():
            result["technologies"].append("Envoy")
        if powered_by:
            result["technologies"].append(powered_by)
        if cf_error:
            result["technologies"].append("Cloud Foundry")

        # Auth type detection
        www_auth = headers_lower.get("www-authenticate", "")
        if "bearer" in www_auth.lower():
            result["auth_type"] = "xsuaa"
        elif "basic" in www_auth.lower():
            result["auth_type"] = "basic"
        elif "saml" in www_auth.lower() or "saml" in headers_lower.get("location", "").lower():
            result["auth_type"] = "saml"

        return result


class CFSSHScanner:
    """Detect Cloud Foundry Diego SSH proxy on port 2222."""

    DIEGO_PORT = 2222
    DIEGO_BANNER = "diego-ssh-proxy"

    def __init__(self, timeout=3):
        self.timeout = timeout
        self.dns_resolver = DNSResolver(timeout=timeout)

    def check_ssh(self, hostname):
        """TCP connect to port 2222 and read SSH banner."""
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
            "infrastructure_details": None,
        }

        # Resolve hostname
        ips = self.dns_resolver.resolve(hostname)
        result["resolved_ips"] = ips

        # Reverse DNS on each IP to identify cloud provider
        for ip in ips[:3]:  # Limit to first 3 IPs
            rdns = self.dns_resolver.reverse_lookup(ip)
            if rdns and rdns.lower() != hostname.lower():
                result["rdns"].append(rdns)
                provider_info = self._identify_cloud_provider(rdns)
                if provider_info:
                    result["cloud_provider"] = provider_info["provider"]
                    result["cloud_region"] = provider_info.get("region", "unknown")
                    result["infrastructure_details"] = provider_info

            # If rDNS returned the custom domain itself (PTR override) or
            # didn't match a cloud provider, try constructing the AWS rDNS
            # name from the IP and verify with a forward lookup
            if not result["cloud_provider"]:
                aws_rdns = self._probe_aws_rdns(ip)
                if aws_rdns:
                    result["rdns"].append(aws_rdns)
                    provider_info = self._identify_cloud_provider(aws_rdns)
                    if provider_info:
                        result["cloud_provider"] = provider_info["provider"]
                        result["cloud_region"] = provider_info.get("region", "unknown")
                        result["infrastructure_details"] = provider_info

        # TCP connect and grab SSH banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((hostname, self.DIEGO_PORT))
            banner = sock.recv(256)
            sock.close()

            banner_str = banner.decode("utf-8", errors="replace").strip()
            result["open"] = True
            result["banner"] = banner_str
            result["is_diego"] = self.DIEGO_BANNER in banner_str.lower()
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

        return result

    def _probe_aws_rdns(self, ip):
        """Try to find the AWS rDNS name for an IP by probing known regions."""
        octets = ip.split(".")
        ip_slug = "-".join(octets)  # e.g., "3-70-38-218"
        # Try common AWS regions — the rDNS format is:
        # ec2-A-B-C-D.<region>.compute.amazonaws.com
        aws_regions = [
            "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3",
            "eu-north-1", "eu-south-1",
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
            "ap-northeast-2", "ap-south-1",
            "sa-east-1", "ca-central-1", "me-south-1", "af-south-1",
        ]
        for region in aws_regions:
            candidate = "ec2-%s.%s.compute.amazonaws.com" % (ip_slug, region)
            try:
                socket.setdefaulttimeout(2)
                resolved = socket.getaddrinfo(candidate, None, socket.AF_INET)
                resolved_ips = set(r[4][0] for r in resolved)
                if ip in resolved_ips:
                    return candidate
            except (socket.gaierror, socket.timeout, OSError):
                continue
        return None

    def _identify_cloud_provider(self, rdns):
        """Identify cloud provider and region from rDNS hostname."""
        # AWS
        m = CLOUD_PROVIDER_RE["AWS"].search(rdns)
        if m:
            return {"provider": "AWS", "region": m.group(1), "service": "EC2"}

        # Azure
        m = CLOUD_PROVIDER_RE["Azure"].search(rdns)
        if m:
            return {"provider": "Azure", "region": m.group(1), "service": "VM"}
        if "cloudapp.azure.com" in rdns or "azurewebsites.net" in rdns:
            return {"provider": "Azure", "region": "unknown", "service": "AppService"}

        # GCP
        if "googleusercontent.com" in rdns or "google.com" in rdns:
            return {"provider": "GCP", "region": "unknown", "service": "Compute Engine"}

        return None

    def scan_batch(self, hostnames, threads=20, cancel_check=None):
        """Scan multiple hostnames for SSH concurrently."""
        results = []
        with ThreadPoolExecutor(max_workers=min(len(hostnames), threads)) as executor:
            futures = {executor.submit(self.check_ssh, h): h for h in hostnames}
            for future in as_completed(futures):
                if cancel_check and cancel_check():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    results.append(future.result())
                except Exception:
                    pass
        return results


class TLSAnalyzer:
    """Analyze TLS certificates and protocol versions."""

    def __init__(self, timeout=5):
        self.timeout = timeout

    def analyze(self, hostname, port=443):
        """Analyze TLS certificate and protocol support."""
        result = {
            "hostname": hostname,
            "port": port,
            "cert_subject": "",
            "cert_issuer": "",
            "cert_not_before": "",
            "cert_not_after": "",
            "cert_sans": [],
            "is_self_signed": False,
            "days_until_expiry": -1,
            "protocol_versions": [],
            "has_tls10": False,
            "has_tls11": False,
        }

        # Get certificate info
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((hostname, port))
            wrapped = ctx.wrap_socket(sock, server_hostname=hostname)

            cert = wrapped.getpeercert(binary_form=False)
            if cert:
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                result["cert_subject"] = subject.get("commonName", "")
                result["cert_issuer"] = issuer.get("commonName", "")
                result["cert_not_before"] = cert.get("notBefore", "")
                result["cert_not_after"] = cert.get("notAfter", "")

                sans = []
                for san_type, san_val in cert.get("subjectAltName", ()):
                    if san_type == "DNS":
                        sans.append(san_val)
                result["cert_sans"] = sans

                # Self-signed check
                result["is_self_signed"] = (
                    subject.get("commonName") == issuer.get("commonName") and
                    subject.get("organizationName", "") == issuer.get("organizationName", "")
                )

                # Days until expiry
                try:
                    not_after = ssl.cert_time_to_seconds(cert.get("notAfter", ""))
                    result["days_until_expiry"] = int(
                        (not_after - time.time()) / 86400)
                except Exception:
                    pass

            proto = wrapped.version() or ""
            result["protocol_versions"].append(proto)
            wrapped.close()
        except Exception:
            pass

        # Check for legacy TLS versions
        for ver_name, min_ver, max_ver in [
            ("TLSv1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
        ]:
            try:
                ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                ctx2.set_ciphers("DEFAULT:@SECLEVEL=0")
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    ctx2.minimum_version = min_ver
                    ctx2.maximum_version = max_ver

                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(self.timeout)
                sock2.connect((hostname, port))
                wrapped2 = ctx2.wrap_socket(sock2, server_hostname=hostname)
                actual = wrapped2.version() or ""
                wrapped2.close()

                if ver_name.replace("v", " ").replace(".", " ") in actual.replace("v", " ").replace(".", " "):
                    if ver_name == "TLSv1.0":
                        result["has_tls10"] = True
                    elif ver_name == "TLSv1.1":
                        result["has_tls11"] = True
                    result["protocol_versions"].append(ver_name)
            except Exception:
                pass

        return result


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: Phase 3 — Vulnerability Assessment
# ═══════════════════════════════════════════════════════════════════════════════

class BTPVulnAssessor:
    """Assess BTP endpoints for security issues."""

    def __init__(self, timeout=5):
        self.timeout = timeout

    def assess(self, endpoint):
        """Run all applicable checks against an endpoint."""
        checks = [
            self.check_cf_ssh_enabled,
            self.check_cf_ssh_outdated,
            self.check_cf_infrastructure_leak,
            self.check_unauthenticated_access,
            self.check_metadata_exposure,
            self.check_oauth_token_endpoint,
            self.check_xs_app_json_exposed,
            self.check_manifest_json_exposed,
            self.check_actuator_endpoints,
            self.check_actuator_env,
            self.check_swagger_exposed,
            self.check_cors_wildcard,
            self.check_cors_null_origin,
            self.check_missing_hsts,
            self.check_tls_version,
            self.check_error_disclosure,
            self.check_version_disclosure,
            self.check_debug_mode,
        ]

        for check_fn in checks:
            try:
                finding = check_fn(endpoint)
                if finding:
                    endpoint.findings.append(finding)
            except Exception as e:
                log_verbose("  [Vuln] %s error on %s: %s" % (
                    check_fn.__name__, endpoint.hostname, e))

        return len(endpoint.findings)

    # ── Cloud Foundry SSH Exposure ──

    def check_cf_ssh_enabled(self, endpoint):
        """BTP-SSH-001: CF Diego SSH proxy exposed on port 2222."""
        ssh = endpoint.ssh_info
        if not ssh.get("open"):
            return None
        if not ssh.get("is_diego"):
            return None

        # Fingerprint Diego SSH version via KEXINIT analysis
        # Store result on ssh_info so check_cf_ssh_outdated can reuse it
        detail = "Banner: %s" % ssh.get("banner", "")
        try:
            from diego_ssh_fingerprint import fingerprint_diego_ssh
            fp = fingerprint_diego_ssh(endpoint.hostname, 2222, timeout=self.timeout)
            ssh["_diego_fp"] = fp
            if fp.get("epoch") and fp.get("version_range"):
                detail += " | Estimated Diego version: %s (%s)" % (
                    fp["version_range"], fp.get("version_info", ""))
                detail += " [estimate based on KEXINIT fingerprint]"
                if not fp.get("has_kex_strict"):
                    detail += " [Terrapin vulnerable: no kex-strict]"
        except Exception:
            pass

        return Finding(
            name="Cloud Foundry SSH enabled (Diego proxy exposed)",
            severity=Severity.HIGH,
            description=(
                "Port 2222 is open with SSH-2.0-diego-ssh-proxy banner. An attacker "
                "with a stolen CF OAuth token can SSH directly into the application "
                "container, accessing environment variables (VCAP_SERVICES with DB "
                "credentials), internal CF networking, and potentially pivot to other "
                "services."
            ),
            remediation=(
                "Disable SSH at the app level: cf disable-ssh <app-name>. "
                "Or disable org-wide: cf disallow-space-ssh <space>. "
                "Verify with: cf ssh-enabled <app-name>. "
                "See SAP Note 3395594 (https://me.sap.com/notes/3395594) "
                "for guidance on securing CF SSH access in BTP."
            ),
            detail=detail,
            port=2222,
        )

    def check_cf_ssh_outdated(self, endpoint):
        """BTP-SSH-003: Outdated Diego SSH proxy version (< v2.113.0)."""
        ssh = endpoint.ssh_info
        if not ssh.get("is_diego"):
            return None
        fp = ssh.get("_diego_fp")
        if not fp or not fp.get("epoch"):
            return None
        # Epoch 4 (>= v2.113.0) is current; epochs 1-3 are outdated
        if fp["epoch"] >= 4:
            return None

        version_range = fp.get("version_range", "unknown")
        risks = []
        if fp["epoch"] <= 2:
            # No kex-strict → vulnerable to Terrapin (CVE-2023-48795)
            risks.append(
                "Vulnerable to Terrapin attack (CVE-2023-48795) — "
                "kex-strict countermeasure is missing"
            )
        if fp.get("has_chacha20"):
            risks.append(
                "chacha20-poly1305 cipher still offered — removed in v2.113.0 "
                "per SAP CFAR-1064 to harden against Terrapin"
            )
        if fp["epoch"] == 1:
            risks.append(
                "Uses Go SSH library defaults with a broad cipher/kex set "
                "instead of hardcoded secure algorithm lists"
            )

        detail = "Estimated Diego version: %s (%s)" % (
            version_range, fp.get("version_info", ""))
        detail += " [estimate based on KEXINIT fingerprint]"
        if risks:
            detail += "\nRisks: " + "; ".join(risks)

        return Finding(
            name="Outdated Diego SSH proxy (< v2.113.0)",
            severity=Severity.MEDIUM,
            description=(
                "The Diego SSH proxy appears to be running a version older than "
                "v2.113.0 based on its SSH KEXINIT algorithm fingerprint. Older "
                "versions may be vulnerable to the Terrapin attack (CVE-2023-48795) "
                "and offer deprecated cipher suites such as chacha20-poly1305. "
                "Note: this version estimate is based on algorithm negotiation "
                "patterns and may not be 100%% conclusive."
            ),
            remediation=(
                "Update the Cloud Foundry Diego release to v2.113.0 or later. "
                "Contact SAP support if running on BTP to request platform updates. "
                "See SAP CFAR-1064 for details on the chacha20 removal."
            ),
            detail=detail,
            port=2222,
        )

    def check_cf_infrastructure_leak(self, endpoint):
        """BTP-SSH-002: Cloud infrastructure details leaked via rDNS."""
        ssh = endpoint.ssh_info
        if not ssh.get("rdns"):
            return None
        provider = ssh.get("cloud_provider")
        if not provider:
            return None
        rdns_str = ", ".join(ssh["rdns"][:3])
        region = ssh.get("cloud_region", "unknown")
        return Finding(
            name="Cloud infrastructure details leaked via rDNS",
            severity=Severity.MEDIUM,
            description=(
                "Reverse DNS on the endpoint IP addresses reveals the underlying "
                "cloud provider (%s), region (%s), and instance identifiers. This "
                "aids targeted attacks against the infrastructure layer."
                % (provider, region)
            ),
            remediation=(
                "Infrastructure-level finding. The rDNS records are controlled "
                "by the cloud provider and cannot be changed by the SAP customer. "
                "Minimize exposure by using custom domains instead of default "
                "*.cfapps.<region>.hana.ondemand.com hostnames, and restrict "
                "public DNS resolution where possible (e.g., split-horizon DNS)."
            ),
            detail="rDNS: %s -> %s %s" % (rdns_str, provider, region),
            port=0,
        )

    # ── Authentication & Authorization ──

    def check_unauthenticated_access(self, endpoint):
        """BTP-AUTH-001: Data accessible without authentication."""
        if not endpoint.alive:
            return None
        base = endpoint.url.rstrip("/")
        # Check OData endpoints and API endpoints
        test_paths = [
            "/sap/opu/odata/sap/",
            "/odata/v4/",
            "/odata/v2/",
            "/api/v1/",
        ]
        for path in test_paths:
            for fp in endpoint.fingerprint_results:
                if fp["path"] == path and fp["status"] == 200:
                    return Finding(
                        name="Unauthenticated API/OData access",
                        severity=Severity.CRITICAL,
                        description=(
                            "API endpoint %s returns data (HTTP 200) without "
                            "requiring authentication. Sensitive business data "
                            "may be exposed." % path
                        ),
                        remediation=(
                            "Add authentication to xs-app.json route or enforce "
                            "scopes in XSUAA service binding."
                        ),
                        detail="HTTP 200 on %s%s (size: %d bytes)" % (
                            base, path, fp.get("size", 0)),
                        port=endpoint.port,
                    )
        return None

    def check_metadata_exposure(self, endpoint):
        """BTP-AUTH-002: OData $metadata accessible without auth."""
        if not endpoint.alive:
            return None
        for fp in endpoint.fingerprint_results:
            if fp["path"] == "/$metadata" and fp["status"] == 200 and fp.get("size", 0) > 100:
                return Finding(
                    name="OData $metadata exposed without authentication",
                    severity=Severity.HIGH,
                    description=(
                        "The OData $metadata endpoint returns the full entity data "
                        "model without authentication. This reveals database schema, "
                        "entity names, property types, and navigation properties."
                    ),
                    remediation=(
                        "Require authentication for $metadata endpoint in xs-app.json "
                        "or CAP service annotations."
                    ),
                    detail="/$metadata returns %d bytes" % fp.get("size", 0),
                    port=endpoint.port,
                )
        return None

    def check_oauth_token_endpoint(self, endpoint):
        """BTP-AUTH-003: OAuth token endpoint reachable."""
        if not endpoint.alive:
            return None
        for fp in endpoint.fingerprint_results:
            if fp["path"] == "/oauth/token" and fp["status"] in (200, 401, 405):
                return Finding(
                    name="OAuth token endpoint reachable",
                    severity=Severity.MEDIUM,
                    description=(
                        "The XSUAA /oauth/token endpoint is reachable. While this is "
                        "expected for authentication flows, it can be used for "
                        "credential stuffing or token brute-forcing if combined with "
                        "leaked client credentials."
                    ),
                    remediation=(
                        "Ensure client_credentials grant type is restricted. Use "
                        "strong client secrets and rotate regularly. Consider IP "
                        "whitelisting for token endpoint access."
                    ),
                    detail="HTTP %d on /oauth/token" % fp["status"],
                    port=endpoint.port,
                )
        return None

    # ── Configuration Exposure ──

    def check_xs_app_json_exposed(self, endpoint):
        """BTP-CFG-001: xs-app.json routing configuration leaked."""
        if not endpoint.alive:
            return None
        for fp in endpoint.fingerprint_results:
            if fp["path"] == "/xs-app.json" and fp["status"] == 200:
                return Finding(
                    name="App Router configuration exposed (xs-app.json)",
                    severity=Severity.MEDIUM,
                    description=(
                        "The xs-app.json file is publicly accessible. This reveals "
                        "internal routing rules, backend service destinations, "
                        "authentication settings, and CORS configuration."
                    ),
                    remediation=(
                        "Block access to xs-app.json in the app router configuration "
                        "or add a route rule to deny direct access."
                    ),
                    detail="xs-app.json accessible (%d bytes)" % fp.get("size", 0),
                    port=endpoint.port,
                )
        return None

    def check_manifest_json_exposed(self, endpoint):
        """BTP-CFG-002: UI5 manifest.json configuration leaked."""
        if not endpoint.alive:
            return None
        for fp in endpoint.fingerprint_results:
            if fp["path"] == "/manifest.json" and fp["status"] == 200 and fp.get("size", 0) > 200:
                return Finding(
                    name="UI5 manifest.json exposed",
                    severity=Severity.LOW,
                    description=(
                        "The UI5 manifest.json is publicly accessible. This reveals "
                        "application metadata, data source URLs, component details, "
                        "and model configurations."
                    ),
                    remediation=(
                        "Restrict access to manifest.json via xs-app.json routing "
                        "rules if it contains sensitive configuration."
                    ),
                    detail="manifest.json accessible (%d bytes)" % fp.get("size", 0),
                    port=endpoint.port,
                )
        return None

    def check_actuator_endpoints(self, endpoint):
        """BTP-CFG-003: Spring Boot actuator endpoints exposed."""
        if not endpoint.alive:
            return None
        for fp in endpoint.fingerprint_results:
            if fp["path"] in ("/actuator", "/actuator/health") and fp["status"] == 200:
                return Finding(
                    name="Spring Boot actuator endpoints exposed",
                    severity=Severity.HIGH,
                    description=(
                        "Spring Boot actuator endpoints are publicly accessible. "
                        "These can reveal application health, metrics, thread dumps, "
                        "configuration properties, and environment variables."
                    ),
                    remediation=(
                        "Restrict actuator endpoints to management port only. "
                        "In application.yml: management.server.port=8081 and "
                        "management.endpoints.web.exposure.include=health,info"
                    ),
                    detail="HTTP %d on %s" % (fp["status"], fp["path"]),
                    port=endpoint.port,
                )
        return None

    def check_actuator_env(self, endpoint):
        """BTP-CFG-004: Actuator /env with potential secrets."""
        if not endpoint.alive:
            return None
        for fp in endpoint.fingerprint_results:
            if fp["path"] == "/actuator/env" and fp["status"] == 200:
                return Finding(
                    name="Spring Boot /actuator/env exposed (potential credential leak)",
                    severity=Severity.CRITICAL,
                    description=(
                        "The /actuator/env endpoint is publicly accessible and may "
                        "expose environment variables including database credentials, "
                        "API keys, VCAP_SERVICES bindings, and other secrets."
                    ),
                    remediation=(
                        "Disable the env endpoint: "
                        "management.endpoint.env.enabled=false. "
                        "Never expose actuator endpoints publicly."
                    ),
                    detail="/actuator/env accessible (%d bytes)" % fp.get("size", 0),
                    port=endpoint.port,
                )
        return None

    def check_swagger_exposed(self, endpoint):
        """BTP-CFG-005: Swagger/API docs publicly accessible."""
        if not endpoint.alive:
            return None
        for fp in endpoint.fingerprint_results:
            if fp["path"] in ("/api-docs", "/swagger-ui.html") and fp["status"] == 200:
                return Finding(
                    name="API documentation (Swagger) publicly accessible",
                    severity=Severity.LOW,
                    description=(
                        "Swagger UI or API documentation is publicly accessible. "
                        "This reveals all API endpoints, request/response schemas, "
                        "and may include authentication bypass information."
                    ),
                    remediation=(
                        "Restrict Swagger UI to internal access only. "
                        "Disable in production: springdoc.swagger-ui.enabled=false"
                    ),
                    detail="HTTP %d on %s" % (fp["status"], fp["path"]),
                    port=endpoint.port,
                )
        return None

    # ── CORS & Transport Security ──

    def check_cors_wildcard(self, endpoint):
        """BTP-CORS-001: Wildcard CORS origin."""
        if not endpoint.alive:
            return None
        acao = endpoint.headers.get("access-control-allow-origin",
                endpoint.headers.get("Access-Control-Allow-Origin", ""))
        if acao == "*":
            return Finding(
                name="Wildcard CORS origin (Access-Control-Allow-Origin: *)",
                severity=Severity.MEDIUM,
                description=(
                    "The server sets Access-Control-Allow-Origin: * which allows "
                    "any website to make cross-origin requests to this API. "
                    "Combined with Access-Control-Allow-Credentials, this can "
                    "enable cross-site data theft."
                ),
                remediation=(
                    "Restrict CORS to specific trusted origins instead of using "
                    "wildcard. Configure allowed origins in xs-app.json or "
                    "application CORS filter."
                ),
                detail="Header: Access-Control-Allow-Origin: *",
                port=endpoint.port,
            )
        return None

    def check_cors_null_origin(self, endpoint):
        """BTP-CORS-002: Null origin accepted in CORS."""
        if not endpoint.alive:
            return None
        # Send a request with Origin: null
        try:
            r = requests.get(endpoint.url, timeout=self.timeout, verify=False,
                             allow_redirects=False,
                             headers={"Origin": "null"})
            acao = r.headers.get("access-control-allow-origin", "")
            if acao == "null":
                return Finding(
                    name="CORS accepts null origin",
                    severity=Severity.MEDIUM,
                    description=(
                        "The server accepts Origin: null in CORS preflight. "
                        "Sandboxed iframes and data: URLs send null origin, "
                        "enabling CORS bypass attacks."
                    ),
                    remediation=(
                        "Do not reflect null as an allowed origin. Use an "
                        "explicit whitelist of trusted origins."
                    ),
                    detail="Access-Control-Allow-Origin: null reflected",
                    port=endpoint.port,
                )
        except RequestException:
            pass
        return None

    def check_missing_hsts(self, endpoint):
        """BTP-HDR-001: Missing Strict-Transport-Security header."""
        if not endpoint.alive:
            return None
        if endpoint.port != 443:
            return None
        headers_lower = {k.lower(): v for k, v in endpoint.headers.items()}
        if "strict-transport-security" not in headers_lower:
            return Finding(
                name="Missing HSTS header (Strict-Transport-Security)",
                severity=Severity.LOW,
                description=(
                    "The HTTPS endpoint does not set Strict-Transport-Security "
                    "header. Users may be vulnerable to SSL stripping attacks."
                ),
                remediation=(
                    "Add Strict-Transport-Security header with appropriate "
                    "max-age: Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains"
                ),
                detail="No HSTS header in response",
                port=endpoint.port,
            )
        return None

    def check_tls_version(self, endpoint):
        """BTP-TLS-001: Legacy TLS versions supported."""
        tls = endpoint.tls_info
        if not tls:
            return None
        has_legacy = tls.get("has_tls10") or tls.get("has_tls11")
        if not has_legacy:
            return None
        versions = []
        if tls.get("has_tls10"):
            versions.append("TLS 1.0")
        if tls.get("has_tls11"):
            versions.append("TLS 1.1")
        return Finding(
            name="Legacy TLS version(s) supported",
            severity=Severity.MEDIUM,
            description=(
                "The endpoint supports deprecated TLS version(s): %s. "
                "These are considered insecure and should be disabled."
                % ", ".join(versions)
            ),
            remediation=(
                "Disable TLS 1.0 and TLS 1.1. Require TLS 1.2 as minimum. "
                "Configure in SAP BTP destination or application server."
            ),
            detail="Supported legacy versions: %s" % ", ".join(versions),
            port=endpoint.port,
        )

    # ── Information Disclosure ──

    def check_error_disclosure(self, endpoint):
        """BTP-INFO-001: Stack traces in error responses."""
        if not endpoint.alive:
            return None
        base = endpoint.url.rstrip("/")
        try:
            r = requests.get(base + "/nonexistent_path_9876543210",
                             timeout=self.timeout, verify=False,
                             allow_redirects=False)
            body = r.text[:5000]
            patterns = [
                r"at\s+[\w.]+\([\w]+\.java:\d+\)",
                r"Traceback \(most recent call last\)",
                r"at\s+Object\.<anonymous>.*\.js:\d+:\d+",
                r"VCAP_SERVICES",
                r"com\.sap\.\w+",
                r"Exception in thread",
            ]
            for pat in patterns:
                m = re.search(pat, body)
                if m:
                    return Finding(
                        name="Error page information disclosure",
                        severity=Severity.MEDIUM,
                        description=(
                            "Error responses contain stack traces or internal "
                            "implementation details that reveal server technology, "
                            "file paths, and potentially sensitive configuration."
                        ),
                        remediation=(
                            "Configure custom error pages. In Spring Boot: "
                            "server.error.include-stacktrace=never. In Node.js: "
                            "disable debug mode in production."
                        ),
                        detail="Pattern found: %s" % m.group(0)[:200],
                        port=endpoint.port,
                    )
        except RequestException:
            pass
        return None

    def check_version_disclosure(self, endpoint):
        """BTP-INFO-002: Server version leaked in headers."""
        if not endpoint.alive:
            return None
        server = endpoint.server_header
        if not server:
            return None
        # Check if version number is present
        if re.search(r"\d+\.\d+", server):
            return Finding(
                name="Server version disclosed in headers",
                severity=Severity.LOW,
                description=(
                    "The Server header reveals the web server software version. "
                    "This information helps attackers identify known vulnerabilities "
                    "for the specific version."
                ),
                remediation=(
                    "Suppress server version in response headers. Configure "
                    "the application server to return a generic server name."
                ),
                detail="Server: %s" % server,
                port=endpoint.port,
            )
        return None

    def check_debug_mode(self, endpoint):
        """BTP-INFO-003: Debug/trace mode enabled."""
        if not endpoint.alive:
            return None
        headers_lower = {k.lower(): v for k, v in endpoint.headers.items()}
        indicators = []
        if headers_lower.get("x-debug"):
            indicators.append("X-Debug header present")
        if headers_lower.get("x-powered-by", "").lower().count("debug"):
            indicators.append("Debug mode in X-Powered-By")
        # Try TRACE method
        try:
            r = requests.request("TRACE", endpoint.url, timeout=self.timeout,
                                 verify=False, allow_redirects=False)
            if r.status_code == 200 and "TRACE" in r.text[:500]:
                indicators.append("HTTP TRACE method enabled")
        except RequestException:
            pass
        if indicators:
            return Finding(
                name="Debug/trace mode detected",
                severity=Severity.HIGH,
                description=(
                    "The endpoint has debug or trace features enabled: %s. "
                    "Debug mode may expose internal state, credentials, and "
                    "verbose error messages."
                    % "; ".join(indicators)
                ),
                remediation=(
                    "Disable debug mode in production. Disable HTTP TRACE "
                    "method. Remove debug headers."
                ),
                detail="; ".join(indicators),
                port=endpoint.port,
            )
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6: Reporting
# ═══════════════════════════════════════════════════════════════════════════════

def generate_btp_json(result, output_path):
    """Export BTP scan results as JSON."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)


def generate_btp_html_section(result):
    """Generate HTML fragment for injection into SAPology HTML report."""
    if not result or not result.endpoints:
        return ""

    summary = result.summary()
    alive = [ep for ep in result.endpoints if ep.alive]
    all_findings = []
    for ep in result.endpoints:
        for f in ep.findings:
            all_findings.append((ep, f))
    all_findings.sort(key=lambda x: x[1].severity)

    rows_html = ""
    for ep, f in all_findings:
        color = SEVERITY_COLORS.get(f.severity, "#95a5a6")
        sev_name = SEVERITY_NAMES.get(f.severity, "INFO")
        rows_html += """<tr>
            <td><span style="background:%s;color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold">%s</span></td>
            <td>%s</td>
            <td>%s<br><small style="color:#888">%s | %s</small></td>
            <td>%s</td>
            <td style="font-family:monospace;font-size:11px;color:#888">%s</td>
            <td>%s</td>
        </tr>""" % (
            color, sev_name,
            _html_escape(f.name),
            _html_escape(ep.hostname),
            _html_escape(ep.service_type), _html_escape(ep.region),
            _html_escape(f.description),
            _html_escape(f.detail),
            _html_escape(f.remediation),
        )

    endpoints_html = ""
    for ep in alive:
        svc = ep.service_type or "unknown"
        finding_badges = ""
        sev_counts = {}
        for f in ep.findings:
            sn = SEVERITY_NAMES.get(f.severity, "INFO")
            sev_counts[sn] = sev_counts.get(sn, 0) + 1
        for sn in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt = sev_counts.get(sn, 0)
            if cnt > 0:
                sev_enum = [k for k, v in SEVERITY_NAMES.items() if v == sn][0]
                color = SEVERITY_COLORS.get(sev_enum, "#95a5a6")
                finding_badges += ('<span style="background:%s;color:#fff;padding:1px 6px;'
                                   'border-radius:3px;font-size:10px;margin-right:3px">'
                                   '%d %s</span>' % (color, cnt, sn))

        ssh_badge = ""
        if ep.ssh_info.get("is_diego"):
            ssh_badge = ('<span style="background:#e67e22;color:#fff;padding:1px 6px;'
                         'border-radius:3px;font-size:10px;margin-left:5px">SSH:2222</span>')

        endpoints_html += """<tr>
            <td><a href="%s" target="_blank" style="color:#3498db">%s</a>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
        </tr>""" % (
            _html_escape(ep.url), _html_escape(ep.hostname), ssh_badge,
            _html_escape(svc), _html_escape(ep.region),
            _html_escape(ep.auth_type or "unknown"),
            _html_escape(ep.server_header[:50]) if ep.server_header else "-",
            finding_badges or "-",
        )

    html = """
    <div style="margin-top:30px;padding-top:20px;border-top:2px solid #333">
        <h2 style="color:#3498db;margin-bottom:15px">BTP Cloud Scan Results</h2>

        <div style="display:flex;gap:15px;margin-bottom:20px;flex-wrap:wrap">
            <div style="background:#1a1a2e;padding:12px 20px;border-radius:8px;min-width:120px;text-align:center">
                <div style="font-size:24px;font-weight:bold;color:#3498db">%d</div>
                <div style="font-size:11px;color:#888">Endpoints</div>
            </div>
            <div style="background:#1a1a2e;padding:12px 20px;border-radius:8px;min-width:120px;text-align:center">
                <div style="font-size:24px;font-weight:bold;color:#2ecc71">%d</div>
                <div style="font-size:11px;color:#888">Alive</div>
            </div>
            <div style="background:#1a1a2e;padding:12px 20px;border-radius:8px;min-width:120px;text-align:center">
                <div style="font-size:24px;font-weight:bold;color:#e74c3c">%d</div>
                <div style="font-size:11px;color:#888">Critical</div>
            </div>
            <div style="background:#1a1a2e;padding:12px 20px;border-radius:8px;min-width:120px;text-align:center">
                <div style="font-size:24px;font-weight:bold;color:#e67e22">%d</div>
                <div style="font-size:11px;color:#888">High</div>
            </div>
            <div style="background:#1a1a2e;padding:12px 20px;border-radius:8px;min-width:120px;text-align:center">
                <div style="font-size:24px;font-weight:bold;color:#f1c40f">%d</div>
                <div style="font-size:11px;color:#888">Medium</div>
            </div>
            <div style="background:#1a1a2e;padding:12px 20px;border-radius:8px;min-width:120px;text-align:center">
                <div style="font-size:24px;font-weight:bold;color:#95a5a6">%d</div>
                <div style="font-size:11px;color:#888">Regions</div>
            </div>
        </div>

        <h3 style="color:#ccc;margin-top:25px">Discovered Endpoints (%d)</h3>
        <table style="width:100%%;border-collapse:collapse;margin-top:10px">
            <thead>
                <tr style="background:#1a1a2e;color:#888;font-size:12px;text-transform:uppercase">
                    <th style="padding:8px;text-align:left">Hostname</th>
                    <th style="padding:8px;text-align:left">Service</th>
                    <th style="padding:8px;text-align:left">Region</th>
                    <th style="padding:8px;text-align:left">Auth</th>
                    <th style="padding:8px;text-align:left">Server</th>
                    <th style="padding:8px;text-align:left">Findings</th>
                </tr>
            </thead>
            <tbody>%s</tbody>
        </table>

        <h3 style="color:#ccc;margin-top:25px">BTP Findings (%d)</h3>
        <table style="width:100%%;border-collapse:collapse;margin-top:10px">
            <thead>
                <tr style="background:#1a1a2e;color:#888;font-size:12px;text-transform:uppercase">
                    <th style="padding:8px;text-align:left">Severity</th>
                    <th style="padding:8px;text-align:left">Finding</th>
                    <th style="padding:8px;text-align:left">Endpoint</th>
                    <th style="padding:8px;text-align:left">Description</th>
                    <th style="padding:8px;text-align:left">Detail</th>
                    <th style="padding:8px;text-align:left">Remediation</th>
                </tr>
            </thead>
            <tbody>%s</tbody>
        </table>
    </div>
    """ % (
        summary["total_endpoints"], summary["alive_endpoints"],
        summary["critical"], summary["high"], summary["medium"],
        summary["regions"],
        len(alive), endpoints_html,
        len(all_findings), rows_html,
    )

    return html


def generate_btp_html_report(result, output_path):
    """Generate a standalone BTP HTML report."""
    summary = result.summary()
    btp_section = generate_btp_html_section(result)

    # Build scan options table
    cfg = result.config or {}
    scan_options_spec = [
        ("--target, -t", _html_escape(cfg.get("target", "")) or "not used", "not used",
         "BTP hostname(s) to scan (comma-separated)"),
        ("--discover, -d", _html_escape(cfg.get("keyword", "")) or "not used", "not used",
         "Search CT logs for organization keyword"),
        ("--domain", _html_escape(cfg.get("domain", "")) or "not used", "not used",
         "Target custom domain"),
        ("--subaccount, -s", _html_escape(cfg.get("subaccount", "")) or "not used", "not used",
         "Known BTP subaccount identifier"),
        ("--targets, -T", _html_escape(cfg.get("targets_file", "") or "") or "not used", "not used",
         "File with BTP URLs (one per line)"),
        ("--regions", cfg.get("regions", "all"), "all",
         "BTP regions to scan"),
        ("--skip-ct", "Yes" if cfg.get("skip_ct") else "No", "No",
         "Skip Certificate Transparency log search"),
        ("--skip-vuln", "Yes" if cfg.get("skip_vuln") else "No", "No",
         "Skip BTP vulnerability assessment"),
        ("--threads", str(cfg.get("threads", 20)), "20",
         "Parallel scan threads"),
        ("--timeout", "%ds" % cfg.get("timeout", 5), "5s",
         "Per-connection timeout"),
        ("--shodan-key", "***" if cfg.get("shodan_key") else "not used", "not used",
         "Shodan API key for infrastructure discovery"),
        ("--censys-id", "***" if cfg.get("censys_id") else "not used", "not used",
         "Censys API ID"),
        ("--censys-secret", "***" if cfg.get("censys_secret") else "not used", "not used",
         "Censys API secret"),
        ("-v, --verbose", "Yes" if cfg.get("verbose") else "No", "No",
         "Verbose terminal output"),
    ]
    scan_options_rows = ""
    for opt, value, default, description in scan_options_spec:
        is_default = (value == default)
        val_style = "color:#888" if is_default else "color:#2ecc71;font-weight:bold"
        scan_options_rows += (
            '<tr><td style="font-weight:600;color:#3498db;white-space:nowrap">%s</td>'
            '<td style="%s">%s</td><td style="color:#888;font-size:12px">%s</td>'
            '<td style="color:#aaa">%s</td></tr>'
            % (_html_escape(opt), val_style, value, default, _html_escape(description))
        )

    html_content = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>SAPology BTP Cloud Scan Report</title>
<style>
    body {{ background: #0d1117; color: #e6e6e6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; }}
    .container {{ max-width: 1400px; margin: 0 auto; }}
    h1 {{ color: #3498db; border-bottom: 2px solid #333; padding-bottom: 10px; }}
    h2 {{ color: #3498db; }}
    h3 {{ color: #ccc; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ background: #1a1a2e; color: #888; font-size: 12px; text-transform: uppercase; padding: 8px; text-align: left; }}
    td {{ padding: 8px; border-bottom: 1px solid #222; font-size: 13px; }}
    tr:hover {{ background: #161b22; }}
    a {{ color: #3498db; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #333; color: #666; font-size: 11px; text-align: center; }}
</style>
</head>
<body>
<div class="container">
    <h1>[SAPology] BTP Cloud Scan Report</h1>
    <p style="color:#888">
        Scan time: {scan_time} | Duration: {duration}s |
        Keyword: {keyword} | Domain: {domain} | Subaccount: {subaccount}
    </p>
    {btp_section}
    <div style="background:#1a1a2e;border-radius:8px;padding:20px;margin-top:30px;border:1px solid #333">
        <h2 style="border:none;margin-top:0">Scan Options</h2>
        <table>
            <thead><tr><th>Option</th><th>Selected Value</th><th>Default</th><th>Description</th></tr></thead>
            <tbody>{scan_options_rows}</tbody>
        </table>
    </div>
    <div class="footer">
        Generated by SAPology BTP Cloud Scanner &mdash; {scan_time}<br>
        by Joris van de Vis
    </div>
</div>
</body>
</html>""".format(
        scan_time=result.scan_time or datetime.now().isoformat(),
        duration="%.1f" % result.scan_duration,
        keyword=_html_escape(result.keyword or "-"),
        domain=_html_escape(result.domain or "-"),
        subaccount=_html_escape(result.subaccount or "-"),
        btp_section=btp_section,
        scan_options_rows=scan_options_rows,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def _html_escape(s):
    """Escape HTML special characters."""
    if not s:
        return ""
    import html as html_mod
    return html_mod.escape(str(s))


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7: BTPScanner Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

class BTPScanner:
    """Main orchestrator for BTP cloud scanning."""

    def __init__(self, config):
        self.config = config
        self.result = BTPScanResult()
        self.cancel_check = config.get("cancel_check")
        self.timeout = config.get("timeout", 5)
        self.threads = config.get("threads", 20)
        self.verbose = config.get("verbose", False)

        global VERBOSE
        VERBOSE = self.verbose

    def _cancelled(self):
        return self.cancel_check and self.cancel_check()

    def run(self):
        """Execute full BTP scan pipeline."""
        start = time.time()
        self.result.scan_time = datetime.now().isoformat()
        self.result.keyword = self.config.get("keyword", "")
        self.result.domain = self.config.get("domain", "")
        self.result.subaccount = self.config.get("subaccount", "")
        self.result.config = {k: v for k, v in self.config.items()
                              if k != "cancel_check"}

        # Parse regions
        regions_str = self.config.get("regions", "all")
        if regions_str == "all":
            self.result.regions_scanned = list(BTP_REGIONS)
        else:
            self.result.regions_scanned = [r.strip() for r in regions_str.split(",")
                                            if r.strip() in BTP_REGIONS]

        # Phase 1: Discovery
        print("\n[*] BTP Phase 1: Discovery")
        print("-" * 40)
        endpoints = self._discover()

        if not endpoints:
            print("[-] No BTP endpoints discovered")
            self.result.scan_duration = time.time() - start
            return self.result

        print("[+] Discovered %d unique endpoints" % len(endpoints))

        # DNS Resolution
        print("\n[*] Resolving hostnames ...")
        endpoints = self._resolve_dns(endpoints)
        alive_count = sum(1 for ep in endpoints if ep.alive)
        print("[+] %d/%d endpoints resolved" % (alive_count, len(endpoints)))
        self.result.dns_resolved = alive_count

        if self._cancelled():
            print("\n[!] Scan cancelled by user")
            self.result.endpoints = endpoints
            self.result.scan_duration = time.time() - start
            return self.result

        # Phase 2: Fingerprinting
        alive_eps = [ep for ep in endpoints if ep.alive]
        if alive_eps and not self.config.get("skip_fingerprint"):
            print("\n[*] BTP Phase 2: Fingerprinting")
            print("-" * 40)

            # Active scanning warning
            print("[!] ACTIVE SCANNING MODE — Ensure you have authorization")
            print("[!] Probing %d live endpoints ..." % len(alive_eps))

            self._fingerprint(alive_eps)

            if self._cancelled():
                print("\n[!] Scan cancelled by user")
                self.result.endpoints = endpoints
                self.result.scan_duration = time.time() - start
                return self.result

        # Phase 3: Vulnerability Assessment
        if alive_eps and not self.config.get("skip_vuln"):
            print("\n[*] BTP Phase 3: Vulnerability Assessment")
            print("-" * 40)
            self._assess(alive_eps)

        # Finalize
        self.result.endpoints = endpoints
        total_findings = sum(len(ep.findings) for ep in endpoints)
        self.result.total_findings = total_findings
        self.result.scan_duration = time.time() - start

        # Summary
        summary = self.result.summary()
        print("\n[+] BTP scan complete: %d endpoints, %d findings "
              "(%d critical, %d high, %d medium)" % (
                  summary["alive_endpoints"], summary["total_findings"],
                  summary["critical"], summary["high"], summary["medium"]))

        return self.result

    def _discover(self):
        """Run all discovery sources."""
        all_hostnames = set()
        total_certs = 0

        keyword = self.config.get("keyword")
        domain = self.config.get("domain")
        subaccount = self.config.get("subaccount")
        targets_file = self.config.get("targets_file")
        direct_targets = self.config.get("target")

        # Direct targets from command line (--target / --btp-target)
        if direct_targets:
            for entry in direct_targets.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                if entry.startswith("http"):
                    parsed = urlparse(entry)
                    if parsed.hostname:
                        all_hostnames.add(parsed.hostname.lower())
                else:
                    all_hostnames.add(entry.lower())
            print("[+] Direct targets: %d hostnames" % len(all_hostnames))

        # CT Log discovery
        if not self.config.get("skip_ct"):
            ct = CTLogDiscovery(timeout=self.timeout)

            if keyword:
                print("[*] Searching CT logs for keyword: %s" % keyword)
                hosts, certs = ct.search_org(keyword)
                all_hostnames.update(hosts)
                total_certs += certs
                print("[+] CT logs (keyword): %d hostnames from %d certificates" % (
                    len(hosts), certs))

            if subaccount:
                print("[*] Searching CT logs for subaccount: %s" % subaccount)
                hosts, certs = ct.search_subaccount(subaccount)
                all_hostnames.update(hosts)
                total_certs += certs
                print("[+] CT logs (subaccount): %d hostnames from %d certificates" % (
                    len(hosts), certs))

            if domain:
                print("[*] Searching CT logs for domain: %s" % domain)
                hosts, certs = ct.search_domain(domain)
                all_hostnames.update(hosts)
                total_certs += certs
                print("[+] CT logs (domain): %d hostnames from %d certificates" % (
                    len(hosts), certs))
        else:
            print("[*] Skipping CT log search (--btp-skip-ct)")

        self.result.ct_certificates = total_certs

        if self._cancelled():
            return []

        # Shodan discovery (optional)
        shodan_key = self.config.get("shodan_key")
        if shodan_key and keyword:
            print("[*] Querying Shodan ...")
            shodan = ShodanDiscovery(shodan_key, timeout=self.timeout)
            hosts = shodan.search(keyword)
            print("[+] Shodan: %d hostnames" % len(hosts))
            all_hostnames.update(hosts)

        # Censys discovery (optional)
        censys_id = self.config.get("censys_id")
        censys_secret = self.config.get("censys_secret")
        if censys_id and censys_secret and keyword:
            print("[*] Querying Censys ...")
            censys = CensysDiscovery(censys_id, censys_secret, timeout=self.timeout)
            hosts = censys.search(keyword)
            print("[+] Censys: %d hostnames" % len(hosts))
            all_hostnames.update(hosts)

        # Wayback Machine
        if domain:
            print("[*] Querying Wayback Machine for: %s" % domain)
            wayback = WaybackDiscovery(timeout=self.timeout)
            hosts = wayback.search(domain)
            print("[+] Wayback: %d hostnames" % len(hosts))
            all_hostnames.update(hosts)

        # Manual targets file
        if targets_file:
            print("[*] Loading targets from: %s" % targets_file)
            try:
                with open(targets_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Could be a URL or hostname
                            if line.startswith("http"):
                                parsed = urlparse(line)
                                if parsed.hostname:
                                    all_hostnames.add(parsed.hostname.lower())
                            else:
                                all_hostnames.add(line.lower())
                print("[+] Loaded %d targets from file" % len(all_hostnames))
            except IOError as e:
                print("[-] Error reading targets file: %s" % e)

        # Filter to BTP-relevant hostnames
        btp_hostnames = set()
        for h in all_hostnames:
            if ("ondemand.com" in h or "hana.ondemand.com" in h or
                    (domain and domain in h)):
                btp_hostnames.add(h)
            elif targets_file or direct_targets:
                # Manual/direct targets are always included
                btp_hostnames.add(h)

        # Build BTPEndpoint objects
        endpoints = []
        seen = set()
        for hostname in sorted(btp_hostnames):
            if hostname in seen:
                continue
            seen.add(hostname)

            service_type, region = classify_hostname(hostname)
            sub = extract_subaccount(hostname, service_type)

            ep = BTPEndpoint(
                url="https://%s" % hostname,
                hostname=hostname,
                port=443,
                source="ct_log",
                service_type=service_type,
                region=region,
                subaccount=sub,
            )
            endpoints.append(ep)

        # Print classification summary
        type_counts = {}
        for ep in endpoints:
            t = ep.service_type or "unknown"
            type_counts[t] = type_counts.get(t, 0) + 1
        if type_counts:
            print("[*] Classification: %s" % ", ".join(
                "%s=%d" % (k, v) for k, v in sorted(type_counts.items())))

        return endpoints

    def _resolve_dns(self, endpoints):
        """Resolve DNS for all endpoints."""
        resolver = DNSResolver(timeout=self.timeout)
        hostnames = [ep.hostname for ep in endpoints]
        resolved = resolver.resolve_batch(hostnames, threads=min(50, self.threads * 2))

        for ep in endpoints:
            ips = resolved.get(ep.hostname, [])
            if ips:
                ep.ip = ips[0]
                ep.alive = True
            else:
                ep.alive = False

        return endpoints

    def _fingerprint(self, endpoints):
        """Run HTTP fingerprinting and CF SSH scanning."""
        # HTTP fingerprinting
        print("[*] HTTP fingerprinting %d endpoints ..." % len(endpoints))
        fingerprinter = BTPFingerprinter(timeout=self.timeout)

        if HAS_RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%%"),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
            ) as prog:
                task = prog.add_task("Fingerprinting", total=len(endpoints))
                with ThreadPoolExecutor(max_workers=min(len(endpoints), self.threads)) as executor:
                    futures = {executor.submit(fingerprinter.fingerprint, ep): ep
                               for ep in endpoints}
                    for future in as_completed(futures):
                        if self._cancelled():
                            for f in futures:
                                f.cancel()
                            break
                        try:
                            future.result()
                        except Exception as e:
                            log_verbose("  [FP] Error: %s" % e)
                        prog.update(task, advance=1)
        else:
            done = [0]
            total = len(endpoints)
            with ThreadPoolExecutor(max_workers=min(len(endpoints), self.threads)) as executor:
                futures = {executor.submit(fingerprinter.fingerprint, ep): ep
                           for ep in endpoints}
                for future in as_completed(futures):
                    if self._cancelled():
                        for f in futures:
                            f.cancel()
                        break
                    try:
                        future.result()
                    except Exception:
                        pass
                    done[0] += 1
                    pct = done[0] * 100 // total
                    sys.stdout.write("\r[*] Fingerprinting ... %d%%" % pct)
                    sys.stdout.flush()
            sys.stdout.write("\r" + " " * 50 + "\r")
            sys.stdout.flush()

        responding = sum(1 for ep in endpoints if ep.status_code > 0)
        print("[+] %d/%d endpoints responded to HTTP" % (responding, len(endpoints)))

        # CF SSH scanning — scan CF app types plus any direct/unknown targets
        # (custom domains pointing to CF apps won't have a CF service_type)
        cf_types = ("cf_app", "cpi", "launchpad", "workzone", "portal")
        cf_hosts = [ep.hostname for ep in endpoints
                    if ep.service_type in cf_types
                    or ep.service_type in ("unknown", "unknown_btp")]
        if cf_hosts:
            print("[*] Scanning %d CF endpoints for SSH (port 2222) ..." % len(cf_hosts))
            ssh_scanner = CFSSHScanner(timeout=self.timeout)
            ssh_results = ssh_scanner.scan_batch(cf_hosts, threads=min(len(cf_hosts), self.threads),
                                                  cancel_check=self.cancel_check)
            # Map SSH results back to endpoints
            ssh_map = {r["hostname"]: r for r in ssh_results}
            ssh_open = 0
            for ep in endpoints:
                if ep.hostname in ssh_map:
                    ep.ssh_info = ssh_map[ep.hostname]
                    if ep.ssh_info.get("is_diego"):
                        ssh_open += 1
                        # Mark as alive even if HTTPS didn't respond
                        if not ep.alive:
                            ep.alive = True
            print("[+] CF SSH (Diego): %d/%d endpoints with port 2222 open" % (
                ssh_open, len(cf_hosts)))

        # TLS analysis on a sample
        tls_eps = [ep for ep in endpoints if ep.port == 443 and ep.alive][:50]
        if tls_eps:
            print("[*] TLS analysis on %d endpoints ..." % len(tls_eps))
            tls_analyzer = TLSAnalyzer(timeout=self.timeout)
            with ThreadPoolExecutor(max_workers=min(len(tls_eps), 10)) as executor:
                futures = {executor.submit(tls_analyzer.analyze, ep.hostname, ep.port): ep
                           for ep in tls_eps}
                for future in as_completed(futures):
                    ep = futures[future]
                    try:
                        ep.tls_info = future.result()
                    except Exception:
                        pass

    def _assess(self, endpoints):
        """Run vulnerability checks with progress tracking."""
        assessor = BTPVulnAssessor(timeout=self.timeout)
        total = len(endpoints)
        print("[*] Running vulnerability checks on %d endpoints ..." % total)

        if HAS_RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%%"),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
            ) as prog:
                task = prog.add_task("Vulnerability assessment", total=total)
                for ep in endpoints:
                    if self._cancelled():
                        print("\n[!] Scan cancelled by user")
                        break
                    assessor.assess(ep)
                    prog.update(task, advance=1)
        else:
            for i, ep in enumerate(endpoints):
                if self._cancelled():
                    print("\n[!] Scan cancelled by user")
                    break
                assessor.assess(ep)
                pct = (i + 1) * 100 // total
                sys.stdout.write("\r[*] Vulnerability assessment ... %d%%" % pct)
                sys.stdout.flush()
            sys.stdout.write("\r" + " " * 50 + "\r")
            sys.stdout.flush()


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8: Banner & Standalone CLI
# ═══════════════════════════════════════════════════════════════════════════════

def print_btp_banner():
    """Print the BTP scanner banner."""
    banner = r"""
  ____    _    ____       _
 / ___|  / \  |  _ \ ___ | | ___   __ _ _   _
 \___ \ / _ \ | |_) / _ \| |/ _ \ / _` | | | |
  ___) / ___ \|  __/ (_) | | (_) | (_| | |_| |
 |____/_/   \_\_|   \___/|_|\___/ \__, |\__, |
    BTP Cloud Scanner              |___/ |___/
"""
    print(banner)
    print("  SAP BTP Cloud Surface Scanner")
    print("  by Joris van de Vis")
    print("  CT Logs + DNS + Shodan + Censys + Wayback")
    print()


def print_btp_terminal_summary(result):
    """Print BTP scan results to terminal."""
    summary = result.summary()
    print("\n" + "=" * 60)
    print(" BTP Cloud Scan Results")
    print("=" * 60)
    print("[*] Endpoints: %d discovered, %d alive" % (
        summary["total_endpoints"], summary["alive_endpoints"]))
    print("[*] Regions: %d" % summary["regions"])
    print("[*] Findings: %d total" % summary["total_findings"])
    if summary["critical"] > 0:
        print("[!] CRITICAL: %d" % summary["critical"])
    if summary["high"] > 0:
        print("[!] HIGH: %d" % summary["high"])
    if summary["medium"] > 0:
        print("[*] MEDIUM: %d" % summary["medium"])
    if summary["low"] > 0:
        print("[*] LOW: %d" % summary["low"])
    if summary["info"] > 0:
        print("[*] INFO: %d" % summary["info"])

    # Print alive endpoints
    alive = [ep for ep in result.endpoints if ep.alive]
    if alive and HAS_RICH:
        try:
            console = Console()
            from rich.table import Table
            table = Table(title="Discovered BTP Endpoints", show_lines=False)
            table.add_column("Hostname", style="cyan")
            table.add_column("Service", style="green")
            table.add_column("Region", style="yellow")
            table.add_column("Auth", style="magenta")
            table.add_column("Findings", style="red")
            for ep in alive[:50]:
                fc = len(ep.findings)
                table.add_row(
                    ep.hostname[:60],
                    ep.service_type or "-",
                    ep.region or "-",
                    ep.auth_type or "-",
                    str(fc) if fc > 0 else "-",
                )
            console.print(table)
        except Exception:
            pass
    elif alive:
        print("\nDiscovered endpoints:")
        for ep in alive[:20]:
            fc = len(ep.findings)
            print("  %s [%s] %s %s" % (
                ep.hostname, ep.service_type or "?",
                ep.region or "", "(%d findings)" % fc if fc > 0 else ""))
        if len(alive) > 20:
            print("  ... and %d more" % (len(alive) - 20))


def main():
    """Standalone CLI entry point."""
    print_btp_banner()

    parser = argparse.ArgumentParser(
        description="SAPology BTP Cloud Scanner — Discover, fingerprint, and "
                    "assess SAP BTP cloud services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  SAPology_btp.py -t myapp.cfapps.eu10.hana.ondemand.com
  SAPology_btp.py -t host1.cfapps.eu10.hana.ondemand.com,host2.cfapps.us20.hana.ondemand.com
  SAPology_btp.py --discover acmecorp
  SAPology_btp.py --subaccount a1b2c3trial -v
  SAPology_btp.py --domain mycompany.com -o btp_report.html
  SAPology_btp.py --targets btp_urls.txt --json results.json
  SAPology_btp.py --discover acmecorp --skip-vuln
""",
    )

    parser.add_argument("--target", "-t",
                        help="Target BTP URL or hostname (comma-separated)")
    parser.add_argument("--discover", "-d",
                        help="Search CT logs for org keyword")
    parser.add_argument("--domain",
                        help="Target custom domain (e.g., mycompany.com)")
    parser.add_argument("--subaccount", "-s",
                        help="Known subaccount identifier")
    parser.add_argument("--targets", "-T",
                        help="File with BTP URLs (one per line)")
    parser.add_argument("--regions", default="all",
                        help="Comma-separated BTP regions (default: all)")
    parser.add_argument("--skip-ct", action="store_true",
                        help="Skip Certificate Transparency log search")
    parser.add_argument("--skip-vuln", action="store_true",
                        help="Skip vulnerability assessment")
    parser.add_argument("--skip-fingerprint", action="store_true",
                        help="Skip HTTP fingerprinting (discovery only)")
    parser.add_argument("--shodan-key",
                        help="Shodan API key for infrastructure discovery")
    parser.add_argument("--censys-id",
                        help="Censys API ID")
    parser.add_argument("--censys-secret",
                        help="Censys API secret")
    parser.add_argument("-o", "--output",
                        help="HTML report output path")
    parser.add_argument("--json", dest="json_output",
                        help="JSON export path")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--threads", type=int, default=20,
                        help="Number of parallel threads (default: 20)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Per-connection timeout in seconds (default: 5)")

    args = parser.parse_args()

    if not args.target and not args.discover and not args.domain and not args.subaccount and not args.targets:
        parser.error("At least one of --target, --discover, --domain, --subaccount, or --targets is required")

    config = {
        "target": args.target,
        "keyword": args.discover,
        "domain": args.domain,
        "subaccount": args.subaccount,
        "targets_file": args.targets,
        "regions": args.regions,
        "skip_ct": args.skip_ct,
        "skip_vuln": args.skip_vuln,
        "skip_fingerprint": args.skip_fingerprint,
        "shodan_key": args.shodan_key,
        "censys_id": args.censys_id,
        "censys_secret": args.censys_secret,
        "verbose": args.verbose,
        "threads": args.threads,
        "timeout": args.timeout,
    }

    scanner = BTPScanner(config)
    result = scanner.run()

    # Terminal summary
    print_btp_terminal_summary(result)

    # HTML report
    if args.output:
        print("\n[*] Generating HTML report: %s" % args.output)
        generate_btp_html_report(result, args.output)
        print("[+] HTML report saved to: %s" % args.output)
    elif result.endpoints:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = "SAPology_BTP_%s.html" % ts
        print("\n[*] Generating HTML report: %s" % output_path)
        generate_btp_html_report(result, output_path)
        print("[+] HTML report saved to: %s" % output_path)

    # JSON export
    if args.json_output:
        print("[*] Generating JSON export: %s" % args.json_output)
        generate_btp_json(result, args.json_output)
        print("[+] JSON export saved to: %s" % args.json_output)

    # Duration
    dur_m = int(result.scan_duration // 60)
    dur_s = int(result.scan_duration % 60)
    print("\n[*] Scan complete in %d:%02d" % (dur_m, dur_s))

    summary = result.summary()
    print("[*] %d endpoint(s), %d finding(s) (%d critical)" % (
        summary["alive_endpoints"], summary["total_findings"],
        summary["critical"]))


if __name__ == "__main__":
    main()

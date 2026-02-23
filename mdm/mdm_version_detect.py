#!/usr/bin/env python3
"""
SAP MDM Version Detection Scanner
===================================
Standalone tool that detects SAP MDM service versions across all four
MDM server components (MDS, MDIS, MDLS, MDSS) on a target host.

Supports version detection for SAP MDM 3.x through 7.x by trying
multiple known interface CRCs from different MDM releases.

Protocol details reverse-engineered from SAP MDM binaries and traffic
analysis during authorized security research.

Usage:
  python mdm_version_detect.py <host>
  python mdm_version_detect.py <host> --ports 59950 59750
  python mdm_version_detect.py <host> --timeout 10

DISCLAIMER: For authorized security testing only.
"""

import socket
import struct
import sys
import re
import argparse
import subprocess
import os

# ============================================================
# Protocol constants
# ============================================================

MAGIC = bytes.fromhex('691294a2')
IDENT = bytes.fromhex('693241')       # "i2A"
BAND_INIT = 0x03
BAND_NORMAL = 0x00

# Default ports for MDM services
DEFAULT_PORTS = {
    'MDS':  59950,   # Master Data Server
    'MDIS': 59750,   # Import Server
    'MDLS': 59650,   # Layout Server
    'MDSS': 59850,   # Syndication Server
}

# Known interface CRCs across MDM versions (from binary analysis of
# CLIX.exe, MDS.exe, MDIS.exe across versions 7.1.16 and 7.1.21)
#
# MDM uses CRC pairs (primary + secondary) for interface negotiation.
# The primary CRC must match for round 1-2 of negotiation, and a
# secondary CRC for round 3. If the CRC doesn't match, MDS rejects
# all commands. MDIS on some versions has a CRC bypass (commands
# execute without negotiation).

# All unique CRCs found across MDM binaries
KNOWN_CRCS = [
    # v7.1.21 CRCs (from CLIX 7.1.21.154 + MDS.exe + MDIS.exe)
    (0x054f58ee, 'MDM 7.1.21 primary'),
    (0x646e35f0, 'MDM 7.1.21 secondary'),
    (0xd92079cf, 'MDM 7.1.21 v2'),
    # v7.1.16 CRCs (from CLIX old)
    (0x82072e43, 'MDM 7.1.16 primary'),
    (0x5bed2b5c, 'MDM 7.1.16 secondary'),
    (0x8ce88d20, 'MDM 7.1.16 v5'),
    # Shared across versions
    (0x83381ec1, 'MDM shared v3'),
    (0x24ec5073, 'MDM shared v4'),
    (0x1d725db0, 'MDM shared v1'),
    # MDIS-specific
    (0xa71ed79d, 'MDIS 7.1.16+'),
]

# Known primary/secondary CRC pairs for MDS negotiation
# Format: (primary_crc, secondary_crc, description)
MDS_CRC_PAIRS = [
    (0x054f58ee, 0x646e35f0, 'MDM 7.1.21'),
    (0x82072e43, 0x5bed2b5c, 'MDM 7.1.16'),
    # Additional pairs to try (primary with each secondary)
    (0xd92079cf, 0x646e35f0, 'MDM 7.1.21 alt'),
    (0x83381ec1, 0x24ec5073, 'MDM shared'),
    (0x8ce88d20, 0x1d725db0, 'MDM 7.1.16 alt'),
    (0x1d725db0, 0x83381ec1, 'MDM legacy'),
    (0x24ec5073, 0x83381ec1, 'MDM legacy alt'),
]

# Command types per service
CMD_TYPE_MDS = 1     # MDS uses type=1 in command headers
CMD_TYPE_MDIS = 5    # MDIS uses type=5 in command headers


# ============================================================
# Low-level protocol helpers
# ============================================================

def build_packet(band, payload):
    """Build a complete MDM wire-protocol packet.

    Format: [4B magic][1B band][3B ident][4B len LE][payload]
    """
    return MAGIC + bytes([band]) + IDENT + struct.pack('<I', len(payload)) + payload


def build_cmd(cmd_type, cmd_id, crc, extra=b''):
    """Build a command payload.

    Format: [2B type LE][2B cmd_id LE][4B crc LE][extra...]
    """
    return struct.pack('<HHI', cmd_type, cmd_id, crc) + extra


def parse_response(data):
    """Parse an MDM response packet, return (band, payload) or None."""
    if not data or len(data) < 12:
        return None
    magic = data[0:4]
    if magic != MAGIC:
        return None
    band = data[4]
    msg_len = struct.unpack('<I', data[8:12])[0]
    payload = data[12:12 + msg_len] if len(data) >= 12 + msg_len else data[12:]
    return band, payload


def decode_printable(data):
    """Extract printable ASCII from binary data."""
    return ''.join(chr(b) if 32 <= b < 127 else '' for b in data)


# ============================================================
# Service probing functions
# ============================================================

def probe_init(host, port, timeout=5):
    """Send an init handshake (band 0x03) and return the response info.

    All MDM services respond to the init handshake with their IP and
    a timestamp, regardless of CRC or version. This is the most
    reliable way to detect any MDM service.

    Returns dict with keys: alive, ip, timestamp, raw_payload
    Or None if no MDM service is listening.
    """
    result = {
        'alive': False,
        'ip': None,
        'timestamp': None,
        'raw_payload': None,
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.send(build_packet(BAND_INIT, b'\x01'))
        resp = s.recv(4096)
        s.close()
    except (ConnectionRefusedError, socket.timeout, OSError):
        return None

    parsed = parse_response(resp)
    if not parsed:
        return None

    band, payload = parsed
    result['alive'] = True
    result['raw_payload'] = payload

    # Init response format: [1B type][4B str_len LE][str_len B string]
    # String: "IP.::timestamp"
    if len(payload) > 5:
        str_len = struct.unpack('<I', payload[1:5])[0]
        if str_len > 0 and 5 + str_len <= len(payload):
            try:
                info_text = payload[5:5 + str_len].decode('latin-1')
                if '.::' in info_text:
                    parts = info_text.split('.::')
                    result['ip'] = parts[0].rstrip('.')
                    result['timestamp'] = parts[1] if len(parts) > 1 else None
                else:
                    result['ip'] = info_text
            except Exception:
                pass

    return result


def probe_mdis_version(host, port, timeout=5):
    """Probe an MDIS service for its version string.

    MDIS accepts commands without CRC negotiation (CRC bypass).
    cmd 0x02 (type=5) returns the full version string.

    Returns dict with keys: version_full, version_number, platform, raw
    Or None on failure.
    """
    result = {
        'version_full': None,
        'version_number': None,
        'platform': None,
        'raw': None,
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))

        # Init handshake
        s.send(build_packet(BAND_INIT, b'\x01'))
        s.recv(4096)

        # Try each known MDIS CRC
        for crc, crc_name in KNOWN_CRCS:
            try:
                s.send(build_packet(BAND_NORMAL, build_cmd(CMD_TYPE_MDIS, 0x02, crc)))
                resp = s.recv(4096)
                parsed = parse_response(resp)
                if parsed:
                    _, payload = parsed
                    text = decode_printable(payload)
                    ver_match = re.search(r'(Version\s+[\d.]+\s*\([^)]+\))', text)
                    if ver_match:
                        result['version_full'] = ver_match.group(1)
                        num_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', text)
                        plat_match = re.search(r'(Win\d+|Linux\w*|AIX\w*|SunOS\w*|HP-UX\w*)', text)
                        if num_match:
                            result['version_number'] = num_match.group(1)
                        if plat_match:
                            result['platform'] = plat_match.group(1)
                        result['raw'] = payload
                        s.close()
                        return result
            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                # CRC mismatch may cause disconnect; reconnect and try next
                try:
                    s.close()
                except Exception:
                    pass
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((host, port))
                s.send(build_packet(BAND_INIT, b'\x01'))
                s.recv(4096)

        s.close()
    except Exception:
        pass

    return result if result['version_full'] else None


def _mds_negotiate_and_query(host, port, primary_crc, secondary_crc, timeout=5):
    """Try a specific CRC pair for MDS negotiation and version extraction.

    Negotiation: 3 rounds of cmd 0x00 (type=1)
      Round 1: param_id=1, check=primary_crc
      Round 2: param_id=1, check=primary_crc
      Round 3: param_id=2, check=secondary_crc

    If round 1 fails, the primary CRC is wrong (no point trying further).
    If round 3 fails, we still attempt registration and version query
    since some server states allow partial negotiation.

    Returns dict or None.
    """
    result = {
        'version': None,
        'server_count': None,
        'sid': None,
        'raw': None,
    }

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))

    # Init
    s.send(build_packet(BAND_INIT, b'\x01'))
    init_resp = s.recv(4096)
    if not parse_response(init_resp):
        s.close()
        return None

    # Round 1: primary CRC check
    extra = b'\x00' + struct.pack('<H', 1) + struct.pack('<I', primary_crc)
    s.send(build_packet(BAND_NORMAL, build_cmd(CMD_TYPE_MDS, 0x00, primary_crc, extra)))
    resp = s.recv(4096)
    parsed = parse_response(resp)
    if not parsed or parsed[1] != b'\x00':
        s.close()
        return None  # Primary CRC rejected

    # Round 2: same primary
    s.send(build_packet(BAND_NORMAL, build_cmd(CMD_TYPE_MDS, 0x00, primary_crc, extra)))
    resp = s.recv(4096)
    parsed = parse_response(resp)
    if not parsed or parsed[1] != b'\x00':
        s.close()
        return None

    # Round 3: secondary CRC
    extra3 = b'\x00' + struct.pack('<H', 2) + struct.pack('<I', secondary_crc)
    s.send(build_packet(BAND_NORMAL, build_cmd(CMD_TYPE_MDS, 0x00, primary_crc, extra3)))
    resp = s.recv(4096)
    parsed = parse_response(resp)
    # Round 3 failure is non-fatal - continue anyway

    # Register client (cmd 0x0e)
    lang = b'engUS0'
    def mdm_str(text):
        b = text.encode('latin-1')
        return struct.pack('<II', len(b), len(b)) + b'000000' + b

    reg_extra = b'\x00' + lang + mdm_str('SAP MDM Scanner') + mdm_str('')
    s.send(build_packet(BAND_NORMAL, build_cmd(CMD_TYPE_MDS, 0x0e, primary_crc, reg_extra)))
    reg_resp = s.recv(4096)
    reg_parsed = parse_response(reg_resp)

    session_token = None
    if reg_parsed and len(reg_parsed[1]) >= 9:
        session_token = reg_parsed[1][2:9]

    # Session setup (cmd 0x14) - may fail, non-fatal
    if session_token:
        setup_extra = (b'\x00\x01' + session_token +
                       b'\x00' * 8 + b'000000' +
                       b'\x00' * 8 + b'000000')
        s.send(build_packet(BAND_NORMAL, build_cmd(CMD_TYPE_MDS, 0x14, primary_crc, setup_extra)))
        try:
            s.recv(4096)
        except Exception:
            pass

    # Get version (cmd 0x01)
    s.send(build_packet(BAND_NORMAL, build_cmd(CMD_TYPE_MDS, 0x01, primary_crc, b'\x00')))
    ver_resp = s.recv(4096)
    ver_parsed = parse_response(ver_resp)

    if ver_parsed and len(ver_parsed[1]) >= 15:
        payload = ver_parsed[1]
        # Format: [1B status][4B str_len][4B alloc_len][6B sid_prefix][str_len B string]
        str_len = struct.unpack_from('<I', payload, 1)[0]
        if str_len > 0 and 15 + str_len <= len(payload):
            sid_prefix = payload[9:15]
            version_bytes = payload[15:15 + str_len]
            try:
                result['version'] = version_bytes.decode('latin-1')
                sid_candidate = sid_prefix.decode('latin-1').rstrip('0').rstrip('\x00')
                if sid_candidate and sid_candidate.isalnum():
                    result['sid'] = sid_candidate
            except Exception:
                pass
        result['raw'] = payload

    # Get server count (cmd 0x02)
    try:
        s.send(build_packet(BAND_NORMAL, build_cmd(CMD_TYPE_MDS, 0x02, primary_crc, b'\x00')))
        cnt_resp = s.recv(4096)
        cnt_parsed = parse_response(cnt_resp)
        if cnt_parsed and len(cnt_parsed[1]) >= 5:
            if cnt_parsed[1][0] == 0:
                result['server_count'] = struct.unpack('<I', cnt_parsed[1][1:5])[0]
    except Exception:
        pass

    s.close()
    return result if result['version'] else None


def probe_mds_version(host, port, timeout=5):
    """Probe an MDS service for its version string.

    MDS requires CRC negotiation before commands work. We try known
    CRC pairs first, then brute-force all combinations.

    Returns dict with keys: version, server_count, crc_used, sid, raw
    Or None on failure.
    """
    # Try known CRC pairs first (fastest)
    for primary_crc, secondary_crc, pair_name in MDS_CRC_PAIRS:
        try:
            result = _mds_negotiate_and_query(host, port, primary_crc, secondary_crc, timeout)
            if result and result['version']:
                result['crc_used'] = pair_name
                return result
        except Exception:
            pass

    # Fallback: try every primary CRC with itself as secondary
    for primary_crc, crc_name in KNOWN_CRCS:
        if primary_crc == 0xa71ed79d:
            continue
        try:
            result = _mds_negotiate_and_query(host, port, primary_crc, primary_crc, timeout)
            if result and result['version']:
                result['crc_used'] = crc_name
                return result
        except Exception:
            pass

    return None


def probe_generic_version(host, port, cmd_type, timeout=5):
    """Generic version probe using MDIS-style CRC bypass.

    MDLS and MDSS may also accept commands without CRC negotiation
    (like MDIS does). We try cmd 0x02 with each known CRC.
    We also try cmd_type=5 (MDIS-style) and service-specific types.

    Returns version dict or None.
    """
    result = {
        'version_full': None,
        'version_number': None,
        'platform': None,
    }

    # Try multiple command types: the service-specific one and MDIS-style (5)
    cmd_types_to_try = list(set([cmd_type, CMD_TYPE_MDIS, CMD_TYPE_MDS, 3, 4, 6, 7]))

    for try_type in cmd_types_to_try:
        for crc, crc_name in KNOWN_CRCS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((host, port))

                # Init
                s.send(build_packet(BAND_INIT, b'\x01'))
                s.recv(4096)

                # Try version command (0x02) without CRC negotiation
                s.send(build_packet(BAND_NORMAL, build_cmd(try_type, 0x02, crc)))
                resp = s.recv(4096)
                s.close()

                parsed = parse_response(resp)
                if parsed:
                    _, payload = parsed
                    text = decode_printable(payload)
                    ver_match = re.search(r'(Version\s+[\d.]+\s*\([^)]+\))', text)
                    if ver_match:
                        result['version_full'] = ver_match.group(1)
                        num_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', text)
                        plat_match = re.search(r'(Win\d+|Linux\w*|AIX\w*|SunOS\w*|HP-UX\w*)', text)
                        if num_match:
                            result['version_number'] = num_match.group(1)
                        if plat_match:
                            result['platform'] = plat_match.group(1)
                        return result

            except Exception:
                try:
                    s.close()
                except Exception:
                    pass

    return None


# ============================================================
# CLIX command fallback
# ============================================================

# CLIX version commands per service
CLIX_COMMANDS = {
    'MDS':  'svrMDSVersion',
    'MDIS': 'svrImportVersion',
    'MDLS': 'svrLayoutVersion',
    'MDSS': 'svrSyndicationVersion',
}


def find_clix():
    """Find CLIX.exe in common locations."""
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'CLIX', 'CLIX.exe'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'MDM_CLIX_7.121_154', 'CLIX.exe'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'CLIX.exe'),
    ]
    # Also check PATH
    for candidate in candidates:
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return None


def probe_clix_version(host, port, service_name, clix_path=None, timeout=10):
    """Use CLIX.exe to query service version.

    CLIX uses the same MDM protocol but handles CRC negotiation internally.
    Falls back gracefully if CLIX is not found or returns an error.

    Returns version string or None.
    """
    if clix_path is None:
        clix_path = find_clix()
    if not clix_path:
        return None

    cmd_name = CLIX_COMMANDS.get(service_name)
    if not cmd_name:
        return None

    try:
        args = [clix_path, cmd_name, host, '-#', str(port)]
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        output = (result.stdout + result.stderr).strip()

        # Parse version from CLIX output
        # Typical: "MDM Server: Version 7.1 (7.1.21.154 Win64)"
        # Or: "Import Server: Version 7.1 (7.1.21.154 Win64)"
        ver_match = re.search(r'(Version\s+[\d.]+\s*\([^)]+\))', output)
        if ver_match:
            return ver_match.group(1)

        # Check for errors
        if 'Error' in output or 'CRC' in output:
            return None

        return None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


# ============================================================
# Main scanner
# ============================================================

def _parse_version_into_findings(findings, ver_text):
    """Parse a version string and populate findings dict."""
    full_match = re.search(r'(Version\s+[\d.]+\s*\([^)]+\))', ver_text)
    if full_match:
        findings['version'] = full_match.group(1)
    else:
        findings['version'] = ver_text
    num_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', ver_text)
    plat_match = re.search(r'(Win\d+|Linux\w*|AIX\w*|SunOS\w*|HP-UX\w*)', ver_text)
    if num_match:
        findings['version_number'] = num_match.group(1)
    if plat_match:
        findings['platform'] = plat_match.group(1)


def scan_service(host, port, service_name, timeout=5, clix_path=None):
    """Scan a single MDM service port and return findings.

    Detection order:
      1. MDM binary protocol (init handshake + CRC negotiation/bypass)
      2. CLIX command fallback (if clix_path provided and protocol fails)
    """
    findings = {
        'service': service_name,
        'port': port,
        'alive': False,
        'ip': None,
        'timestamp': None,
        'version': None,
        'version_number': None,
        'platform': None,
        'server_count': None,
        'sid': None,
        'crc_info': None,
        'detection_method': None,
    }

    # Phase 1: Init handshake (detects any MDM service)
    init = probe_init(host, port, timeout)
    if not init:
        return findings

    findings['alive'] = True
    findings['ip'] = init['ip']
    findings['timestamp'] = init['timestamp']

    # Phase 2: Version detection via MDM protocol (service-specific)
    if service_name == 'MDIS':
        ver = probe_mdis_version(host, port, timeout)
        if ver:
            findings['version'] = ver['version_full']
            findings['version_number'] = ver['version_number']
            findings['platform'] = ver['platform']
            findings['detection_method'] = 'MDIS CRC bypass (cmd 0x02)'

    elif service_name == 'MDS':
        ver = probe_mds_version(host, port, timeout)
        if ver:
            findings['server_count'] = ver['server_count']
            findings['sid'] = ver['sid']
            findings['crc_info'] = ver['crc_used']
            findings['detection_method'] = 'MDS CRC negotiation (cmd 0x01)'
            if ver['version']:
                _parse_version_into_findings(findings, ver['version'])

    else:
        # MDLS / MDSS: try generic approach
        ver = probe_generic_version(host, port, cmd_type=CMD_TYPE_MDIS, timeout=timeout)
        if ver:
            findings['version'] = ver['version_full']
            findings['version_number'] = ver['version_number']
            findings['platform'] = ver['platform']
            findings['detection_method'] = 'CRC bypass (cmd 0x02)'
        else:
            ver = probe_mds_version(host, port, timeout)
            if ver:
                findings['crc_info'] = ver['crc_used']
                findings['detection_method'] = 'CRC negotiation (cmd 0x01)'
                if ver['version']:
                    _parse_version_into_findings(findings, ver['version'])

    # Phase 3: CLIX fallback (if protocol-level version detection failed)
    if not findings['version'] and clix_path:
        clix_ver = probe_clix_version(host, port, service_name, clix_path, timeout=timeout+5)
        if clix_ver:
            _parse_version_into_findings(findings, clix_ver)
            findings['detection_method'] = 'CLIX command'

    return findings


def print_banner():
    print()
    print('  +------------------------------------------------------+')
    print('  |        SAP MDM Version Detection Scanner              |')
    print('  |        Pre-Auth Service Fingerprinting                |')
    print('  +------------------------------------------------------+')
    print()


def print_findings(findings_list, host):
    """Print scan results in a formatted report."""
    print()
    print(f'  Target: {host}')
    print(f'  Services scanned: {len(findings_list)}')
    print()

    alive_count = sum(1 for f in findings_list if f['alive'])
    version_count = sum(1 for f in findings_list if f['version'])

    print(f'  +-{"-" * 8}-+-{"-" * 7}-+-{"-" * 8}-+-{"-" * 40}-+')
    print(f'  | {"Service":<8} | {"Port":<7} | {"Status":<8} | {"Version":<40} |')
    print(f'  +-{"-" * 8}-+-{"-" * 7}-+-{"-" * 8}-+-{"-" * 40}-+')

    for f in findings_list:
        service = f['service']
        port = str(f['port'])
        if not f['alive']:
            status = 'DOWN'
            version = '-'
        elif f['version']:
            status = 'UP'
            version = f['version'][:40]
        else:
            status = 'UP'
            version = '(detected, version unknown)'

        print(f'  | {service:<8} | {port:<7} | {status:<8} | {version:<40} |')

    print(f'  +-{"-" * 8}-+-{"-" * 7}-+-{"-" * 8}-+-{"-" * 40}-+')
    print()

    # Detailed info for alive services
    for f in findings_list:
        if not f['alive']:
            continue

        print(f'  [{f["service"]}] Port {f["port"]}:')
        if f['ip']:
            print(f'    Server IP     : {f["ip"]}')
        if f['timestamp']:
            print(f'    Server Time   : {f["timestamp"]}')
        if f['version']:
            print(f'    Version       : {f["version"]}')
        if f['version_number']:
            print(f'    Build Number  : {f["version_number"]}')
        if f['platform']:
            print(f'    Platform      : {f["platform"]}')
        if f['server_count'] is not None:
            print(f'    Repositories  : {f["server_count"]}')
        if f['sid']:
            print(f'    SAP SID       : {f["sid"]}')
        if f['crc_info']:
            print(f'    Interface CRC : {f["crc_info"]}')
        if f.get('detection_method'):
            print(f'    Detected via  : {f["detection_method"]}')
        if not f['version']:
            print(f'    Note          : Service responds to MDM init handshake but')
            print(f'                    version string could not be extracted.')
            print(f'                    May be a different MDM version or service type.')
        print()

    # Summary
    print(f'  Summary: {alive_count}/{len(findings_list)} services alive, '
          f'{version_count}/{len(findings_list)} versions extracted')
    print()


def main():
    parser = argparse.ArgumentParser(
        description='SAP MDM Version Detection Scanner - detects MDS, MDIS, MDLS, MDSS',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.100
  %(prog)s 192.168.1.100 --ports 59950 59750
  %(prog)s 192.168.1.100 --timeout 10
  %(prog)s 192.168.1.100 --clix C:\\path\\to\\CLIX.exe

Detection methods (in order):
  1. MDM binary protocol (init handshake + CRC negotiation/bypass)
  2. CLIX.exe command fallback (auto-detected or --clix path)

Default ports: MDS=59950, MDIS=59750, MDLS=59650, MDSS=59850

DISCLAIMER: For authorized security testing only.
        """,
    )

    parser.add_argument('host', help='Target host IP address')
    parser.add_argument('--ports', '-p', nargs='+', type=int, default=None,
                        help='Specific ports to scan (overrides defaults)')
    parser.add_argument('--all-ports', '-a', action='store_true',
                        help='Scan all 4 default MDM ports (default behavior)')
    parser.add_argument('--timeout', '-t', type=float, default=5.0,
                        help='Socket timeout in seconds (default: 5)')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output results as JSON')
    parser.add_argument('--clix', metavar='PATH',
                        help='Path to CLIX.exe for fallback version detection')

    args = parser.parse_args()

    if not args.json:
        print_banner()

    # Determine which ports/services to scan
    if args.ports:
        services_to_scan = []
        for port in args.ports:
            service_name = None
            for name, default_port in DEFAULT_PORTS.items():
                if port == default_port:
                    service_name = name
                    break
            if not service_name:
                service_name = f'MDM?'
            services_to_scan.append((service_name, port))
    else:
        services_to_scan = list(DEFAULT_PORTS.items())

    # Find CLIX if requested or auto-detect
    clix_path = None
    if args.clix:
        clix_path = args.clix
        if not os.path.isfile(clix_path):
            print(f'  Warning: CLIX not found at {clix_path}')
            clix_path = None
    else:
        clix_path = find_clix()

    if clix_path and not args.json:
        print(f'  CLIX fallback: {os.path.basename(clix_path)}')

    if not args.json:
        print()

    # Scan each service
    findings = []
    for service_name, port in services_to_scan:
        if not args.json:
            print(f'  Scanning {service_name} on port {port}...', end='', flush=True)

        result = scan_service(
            args.host, port, service_name, args.timeout,
            clix_path=clix_path
        )
        findings.append(result)

        if not args.json:
            if not result['alive']:
                print(' not responding')
            elif result['version']:
                print(f' {result["version"]}')
            else:
                print(' alive (version unknown)')

    # Output results
    if args.json:
        import json
        # Clean up for JSON output
        json_findings = []
        for f in findings:
            clean = {k: v for k, v in f.items() if v is not None}
            json_findings.append(clean)
        print(json.dumps({
            'host': args.host,
            'findings': json_findings,
        }, indent=2))
    else:
        print_findings(findings, args.host)


if __name__ == '__main__':
    main()

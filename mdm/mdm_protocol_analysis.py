#!/usr/bin/env python3
"""
SAP MDM Protocol Analysis - Based on captured traffic
"""

import struct

# Protocol structure discovered from traffic capture:
#
# Header (8 bytes):
#   [4 bytes] Magic: 0x69 0x12 0x94 0xa2 (constant)
#   [1 byte]  Band tag: 0x03 (init) or 0x00 (normal)
#   [3 bytes] Identifier: 0x69 0x32 0x41 ("i2A")
#
# After header:
#   [4 bytes] Message length (little-endian)
#   [N bytes] Payload

MAGIC = b'\x69\x12\x94\xa2'
IDENT = b'\x69\x32\x41'  # "i2A"

BAND_INIT = 0x03
BAND_NORMAL = 0x00

def parse_message(data):
    """Parse a MDM protocol message"""
    if len(data) < 12:
        return None

    magic = data[0:4]
    band = data[4]
    ident = data[5:8]
    msg_len = struct.unpack('<I', data[8:12])[0]
    payload = data[12:12+msg_len] if len(data) >= 12 + msg_len else data[12:]

    return {
        'magic': magic,
        'magic_valid': magic == MAGIC,
        'band': band,
        'band_name': 'INIT' if band == BAND_INIT else 'NORMAL' if band == BAND_NORMAL else f'UNKNOWN({band})',
        'ident': ident,
        'ident_valid': ident == IDENT,
        'msg_len': msg_len,
        'payload': payload,
    }

def build_message(band, payload):
    """Build a MDM protocol message"""
    msg_len = len(payload)
    header = MAGIC + bytes([band]) + IDENT + struct.pack('<I', msg_len)
    return header + payload

# Captured messages analysis
print("="*70)
print("SAP MDM Protocol Analysis")
print("="*70)

print("\nProtocol Structure:")
print("-"*70)
print("Offset  Size  Field          Value")
print("-"*70)
print("0x00    4     Magic          69 12 94 a2")
print("0x04    1     Band Tag       03=Init, 00=Normal")
print("0x05    3     Identifier     69 32 41 ('i2A')")
print("0x08    4     Message Len    Little-endian uint32")
print("0x0C    N     Payload        Variable")

print("\n\nCaptured Messages:")
print("-"*70)

# First message (client init)
msg1 = bytes.fromhex('691294a20369324101000000' + '01')
parsed = parse_message(msg1)
print(f"\n1. CLIENT INIT:")
print(f"   Magic valid: {parsed['magic_valid']}")
print(f"   Band: {parsed['band_name']}")
print(f"   Ident valid: {parsed['ident_valid']}")
print(f"   Msg len: {parsed['msg_len']}")
print(f"   Payload: {parsed['payload'].hex()}")

# Server response (session info)
msg2 = bytes.fromhex('691294a203693241' + '2c000000' + '02270000003139322e3136382e322e39312e3a3a54756520' +
                     '4a616e2032372031313a32303a333220323032')
parsed = parse_message(msg2)
print(f"\n2. SERVER SESSION RESPONSE:")
print(f"   Band: {parsed['band_name']}")
print(f"   Msg len: {parsed['msg_len']}")
print(f"   Payload contains IP: 192.168.2.91 and timestamp")

# Normal message (version query)
msg3 = bytes.fromhex('691294a200693241' + '09000000' + '01000100432e078200')
parsed = parse_message(msg3)
print(f"\n3. CLIENT VERSION QUERY:")
print(f"   Band: {parsed['band_name']}")
print(f"   Msg len: {parsed['msg_len']}")
print(f"   Payload: {parsed['payload'].hex()}")

# Version response
msg4 = bytes.fromhex('691294a200693241' + '2d000000' + '001e0000001e00000030303030303056657273696f6e20372e3120283' +
                     '72e312e31362e323230252057696e363429')
parsed = parse_message(msg4)
print(f"\n4. SERVER VERSION RESPONSE:")
print(f"   Band: {parsed['band_name']}")
print(f"   Msg len: {parsed['msg_len']}")
print(f"   Contains: 'Version 7.1 (7.1.16.220 Win64)'")

print("\n\nCommand Structure (from payload analysis):")
print("-"*70)
print("Offset  Size  Field")
print("-"*70)
print("0x00    1     Command type (01=request)")
print("0x01    2     Command ID")
print("0x03    4     CRC/identifier (43 2e 07 82 = protocol CRC)")
print("0x07    1     Sub-command")
print("...")

print("\n\nKnown Protocol CRCs (from binary):")
print("-"*70)
crc_values = [
    ("0x1d725db0", "Interface CRC 1"),
    ("0x82072e43", "Interface CRC 2 (seen in traffic as 43 2e 07 82)"),
    ("0x83381ec1", "Interface CRC 3"),
    ("0x24ec5073", "Interface CRC 4"),
    ("0x8ce88d20", "Interface CRC 5"),
    ("0x5bed2b5c", "Interface CRC 6"),
]
for crc, name in crc_values:
    print(f"  {crc}: {name}")

print("\n\nVULNERABILITY IMPLICATIONS:")
print("="*70)
print("""
Based on the captured protocol:

1. MAGIC VALIDATION:
   - Magic: 69 12 94 a2
   - What happens if we send wrong magic?
   - Could bypass protocol checks?

2. BAND TAG MANIPULATION:
   - Band 0x03 = Initialization (pre-auth)
   - Band 0x00 = Normal communication
   - What happens with invalid band tags (0xFF, etc.)?

3. MESSAGE LENGTH OVERFLOW:
   - Length is uint32 at offset 0x08
   - Send length = 0xFFFFFFFF
   - Server allocates huge buffer or integer overflow?

4. PAYLOAD PARSING:
   - CRC at offset 0x03 of payload
   - What if CRC is invalid?
   - What if command ID is out of range?

5. SESSION HANDLING:
   - Session token visible in traffic (8f f5 bf ba 3d b6 fa)
   - Can we forge/replay sessions?
""")

if __name__ == '__main__':
    pass

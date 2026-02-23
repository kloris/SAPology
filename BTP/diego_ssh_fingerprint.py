#!/usr/bin/env python3
"""
Diego-SSH Proxy Fingerprinting Tool

Fingerprints Cloud Foundry Diego-SSH proxy instances by analysing the
SSH KEXINIT algorithm negotiation, which happens *before* authentication.

The diego-ssh-proxy hardcodes specific algorithm lists that changed at
known dates, creating distinct "epochs" that reveal the diego-release
version range.

Epoch table
-----------
Epoch 1  (< ~v2.78.0)        : Go SSH defaults (broad cipher/kex set)
Epoch 2  (~v2.78.0 - v2.87.0): chacha20 + aes-gcm + aes-ctr, no kex-strict
Epoch 3  (v2.88.0 - v2.112.0): same ciphers, kex-strict added (Terrapin fix)
Epoch 4  (>= v2.113.0)       : chacha20 removed (SAP CFAR-1064), kex-strict

Usage
-----
    python3 diego_ssh_fingerprint.py <hostname> [port]
    python3 diego_ssh_fingerprint.py --batch hosts.txt

Designed so that the fingerprint_diego_ssh() function can be imported
directly into SAPology_btp.py.
"""

import argparse
import json
import socket
import struct
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DIEGO_BANNER = "diego-ssh-proxy"
DEFAULT_PORT = 2222
DEFAULT_TIMEOUT = 5

# Known diego-ssh-proxy algorithm epochs.
# Each epoch is identified by checking the cipher and kex lists advertised
# in the server's SSH_MSG_KEXINIT (message type 20).
#
# Diego-ssh overrides the Go crypto/ssh defaults in cmd/ssh-proxy/main.go:
#   Ciphers      -> AllowedCiphers  (or hardcoded default)
#   MACs         -> AllowedMACs     (or hardcoded default)
#   KeyExchanges -> AllowedKeyExchanges (or hardcoded default)
#
# The kex-strict-s-v00@openssh.com pseudo-algorithm is injected by the Go
# SSH library itself (>= golang.org/x/crypto v0.17.0) and is not part of
# the diego-ssh configuration.

DIEGO_EPOCHS = [
    {
        "epoch": 4,
        "version_range": ">= v2.113.0",
        "release_date": "Feb 2025+",
        "description": "chacha20 removed (Terrapin hardening, SAP CFAR-1064)",
        "match": {
            "has_kex_strict": True,
            "has_chacha20": False,
        },
    },
    {
        "epoch": 3,
        "version_range": "v2.88.0 - v2.112.0",
        "release_date": "Dec 2023 - Jan 2025",
        "description": "Terrapin kex-strict mitigation added",
        "match": {
            "has_kex_strict": True,
            "has_chacha20": True,
        },
    },
    {
        "epoch": 2,
        "version_range": "~v2.78.0 - v2.87.0",
        "release_date": "Apr 2018 - Dec 2023",
        "description": "Hardcoded secure defaults with chacha20",
        "match": {
            "has_kex_strict": False,
            "has_chacha20": True,
        },
    },
    {
        "epoch": 1,
        "version_range": "< ~v2.78.0",
        "release_date": "before Apr 2018",
        "description": "Go SSH library defaults (no hardcoded overrides)",
        "match": {
            "has_kex_strict": False,
            "has_chacha20": False,
        },
    },
]

# ---------------------------------------------------------------------------
# SSH KEXINIT parser
# ---------------------------------------------------------------------------

KEXINIT_FIELDS = [
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_client_to_server",
    "encryption_server_to_client",
    "mac_client_to_server",
    "mac_server_to_client",
    "compression_client_to_server",
    "compression_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
]


def _recv_exact(sock, n):
    """Read exactly *n* bytes from *sock*."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading")
        buf += chunk
    return buf


def _parse_kexinit(data):
    """Parse an SSH_MSG_KEXINIT payload into a dict of name-lists.

    *data* starts at the message type byte (0x14 / 20).
    """
    if data[0] != 20:
        raise ValueError("Not a KEXINIT message (type=%d)" % data[0])

    # Skip message type (1 byte) + cookie (16 bytes)
    offset = 17
    result = {}
    for field in KEXINIT_FIELDS:
        if offset + 4 > len(data):
            break
        str_len = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
        value = data[offset : offset + str_len].decode("utf-8", errors="replace")
        offset += str_len
        result[field] = value.split(",") if value else []

    return result


def _grab_kexinit(hostname, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    """Connect, exchange banners, and return (banner, kexinit_dict).

    Raises on any connection / parsing failure.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((hostname, port))

        # --- Read server banner (terminated by \n) ---
        banner_buf = b""
        while not banner_buf.endswith(b"\n"):
            b = sock.recv(1)
            if not b:
                raise ConnectionError("Connection closed during banner read")
            banner_buf += b
            if len(banner_buf) > 512:
                raise ValueError("Banner too long")
        banner = banner_buf.strip().decode("utf-8", errors="replace")

        # --- Send a minimal client banner ---
        sock.sendall(b"SSH-2.0-SAPology_fingerprint\r\n")

        # --- Read KEXINIT packet ---
        # Packet: uint32 packet_length | byte padding_length | payload | padding
        header = _recv_exact(sock, 5)
        pkt_len = struct.unpack(">I", header[:4])[0]
        pad_len = header[4]

        if pkt_len > 65536:
            raise ValueError("Packet too large (%d)" % pkt_len)

        # Read the remaining payload (+padding) — we already read the pad_len byte
        remaining = pkt_len - 1
        payload = _recv_exact(sock, remaining)

        kexinit = _parse_kexinit(payload)
        return banner, kexinit

    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Fingerprinting logic
# ---------------------------------------------------------------------------

def fingerprint_diego_ssh(hostname, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    """Fingerprint a Diego-SSH proxy and return a result dict.

    The returned dict is designed to merge cleanly into the existing
    ``ssh_info`` dict produced by ``CFSSHScanner.check_ssh()`` in
    SAPology_btp.py.

    Returns
    -------
    dict with keys:
        hostname          : str
        port              : int
        open              : bool   - TCP port reachable
        banner            : str    - raw SSH banner
        is_diego          : bool   - banner contains "diego-ssh-proxy"
        kexinit           : dict   - parsed KEXINIT algorithm lists
        has_kex_strict    : bool   - Terrapin mitigation present
        has_chacha20      : bool   - chacha20-poly1305 offered
        epoch             : int    - matched epoch number (1-4) or 0
        version_range     : str    - human-readable diego-release range
        version_info      : str    - epoch description
        error             : str    - error message if fingerprinting failed
    """
    result = {
        "hostname": hostname,
        "port": port,
        "open": False,
        "banner": None,
        "is_diego": False,
        "kexinit": {},
        "has_kex_strict": False,
        "has_chacha20": False,
        "epoch": 0,
        "version_range": "unknown",
        "version_info": None,
        "error": None,
    }

    try:
        banner, kexinit = _grab_kexinit(hostname, port, timeout)
    except (socket.timeout, ConnectionRefusedError, OSError, ValueError, ConnectionError) as exc:
        result["error"] = str(exc)
        if isinstance(exc, (socket.timeout, ConnectionRefusedError)):
            result["error"] = "Port %d closed or filtered" % port
        else:
            result["open"] = True  # got far enough to know it's open
        return result

    result["open"] = True
    result["banner"] = banner
    result["is_diego"] = DIEGO_BANNER in banner.lower()
    result["kexinit"] = kexinit

    if not result["is_diego"]:
        result["version_info"] = "Not a Diego-SSH proxy"
        return result

    # --- Determine epoch from algorithm fingerprint ---

    kex_algos = kexinit.get("kex_algorithms", [])
    ciphers_c2s = kexinit.get("encryption_client_to_server", [])
    ciphers_s2c = kexinit.get("encryption_server_to_client", [])
    ciphers = set(ciphers_c2s) | set(ciphers_s2c)

    result["has_kex_strict"] = "kex-strict-s-v00@openssh.com" in kex_algos
    result["has_chacha20"] = "chacha20-poly1305@openssh.com" in ciphers

    for epoch_def in DIEGO_EPOCHS:
        match = epoch_def["match"]
        if (
            result["has_kex_strict"] == match["has_kex_strict"]
            and result["has_chacha20"] == match["has_chacha20"]
        ):
            result["epoch"] = epoch_def["epoch"]
            result["version_range"] = epoch_def["version_range"]
            result["version_info"] = epoch_def["description"]
            break

    return result


# ---------------------------------------------------------------------------
# Batch scanning
# ---------------------------------------------------------------------------

def scan_batch(targets, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT, threads=20):
    """Scan a list of (hostname,) or (hostname, port) targets concurrently."""
    results = []
    with ThreadPoolExecutor(max_workers=min(len(targets), threads)) as pool:
        futures = {}
        for t in targets:
            if isinstance(t, str):
                h, p = t.strip(), port
            else:
                h = t[0].strip()
                p = int(t[1]) if len(t) > 1 else port
            if not h or h.startswith("#"):
                continue
            futures[pool.submit(fingerprint_diego_ssh, h, p, timeout)] = (h, p)

        for future in as_completed(futures):
            results.append(future.result())

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_result(r, verbose=False):
    """Pretty-print a single fingerprint result."""
    status = "OPEN" if r["open"] else "CLOSED"
    diego = "Diego-SSH" if r["is_diego"] else "Not Diego"
    header = "%s:%d  [%s] [%s]" % (r["hostname"], r["port"], status, diego)

    if r["error"]:
        print("%s  ERROR: %s" % (header, r["error"]))
        return

    if not r["is_diego"]:
        print("%s  Banner: %s" % (header, r["banner"]))
        return

    print(header)
    print("  Banner       : %s" % r["banner"])
    print("  Version range: %s" % r["version_range"])
    print("  Epoch        : %d — %s" % (r["epoch"], r["version_info"]))
    print("  Kex-strict   : %s" % r["has_kex_strict"])
    print("  ChaCha20     : %s" % r["has_chacha20"])

    if verbose:
        kex = r["kexinit"]
        print("  KEX algos    : %s" % ", ".join(kex.get("kex_algorithms", [])))
        print("  Host key     : %s" % ", ".join(kex.get("server_host_key_algorithms", [])))
        print("  Ciphers C→S  : %s" % ", ".join(kex.get("encryption_client_to_server", [])))
        print("  MACs C→S     : %s" % ", ".join(kex.get("mac_client_to_server", [])))
        print("  Compression  : %s" % ", ".join(kex.get("compression_client_to_server", [])))


def main():
    parser = argparse.ArgumentParser(
        description="Fingerprint Cloud Foundry Diego-SSH proxy version via KEXINIT analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s approuter.example.com
  %(prog)s approuter.example.com 2222
  %(prog)s --batch hosts.txt --json
  %(prog)s --batch hosts.txt -v
        """,
    )
    parser.add_argument("hostname", nargs="?", help="Target hostname")
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT,
                        help="Target port (default: %d)" % DEFAULT_PORT)
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="Connection timeout in seconds (default: %d)" % DEFAULT_TIMEOUT)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show full algorithm lists")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--batch", metavar="FILE",
                        help="File with one hostname[:port] per line")
    parser.add_argument("--threads", type=int, default=20,
                        help="Concurrent threads for batch mode (default: 20)")

    args = parser.parse_args()

    if not args.hostname and not args.batch:
        parser.print_help()
        sys.exit(1)

    # --- Batch mode ---
    if args.batch:
        targets = []
        with open(args.batch) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                targets.append(parts)

        results = scan_batch(targets, args.port, args.timeout, args.threads)

        if args.json:
            print(json.dumps(results, indent=2, default=str))
        else:
            for r in sorted(results, key=lambda x: x["hostname"]):
                _print_result(r, args.verbose)
                print()
        sys.exit(0)

    # --- Single target ---
    result = fingerprint_diego_ssh(args.hostname, args.port, args.timeout)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_result(result, args.verbose)


if __name__ == "__main__":
    main()

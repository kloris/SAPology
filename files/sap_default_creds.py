#!/usr/bin/env python3
"""
SAP Default Credential Check via DIAG Protocol

Tests well-known SAP default user/password combinations against discovered
systems by sending DIAG login attempts to the SAP Dispatcher port (32XX).

WARNING: Failed login attempts can lock SAP accounts. This check is opt-in only.

Uses the proven DIAG packet construction from sap_client_enum.py (no code
duplication — imports build_diag_init, build_diag_login_packet, ni_send, ni_recv).

Usage:
    python3 sap_default_creds.py -t <host>:<port> -c 000,001,066
    python3 sap_default_creds.py -t <host>:<port> -c 000,001 -v

Author: Joris van de Vis
"""

import socket
import re
import sys
import time
import argparse

try:
    from sap_client_enum import (build_diag_init, build_diag_login_packet,
                                  ni_send, ni_recv)
except ImportError:
    from files.sap_client_enum import (build_diag_init, build_diag_login_packet,
                                        ni_send, ni_recv)


# ============================================================================
# Default Credentials Table
# ============================================================================

# Each entry: (severity, username, password, clients)
# clients: "ALL" = test on all enumerated clients, or specific client string
DEFAULT_CREDENTIALS = [
    ("CRITICAL", "SAP*",         "06071992",  "ALL"),
    ("CRITICAL", "SAP*",         "PASS",      "ALL"),
    ("CRITICAL", "DDIC",         "19920706",  "ALL"),
    ("CRITICAL", "IDEADM",       "admin",     "ALL"),
    ("HIGH",     "EARLYWATCH",   "SUPPORT",   "066"),
    ("MEDIUM",   "TMSADM",       "PASSWORD",  "ALL"),
    ("MEDIUM",   "TMSADM",       "$1Pawd2&",  "ALL"),
    ("MEDIUM",   "SAPCPIC",      "ADMIN",     "ALL"),
    ("HIGH",     "SMD_ADMIN",    "init1234",  "ALL"),
    ("HIGH",     "SMD_BI_RFC",   "init1234",  "ALL"),
    ("HIGH",     "SMD_RFC",      "init1234",  "ALL"),
    ("HIGH",     "SOLMAN_ADMIN", "init1234",  "ALL"),
    ("HIGH",     "SOLMAN_BTC",   "init1234",  "ALL"),
    ("HIGH",     "SAPSUPPORT",   "init1234",  "ALL"),
    ("MEDIUM",   "CONTENTSERV",  "init1234",  "ALL"),
    ("MEDIUM",   "SMD_AGT",      "init1234",  "ALL"),
]


# ============================================================================
# Login Response Classification
# ============================================================================

# Result codes
SUCCESS = "SUCCESS"
PASSWORD_CHANGE = "PASSWORD_CHANGE"
NO_AUTH_LOGON = "NO_AUTH_LOGON"
WRONG_PASSWORD = "WRONG_PASSWORD"
USER_LOCKED = "USER_LOCKED"
USER_NOT_EXIST = "USER_NOT_EXIST"
CLIENT_UNAVAIL = "CLIENT_UNAVAIL"
ERROR = "ERROR"

# Patterns matched against raw DIAG response bytes
_PATTERNS = [
    (re.compile(rb'Enter a new password', re.IGNORECASE),            PASSWORD_CHANGE),
    (re.compile(rb'No authorization to logon', re.IGNORECASE),       NO_AUTH_LOGON),
    (re.compile(rb'Name or password is incorrect', re.IGNORECASE),   WRONG_PASSWORD),
    (re.compile(rb'User .{1,40} is locked', re.IGNORECASE),         USER_LOCKED),
    (re.compile(rb'User .{1,40} does not exist', re.IGNORECASE),    USER_NOT_EXIST),
    (re.compile(rb'Client \d{3} is not available', re.IGNORECASE),  CLIENT_UNAVAIL),
    (re.compile(rb'Client does not exist', re.IGNORECASE),          CLIENT_UNAVAIL),
]

# Results that mean the password was correct (= finding)
FINDING_RESULTS = {SUCCESS, PASSWORD_CHANGE, NO_AUTH_LOGON}

RESULT_DESCRIPTIONS = {
    SUCCESS:         "Successful login",
    PASSWORD_CHANGE: "Password correct but expired (change required)",
    NO_AUTH_LOGON:   "Password correct but no dialog authorization",
    WRONG_PASSWORD:  "Wrong password",
    USER_LOCKED:     "User is locked",
    USER_NOT_EXIST:  "User does not exist",
    CLIENT_UNAVAIL:  "Client not available",
    ERROR:           "Connection error",
}


def classify_login_response(resp_bytes):
    """Classify a DIAG login response into a result code.

    Returns (result_code, detail_string).
    """
    if not resp_bytes:
        return (ERROR, "Empty response")

    for pattern, result in _PATTERNS:
        if pattern.search(resp_bytes):
            return (result, RESULT_DESCRIPTIONS[result])

    # No error pattern matched and response is substantial → likely success
    if len(resp_bytes) > 200:
        return (SUCCESS, RESULT_DESCRIPTIONS[SUCCESS])

    return (ERROR, "Inconclusive response (%d bytes)" % len(resp_bytes))


# ============================================================================
# Single Login Attempt
# ============================================================================

def try_login(host, port, client, user, password, timeout=5):
    """Attempt a single DIAG login. One TCP connection per attempt.

    Returns (result_code, detail_string).
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # DIAG init handshake
        ni_send(sock, build_diag_init())
        resp = ni_recv(sock, timeout)
        if not resp or len(resp) < 100:
            return (ERROR, "DIAG init failed")

        # Send login packet
        client_str = client if isinstance(client, str) else "%03d" % client
        login_pkt = build_diag_login_packet(client_str, user, password)
        ni_send(sock, login_pkt)

        # Receive and classify response
        resp2 = ni_recv(sock, timeout + 2)
        return classify_login_response(resp2)

    except ConnectionRefusedError:
        return (ERROR, "Connection refused")
    except socket.timeout:
        return (ERROR, "Connection timeout")
    except OSError as e:
        return (ERROR, str(e))
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ============================================================================
# Full Default Credential Check
# ============================================================================

def check_default_credentials(host, port, clients, timeout=5, verbose=False,
                               cancel_check=None):
    """Check all default credentials against the given host/port/clients.

    Iterates credentials sequentially (no threading — avoids flooding/lockout).

    Args:
        host: target IP or hostname
        port: SAP Dispatcher port (e.g. 3200)
        clients: list of client strings (e.g. ["000", "001", "066"])
        timeout: per-connection timeout
        verbose: print progress for misses
        cancel_check: callable returning True to abort

    Returns:
        list of dicts: [{"username", "password", "client", "result", "severity", "detail"}]
        Only entries where the password was correct (SUCCESS, PASSWORD_CHANGE, NO_AUTH_LOGON).
    """
    findings = []
    locked_users = set()

    for severity, user, password, target_clients in DEFAULT_CREDENTIALS:
        if cancel_check and cancel_check():
            break

        # Skip if user is already locked
        if user in locked_users:
            if verbose:
                print("  [-] Skipping %s (already locked)" % user)
            continue

        # Determine which clients to test
        if target_clients == "ALL":
            test_clients = clients
        else:
            # Specific client (e.g. "066") — only test if enumerated
            if target_clients in clients:
                test_clients = [target_clients]
            else:
                continue

        for client in test_clients:
            if cancel_check and cancel_check():
                break

            # Stop probing this user if locked
            if user in locked_users:
                break

            result, detail = try_login(host, port, client, user, password, timeout)

            if result == USER_LOCKED:
                locked_users.add(user)
                if verbose:
                    print("  [!] %s is locked on client %s — skipping further attempts" %
                          (user, client))
                break

            if result in FINDING_RESULTS:
                print("  [+] DEFAULT CREDENTIAL: %s / %s on client %s (%s)" %
                      (user, password, client, detail))
                findings.append({
                    "username": user,
                    "password": password,
                    "client": client,
                    "result": result,
                    "severity": severity,
                    "detail": detail,
                })
            elif verbose:
                print("  [-] %s / %s on client %s: %s" %
                      (user, password, client, detail))

    return findings


# ============================================================================
# Standalone CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SAP Default Credential Check via DIAG Protocol",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
WARNING: Failed login attempts can lock SAP accounts!
         Only use this tool with explicit authorization.

Examples:
  %(prog)s -t 192.168.1.100:3200 -c 000,001,066
  %(prog)s -t 192.168.1.100 -p 3200 -c 000 -v
        """)
    parser.add_argument("-t", "--target", required=True,
                        help="Target host or host:port")
    parser.add_argument("-p", "--port", type=int, default=None,
                        help="SAP Dispatcher port (default: from target)")
    parser.add_argument("-c", "--clients", required=True,
                        help="Comma-separated client numbers (e.g. 000,001,066)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Per-connection timeout in seconds (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output (show all attempts)")

    args = parser.parse_args()

    # Parse target
    target = args.target
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        port = args.port or int(port_str)
    else:
        host = target
        port = args.port or 3200

    # Parse clients
    clients = [c.strip().zfill(3) for c in args.clients.split(",")]

    print("=" * 60)
    print("SAP Default Credential Check via DIAG Protocol")
    print("=" * 60)
    print("Target:  %s:%d" % (host, port))
    print("Clients: %s" % ", ".join(clients))
    print()
    print("WARNING: Failed login attempts can lock SAP accounts!")
    print()

    t0 = time.time()
    results = check_default_credentials(host, port, clients,
                                         timeout=args.timeout,
                                         verbose=args.verbose)
    elapsed = time.time() - t0

    print()
    print("-" * 60)
    if results:
        print("Found %d default credential(s):" % len(results))
        for r in results:
            print("  [%s] %s / %s on client %s (%s)" %
                  (r["severity"], r["username"], r["password"],
                   r["client"], r["detail"]))
    else:
        print("No default credentials found.")
    print("Time: %.1fs" % elapsed)
    print("-" * 60)

    return 0 if not results else 2


if __name__ == "__main__":
    sys.exit(main())

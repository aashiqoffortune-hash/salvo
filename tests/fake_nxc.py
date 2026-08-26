#!/usr/bin/env python3
"""
A stand-in for nxc, so the end-to-end path can be tested without a network or
a NetExec install.

It emits real nxc line shapes for a fixed cast of hosts and exits 0. Pointed at
with `salvo --nxc-bin tests/fake_nxc.py`.

Behaviour by protocol, chosen to exercise every verdict bucket:
    smb    10.0.0.10 -> Pwn3d!   (ADMIN)      10.0.0.11 -> LOGON_TYPE_NOT_GRANTED (VALID*)
    winrm  both      -> bare [-] (UNKNOWN, the WinRM trap)
    ldap   10.0.0.10 -> plain [+] (ok)
    others            -> nothing at all, like a closed port

Environment switches, each reproducing a failure mode that is awkward to
arrange on a live range:

    FAKE_NXC_FAIL=1      exit non-zero with a usage error, the way nxc does
                         when salvo builds a command a protocol rejects
    FAKE_NXC_LOCKOUT=1   answer STATUS_ACCOUNT_LOCKED_OUT on the first host
    FAKE_NXC_BINARY=1    emit an invalid UTF-8 byte in a hostname
    FAKE_NXC_HANG=1      sleep, so kill paths can be exercised
    FAKE_NXC_DRIFT=1     drop --local-auth from smb\'s help, so --check-nxc
                         can be shown to still catch a real disagreement

`<proto> --help` reproduces what a real NetExec 1.x reports, transcribed from
an actual `nxc <proto> --help` on Kali. That makes --check-nxc testable without
NetExec installed, and pins salvo\'s capability tables to observed reality
rather than to salvo\'s own beliefs about it.
"""

import os
import sys

HOSTS = [("10.0.0.10", "DC01", 1), ("10.0.0.11", "WEB01", 2)]

# (accepts -d, accepts --local-auth, accepts -H, own timeout flag)
CAPABILITIES = {
    "smb":   (True,  True,  True,  "--smb-timeout"),
    "winrm": (True,  True,  True,  "--http-timeout"),
    "wmi":   (True,  True,  True,  "--rpc-timeout"),
    "mssql": (True,  True,  True,  "--mssql-timeout"),
    # the trap: ldap takes -d but not --local-auth, a bind is domain-scoped
    "ldap":  (True,  False, True,  None),
    "rdp":   (True,  True,  True,  "--rdp-timeout"),
    "ssh":   (False, False, False, "--ssh-timeout"),
    "ftp":   (False, False, False, None),
    "nfs":   (False, False, False, "--nfs-timeout"),
    "vnc":   (False, False, False, None),
}

PORTS = {"smb": 445, "winrm": 5985, "wmi": 135, "mssql": 1433,
         "ldap": 389, "rdp": 3389, "ssh": 22, "ftp": 21, "nfs": 111, "vnc": 5900}

# flags that consume the following token, so it is not mistaken for the protocol
VALUE_FLAGS = {"-t", "-u", "-p", "-H", "-d", "--jitter"}


def parse():
    argv = sys.argv[1:]
    proto, targets, user = None, [], "user"
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "-u" and i + 1 < len(argv):
            user = argv[i + 1]
        if tok.startswith("-"):
            i += 2 if (tok in VALUE_FLAGS or tok.endswith("-timeout")) else 1
            continue
        if proto is None:
            proto = tok
        else:
            targets.append(tok)
        i += 1
    return proto, targets, user


def emit_help(proto):
    """What `nxc <proto> --help` really prints, in the parts salvo reads."""
    takes_domain, takes_local, takes_hash, timeout_flag = CAPABILITIES[proto]
    if os.environ.get("FAKE_NXC_DRIFT") and proto == "smb":
        takes_local = False          # a real disagreement, to prove it is caught

    print("usage: nxc {} [-h] ...".format(proto))
    print("\noptions:")
    print("  -h, --help            show this help message and exit")
    print("  -t THREADS            number of concurrent threads")
    print("  --jitter INTERVAL     sleep between requests")
    print("  --no-progress         do not displaying progress bars")
    # Generic, printed under EVERY protocol. salvo must not mistake it for a
    # per-protocol flag it is failing to send.
    print("  --dns-timeout DNS_TIMEOUT   DNS query timeout in seconds")
    print("\nauthentication:")
    print("  -u USERNAME           username(s) or file containing usernames")
    print("  -p PASSWORD           password(s) or file containing passwords")
    if takes_domain:
        print("  -d DOMAIN, --domain DOMAIN   domain to authenticate to")
    if takes_hash:
        print("  -H HASH, --hash HASH  NTLM hash(es) or file containing hashes")
    if takes_local:
        print("  --local-auth          authenticate locally to each target")
    print("  --continue-on-success  continue authentication after a success")
    if timeout_flag:
        print("  {} SECONDS   {} connection timeout".format(timeout_flag, proto))
    return 0


def main():
    if "--version" in sys.argv[1:]:
        print("nxc 1.5.0-fake")
        return 0

    if os.environ.get("FAKE_NXC_HANG"):
        import time
        time.sleep(300)
        return 0

    if os.environ.get("FAKE_NXC_FAIL"):
        sys.stderr.write("usage: nxc [-h] ...\nnxc: error: unrecognized arguments: -d\n")
        return 2

    proto, _targets, user = parse()
    if proto is None:
        return 2

    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        if proto not in CAPABILITIES:
            return 2
        return emit_help(proto)
    port = PORTS.get(proto, 445)
    tag = proto.upper()

    if os.environ.get("FAKE_NXC_BINARY"):
        # a hostname that is not valid UTF-8. Reading this must not take the
        # job down with a decode error.
        sys.stdout.flush()
        sys.stdout.buffer.write(
            "{:<11} {:<15} {:<6} ".format(tag, "10.0.0.10", port).encode()
            + b"WEB\xff01           "
            + "[+] corp.local\\{}:Password123! (Pwn3d!)\n".format(user).encode())
        sys.stdout.buffer.flush()
        return 0

    for ip, name, _n in HOSTS:
        if os.environ.get("FAKE_NXC_LOCKOUT") and ip == "10.0.0.10":
            print("{:<11} {:<15} {:<6} {:<16} [-] corp.local\\{}:Password123! "
                  "STATUS_ACCOUNT_LOCKED_OUT".format(tag, ip, port, name, user))
            continue

        print("{:<11} {:<15} {:<6} {:<16} [*] Windows 10.0 Build 19044 x64 "
              "(name:{}) (domain:corp.local) (signing:False) (SMBv1:False)"
              .format(tag, ip, port, name, name))

        if proto == "smb":
            if ip == "10.0.0.10":
                print("{:<11} {:<15} {:<6} {:<16} [+] corp.local\\{}:Password123! (Pwn3d!)"
                      .format(tag, ip, port, name, user))
            else:
                print("{:<11} {:<15} {:<6} {:<16} [-] corp.local\\{}:Password123! "
                      "STATUS_LOGON_TYPE_NOT_GRANTED".format(tag, ip, port, name, user))
        elif proto == "winrm":
            print("{:<11} {:<15} {:<6} {:<16} [-] corp.local\\{}:Password123!"
                  .format(tag, ip, port, name, user))
        elif proto == "ldap" and ip == "10.0.0.10":
            print("{:<11} {:<15} {:<6} {:<16} [+] corp.local\\{}:Password123!"
                  .format(tag, ip, port, name, user))
    return 0


if __name__ == "__main__":
    sys.exit(main())

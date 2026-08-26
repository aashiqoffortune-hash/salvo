#!/usr/bin/env python3
"""
salvo.py - fire every protocol at once and fill the credential reuse matrix.

A salvo is every weapon discharged simultaneously. nxc takes ONE protocol per
invocation; this runs all of them at once, for every credential you hold,
against every host you know, and prints the result as a matrix instead of ten
separate scrollbacks.

DESIGN RULE - AUTHENTICATION ONLY.
This tool never passes -x, -X, -M, --sam, --lsa, --ntds or any execution or
dumping flag to nxc. It logs in and reports. Nothing else. That keeps it
unambiguously inside restricted-tooling rules: it is a scheduler for a
tool you are already allowed to run manually.

THE THING IT DOES THAT YOU DO NOT DO BY HAND:
it has three result buckets, not two. VALID / INVALID / INCONCLUSIVE.
A WinRM refusal, an ACCESS_DENIED, a LOGON_TYPE_NOT_GRANTED - none of those
mean the password is wrong. Collapsing them into "failed" is how a live
credential gets thrown away at hour twelve.

Stdlib only - no pip, no virtualenv, no dependencies beyond nxc itself.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

__version__ = "1.0.0"

STATE_VERSION = 1

# ---------------------------------------------------------------------------
# Determinism helpers
#
# Two identical invocations must produce byte-identical output. Results arrive
# in thread-completion order, which is not stable, so nothing is ever printed
# or serialised in arrival order - everything sorts through these.
# ---------------------------------------------------------------------------


def ip_sort_key(addr):
    """Numeric sort for IPv4, lexical fallback for hostnames and IPv6."""
    try:
        parts = [int(x) for x in addr.split(".")]
        if len(parts) == 4 and all(0 <= p <= 255 for p in parts):
            return (0, tuple(parts), "")
    except (ValueError, AttributeError):
        pass
    return (1, (), str(addr))


# Everything salvo writes to disk carries the plaintext credential: the state
# file and the --json report serialise `secret` directly, and an nxc log line
# echoes the password back on every attempt. Default file creation is 0644,
# which puts those on a shared box for any local account to read. Owner-only
# is the only defensible mode for any of them.
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700


def now_iso():
    """
    Timezone-aware local time. A naive timestamp in a report that will be read
    by someone in another office is an ambiguity nobody can resolve later.
    """
    return datetime.now().astimezone().isoformat(timespec="seconds")


def ensure_writable(path, what):
    """
    Fail before the first logon rather than after the last one. Finding out
    that the report directory does not exist at the end of a two-hour run
    loses the run, and the logons are not refundable.
    """
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        sys.exit("[!] {} directory does not exist: {}".format(what, directory))
    if not os.access(directory, os.W_OK):
        sys.exit("[!] {} directory is not writable: {}".format(what, directory))
    if os.path.exists(path) and not os.access(path, os.W_OK):
        sys.exit("[!] {} is not writable: {}".format(what, path))


def open_private(path):
    """open(path, 'w') that never widens past owner read/write."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_FILE_MODE)
    try:
        os.fchmod(fd, PRIVATE_FILE_MODE)   # a pre-existing file keeps its old mode otherwise
    except OSError:
        pass
    return os.fdopen(fd, "w")


def write_json_atomic(path, obj):
    """
    Write via a temp file and rename. An interrupted write leaves the previous
    file intact rather than a half-parsed one - which matters when the thing
    being written is the state file you are about to resume from.

    The temp file is created owner-only, so the credentials inside it are
    never briefly world-readable between create and rename.
    """
    tmp = path + ".tmp"
    with open_private(tmp) as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)

# ---------------------------------------------------------------------------
# Protocol tables
# ---------------------------------------------------------------------------

# every protocol nxc 1.5.x exposes
ALL_PROTOCOLS = ["smb", "winrm", "wmi", "mssql", "ldap", "rdp", "ssh", "ftp", "nfs", "vnc"]

# default spray set for a password - the ones that take user+pass and matter in AD
DEFAULT_PW_PROTOCOLS = ["smb", "winrm", "wmi", "mssql", "ldap", "rdp", "ssh", "ftp"]

# protocols that accept -H (pass-the-hash). ssh/ftp/nfs/vnc cannot PTH.
HASH_CAPABLE = {"smb", "winrm", "wmi", "mssql", "ldap", "rdp"}

# Protocols whose nxc sub-parser actually defines -d/--domain.
# ssh, ftp, nfs and vnc have NO domain concept and NO -d argument. Passing it
# makes argparse exit with a usage error before a single packet is sent, the
# job produces nothing parseable, and the cell renders as '-' - which reads as
# "port closed" when the truth is "salvo built a broken command".
# Verified against nxc/protocols/<proto>/proto_args.py upstream.
DOMAIN_CAPABLE = {"smb", "winrm", "wmi", "mssql", "ldap", "rdp"}

# Protocols whose nxc sub-parser defines --local-auth.
# LDAP is the trap: it takes -d but NOT --local-auth, because a directory bind
# is inherently domain-scoped. It was in this set and it should not have been.
LOCAL_AUTH_CAPABLE = {"smb", "winrm", "wmi", "mssql", "rdp"}

# nxc's global --timeout is DEPRECATED and does nothing. Its own help text says
# so: "no longer used, replaced by per-protocol timeouts". Every protocol now
# carries its own flag, with defaults that are brutally short over a tunnel:
#   smb 2s | wmi(rpc) 2s | ldap 3s | mssql 5s | rdp 5s | nfs 5s | winrm 10s | ssh 15s
# ftp and vnc expose no timeout flag at all.
TIMEOUT_FLAG = {
    "smb":   "--smb-timeout",
    "winrm": "--http-timeout",
    "wmi":   "--rpc-timeout",
    "mssql": "--mssql-timeout",
    "rdp":   "--rdp-timeout",
    "ssh":   "--ssh-timeout",
    "nfs":   "--nfs-timeout",
    # ldap, ftp and vnc have NO entry here, so --nxc-timeout does not reach
    # them and they run at nxc's own default. This table is a snapshot of
    # upstream and upstream moves: `salvo --check-nxc` reads the installed
    # nxc's help and reports a per-protocol timeout flag that exists there but
    # is missing here, so the gap shows up as a check failure rather than as a
    # silently unapplied timeout over a tunnel.
}

# default nxc port per protocol, used only for the follow-up command hints
DEFAULT_PORT = {
    "smb": 445,
    "winrm": 5985,
    "wmi": 135,
    "mssql": 1433,
    "ldap": 389,
    "rdp": 3389,
    "ssh": 22,
    "ftp": 21,
    "nfs": 111,
    "vnc": 5900,
}

# ---------------------------------------------------------------------------
# Authentication-only enforcement
#
# salvo's entire claim - that it is a scheduler for logins and nothing else -
# rests on what it is willing to put on an nxc command line. A claim in a
# README is documentation; this is enforcement. Every command is checked
# against these sets immediately before it spawns, so an edit or a merged
# patch that reaches for an execution flag aborts the run loudly instead of
# quietly turning salvo into a different class of tool. See EXAM.md.
# ---------------------------------------------------------------------------

# flags salvo may emit, and which of them consume the following token.
# TIMEOUT_FLAG is folded in rather than restated, so a protocol added to that
# table cannot be permitted here by accident or forbidden here by omission.
ALLOWED_VALUE_FLAGS = (frozenset(["-t", "--jitter", "-u", "-p", "-H", "-d"])
                       | frozenset(TIMEOUT_FLAG.values()))
ALLOWED_BARE_FLAGS = frozenset([
    "--no-progress", "--local-auth", "--continue-on-success",
    "-q",   # proxychains' own quiet flag, when wrapping
])

# Named so the refusal can say what it refused rather than only that it did.
# Not a filter - the allowlist above is what actually decides - but the list a
# reader wants to see, and the list the test suite asserts against.
NEVER_SENT = frozenset([
    "-x", "-X", "-M", "--module",                      # command execution
    "--sam", "--lsa", "--ntds", "--dpapi", "--laps",   # credential dumping
    "--shares", "--users", "--groups", "--rid-brute",  # enumeration beyond auth
    "--pass-pol", "--kerberoasting", "--asreproast", "--bloodhound",
    "--put-file", "--get-file", "--exec-method",
])


class ScopeViolation(Exception):
    """salvo built a command outside its authentication-only remit."""


def assert_authentication_only(cmd):
    """
    Refuse to run a command carrying any flag outside the allowlist.

    Checked immediately before every spawn. The allowlist is exhaustive on
    purpose: an unrecognised flag is refused rather than permitted, so the
    failure mode of a future edit is a loud abort, not a silent change in what
    the tool does on someone else's estate.
    """
    i = 0
    while i < len(cmd):
        token = cmd[i]
        if token in ALLOWED_VALUE_FLAGS:
            i += 2          # the flag and its value
            continue
        if token in ALLOWED_BARE_FLAGS or not token.startswith("-"):
            i += 1
            continue
        raise ScopeViolation(
            "{!r} is not an authentication flag. salvo logs in and reports; "
            "it does not execute, dump, or collect.".format(token))
    return cmd


# ---------------------------------------------------------------------------
# Result statuses
# ---------------------------------------------------------------------------

ADMIN = "ADMIN"                # authenticated AND provably administrative
EXEC = "EXEC"                  # command execution, but privilege NOT established
VALID = "VALID"                # authenticated, no execution
CRED_OK_ACCESS_NO = "BLOCKED"  # password is CORRECT, this access path is closed
INCONCLUSIVE = "UNKNOWN"       # cannot tell - treat as still-live, retest elsewhere
INVALID = "INVALID"            # confirmed wrong credential
LOCKED = "LOCKED"              # account lockout - stop everything
NO_SERVICE = "NOSVC"           # port closed / no such service on that host
ERROR = "ERROR"                # nxc itself failed
USAGE = "USAGE"                # salvo built a command nxc rejected - OUR bug, not the target's
NOT_RUN = "NOTRUN"             # salvo declined to run this job at all - no packet was sent

# What nxc's "Pwn3d!" actually proves, per protocol. This is not cosmetic:
#   smb    - Pwn3d means write access to ADMIN$/C$. That IS local admin.
#   mssql  - Pwn3d means the sysadmin role on the instance.
#   winrm  - Pwn3d only means the account can execute. Membership in
#            Remote Management Users grants that on its own, with no admin
#            rights whatsoever. Reading this as admin is a real trap.
#   ssh    - nxc probes for uid 0 or passwordless sudo. Against Windows
#            OpenSSH those probes return nonsense. Treat as execution only.
#   others - execution at best.
PWN_MEANING = {
    "smb":   (ADMIN, "write access to admin shares - this is local admin"),
    "mssql": (ADMIN, "sysadmin role on the SQL instance"),
    "winrm": (EXEC,  "can execute - Remote Management Users grants this WITHOUT admin"),
    "wmi":   (EXEC,  "can execute - privilege not established"),
    "rdp":   (EXEC,  "interactive logon allowed - privilege not established"),
    "ssh":   (EXEC,  "shell access - nxc's root check is unreliable, especially on Windows"),
    "ftp":   (EXEC,  "write access to the FTP root"),
    "vnc":   (EXEC,  "session access - privilege not established"),
    "nfs":   (EXEC,  "write access to an export"),
    "ldap":  (EXEC,  "privileged bind - privilege not established"),
}

# how each status renders in the matrix
GLYPH = {
    ADMIN: "ADMIN",
    EXEC: "exec",
    VALID: "ok",
    CRED_OK_ACCESS_NO: "VALID*",
    INCONCLUSIVE: "?",
    INVALID: ".",
    LOCKED: "LOCK!",
    NO_SERVICE: "-",
    ERROR: "err",
    USAGE: "!CMD",
    NOT_RUN: "n/a",
}

# ordering for "which status wins" when one host+protocol produces several lines
SEVERITY = {
    ADMIN: 100,
    EXEC: 95,
    VALID: 90,
    CRED_OK_ACCESS_NO: 80,
    LOCKED: 75,
    INCONCLUSIVE: 50,
    USAGE: 30,
    ERROR: 20,
    INVALID: 10,
    NO_SERVICE: 0,
    NOT_RUN: -1,   # never competes: it is an absence, not a result
}

# ---------------------------------------------------------------------------
# NT status string -> meaning.
# The middle group is the whole point of this tool: the credential is CORRECT.
# ---------------------------------------------------------------------------

STATUS_MAP = [
    # (substring to look for, bucket, human explanation)
    ("STATUS_ACCOUNT_LOCKED_OUT",      LOCKED,              "account is LOCKED OUT - stop spraying now"),
    ("KDC_ERR_CLIENT_REVOKED",         LOCKED,              "kerberos: account locked or disabled"),

    ("STATUS_LOGON_TYPE_NOT_GRANTED",  CRED_OK_ACCESS_NO,   "password correct, account denied this logon type"),
    ("STATUS_ACCOUNT_DISABLED",        CRED_OK_ACCESS_NO,   "password correct, account disabled"),
    ("STATUS_ACCOUNT_EXPIRED",         CRED_OK_ACCESS_NO,   "password correct, account expired"),
    ("STATUS_PASSWORD_EXPIRED",        CRED_OK_ACCESS_NO,   "password correct but expired - can often still be changed"),
    ("STATUS_PASSWORD_MUST_CHANGE",    CRED_OK_ACCESS_NO,   "password correct, must be changed at next logon"),
    ("STATUS_ACCOUNT_RESTRICTION",     CRED_OK_ACCESS_NO,   "password correct, workstation/time restriction"),
    ("STATUS_INVALID_LOGON_HOURS",     CRED_OK_ACCESS_NO,   "password correct, outside permitted logon hours"),
    ("STATUS_INVALID_WORKSTATION",     CRED_OK_ACCESS_NO,   "password correct, not allowed from this host"),
    ("STATUS_NOT_SUPPORTED",           CRED_OK_ACCESS_NO,   "auth mechanism refused, not a credential failure"),

    ("STATUS_ACCESS_DENIED",           INCONCLUSIVE,        "authenticated then authorization denied - cred may be live"),
    ("STATUS_TRUSTED_RELATIONSHIP",    INCONCLUSIVE,        "machine trust issue, not a credential verdict"),
    ("STATUS_NO_LOGON_SERVERS",        INCONCLUSIVE,        "no DC reachable - retest, not a credential verdict"),
    ("STATUS_NETWORK_SESSION_EXPIRED", INCONCLUSIVE,        "session expired mid-auth - retest"),
    ("STATUS_IO_TIMEOUT",              NO_SERVICE,          "timed out"),
    ("STATUS_CONNECTION_RESET",        NO_SERVICE,          "connection reset"),

    ("STATUS_LOGON_FAILURE",           INVALID,             "wrong username or password"),
    ("KDC_ERR_PREAUTH_FAILED",         INVALID,             "kerberos pre-auth failed - wrong password"),
    ("KDC_ERR_C_PRINCIPAL_UNKNOWN",    INVALID,             "no such principal in this domain"),
    ("STATUS_NO_SUCH_USER",            INVALID,             "no such user"),
]

# protocols where a bare "[-]" with no NT status code is genuinely ambiguous.
# WinRM is the big one: a valid account not in Remote Management Users looks
# identical to a wrong password.
AMBIGUOUS_BARE_FAILURE = {"winrm", "rdp", "wmi", "ldap", "mssql"}

# nxc's "first-last-octet" range form, e.g. 10.0.0.20-40
OCTET_RANGE_RE = re.compile(r"^(?P<head>\d{1,3}(?:\.\d{1,3}){2})\.(?P<first>\d{1,3})-(?P<last>\d{1,3})$")


def is_literal_ip(text):
    """
    True only for an address that really parses. The old regex accepted
    '192.168.1.999', which then got a matrix row of its own.
    """
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def count_hosts(targets):
    """
    How many addresses this target spec actually covers.

    The lockout warning is only worth printing if the number in it is real.
    Saying "N per host, and the host count is unknown" for a /24 leaves the
    operator to do the multiplication that the whole warning exists to do.

    CIDR is counted at full size, network and broadcast included: for a
    warning about spending an account's lockout budget, over-counting is the
    safe direction. A hostname counts as one host. Returns None only when a
    target file cannot be read.
    """
    total = 0
    for t in targets:
        n = _count_one(t)
        if n is None:
            return None
        total += n
    return total


def _count_one(target, follow_files=True):
    if is_literal_ip(target):
        return 1
    try:
        return ipaddress.ip_network(target, strict=False).num_addresses
    except ValueError:
        pass
    m = OCTET_RANGE_RE.match(target)
    if m:
        first, last = int(m.group("first")), int(m.group("last"))
        if 0 <= first <= last <= 255:
            return last - first + 1
    if follow_files and os.path.isfile(target):
        try:
            with open(target, errors="replace") as fh:
                entries = [l.strip() for l in fh
                           if l.strip() and not l.strip().startswith("#")]
        except OSError:
            return None
        return sum(_count_one(e, follow_files=False) or 1 for e in entries)
    return 1   # a hostname is one host

# any timeout flag in an nxc --help, including ones salvo's TIMEOUT_FLAG table
# has never heard of
TIMEOUT_ANY_RE = re.compile(r"--[a-z0-9]+-timeout")

# Timeout flags that belong to nxc's GENERIC parser rather than to a protocol.
# `nxc <proto> --help` prints the generic options under every protocol, so
# these turn up in all ten and must not be mistaken for a per-protocol flag
# salvo is failing to send. Putting --dns-timeout in TIMEOUT_FLAG would make
# --nxc-timeout set name-resolution time instead of connection time: a
# different knob, changed silently.
KNOWN_GENERIC_TIMEOUT_FLAGS = frozenset(["--dns-timeout"])

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
LINE_RE = re.compile(
    r"^(?P<proto>[A-Z0-9]+)\s+"      # SMB / WINRM / MSSQL ...
    r"(?P<ip>[0-9a-fA-F:.]+)\s+"     # target address
    r"(?P<port>\d+)\s+"              # port
    r"(?P<host>\S+)\s+"              # netbios / hostname column
    r"(?P<rest>.*)$"                 # [+] / [-] / [*] and the message
)


def strip_ansi(s):
    return ANSI_RE.sub("", s)


# ---------------------------------------------------------------------------
# Credential model
# ---------------------------------------------------------------------------

class Cred:
    def __init__(self, user, secret, is_hash, domain=None, local=False, idx=0):
        self.user = user
        self.secret = secret
        self.is_hash = is_hash
        self.domain = domain
        self.local = local
        self.idx = idx          # position in the input list - fixes render order

    @property
    def label(self):
        kind = "H" if self.is_hash else "P"
        shown = self.secret if len(self.secret) <= 34 else self.secret[:31] + "..."
        if self.local:
            return "LOCAL\\{}:{} [{}]".format(self.user, shown, kind)
        if self.domain:
            return "{}\\{}:{} [{}]".format(self.domain, self.user, shown, kind)
        # No -d and no --local-auth. Printing "DOMAIN\" here would read as if a
        # domain had been applied when nxc was in fact left to guess.
        return "{}:{} [{}]  (no -d given - nxc guessed the scope)".format(
            self.user, shown, kind)

    @property
    def key(self):
        return (self.user, self.secret, self.is_hash, self.domain, self.local)

    @property
    def fingerprint(self):
        """Short stable id, safe for filenames. Disambiguates two passwords
        for the same user, which would otherwise share one log file."""
        blob = "|".join([
            self.user, self.secret, str(self.is_hash),
            self.domain or "", str(self.local),
        ])
        return hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()[:8]

    def to_dict(self):
        return {
            "user": self.user, "secret": self.secret, "is_hash": self.is_hash,
            "domain": self.domain, "local": self.local,
        }

    @classmethod
    def from_dict(cls, d, idx=0):
        return cls(d["user"], d["secret"], d["is_hash"], d.get("domain"),
                   d.get("local", False), idx)


def job_signature(cred, proto, targets):
    """
    Stable id for one unit of work. Any change to the credential, the protocol,
    or the target list produces a different signature, so a resumed run never
    silently skips a job whose scope has moved.
    """
    payload = json.dumps(
        {"cred": cred.to_dict(), "proto": proto, "targets": sorted(targets)},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:16]


HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}:)?[a-fA-F0-9]{32}$")


def looks_like_hash(s):
    """32-hex NT hash, or the LM:NT pair form."""
    return bool(HASH_RE.match(s.strip()))


def parse_cred_file(path):
    """
    One credential per line. Accepted forms:
        user:password
        user:31d6cfe0d16ae931b73c59d7e0c089c0
        user:aad3b435b51404eeaad3b435b51404ee:31d6cfe0...
        DOMAIN\\user:password
    Blank lines and lines starting with # are ignored.

    Returns (entries, problems). A line salvo cannot read is a credential the
    operator believes is being tested and is not, so every one is reported by
    line number instead of dropped in silence.
    """
    out, problems = [], []
    with open(path, "r", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                problems.append("line {}: no ':' separator, skipped - {!r}"
                                .format(lineno, line[:40]))
                continue
            user, secret = line.split(":", 1)
            dom = None
            if "\\" in user:
                dom, user = user.split("\\", 1)
            user = user.strip().lstrip("\\")
            dom = dom.strip().rstrip("\\") if dom else None
            secret = secret.strip()
            if not user:
                problems.append("line {}: empty username, skipped".format(lineno))
                continue
            if not secret:
                problems.append("line {}: empty secret for {!r}, skipped - an "
                                "empty password still spends a logon"
                                .format(lineno, user))
                continue
            out.append((dom, user, secret, looks_like_hash(secret)))
    return out, problems


class State:
    """
    Resume store. Records which (credential, protocol, target-set) jobs have
    already completed, and the results they produced.

    Why this exists: every protocol you spray is a real authentication attempt
    against a real lockout counter. If the VM hangs at job 30 of 44 and you
    re-run, the naive tool re-fires all 44. This one re-fires 14. The results
    from the first 30 are merged back in, so the matrix you end up looking at
    is complete even though no single process ever saw all of it.

    A job is only recorded complete when nxc exited cleanly and the run was
    not aborted. Anything else is left unrecorded and will be retried, which
    is the safe direction to fail.
    """

    def __init__(self, path):
        self.path = path
        self.jobs = {}
        self.lock = threading.Lock()
        self.dirty = False
        self.ignore = False   # --no-resume: keep the file, but skip nothing

    def load(self):
        if not self.path or not os.path.isfile(self.path):
            return 0
        try:
            with open(self.path) as fh:
                data = json.load(fh)
        except (ValueError, OSError) as exc:
            sys.stderr.write("[!] state file unreadable ({}), starting fresh\n".format(exc))
            return 0
        if data.get("version") != STATE_VERSION:
            sys.stderr.write("[!] state file is version {}, expected {} - starting fresh\n"
                             .format(data.get("version"), STATE_VERSION))
            return 0
        jobs = data.get("jobs")
        if not isinstance(jobs, dict):
            sys.stderr.write("[!] state file has no usable job table, starting fresh\n")
            return 0
        self.jobs = jobs
        return len(self.jobs)

    def is_done(self, sig):
        return (not self.ignore) and sig in self.jobs

    def prior_hits(self, sig, cred):
        """Rebuild Hit objects from a completed job so they merge into the matrix."""
        out = []
        record = self.jobs.get(sig) or {}
        for r in record.get("hits") or []:
            try:
                out.append(Hit(cred, r["protocol"], r["ip"], int(r["port"]),
                               r["hostname"], r["status"], r["note"], r["raw"]))
            except (KeyError, TypeError, ValueError):
                # A record salvo cannot rebuild is one it must not claim to
                # have. Dropping it means the job is re-run, which is the safe
                # direction: an extra logon beats a fabricated verdict.
                sys.stderr.write("[!] unreadable result in state file, that job "
                                 "will be re-run\n")
                return []
        return out

    def complete(self, sig, cred, proto, targets, hits):
        with self.lock:
            self.jobs[sig] = {
                "cred": cred.to_dict(),
                "protocol": proto,
                "targets": sorted(targets),
                "completed": now_iso(),
                "hits": [h.as_dict() for h in hits],
            }
            self.dirty = True

    def save(self):
        if not self.path or not self.dirty:
            return
        with self.lock:
            write_json_atomic(self.path, {
                "version": STATE_VERSION,
                "updated": datetime.now().isoformat(timespec="seconds"),
                "jobs": self.jobs,
            })
            self.dirty = False


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

class Hit:
    __slots__ = ("cred", "proto", "ip", "port", "host", "status", "note", "raw")

    def __init__(self, cred, proto, ip, port, host, status, note, raw):
        self.cred = cred
        self.proto = proto
        self.ip = ip
        self.port = port
        self.host = host
        self.status = status
        self.note = note
        self.raw = raw

    def as_dict(self):
        return {
            "user": self.cred.user,
            "secret": self.cred.secret,
            "is_hash": self.cred.is_hash,
            "domain": self.cred.domain,
            "local_auth": self.cred.local,
            "protocol": self.proto,
            "ip": self.ip,
            "port": self.port,
            "hostname": self.host,
            "status": self.status,
            "note": self.note,
            "raw": self.raw,
        }


def classify(proto, rest):
    """
    Turn one nxc output line into (status, note).
    Everything hinges on being honest about what we cannot tell.
    """
    upper = rest.upper()

    if rest.startswith("[+]"):
        if "PWN3D" in upper or "(ADMIN)" in upper:
            # What "Pwn3d!" proves depends entirely on the protocol.
            # See PWN_MEANING - winrm and ssh are the traps.
            return PWN_MEANING.get(proto, (EXEC, "elevated access reported by nxc"))
        return VALID, "authenticated"

    if rest.startswith("[-]"):
        for needle, bucket, note in STATUS_MAP:
            if needle in upper:
                return bucket, note
        # no NT status code at all
        if proto in AMBIGUOUS_BARE_FAILURE:
            return INCONCLUSIVE, (
                "refused with no status code - on {} this cannot be told apart "
                "from an authorization denial. Do not write the cred off.".format(proto)
            )
        return INVALID, "authentication refused"

    if rest.startswith("[*]"):
        return None, None  # banner / info line, not a verdict

    return None, None


def classify_error(text):
    low = text.lower()
    if "connection refused" in low or "no route to host" in low:
        return NO_SERVICE, "port closed / host unreachable"
    if "timed out" in low or "timeout" in low:
        return NO_SERVICE, "timed out"
    return ERROR, text.strip()[:120]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class Runner:
    def __init__(self, args, state=None):
        self.args = args
        self.state = state
        self.hits = []
        self.lock = threading.Lock()
        self.abort = threading.Event()
        self.procs = []
        self.hostnames = {}   # ip -> hostname learned from [*] banner lines
        self.os_hint = {}     # ip -> "windows", learned from SMB banner lines
        self.seen_domains = set()   # domains the targets advertised themselves
        self.logdir = args.logdir
        self.skipped = 0
        self.domain_dropped = set()   # protocols where -d was withheld (no such flag)
        self.job_failures = []        # (proto, user, returncode, tail) - nxc refused to run
        self.unparsed = {}            # proto -> count of output lines LINE_RE did not match
        self.parsed = {}              # proto -> count of output lines it did match
        # (cred.key, proto) -> (status, reason) for a job that produced no
        # result of its own: skipped, rejected by nxc, or errored. Without it
        # the cell stays empty and renders '-'.
        self.overlay = {}
        self.job_errors = []          # (proto, user, message) - salvo could not run it
        self.commands = []            # every nxc command line actually executed
        # Guards self.procs only. Spawning holds it, so a spawn cannot
        # interleave with the kill sweep; keeping it off self.lock means the
        # per-output-line bookkeeping does not contend with process startup.
        self.proc_lock = threading.Lock()

    def build_cmd(self, cred, proto, targets):
        """
        nxc generic options come BEFORE the protocol. Protocol options after.
        Getting that order wrong is the number one nxc syntax mistake.
        """
        cmd = []
        if self.args.proxychains:
            # nxc has no proxy flag of its own; the standard route is to run it
            # under proxychains. -q keeps its chatter out of the parsed stream.
            cmd += [self.args.proxychains_bin, "-q"]

        cmd += [self.args.nxc_bin]
        cmd += ["-t", str(self.args.nxc_threads)]           # nxc's own per-target concurrency
        if self.args.jitter:
            cmd += ["--jitter", self.args.jitter]
        cmd += ["--no-progress"]                            # progress bar corrupts parsing
        cmd += [proto]
        cmd += list(targets)

        # ---- per-protocol timeout ----------------------------------------
        # The global --timeout is deprecated upstream and silently ignored.
        # Only emit the flag this protocol actually owns.
        if self.args.nxc_timeout and proto in TIMEOUT_FLAG:
            cmd += [TIMEOUT_FLAG[proto], str(self.args.nxc_timeout)]

        cmd += ["-u", cred.user]
        cmd += ["-H" if cred.is_hash else "-p", cred.secret]

        # ---- auth mode, whitelisted per protocol -------------------------
        # Never send a flag the sub-parser does not define. The cost of getting
        # this wrong is not an error message, it is a silent '-' in the matrix.
        if cred.local:
            if proto in LOCAL_AUTH_CAPABLE:
                cmd += ["--local-auth"]
            # ssh/ftp/nfs/vnc: no domain concept, so local IS the only mode.
            # Send nothing and let it run.
        elif cred.domain:
            if proto in DOMAIN_CAPABLE:
                cmd += ["-d", cred.domain]
            else:
                # Record it so the run can say so afterwards rather than
                # letting the user believe the domain cred was tested here.
                self.domain_dropped.add(proto)

        cmd += ["--continue-on-success"]                    # without this you stop at hit one
        return cmd

    def logpath_for(self, cred, proto):
        if not self.logdir:
            return None
        # fingerprint keeps two passwords for the same user in separate files
        name = "{}_{}_{}_{}.log".format(
            proto, re.sub(r"[^A-Za-z0-9_.-]", "_", cred.user),
            "hash" if cred.is_hash else "pw", cred.fingerprint)
        return os.path.join(self.logdir, name)

    def run_one(self, cred, proto, targets, sig):
        if self.abort.is_set():
            return
        if self.args.job_delay:
            # Spaces salvo's own processes apart. nxc --jitter cannot do this;
            # it only delays attempts within a single process.
            time.sleep(self.args.job_delay)
            if self.abort.is_set():
                return
        # Refuse before the packet, not after the report.
        cmd = assert_authentication_only(self.build_cmd(cred, proto, targets))
        logpath = self.logpath_for(cred, proto)
        job_hits = []

        # truncating open, not append - a re-run of the same job replaces its
        # log rather than growing it. Owner-only: every nxc line echoes the
        # password back. Opened before the spawn so a bad --logdir costs
        # nothing rather than orphaning a running process.
        logfh = None
        if logpath:
            try:
                logfh = open_private(logpath)
            except OSError as exc:
                self.record_job_error(cred, proto,
                                      "cannot write {}: {}".format(logpath, exc))
                return

        # The abort check and the spawn must be atomic. Checked outside the
        # lock, a job that passed the check microseconds before a lockout was
        # detected would spawn AFTER kill_all had already swept - and spend a
        # logon against an account that is already locked out. That is the one
        # thing this tool must never do.
        try:
            with self.proc_lock:
                if self.abort.is_set():
                    logfh and logfh.close()
                    return
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    # nxc must never reach the operator's terminal: six of them
                    # sharing a stdin will eat the keystrokes meant for salvo.
                    stdin=subprocess.DEVNULL,
                    # a stray non-UTF-8 byte in a hostname must not take the
                    # whole job down with a decode error
                    text=True, errors="replace", bufsize=1,
                )
                self.procs.append(proc)
            with self.lock:
                # the audit answer to "what exactly did you send at our estate"
                self.commands.append(" ".join(quote(c) for c in cmd))
        except OSError as exc:
            logfh and logfh.close()
            self.record_job_error(cred, proto, "could not start {}: {}".format(
                self.args.nxc_bin, exc))
            return

        clean = False
        tail = deque(maxlen=6)   # last few lines, for when nxc refuses to run
        try:
            for raw in proc.stdout:
                if logfh:
                    logfh.write(raw)
                line = strip_ansi(raw.rstrip("\n"))
                if not line.strip():
                    continue
                tail.append(line.strip())
                m = LINE_RE.match(line)
                if not m:
                    # Format-drift detector. nxc's human-readable output is the
                    # only interface salvo has; if upstream changes its column
                    # layout this counter is what says so out loud.
                    with self.lock:
                        self.unparsed[proto] = self.unparsed.get(proto, 0) + 1
                    continue
                with self.lock:
                    self.parsed[proto] = self.parsed.get(proto, 0) + 1
                ip = m.group("ip")
                host = m.group("host")
                rest = m.group("rest").strip()
                port = int(m.group("port"))

                # If the hostname column was blank, the regex will have eaten
                # the "[+]" marker as the hostname. Push it back.
                if host.startswith("["):
                    rest = (host + " " + rest).strip()
                    host = ip

                if host and host not in ("None", "-"):
                    self.hostnames.setdefault(ip, host)

                # Banner lines are not verdicts, but they carry the two facts
                # that make later verdicts honest: the OS, and the real domain.
                if rest.startswith("[*]"):
                    low = rest.lower()
                    if "windows" in low:
                        self.os_hint[ip] = "windows"
                    dm = re.search(r"\(domain:([^)]*)\)", rest)
                    if dm and dm.group(1).strip():
                        self.seen_domains.add(dm.group(1).strip())

                status, note = classify(proto, rest)
                if status is None:
                    continue

                hit = Hit(cred, proto, ip, port, self.hostnames.get(ip, host),
                          status, note, rest)
                job_hits.append(hit)
                self.record(hit)

                if status == LOCKED and not self.args.no_lockout_guard:
                    self.trigger_abort(hit)
            clean = True
        except (OSError, ValueError) as exc:
            # the pipe went away - killed process, closed descriptor
            if not self.abort.is_set():
                self.record_job_error(cred, proto,
                                      "reading nxc output failed: {}".format(exc))
        finally:
            if logfh:
                logfh.close()
            self.reap(proc)

        # ---- a job that produced no verdict at all ---------------------------
        # Three different facts used to collapse into the same '-' cell:
        #   the port is closed, nxc crashed, and salvo built a command nxc
        #   rejected. Only the first is a statement about the target. Separate
        #   them here, or an argparse error reads as "nothing listening".
        if (not job_hits and not self.abort.is_set()
                and proc.returncode not in (0, None)):
            msg = " | ".join(t for t in tail) or "no output"
            with self.lock:
                self.job_failures.append((proto, cred, proc.returncode, msg))
            self.mark_cell(cred, proto, USAGE,
                           "nxc exited {} without producing a single result "
                           "line - this protocol was never tested"
                           .format(proc.returncode))
            return   # do NOT mark done - a rejected command must be retried

        # Only a clean, unaborted, zero-exit job is recorded as done. Anything
        # else stays unrecorded so the next run retries it.
        if (self.state and clean and not self.abort.is_set()
                and proc.returncode == 0):
            self.state.complete(sig, cred, proto, targets, job_hits)

    def record(self, hit):
        with self.lock:
            self.hits.append(hit)
        if self.args.stream:
            print(fmt_live(hit))

    def trigger_abort(self, hit):
        if self.abort.is_set():
            return
        self.abort.set()
        sys.stderr.write(
            "\n" + "!" * 70 + "\n"
            "  LOCKOUT DETECTED on {} ({}) as {}\n"
            "  Every remaining job has been killed.\n"
            "  Check the policy before you touch this domain again:\n"
            "      nxc smb <DC_IP> -u '' -p '' --pass-pol\n"
            "  Re-run with --no-lockout-guard only if you know what you are doing.\n"
            .format(hit.ip, hit.proto, hit.cred.user)
            + "!" * 70 + "\n\n"
        )
        self.kill_all()

    def kill_all(self):
        with self.proc_lock:
            for p in list(self.procs):
                try:
                    p.kill()
                except Exception:
                    pass

    def reap(self, proc):
        """
        Close the pipe, make sure the child is really gone, and stop tracking
        it. Killing without waiting leaves a zombie, and never dropping the
        reference means a long run carries every process it ever started.
        """
        try:
            if proc.stdout:
                proc.stdout.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=10)
            except Exception:
                pass
        with self.proc_lock:
            try:
                self.procs.remove(proc)
            except ValueError:
                pass

    def mark_cell(self, cred, proto, status, reason):
        """
        Annotate a (credential, protocol) that produced no result of its own.

        An absent result leaves an empty cell, and an empty cell renders '-',
        which the legend defines as "no service / no answer" - a claim about
        the target. Skipped, rejected and errored jobs are claims about salvo,
        and the matrix has to keep them apart from a closed port.
        """
        with self.lock:
            self.overlay[(cred.key, proto)] = (status, reason)

    def record_job_error(self, cred, proto, message):
        """A job salvo could not run at all - not a verdict about the target."""
        with self.lock:
            self.job_errors.append((proto, cred.user, message))
        _status, note = classify_error(message)
        # Always ERROR, never NO_SERVICE. classify_error reads "timed out" out
        # of a message and would hand back NO_SERVICE, which renders '-' - a
        # statement about the target for something that is salvo failing.
        self.mark_cell(cred, proto, ERROR, note)

    def finalize(self):
        """
        Post-pass. Some verdicts can only be judged once every protocol has
        reported, because the evidence arrives from a different nxc process.

        Runs on the merged hit list (this run plus anything resumed), so it is
        idempotent and re-applies correctly on every invocation.
        """
        for h in self.hits:
            if h.proto == "ssh" and h.status == EXEC and self.os_hint.get(h.ip) == "windows":
                h.note = ("shell on a WINDOWS host - nxc's root/sudo probe is "
                          "meaningless against Windows OpenSSH. Expect a standard "
                          "user in cmd.exe.")

    def probe_flags(self, proto):
        """
        Ask nxc itself which flags this protocol accepts.

        The hardcoded capability tables above are a snapshot of upstream, and a
        snapshot goes stale. This is the escape hatch: it is only paid for when
        something has already gone wrong, and it turns "the ssh column is
        empty" into "nxc ssh has no -d".
        """
        try:
            r = subprocess.run([self.args.nxc_bin, proto, "--help"],
                               capture_output=True, text=True, timeout=60)
        except Exception:
            return None
        help_text = (r.stdout or "") + (r.stderr or "")
        if not help_text.strip():
            return None
        return {
            "-d": (" -d " in help_text or "--domain" in help_text),
            "--local-auth": ("--local-auth" in help_text),
            "-H": (" -H " in help_text or "--hash" in help_text),
            # sent unconditionally to every protocol, so it is the one flag
            # that would break every column at once if a protocol lacked it
            "--continue-on-success": ("--continue-on-success" in help_text),
            "timeout": TIMEOUT_FLAG.get(proto, "") in help_text if proto in TIMEOUT_FLAG else None,
        }

    def diagnose_failures(self):
        """
        For every protocol whose job nxc refused to run, work out which flag
        salvo sent that the protocol does not define, and say so by name.
        """
        out = []
        by_proto = {}
        for proto, cred, _rc, _m in self.job_failures:
            by_proto.setdefault(proto, []).append(cred)

        for proto in sorted(by_proto):
            supported = self.probe_flags(proto)
            if supported is None:
                out.append("  {}: could not run 'nxc {} --help' to diagnose".format(proto, proto))
                continue
            # What salvo sent for THIS job's credential, not for the run as a
            # whole. Under --both-auth the same protocol runs with and without
            # --local-auth, and reading the run-level flags blamed the wrong one.
            sent = {"--continue-on-success"}
            for cred in by_proto[proto]:
                if cred.local:
                    if proto in LOCAL_AUTH_CAPABLE:
                        sent.add("--local-auth")
                elif cred.domain and proto in DOMAIN_CAPABLE:
                    sent.add("-d")
                if cred.is_hash:
                    sent.add("-H")
            bad = sorted(f for f in sent if supported.get(f) is False)
            if bad:
                out.append("  {}: salvo sent {} but 'nxc {}' does not define it. "
                           "Correct the capability tables at the top of this file, "
                           "then re-run 'salvo --check-nxc -P all'."
                           .format(proto, " and ".join(bad), proto))
            else:
                out.append("  {}: flags look valid - the failure is nxc itself, "
                           "not the command. Check the log.".format(proto))
        return out

    def advisories(self):
        """Things worth saying once, after the matrix, that are not verdicts."""
        out = []

        # A domain credential tested over a protocol with no domain concept is
        # not the same test. Say so rather than letting the column stand.
        if self.domain_dropped:
            out.append(
                "-d was NOT sent to {} - those protocols have no domain argument, "
                "so nxc authenticated the bare username with no '{}\\' prefix. "
                "Those cells answer a different question from the domain columns; "
                "on a Windows host they usually resolve to the LOCAL account of "
                "the same name."
                .format(", ".join(sorted(self.domain_dropped)), self.args.domain))

        # Format drift: nxc printed lines, salvo understood none of them.
        for proto, n in sorted(self.unparsed.items()):
            if n >= 3 and self.parsed.get(proto, 0) == 0:
                out.append(
                    "{}: nxc produced {} output line(s) and salvo parsed NONE of them. "
                    "Either the command failed or NetExec's output format has changed. "
                    "Re-run with --logdir and read the raw log before trusting this row."
                    .format(proto, n))

        given = {c for c in [self.args.domain] if c}
        undeclared = {d for d in self.seen_domains if d and d.lower() not in
                      {g.lower() for g in given}}
        if undeclared and not self.args.local_auth:
            for d in sorted(undeclared):
                out.append("The targets advertise the domain '{}'. You did not pass -d. "
                           "Re-run with -d {} before trusting ldap, or any "
                           "Kerberos-backed result.".format(d, d))
        return out

    def attempts_made(self):
        """
        Authentication attempts that ACTUALLY happened, per account.
        A '-' cell never reached authentication, so it never touched a lockout
        counter. The pre-run warning is a worst case; this is the real bill.
        """
        counted = {}
        for (_ck, _ip, _p), h in collapse(self.hits).items():
            if h.status in (NO_SERVICE, ERROR, USAGE):
                continue
            counted[h.cred.user] = counted.get(h.cred.user, 0) + 1
        return counted

    def plan(self, creds, protocols, targets):
        """
        Expand to concrete jobs, then drop any already answered in the state
        file. Returns the list still to run.
        """
        jobs = []
        for cred in creds:
            for proto in protocols:
                if cred.is_hash and proto not in HASH_CAPABLE:
                    # cannot pass-the-hash over ssh/ftp/nfs/vnc
                    # Reason text is deliberately protocol-independent so
                    # several protocols collapse onto one explanation line.
                    self.mark_not_run(cred, proto,
                                      "nxc defines no -H here, so a hash cannot "
                                      "be tested over this protocol")
                    continue
                if cred.local and proto == "ldap":
                    # nxc ldap has no --local-auth: a directory bind is always
                    # domain-scoped. Running it anyway would spend a logon to
                    # learn nothing, and print an INVALID that is not true.
                    self.mark_not_run(cred, proto,
                                      "nxc ldap has no --local-auth - a directory "
                                      "bind is always domain-scoped")
                    continue
                sig = job_signature(cred, proto, targets)
                if self.state and self.state.is_done(sig):
                    self.skipped += 1
                    # pull the earlier results forward so the matrix is whole
                    with self.lock:
                        self.hits.extend(self.state.prior_hits(sig, cred))
                    continue
                jobs.append((cred, proto, targets, sig))
        return jobs

    def mark_not_run(self, cred, proto, reason):
        """A job salvo declined to run - no packet was ever sent."""
        self.mark_cell(cred, proto, NOT_RUN, reason)

    @property
    def not_run(self):
        """The skipped subset of the overlay, for the JSON report."""
        return {k: why for k, (st, why) in self.overlay.items() if st == NOT_RUN}

    def execute(self, jobs):
        if not jobs:
            print("[*] nothing left to run - every job is already answered in the state file\n")
            return
        print("[*] {} nxc process(es), {} at a time{}\n".format(
            len(jobs), self.args.parallel,
            "  ({} skipped, already answered)".format(self.skipped) if self.skipped else ""))

        started = time.time()
        # Not a `with` block. ThreadPoolExecutor.__exit__ shuts down with
        # wait=True, so a Ctrl-C raised inside it would sit through every
        # remaining queued job before the handler below ever ran - minutes of
        # spraying after the operator asked it to stop. Aborting first makes
        # the queued jobs return immediately, and only then do we shut down.
        pool = ThreadPoolExecutor(max_workers=self.args.parallel)
        futures = {}
        try:
            for job in jobs:
                futures[pool.submit(self.run_one, *job)] = job
            for f in as_completed(futures):
                cred, proto = futures[f][0], futures[f][1]
                try:
                    f.result()
                except Exception as exc:
                    # A job that raised produced no cell of its own, and an
                    # empty cell renders '-'. Say what actually happened.
                    self.record_job_error(
                        cred, proto, "salvo raised while running this job: {}".format(exc))
                    sys.stderr.write("[!] {} as {}: {}\n".format(proto, cred.user, exc))
        except KeyboardInterrupt:
            self.abort.set()
            self.kill_all()
            for f in futures:
                f.cancel()
            sys.stderr.write("\n[!] interrupted - nxc killed, keeping results "
                             "gathered so far\n")
        finally:
            pool.shutdown(wait=True)
            if self.state:
                self.state.save()
        print("\n[*] finished in {:.0f}s".format(time.time() - started))


def quote(s):
    """Proper shell quoting - a password containing a quote must not produce
    a command that silently means something else when pasted."""
    return shlex.quote(s)


def fmt_live(hit):
    tags = {
        ADMIN: "[ADMIN]",
        EXEC: "[EXEC ]",
        VALID: "[  +  ]",
        CRED_OK_ACCESS_NO: "[VALID*]",
        INCONCLUSIVE: "[  ?  ]",
        LOCKED: "[LOCK!]",
        INVALID: "[  -  ]",
        NO_SERVICE: "[ nosvc]",
        ERROR: "[ err ]",
        USAGE: "[!CMD ]",
        NOT_RUN: "[ n/a ]",
    }
    tag = tags.get(hit.status, "[{:^5}]".format(hit.status[:5]))
    return "{:8} {:6} {:<16} {:<16} {}".format(
        tag, hit.proto, hit.ip, hit.host[:16], hit.cred.user
    )


# ---------------------------------------------------------------------------
# Matrix rendering
# ---------------------------------------------------------------------------

def collapse(hits):
    """
    (cred_key, ip, proto) -> single best hit.
    nxc emits several lines per host; keep the most significant. Ties break on
    the raw text so the winner is stable across runs.
    """
    best = {}
    for h in hits:
        k = (h.cred.key, h.ip, h.proto)
        cur = best.get(k)
        if cur is None:
            best[k] = h
        elif SEVERITY[h.status] > SEVERITY[cur.status]:
            best[k] = h
        elif SEVERITY[h.status] == SEVERITY[cur.status] and h.raw < cur.raw:
            best[k] = h
    return best


def ordered_creds(hits):
    """Credentials in input order, not thread-completion order."""
    seen = {}
    for h in hits:
        seen.setdefault(h.cred.key, h.cred)
    return OrderedDict(
        (c.key, c) for c in sorted(seen.values(), key=lambda c: (c.idx, c.label))
    )


def ordered_hosts(hits):
    """Hosts sorted numerically by address, hostname taken from any line that has one."""
    names = {}
    for h in hits:
        if h.host not in ("-", "", None) and h.host != h.ip:
            names.setdefault(h.ip, h.host)
    ips = {h.ip for h in hits if h.ip != "-"}
    return OrderedDict((ip, names.get(ip, ip)) for ip in sorted(ips, key=ip_sort_key))


def render_matrix(hits, protocols, markdown=False, overlay=None):
    """
    overlay maps (cred.key, protocol) to (status, reason) for a job that
    produced no result of its own - skipped, rejected by nxc, or errored.

    Those cells carry the overlay's glyph rather than '-'. A '-' is a fact
    about the host; every overlay entry is a fact about salvo, and collapsing
    the two is the exact failure this tool exists to remove.
    """
    overlay = overlay or {}

    def reason_lines(ckey, indent="  "):
        grouped = {}
        for p in protocols:
            entry = overlay.get((ckey, p))
            if entry:
                grouped.setdefault(entry, []).append(p)
        return ["{}{:<5} {:<20} {}".format(indent, GLYPH[st], ", ".join(ps), why)
                for (st, why), ps in sorted(grouped.items(),
                                            key=lambda kv: (kv[0][0], kv[1]))]

    if not hits:
        if not overlay:
            return "no results.\n"
        # Nothing answered anywhere, but salvo still knows why it ran nothing,
        # and that is the whole message.
        out = ["", "No host produced a result. Nothing here is a verdict:"]
        for ckey in sorted({k for k, _ in overlay}):
            out.extend(reason_lines(ckey))
        return "\n".join(out) + "\n"

    best = collapse(hits)
    creds = ordered_creds(hits)
    hosts = ordered_hosts(hits)

    out = []
    for ckey, cred in creds.items():
        rows = []
        for ip, hostname in hosts.items():
            cells = []
            any_signal = False
            for p in protocols:
                hit = best.get((ckey, ip, p))
                if hit is not None:
                    cells.append(GLYPH[hit.status])
                    if hit.status in (ADMIN, EXEC, VALID, CRED_OK_ACCESS_NO,
                                      INCONCLUSIVE, LOCKED):
                        any_signal = True
                elif (ckey, p) in overlay:
                    cells.append(GLYPH[overlay[(ckey, p)][0]])
                else:
                    cells.append("")
            label = ip if hostname in ("-", ip, "") else "{} ({})".format(ip, hostname)
            rows.append((label, cells, any_signal))

        if markdown:
            out.append("\n### {}\n".format(cred.label))
            out.append("| host | " + " | ".join(protocols) + " |")
            out.append("|---" * (len(protocols) + 1) + "|")
            for label, cells, _ in rows:
                out.append("| {} | ".format(label) + " | ".join(c or GLYPH[NO_SERVICE] for c in cells) + " |")
            for line in reason_lines(ckey, indent=""):
                out.append("\n`" + line.strip() + "`")
        else:
            out.append("\n" + "=" * 78)
            out.append(" {}".format(cred.label))
            out.append("=" * 78)
            width = max([len(r[0]) for r in rows] + [12])
            header = "{:<{w}}".format("host", w=width) + "".join("{:>8}".format(p) for p in protocols)
            out.append(header)
            out.append("-" * len(header))
            for label, cells, sig in rows:
                mark = " <" if sig else ""
                out.append("{:<{w}}".format(label, w=width)
                           + "".join("{:>8}".format(c or GLYPH[NO_SERVICE]) for c in cells) + mark)
            out.extend(reason_lines(ckey))
    out.append("")
    out.append("  ADMIN  = provably administrative (smb admin-share write, mssql sysadmin)")
    out.append("  exec   = code execution, NOT admin - check the smb column before assuming")
    out.append("  ok     = authenticated    VALID* = password correct, this access path blocked")
    out.append("  ?      = cannot tell, retest elsewhere    . = refused    - = no service / no answer")
    out.append("  !CMD   = nxc REJECTED the command salvo built - this cell was never tested")
    out.append("  n/a    = salvo ran NO job here - a fact about salvo, not about the host")
    out.append("  err    = salvo could not run this job - also not a verdict")
    out.append("  <      = this host answered on at least one protocol")
    out.append("")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Follow-up command suggestions
# ---------------------------------------------------------------------------

def secret_flag(cred):
    return ("-H " + cred.secret) if cred.is_hash else ("-p " + quote(cred.secret))


# which protocol to reach for first once you have access on several
PROTO_RANK = {"winrm": 0, "smb": 1, "mssql": 2, "ssh": 3, "rdp": 4, "wmi": 5, "ftp": 6, "ldap": 7}

# appended to any command that lands you a shell without admin being proven
NO_ADMIN_NOTE = "   # NOT local admin here - expect to land as a standard user"


def commands_for(h, admin_here=False):
    """
    Follow-up commands for one usable result.

    admin_here says whether ANY protocol on this host proved administrative
    rights. If not, every shell command gets flagged - because an `exec` on
    WinRM or SSH will drop you in as a standard user, and finding that out by
    watching a privileged read fail is an expensive way to learn it.

    Only ADMIN / EXEC / VALID get here. A BLOCKED result means that exact
    access path is closed, so handing back a command for it would be a lie.
    """
    c, ip, proto = h.cred, h.ip, h.proto
    dom = c.domain or "."
    sec = quote(c.secret)
    shell_note = "" if admin_here else NO_ADMIN_NOTE
    out = []

    if proto == "winrm":
        if c.is_hash:
            out.append("evil-winrm -i {} -u {} -H {}{}".format(ip, c.user, c.secret, shell_note))
        else:
            out.append("evil-winrm -i {} -u {} -p {}{}".format(ip, c.user, sec, shell_note))
    elif proto == "smb":
        if h.status == ADMIN:
            if c.is_hash:
                out.append("impacket-psexec  -hashes :{} {}/{}@{}".format(c.secret, dom, c.user, ip))
                out.append("impacket-wmiexec -hashes :{} {}/{}@{}".format(c.secret, dom, c.user, ip))
            else:
                out.append("impacket-psexec  {}/{}:{}@{}".format(dom, c.user, sec, ip))
                out.append("impacket-wmiexec {}/{}:{}@{}".format(dom, c.user, sec, ip))
        else:
            out.append("nxc smb {} -u {} {} --shares   # non-admin still reads shares"
                       .format(ip, c.user, secret_flag(c)))
    elif proto == "mssql":
        if c.is_hash:
            out.append("impacket-mssqlclient {}@{} -hashes :{} -windows-auth"
                       .format(c.user, ip, c.secret))
        else:
            out.append("impacket-mssqlclient {}:{}@{} -windows-auth".format(c.user, sec, ip))
    elif proto == "rdp":
        out.append("xfreerdp3 /u:{} /p:{} /v:{} /cert:ignore /drive:kali,/home/kali{}"
                   .format(c.user, sec, ip, shell_note))
    elif proto == "ssh":
        out.append("ssh {}@{}{}".format(c.user, ip, shell_note))
    elif proto == "ftp":
        out.append("ftp {}   # login {} / {}".format(ip, c.user, c.secret))
    elif proto == "wmi" and h.status == ADMIN:
        out.append("impacket-wmiexec {}/{}:{}@{}".format(dom, c.user, sec, ip))
    return out


def next_moves(hits):
    """
    Grouped by host, best access first. LDAP is emitted once at the end
    because it is a domain-wide action, not a per-host one.
    """
    best = collapse(hits)
    by_host = {}
    ldap_hits = []

    for (_, ip, proto), h in best.items():
        if h.status not in (ADMIN, EXEC, VALID):
            continue
        if proto == "ldap":
            ldap_hits.append(h)
            continue
        by_host.setdefault(ip, []).append(h)

    # prefer an admin LDAP bind, then the lowest address - never dict order
    ldap_cred = None
    if ldap_hits:
        ldap_cred = sorted(ldap_hits,
                           key=lambda h: (-SEVERITY[h.status], ip_sort_key(h.ip),
                                          h.cred.idx, h.cred.user))[0]

    blocks = []
    ordered = sorted(
        by_host.items(),
        key=lambda kv: (-max(SEVERITY[x.status] for x in kv[1]), ip_sort_key(kv[0])),
    )
    for ip, hs in ordered:
        hs.sort(key=lambda x: (-SEVERITY[x.status], PROTO_RANK.get(x.proto, 99),
                               x.proto, x.cred.idx, x.cred.user, x.cred.secret))
        # was admin PROVEN anywhere on this host, by any protocol?
        admin_here = any(x.status == ADMIN for x in hs)
        label = hs[0].host if hs[0].host not in ("-", "", ip) else ip
        head = "  {} ({})".format(ip, label) if label != ip else "  {}".format(ip)
        head += "   " + ", ".join("{}:{}".format(x.proto, GLYPH[x.status]) for x in hs)
        if not admin_here:
            head += "   [no admin proven on this host]"
        blocks.append(head)
        for h in hs:
            for cmd in commands_for(h, admin_here):
                blocks.append("      " + cmd)

    if ldap_cred is not None:
        c = ldap_cred.cred
        blocks.append("  domain-wide (LDAP bind works as {})".format(c.user))
        blocks.append("      nxc ldap {} -u {} {} --bloodhound -c All --dns-server {}"
                      .format(ldap_cred.ip, c.user, secret_flag(c), ldap_cred.ip))
        blocks.append("      nxc ldap {} -u {} {} --kerberoasting kerb.hashes"
                      .format(ldap_cred.ip, c.user, secret_flag(c)))
    return blocks


def inconclusive_report(hits):
    """
    Group by (user, protocol, reason) so three hosts giving the same answer
    print as one line with three addresses, not three identical paragraphs.
    """
    best = collapse(hits)
    grouped = {}
    for (_, ip, proto), h in best.items():
        if h.status in (INCONCLUSIVE, CRED_OK_ACCESS_NO):
            grouped.setdefault((h.cred.user, proto, h.note), []).append(ip)

    out = []
    for (user, proto, note), ips in sorted(grouped.items()):
        out.append("  {:<6} as {:<16} {}".format(proto, user, note))
        out.append("         {}".format(", ".join(sorted(ips))))
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Parser self-test
# ---------------------------------------------------------------------------

# Real nxc output shapes and the verdict each MUST produce. This is the
# regression net under the only interface salvo has - if NetExec changes its
# column layout, this fails before a live run silently reports nothing.
SELFTEST = [
    ("smb",   "SMB         192.168.100.25  445    WEB01            [*] Windows 10.0 Build 19044 x64 (name:WEB01) (domain:corp.local) (signing:False) (SMBv1:False)", None),
    ("smb",   "SMB         192.168.100.25  445    WEB01            [+] corp.local\\jdoe:Password123! (Pwn3d!)", ADMIN),
    ("smb",   "SMB         192.168.100.25  445    WEB01            [+] corp.local\\jdoe:Password123!", VALID),
    ("smb",   "SMB         192.168.100.25  445    WEB01            [-] corp.local\\jdoe:Password123! STATUS_LOGON_FAILURE", INVALID),
    ("smb",   "SMB         192.168.100.25  445    WEB01            [-] corp.local\\jdoe:Password123! STATUS_ACCOUNT_LOCKED_OUT", LOCKED),
    ("smb",   "SMB         192.168.100.25  445    WEB01            [-] corp.local\\jdoe:Password123! STATUS_LOGON_TYPE_NOT_GRANTED", CRED_OK_ACCESS_NO),
    ("winrm", "WINRM       192.168.100.25  5985   WEB01            [+] corp.local\\jdoe:Password123! (Pwn3d!)", EXEC),
    ("winrm", "WINRM       192.168.100.25  5985   WEB01            [-] corp.local\\jdoe:Password123!", INCONCLUSIVE),
    ("ssh",   "SSH         192.168.100.25  22     192.168.100.25   [+] jdoe:Password123! (Pwn3d!)", EXEC),
    ("ssh",   "SSH         192.168.100.25  22     192.168.100.25   [-] jdoe:Password123!", INVALID),
    ("mssql", "MSSQL       192.168.100.26  1433   SRV22            [+] corp.local\\sa:Passw0rd (Pwn3d!)", ADMIN),
    ("ldap",  "LDAP        192.168.100.10  389    DC01             [-] corp.local\\jdoe:Password123! STATUS_ACCESS_DENIED", INCONCLUSIVE),
]


def selftest():
    """Prove the line parser and the verdict table still agree with reality."""
    bad = 0
    for proto, line, expect in SELFTEST:
        m = LINE_RE.match(strip_ansi(line))
        if not m:
            print("  FAIL  regex did not match: {}".format(line[:70]))
            bad += 1
            continue
        rest = m.group("rest").strip()
        host = m.group("host")
        if host.startswith("["):
            rest = (host + " " + rest).strip()
        status, _note = classify(proto, rest)
        if status != expect:
            print("  FAIL  {:6} expected {} got {}  <- {}".format(
                proto, expect, status, line[:60]))
            bad += 1
        else:
            print("  ok    {:6} {:9} {}".format(proto, str(expect), line[:52]))
    print("")
    if bad:
        print("[!] {} of {} parser checks FAILED. NetExec's output format has "
              "probably changed - fix LINE_RE / STATUS_MAP before you trust a "
              "live run.".format(bad, len(SELFTEST)))
        return 1
    print("[*] all {} parser checks passed.".format(len(SELFTEST)))
    return 0


def print_scope():
    """
    What salvo is permitted to do, printed from the sets that actually gate it.

    This is not a summary of the code, it IS the code's data - so it cannot
    drift from behaviour the way a README section can. Useful when someone
    asks whether the tool is eligible under a given set of rules.
    """
    print("\nsalvo {} - authentication only".format(__version__))
    print("running from: {}\n".format(_running_path()))
    print("  Every nxc command salvo builds is checked against the lists below")
    print("  immediately before it is executed. Anything unrecognised aborts")
    print("  the run rather than being sent.\n")
    print("  flags salvo may send:")
    for f in sorted(ALLOWED_VALUE_FLAGS):
        print("      {} <value>".format(f))
    for f in sorted(ALLOWED_BARE_FLAGS):
        print("      {}".format(f))
    print("\n  flags salvo will never send:")
    for f in sorted(NEVER_SENT):
        print("      {}".format(f))
    print("\n  salvo does not exploit, execute commands, dump credentials,")
    print("  spoof, poison, relay, or scan for vulnerabilities. It authenticates,")
    print("  reads the answer, and prints a matrix.")
    print("\n  Your own exam or engagement rules are the authority, not this")
    print("  output. Confirm them yourself, and use --dry-run to see exactly")
    print("  what would be sent before you send it.\n")
    return 0


def _running_path():
    try:
        return os.path.realpath(sys.argv[0]) if sys.argv and sys.argv[0] else "?"
    except OSError:
        return "?"


def other_installs():
    """
    Every executable named 'salvo' on PATH that is not the one running.

    salvo used to be installed by hand - `install -m 755 salvo.py ~/bin/salvo`
    - so a later pip install leaves that copy in place and PATH order silently
    decides which one runs. Running last month's parser against this month's
    NetExec produces confident, wrong cells, which is the one failure this
    tool exists to prevent.
    """
    running = _running_path()
    found, seen = [], set()
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        candidate = os.path.join(directory, "salvo")
        try:
            if not (os.path.isfile(candidate) and os.access(candidate, os.X_OK)):
                continue
            real = os.path.realpath(candidate)
        except OSError:
            continue
        if real == running or real in seen:
            continue
        seen.add(real)
        found.append(candidate)
    return found


def warn_about_other_installs():
    others = other_installs()
    if not others:
        return
    sys.stderr.write(
        "[!] another 'salvo' is installed and PATH order decides which runs:\n")
    for path in others:
        sys.stderr.write("      {}\n".format(path))
    sys.stderr.write(
        "    this one: {}\n"
        "    If that is an older hand-installed copy, delete it and reinstall.\n\n"
        .format(_running_path()))


def nxc_version(nxc_bin):
    """
    Which NetExec produced this report. salvo reads nxc's human-readable
    output, so a result is only interpretable against a known version, and a
    report handed to a client should say which one it was.
    """
    try:
        r = subprocess.run([nxc_bin, "--version"], capture_output=True,
                           text=True, timeout=30)
    except Exception:
        return None
    text = ((r.stdout or "") + (r.stderr or "")).strip()
    return text.splitlines()[0].strip() if text else None


def check_nxc(nxc_bin, protocols):
    """
    Compare salvo's capability tables against what the installed nxc really
    accepts. Run this after any NetExec upgrade.
    """
    # Read every protocol's help first, so a flag can be judged against the
    # others rather than in isolation.
    helps = {}
    for proto in protocols:
        try:
            r = subprocess.run([nxc_bin, proto, "--help"],
                               capture_output=True, text=True, timeout=60)
            helps[proto] = (r.stdout or "") + (r.stderr or "")
        except Exception as exc:
            helps[proto] = None
            print("  {:<10} could not run: {}".format(proto, exc))

    # A timeout flag every probed protocol offers is a generic nxc option, not
    # one salvo is failing to send. Two independent rules, because each covers
    # the other's blind spot: the known list still works when only one protocol
    # is probed, and the intersection still works when upstream adds a generic
    # flag this list has never heard of.
    offered_by = {p: set(TIMEOUT_ANY_RE.findall(h))
                  for p, h in helps.items() if h is not None}
    generic = set(KNOWN_GENERIC_TIMEOUT_FLAGS)
    if len(offered_by) >= 2:
        generic |= set.intersection(*offered_by.values())

    print("\n  protocol   -d     --local-auth  -H     cont   timeout flag")
    print("  " + "-" * 68)
    drift = []
    for proto in protocols:
        h = helps.get(proto)
        if h is None:
            continue
        has_d = (" -d " in h or "--domain" in h)
        has_la = ("--local-auth" in h)
        has_hash = (" -H " in h or "--hash" in h)
        # salvo sends this to every protocol unconditionally; without it nxc
        # stops at the first hit and every column below that is a lie
        has_cont = ("--continue-on-success" in h)
        tflag = TIMEOUT_FLAG.get(proto)
        # Every --*-timeout this protocol's parser advertises. Checking only
        # the flag salvo already knows about can confirm the table but can
        # never catch upstream ADDING one, which is the direction that costs
        # you a false '-' over a tunnel.
        offered = sorted(offered_by.get(proto, set()) - generic)
        has_t = (tflag in offered) if tflag else False
        if tflag:
            shown = tflag + (" ok" if has_t else " MISSING")
        elif offered:
            shown = "none set - nxc offers " + ",".join(offered)
        else:
            shown = "none"
        print("  {:<10} {:<6} {:<13} {:<6} {:<6} {}".format(
            proto,
            "yes" if has_d else "no",
            "yes" if has_la else "no",
            "yes" if has_hash else "no",
            "yes" if has_cont else "NO",
            shown))
        if has_d != (proto in DOMAIN_CAPABLE):
            drift.append("DOMAIN_CAPABLE is wrong for {}".format(proto))
        if has_la != (proto in LOCAL_AUTH_CAPABLE):
            drift.append("LOCAL_AUTH_CAPABLE is wrong for {}".format(proto))
        if has_hash != (proto in HASH_CAPABLE):
            drift.append("HASH_CAPABLE is wrong for {}".format(proto))
        if not has_cont:
            drift.append("nxc {} does not define --continue-on-success, which "
                         "salvo sends to every protocol - every {} job would be "
                         "rejected".format(proto, proto))
        if tflag and not has_t:
            drift.append("TIMEOUT_FLAG[{}] = {} no longer exists".format(proto, tflag))
        if not tflag and offered:
            drift.append("nxc {} accepts {} but TIMEOUT_FLAG has no entry, so "
                         "--nxc-timeout never reaches it"
                         .format(proto, " / ".join(offered)))
    print("")
    if drift:
        print("[!] salvo's tables disagree with your nxc:")
        for d in drift:
            print("      " + d)
        print("    Fix the sets at the top of salvo.py before your next run.\n")
        return 1
    print("[*] capability tables match the installed NetExec.\n")
    return 0


def main():
    ap = argparse.ArgumentParser(
        prog="salvo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Spray one or many credentials across every nxc protocol at once.",
        epilog="""
examples
--------
  # one password, default protocol set, whole subnet
  salvo 192.168.100.0/24 -u jdoe -p 'Password123!' -d corp.local

  # a local admin hash recovered from a SAM dump, against three known hosts
  salvo 192.168.100.10 192.168.100.25 192.168.100.26 \\
      -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 --local-auth

  # every credential you have collected so far, against every host, both auth modes
  salvo targets.txt -C creds.txt -d corp.local --both-auth --markdown

  # resumable: if the VM hangs, re-run the IDENTICAL command. Answered jobs are
  # skipped, their results merged back in, and no account takes a second logon.
  salvo 192.168.100.0/24 -C creds.txt -d corp.local --state .salvo.state

  # start that scope over from scratch
  salvo --state .salvo.state --forget

  # show me the nxc commands, run nothing
  salvo 192.168.100.0/24 -u jdoe -p 'Password123!' -d corp.local --dry-run

  # low and slow - one protocol at a time, spaced, for a monitored network
  salvo 192.168.100.0/24 -u jdoe -p 'Password123!' -d corp.local --stealth

  # through a chisel / ssh -D SOCKS proxy (not needed with ligolo-ng)
  salvo 172.16.5.0/24 -u jdoe -p 'Password123!' -d corp.local --proxychains

  # after upgrading NetExec: does salvo still agree with it?
  salvo --check-nxc -P all
  salvo --selftest

idempotence
-----------
  Same arguments in, same bytes out - results are sorted, never printed in
  thread order. Duplicate credentials and targets are dropped before they cost
  you a logon. Logs and JSON are overwritten, not appended. With --state, a
  repeat run is a no-op; changing the credentials, protocols or target list
  changes the job signature, so a moved scope is never silently skipped.

creds.txt format
----------------
  jdoe:Password123!
  Administrator:31d6cfe0d16ae931b73c59d7e0c089c0
  CORP\\svc_sql:Winter2026!
""",
    )

    ap.add_argument("--version", action="version",
                    version="salvo {}".format(__version__))

    ap.add_argument("targets", nargs="*",
                    help="IPs, ranges, CIDRs, hostnames, or a file of them - anything nxc accepts")

    g = ap.add_argument_group("credentials")
    g.add_argument("-u", "--user", help="single username")
    g.add_argument("-p", "--password", help="single password")
    g.add_argument("-H", "--hash", dest="nthash", help="single NT hash (pass-the-hash)")
    g.add_argument("-C", "--creds", help="file of user:secret lines - hashes auto-detected")
    g.add_argument("-d", "--domain", help="domain for domain authentication")
    g.add_argument("--local-auth", action="store_true", help="authenticate as a LOCAL account")
    g.add_argument("--both-auth", action="store_true",
                   help="run every credential twice: once domain, once --local-auth")

    g = ap.add_argument_group("scope")
    g.add_argument("-P", "--protocols", default=",".join(DEFAULT_PW_PROTOCOLS),
                   help="comma list, or 'all'. default: " + ",".join(DEFAULT_PW_PROTOCOLS))
    # These default to None, not to their value, so --slow and --stealth can
    # fill in only what the operator left unset. A preset is a default, not an
    # override: '--nxc-timeout 60 --slow' has to stay 60.
    g.add_argument("--parallel", type=int, default=None,
                   help="concurrent nxc processes (default 6)")
    g.add_argument("--nxc-threads", type=int, default=None,
                   help="nxc's own -t per process (default 25, drop to 5 over a slow tunnel)")
    g.add_argument("--nxc-timeout", type=int, default=None,
                   help="seconds for nxc's PER-PROTOCOL timeout flag (default 15). "
                        "nxc's global --timeout is deprecated upstream and silently "
                        "ignored, so salvo emits --smb-timeout / --rpc-timeout / etc "
                        "instead. ldap, ftp and vnc define no such flag and run at "
                        "nxc's own default - see --check-nxc")
    g.add_argument("--jitter", help="nxc --jitter value, e.g. 2 or 1-3")
    g.add_argument("--job-delay", type=float, default=0.0, metavar="SECS",
                   help="sleep this long before each nxc process starts. nxc's "
                        "own --jitter only spaces attempts INSIDE one process; "
                        "this is the only thing that spaces salvo's processes apart")
    g.add_argument("--slow", action="store_true",
                   help="tunnel preset: parallel 3, nxc-threads 5, per-protocol timeout 30")
    g.add_argument("--stealth", action="store_true",
                   help="low and slow: parallel 1, nxc-threads 1, jitter 3-7, "
                        "job-delay 5, timeout 30. One protocol at a time, in order")

    g = ap.add_argument_group("pivoting")
    g.add_argument("--proxychains", action="store_true",
                   help="run every nxc under proxychains (for chisel / ssh -D SOCKS). "
                        "NOT needed with ligolo-ng, which routes in the kernel")
    g.add_argument("--proxychains-bin", default="proxychains4",
                   help="proxychains binary (default proxychains4)")

    g = ap.add_argument_group("output")
    g.add_argument("--markdown", action="store_true", help="emit the matrix as an Obsidian table")
    g.add_argument("--json", dest="jsonout", help="write all results to this JSON file")
    g.add_argument("--logdir", help="save raw nxc output per job into this directory")
    g.add_argument("--quiet", dest="stream", action="store_false", default=True,
                   help="suppress live lines, print only the matrix")
    g.add_argument("--dry-run", action="store_true", help="print the nxc commands and exit")

    g = ap.add_argument_group("safety")
    g.add_argument("--no-lockout-guard", action="store_true",
                   help="do NOT abort the run when a lockout is seen")
    g.add_argument("--nxc-bin", default="nxc", help="path to nxc (default: nxc on PATH)")
    g.add_argument("--scope", action="store_true",
                   help="print exactly which nxc flags salvo may and may not send, "
                        "from the lists that gate it at runtime, and exit")
    g.add_argument("--selftest", action="store_true",
                   help="run the output parser against known nxc line formats and exit")
    g.add_argument("--check-nxc", action="store_true",
                   help="ask the installed nxc which flags each protocol accepts and "
                        "compare against salvo's tables. Run after any NetExec upgrade")

    g = ap.add_argument_group("resume")
    g.add_argument("--state", metavar="FILE",
                   help="resume file. Jobs already answered here are skipped, and "
                        "their results merged into this run's matrix. Safe to "
                        "re-run the identical command after a crash or Ctrl-C.")
    g.add_argument("--no-resume", action="store_true",
                   help="with --state: ignore what is in the file, but still write to it")
    g.add_argument("--forget", action="store_true",
                   help="delete the --state file and exit")

    # A bare `salvo` should say what it is. Without this it falls through to
    # the targets guard and answers a first-time user with "no targets given"
    # and nothing else - true, but useless.
    if len(sys.argv) == 1:
        ap.print_help()
        sys.exit(1)

    args = ap.parse_args()

    if args.scope:
        sys.exit(print_scope())

    warn_about_other_installs()

    if args.selftest:
        print("\n[*] salvo parser self-test\n")
        sys.exit(selftest())

    if args.check_nxc:
        protos = (list(ALL_PROTOCOLS) if args.protocols.strip().lower() == "all"
                  else [x.strip().lower() for x in args.protocols.split(",") if x.strip()])
        sys.exit(check_nxc(args.nxc_bin, [x for x in protos if x in ALL_PROTOCOLS]))

    # --forget is a state-file operation, not a run. It must be handled before
    # the targets guard, or the documented 'salvo --state FILE --forget' exits
    # with "no targets given" instead of forgetting anything.
    if args.forget:
        if not args.state:
            sys.exit("[!] --forget needs --state FILE")
        removed = False
        for p in (args.state, args.state + ".tmp"):
            if os.path.isfile(p):
                os.remove(p)
                print("[*] removed " + p)
                removed = True
        if not removed:
            print("[*] nothing to forget - no such state file: " + args.state)
        return

    if not args.targets:
        sys.exit("[!] no targets given.")

    # --stealth wins over --slow when both are given; anything the operator
    # set explicitly wins over both.
    TUNING_DEFAULTS = {"parallel": 6, "nxc_threads": 25, "nxc_timeout": 15}
    preset = {}
    if args.slow:
        preset = {"parallel": 3, "nxc_threads": 5, "nxc_timeout": 30}
    if args.stealth:
        # Eight protocols fired at once across a subnet is a wall of failed
        # logons from one source address. This makes it a trickle instead:
        # one process, one thread, spaced apart at both levels.
        preset = {"parallel": 1, "nxc_threads": 1, "nxc_timeout": 30}
    explicit = {k for k in TUNING_DEFAULTS if getattr(args, k) is not None}
    for name, fallback in TUNING_DEFAULTS.items():
        if getattr(args, name) is None:
            setattr(args, name, preset.get(name, fallback))
    if preset and explicit:
        print("[*] keeping your explicit {} over the preset".format(
            ", ".join("--" + e.replace("_", "-") for e in sorted(explicit))))

    if args.parallel < 1 or args.nxc_threads < 1:
        sys.exit("[!] --parallel and --nxc-threads must be at least 1")

    if args.stealth:
        args.jitter = args.jitter or "3-7"
        args.job_delay = args.job_delay or 5.0
        print("[*] --stealth: {} process(es) at a time, {} nxc thread(s), "
              "jitter {}, {:.0f}s between jobs.".format(
                  args.parallel, args.nxc_threads, args.jitter, args.job_delay))
        print("    This is slow ON PURPOSE. A full 8-protocol sweep of one host "
              "will take minutes, not seconds.\n")

    if args.proxychains:
        if not shutil.which(args.proxychains_bin):
            sys.exit("[!] '{}' not found on PATH.".format(args.proxychains_bin))
        if args.nxc_threads > 5:
            # proxychains hooks libc socket calls and does not survive high
            # concurrency intact; connections get dropped and misread as '-'.
            args.nxc_threads = 5
            print("[*] --proxychains: capped nxc-threads at 5. Its socket "
                  "hooking is unreliable under heavy concurrency, and a dropped "
                  "connection here would render as a false '-'.")
        if not args.nxc_timeout or args.nxc_timeout < 20:
            args.nxc_timeout = 20
            print("[*] --proxychains: raised per-protocol timeout to 20s to "
                  "absorb SOCKS latency.")
        print("")

    if not args.dry_run and not shutil.which(args.nxc_bin):
        sys.exit("[!] '{}' not found on PATH. Install NetExec or pass --nxc-bin.".format(args.nxc_bin))

    # salvo parses nxc's human-readable output, so a result is only
    # interpretable against a known nxc. A report that cannot name the version
    # that produced it is a report nobody can reproduce.
    nxc_ver = None
    if not args.dry_run:
        nxc_ver = nxc_version(args.nxc_bin)
        print("[*] salvo {}  |  {}".format(
            __version__, nxc_ver or "nxc version could not be read"))

    # targets: drop exact repeats, keep the order given
    targets = []
    for t in args.targets:
        if t not in targets:
            targets.append(t)
    if len(targets) != len(args.targets):
        print("[*] dropped {} duplicate target(s)".format(len(args.targets) - len(targets)))
    args.targets = targets

    # ---- build credential list ------------------------------------------
    raw_creds = []
    if args.creds:
        if not os.path.isfile(args.creds):
            sys.exit("[!] no such creds file: " + args.creds)
        parsed, problems = parse_cred_file(args.creds)
        raw_creds += parsed
        for problem in problems:
            print("[!] {}: {}".format(args.creds, problem))
        if problems:
            print("    Those credentials are NOT being tested.\n")
    if args.user:
        if args.password and args.nthash:
            # Silently preferring one would put a credential in the report that
            # was never the one tested.
            sys.exit("[!] -p and -H are mutually exclusive - pass one, or list "
                     "both credentials in a -C file")
        if args.password:
            raw_creds.append((args.domain, args.user, args.password, False))
        elif args.nthash:
            raw_creds.append((args.domain, args.user, args.nthash, True))
        else:
            sys.exit("[!] -u needs -p or -H")
    if not raw_creds:
        sys.exit("[!] no credentials given. Use -u/-p, -u/-H, or -C.")

    creds = []
    seen_creds = set()
    dupes = 0
    for dom, user, secret, is_hash in raw_creds:
        dom = dom or args.domain
        if args.both_auth:
            variants = [(dom, False), (None, True)]
        else:
            variants = [(None if args.local_auth else dom, args.local_auth)]
        for vdom, vlocal in variants:
            c = Cred(user, secret, is_hash, vdom, vlocal, idx=len(creds))
            if c.key in seen_creds:
                dupes += 1
                continue
            seen_creds.add(c.key)
            creds.append(c)
    if dupes:
        print("[*] dropped {} duplicate credential(s) - each one would have been "
              "another logon against the lockout counter".format(dupes))

    # ---- protocols -------------------------------------------------------
    if args.protocols.strip().lower() == "all":
        protocols = list(ALL_PROTOCOLS)
    else:
        protocols = [p.strip().lower() for p in args.protocols.split(",") if p.strip()]
    bad = [p for p in protocols if p not in ALL_PROTOCOLS]
    if bad:
        sys.exit("[!] unknown protocol(s): {}. valid: {}".format(",".join(bad), ",".join(ALL_PROTOCOLS)))

    from_file_hashes = sorted({c.user for c in creds if c.is_hash}) if args.creds else []
    if from_file_hashes:
        print("[*] read as NT hashes: {} - a 32-hex-character password would be "
              "auto-detected the same way".format(", ".join(from_file_hashes)))

    if any(c.is_hash for c in creds):
        skipped = [p for p in protocols if p not in HASH_CAPABLE]
        if skipped:
            print("[*] hash credentials cannot pass-the-hash over: {} - skipping those jobs"
                  .format(", ".join(skipped)))
    if any(c.local for c in creds) and "ldap" in protocols:
        print("[*] ldap has no --local-auth in nxc (a bind is always domain-scoped) "
              "- skipping the local-auth ldap job rather than spending a logon on it")
    if "vnc" in protocols:
        print("[*] note: nxc vnc authenticates with a password only, the username is ignored")

    # Every output path is checked before a single logon is spent. A run that
    # sprays for two hours and then cannot write its report has lost the run,
    # and the authentication attempts are not refundable.
    if args.jsonout:
        ensure_writable(args.jsonout, "--json")
    if args.state:
        ensure_writable(args.state, "--state")

    if args.logdir:
        # Only tighten a directory salvo created. Clamping one the user already
        # had would be an unasked-for change to something outside our scope.
        fresh = not os.path.isdir(args.logdir)
        try:
            os.makedirs(args.logdir, exist_ok=True)
        except OSError as exc:
            sys.exit("[!] cannot create --logdir {}: {}".format(args.logdir, exc))
        if not os.access(args.logdir, os.W_OK):
            sys.exit("[!] --logdir is not writable: " + args.logdir)
        if fresh:
            os.chmod(args.logdir, PRIVATE_DIR_MODE)
        elif (os.stat(args.logdir).st_mode & 0o077):
            print("[*] note: {} is group/world readable and every log in it "
                  "contains the password.".format(args.logdir))

    # ---- resume store ----------------------------------------------------
    state = None
    if args.state:
        state = State(args.state)
        n = state.load()
        if args.no_resume:
            # Re-run everything, but keep what is already on disk. Wiping the
            # file here would throw away answers from an earlier scope.
            state.ignore = True
            print("[*] --no-resume: re-running all jobs; {} existing record(s) kept"
                  .format(n))
        elif n:
            print("[*] resume file has {} completed job(s): {}".format(n, args.state))

    # ---- dry run ---------------------------------------------------------
    if args.dry_run:
        runner = Runner(args, state)
        jobs = runner.plan(creds, protocols, args.targets)
        print("\n[commands that would run - {} of them{}]\n".format(
            len(jobs), ", {} skipped".format(runner.skipped) if runner.skipped else ""))
        for cred, proto, tgts, _sig in jobs:
            cmd = assert_authentication_only(runner.build_cmd(cred, proto, tgts))
            print("  " + " ".join(quote(c) for c in cmd))
        print("")
        return

    # ---- plan ------------------------------------------------------------
    runner = Runner(args, state)
    jobs = runner.plan(creds, protocols, args.targets)

    # ---- lockout arithmetic ---------------------------------------------
    # Every protocol against every host is a separate authentication attempt,
    # and a DOMAIN account's lockout counter lives on the DC regardless of
    # which member server you authenticated against. So the bill is
    # protocols x hosts, not protocols. Counted on the jobs that will ACTUALLY
    # run, so a resumed run does not warn about attempts it is not making.
    # CIDRs, ranges and target files are expanded rather than shrugged at.
    # "N per host, host count unknown" leaves the operator doing the one
    # multiplication the warning exists to do for them.
    host_count = count_hosts(args.targets)

    protos_per_user = {}
    for cred, proto, _t, _s in jobs:
        protos_per_user[cred.user] = protos_per_user.get(cred.user, 0) + 1

    # Every account at risk, not just the worst one. A second account also
    # over the threshold is a second lockout.
    at_risk = []
    for user, n_proto in sorted(protos_per_user.items()):
        worst = n_proto * host_count if host_count is not None else n_proto
        if worst > 3:
            at_risk.append((user, n_proto, worst))

    if at_risk:
        print("[!] LOCKOUT MATH - each protocol against each host is a separate logon,")
        print("    and a domain account's counter lives on the DC, so every host counts.")
        for user, n_proto, worst in at_risk:
            if host_count is None:
                print("      {:<24} up to {} logons PER HOST ({} protocol-jobs; the "
                      "target list could not be counted)".format(user, n_proto, n_proto))
            else:
                print("      {:<24} up to {} logons ({} protocol-jobs x {} hosts)"
                      .format(user, worst, n_proto, host_count))
        print("    Default AD lockout threshold is often 5. Check it first:")
        print("        nxc smb <DC_IP> -u '' -p '' --pass-pol")
        print("    Narrow with -P smb,winrm, or spread it out with --stealth.\n")

    # ---- go --------------------------------------------------------------
    runner.execute(jobs)
    runner.finalize()

    print(render_matrix(runner.hits, protocols, markdown=args.markdown,
                        overlay=runner.overlay))

    # what the run actually cost, as opposed to the worst case warned about
    real = runner.attempts_made()
    if real:
        print("AUTHENTICATION ATTEMPTS ACTUALLY MADE (a '-' never reached auth):")
        for user, n in sorted(real.items()):
            print("  {:<24} {}".format(user, n))
        print("")

    incon = inconclusive_report(runner.hits)
    if incon:
        print("NOT A VERDICT - these did not fail, they were blocked or unreadable:")
        print("\n".join(incon))
        print("  A credential in this list is still live. Take it to another protocol.\n")

    moves = next_moves(runner.hits)
    if moves:
        print("NEXT:")
        for m in moves:
            print(m)
        print("")

    if runner.job_failures:
        print("!" * 70)
        print("  {} job(s) never ran - nxc rejected the command salvo built.".format(
            len(runner.job_failures)))
        print("  Those cells are marked !CMD. They are NOT a statement about the target.")
        for proto, cred, rc, msg in sorted(runner.job_failures,
                                           key=lambda f: (f[0], f[1].user)):
            print("    {:6} {:<20} exit {}  {}".format(proto, cred.user, rc, msg[:90]))
        print("\n  asking nxc which flag it objected to:")
        for line in runner.diagnose_failures():
            print(line)
        print("!" * 70 + "\n")

    if runner.job_errors:
        print("!" * 70)
        print("  {} job(s) could not be run by salvo at all.".format(len(runner.job_errors)))
        print("  Those cells are marked err. They are NOT a statement about the target.")
        for proto, user, msg in sorted(runner.job_errors):
            print("    {:6} {:<20} {}".format(proto, user, msg[:100]))
        print("!" * 70 + "\n")

    # An impacket target is parsed positionally as domain/user:password@host,
    # so a password carrying one of its separators makes the pasted command
    # mean something else. Cheaper to say than to debug at 2am.
    risky = sorted({c.user for c in creds
                    if not c.is_hash and any(ch in c.secret for ch in "@:/")})
    if risky:
        print("[!] the password for {} contains @, : or / - impacket parses "
              "domain/user:password@target positionally, so the commands above "
              "need care rather than a straight paste.\n".format(", ".join(risky)))

    notes = runner.advisories()   # computed once: it probes and it is not free
    for note in notes:
        print("[!] " + note)
    if notes:
        print("")

    if args.jsonout:
        proto_rank = {p: i for i, p in enumerate(protocols)}
        results = sorted(
            (h.as_dict() for h in runner.hits),
            key=lambda r: (r["user"], r["secret"], bool(r["local_auth"]),
                           proto_rank.get(r["protocol"], 99),
                           ip_sort_key(r["ip"]), r["raw"]),
        )
        # A consumer of this file faces the same ambiguity the matrix does:
        # a protocol with no rows could be a dead port or a job that was never
        # run. Name the second case explicitly rather than leaving it as an
        # absence to be misread.
        not_run = sorted(
            ({"user": ck[0], "secret": ck[1], "is_hash": ck[2],
              "domain": ck[3], "local_auth": ck[4],
              "protocol": proto, "reason": why}
             for (ck, proto), why in runner.not_run.items()),
            key=lambda r: (r["user"], r["secret"], bool(r["local_auth"]),
                           proto_rank.get(r["protocol"], 99)),
        )
        write_json_atomic(args.jsonout, {
            # Provenance first: a report that cannot say what produced it, from
            # where, against what, is not evidence.
            "salvo_version": __version__,
            "nxc_version": nxc_ver,
            "generated": now_iso(),
            "targets": args.targets,
            "host_count": host_count,
            "protocols": protocols,
            # exactly what was sent at the estate, for the client who asks
            "commands": sorted(runner.commands),
            "results": results,
            "not_run": not_run,
        })
        print("[*] json written to " + args.jsonout)

    if state:
        state.save()
        print("[*] resume state: {} ({} job(s) recorded)".format(args.state, len(state.jobs)))


def cli():
    """
    Console-script entry point.

    The installed `salvo` command calls this, not main(), so the interrupt,
    scope and broken-pipe handling below applies to it exactly as it does to
    `python3 salvo.py`.
    """
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] interrupted")
    except ScopeViolation as exc:
        sys.exit("\n[!] REFUSING TO RUN - {}\n    This is salvo's "
                 "authentication-only guard. Nothing was sent.\n".format(exc))
    except BrokenPipeError:
        # Piped into head, less, or a pager the operator quit. Python flushes
        # stdout again on the way out, which would raise a second time and
        # print an "Exception ignored" block over their terminal, so point the
        # descriptor at devnull before exiting.
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        sys.exit(0)


if __name__ == "__main__":
    cli()

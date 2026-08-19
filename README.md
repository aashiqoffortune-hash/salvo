# salvo

Spray one or many credentials across **every NetExec protocol at once** and read the result as a matrix.

`nxc` takes one protocol per invocation. Testing a credential properly means running it eight times and reading eight scrollbacks. `salvo` runs them concurrently and prints one table — with an honest verdict in every cell.

```
host                       smb   winrm     wmi   mssql    ldap     rdp     ssh     ftp
--------------------------------------------------------------------------------------
192.168.100.10 (DC01)       ok       ?       ?   ADMIN      ok  VALID*       -       - <
192.168.100.25 (WEB01)   ADMIN       ?       ?      ok      ok  VALID*    exec       . <
192.168.100.26 (SQL01)      ok       ?       ?   ADMIN      ok  VALID*       -       - <

  ADMIN  = provably administrative (smb admin-share write, mssql sysadmin)
  exec   = code execution, NOT admin - check the smb column before assuming
  ok     = authenticated    VALID* = password correct, this access path blocked
  ?      = cannot tell, retest elsewhere    . = refused    - = no service / no answer
```

Stdlib only. No pip, no virtualenv, no dependencies beyond `nxc` itself.

---

## Why

Two design decisions do the real work.

### 1. Three verdict buckets, not two

Most tooling has *worked* and *failed*. Collapsing everything else into *failed* is how a live credential gets thrown away.

| bucket | meaning |
|---|---|
| **valid** | `ADMIN`, `exec`, `ok` — the credential authenticated |
| **blocked** | `VALID*` — the password is **provably correct**, but this access path is closed |
| **unknown** | `?` — the service refused without saying why; it cannot be told apart from an authorization denial |

`VALID*` covers `STATUS_LOGON_TYPE_NOT_GRANTED`, `STATUS_ACCOUNT_DISABLED`, `STATUS_PASSWORD_EXPIRED`, `STATUS_PASSWORD_MUST_CHANGE`, and workstation or logon-hour restrictions. All of them mean the password checked out.

`?` is mostly WinRM. **A WinRM refusal is not an invalid credential** — a valid account that simply isn't in `Remote Management Users` looks byte-identical to a wrong password.

Under the matrix, a **NOT A VERDICT** block lists every blocked and unknown result with its reason. A credential in that list is still live.

### 2. `Pwn3d!` means different things on different protocols

NetExec prints `(Pwn3d!)` for several unrelated conditions. Treating them as one thing is a real trap, so `salvo` separates them:

| protocol | what `Pwn3d!` actually proves | rendered |
|---|---|---|
| `smb` | write access to `ADMIN$` / `C$` | `ADMIN` |
| `mssql` | `sysadmin` role on the instance | `ADMIN` |
| `winrm` | the account can execute — `Remote Management Users` grants this **with no admin rights at all** | `exec` |
| `ssh` | a uid-0 / passwordless-sudo probe that returns nonsense against Windows OpenSSH | `exec` |
| `wmi`, `rdp`, `ftp`, `vnc`, `nfs`, `ldap` | execution or access at best | `exec` |

If no protocol proved admin on a host, the follow-up commands say so:

```
NEXT:
  192.168.100.25 (WEB01)   winrm:exec, ssh:exec, smb:ok   [no admin proven on this host]
      evil-winrm -i 192.168.100.25 -u jdoe -p 'Password123!'   # NOT local admin here - expect to land as a standard user
```

---

## Install

```bash
git clone https://github.com/aashiqoffortune-hash/salvo.git
cd salvo
install -m 755 salvo.py ~/bin/salvo   # or anywhere on PATH
salvo --help
```

Requires Python 3.8+ and [NetExec](https://github.com/Pennyw0rth/NetExec) on `PATH`.

---

## Usage

```bash
# one password, every protocol, whole subnet
salvo 192.168.100.0/24 -u jdoe -p 'Password123!' -d corp.local

# an NT hash against three known hosts, local authentication
salvo 192.168.100.10 192.168.100.25 192.168.100.26 \
    -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 --local-auth

# every credential you hold, both auth scopes, table for your notes
salvo targets.txt -C creds.txt -d corp.local --both-auth --markdown

# over a slow tunnel
salvo 10.10.100.0/24 -C creds.txt -d corp.local --slow

# print the nxc commands, run nothing
salvo 192.168.100.0/24 -u jdoe -p 'Password123!' -d corp.local --dry-run
```

`creds.txt` — hashes are auto-detected (32 hex, or the `LM:NT` pair form):

```
jdoe:Password123!
Administrator:31d6cfe0d16ae931b73c59d7e0c089c0
CORP\svc_sql:Winter2026!
```

Hash credentials automatically skip `ssh`, `ftp`, `nfs` and `vnc` — you cannot pass-the-hash over those.

---

## Resume

Add `--state` and a repeat run is free. Answered jobs are skipped and their results merged back in, so the matrix stays complete even though no single process ever saw all of it.

```bash
salvo 10.10.100.0/24 -C creds.txt -d corp.local --state .salvo.state
# ... connection drops, VM hangs, whatever ...
salvo 10.10.100.0/24 -C creds.txt -d corp.local --state .salvo.state
#   [*] resume file has 18 completed job(s)
#   [*] 8 nxc process(es), 6 at a time  (18 skipped, already answered)

salvo --state .salvo.state --forget    # start the scope over
```

This is not only about time. Every skipped job is an authentication attempt **not** made against a lockout counter.

Each job is keyed on a hash of the credential, the protocol **and** the target list, so changing scope never silently skips anything. A job is recorded only if `nxc` exited cleanly and the run wasn't aborted — killed, crashed and lockout-aborted jobs stay unrecorded and retry. `Ctrl-C` still prints the matrix and saves state.

---

## Lockout safety

Every protocol against every host is a separate authentication attempt, and a domain account's counter lives on the DC regardless of which member server you hit. `salvo` does the arithmetic before it starts:

```
[!] LOCKOUT MATH: 'jdoe' will take up to 24 logons (8 protocol-jobs x 3 hosts).
    A domain account's counter is on the DC, so every host counts.
    Default AD lockout threshold is often 5. Check it first:
        nxc smb <DC_IP> -u '' -p '' --pass-pol
```

and reports what it actually cost afterwards, since a `-` cell never reached authentication:

```
AUTHENTICATION ATTEMPTS ACTUALLY MADE (a '-' never reached auth):
  jdoe                     12
```

If any host returns `STATUS_ACCOUNT_LOCKED_OUT` mid-run, every remaining process is killed immediately rather than finishing the sweep. `--no-lockout-guard` disables that.

**Check the password policy before you point this at a domain.**

---

## Authentication only

`salvo` never passes `-x`, `-X`, `-M`, `--sam`, `--lsa`, `--ntds` or any other execution or dumping flag to `nxc`. It logs in, reports, and stops. It is a scheduler for a tool you would otherwise run by hand, eight times.

If you are operating under rules that restrict tooling, confirm those rules yourself. That design intent is a reading, not a ruling.

---

## Options

| flag | default | description |
|---|---|---|
| `<targets>` | — | IPs, ranges, CIDRs, hostnames, or a file — anything `nxc` accepts |
| `-u`, `--user` | — | single username |
| `-p`, `--password` | — | single password |
| `-H`, `--hash` | — | single NT hash (pass-the-hash) |
| `-C`, `--creds` | — | file of `user:secret` lines |
| `-d`, `--domain` | — | domain authentication |
| `--local-auth` | off | authenticate as a local account |
| `--both-auth` | off | run every credential domain **and** local |
| `-P`, `--protocols` | `smb,winrm,wmi,mssql,ldap,rdp,ssh,ftp` | comma list, or `all` |
| `--parallel` | 6 | concurrent `nxc` processes |
| `--nxc-threads` | 25 | `nxc`'s own `-t` per process |
| `--nxc-timeout` | 15 | `nxc --timeout` seconds |
| `--jitter` | — | `nxc --jitter` value |
| `--slow` | off | tunnel preset: 3 / 5 / 30 |
| `--markdown` | off | matrix as a Markdown table |
| `--json` | — | write all results as JSON |
| `--logdir` | — | raw `nxc` output, one file per job |
| `--quiet` | off | suppress live lines |
| `--dry-run` | off | print the `nxc` commands, run nothing |
| `--state` | — | resume file |
| `--no-resume` | off | re-run everything, keep existing records |
| `--forget` | off | delete the state file and exit |
| `--no-lockout-guard` | off | do not abort on lockout |
| `--nxc-bin` | `nxc` | path to `nxc` |

---

## Notes

- **Deterministic.** Same arguments in, same bytes out. Results are sorted, never printed in thread-arrival order, so two runs diff cleanly.
- **Idempotent.** Duplicate credentials and targets are dropped before they cost a logon. Logs and JSON are overwritten, never appended. Log filenames carry a credential fingerprint, so two passwords for one user don't overwrite each other's evidence.
- **Advisory on undeclared domains.** If a target's SMB banner advertises a domain you didn't pass with `-d`, it says so — `ldap` and Kerberos-backed results are unreliable without it.
- Parsing is against `nxc`'s human-readable output. A future format change upstream could break it; `--logdir` keeps the raw text either way.

## Credits

Built on [NetExec](https://github.com/Pennyw0rth/NetExec) by @NeffIsBack, @MJHallenbeck and @\_zblurx. Multi-protocol mode is [an open feature request upstream](https://github.com/Pennyw0rth/NetExec/issues/1249); until it lands, this wraps it.

## License

MIT

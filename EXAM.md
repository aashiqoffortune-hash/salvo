# salvo and OffSec exam rules

salvo automates credential validation, and automation is the thing exam rules
are most careful about. This document sets out exactly what salvo does, what
it refuses to do, and how that maps onto OffSec's published restrictions, so
you can make the call yourself rather than take a README's word for it.

**Read this as an argument, not a ruling.** OffSec's exam guide is the
authority, it changes, and OffSec will not comment on individual tools beyond
what the guide says. Verify against the current guide for your exam before you
sit it:

- [OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
- [OSCP+ Exam FAQ](https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ)

---

## The rules that apply

Four restrictions in the OSCP/OSCP+ guide could plausibly touch a tool like
this one.

**Automated exploitation is prohibited.** The guide names `db_autopwn`,
`browser_autopwn`, SQLmap and SQLninja. The stated principle is that the exam
evaluates your skill at identifying and exploiting vulnerabilities, not at
automating the process.

**Automated enumeration is permitted.** The guide draws the line here
explicitly: tools that perform automatic *enumeration* are allowed; tools that
perform automatic *exploitation* are not.

**Mass vulnerability scanners are prohibited.** Nessus, NeXpose, OpenVAS,
Canvas, Core Impact, SAINT.

**Spoofing is prohibited** — IP, ARP, DNS, NBNS. Responder appears on the
allowed list specifically with poisoning and spoofing excluded.

Two further points matter for anything that wraps another tool:

**CrackMapExec / NetExec is on the allowed list**, alongside Impacket,
evil-winrm, BloodHound and SharpHound, Rubeus, PowerView and Mimikatz.
Metasploit and Meterpreter are separately restricted to a single target
machine of your choosing.

**You are responsible for knowing what your tools do.** The guide puts the
obligation on the candidate to know what features and external utilities any
chosen tool is using. Custom scripts in Python or similar are permitted on the
same terms — you are expected to understand what you are running.

---

## What salvo actually does

salvo runs `nxc <protocol> <targets> -u <user> -p <secret>` concurrently
across protocols, reads the output, and prints a matrix. That is the entire
behaviour.

It builds command lines from a fixed allowlist and **refuses to run anything
outside it**. This is not a policy in a document; it is a check in
`assert_authentication_only()` that runs immediately before every process
spawn and aborts the run if any unrecognised flag appears:

```
$ salvo --scope
```

prints the two lists straight out of the code that gates it. The flags salvo
will never send:

```
-x  -X  -M  --module                       command execution
--sam  --lsa  --ntds  --dpapi  --laps      credential dumping
--shares  --users  --groups  --rid-brute   enumeration beyond authentication
--pass-pol  --kerberoasting  --asreproast  --bloodhound
--put-file  --get-file  --exec-method
```

The test suite asserts this across every protocol and every credential shape
on every commit, so a future patch that reaches for an execution flag fails CI
before it reaches anyone's exam.

---

## The mapping

| Restriction | salvo |
|---|---|
| Automated exploitation | Does not exploit. It authenticates and reports. No exploit is selected, launched or chained; the guard above makes execution flags unreachable. |
| Automated enumeration | This is what salvo is. Credential validation across protocols is enumeration of which logins work, and it is the permitted side of the line. |
| Mass vulnerability scanners | Not a scanner. It tests no vulnerabilities, has no signature or plugin set, and reports no findings — only whether a credential authenticated. |
| Spoofing and poisoning | Does none. No packet is forged, no name service answered, no traffic relayed. It makes ordinary authentication attempts from your own address. |
| Metasploit / Meterpreter limit | Never invokes either. Unaffected, and it does not consume your one permitted machine. |
| Allowed tooling | The only thing salvo executes is `nxc`, which is on the allowed list. Nothing else is spawned. |
| Knowing what your tool does | `--dry-run` prints every command it would run and runs nothing. `--scope` prints what it may and may not send. The `--json` report records every command actually executed. |

### One point worth being precise about

salvo's **NEXT** section suggests follow-up commands — `evil-winrm`,
`impacket-psexec`, and `nxc ldap --bloodhound` / `--kerberoasting`. Those are
printed text, not actions. salvo never runs them, and `--bloodhound` and
`--kerberoasting` are on its own refusal list even though BloodHound and
Rubeus are themselves permitted tools. Whether to run a suggestion, and under
which rules, is your decision and your keystroke.

---

## Where salvo helps with the rules rather than tests them

Two of its behaviours exist because of exam and engagement constraints, not in
spite of them.

**Lockout arithmetic.** Every protocol against every host is a separate logon
against a counter you cannot see, and a domain account's counter lives on the
DC regardless of which member server you touched. salvo prints the worst case
for every account before it starts, reports what the run actually cost, and
kills every remaining process the moment a real `STATUS_ACCOUNT_LOCKED_OUT`
appears. Locking the exam's domain administrator is a bad afternoon.

**Resume.** `--state` records answered jobs, so re-running after a VM hang
re-fires only what is unanswered. Every skipped job is an authentication
attempt *not* made.

---

## If you are still unsure

Run `salvo --dry-run` and read the commands. They are plain `nxc`
authentication invocations that you could have typed yourself, one protocol at
a time — which is precisely what salvo is: a scheduler for a tool you are
already permitted to run, saving you from running it eight times and reading
eight scrollbacks.

If your reading of your own exam's rules differs, follow your reading. The
guide is the authority.

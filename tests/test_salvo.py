"""
Test suite for salvo.

Stdlib only, like salvo itself - no pip, no virtualenv, runnable on a bare
Kali box straight after `git clone`:

    python3 -m unittest discover -s tests -v

pytest collects unittest.TestCase classes too, if you happen to have it.
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import salvo  # noqa: E402

SALVO_PY = os.path.join(ROOT, "salvo.py")


def args_ns(**over):
    """A stand-in for the argparse namespace, carrying main()'s defaults."""
    ns = types.SimpleNamespace(
        nxc_bin="nxc", nxc_threads=25, nxc_timeout=15, jitter=None,
        proxychains=False, proxychains_bin="proxychains4",
        logdir=None, stream=False, job_delay=0.0, parallel=6,
        domain=None, local_auth=False, no_lockout_guard=False,
    )
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


def pw(user="jdoe", secret="Password123!", **kw):
    return salvo.Cred(user, secret, False, **kw)


def nt(user="Administrator", secret="31d6cfe0d16ae931b73c59d7e0c089c0", **kw):
    return salvo.Cred(user, secret, True, **kw)


# ---------------------------------------------------------------------------
# The scope invariant.
#
# salvo's stated design rule is that it authenticates and reports, and never
# asks nxc to execute or dump anything. That is the whole basis for running it
# under restricted-tooling rules, and it is a property of build_cmd, so it can
# be asserted rather than believed.
# ---------------------------------------------------------------------------

# flags that would turn salvo from a login scheduler into something else
EXECUTION_AND_DUMP_FLAGS = {
    "-x", "-X", "-M", "--module",
    "--sam", "--lsa", "--ntds", "--dpapi", "--laps",
    "--shares", "--users", "--groups", "--rid-brute", "--pass-pol",
    "--kerberoasting", "--asreproast", "--bloodhound",
    "--put-file", "--get-file", "--exec-method",
}

# every flag build_cmd is allowed to emit, and whether it consumes the next token
VALUE_FLAGS = {"-t", "--jitter", "-u", "-p", "-H", "-d"} | set(salvo.TIMEOUT_FLAG.values())
BARE_FLAGS = {"--no-progress", "--local-auth", "--continue-on-success", "-q"}


def cred_matrix():
    """Every shape of credential salvo can be handed."""
    return [
        pw(),
        pw(domain="corp.local"),
        pw(local=True),
        nt(),
        nt(domain="corp.local"),
        nt(local=True),
    ]


class TestAuthenticationOnlyScope(unittest.TestCase):
    def test_no_execution_or_dump_flag_is_ever_built(self):
        runner = salvo.Runner(args_ns(), None)
        for cred in cred_matrix():
            for proto in salvo.ALL_PROTOCOLS:
                cmd = runner.build_cmd(cred, proto, ["10.0.0.1"])
                for bad in EXECUTION_AND_DUMP_FLAGS:
                    self.assertNotIn(
                        bad, cmd,
                        "{} leaked into the {} command line".format(bad, proto))

    def test_every_emitted_flag_is_on_the_allowlist(self):
        """
        Stronger than a denylist: a flag added to build_cmd in future fails
        here until it is consciously added to the allowlist above.
        """
        runner = salvo.Runner(args_ns(jitter="1-3", proxychains=True), None)
        for cred in cred_matrix():
            for proto in salvo.ALL_PROTOCOLS:
                cmd = runner.build_cmd(cred, proto, ["10.0.0.1"])
                i = 0
                while i < len(cmd):
                    tok = cmd[i]
                    if tok in VALUE_FLAGS:
                        i += 2          # skip the flag's value
                        continue
                    if tok in BARE_FLAGS or not tok.startswith("-"):
                        i += 1
                        continue
                    self.fail("{} emitted an unexpected flag {!r}".format(proto, tok))


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------

class TestBuildCmd(unittest.TestCase):
    def setUp(self):
        self.runner = salvo.Runner(args_ns(), None)

    def test_generic_options_precede_the_protocol(self):
        """nxc's number one syntax trap: generic flags must come first."""
        cmd = salvo.Runner(args_ns(jitter="2"), None).build_cmd(
            pw(domain="corp.local"), "smb", ["10.0.0.1"])
        proto_at = cmd.index("smb")
        for generic in ("-t", "--jitter", "--no-progress"):
            self.assertLess(cmd.index(generic), proto_at,
                            "{} must precede the protocol".format(generic))
        for protocol_arg in ("-u", "-p", "-d", "--continue-on-success"):
            self.assertGreater(cmd.index(protocol_arg), proto_at,
                               "{} must follow the protocol".format(protocol_arg))

    def test_domain_is_withheld_from_protocols_with_no_domain_concept(self):
        for proto in ("ssh", "ftp", "nfs", "vnc"):
            cmd = self.runner.build_cmd(pw(domain="corp.local"), proto, ["10.0.0.1"])
            self.assertNotIn("-d", cmd, "{} has no -d in nxc".format(proto))
            self.assertIn(proto, self.runner.domain_dropped)

    def test_domain_is_sent_to_protocols_that_define_it(self):
        for proto in sorted(salvo.DOMAIN_CAPABLE):
            cmd = self.runner.build_cmd(pw(domain="corp.local"), proto, ["10.0.0.1"])
            self.assertIn("-d", cmd)
            self.assertEqual(cmd[cmd.index("-d") + 1], "corp.local")

    def test_local_auth_is_never_sent_to_ldap(self):
        """A directory bind is domain-scoped; nxc ldap defines no --local-auth."""
        cmd = self.runner.build_cmd(pw(local=True), "ldap", ["10.0.0.1"])
        self.assertNotIn("--local-auth", cmd)

    def test_local_auth_is_sent_where_it_exists(self):
        for proto in sorted(salvo.LOCAL_AUTH_CAPABLE):
            cmd = self.runner.build_cmd(pw(local=True), proto, ["10.0.0.1"])
            self.assertIn("--local-auth", cmd)

    def test_hash_uses_H_and_password_uses_p(self):
        self.assertIn("-H", self.runner.build_cmd(nt(), "smb", ["10.0.0.1"]))
        self.assertNotIn("-p", self.runner.build_cmd(nt(), "smb", ["10.0.0.1"]))
        self.assertIn("-p", self.runner.build_cmd(pw(), "smb", ["10.0.0.1"]))
        self.assertNotIn("-H", self.runner.build_cmd(pw(), "smb", ["10.0.0.1"]))

    def test_per_protocol_timeout_flag_not_the_deprecated_global(self):
        cmd = self.runner.build_cmd(pw(), "smb", ["10.0.0.1"])
        self.assertIn("--smb-timeout", cmd)
        self.assertNotIn("--timeout", cmd)

    def test_protocols_without_a_timeout_flag_get_none(self):
        for proto in ("ldap", "ftp", "vnc"):
            cmd = self.runner.build_cmd(pw(), proto, ["10.0.0.1"])
            self.assertFalse([c for c in cmd if c.endswith("-timeout")],
                             "{} should carry no timeout flag".format(proto))

    def test_proxychains_wraps_the_invocation(self):
        cmd = salvo.Runner(args_ns(proxychains=True), None).build_cmd(
            pw(), "smb", ["10.0.0.1"])
        self.assertEqual(cmd[:2], ["proxychains4", "-q"])
        self.assertEqual(cmd[2], "nxc")

    def test_continue_on_success_is_always_present(self):
        """Without it nxc stops at the first hit and the matrix is a lie."""
        for proto in salvo.ALL_PROTOCOLS:
            self.assertIn("--continue-on-success",
                          self.runner.build_cmd(pw(), proto, ["10.0.0.1"]))


# ---------------------------------------------------------------------------
# Output classification - the verdict table
# ---------------------------------------------------------------------------

class TestClassify(unittest.TestCase):
    def test_pwn3d_means_different_things_per_protocol(self):
        line = "[+] corp.local\\jdoe:Password123! (Pwn3d!)"
        self.assertEqual(salvo.classify("smb", line)[0], salvo.ADMIN)
        self.assertEqual(salvo.classify("mssql", line)[0], salvo.ADMIN)
        # the trap: Remote Management Users grants this with no admin rights
        self.assertEqual(salvo.classify("winrm", line)[0], salvo.EXEC)
        self.assertEqual(salvo.classify("ssh", line)[0], salvo.EXEC)
        self.assertEqual(salvo.classify("rdp", line)[0], salvo.EXEC)

    def test_plain_success_is_authenticated_not_admin(self):
        status, _ = salvo.classify("smb", "[+] corp.local\\jdoe:Password123!")
        self.assertEqual(status, salvo.VALID)

    def test_password_correct_failures_are_not_invalid(self):
        """The whole point of the tool: these mean the password checked out."""
        for code in ("STATUS_LOGON_TYPE_NOT_GRANTED", "STATUS_ACCOUNT_DISABLED",
                     "STATUS_PASSWORD_EXPIRED", "STATUS_PASSWORD_MUST_CHANGE",
                     "STATUS_ACCOUNT_EXPIRED", "STATUS_ACCOUNT_RESTRICTION",
                     "STATUS_INVALID_LOGON_HOURS", "STATUS_INVALID_WORKSTATION"):
            status, _ = salvo.classify("smb", "[-] corp\\jdoe:Pw " + code)
            self.assertEqual(status, salvo.CRED_OK_ACCESS_NO,
                             "{} must not be filed as a failure".format(code))

    def test_lockout_is_its_own_bucket(self):
        status, _ = salvo.classify("smb", "[-] corp\\jdoe:Pw STATUS_ACCOUNT_LOCKED_OUT")
        self.assertEqual(status, salvo.LOCKED)

    def test_confirmed_wrong_credentials(self):
        for code in ("STATUS_LOGON_FAILURE", "STATUS_NO_SUCH_USER",
                     "KDC_ERR_PREAUTH_FAILED"):
            status, _ = salvo.classify("smb", "[-] corp\\jdoe:Pw " + code)
            self.assertEqual(status, salvo.INVALID)

    def test_bare_refusal_is_inconclusive_on_ambiguous_protocols(self):
        """A valid account outside Remote Management Users looks like a bad password."""
        for proto in sorted(salvo.AMBIGUOUS_BARE_FAILURE):
            status, _ = salvo.classify(proto, "[-] corp.local\\jdoe:Password123!")
            self.assertEqual(status, salvo.INCONCLUSIVE, proto)

    def test_bare_refusal_is_invalid_where_it_is_unambiguous(self):
        status, _ = salvo.classify("ssh", "[-] jdoe:Password123!")
        self.assertEqual(status, salvo.INVALID)

    def test_banner_lines_are_not_verdicts(self):
        self.assertEqual(salvo.classify("smb", "[*] Windows 10.0 Build 19044"), (None, None))

    def test_access_denied_keeps_the_credential_alive(self):
        status, _ = salvo.classify("ldap", "[-] corp\\jdoe:Pw STATUS_ACCESS_DENIED")
        self.assertEqual(status, salvo.INCONCLUSIVE)

    def test_every_status_has_a_glyph_and_a_severity(self):
        for name in (salvo.ADMIN, salvo.EXEC, salvo.VALID, salvo.CRED_OK_ACCESS_NO,
                     salvo.INCONCLUSIVE, salvo.INVALID, salvo.LOCKED,
                     salvo.NO_SERVICE, salvo.ERROR, salvo.USAGE, salvo.NOT_RUN):
            self.assertIn(name, salvo.GLYPH)
            self.assertIn(name, salvo.SEVERITY)


class TestLineParsing(unittest.TestCase):
    def test_ansi_colour_is_stripped(self):
        self.assertEqual(salvo.strip_ansi("\x1b[1;32m[+]\x1b[0m ok"), "[+] ok")

    def test_standard_line_shape(self):
        m = salvo.LINE_RE.match(
            "SMB         192.168.100.25  445    WEB01            [+] corp\\jdoe:Pw")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("ip"), "192.168.100.25")
        self.assertEqual(m.group("port"), "445")
        self.assertEqual(m.group("host"), "WEB01")

    def test_selftest_corpus_still_passes(self):
        """The parser regression net, asserted rather than printed."""
        for proto, line, expect in salvo.SELFTEST:
            m = salvo.LINE_RE.match(salvo.strip_ansi(line))
            self.assertIsNotNone(m, line)
            rest = m.group("rest").strip()
            host = m.group("host")
            if host.startswith("["):
                rest = (host + " " + rest).strip()
            self.assertEqual(salvo.classify(proto, rest)[0], expect, line)


# ---------------------------------------------------------------------------
# Planning, and the jobs salvo declines to run
# ---------------------------------------------------------------------------

class TestPlan(unittest.TestCase):
    def test_hash_creds_skip_protocols_that_cannot_pass_the_hash(self):
        runner = salvo.Runner(args_ns(), None)
        protos = ["smb", "winrm", "ssh", "ftp", "nfs", "vnc"]
        jobs = runner.plan([nt()], protos, ["10.0.0.1"])
        self.assertEqual(sorted(j[1] for j in jobs), ["smb", "winrm"])
        for proto in ("ssh", "ftp", "nfs", "vnc"):
            self.assertIn((nt().key, proto), runner.not_run)

    def test_local_auth_skips_ldap(self):
        runner = salvo.Runner(args_ns(), None)
        jobs = runner.plan([pw(local=True)], ["smb", "ldap"], ["10.0.0.1"])
        self.assertEqual([j[1] for j in jobs], ["smb"])
        self.assertIn((pw(local=True).key, "ldap"), runner.not_run)

    def test_a_skipped_job_is_recorded_not_dropped(self):
        """
        The regression this guards: a dropped job left an empty cell, and an
        empty cell renders '-', documented as "no service". Nothing was sent.
        """
        runner = salvo.Runner(args_ns(), None)
        runner.plan([nt()], ["ssh"], ["10.0.0.1"])
        self.assertTrue(runner.not_run)
        self.assertIn("-H", list(runner.not_run.values())[0])

    def test_nothing_is_skipped_for_an_ordinary_password(self):
        runner = salvo.Runner(args_ns(), None)
        protos = list(salvo.DEFAULT_PW_PROTOCOLS)
        jobs = runner.plan([pw(domain="corp.local")], protos, ["10.0.0.1"])
        self.assertEqual(len(jobs), len(protos))
        self.assertEqual(runner.not_run, {})


# ---------------------------------------------------------------------------
# Matrix rendering
# ---------------------------------------------------------------------------

def hit(cred, proto, ip="192.168.100.25", status=None, host="WEB01", raw="[+] x"):
    return salvo.Hit(cred, proto, ip, 445, host, status or salvo.VALID, "note", raw)


class TestMatrix(unittest.TestCase):
    def test_never_run_renders_n_a_not_no_service(self):
        cred = nt(local=True)
        runner = salvo.Runner(args_ns(), None)
        protos = ["smb", "ssh"]
        runner.plan([cred], protos, ["192.168.100.25"])
        out = salvo.render_matrix([hit(cred, "smb", status=salvo.ADMIN)],
                                  protos, not_run=runner.not_run)
        ssh_row = [l for l in out.splitlines() if "192.168.100.25" in l][0]
        self.assertIn("n/a", ssh_row)
        self.assertIn("ADMIN", ssh_row)
        self.assertIn("salvo ran NO job here", out)

    def test_a_job_that_ran_and_got_nothing_still_renders_dash(self):
        cred = pw()
        out = salvo.render_matrix([hit(cred, "smb", status=salvo.ADMIN)],
                                  ["smb", "winrm"], not_run={})
        row = [l for l in out.splitlines() if "192.168.100.25" in l][0]
        self.assertIn("-", row)
        self.assertNotIn("n/a", row)

    def test_skip_reasons_group_onto_one_line(self):
        cred = nt()
        runner = salvo.Runner(args_ns(), None)
        protos = ["smb", "ssh", "ftp", "nfs"]
        runner.plan([cred], protos, ["10.0.0.1"])
        out = salvo.render_matrix([hit(cred, "smb")], protos, not_run=runner.not_run)
        # one explanation for all three, not the same sentence three times
        # (the legend also mentions n/a, so match on the reason text itself)
        self.assertEqual(out.count("nxc defines no -H here"), 1, out)
        self.assertIn("ssh, ftp, nfs", out)

    def test_output_is_deterministic_regardless_of_arrival_order(self):
        cred = pw()
        a = hit(cred, "smb", ip="192.168.100.25", status=salvo.ADMIN)
        b = hit(cred, "smb", ip="192.168.100.9", status=salvo.VALID)
        c = hit(cred, "winrm", ip="192.168.100.25", status=salvo.EXEC)
        first = salvo.render_matrix([a, b, c], ["smb", "winrm"])
        second = salvo.render_matrix([c, a, b], ["smb", "winrm"])
        self.assertEqual(first, second)

    def test_hosts_sort_numerically_not_lexically(self):
        cred = pw()
        hits = [hit(cred, "smb", ip="192.168.100.9"),
                hit(cred, "smb", ip="192.168.100.10")]
        out = salvo.render_matrix(hits, ["smb"])
        self.assertLess(out.index("192.168.100.9"), out.index("192.168.100.10"))

    def test_collapse_keeps_the_most_significant_result(self):
        cred = pw()
        best = salvo.collapse([
            hit(cred, "smb", status=salvo.VALID),
            hit(cred, "smb", status=salvo.ADMIN),
            hit(cred, "smb", status=salvo.INVALID),
        ])
        self.assertEqual(list(best.values())[0].status, salvo.ADMIN)

    def test_markdown_carries_the_skip_reason_too(self):
        cred = nt()
        runner = salvo.Runner(args_ns(), None)
        runner.plan([cred], ["smb", "ssh"], ["10.0.0.1"])
        out = salvo.render_matrix([hit(cred, "smb")], ["smb", "ssh"],
                                  markdown=True, not_run=runner.not_run)
        self.assertIn("n/a", out)
        self.assertIn("no -H", out)


class TestIpSortKey(unittest.TestCase):
    def test_ipv4_sorts_numerically(self):
        addrs = ["10.0.0.2", "10.0.0.10", "10.0.0.1"]
        self.assertEqual(sorted(addrs, key=salvo.ip_sort_key),
                         ["10.0.0.1", "10.0.0.2", "10.0.0.10"])

    def test_hostnames_sort_after_addresses(self):
        addrs = ["dc01.corp.local", "10.0.0.1"]
        self.assertEqual(sorted(addrs, key=salvo.ip_sort_key)[0], "10.0.0.1")


# ---------------------------------------------------------------------------
# Credential input
# ---------------------------------------------------------------------------

class TestCredFile(unittest.TestCase):
    def parse(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(text)
            path = fh.name
        try:
            return salvo.parse_cred_file(path)
        finally:
            os.unlink(path)

    def test_plain_pairs(self):
        self.assertEqual(self.parse("jdoe:Password123!\n"),
                         [(None, "jdoe", "Password123!", False)])

    def test_domain_prefix_is_split_out(self):
        dom, user, secret, is_hash = self.parse("CORP\\svc_sql:Winter2026!\n")[0]
        self.assertEqual((dom, user, secret, is_hash),
                         ("CORP", "svc_sql", "Winter2026!", False))

    def test_nt_hash_is_detected(self):
        self.assertTrue(self.parse("Administrator:31d6cfe0d16ae931b73c59d7e0c089c0\n")[0][3])

    def test_lm_nt_pair_is_detected(self):
        line = "Administrator:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n"
        dom, user, secret, is_hash = self.parse(line)[0]
        self.assertTrue(is_hash)
        self.assertIn(":", secret)

    def test_password_containing_a_colon_survives(self):
        self.assertEqual(self.parse("jdoe:pa:ss:word\n")[0][2], "pa:ss:word")

    def test_comments_and_blanks_are_ignored(self):
        self.assertEqual(self.parse("# note\n\njdoe:Pw\n"), [(None, "jdoe", "Pw", False)])

    def test_a_password_that_looks_like_a_hash_is_treated_as_one(self):
        """Documented behaviour, asserted so a change to it is deliberate."""
        self.assertTrue(salvo.looks_like_hash("31d6cfe0d16ae931b73c59d7e0c089c0"))
        self.assertFalse(salvo.looks_like_hash("Password123!"))


# ---------------------------------------------------------------------------
# Resume state
# ---------------------------------------------------------------------------

class TestState(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "s.state")

    def tearDown(self):
        for f in os.listdir(self.dir):
            os.unlink(os.path.join(self.dir, f))
        os.rmdir(self.dir)

    def test_round_trip(self):
        cred = pw()
        st = salvo.State(self.path)
        sig = salvo.job_signature(cred, "smb", ["10.0.0.1"])
        st.complete(sig, cred, "smb", ["10.0.0.1"], [hit(cred, "smb", status=salvo.ADMIN)])
        st.save()

        again = salvo.State(self.path)
        self.assertEqual(again.load(), 1)
        self.assertTrue(again.is_done(sig))
        restored = again.prior_hits(sig, cred)
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].status, salvo.ADMIN)

    def test_signature_changes_when_the_scope_moves(self):
        cred = pw()
        a = salvo.job_signature(cred, "smb", ["10.0.0.1"])
        self.assertNotEqual(a, salvo.job_signature(cred, "smb", ["10.0.0.1", "10.0.0.2"]))
        self.assertNotEqual(a, salvo.job_signature(cred, "winrm", ["10.0.0.1"]))
        self.assertNotEqual(a, salvo.job_signature(pw(secret="other"), "smb", ["10.0.0.1"]))

    def test_signature_is_stable_for_the_same_scope(self):
        cred = pw()
        self.assertEqual(salvo.job_signature(cred, "smb", ["10.0.0.2", "10.0.0.1"]),
                         salvo.job_signature(cred, "smb", ["10.0.0.1", "10.0.0.2"]))

    def test_a_future_version_file_is_not_trusted(self):
        with open(self.path, "w") as fh:
            json.dump({"version": salvo.STATE_VERSION + 1, "jobs": {"x": {}}}, fh)
        st = salvo.State(self.path)
        self.assertEqual(st.load(), 0)

    def test_a_corrupt_file_starts_fresh_instead_of_raising(self):
        with open(self.path, "w") as fh:
            fh.write("{not json")
        self.assertEqual(salvo.State(self.path).load(), 0)

    def test_completed_jobs_are_skipped_and_their_results_merged(self):
        cred = pw()
        st = salvo.State(self.path)
        sig = salvo.job_signature(cred, "smb", ["10.0.0.1"])
        st.complete(sig, cred, "smb", ["10.0.0.1"], [hit(cred, "smb", status=salvo.ADMIN)])

        runner = salvo.Runner(args_ns(), st)
        jobs = runner.plan([cred], ["smb", "winrm"], ["10.0.0.1"])
        self.assertEqual([j[1] for j in jobs], ["winrm"])
        self.assertEqual(runner.skipped, 1)
        self.assertEqual(len(runner.hits), 1)      # the earlier result came forward

    def test_no_resume_reruns_everything(self):
        cred = pw()
        st = salvo.State(self.path)
        sig = salvo.job_signature(cred, "smb", ["10.0.0.1"])
        st.complete(sig, cred, "smb", ["10.0.0.1"], [])
        st.ignore = True
        runner = salvo.Runner(args_ns(), st)
        self.assertEqual(len(runner.plan([cred], ["smb"], ["10.0.0.1"])), 1)


# ---------------------------------------------------------------------------
# Anything written to disk carries the plaintext credential
# ---------------------------------------------------------------------------

class TestFilePermissions(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        for f in os.listdir(self.dir):
            os.unlink(os.path.join(self.dir, f))
        os.rmdir(self.dir)

    def mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def test_state_and_json_are_owner_only(self):
        path = os.path.join(self.dir, "out.json")
        salvo.write_json_atomic(path, {"secret": "Winter2026!"})
        self.assertEqual(self.mode(path), 0o600)

    def test_logs_are_owner_only(self):
        path = os.path.join(self.dir, "smb.log")
        with salvo.open_private(path) as fh:
            fh.write("SMB 10.0.0.1 445 DC01 [+] corp\\jdoe:Password123!\n")
        self.assertEqual(self.mode(path), 0o600)

    def test_an_existing_wide_open_file_is_tightened_on_rewrite(self):
        path = os.path.join(self.dir, "old.json")
        with open(path, "w") as fh:
            fh.write("{}")
        os.chmod(path, 0o644)
        salvo.write_json_atomic(path, {"secret": "Winter2026!"})
        self.assertEqual(self.mode(path), 0o600)

    def test_the_temp_file_never_outlives_a_successful_write(self):
        path = os.path.join(self.dir, "out.json")
        salvo.write_json_atomic(path, {"a": 1})
        self.assertFalse(os.path.exists(path + ".tmp"))


# ---------------------------------------------------------------------------
# CLI entry points
# ---------------------------------------------------------------------------

FAKE_NXC = os.path.join(ROOT, "tests", "fake_nxc.py")


def run_cli(*argv, **kw):
    env = dict(os.environ)
    env.update(kw.pop("env", {}))
    return subprocess.run([sys.executable, SALVO_PY] + list(argv),
                          capture_output=True, text=True, timeout=120, env=env)


class TestCli(unittest.TestCase):
    def test_selftest_passes(self):
        r = run_cli("--selftest")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_forget_does_not_require_targets(self):
        """
        Regression: --forget sat behind the targets guard, so the command
        printed in the README exited with "no targets given".
        """
        with tempfile.NamedTemporaryFile("w", suffix=".state", delete=False) as fh:
            fh.write('{"version": 1, "jobs": {}}')
            path = fh.name
        try:
            r = run_cli("--state", path, "--forget")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertFalse(os.path.exists(path))
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_forget_without_state_is_an_error(self):
        self.assertNotEqual(run_cli("--forget").returncode, 0)

    def test_password_and_hash_together_is_refused(self):
        r = run_cli("10.0.0.1", "-u", "jdoe", "-p", "pw",
                    "-H", "31d6cfe0d16ae931b73c59d7e0c089c0", "--dry-run")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("mutually exclusive", r.stdout + r.stderr)

    def test_dry_run_prints_commands_and_contacts_nothing(self):
        r = run_cli("10.0.0.1", "-u", "jdoe", "-p", "Password123!",
                    "-d", "corp.local", "-P", "smb,winrm", "--dry-run")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("nxc", r.stdout)
        self.assertIn("smb", r.stdout)

    def test_unknown_protocol_is_rejected(self):
        r = run_cli("10.0.0.1", "-u", "j", "-p", "p", "-P", "telnet", "--dry-run")
        self.assertNotEqual(r.returncode, 0)

    def test_credentials_are_required(self):
        self.assertNotEqual(run_cli("10.0.0.1", "--dry-run").returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ---------------------------------------------------------------------------
# End to end, against a fake nxc.
#
# run_one is where the subprocess, the parser, the log writer and the state
# store meet, and none of it is reachable from a unit test. tests/fake_nxc.py
# emits real nxc line shapes so the whole path runs with no network and no
# NetExec install.
# ---------------------------------------------------------------------------

class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.json = os.path.join(self.dir, "out.json")
        self.state = os.path.join(self.dir, "s.state")
        self.logs = os.path.join(self.dir, "logs")

    def tearDown(self):
        import shutil as _sh
        _sh.rmtree(self.dir, ignore_errors=True)

    def run_salvo(self, *extra, **kw):
        base = ["10.0.0.10", "10.0.0.11", "-u", "jdoe", "-p", "Password123!",
                "-d", "corp.local", "--nxc-bin", FAKE_NXC, "--quiet"]
        return run_cli(*(base + list(extra)), **kw)

    def test_full_run_renders_every_bucket(self):
        r = self.run_salvo("-P", "smb,winrm,ldap,ssh")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = r.stdout
        self.assertIn("ADMIN", out)      # smb Pwn3d on the DC
        self.assertIn("VALID*", out)     # LOGON_TYPE_NOT_GRANTED is not a failure
        self.assertIn("?", out)          # bare winrm refusal stays unknown
        self.assertIn("NOT A VERDICT", out)

    def test_attempts_made_excludes_cells_that_never_reached_auth(self):
        r = self.run_salvo("-P", "smb,winrm,ldap,ssh")
        self.assertIn("AUTHENTICATION ATTEMPTS ACTUALLY MADE", r.stdout)
        # smb 2 + winrm 2 + ldap 1; ssh answered nothing and is not billed
        line = [l for l in r.stdout.splitlines() if l.strip().startswith("jdoe")][-1]
        self.assertEqual(line.split()[-1], "5")

    def test_json_report_is_written_and_well_formed(self):
        self.run_salvo("-P", "smb,winrm", "--json", self.json)
        with open(self.json) as fh:
            doc = json.load(fh)
        self.assertEqual(sorted(doc),
                         ["generated", "not_run", "protocols", "results", "targets"])
        self.assertTrue(doc["results"])
        self.assertTrue(any(r["status"] == salvo.ADMIN for r in doc["results"]))

    def test_json_names_the_jobs_that_never_ran(self):
        r = run_cli("10.0.0.10", "-u", "Administrator",
                    "-H", "31d6cfe0d16ae931b73c59d7e0c089c0",
                    "--local-auth", "-P", "smb,ssh,ftp",
                    "--nxc-bin", FAKE_NXC, "--quiet", "--json", self.json)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        with open(self.json) as fh:
            doc = json.load(fh)
        self.assertEqual(sorted(e["protocol"] for e in doc["not_run"]), ["ftp", "ssh"])
        self.assertIn("n/a", r.stdout)

    def test_everything_written_to_disk_is_owner_only(self):
        self.run_salvo("-P", "smb", "--json", self.json,
                       "--state", self.state, "--logdir", self.logs)
        self.assertEqual(stat.S_IMODE(os.stat(self.json).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.state).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.logs).st_mode), 0o700)
        for name in os.listdir(self.logs):
            self.assertEqual(
                stat.S_IMODE(os.stat(os.path.join(self.logs, name)).st_mode), 0o600,
                "{} echoes the password back".format(name))

    def test_a_resumed_run_spends_no_further_logons(self):
        first = self.run_salvo("-P", "smb,winrm", "--state", self.state)
        self.assertIn("2 nxc process(es)", first.stdout)

        second = self.run_salvo("-P", "smb,winrm", "--state", self.state)
        self.assertIn("resume file has 2 completed job(s)", second.stdout)
        self.assertIn("nothing left to run", second.stdout)
        # the matrix is still complete even though this process ran nothing
        self.assertIn("ADMIN", second.stdout)

    def test_forget_clears_the_scope(self):
        self.run_salvo("-P", "smb", "--state", self.state)
        self.assertTrue(os.path.exists(self.state))
        r = run_cli("--state", self.state, "--forget")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(os.path.exists(self.state))

    def test_a_rejected_command_is_marked_not_reported_as_a_closed_port(self):
        """
        nxc exiting on a usage error used to render as '-'. It must render
        !CMD and say so, because it is salvo's bug, not the target's state.
        """
        r = self.run_salvo("-P", "smb,winrm", "--state", self.state,
                           env={"FAKE_NXC_FAIL": "1"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("!CMD", r.stdout)
        self.assertIn("never ran", r.stdout)
        # and it must NOT be recorded as done, or the retry would be skipped.
        # With every job rejected there is nothing to record, so the state
        # file is legitimately never created.
        recorded = {}
        if os.path.exists(self.state):
            with open(self.state) as fh:
                recorded = json.load(fh)["jobs"]
        self.assertEqual(recorded, {})

    def test_a_rejected_job_is_retried_on_the_next_run(self):
        self.run_salvo("-P", "smb", "--state", self.state,
                       env={"FAKE_NXC_FAIL": "1"})
        good = self.run_salvo("-P", "smb", "--state", self.state)
        self.assertIn("1 nxc process(es)", good.stdout)
        self.assertIn("ADMIN", good.stdout)

"""
Test suite for salvo.

Stdlib only, like salvo itself - no pip, no virtualenv, runnable on a bare
Kali box straight after `git clone`:

    python3 -m unittest discover -s tests -v

pytest collects unittest.TestCase classes too, if you happen to have it.
"""

import io
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

# These are salvo's own lists, not a copy of them. They gate the tool at
# runtime, so asserting against them here checks the thing that actually runs.
EXECUTION_AND_DUMP_FLAGS = salvo.NEVER_SENT
VALUE_FLAGS = salvo.ALLOWED_VALUE_FLAGS
BARE_FLAGS = salvo.ALLOWED_BARE_FLAGS


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

    def test_the_guard_refuses_every_flag_it_names(self):
        """The refusal list is enforced, not decorative."""
        for bad in sorted(salvo.NEVER_SENT):
            with self.assertRaises(salvo.ScopeViolation):
                salvo.assert_authentication_only(
                    ["nxc", "smb", "10.0.0.1", "-u", "a", "-p", "b", bad])

    def test_the_guard_passes_a_real_command(self):
        runner = salvo.Runner(args_ns(), None)
        for proto in salvo.ALL_PROTOCOLS:
            for cred in cred_matrix():
                cmd = runner.build_cmd(cred, proto, ["10.0.0.1"])
                self.assertIs(salvo.assert_authentication_only(cmd), cmd)

    def test_a_password_that_looks_like_a_flag_does_not_trip_the_guard(self):
        """The token after -p is a value, not a flag, however it is spelled."""
        runner = salvo.Runner(args_ns(), None)
        cmd = runner.build_cmd(pw(secret="-x whoami"), "smb", ["10.0.0.1"])
        salvo.assert_authentication_only(cmd)

    def test_nothing_spawns_when_the_guard_trips(self):
        """The refusal happens before the packet, not after the report."""
        runner = salvo.Runner(args_ns(), None)
        spawned = []

        def popen(cmd, **kw):
            spawned.append(cmd)
            raise AssertionError("must not spawn")

        real_build = runner.build_cmd
        runner.build_cmd = lambda c, p, t: real_build(c, p, t) + ["--sam"]
        real_popen = salvo.subprocess.Popen
        salvo.subprocess.Popen = popen
        try:
            with self.assertRaises(salvo.ScopeViolation):
                runner.run_one(pw(), "smb", ["10.0.0.1"], "sig")
        finally:
            salvo.subprocess.Popen = real_popen
        self.assertEqual(spawned, [])


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
            self.assertIn((nt().key, proto), runner.overlay)

    def test_local_auth_skips_ldap(self):
        runner = salvo.Runner(args_ns(), None)
        jobs = runner.plan([pw(local=True)], ["smb", "ldap"], ["10.0.0.1"])
        self.assertEqual([j[1] for j in jobs], ["smb"])
        self.assertIn((pw(local=True).key, "ldap"), runner.overlay)

    def test_a_skipped_job_is_recorded_not_dropped(self):
        """
        The regression this guards: a dropped job left an empty cell, and an
        empty cell renders '-', documented as "no service". Nothing was sent.
        """
        runner = salvo.Runner(args_ns(), None)
        runner.plan([nt()], ["ssh"], ["10.0.0.1"])
        self.assertTrue(runner.overlay)
        status, reason = list(runner.overlay.values())[0]
        self.assertEqual(status, salvo.NOT_RUN)
        self.assertIn("-H", reason)

    def test_nothing_is_skipped_for_an_ordinary_password(self):
        runner = salvo.Runner(args_ns(), None)
        protos = list(salvo.DEFAULT_PW_PROTOCOLS)
        jobs = runner.plan([pw(domain="corp.local")], protos, ["10.0.0.1"])
        self.assertEqual(len(jobs), len(protos))
        self.assertEqual(runner.overlay, {})


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
                                  protos, overlay=runner.overlay)
        ssh_row = [l for l in out.splitlines() if "192.168.100.25" in l][0]
        self.assertIn("n/a", ssh_row)
        self.assertIn("ADMIN", ssh_row)
        self.assertIn("salvo ran NO job here", out)

    def test_a_job_that_ran_and_got_nothing_still_renders_dash(self):
        cred = pw()
        out = salvo.render_matrix([hit(cred, "smb", status=salvo.ADMIN)],
                                  ["smb", "winrm"], overlay={})
        row = [l for l in out.splitlines() if "192.168.100.25" in l][0]
        self.assertIn("-", row)
        self.assertNotIn("n/a", row)

    def test_skip_reasons_group_onto_one_line(self):
        cred = nt()
        runner = salvo.Runner(args_ns(), None)
        protos = ["smb", "ssh", "ftp", "nfs"]
        runner.plan([cred], protos, ["10.0.0.1"])
        out = salvo.render_matrix([hit(cred, "smb")], protos, overlay=runner.overlay)
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
                                  markdown=True, overlay=runner.overlay)
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
        return self.parse_full(text)[0]

    def problems(self, text):
        return self.parse_full(text)[1]

    def parse_full(self, text):
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
        self.assertEqual(sorted(doc), [
            "commands", "generated", "host_count", "not_run", "nxc_version",
            "protocols", "results", "salvo_version", "targets"])
        self.assertEqual(doc["salvo_version"], salvo.__version__)
        self.assertIn("fake", doc["nxc_version"])
        self.assertTrue(doc["commands"])
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


# ---------------------------------------------------------------------------
# Address handling and the lockout arithmetic
# ---------------------------------------------------------------------------

class TestHostCounting(unittest.TestCase):
    def test_a_malformed_address_is_not_an_address(self):
        """The old regex accepted this and gave it a row in the matrix."""
        self.assertFalse(salvo.is_literal_ip("192.168.1.999"))
        self.assertFalse(salvo.is_literal_ip("10.0.0.0/24"))
        self.assertTrue(salvo.is_literal_ip("10.0.0.1"))
        self.assertTrue(salvo.is_literal_ip("::1"))

    def test_cidr_is_expanded_rather_than_shrugged_at(self):
        self.assertEqual(salvo.count_hosts(["10.0.0.0/24"]), 256)
        self.assertEqual(salvo.count_hosts(["10.0.0.0/30"]), 4)

    def test_octet_range_is_counted(self):
        self.assertEqual(salvo.count_hosts(["10.0.0.20-40"]), 21)

    def test_a_hostname_counts_as_one_host(self):
        self.assertEqual(salvo.count_hosts(["dc01.corp.local"]), 1)

    def test_mixed_targets_add_up(self):
        self.assertEqual(salvo.count_hosts(["10.0.0.1", "10.0.0.8/30", "srv"]), 6)

    def test_a_target_file_is_read_and_counted(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# hosts\n10.0.0.1\n10.0.0.8/30\ndc01\n")
            path = fh.name
        try:
            self.assertEqual(salvo.count_hosts([path]), 6)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Process hygiene
# ---------------------------------------------------------------------------

class FakeProc(object):
    def __init__(self, text=""):
        self.stdout = io.StringIO(text)
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


class TestProcessHygiene(unittest.TestCase):
    def spawn_with(self, runner, popen):
        real = salvo.subprocess.Popen
        salvo.subprocess.Popen = popen
        try:
            runner.run_one(pw(), "smb", ["10.0.0.1"], "sig")
        finally:
            salvo.subprocess.Popen = real

    def test_nxc_never_inherits_the_operators_terminal(self):
        """
        Six concurrent nxc processes sharing salvo's stdin will eat the
        keystrokes meant for salvo.
        """
        seen = {}
        self.spawn_with(salvo.Runner(args_ns(), None),
                        lambda cmd, **kw: (seen.update(kw), FakeProc())[1])
        self.assertEqual(seen.get("stdin"), salvo.subprocess.DEVNULL)

    def test_output_decoding_never_raises(self):
        """A non-UTF-8 byte in a hostname must not take the job down."""
        seen = {}
        self.spawn_with(salvo.Runner(args_ns(), None),
                        lambda cmd, **kw: (seen.update(kw), FakeProc())[1])
        self.assertEqual(seen.get("errors"), "replace")

    def test_the_spawn_is_guarded_against_the_lockout_sweep(self):
        """
        The abort check and the spawn have to be atomic. If they are not, a
        job that passed the check just before a lockout was detected spawns
        after kill_all has swept, and spends a logon on a locked account.
        """
        runner = salvo.Runner(args_ns(), None)
        held = []

        def popen(cmd, **kw):
            # same thread: a plain Lock cannot be re-acquired if it is held
            held.append(not runner.proc_lock.acquire(blocking=False))
            return FakeProc()

        self.spawn_with(runner, popen)
        self.assertEqual(held, [True], "the process lock was not held across the spawn")

    def test_finished_processes_are_not_retained(self):
        runner = salvo.Runner(args_ns(), None)
        self.spawn_with(runner, lambda cmd, **kw: FakeProc())
        self.assertEqual(runner.procs, [], "a long run would carry every process it started")

    def test_a_process_that_cannot_start_becomes_a_visible_cell(self):
        runner = salvo.Runner(args_ns(), None)

        def boom(cmd, **kw):
            raise OSError(13, "Permission denied")

        self.spawn_with(runner, boom)
        self.assertIn((pw().key, "smb"), runner.overlay)
        self.assertTrue(runner.job_errors)

    def test_the_command_actually_sent_is_recorded_for_audit(self):
        runner = salvo.Runner(args_ns(), None)
        self.spawn_with(runner, lambda cmd, **kw: FakeProc())
        self.assertEqual(len(runner.commands), 1)
        self.assertIn("smb", runner.commands[0])


# ---------------------------------------------------------------------------
# Credential file problems are reported, never swallowed
# ---------------------------------------------------------------------------

class TestCredFileProblems(unittest.TestCase):
    def problems(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(text)
            path = fh.name
        try:
            return salvo.parse_cred_file(path)[1]
        finally:
            os.unlink(path)

    def test_a_line_with_no_separator_is_named_by_number(self):
        problems = self.problems("jdoe:Pw\ngarbage\n")
        self.assertEqual(len(problems), 1)
        self.assertIn("line 2", problems[0])

    def test_an_empty_secret_is_refused_not_sprayed(self):
        problems = self.problems("jdoe:\n")
        self.assertEqual(len(problems), 1)
        self.assertIn("empty secret", problems[0])

    def test_an_empty_username_is_refused(self):
        self.assertIn("empty username", self.problems(":Password1\n")[0])

    def test_a_clean_file_reports_nothing(self):
        self.assertEqual(self.problems("# note\n\njdoe:Pw\nCORP\\svc:Pw2\n"), [])


# ---------------------------------------------------------------------------
# Overlay rendering for jobs that failed rather than were skipped
# ---------------------------------------------------------------------------

class TestOverlayRendering(unittest.TestCase):
    def test_a_rejected_job_renders_cmd_not_dash(self):
        cred = pw()
        overlay = {(cred.key, "winrm"): (salvo.USAGE, "nxc exited 2")}
        out = salvo.render_matrix([hit(cred, "smb", status=salvo.ADMIN)],
                                  ["smb", "winrm"], overlay=overlay)
        row = [l for l in out.splitlines() if "192.168.100.25" in l][0]
        self.assertIn("!CMD", row)

    def test_an_errored_job_renders_err(self):
        cred = pw()
        overlay = {(cred.key, "winrm"): (salvo.ERROR, "could not start nxc")}
        out = salvo.render_matrix([hit(cred, "smb", status=salvo.ADMIN)],
                                  ["smb", "winrm"], overlay=overlay)
        self.assertIn("err", [c.strip() for c in
                              [l for l in out.splitlines() if "192.168.100.25" in l][0].split()])

    def test_reasons_are_still_reported_when_nothing_answered(self):
        """No hits at all used to print 'no results' and drop every reason."""
        cred = nt()
        runner = salvo.Runner(args_ns(), None)
        runner.plan([cred], ["ssh"], ["10.0.0.1"])
        out = salvo.render_matrix([], ["ssh"], overlay=runner.overlay)
        self.assertIn("no -H", out)
        self.assertNotEqual(out.strip(), "no results.")


# ---------------------------------------------------------------------------
# Operator-facing CLI behaviour
# ---------------------------------------------------------------------------

class TestOperatorCli(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil as _sh
        _sh.rmtree(self.dir, ignore_errors=True)

    def test_version_is_reportable(self):
        r = run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn(salvo.__version__, r.stdout + r.stderr)

    def test_an_explicit_setting_beats_a_preset(self):
        """--slow is a set of defaults, not an override of what was asked for."""
        r = run_cli("10.0.0.1", "-u", "j", "-p", "p", "-P", "smb",
                    "--slow", "--nxc-timeout", "60", "--dry-run")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("--smb-timeout 60", r.stdout)

    def test_a_preset_still_applies_where_nothing_was_asked_for(self):
        r = run_cli("10.0.0.1", "-u", "j", "-p", "p", "-P", "smb",
                    "--slow", "--dry-run")
        self.assertIn("--smb-timeout 30", r.stdout)

    def test_an_unwritable_report_path_fails_before_any_logon(self):
        r = run_cli("10.0.0.10", "-u", "j", "-p", "p", "-P", "smb",
                    "--nxc-bin", FAKE_NXC, "--quiet",
                    "--json", os.path.join(self.dir, "no", "such", "out.json"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not exist", r.stdout + r.stderr)
        # and nothing was sprayed on the way to finding out
        self.assertNotIn("nxc process(es)", r.stdout)

    def test_an_unwritable_state_path_fails_before_any_logon(self):
        r = run_cli("10.0.0.10", "-u", "j", "-p", "p", "-P", "smb",
                    "--nxc-bin", FAKE_NXC, "--quiet",
                    "--state", os.path.join(self.dir, "nope", "s.state"))
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("nxc process(es)", r.stdout)

    def test_unreadable_credential_lines_are_reported(self):
        path = os.path.join(self.dir, "creds.txt")
        with open(path, "w") as fh:
            fh.write("jdoe:Password123!\nthis-line-is-broken\n")
        r = run_cli("10.0.0.1", "-C", path, "-P", "smb", "--dry-run")
        self.assertIn("line 2", r.stdout)
        self.assertIn("NOT being tested", r.stdout)

    def test_lockout_math_counts_a_cidr_and_names_every_account(self):
        path = os.path.join(self.dir, "creds.txt")
        with open(path, "w") as fh:
            fh.write("jdoe:Password123!\nsvc_sql:Winter2026!\n")
        r = run_cli("10.0.0.0/29", "-C", path, "-P", "smb,winrm",
                    "--nxc-bin", FAKE_NXC, "--quiet")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("2 protocol-jobs x 8 hosts", r.stdout)
        self.assertIn("jdoe", r.stdout)
        self.assertIn("svc_sql", r.stdout)

    def test_parallel_must_be_sane(self):
        r = run_cli("10.0.0.1", "-u", "j", "-p", "p", "--parallel", "0", "--dry-run")
        self.assertNotEqual(r.returncode, 0)


class TestEndToEndFailureModes(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.state = os.path.join(self.dir, "s.state")

    def tearDown(self):
        import shutil as _sh
        _sh.rmtree(self.dir, ignore_errors=True)

    def salvo(self, *extra, **kw):
        base = ["10.0.0.10", "10.0.0.11", "-u", "jdoe", "-p", "Password123!",
                "-d", "corp.local", "--nxc-bin", FAKE_NXC, "--quiet"]
        return run_cli(*(base + list(extra)), **kw)

    def test_a_lockout_stops_the_run_and_is_not_recorded_as_done(self):
        r = self.salvo("-P", "smb,winrm,ldap", "--state", self.state,
                       env={"FAKE_NXC_LOCKOUT": "1"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("LOCKOUT DETECTED", r.stderr)
        # an aborted run must leave nothing marked complete, or the retry
        # would skip exactly the jobs that never finished
        recorded = {}
        if os.path.exists(self.state):
            with open(self.state) as fh:
                recorded = json.load(fh)["jobs"]
        self.assertEqual(recorded, {})

    def test_undecodable_output_does_not_kill_the_job(self):
        r = self.salvo("-P", "smb", env={"FAKE_NXC_BINARY": "1"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("ADMIN", r.stdout)
        self.assertNotIn("Traceback", r.stdout + r.stderr)

    def test_the_report_names_the_nxc_that_produced_it(self):
        r = self.salvo("-P", "smb")
        self.assertIn("salvo " + salvo.__version__, r.stdout)
        self.assertIn("nxc 1.5.0-fake", r.stdout)


# ---------------------------------------------------------------------------
# Degenerate inputs
# ---------------------------------------------------------------------------

class TestDegradedInputs(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "s.state")

    def tearDown(self):
        import shutil as _sh
        _sh.rmtree(self.dir, ignore_errors=True)

    def test_a_salvo_side_failure_never_renders_as_a_closed_port(self):
        """
        classify_error reads "timed out" out of a message and returns
        NO_SERVICE, which renders '-'. For salvo's own failure that would
        state something about the target that salvo never learned.
        """
        runner = salvo.Runner(args_ns(), None)
        runner.record_job_error(pw(), "smb", "could not start nxc: timed out")
        status, _reason = runner.overlay[(pw().key, "smb")]
        self.assertEqual(status, salvo.ERROR)
        self.assertNotEqual(status, salvo.NO_SERVICE)

    def test_a_state_file_with_no_job_table_starts_fresh(self):
        with open(self.path, "w") as fh:
            json.dump({"version": salvo.STATE_VERSION, "jobs": "not a dict"}, fh)
        self.assertEqual(salvo.State(self.path).load(), 0)

    def test_an_unrebuildable_result_forces_a_re_run(self):
        """An extra logon beats a fabricated verdict."""
        cred = pw()
        sig = salvo.job_signature(cred, "smb", ["10.0.0.1"])
        with open(self.path, "w") as fh:
            json.dump({"version": salvo.STATE_VERSION,
                       "jobs": {sig: {"hits": [{"protocol": "smb"}]}}}, fh)
        st = salvo.State(self.path)
        st.load()
        self.assertEqual(st.prior_hits(sig, cred), [])

    def test_the_live_line_survives_an_unexpected_status(self):
        cred = pw()
        line = salvo.fmt_live(salvo.Hit(cred, "smb", "10.0.0.1", 445, "DC01",
                                        salvo.NOT_RUN, "n", ""))
        self.assertIn("smb", line)

    def test_piping_into_head_does_not_traceback(self):
        """An operator pipes into head or less constantly."""
        import shlex as _sh
        cmd = "{} {} 10.0.0.10 -u j -p p -P smb,winrm --nxc-bin {} --quiet | head -2".format(
            _sh.quote(sys.executable), _sh.quote(SALVO_PY), _sh.quote(FAKE_NXC))
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        self.assertNotIn("BrokenPipeError", r.stderr)
        self.assertNotIn("Traceback", r.stderr)


# ---------------------------------------------------------------------------
# Packaging and installation
# ---------------------------------------------------------------------------

class TestPackaging(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "pyproject.toml")) as fh:
            self.toml = fh.read()

    def test_the_distribution_is_not_named_salvo(self):
        """
        `salvo` on PyPI is an unrelated HTTP load tester, so `pip install
        salvo` would install a stranger's package.
        """
        self.assertIn('name = "salvo-nxc"', self.toml)

    def test_the_installed_command_is_salvo(self):
        self.assertIn('salvo = "salvo:cli"', self.toml)

    def test_the_entry_point_exists_and_is_not_main(self):
        """
        The console script must go through cli(), or the interrupt, scope and
        broken-pipe handling would apply only to `python3 salvo.py`.
        """
        self.assertTrue(callable(salvo.cli))
        self.assertIsNot(salvo.cli, salvo.main)

    def test_it_declares_no_dependencies(self):
        self.assertIn("dependencies = []", self.toml)

    def test_the_version_is_single_sourced(self):
        self.assertIn('version = { attr = "salvo.__version__" }', self.toml)
        self.assertIn('dynamic = ["version"]', self.toml)

    def test_the_supported_python_range_matches_ci(self):
        self.assertIn('requires-python = ">=3.8"', self.toml)
        with open(os.path.join(ROOT, ".github", "workflows", "tests.yml")) as fh:
            workflow = fh.read()
        for version in ("3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"):
            self.assertIn('"{}"'.format(version), workflow)


class TestInstallHygiene(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path_backup = os.environ.get("PATH", "")

    def tearDown(self):
        os.environ["PATH"] = self.path_backup
        import shutil as _sh
        _sh.rmtree(self.dir, ignore_errors=True)

    def make_salvo(self, name="salvo"):
        path = os.path.join(self.dir, name)
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, 0o755)
        return path

    def test_a_shadowing_copy_is_found(self):
        stale = self.make_salvo()
        os.environ["PATH"] = self.dir + os.pathsep + self.path_backup
        self.assertIn(stale, salvo.other_installs())

    def test_nothing_is_reported_when_the_path_is_clean(self):
        os.environ["PATH"] = self.dir
        self.assertEqual(salvo.other_installs(), [])

    def test_the_running_file_is_not_reported_as_a_conflict(self):
        os.environ["PATH"] = os.path.dirname(os.path.abspath(salvo.__file__))
        real = os.path.realpath(salvo.__file__)
        self.assertNotIn(real, [os.path.realpath(p) for p in salvo.other_installs()])


class TestScopeCommand(unittest.TestCase):
    def test_scope_prints_the_lists_that_gate_the_tool(self):
        r = run_cli("--scope")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for flag in sorted(salvo.NEVER_SENT):
            self.assertIn(flag, r.stdout)
        for flag in sorted(salvo.ALLOWED_BARE_FLAGS):
            self.assertIn(flag, r.stdout)

    def test_scope_needs_no_targets_and_contacts_nothing(self):
        r = run_cli("--scope")
        self.assertNotIn("no targets given", r.stdout + r.stderr)
        self.assertIn("authentication only", r.stdout)


class TestReleaseWorkflow(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, ".github", "workflows", "release.yml")) as fh:
            self.workflow = fh.read()

    def test_a_tag_that_disagrees_with_the_module_stops_the_release(self):
        """A release advertising a version nobody can reproduce is worse than none."""
        self.assertIn("salvo.__version__", self.workflow)
        self.assertIn("GITHUB_REF_NAME#v", self.workflow)

    def test_the_suite_gates_the_release(self):
        self.assertIn("python -m unittest discover -s tests", self.workflow)

    def test_pypi_upload_uses_trusted_publishing_not_a_stored_token(self):
        self.assertIn("id-token: write", self.workflow)
        self.assertIn("pypa/gh-action-pypi-publish", self.workflow)
        self.assertNotIn("PYPI_API_TOKEN", self.workflow)
        self.assertNotIn("password:", self.workflow)

    def test_it_publishes_under_the_right_distribution_name(self):
        self.assertIn("salvo-nxc", self.workflow)


class TestBareInvocation(unittest.TestCase):
    def test_running_salvo_with_no_arguments_shows_help(self):
        """
        A first-time user typing `salvo` got "[!] no targets given." and
        nothing else. True, but it does not tell them what the tool is.
        """
        r = run_cli()
        self.assertIn("usage: salvo", r.stdout)
        self.assertIn("--dry-run", r.stdout)
        self.assertNotEqual(r.returncode, 0)

    def test_a_real_invocation_missing_targets_still_says_so(self):
        r = run_cli("-u", "jdoe", "-p", "Password123!")
        self.assertIn("no targets given", r.stdout + r.stderr)

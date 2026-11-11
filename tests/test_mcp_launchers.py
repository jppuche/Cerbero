"""Launcher allowlist and child-process hardening for cerbero-mcp-snapshot.py.

classify_launcher() does not try to understand the command lines of npx, uvx,
pipx, docker or an interpreter. It recognizes a short list of exact shapes
and calls everything else unverified (pinned None). The tables below are the
contract: PINNED is the whole allowlist, UNPINNED is a known shape without an
exact version, and nothing in NEVER_PINNED may ever come back as True.

Fixtures only. No package runner, registry or remote host is contacted.
"""
import importlib.util
import json
import os
import socket
import subprocess
import sys
import unittest
import warnings

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


base = _load("cerbero_snapshot_test_base2", os.path.join(REPO_ROOT, "tests", "test_mcp_snapshot.py"))
snap = base.snap
Sandbox = base.Sandbox
FAKE_SERVER = base.FAKE_SERVER
AUDIT_HOOK = os.path.join(REPO_ROOT, "hooks", "mcp-audit.py")

DIGEST = "sha256:" + "a" * 64
SECRET = "tok-1a2b3c4d5e6f"
PY = sys.executable            # an absolute interpreter path


def E(command, *args, **extra):
    entry = {"command": command, "args": list(args)}
    entry.update(extra)
    return entry


# (entry, kind, spec): the complete allowlist.
PINNED = [
    (E("npx", "pkg@1.2.3"), "npx", "pkg@1.2.3"),
    (E("npx", "-y", "pkg@1.2.3"), "npx", "pkg@1.2.3"),
    (E("npx", "--yes", "@scope/pkg@1.2.3-beta.1", "--stdio", "--token", SECRET), "npx", "@scope/pkg@1.2.3-beta.1"),
    (E("npx.cmd", "-y", "pkg@1.2.3"), "npx", "pkg@1.2.3"),
    (E("uvx", "pkg==1.0.0"), "uvx", "pkg==1.0.0"),
    (E("uvx", "some.pkg@1.0", "serve", "--port", "0"), "uvx", "some.pkg@1.0"),
    (E("pipx", "run", "pkg==1.0.0", "--flag"), "uvx", "pkg==1.0.0"),
    (E("docker", "run", "-i", "--rm", "ghcr.io/o/img@" + DIGEST), "docker", "ghcr.io/o/img@" + DIGEST),
    (E("docker", "run", "--interactive", "--rm", "-e", "API_TOKEN", "--env", "X=1", "--env=Y", "img:1@" + DIGEST, "serve"),
     "docker", "img:1@" + DIGEST),
]

# Known shape, no exact version: explicitly unpinned.
UNPINNED = [
    E("npx", "-y", "pkg"),
    E("npx", "-y", "@scope/pkg"),
    E("npx", "-y", "pkg@latest"),
    E("npx", "-y", "pkg@next"),
    E("npx", "-y", "pkg@1.2"),
    E("npx", "-y", "pkg@1"),
    E("npx", "-y", "pkg@1.x"),
    E("npx", "-y", "pkg@^1.2.3"),
    E("npx", "-y", "pkg@~1.2.3"),
    E("npx", "-y", "pkg@>=1.2.3"),
    E("uvx", "pkg"),
    E("uvx", "pkg@latest"),
    E("uvx", "pkg==1.*"),
    E("uvx", "pkg>=1.0"),
    E("pipx", "run", "pkg"),
    E("docker", "run", "-i", "--rm", "img"),
    E("docker", "run", "-i", "--rm", "img:latest"),
    E("docker", "run", "-i", "ghcr.io/o/img:1.2.3"),
]

# Everything else: unverified (None) or unpinned (False), never True.
NEVER_PINNED = [
    # the three inputs of the review
    E("node", "C:/Program Files/nodejs/node_modules/npm/bin/npx-cli.js", "-y", "pkg@1.2.3"),
    E("npx", "-y", "-p", "pkg@1.2.3", "-c", "echo x"),
    E("docker", "run", "-i", "--ulimit", "x@" + DIGEST, "evil:latest"),
    # a second package, a command override, a registry or an unknown flag
    E("npx", "-y", "-p", "pkg@1.2.3", "second-pkg"),
    E("npx", "-y", "--package", "pkg@1.2.3", "cmd"),
    E("npx", "-y", "--package=pkg@1.2.3", "cmd"),
    E("npx", "-c", "pkg@1.2.3"),
    E("npx", "--call", "echo x", "pkg@1.2.3"),
    E("npx", "-w", "ws", "pkg@1.2.3"),
    E("npx", "--registry", "https://r.example", "pkg@1.2.3"),
    E("npx", "--registry=https://r.example", "pkg@1.2.3"),
    E("npx", "--", "pkg@1.2.3"),
    E("npx", "--no-install", "pkg@1.2.3"),
    E("npx", "-q", "pkg@1.2.3"),
    E("npx"),
    E("npx", "-y"),
    E("uvx", "--from", "pkg==1.0.0", "tool"),
    E("uvx", "--from", "git+https://%s@example.com/o/r@1.0.0" % SECRET, "tool"),
    E("uvx", "--from", "git+ssh://git@example.com:o/r", "tool"),
    E("uvx", "git+ssh://git@example.com:o/r"),
    E("uvx", "--with", "other==2.0.0", "pkg==1.0.0"),
    E("uvx", "--with", "second-pkg", "pkg==1.0.0"),
    E("uvx", "--with-requirements", "r.txt", "pkg==1.0.0"),
    E("uvx", "--index-url", "https://pypi.example/simple", "pkg==1.0.0"),
    E("uvx", "-i", "https://pypi.example/simple", "pkg==1.0.0"),
    E("uvx", "--python", "3.12", "pkg==1.0.0"),
    E("uvx", "-q", "pkg==1.0.0"),
    E("uvx", "pkg[extra]==1.0.0"),
    E("uv", "tool", "run", "pkg==1.0.0"),
    E("uv", "run", "--with", "pkg==1.0.0", "server.py"),
    E("uv", "run", "server.py"),
    E("pipx", "pkg==1.0.0"),
    E("pipx", "run", "--spec", "pkg==1.0.0", "tool"),
    E("pipx", "run", "--pip-args=--index-url=https://x", "pkg==1.0.0"),
    E("pipx", "run", "pkg@1.0.0"),
    E("docker", "-H", "tcp://h", "run", "-i", "img@" + DIGEST),
    E("docker", "run", "-v", "/:/host", "img@" + DIGEST),
    E("docker", "run", "--privileged", "img@" + DIGEST),
    E("docker", "run", "--entrypoint", "sh", "img@" + DIGEST),
    E("docker", "run", "--network=host", "img@" + DIGEST),
    E("docker", "run", "-it", "img@" + DIGEST),
    E("docker", "run", "-e"),
    E("docker", "exec", "-i", "c", "sh"),
    E("docker", "run", "-i", "img@sha256:" + "a" * 63),
    E("docker", "run", "-i", "img@sha256:" + "A" * 64),
    E("podman", "run", "-i", "img@" + DIGEST),
    # wrappers and stand-ins
    E("cmd", "/c", "npx", "-y", "pkg@1.2.3"),
    E("cmd.exe", "/c", "npx -y pkg@1.2.3"),
    E("sh", "-c", "npx -y pkg@1.2.3"),
    E("/bin/sh", "-c", "npx -y pkg@1.2.3"),
    E("bash", "-lc", "uvx pkg==1.0.0"),
    E("env", "npx", "-y", "pkg@1.2.3"),
    E("/usr/bin/env", "node", FAKE_SERVER),
    E("winpty", "npx", "-y", "pkg@1.2.3"),
    E("node", "/usr/lib/node_modules/npm/bin/npx-cli.js", "-y", "pkg@1.2.3"),
    E("npm", "exec", "--", "pkg@1.2.3"),
    E("pnpm", "dlx", "pkg@1.2.3"),
    E("yarn", "dlx", "pkg@1.2.3"),
    E("bunx", "pkg@1.2.3"),
    E("bun", "x", "pkg@1.2.3"),
    E("deno", "run", "-A", "npm:pkg@1.2.3"),
    E("deno", "run", "https://example.com/server.ts"),
    # relative paths, interpreter flags, things that are not a script
    E("./npx", "-y", "pkg@1.2.3"),
    E("bin/npx", "-y", "pkg@1.2.3"),
    E("..\\npx.cmd", "-y", "pkg@1.2.3"),
    E(PY, "server.py"),
    E(PY, "./server.py"),
    E(PY, "-m", "some_module"),
    E(PY, "-c", "import os"),
    E(PY, "-X", "importtime", FAKE_SERVER),
    E(PY, "-W", "ignore", FAKE_SERVER),
    E(PY, "-S", FAKE_SERVER),
    E(PY, "-i", FAKE_SERVER),
    E(PY, os.path.join(REPO_ROOT, "tests", "fixtures", "no-such-file.py")),
    E(PY, os.path.join(REPO_ROOT, "tests", "fixtures")),
    E(PY),
    E("node", "--require", "./x.js", FAKE_SERVER),
    E("node", "-e", "require('x')"),
    E("node", "--experimental-strip-types", FAKE_SERVER),
    E("some-binary-on-path", "serve"),
    E("some-binary-on-path", "--token", SECRET),
    E(PY + "-not-an-interpreter", FAKE_SERVER),
    E("ruby", FAKE_SERVER),
    E("java", "-jar", "server.jar"),
    E("", "x"),
    # an env block that changes what the launcher itself does
    E("npx", "-y", "pkg@1.2.3", env={"NPM_CONFIG_REGISTRY": "https://r.example"}),
    E("npx", "-y", "pkg@1.2.3", env={"npm_config_registry": "https://r.example"}),
    E("npx", "-y", "pkg@1.2.3", env={"NODE_OPTIONS": "--require ./x.js"}),
    E("npx", "-y", "pkg@1.2.3", env={"PATH": "/tmp/bin"}),
    E("uvx", "pkg==1.0.0", env={"UV_INDEX_URL": "https://pypi.example/simple"}),
    E("uvx", "pkg==1.0.0", env={"PIP_INDEX_URL": "https://pypi.example/simple"}),
    E("docker", "run", "-i", "img@" + DIGEST, env={"DOCKER_HOST": "tcp://h"}),
    E(PY, FAKE_SERVER, env={"PYTHONPATH": "/tmp/x"}),
    E(PY, FAKE_SERVER, env={"PYTHONSTARTUP": "/tmp/x.py"}),
    E("node", FAKE_SERVER, env={"NODE_PATH": "/tmp/x"}),
    E(PY, FAKE_SERVER, env={"LD_PRELOAD": "/tmp/x.so"}),
    # specs that are not registry names
    E("npx", "-y", "https://user:%s@example.com/pkg-1.0.0.tgz" % SECRET),
    E("npx", "-y", "github:o/r#v1.2.3"),
    E("npx", "-y", "../local@1.2.3"),
    E("npx", "-y", "pkg@npm:other@1.2.3"),
    E("uvx", "https://example.com/pkg-1.0.0.tar.gz"),
    E("uvx", "./local==1.0.0"),
]


class TestClassifierTable(unittest.TestCase):
    def setUp(self):
        self.project = os.path.join(REPO_ROOT, "tests")

    def test_allowlisted_shapes_are_pinned(self):
        for entry, kind, spec in PINNED:
            with self.subTest(entry=entry):
                got = snap.classify_launcher(entry, self.project)
                self.assertEqual((got["kind"], got["spec"], got["pinned"]), (kind, spec, True), got)

    def test_interpreter_with_one_absolute_script_is_pinned_by_hash(self):
        for entry in (E(PY, FAKE_SERVER), E(PY, FAKE_SERVER, "--era", "dual", "-c", "x"),
                      E(PY, "-u", FAKE_SERVER), E(PY, "-I", "-u", FAKE_SERVER, "--x")):
            with self.subTest(entry=entry):
                got = snap.classify_launcher(entry, self.project)
                self.assertEqual((got["kind"], got["pinned"]), ("path", True), got)
                # The hash is of the file that runs, the script, not of anything else.
                self.assertEqual(got["integrity"], snap.sha_file(FAKE_SERVER))

    def test_bare_interpreter_name_is_as_good_as_bare_npx(self):
        for name in ("python", "python3", "python3.12", "node", "node.exe"):
            with self.subTest(name):
                got = snap.classify_launcher(E(name, FAKE_SERVER), self.project)
                self.assertEqual((got["kind"], got["pinned"]), ("path", True), got)

    def test_known_shape_without_exact_version_is_unpinned(self):
        for entry in UNPINNED:
            with self.subTest(entry=entry):
                self.assertIs(snap.classify_launcher(entry, self.project)["pinned"], False)

    def test_everything_else_is_never_pinned(self):
        for entry in NEVER_PINNED + UNPINNED:
            with self.subTest(entry=entry):
                got = snap.classify_launcher(entry, self.project)
                self.assertIsNot(got["pinned"], True, got)
                self.assertNotIn(SECRET, json.dumps(got))

    def test_unverified_launcher_is_stored_as_a_hash_not_as_text(self):
        for entry in NEVER_PINNED:
            got = snap.classify_launcher(entry, self.project)
            if got["pinned"] is None:
                with self.subTest(entry=entry):
                    self.assertEqual(got["kind"], "other")
                    self.assertRegex(got["spec"], r"^sha256:[0-9a-f]{64}$")
                    for token in [entry["command"]] + entry["args"]:
                        if len(token) > 3:
                            self.assertNotIn(token, json.dumps({k: v for k, v in got.items() if k != "note"}))

    def test_unverified_binary_given_by_absolute_path_still_records_its_hash(self):
        got = snap.classify_launcher(E(PY, "-m", "some_module"), self.project)
        self.assertIsNone(got["pinned"])
        self.assertEqual(got["integrity"], snap.sha_file(PY))

    def test_malformed_entries_do_not_raise(self):
        for entry in ({"command": "npx", "args": "pkg@1.2.3"}, {"command": "npx", "args": [["pkg@1.2.3"]]},
                      {"command": ["npx"], "args": []}, {"command": "npx", "args": ["-y", "pkg@1.2.3"], "env": "X=1"},
                      {"command": None}, {"type": "http", "url": 5}, {"type": "http", "url": "http://x", "headers": "a"}):
            with self.subTest(entry=entry):
                self.assertIsNotNone(snap.entry_problem(entry))


class Base(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox(self)


def _closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestSecretsStayOut(Base):
    """Item 5: a spec is text only for an allowlisted shape; otherwise kind and hash."""

    def test_nothing_secret_reaches_files_or_stdout(self):
        url = "http://user:%s@127.0.0.1:%d/v1/%s/mcp?key=%s" % (SECRET, _closed_port(), SECRET, SECRET)
        entries = {
            "space flag": E("some-binary", "--token", SECRET),
            "equals flag": E("some-binary", "--api-key=" + SECRET),
            "positional": E("some-binary", SECRET),
            "scp git": E("uvx", "--from", "git+ssh://git:%s@example.com:o/r" % SECRET, "tool"),
            "npm url": E("npx", "-y", "https://user:%s@example.com/p.tgz" % SECRET),
            "npx arg": E("npx", "-y", "pkg@1.2.3", "--token", SECRET),
            "docker env": E("docker", "run", "-i", "-e", "TOKEN=" + SECRET, "img@" + DIGEST),
            "remote": {"type": "http", "url": url, "headers": {"X-Key": SECRET}},
        }
        self.sb.local = entries
        self.sb.write_home()
        out = ""
        for name in entries:
            _, _, text = self.sb.run("approve", name, "--risk", "MEDIUM", "--offline", "--allow-unverified",
                                     "--project", self.sb.project)
            out += text
        _, _, text = self.sb.run("pins", "--offline", "--project", self.sb.project)
        out += text
        # Only the remote entry is contacted, and it is a closed port on this machine.
        self.sb.local = {"remote": entries["remote"]}
        self.sb.write_home()
        doc, _, text = self.sb.snapshot("current.json", "--timeout", "5")
        self.assertEqual(doc["servers"]["remote"]["status"], "error", doc["servers"]["remote"])
        out += text
        for folder, _, files in os.walk(self.sb.tmp):
            for name in files:
                if name not in (".claude.json", ".mcp.json", "tools.json"):
                    with open(os.path.join(folder, name), encoding="utf-8", errors="replace") as f:
                        out += f.read()
        self.assertNotIn(SECRET, out)


class TestInvalidEntries(Base):
    """Item 6: one malformed entry is skipped; the other servers are still read."""

    def test_malformed_entry_does_not_lose_the_others(self):
        good = self.sb.stdio_entry()
        self.sb.local = {"wiki": good}
        self.sb.write_home()
        self.sb.approve("wiki")
        bad = {
            "bad-env": dict(good, env="TOKEN=x"),
            "bad-env-value": dict(good, env={"A": {"b": 1}}),
            "bad-args": dict(good, args="--era dual"),
            "bad-args-item": dict(good, args=[["x"]]),
            "bad-command": {"command": ["python"], "args": []},
            "no-command": {"args": ["x"]},
            "bad-headers": {"type": "http", "url": "http://127.0.0.1:9/mcp", "headers": ["a"]},
            "bad-url": {"type": "http", "url": None},
        }
        self.sb.local = dict(bad, wiki=good)
        self.sb.write_home()
        # Records for the bad entries, as if they had been valid when approved.
        with open(os.path.join(self.sb.security, "mcp-approved.json"), encoding="utf-8") as f:
            records = json.load(f)
        for name in bad:
            records[name] = dict(records["wiki"])
        self.sb.write_approved(records)
        doc, summary, text = self.sb.snapshot()
        self.assertEqual(doc["servers"]["wiki"]["status"], "ok", text)
        for name in bad:
            with self.subTest(name):
                s = doc["servers"][name]
                self.assertEqual((s["status"], s["reason"]), ("skipped", "invalid_entry"), s)
        code, report, text = self.sb.run("pins", "--offline", "--project", self.sb.project)
        self.assertIsNotNone(report, text)
        for name in bad:
            self.assertIn("INVALID_ENTRY", report["servers"][name]["findings"])
        code, data, _ = self.sb.run("approve", "bad-env", "--risk", "MEDIUM", "--offline", "--project", self.sb.project)
        self.assertEqual((code, data["error"]), (2, "invalid_entry"))


class TestChildProcessHardening(Base):
    """Item 4."""

    def _report(self, entry_scope):
        report = self.sb.path("report.json")
        entry = self.sb.stdio_entry("--report", report)
        if entry_scope == "project":
            self.sb.write_mcp_json({"wiki": entry})
            self.sb.trusted = True
        else:
            setattr(self.sb, entry_scope, {"wiki": entry})
        self.sb.write_home()
        self.sb.approve("wiki")
        # Run from inside the project, as /cerbero verify does.
        path = self.sb.path("current.json")
        code, _, text = self.sb.run("snapshot", "--out", path, "--project", self.sb.project,
                                    "--probe-timeout", "1", cwd=self.sb.project)
        self.assertEqual(code, 0, text)
        with open(path, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["servers"]["wiki"]["status"], "ok", text)
        with open(report, encoding="utf-8") as f:
            return json.load(f)

    def _same(self, a, b):
        return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))

    def test_local_and_user_servers_do_not_start_in_the_project(self):
        for scope in ("local", "user"):
            with self.subTest(scope):
                got = self._report(scope)
                self.assertFalse(self._same(got["cwd"], self.sb.project), got["cwd"])
                self.assertFalse(os.path.exists(got["cwd"]), "the neutral working directory was left behind")

    def test_trusted_project_server_starts_in_the_project(self):
        got = self._report("project")
        self.assertTrue(self._same(got["cwd"], self.sb.project), got["cwd"])

    @unittest.skipUnless(os.name == "nt", "Windows only")
    def test_windows_child_does_not_search_its_current_directory(self):
        self.assertEqual(self._report("local")["NoDefaultCurrentDirectoryInExePath"], "1")

    def _tool_in_project(self):
        folder = os.path.join(self.sb.project, "bin")
        os.makedirs(folder)
        marker = self.sb.path("ran.txt")
        names = ["cerbero-fixture-tool.cmd", "python.cmd"] if os.name == "nt" else ["cerbero-fixture-tool", "python"]
        for name in names:
            path = os.path.join(folder, name)
            with open(path, "w") as f:
                f.write(("@echo off\r\necho ran> \"%s\"\r\n" if os.name == "nt" else "#!/bin/sh\necho ran > '%s'\n") % marker)
            os.chmod(path, 0o755)
        return folder, marker, [os.path.join(folder, n) for n in names]

    def _snapshot_one(self, entry, *approve_flags):
        self.sb.user = {"tool": entry}
        self.sb.write_home()
        self.sb.approve("tool", *approve_flags)
        doc, _, _ = self.sb.snapshot("current.json", "--timeout", "5")
        return doc["servers"]["tool"]

    def test_command_found_through_a_path_entry_inside_the_project_is_refused(self):
        folder, marker, _ = self._tool_in_project()
        s = self._snapshot_one(E("cerbero-fixture-tool", "serve"), "--allow-unverified")
        self.assertEqual(s["reason"], "spawn_failed", s)       # not on PATH at all: nothing ran
        doc, _, _ = self.sb.snapshot("current.json", "--timeout", "5",
                                     env={"PATH": folder + os.pathsep + os.environ.get("PATH", "")})
        s = doc["servers"]["tool"]
        self.assertEqual((s["status"], s["reason"]), ("skipped", "command_in_project"), s)
        self.assertFalse(os.path.exists(marker))

    def test_interpreter_inside_the_project_is_refused(self):
        _, marker, paths = self._tool_in_project()
        s = self._snapshot_one(E(paths[1], FAKE_SERVER, "--tools", self.sb.tools_path), "--allow-unverified")
        self.assertEqual((s["status"], s["reason"]), ("skipped", "command_in_project"), s)
        self.assertFalse(os.path.exists(marker))

    def test_hashed_binary_inside_the_project_is_the_one_exception(self):
        # The record's launcher is that very file, by hash: it may live in the project.
        _, marker, paths = self._tool_in_project()
        s = self._snapshot_one(E(paths[0], "serve"), "--allow-unverified")
        self.assertNotEqual(s["reason"], "command_in_project", s)
        with open(paths[0], "a") as f:
            f.write("\n")
        if os.path.exists(marker):
            os.remove(marker)
        doc, _, _ = self.sb.snapshot("current.json", "--timeout", "5")
        self.assertEqual(doc["servers"]["tool"]["reason"], "integrity_mismatch")
        self.assertFalse(os.path.exists(marker))

    def test_resolved_command_is_always_absolute(self):
        for command in ("cerbero-no-such-tool", os.path.join("bin", "tool"), "." + os.sep + "tool"):
            with self.subTest(command):
                got = snap.resolve_command(command, {"PATH": os.environ.get("PATH", "")}, self.sb.project)
                self.assertTrue(got is None or os.path.isabs(got), got)
        got = snap.resolve_command(os.path.basename(PY), {"PATH": os.path.dirname(PY)}, self.sb.project)
        self.assertTrue(os.path.isabs(got))


class TestNoLeakedPipes(Base):
    """Item 6: the stuck-writer path closes what it opened."""

    def test_stuck_session_leaves_no_open_pipe(self):
        import time
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            sess = snap.StdioSession([PY, "-c", "import time; time.sleep(60)"], dict(os.environ),
                                     self.sb.tmp, time.time() + 2)
            with self.assertRaises(snap.SnapError):
                for _ in range(64):
                    sess.send("tools/list", {"cursor": "x" * (1024 * 1024)})
            sess.close()
            self.assertTrue(sess.proc.stdin.closed)
            self.assertTrue(sess.proc.stdout.closed)
            del sess
            import gc
            gc.collect()
        self.assertEqual([str(w.message) for w in caught if issubclass(w.category, ResourceWarning)], [])


class TestAuditHookClosedStdout(unittest.TestCase):
    """Item 6: a closed stdout is one more error that must exit 0, silently."""

    def test_closed_stdout_exits_zero(self):
        import shutil
        import tempfile
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        security = os.path.join(tmp, ".claude", "security")
        os.makedirs(security)
        with open(os.path.join(security, "invocation-counter.txt"), "w") as f:
            f.write("49")                                   # call 50 prints the reminder
        env = {k: v for k, v in os.environ.items() if k not in ("CERBERO_LOG_DIR", "CERBERO_TRIPWIRE")}
        env["CLAUDE_PROJECT_DIR"] = tmp
        r, w = os.pipe()
        os.close(r)                                         # nobody will ever read
        try:
            p = subprocess.run([sys.executable, AUDIT_HOOK],
                               input=json.dumps({"tool_name": "mcp__a__b", "tool_input": {}, "cwd": tmp}).encode(),
                               stdout=w, stderr=subprocess.PIPE, env=env, timeout=30)
        finally:
            os.close(w)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stderr, b"")


if __name__ == "__main__":
    unittest.main()

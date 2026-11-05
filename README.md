# skill-guard

A Claude Code plugin that reviews every skill before it runs and limits what it can reach while running.

Try it in one session:

```bash
claude --plugin-dir /path/to/skill-security
```

It covers all three ways a skill can start: a typed `/name`, the `Skill` tool, and reading `SKILL.md` directly.

## What happens

1. Every file in the skill is read and hashed. Static rules run first, and a static block is final.
2. Packages found in lockfiles, `requirements*.txt`, `node_modules` and `.dist-info` are checked against OSV. Only names and versions are sent. Known malicious packages block, and serious advisories or a failed lookup go to a person. `__pycache__` files stay blocked, because compiled code can't be reviewed.
3. A reviewer runs a standard review and an adversarial one. By default that is Claude; if Claude isn't installed, Codex; otherwise `ANTHROPIC_API_KEY`. Blocking on the LLM's word needs both reviews to agree; one objection asks you instead.
4. Plain code makes the decision. The LLM can only make a result stricter.
5. Clean results are signed and cached by content hash, so any edit forces a new review.
6. While a skill is active, tool calls are checked against the allowlist. Secret paths and guard files are protected in all sessions.

Any error blocks. Results that need a person are shown as a prompt, or as a block for typed commands. To approve an exact version, run this in your own terminal:

```bash
python3 -I guard/cli.py approve <skill>
```

## Configuration

Copy `config/config.example.toml` to `~/.claude/skill-guard/config.toml` and keep only what you change. For example, to use two models:

```toml
reviewers = ["claude-cli", "codex-cli"]
```

An org file at `/Library/Application Support/ClaudeCode/skill-guard.toml` (macOS) or `/etc/claude-code/skill-guard.toml` (Linux) overrides the user file. Unknown settings or invalid values block every skill until fixed, so a typo can't weaken the guard. Check the current state with `python3 -I guard/cli.py status`.

Set `mode = "audit"` to log decisions without blocking while you tune the rules.

## Tests

```bash
python3 -m unittest tests/test_guard.py
```

## Limits

- The hook checks are not a network boundary. Turn on the Claude Code sandbox as well.
- Opening a skill with `cat` through Bash is not treated as starting it.
- Attacks through allowed services, or harmful changes that make no network call, can still get through.
- A Codex reviewer runs read-only but can't have its tools fully removed.

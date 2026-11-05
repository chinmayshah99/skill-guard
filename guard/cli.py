"""Entry point. Hooks fail closed: any unexpected error exits 2, which blocks."""
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guard import audit, cache, deps, llm_review, runtime_gate  # noqa: E402
from guard import gate, report  # noqa: E402
from guard.collect import collect  # noqa: E402
from guard.config import ConfigError, load_policy, state_dir, user_path  # noqa: E402
from guard.resolve import resolve, skill_for_path  # noqa: E402
from guard.static_scan import scan  # noqa: E402

SELF = "skill-guard"


def _tool_response(decision, reason):
    # "allow" stays silent on purpose: answering allow would skip normal permission prompts.
    if decision == "allow":
        return 0
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask" if decision == "ask" else "deny",
        "permissionDecisionReason": f"skill-guard: {reason}",
    }}))
    return 0


def _on_prompt(event, policy):
    match = re.match(r"\s*/([\w:.-]+)", event.get("prompt", ""))
    if not match:
        return 0
    name = match.group(1)
    if name.rsplit(":", 1)[-1] == SELF:
        return 0
    if not resolve(name, event.get("cwd", ".")) and name not in policy["builtin_skills"] and ":" not in name:
        return 0  # Built-in commands like /help have no skill files.
    decision, items = gate.check_skill(name, event.get("cwd", "."), policy)
    if gate.enforce(decision, policy) != "allow":
        # A typed command can't show a permission prompt, so "ask" stops here too.
        print(json.dumps({"decision": "block", "reason": report.summary(name, decision, items)}))
        return 0
    runtime_gate.mark_active(event.get("session_id"), name)
    return 0


def _on_skill(event, policy):
    name = event["tool_input"]["skill"]
    if name.rsplit(":", 1)[-1] == SELF:
        return 0
    decision, items = gate.check_skill(name, event.get("cwd", "."), policy)
    message = report.summary(name, decision, items)
    decision = gate.enforce(decision, policy)
    if decision != "block":
        runtime_gate.mark_active(event.get("session_id"), name)
    return _tool_response(decision, message)


def _on_read(event, policy):
    skill_dir = skill_for_path(event["tool_input"].get("file_path", ""))
    if skill_dir is None:
        return None
    # Reading a skill is another way to follow it, so it gets the same check.
    decision, items, _ = gate.check_target(skill_dir, policy)
    audit.log("skill-read", target=str(skill_dir), decision=decision)
    message = report.summary(skill_dir.name, decision, items, target=skill_dir)
    decision = gate.enforce(decision, policy)
    if decision != "allow":
        return _tool_response(decision, message)
    runtime_gate.mark_active(event.get("session_id"), skill_dir.name)
    return None


def _on_session_start(policy):
    problems = []
    settings = Path.home() / ".claude" / "settings.json"
    enabled = False
    if settings.exists():
        enabled = json.loads(settings.read_text()).get("sandbox", {}).get("enabled", False)
    if not enabled and not policy["managed"]:
        problems.append("the network sandbox is off, so runtime protection is limited")
    if cache.signing_key() is None:
        problems.append("no secret store is available, so every run needs a fresh review")
    if problems:
        print(json.dumps({"systemMessage": "skill-guard: " + "; ".join(problems) + "."}))
    return 0


def run_hook(event):
    policy = load_policy()
    name = event.get("hook_event_name")
    if name == "SessionStart":
        return _on_session_start(policy)
    if name == "UserPromptSubmit":
        return _on_prompt(event, policy)
    tool = event.get("tool_name", "")
    if tool == "Skill":
        return _on_skill(event, policy)
    if tool == "Read":
        done = _on_read(event, policy)
        if done is not None:
            return done
    decision, reason = runtime_gate.check(tool, event.get("tool_input", {}), event.get("session_id"), policy)
    if decision != "allow":
        audit.log("runtime", tool=tool, decision=decision, reason=reason)
    if policy["mode"] == "audit":
        return 0
    return _tool_response(decision, reason)


def cmd_scan(path):
    policy = load_policy()
    bundle = collect(Path(path).expanduser(), policy)
    findings = scan(bundle, policy) + deps.check(bundle.texts, policy)
    decision = gate.decisions.decide_static(findings)
    items, reviews, why = report.dedupe(report.from_findings(findings)), [], []
    if decision == "block":
        why = ["a static rule blocked it; no LLM review needed"]
    elif "--llm" in sys.argv:
        result = llm_review.review(bundle, policy)
        decision, items, why = gate.decisions.decide(findings, result, policy)
        reviews = result["reviews"]
    else:
        why = ["static checks only; add --llm for the full review"]
    print(report.render(bundle.name, decision, items, bundle.texts, reviews, why))
    print(f"\nversion {bundle.digest[:12]}")
    # scan always reviews afresh, so say separately what a real run would do.
    try:
        cached = cache.load(cache.cache_key(bundle.digest, policy, llm_review.backend_ids(policy)), policy)
    except llm_review.ReviewError:
        cached = None
    if decision == "block" and any(i["severity"] == "block" and i["source"] in ("rules", "dependencies") for i in items):
        print("in Claude: blocked by a rule, whatever was approved")
    elif cached and cached["verdict"] == "approved":
        approved = time.strftime("%Y-%m-%d %H:%M", time.localtime(cached["time"]))
        print(f"in Claude: runs, because you approved this version on {approved}")
    elif cached and cached["verdict"] == "allow":
        print("in Claude: runs, from an earlier clean review")
    else:
        print("in Claude: not approved, so it will be stopped until you approve this version")
    return 0


def cmd_approve(name):
    """Approve the exact current version. Needs a person at a real terminal."""
    policy = load_policy()
    if not policy["allow_self_approval"]:
        print("Your organization doesn't allow self-approval.", file=sys.stderr)
        return 1
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Approval needs an interactive terminal, so an agent can't do it.", file=sys.stderr)
        return 1
    targets = resolve(name, os.getcwd()) or ([Path(name)] if Path(name).exists() else [])
    if not targets:
        print(f"Couldn't find {name}", file=sys.stderr)
        return 1
    for target in targets:
        bundle = collect(target, policy)
        findings = scan(bundle, policy)
        print(f"{target}")
        for item in report.from_findings(findings):
            if item["severity"] != "info":
                print(f"  [{item['severity']}] {report.place(item)}  {item['message']}")
        if gate.decisions.decide_static(findings) == "block":
            print("  Static checks blocked this version; approving it won't override that.")
            return 1
        try:
            answer = input("Approve this exact version? Type the word approve and press Return: ")
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled. Nothing was approved.")
            return 1
        if answer.strip() != "approve":
            print(f"Not approved: expected the word approve, got {answer.strip()[:20]!r}.")
            return 1
        key = cache.cache_key(bundle.digest, policy, llm_review.backend_ids(policy))
        if not cache.store(key, "approved", []):
            print("No secret store is available, so the approval can't be saved.", file=sys.stderr)
            return 1
        audit.log("approved", target=str(target), digest=bundle.digest)
    print("Approved. Any edit will need a new review.")
    return 0


def cmd_status():
    try:
        policy = load_policy()
    except ConfigError as error:
        print(f"config: invalid, so every skill is blocked\n  {error}")
        return 1
    print(f"config: {user_path() if user_path().exists() else 'defaults'}")
    print(f"mode: {policy['mode']}\nmanaged: {policy['managed']}")
    try:
        active = llm_review.backend_ids(policy)
        styles = "standard and adversarial" if len(active) == 1 else "standard, then adversarial"
        print(f"reviewers: {', '.join(active)} ({styles})")
    except llm_review.ReviewError as error:
        print(f"reviewers: none ({error})")
    print(f"secret store: {'ok' if cache.signing_key() else 'unavailable'}")
    log = state_dir() / "audit.log"
    if log.exists():
        print("recent decisions:")
        print("\n".join(log.read_text().splitlines()[-10:]))
    return 0


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "hook":
        try:
            return run_hook(json.load(sys.stdin))
        except ConfigError as error:
            print(f"skill-guard blocked this because its config is invalid: {error}", file=sys.stderr)
            return 2
        except Exception as error:  # noqa: BLE001 - failing closed is the point
            print(f"skill-guard blocked this because the check failed: {error}", file=sys.stderr)
            return 2
    if command == "scan" and len(sys.argv) > 2:
        return cmd_scan(sys.argv[2])
    if command == "approve" and len(sys.argv) > 2:
        return cmd_approve(sys.argv[2])
    if command == "status":
        return cmd_status()
    print("usage: cli.py hook | scan <path> [--llm] | approve <skill> | status", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

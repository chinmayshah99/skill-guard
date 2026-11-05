"""The pre-run check, shared by every way a skill can start."""
from . import audit, cache, deps, llm_review, policy as decisions, report
from .collect import collect
from .resolve import resolve
from .static_scan import scan


def check_target(target, policy):
    """Return (decision, items, digest) for one skill folder or command file."""
    bundle = collect(target, policy)
    findings = scan(bundle, policy)
    if decisions.decide_static(findings) == decisions.BLOCK:
        # Static failures are final; no LLM call or cache can undo them.
        return decisions.BLOCK, report.dedupe(report.from_findings(findings)), bundle.digest

    # Runs before the verdict cache, so a new advisory reaches approved skills too.
    findings += deps.check(bundle.texts, policy)
    items = report.dedupe(report.from_findings(findings))
    if decisions.decide_static(findings) == decisions.BLOCK:
        return decisions.BLOCK, items, bundle.digest

    backend_ids = llm_review.backend_ids(policy)
    entry_key = cache.cache_key(bundle.digest, policy, backend_ids)
    cached = cache.load(entry_key, policy)
    if cached and cached["verdict"] in ("allow", "approved"):
        if cached["verdict"] == "allow" and decisions.decide_static(findings) == decisions.ASK:
            return decisions.ASK, items, bundle.digest
        return decisions.ALLOW, [], bundle.digest

    decision, items, why = decisions.decide(findings, llm_review.review(bundle, policy), policy)
    if decision == decisions.ALLOW:
        cache.store(entry_key, "allow", [])
    return decision, [report.item("decision", "review", "", 0, w.capitalize()) for w in why] + items, bundle.digest


def check_skill(name, cwd, policy):
    """Check every location that could supply this skill. Worst result wins."""
    targets = resolve(name, cwd)
    if not targets:
        if name in policy["builtin_skills"]:
            return decisions.ALLOW, []
        return decisions.BLOCK, [report.item("skill-guard", "block", "", 0, f"Couldn't find the files for {name!r}, so it can't be reviewed")]
    final, all_items = decisions.ALLOW, []
    for target in targets:
        try:
            decision, items, digest = check_target(target, policy)
        except llm_review.ReviewError as error:
            decision, items, digest = decisions.BLOCK, [report.item("skill-guard", "block", "", 0, f"Review unavailable: {error}")], ""
        audit.log("skill-check", skill=name, target=str(target), decision=decision, digest=digest,
                  findings=[f"{report.place(i)} {i['message']}" for i in items if i["severity"] != "info"][:20])
        final = decisions._worst(final, decision)
        all_items += items
    return final, report.dedupe(all_items)


def enforce(decision, policy):
    """Audit mode records what would have happened and lets it run."""
    if policy["mode"] == "audit" and not (policy.get("managed") and policy.get("enforce_always")):
        return decisions.ALLOW
    return decision

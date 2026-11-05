"""Final decision. Plain code over facts, so a fooled reviewer can't approve anything."""
from . import net, report

BLOCK, ASK, ALLOW = "block", "ask", "allow"


def _worst(current, new):
    order = {ALLOW: 0, ASK: 1, BLOCK: 2}
    return new if order[new] > order[current] else current


def decide_static(findings):
    severities = {f["severity"] for f in findings}
    if "block" in severities:
        return BLOCK
    return ASK if "review" in severities else ALLOW


def decide(findings, result, policy):
    """Combine static findings and an LLM result into (decision, items, why)."""
    decision = decide_static(findings)
    items = report.from_findings(findings)
    why = []
    facts = result["facts"]
    flag = lambda severity, message: items.append(report.item("reviewer facts", severity, "", 0, message))
    # LLM verdicts vary between runs, so blocking needs two independent votes.
    # Reviews sharing a model and prompt count once. A single vote still stops
    # the skill, as "ask". Static rule blocks never need a vote.
    block_votes = set()

    for domain in facts["domains"]:
        host, _, path = domain.lower().removeprefix("https://").removeprefix("http://").partition("/")
        status = net.classify(host, "/" + path, policy)
        if status == "denied" or net.is_raw_ip(host):
            block_votes.add("extraction")
            flag("block", f"Contacts a forbidden destination: {host}")
        elif status == "unknown":
            decision = _worst(decision, ASK)
            flag("review", f"Contacts a destination not on the allowlist: {host}")
    if facts["downloads_code"]:
        block_votes.add("extraction")
        flag("block", "Downloads code or instructions")
    if facts["dynamic_destinations"]:
        decision = _worst(decision, ASK)
        flag("review", "Contacts a destination decided at runtime")

    for review in result["reviews"]:
        rating = f"{review['_source']} rated it {review['verdict']}, {review['risk']} risk"
        if review["injection_attempt"] or review["verdict"] == "malicious" or review["risk"] == "high":
            block_votes.add(review.get("_voter", review["_source"]))
            severity = "block"
            why.append(rating + (" and found an injection attempt" if review["injection_attempt"] else ""))
        elif review["verdict"] == "suspicious" or review["risk"] == "medium" or review["purpose_mismatch"]:
            decision, severity = _worst(decision, ASK), "review"
            why.append(rating + (" and found behaviour beyond its purpose" if review["purpose_mismatch"] else ""))
        else:
            severity = "info"  # A "safe" reviewer's notes are context, not reasons.
        items += [report.item(review["_source"], severity, f["file"], f["line"], f["reason"]) for f in review["findings"]]
    if len(block_votes) >= 2:
        decision = BLOCK
        why.insert(0, f"{len(block_votes)} independent reviews found it unsafe")
    elif block_votes:
        decision = _worst(decision, ASK)
        why.insert(0, "one review found it unsafe, but blocking needs two to agree")
    if len({review["verdict"] for review in result["reviews"]}) > 1:
        decision = _worst(decision, ASK)
        why.append("the reviewers disagreed")
    if result["unreviewed_files"]:
        decision = _worst(decision, ASK)
        why.append(f"{result['unreviewed_files']} files had no individual review")
    return decision, report.dedupe(items), why



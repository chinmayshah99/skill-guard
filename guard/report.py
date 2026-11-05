"""Turn findings into a report a person can act on."""
ORDER = {"block": 0, "review": 1, "info": 2}
HEADLINE = {"block": "BLOCKED", "ask": "NEEDS YOUR APPROVAL", "allow": "ALLOWED"}
DEPENDENCY_RULES = {"malicious-package", "vulnerable-package", "minor-advisory", "deps-unchecked",
                    "unpinned-deps", "unreadable-manifest"}


def item(source, severity, file, line, message):
    return {"source": source, "severity": severity, "file": file, "line": line, "message": message}


def from_findings(findings):
    return [item("dependencies" if f["rule"] in DEPENDENCY_RULES else "rules",
                 f["severity"], f["file"], f["line"], f["message"]) for f in findings]


def dedupe(items):
    seen, kept = set(), []
    for entry in sorted(items, key=lambda i: ORDER[i["severity"]]):
        key = (entry["source"], entry["file"], entry["line"] or entry["message"])
        if key not in seen:
            seen.add(key)
            kept.append(entry)
    return kept


def place(entry):
    return entry["file"] + (f":{entry['line']}" if entry["line"] else "")


def summary(name, decision, items, target=None, limit=3):
    """One short paragraph for hook messages, where space is tight."""
    shown = [i for i in items if i["severity"] != "info"]
    lines = [f"{name}: {HEADLINE[decision].lower()}."]
    lines += [f"- {place(i)} {i['message']}" for i in shown[:limit]]
    if len(shown) > limit:
        lines.append(f"- and {len(shown) - limit} more")
    if target:
        lines.append(f"Full report: python3 -I <skill-guard>/guard/cli.py scan {target} --llm")
    if decision == "ask":
        lines.append(f"To allow this exact version, run in your own terminal: python3 -I <skill-guard>/guard/cli.py approve {name}")
    return "\n".join(lines)


def _snippet(texts, entry):
    text = texts.get(entry["file"])
    if not text or not entry["line"]:
        return ""
    lines = text.splitlines()
    return lines[entry["line"] - 1].strip()[:110] if entry["line"] <= len(lines) else ""


def render(name, decision, items, texts, reviews=(), why=()):
    """Full terminal report, grouped by where each finding came from."""
    out = [f"{name}  ->  {HEADLINE[decision]}"]
    if why:
        out.append("Why: " + "; ".join(why))
    if reviews:
        out += ["", "Reviewers"]
        for review in reviews:
            flags = [f for f, on in (("injection attempt", review["injection_attempt"]),
                                     ("purpose mismatch", review["purpose_mismatch"])) if on]
            out.append(f"  {review['_source']}: {review['verdict']}, {review['risk']} risk"
                       + (f", {', '.join(flags)}" if flags else ""))
    groups = {}
    for entry in items:
        groups.setdefault("Context only, not counted" if entry["severity"] == "info" else entry["source"], []).append(entry)
    for title in sorted(groups, key=lambda g: (g.startswith("Context"), g)):
        out += ["", title[0].upper() + title[1:]]
        for entry in groups[title]:
            tag = "" if entry["severity"] == "info" else f"[{entry['severity']}] "
            out.append(f"  {tag}{place(entry)}  {entry['message']}")
            snippet = _snippet(texts, entry)
            if snippet and entry["severity"] != "info":
                out.append(f"      > {snippet}")
    out.append("")
    approve = f"python3 -I guard/cli.py approve {name}"
    static_block = any(i["severity"] == "block" and i["source"] in ("rules", "dependencies") for i in items)
    if decision == "block" and static_block:
        out.append("Next: a rule blocked this version, and that can't be overridden. Fix those findings, or don't use the skill.")
    elif decision == "block":
        out.append("Next: a reviewer blocked this, which you can override. Check the findings against the lines shown.\n"
                   f"If you're confident it's safe, approve this exact version in your own terminal:\n  {approve}")
    elif decision == "ask":
        out.append(f"Next: if this behaviour is acceptable, approve this exact version in your own terminal:\n  {approve}")
    return "\n".join(out)

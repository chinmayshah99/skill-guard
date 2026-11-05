"""Deterministic checks. These can't be talked out of a finding."""
import re

from . import net
from .config import load_rules
from .normalize import normalize


CODE_EXTENSIONS = {"py", "js", "mjs", "cjs", "ts", "sh", "bash", "zsh", "rb", "pl", "php", "ps1", "go", "rs", "lua"}
NETWORK_WORDS = ("curl ", "wget ", "fetch(", "requests.", "urllib", "http.client", "socket", "axios", "git clone", "nc ", "ssh ", "scp ")
# Rules about what a skill says rather than does. In reference docs these are
# usually descriptions, so they go to the LLM; in SKILL.md and code they block.
CONTEXTUAL_RULES = {"agent-config-write", "self-extract", "concealment", "reviewer-directed", "persistence"}


def _distance(a, b):
    row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev, row[0] = row[0], i
        for j, cb in enumerate(b, 1):
            prev, row[j] = row[j], min(row[j] + 1, row[j - 1] + 1, prev + (ca != cb))
    return row[-1]


def lookalike(name, protected):
    short = name.rsplit(":", 1)[-1].lower()
    for known in protected:
        if short != known and len(known) >= 5 and _distance(short, known) <= 2:
            return known
    return None


def _is_reference_doc(file):
    return file != "SKILL.md" and file.lower().endswith((".md", ".txt", ".rst"))


def _line(text, pos):
    return text.count("\n", 0, pos) + 1


def _add(findings, seen, rule, severity, file, line, message):
    key = (rule, file, line)
    if key not in seen:
        seen.add(key)
        findings.append({"rule": rule, "severity": severity, "file": file, "line": line, "message": message})


def scan(bundle, policy):
    rules = [(r, re.compile(r["pattern"], re.I | re.S)) for r in load_rules()]
    findings = list(bundle.findings)
    seen = set()
    known = lookalike(bundle.name, policy["protected_names"])
    if known:
        _add(findings, seen, "typosquat", "block", ".", 0, f"Name resembles {known!r}")
    if bundle.oversize:
        _add(findings, seen, "too-long-for-review", "review", ".", 0, "Skill is too long for a full LLM review")

    for file, text in bundle.texts.items():
        variants, notes = normalize(text)
        for rule, severity, line, message in notes:
            _add(findings, seen, rule, severity, file, line, message)
        for label, content in variants.items():
            for rule, pattern in rules:
                match = pattern.search(content)
                if match and not (label == "joined" and pattern.search(variants["text"])):
                    # Offsets differ between variants, so only "text" has a usable line number.
                    line = _line(content, match.start()) if label == "text" else 0
                    suffix = "" if label == "text" else f" ({label.split(':')[0]} form)"
                    severity = rule["severity"]
                    if rule["id"] in CONTEXTUAL_RULES and _is_reference_doc(file):
                        severity = "info"
                    _add(findings, seen, rule["id"], severity, file, line, rule["message"] + suffix)
            plain_hosts = {d[0] for d in net.destinations(variants["text"])}
            for host, path, line in net.destinations(content):
                if label == "joined" and host in plain_hosts:
                    continue
                lines = content.splitlines() or [""]
                source = lines[line - 1] if label == "text" and line <= len(lines) else ""
                if file.rsplit(".", 1)[-1].lower() in CODE_EXTENSIONS and any(w in content.lower() for w in NETWORK_WORDS):
                    source = "curl "  # Code that can reach the network treats any address as used.
                _check_destination(findings, seen, file, host, path, line if label == "text" else 0, policy, source)
    return findings


def _check_destination(findings, seen, file, host, path, line, policy, line_text=""):
    if host == "<dynamic>":
        _add(findings, seen, "dynamic-destination", "review", file, line, f"URL built at runtime: {path[:80]}")
        return
    status = net.classify(host, path, policy)
    if status == "denied":
        _add(findings, seen, "denied-host", "block", file, line, f"Denied destination: {host}")
    elif net.is_raw_ip(host):
        _add(findings, seen, "raw-ip", "block", file, line, f"Raw IP destination: {host}")
    elif status == "unknown":
        # A mention isn't a call: prose links go to the LLM as context and the
        # runtime gate stops any real request. Code and commands block here.
        if "." not in host:
            return
        used = any(w in line_text.lower() for w in NETWORK_WORDS)
        severity = "block" if used or (line == 0 and not line_text) else "info"
        _add(findings, seen, "offlist-host", severity, file, line, f"Not on the allowlist: {host}{path[:60]}")

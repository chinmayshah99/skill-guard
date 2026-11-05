"""Tool-call checks. A backstop for the sandbox, which remains the real network control."""
import json
import re
from pathlib import Path

from . import net
from .config import state_dir

SECRET_PATH = re.compile(
    r"(^|/)\.ssh(/|$)|\.aws/credentials|(^|/)\.netrc$|\.git-credentials|\.gnupg(/|$)|"
    r"(^|/)\.env(\.[\w-]+)?$|library/keychains|/proc/self/environ"
)
SECRET_IN_COMMAND = re.compile(
    r"\.ssh\b|\.aws/credentials|\.netrc\b|\.git-credentials|\.gnupg\b|(?<![\w.-])\.env\b|"
    r"security\s+(find|dump)-|/proc/self/environ|\bprintenv\b",
    re.I,
)
GUARD_PATH = re.compile(r"\.claude/settings[^/]*$|\.claude/skill-guard(/|$)|\.claude/plugins(/|$)|/skill-guard/(guard|hooks|config)/")
GUARD_IN_COMMAND = re.compile(
    r"\.claude/settings|\.claude/skill-guard|\.claude/plugins|disableAllHooks|guard/cli\.py\s+approve|plugin\s+(uninstall|disable|remove)",
    re.I,
)
SKILL_DIR = re.compile(r"(^|/)(\.claude/)?(skills|commands)/")
NETWORK_COMMAND = re.compile(r"(^|[\s;&|(`])(curl|wget|nc|ncat|socat|scp|sftp|ssh|telnet|ftp|rsync|git\s+(clone|push|fetch|pull)|pip3?\s+install|npm\s+(install|i)\b|brew\s+install)\b")
OPAQUE_COMMAND = re.compile(r"\b(eval|base64\s+(-d|-D|--decode)|python3?\s+-c|node\s+-e|perl\s+-e|ruby\s+-e)\b|\$\(")


def _session_path(session_id):
    safe = re.sub(r"[^\w-]", "", session_id or "unknown")
    return state_dir() / "sessions" / f"{safe}.json"


def mark_active(session_id, skill):
    path = _session_path(session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    state = json.loads(path.read_text()) if path.exists() else {"skills": []}
    state["skills"] = sorted({*state["skills"], skill})
    path.write_text(json.dumps(state))


def active_skills(session_id):
    path = _session_path(session_id)
    return json.loads(path.read_text())["skills"] if path.exists() else []


def _home_relative(path):
    return str(Path(path).expanduser()).lower()


def check(tool, tool_input, session_id, policy):
    """Return ('allow'|'ask'|'block', reason)."""
    active = active_skills(session_id)
    if tool == "Bash":
        return _check_bash(tool_input.get("command", ""), active, policy)
    if tool in ("Read", "Grep", "Glob"):
        path = tool_input.get("file_path") or tool_input.get("path") or ""
        pattern = tool_input.get("pattern", "") if tool == "Glob" else ""
        if SECRET_PATH.search(_home_relative(path)) or SECRET_PATH.search(pattern.lower()):
            return ("block" if active else "ask"), f"Access to a secret location: {path or pattern}"
        return "allow", ""
    if tool in ("Write", "Edit", "NotebookEdit"):
        path = _home_relative(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        if GUARD_PATH.search(path):
            return ("block" if active else "ask"), f"Changes guard or agent settings: {path}"
        if SKILL_DIR.search(path):
            return ("block" if active else "ask"), f"Changes a skill: {path}"
        return "allow", ""
    if not active:
        return "allow", ""
    if tool == "WebFetch":
        return _check_url(tool_input.get("url", ""), policy)
    if tool == "WebSearch":
        return "ask", "A skill is searching the web"
    if tool.startswith("mcp__"):
        server = tool.split("__")[1]
        if server in policy["mcp_allowlist"]:
            return "allow", ""
        return "ask", f"A skill is using an unlisted MCP server: {server}"
    return "allow", ""


def _check_url(url, policy):
    found = net.destinations(url)
    if not found:
        return "ask", f"Couldn't read destination: {url[:100]}"
    for host, path, _ in found:
        if host == "<dynamic>":
            return "ask", f"Destination decided at runtime: {path[:100]}"
        if net.classify(host, path, policy) != "allowed":
            return "block", f"Destination isn't allowed: {host}"
    return "allow", ""


def _check_bash(command, active, policy):
    if GUARD_IN_COMMAND.search(command):
        return ("block" if active else "ask"), "Command touches guard or agent settings"
    if SECRET_IN_COMMAND.search(command):
        return ("block" if active else "ask"), "Command touches a secret location"
    if not active:
        return "allow", ""
    found = net.destinations(command)
    for host, path, _ in found:
        if host == "<dynamic>":
            return "ask", f"Destination decided at runtime: {path[:100]}"
        if net.classify(host, path, policy) != "allowed":
            return "block", f"Destination isn't allowed: {host}"
    if NETWORK_COMMAND.search(command) and not found:
        return "ask", "Network command with no readable destination"
    if OPAQUE_COMMAND.search(command):
        return "ask", "Command can't be fully inspected"
    return "allow", ""

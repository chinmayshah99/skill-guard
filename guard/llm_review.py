"""LLM review. Output can only raise a skill's risk, never clear a static finding."""
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .config import ROOT
from .normalize import normalize


class ReviewError(Exception):
    """Any failure here must end in a block, with text the user can act on."""


REVIEW_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["canary", "verdict", "risk", "injection_attempt", "purpose_mismatch", "findings"],
    "properties": {
        "canary": {"type": "string"},
        "verdict": {"type": "string", "enum": ["safe", "suspicious", "malicious"]},
        "risk": {"type": "string", "enum": ["low", "medium", "high"]},
        "injection_attempt": {"type": "boolean"},
        "purpose_mismatch": {"type": "boolean"},
        "findings": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["file", "line", "reason"],
            "properties": {"file": {"type": "string"}, "line": {"type": "integer"}, "reason": {"type": "string"}},
        }},
    },
}
EXTRACT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["canary", "purpose", "domains", "commands", "file_access", "downloads_code", "dynamic_destinations"],
    "properties": {
        "canary": {"type": "string"},
        "purpose": {"type": "string"},
        "domains": {"type": "array", "items": {"type": "string"}},
        "commands": {"type": "array", "items": {"type": "string"}},
        "file_access": {"type": "array", "items": {"type": "string"}},
        "downloads_code": {"type": "boolean"},
        "dynamic_destinations": {"type": "boolean"},
    },
}


def validate(value, schema, path="$"):
    kind = schema["type"]
    expected = {"object": dict, "array": list, "string": str, "boolean": bool}.get(kind)
    if kind == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise ReviewError(f"{path}: expected integer")
    elif not isinstance(value, expected):
        raise ReviewError(f"{path}: expected {kind}")
    if "enum" in schema and value not in schema["enum"]:
        raise ReviewError(f"{path}: unexpected value")
    if kind == "object":
        if set(value) != set(schema["required"]):
            raise ReviewError(f"{path}: wrong fields")
        for key, child in schema["properties"].items():
            validate(value[key], child, f"{path}.{key}")
    if kind == "array":
        for index, item in enumerate(value):
            validate(item, schema["items"], f"{path}[{index}]")


def _child_env():
    keep = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "TMPDIR", "SHELL", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CODEX_HOME")
    return {k: os.environ[k] for k in keep if k in os.environ}


def _run(command, prompt, cwd, timeout):
    try:
        done = subprocess.run(command, input=prompt, capture_output=True, text=True,
                              cwd=cwd, env=_child_env(), timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ReviewError(f"{command[0]} timed out") from None
    if done.returncode != 0:
        detail = (done.stderr or done.stdout).strip().splitlines()[-1:] or ["no output"]
        raise ReviewError(f"{command[0]} failed: {detail[0][:200]}. Check that you're logged in.")
    return done.stdout


class ClaudeCli:
    id = "claude-cli"

    def __init__(self, model, timeout):
        self.model, self.timeout = model, timeout

    def complete(self, system, content, schema):
        command = ["claude", "-p", "--tools", "", "--strict-mcp-config", "--disable-slash-commands",
                   "--setting-sources", "", "--settings", '{"disableAllHooks":true}',
                   "--no-session-persistence", "--system-prompt", system,
                   "--output-format", "json", "--json-schema", json.dumps(schema)]
        if self.model:
            command += ["--model", self.model]
        with tempfile.TemporaryDirectory() as empty:
            result = json.loads(_run(command, content, empty, self.timeout))
        if result.get("is_error") or "structured_output" not in result:
            raise ReviewError("Claude returned no structured review")
        return result["structured_output"]


class CodexCli:
    id = "codex-cli"

    def __init__(self, model, timeout):
        self.model, self.timeout = model, timeout

    def complete(self, system, content, schema):
        with tempfile.TemporaryDirectory() as empty:
            schema_path = os.path.join(empty, "schema.json")
            with open(schema_path, "w") as handle:
                json.dump(schema, handle)
            command = ["codex", "exec", "--ephemeral", "--skip-git-repo-check", "--ignore-user-config",
                       "--ignore-rules", "-s", "read-only", "-C", empty, "--output-schema", schema_path]
            if self.model:
                command += ["-m", self.model]
            output = _run(command, f"{system}\n\n{content}", empty, self.timeout)
        lines = [line for line in output.splitlines() if line.strip()]
        if not lines:
            raise ReviewError("Codex returned no review")
        return json.loads(lines[-1])


class AnthropicApi:
    id = "anthropic-api"

    def __init__(self, model, timeout):
        self.model, self.timeout = model, timeout

    def complete(self, system, content, schema):
        body = {
            "model": self.model, "max_tokens": 4000, "system": system,
            "messages": [{"role": "user", "content": content}],
            "tools": [{"name": "report", "description": "Report the result", "input_schema": schema}],
            "tool_choice": {"type": "tool", "name": "report"},
        }
        request = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", json.dumps(body).encode(),
            {"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01",
             "content-type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                reply = json.load(response)
        except OSError as error:
            raise ReviewError(f"Anthropic API failed: {error}") from None
        return next(block["input"] for block in reply["content"] if block["type"] == "tool_use")


REVIEWERS = ("claude-cli", "codex-cli", "anthropic-api")


def backends(policy):
    """Return one or two reviewers. With one, it runs both review prompts.

    "auto" uses the first installed of Claude, Codex, then the API. A reviewer
    named in config must be available: swapping in another would send skill
    content to a provider the user didn't choose.
    """
    timeout, models = policy["llm_call_timeout_seconds"], policy["models"]
    available = {
        "claude-cli": lambda: ClaudeCli(models.get("claude-cli"), timeout) if shutil.which("claude") else None,
        "codex-cli": lambda: CodexCli(models.get("codex-cli"), timeout) if shutil.which("codex") else None,
        "anthropic-api": lambda: AnthropicApi(models.get("anthropic-api"), timeout) if os.environ.get("ANTHROPIC_API_KEY") else None,
    }
    if policy["reviewers"] == "auto":
        for name in REVIEWERS:
            made = available[name]()
            if made:
                return [made]
        raise ReviewError("No reviewer available. Install and log in to Claude Code or Codex, or set ANTHROPIC_API_KEY.")
    found = []
    for name in policy["reviewers"]:
        made = available[name]()
        if made is None:
            raise ReviewError(f"Configured reviewer {name} isn't available. Install it, log in, or change reviewers in config.toml.")
        found.append(made)
    return found


def backend_ids(policy):
    return [b.id + ":" + (b.model or "default") for b in backends(policy)]


def _wrap(texts, nonce):
    parts = []
    for name, text in texts.items():
        variants, _ = normalize(text)
        clean = variants["text"].replace(nonce, "")
        # Numbered lines, so reviewers cite real locations instead of guessing.
        numbered = "\n".join(f"{n:>5}| {line}" for n, line in enumerate(clean.splitlines(), 1))
        parts.append(f'<file id="{nonce}" path={json.dumps(name)}>\n{numbered}\n</file id="{nonce}">')
    return "\n".join(parts)


def _fix_locations(result, texts):
    """Drop line numbers that don't exist, rather than show a wrong location."""
    for item in result.get("findings", []):
        lines = texts.get(item["file"], "").count("\n") + 1 if item["file"] in texts else 0
        if not 1 <= item["line"] <= lines:
            item["line"] = 0


def _ask(backend, prompt_file, texts, schema, total=1):
    nonce, canary = secrets.token_hex(8), secrets.token_hex(8)
    system = (ROOT / "guard" / "prompts" / prompt_file).read_text().replace("{{NONCE}}", nonce).replace("{{CANARY}}", canary)
    try:
        result = backend.complete(system, _wrap(texts, nonce), schema)
    except (json.JSONDecodeError, KeyError, StopIteration) as error:
        raise ReviewError(f"{backend.id} returned malformed output") from error
    validate(result, schema)
    if result["canary"] != canary:
        raise ReviewError(f"{backend.id} failed the canary check, which can indicate injection")
    _fix_locations(result, texts)
    style = "adversarial" if "adversarial" in prompt_file else "standard"
    scope = f", {next(iter(texts))} only" if len(texts) == 1 and len(texts) < total else ""
    result["_source"] = f"{backend.id} ({style}{scope})"
    result["_voter"] = f"{backend.id}:{style}"
    return result


def review(bundle, policy):
    """Return extracted facts plus every independent review."""
    active = backends(policy)
    first, second = active[0], active[-1]
    jobs = [("extract", first, "extract.md", bundle.texts, EXTRACT_SCHEMA),
            ("review", first, "review.md", bundle.texts, REVIEW_SCHEMA),
            ("review", second, "review_adversarial.md", bundle.texts, REVIEW_SCHEMA)]
    # With several files, each is judged alone so one can't vouch for another.
    if len(bundle.texts) > 1:
        ranked = sorted(bundle.texts.items(), key=lambda kv: -len(kv[1]))
        for name, text in ranked[: policy["max_per_file_reviews"]]:
            jobs.append(("review", second, "review_adversarial.md", {name: text}, REVIEW_SCHEMA))
    unreviewed = max(0, len(bundle.texts) - policy["max_per_file_reviews"])

    deadline = time.monotonic() + policy["review_deadline_seconds"]
    pool = ThreadPoolExecutor(max_workers=4)
    futures = [(kind, pool.submit(_ask, backend, prompt, texts, schema, len(bundle.texts)))
               for kind, backend, prompt, texts, schema in jobs]
    facts, reviews = None, []
    try:
        for kind, future in futures:
            result = future.result(timeout=max(1, deadline - time.monotonic()))
            if kind == "extract":
                facts = result
            else:
                reviews.append(result)
    except TimeoutError:
        raise ReviewError("Review ran past its deadline") from None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return {"facts": facts, "reviews": reviews, "unreviewed_files": unreviewed}

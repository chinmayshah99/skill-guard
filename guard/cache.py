"""Signed verdict cache. An unsigned or altered entry is treated as a miss."""
import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import time

from .config import PROMPT_VERSION, state_dir

SERVICE, ACCOUNT = "skill-guard", "cache-signing-key"


def _run(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, timeout=10, **kwargs)


def signing_key():
    """Return the key from the OS secret store, or None if there isn't one."""
    override = os.environ.get("SKILL_GUARD_TEST_KEY")
    if override:
        return override.encode()
    fresh = secrets.token_hex(32)
    if shutil.which("security"):
        found = _run(["security", "find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"])
        if found.returncode == 0:
            return found.stdout.strip().encode()
        made = _run(["security", "add-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w", fresh])
        return fresh.encode() if made.returncode == 0 else None
    if shutil.which("secret-tool"):
        attrs = ["service", SERVICE, "account", ACCOUNT]
        found = _run(["secret-tool", "lookup", *attrs])
        if found.returncode == 0 and found.stdout:
            return found.stdout.strip().encode()
        made = _run(["secret-tool", "store", "--label=skill-guard", *attrs], input=fresh)
        return fresh.encode() if made.returncode == 0 else None
    return None


def cache_key(digest, policy, backend_ids):
    material = json.dumps([digest, policy["policy_version"], PROMPT_VERSION, sorted(backend_ids)])
    return hashlib.sha256(material.encode()).hexdigest()


def _sign(key, body):
    return hmac.new(key, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()


def _path(entry_key):
    return state_dir() / "cache" / f"{entry_key}.json"


def load(entry_key, policy):
    key = signing_key()
    path = _path(entry_key)
    if key is None or not path.exists():
        return None
    try:
        entry = json.loads(path.read_text())
        body, signature = entry["body"], entry["signature"]
    except (ValueError, KeyError, TypeError):
        return None
    if not hmac.compare_digest(_sign(key, body), signature) or body["key"] != entry_key:
        return None
    if time.time() - body["time"] > policy["cache_ttl_days"] * 86400:
        return None
    return body


def store(entry_key, verdict, findings):
    key = signing_key()
    if key is None:
        return False
    body = {"key": entry_key, "verdict": verdict, "findings": findings, "time": int(time.time())}
    path = _path(entry_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps({"body": body, "signature": _sign(key, body)}))
    temp.replace(path)
    return True

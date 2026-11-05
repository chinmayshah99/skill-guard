"""Policy loading. Org policy wins over user policy, which wins over defaults."""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPT_VERSION = 1
REVIEWERS = ("claude-cli", "codex-cli", "anthropic-api")


class ConfigError(Exception):
    """A bad config blocks every skill, so a typo can't silently weaken the guard."""


def state_dir():
    return Path.home() / ".claude" / "skill-guard"


def user_path():
    return state_dir() / "config.toml"


def managed_path():
    return Path(os.environ.get(
        "SKILL_GUARD_MANAGED_POLICY",
        "/Library/Application Support/ClaudeCode/skill-guard.toml"
        if os.uname().sysname == "Darwin" else "/etc/claude-code/skill-guard.toml",
    ))


def _read_toml(path):
    try:
        import tomllib
    except ImportError:
        raise ConfigError(f"{path} needs Python 3.11 or later to read") from None
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"{path} isn't valid TOML: {error}") from None


def _merge(base, override, path, where=""):
    """Tables merge key by key; lists and values replace."""
    for key, value in override.items():
        name = f"{where}{key}"
        if key not in base:
            raise ConfigError(f"{path}: unknown setting {name!r}")
        if isinstance(base[key], dict):
            if not isinstance(value, dict):
                raise ConfigError(f"{path}: {name!r} must be a table")
            _merge(base[key], value, path, f"{name}.")
        elif type(value) is not type(base[key]) and not (key == "reviewers" and isinstance(value, list)):
            raise ConfigError(f"{path}: {name!r} must be {type(base[key]).__name__}")
        else:
            base[key] = value


def _validate(policy):
    if policy["mode"] not in ("enforce", "audit"):
        raise ConfigError('mode must be "enforce" or "audit"')
    reviewers = policy["reviewers"]
    if reviewers != "auto":
        if not isinstance(reviewers, list) or not 1 <= len(reviewers) <= 2 or len(set(reviewers)) != len(reviewers):
            raise ConfigError('reviewers must be "auto" or a list of one or two different reviewers')
        unknown = [r for r in reviewers if r not in REVIEWERS]
        if unknown:
            raise ConfigError(f"unknown reviewer {unknown[0]!r}; choose from {', '.join(REVIEWERS)}")


def load_policy():
    policy = json.loads((ROOT / "config" / "policy.default.json").read_text())
    managed = managed_path()
    for path in (user_path(), managed):
        if path.exists():
            _merge(policy, _read_toml(path), path)
    _validate(policy)
    policy["managed"] = managed.exists()
    return policy


def load_rules():
    return json.loads((ROOT / "config" / "rules.json").read_text())

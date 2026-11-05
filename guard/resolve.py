"""Map a skill name to the folders or single files that define it."""
from pathlib import Path


def _project_roots(cwd):
    cwd = Path(cwd).resolve()
    home = Path.home().resolve()
    for path in [cwd, *cwd.parents]:
        if path == home:
            break
        yield path


def _plugin_matches(short, plugin):
    root = Path.home() / ".claude" / "plugins"
    if not root.is_dir():
        return
    for pattern in (f"**/skills/{short}/SKILL.md", f"**/commands/{short}.md"):
        for hit in root.glob(pattern):
            if plugin and plugin not in hit.parts:
                continue
            yield hit.parent if hit.name == "SKILL.md" else hit


def resolve(name, cwd):
    """Return every location that could supply this skill, deduplicated."""
    plugin, _, short = name.rpartition(":")
    if not short or "/" in short or short in (".", ".."):
        return []
    found = []
    if not plugin:
        bases = [p / ".claude" for p in _project_roots(cwd)]
        bases += [Path.home() / ".claude"]
        for base in bases:
            for candidate in (base / "skills" / short, base / "skills" / "synced" / short):
                if (candidate / "SKILL.md").is_file():
                    found.append(candidate)
            command = base / "commands" / f"{short}.md"
            if command.is_file():
                found.append(command)
    found.extend(_plugin_matches(short, plugin))
    return list(dict.fromkeys(found))


def skill_for_path(path):
    """If path sits inside a skill, return that skill's folder."""
    path = Path(path)
    for parent in [path.parent, *path.parent.parents]:
        if (parent / "SKILL.md").is_file():
            return parent
    return None

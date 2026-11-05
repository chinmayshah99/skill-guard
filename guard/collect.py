"""Read every file in a skill, hidden ones included, and hash the result."""
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

MAGIC = {
    "png": [b"\x89PNG"], "jpg": [b"\xff\xd8\xff"], "jpeg": [b"\xff\xd8\xff"],
    "gif": [b"GIF8"], "webp": [b"RIFF"], "ico": [b"\x00\x00\x01\x00"], "pdf": [b"%PDF"],
    "woff": [b"wOFF"], "woff2": [b"wOF2"], "ttf": [b"\x00\x01\x00\x00", b"true"], "otf": [b"OTTO"],
}


@dataclass
class Bundle:
    root: Path
    name: str
    digest: str = ""
    texts: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    total_bytes: int = 0
    oversize: bool = False


def _finding(rule, severity, file, message):
    return {"rule": rule, "severity": severity, "file": file, "line": 0, "message": message}


def collect(target, policy):
    target = Path(target)
    root = target if target.is_dir() else target.parent
    paths = [target] if target.is_file() else None
    bundle = Bundle(root=root, name=target.stem if target.is_file() else target.name)
    limits = policy["limits"]
    digest = hashlib.sha256()

    if paths is None:
        paths = []
        # followlinks stays off, so nothing outside the skill is read by accident.
        for folder, dirs, files in os.walk(root, followlinks=False):
            dirs.sort()
            for entry in dirs:
                link = Path(folder) / entry
                if link.is_symlink():
                    paths.append(link)
            paths.extend(Path(folder) / item for item in sorted(files))
    if len(paths) > limits["file_count"]:
        bundle.findings.append(_finding("too-many-files", "block", ".", f"{len(paths)} files"))
        paths = paths[: limits["file_count"]]

    resolved_root = root.resolve()
    for path in sorted(paths):
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode() + b"\0")
        if path.is_symlink():
            link = os.readlink(path)
            digest.update(link.encode() + b"\0")
            if not path.resolve().is_relative_to(resolved_root):
                bundle.findings.append(_finding("symlink-escape", "block", rel, f"Links outside the skill: {link}"))
            else:
                bundle.findings.append(_finding("symlink", "review", rel, "Symlink inside the skill"))
            continue
        if not path.is_file():
            bundle.findings.append(_finding("special-file", "block", rel, "Not a regular file"))
            continue
        size = path.stat().st_size
        bundle.total_bytes += size
        if size > limits["file_bytes"]:
            bundle.findings.append(_finding("file-too-large", "block", rel, f"{size} bytes"))
        if bundle.total_bytes > limits["total_bytes"]:
            bundle.findings.append(_finding("skill-too-large", "block", rel, "Skill exceeds total size limit"))
            break
        data = path.read_bytes()
        digest.update(hashlib.sha256(data).digest())
        digest.update(b"x" if os.access(path, os.X_OK) else b"-")
        _classify(bundle, rel, data, policy)

    bundle.digest = digest.hexdigest()
    bundle.oversize = sum(len(t) for t in bundle.texts.values()) > limits["llm_chars"]
    return bundle


def _classify(bundle, rel, data, policy):
    ext = rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
    if b"\0" not in data:
        try:
            bundle.texts[rel] = data.decode("utf-8")
            return
        except UnicodeDecodeError:
            pass
    if ext in policy["inert_binary_types"] and any(data.startswith(m) for m in MAGIC.get(ext, [])):
        bundle.findings.append(_finding("media-file", "review", rel, f"Unreviewed {ext} file"))
    else:
        bundle.findings.append(_finding("unreadable-file", "block", rel, "Binary or unreadable file can't be reviewed"))

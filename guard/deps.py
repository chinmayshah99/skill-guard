"""Check a skill's packages against OSV. Sends names and versions, never skill content."""
import hashlib
import json
import re
import time
import urllib.error
import urllib.request

from . import cache

OSV = "https://api.osv.dev/v1"
PINNED = re.compile(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?==([A-Za-z0-9._!+-]+)")
TOML_PACKAGE = re.compile(r'^name = "([^"]+)"\nversion = "([^"]+)"', re.M)
SERIOUS = {"HIGH", "CRITICAL"}


def _finding(rule, severity, file, message):
    return {"rule": rule, "severity": severity, "file": file, "line": 0, "message": message}


def _from_lock(data, found):
    for path, info in data.get("packages", {}).items():
        if "node_modules/" in path and info.get("version"):
            found.add(("npm", info.get("name") or path.rsplit("node_modules/", 1)[1], info["version"]))


def parse(texts):
    """Return ({(ecosystem, name, version)}, findings for what can't be pinned down)."""
    found, findings = set(), []
    for file, text in texts.items():
        name = file.rsplit("/", 1)[-1]
        try:
            if name in ("package-lock.json", "npm-shrinkwrap.json"):
                _from_lock(json.loads(text), found)
            elif name == "package.json":
                data = json.loads(text)
                if "node_modules/" in file:
                    if data.get("name") and data.get("version"):
                        found.add(("npm", data["name"], data["version"]))
                elif data.get("dependencies") and not any(
                        k.rsplit("/", 1)[-1] in ("package-lock.json", "npm-shrinkwrap.json") for k in texts):
                    findings.append(_finding("unpinned-deps", "review", file, "Dependencies have no lockfile"))
        except (ValueError, AttributeError):
            findings.append(_finding("unreadable-manifest", "review", file, "Couldn't parse this manifest"))
        if name.startswith("requirements") and name.endswith(".txt"):
            for line in text.splitlines():
                line = line.split("#")[0].strip()
                if not line or line.startswith("-"):
                    continue
                pinned = PINNED.match(line)
                if pinned:
                    found.add(("PyPI", pinned[1], pinned[2]))
                else:
                    findings.append(_finding("unpinned-deps", "review", file, f"Unpinned dependency: {line[:60]}"))
        elif name in ("uv.lock", "poetry.lock"):
            found.update(("PyPI", n, v) for n, v in TOML_PACKAGE.findall(text))
        elif name == "METADATA" and ".dist-info/" in file:
            package = re.search(r"^Name: (.+)$", text, re.M)
            version = re.search(r"^Version: (.+)$", text, re.M)
            if package and version:
                found.add(("PyPI", package[1].strip(), version[1].strip()))
    return found, findings


def _post(path, body, timeout):
    request = urllib.request.Request(f"{OSV}/{path}", json.dumps(body).encode(), {"content-type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def _severity(vuln_id, timeout):
    with urllib.request.urlopen(f"{OSV}/vulns/{vuln_id}", timeout=timeout) as response:
        return json.load(response).get("database_specific", {}).get("severity", "UNKNOWN").upper()


def lookup(packages, timeout=15):
    """Return findings for sorted (ecosystem, name, version) tuples."""
    queries = [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in packages]
    findings = []
    for start in range(0, len(queries), 500):
        batch = queries[start:start + 500]
        results = _post("querybatch", {"queries": batch}, timeout)["results"]
        for query, result in zip(batch, results):
            label = f"{query['package']['name']}@{query['version']}"
            ids = [v["id"] for v in result.get("vulns", [])]
            if any(i.startswith("MAL-") for i in ids):
                findings.append(_finding("malicious-package", "block", "dependencies", f"Known malicious package: {label}"))
                continue
            serious = [i for i in ids[:10] if _severity(i, timeout) in SERIOUS]
            if serious:
                findings.append(_finding("vulnerable-package", "review", "dependencies",
                                         f"{label} has serious advisories: {', '.join(serious[:3])}"))
            elif ids:
                findings.append(_finding("minor-advisory", "info", "dependencies", f"{label}: {ids[0]}"))
    return findings


def check(texts, policy):
    """Advisories change daily, so results are cached for a day apart from the review."""
    packages, findings = parse(texts)
    if not packages or not policy.get("dependency_check", True):
        return findings
    ordered = sorted(packages)
    day = int(time.time() // 86400)
    key = hashlib.sha256(json.dumps([ordered, day]).encode()).hexdigest()
    cached = cache.load(key, policy)
    if cached and cached["verdict"] == "deps":
        return findings + cached["findings"]
    try:
        looked_up = lookup(ordered)
    except (urllib.error.URLError, OSError, ValueError, KeyError) as error:
        # Unknown isn't clean: a person decides, and nothing is cached.
        return findings + [_finding("deps-unchecked", "review", "dependencies", f"Couldn't check advisories: {error}")]
    cache.store(key, "deps", looked_up)
    return findings + looked_up

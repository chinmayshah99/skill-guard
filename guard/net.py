"""Find destinations in text and compare them to the allowlist."""
import ipaddress
import re
from urllib.parse import urlsplit

URL = re.compile(r"\b(?:https?|ftp|ssh|git|wss?)://[^\s'\"<>)\]}`|\\]+", re.I)
IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
GIT_SSH = re.compile(r"\bgit@([\w.-]+):(\S+)")
BARE_HOST = re.compile(
    r"(?<![\w./@-])((?:[a-z0-9-]+\.)+(?:com|net|org|io|ai|dev|app|xyz|ru|cn|top|site|info|gg))(/[^\s'\"<>)]*)?(?![\w-])",
    re.I,
)


def destinations(text):
    """Return (host, path, line) for everything that looks like a destination."""
    found = []
    consumed = []

    def line(pos):
        return text.count("\n", 0, pos) + 1

    for match in URL.finditer(text):
        parts = urlsplit(match.group().rstrip(".,;:"))
        consumed.append(match.span())
        if "$" in match.group() or "{" in match.group():
            found.append(("<dynamic>", match.group(), line(match.start())))
        elif parts.hostname:
            found.append((parts.hostname.lower(), parts.path or "/", line(match.start())))
    for match in GIT_SSH.finditer(text):
        consumed.append(match.span())
        found.append((match.group(1).lower(), "/" + match.group(2), line(match.start())))
    within = lambda pos: any(start <= pos < end for start, end in consumed)
    for match in IPV4.finditer(text):
        if not within(match.start()):
            try:
                ipaddress.ip_address(match.group(1))
            except ValueError:
                continue
            found.append((match.group(1), "/", line(match.start())))
    for match in BARE_HOST.finditer(text):
        if not within(match.start()):
            found.append((match.group(1).lower(), match.group(2) or "/", line(match.start())))
    return found


def _host_matches(host, pattern):
    return host == pattern or host.endswith("." + pattern)


def classify(host, path, policy):
    """Return 'allowed', 'denied' or 'unknown'. Deny always beats allow."""
    if any(_host_matches(host, item) for item in policy["denied_hosts"]):
        return "denied"
    for entry in policy["allowlist"]:
        if host == entry["host"]:
            prefixes = entry.get("paths")
            if not prefixes or any(path.startswith(p) for p in prefixes):
                return "allowed"
    return "unknown"


def is_raw_ip(host):
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False

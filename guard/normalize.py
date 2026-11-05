"""Undo common text tricks so rules and reviewers see what the agent would act on."""
import base64
import binascii
import re
import unicodedata

INVISIBLE = re.compile("[­͏؜᠎​-‏‪-‮⁠-⁤⁦-⁯﻿\U000e0000-\U000e007f]")
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j",
    "һ": "h", "ԁ": "d", "ɡ": "g", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t",
})
WORD = re.compile(r"[^\W\d_]{2,}")
BASE64 = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")
HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){20,}\b")
# Joins fragments such as c""url, cu'r'l, c\url and "cu""rl".
SPLICE = re.compile(r"(?<=\w)(?:''|\"\"|\\|'(?=\w+')|\"(?=\w+\"))")
QUOTE_GAP = re.compile(r"(?<=\w)['\"](?=\s*\+?\s*['\"]?\w)")
CONCAT = re.compile(r"['\"]\s*\+\s*['\"]")


def _mixed_script(word):
    scripts = {unicodedata.name(ch, "?").split(" ")[0] for ch in word}
    # Short Greek-Latin mixes are ordinary maths notation, such as "πm".
    return "LATIN" in scripts and ("CYRILLIC" in scripts or ("GREEK" in scripts and len(word) >= 4))


def _decoded_blobs(text):
    for match in BASE64.finditer(text):
        blob = match.group()
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(blob + "=" * (-len(blob) % 4))
                yield match.start(), raw.decode("utf-8")
                break
            except (binascii.Error, ValueError):
                continue
    for match in HEX.finditer(text):
        try:
            yield match.start(), bytes.fromhex(match.group()).decode("utf-8")
        except ValueError:
            continue


def normalize(text):
    """Return (variants, findings). variants maps a label to text to scan."""
    findings = []
    text = text.removeprefix("\ufeff")  # A leading byte-order mark is harmless.
    hidden = INVISIBLE.findall(text)
    if hidden:
        tag = any(0xE0000 <= ord(c) <= 0xE007F for c in hidden)
        findings.append(("hidden-unicode", "block", 0,
                         f"{len(hidden)} hidden characters" + (" including Unicode tags" if tag else "")))
    clean = INVISIBLE.sub("", unicodedata.normalize("NFKC", text))
    for word in WORD.findall(clean):
        if _mixed_script(word):
            findings.append(("homoglyph", "block", 0, f"Mixed-alphabet word: {word!r}"))
            break
    clean = clean.translate(CONFUSABLES)
    joined = CONCAT.sub("", SPLICE.sub("", clean))
    joined = re.sub(r"\$\{?[a-z_]*\}?(?=[a-z])", "", QUOTE_GAP.sub("", joined), flags=re.I)
    variants = {"text": clean, "joined": joined}
    for index, (offset, decoded) in enumerate(_decoded_blobs(clean)):
        line = clean.count("\n", 0, offset) + 1
        findings.append(("encoded-blob", "review", line, "Encoded text was decoded and scanned"))
        variants[f"decoded:{index}"] = decoded
    return variants, findings

"""Append-only decision log. Holds names and verdicts, never skill content."""
import json
import time

from .config import state_dir


def log(event, **fields):
    path = state_dir() / "audit.log"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as handle:
            handle.write(json.dumps({"time": int(time.time()), "event": event, **fields}) + "\n")
    except OSError:
        pass  # A full disk shouldn't turn into a blocked or allowed skill.

"""Make command-line output survive consoles that do not default to UTF-8.

The reports contain characters like "·" and "🔴". On Linux and macOS the console is
normally UTF-8, but on Windows it defaults to the legacy ANSI code page (cp1252,
cp437, ...) and printing one of those characters raises UnicodeEncodeError, which
turns a successful run into a traceback. The fix is per-stream: ask for UTF-8 and
replace whatever the console still cannot show instead of crashing.

Standard library only.
"""
from __future__ import annotations

import sys


def use_utf8() -> None:
    """Reconfigure stdout and stderr to UTF-8. Safe to call more than once."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:          # replaced by a test runner or a pipe wrapper
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass

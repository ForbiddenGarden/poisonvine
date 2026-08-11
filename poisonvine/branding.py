"""
POISONVINE branding — braille-art vine logo, block wordmark, rotating
security-culture quotes, and the launch banner.

Kept deliberately dependency-light at import time: `rich` is a core dependency
but the banner degrades to plain text if the terminal or rich is unavailable,
so `pv --help` still works in a bare environment.
"""

from __future__ import annotations

import random
import shutil

__all__ = ["banner", "random_quote", "LOGO", "QUOTES", "TAGLINE"]

TAGLINE = "DNS-borne prompt injection, for the people who have to defend against it."

# ── Block wordmark ─────────────────────────────────────────────────────────
# A tiny 5-row half-block font, just the glyphs POISONVINE needs. Rendered as
# two stacked words so the mark stays inside 80 columns.

_GLYPHS: dict[str, list[str]] = {
    "P": ["████ ", "█  █ ", "████ ", "█    ", "█    "],
    "O": [" ███ ", "█   █", "█   █", "█   █", " ███ "],
    "I": ["█████", "  █  ", "  █  ", "  █  ", "█████"],
    "S": [" ████", "█    ", " ███ ", "    █", "████ "],
    "N": ["█   █", "██  █", "█ █ █", "█  ██", "█   █"],
    "V": ["█   █", "█   █", "█   █", " █ █ ", "  █  "],
    "E": ["█████", "█    ", "███  ", "█    ", "█████"],
    " ": ["     ", "     ", "     ", "     ", "     "],
}


def _render_word(word: str) -> list[str]:
    rows = ["", "", "", "", ""]
    for ch in word:
        glyph = _GLYPHS.get(ch.upper(), _GLYPHS[" "])
        for i in range(5):
            rows[i] += glyph[i] + " "
    return [r.rstrip() for r in rows]


# ── Braille-art vine ───────────────────────────────────────────────────────
# A creeping thorn-vine drawn in Unicode braille (U+2800 block). Swells toward
# the middle like a living stem, with leaf/tendril accents above and below.

_VINE_LEAF = "⢠⡤⠆          ⢠⡤⠆                    ⠰⢤⡄          ⠰⢤⡄"
_VINE_STEM = "⠶⠿⣷⣶⣤⣀⡀⠀⢀⣀⣤⣶⣶⣿⣿⣶⣶⣤⣀⡀⠀⢀⣀⣤⣶⣶⣿⣿⣶⣶⣤⣀⡀⠀⢀⣀⣤⣶⣶⠿⠶"
_VINE_TENDRIL = "⠈⠑⠦⣀      ⣀⠴⠚⠉⠙⠲⢤⣀      ⣀⡤⠖⠋⠉⠓⠦⣀      ⣀⠴⠋⠁"


# ── Quotes ─────────────────────────────────────────────────────────────────
# Security-culture aphorisms + originals themed to the tool. Short sayings,
# shown one-at-random on launch.

QUOTES: list[str] = [
    "The vine doesn't break the wall. It waits for the wall to trust it.",
    "A signed record proves who planted the seed — not that the fruit is safe to eat.",
    "Every field that carries a directive is a field that carries a payload.",
    "DNSSEC authenticates the messenger. It never read the message.",
    "The model didn't disobey you. It obeyed someone else.",
    "Trust is the only vulnerability that ships enabled by default.",
    "You don't own a domain. You rent the right to be believed.",
    "A tool that can describe itself can lie about itself.",
    "Recon output is attacker-controlled the moment it leaves their zone.",
    "The safest parser is the one that assumes every byte is hostile.",
    "In the garden, the prettiest bloom is the one you should test first.",
    "Injection isn't a bug in the model. It's a feature of language.",
    "If it reaches the context window, it reaches the decision.",
    "Deprecation notices are just redirects with better manners.",
    "The capability document is a promise. Promises are not access controls.",
    "Cross-field splitting: no single scanner ever sees the whole sentence.",
    "A canary in the record is worth a thousand assumptions in the pipeline.",
    "Camouflage beats coercion. Ambient beats imperative.",
    "The channel you forgot to sanitize is the one they're already using.",
    "Poison travels well in structured data. It looks like configuration.",
    "Test your own systems before someone tests them for you.",
    "Authenticity of origin is not integrity of intent.",
]


def random_quote() -> str:
    return random.choice(QUOTES)


# ── Assembly ───────────────────────────────────────────────────────────────

def _plain_logo() -> str:
    lines = [_VINE_LEAF, _VINE_STEM, ""]
    lines += _render_word("POISON")
    lines += _render_word("VINE")
    lines += ["", _VINE_STEM, _VINE_TENDRIL]
    return "\n".join(lines)


LOGO = _plain_logo()


def banner(version: str, subtitle: str | None = None, no_color: bool = False) -> str:
    """Return the full launch banner as a printable string.

    Uses rich markup for color when available and a color-capable TTY is
    detected; otherwise returns clean plain text.
    """
    quote = random_quote()
    sub = subtitle or TAGLINE

    use_rich = not no_color
    if use_rich:
        try:
            from rich.console import Console
            from rich.text import Text
        except Exception:
            use_rich = False

    if not use_rich:
        width = shutil.get_terminal_size((80, 24)).columns
        rule = "─" * min(width, 64)
        return (
            f"{LOGO}\n{rule}\n"
            f"  poisonvine v{version} · {sub}\n"
            f"  “{quote}”\n{rule}\n"
            "  Authorized research use only — point it at systems you control.\n"
        )

    from io import StringIO
    from rich.console import Console
    from rich.text import Text

    buf = StringIO()
    console = Console(file=buf, force_terminal=True, color_system="truecolor")

    stem = Text()
    for line in (_VINE_LEAF, _VINE_STEM):
        stem.append(line + "\n", style="bold #2fbf4f")
    console.print(stem, end="")

    mark = Text()
    for row in _render_word("POISON"):
        mark.append(row + "\n", style="bold #b026ff")
    for row in _render_word("VINE"):
        mark.append(row + "\n", style="bold #39ff14")
    console.print(mark, end="")

    tail = Text()
    for line in (_VINE_STEM, _VINE_TENDRIL):
        tail.append(line + "\n", style="bold #2fbf4f")
    console.print(tail, end="")

    meta = Text()
    meta.append(f"  poisonvine ", style="bold #39ff14")
    meta.append(f"v{version}", style="#8be9a3")
    meta.append("  ·  ", style="dim")
    meta.append(sub + "\n", style="italic #b8b8b8")
    meta.append(f"  “{quote}”\n", style="#b026ff")
    meta.append(
        "  Authorized research use only — point it at systems you control.\n",
        style="dim #ff5f5f",
    )
    console.print(meta, end="")

    return buf.getvalue()

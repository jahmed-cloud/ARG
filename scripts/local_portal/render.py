"""
Markdown → HTML for the local portal.

Reports embed values that come from Azure (resource names, tag values), so
raw HTML in markdown is neutralised: every '<' outside code is escaped, and
only the tags the report generator itself emits (<details>, <summary>,
<br/>) survive — swapped for placeholders during rendering so the markdown
inside a <details> block (e.g. a fenced JSON block) is still rendered.
"""

import re

import markdown

_FENCE = re.compile(r"(^```[^\n]*\n.*?^```[ \t]*$)", re.M | re.S)
_INLINE_CODE = re.compile(r"(`[^`\n]+`)")
_ALLOWED = re.compile(r"<(/?(?:details|summary)|br\s*/?)>", re.I)
_TOKEN = "@@ARGTAG{}@@"


def _protect(text: str, tags: list) -> str:
    def keep(match: "re.Match[str]") -> str:
        tags.append(f"<{match.group(1)}>")
        return _TOKEN.format(len(tags) - 1)

    out = []
    for block in _FENCE.split(text):
        if block.startswith("```"):
            out.append(block)
            continue
        for piece in _INLINE_CODE.split(block):
            if len(piece) > 1 and piece.startswith("`") and piece.endswith("`"):
                out.append(piece)
            else:
                out.append(_ALLOWED.sub(keep, piece).replace("<", "&lt;"))
    return "".join(out)


def neutralise_html(text: str) -> str:
    """Escape raw HTML outside code, keeping only <details>/<summary>/<br/>."""
    tags: list = []
    protected = _protect(text, tags)
    for i, tag in enumerate(tags):
        protected = protected.replace(_TOKEN.format(i), tag)
    return protected


def render_markdown(text: str) -> str:
    tags: list = []
    html = markdown.markdown(
        _protect(text, tags),
        extensions=["tables", "fenced_code", "sane_lists", "toc"],
        output_format="html",
    )
    for i, tag in enumerate(tags):
        html = html.replace(_TOKEN.format(i), tag)
    html = re.sub(r"<p>(\s*</?(?:details|summary)\b)", r"\1", html)
    return re.sub(r"(</(?:details|summary)>\s*)</p>", r"\1", html)

"""
PDF export for subscription analysis reports.

A report folder (README.md + 01-... to 05-...) is rendered into ONE print-ready
HTML document (cover, page per markdown file, intra-report links rewritten to
in-document anchors, print CSS) and then printed to PDF by a locally installed
Chromium-based browser (Microsoft Edge or Google Chrome) in headless mode. No
extra Python dependency is needed; Edge ships with Windows.

Two levels of detail:
- summary: README, current findings (without the resource inventory), gap
  analysis, cost drivers, savings register, architectural critique, deep-dive index;
- full:    everything, including the resource inventory and every deep-dive page.

Output: <report>/report-<detail>.html and <report>/report-<detail>.pdf.
"""

import html as html_lib
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

DETAILS = ("summary", "full")
SUMMARY_PAGES = [
    "README.md",
    "01-current-findings/README.md",
    "02-gap-analysis/README.md",
    "03-cost-drivers/README.md",
    "03-cost-drivers/savings-register.md",
    "04-architectural-critique/README.md",
    "05-deep-dive/README.md",
]
FULL_EXTRA = ["01-current-findings/resource-inventory.md"]
MERMAID_CDN = "https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"

BROWSER_CANDIDATES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]
BROWSER_NAMES = ["msedge", "microsoft-edge", "microsoft-edge-stable", "google-chrome", "google-chrome-stable",
                 "chromium", "chromium-browser", "chrome"]

PRINT_CSS = """
@page { size: A4; margin: 14mm 12mm 16mm 12mm; }
* { box-sizing: border-box; }
body { font-family: "Segoe UI", Arial, sans-serif; font-size: 9.5pt; color: #1f2933; line-height: 1.35; margin: 0; }
a { color: #0f6cbd; text-decoration: none; }
h1 { font-size: 18pt; margin: 0 0 8pt; color: #1b2a3a; }
h2 { font-size: 13pt; margin: 14pt 0 6pt; page-break-after: avoid; color: #1b2a3a; }
h3 { font-size: 11pt; margin: 10pt 0 4pt; page-break-after: avoid; }
p, li { orphans: 3; widows: 3; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0 10pt; font-size: 8pt; }
thead { display: table-header-group; }
tr { page-break-inside: avoid; }
th, td { border: 1px solid #d5dce4; padding: 3px 5px; vertical-align: top; text-align: left; word-break: break-word; }
th { background: #eef2f6; }
code { font-family: Consolas, monospace; font-size: 8pt; background: #f1f4f8; padding: 0 2px; }
pre { white-space: pre-wrap; word-break: break-all; font-size: 7.5pt; background: #f6f8fa; border: 1px solid #dde3ea;
      padding: 6px; page-break-inside: avoid; }
blockquote { border-left: 3px solid #d5dce4; margin: 6pt 0; padding: 2pt 8pt; color: #52606d; }
details > *:not(summary) { display: none; }
section.page { page-break-before: always; }
section.page.first { page-break-before: auto; }
.page-path { font-size: 7.5pt; color: #7b8794; margin-bottom: 4pt; }
.cover { height: 250mm; display: flex; flex-direction: column; justify-content: center; }
.cover h1 { font-size: 26pt; }
.cover .meta { font-size: 11pt; color: #52606d; margin-top: 10pt; }
.cover ol { font-size: 10.5pt; }
.mermaid { text-align: center; page-break-inside: avoid; }
.noprint { margin: 12px 0; }
@media print { .noprint { display: none; } }
@media screen { body { max-width: 1100px; margin: 20px auto; padding: 0 20px; } section.page { border-top: 2px solid #d5dce4; margin-top: 30px; } }
"""

MERMAID_BOOTSTRAP = """
document.addEventListener("DOMContentLoaded", function () {
  var blocks = document.querySelectorAll("pre > code.language-mermaid");
  if (!blocks.length || !window.mermaid) return;
  blocks.forEach(function (code) {
    var div = document.createElement("div");
    div.className = "mermaid";
    div.textContent = code.textContent;
    code.parentElement.replaceWith(div);
  });
  window.mermaid.initialize({ startOnLoad: false, securityLevel: "strict", theme: "default" });
  window.mermaid.run({ querySelector: ".mermaid" });
});
"""


class PdfExportError(RuntimeError):
    pass


def report_pages(report_dir: Path, detail: str = "summary") -> List[str]:
    """Ordered page list (relative posix paths) that exist in the report folder."""
    if detail not in DETAILS:
        raise ValueError(f"detail must be one of {DETAILS}")
    pages = list(SUMMARY_PAGES)
    if detail == "full":
        pages.insert(2, FULL_EXTRA[0])
        pages += sorted(p.relative_to(report_dir).as_posix()
                        for p in (report_dir / "05-deep-dive").glob("*/README.md"))
    return [p for p in pages if (report_dir / p).is_file()]


def anchor_for(rel: str) -> str:
    return "page-" + re.sub(r"[^a-z0-9]+", "-", rel.lower()).strip("-")


def page_title(path: Path) -> str:
    """First '# ' heading of a markdown page (backticks stripped), else its relative file name."""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            return line[2:].replace("`", "").strip()
    return path.name


def _rewrite_page(html: str, rel: str, pages: List[str]) -> str:
    """Make heading ids unique per page and point intra-report links at in-document anchors."""
    prefix = anchor_for(rel)
    html = re.sub(r'id="([^"]+)"', lambda m: f'id="{prefix}--{m.group(1)}"', html)
    base = Path(rel).parent

    def link(match: "re.Match[str]") -> str:
        target, frag = match.group(1), match.group(2) or ""
        if re.match(r"^[a-z]+:", target):
            return match.group(0)
        if not target:
            return f'href="#{prefix}--{frag[1:]}"' if frag else match.group(0)
        resolved = os.path.normpath((base / target).as_posix()).replace("\\", "/")
        if resolved in pages:
            dest = anchor_for(resolved)
            return f'href="#{dest}--{frag[1:]}"' if frag else f'href="#{dest}"'
        return match.group(0)

    return re.sub(r'href="([^"#]*)(#[^"]*)?"', link, html)


def build_print_body(report_dir: Path, detail: str = "summary") -> Tuple[str, str]:
    """(title, body_html) for the whole report. Markdown is rendered with raw HTML neutralised."""
    from scripts.local_portal.render import render_markdown

    pages = report_pages(report_dir, detail)
    if not pages:
        raise PdfExportError(f"No report pages found in {report_dir}")
    name = report_dir.name
    title = f"Subscription Analysis - {name}"
    toc = "".join(f'<li><a href="#{anchor_for(p)}">{html_lib.escape(page_title(report_dir / p))}</a></li>'
                  for p in pages)
    parts = [
        '<section class="page first cover">',
        f"<h1>{html_lib.escape(title)}</h1>",
        f'<div class="meta">Azure Resource Guardian - {html_lib.escape(detail)} report - generated '
        f"{datetime.now():%Y-%m-%d %H:%M}</div>",
        f"<h2>Contents</h2><ol>{toc}</ol>",
        "</section>",
    ]
    for rel in pages:
        body = render_markdown((report_dir / rel).read_text(encoding="utf-8"))
        parts.append(f'<section class="page" id="{anchor_for(rel)}">'
                     f'<div class="page-path">{html_lib.escape(name)} / {html_lib.escape(rel)}</div>'
                     f"{_rewrite_page(body, rel, pages)}</section>")
    return title, "\n".join(parts)


def build_print_html(report_dir: Path, detail: str = "summary") -> str:
    """Standalone print-ready HTML (inline CSS; mermaid diagrams render when the CDN is reachable)."""
    title, body = build_print_body(report_dir, detail)
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{html_lib.escape(title)}</title>'
            f"<style>{PRINT_CSS}</style><script src=\"{MERMAID_CDN}\"></script>"
            f"<script>{MERMAID_BOOTSTRAP}</script></head><body>{body}</body></html>")


def find_browser(explicit: Optional[str] = None) -> Optional[str]:
    """Chromium-based browser for headless printing: explicit path, ARG_PDF_BROWSER, well-known paths, PATH."""
    for candidate in (explicit, os.environ.get("ARG_PDF_BROWSER")):
        if candidate and Path(candidate).is_file():
            return candidate
    for candidate in BROWSER_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    for name in BROWSER_NAMES:
        found = shutil.which(name)
        if found:
            return found
    return None


def export_pdf(report_dir: Path, detail: str = "summary", *, browser: Optional[str] = None,
               timeout: int = 300, runner=subprocess.run) -> Path:
    """
    Write report-<detail>.html and print it to report-<detail>.pdf. Raises
    PdfExportError (with the HTML path, which can be printed from any browser)
    when no Chromium-based browser is available or printing fails.
    """
    report_dir = Path(report_dir)
    html_path = report_dir / f"report-{detail}.html"
    pdf_path = report_dir / f"report-{detail}.pdf"
    html_path.write_text(build_print_html(report_dir, detail), encoding="utf-8")

    exe = find_browser(browser)
    if not exe:
        raise PdfExportError(
            "No Microsoft Edge / Google Chrome found for PDF printing. Set ARG_PDF_BROWSER to its path, or open "
            f"{html_path} in a browser and use Print > Save as PDF.")
    if pdf_path.exists():
        pdf_path.unlink()
    profile = tempfile.mkdtemp(prefix="arg-pdf-")
    command = [
        exe, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
        f"--user-data-dir={profile}", "--no-pdf-header-footer", "--run-all-compositor-stages-before-draw",
        "--virtual-time-budget=20000", f"--print-to-pdf={pdf_path}", html_path.resolve().as_uri(),
    ]
    try:
        result = runner(command, capture_output=True, text=True, timeout=timeout)
        _wait_for_file(pdf_path, timeout)
    except subprocess.TimeoutExpired as exc:
        raise PdfExportError(f"PDF printing timed out after {timeout}s; open {html_path} and print it manually.") from exc
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    if not pdf_path.is_file() or pdf_path.stat().st_size == 0:
        detail_text = (getattr(result, "stderr", "") or "").strip().splitlines()[-1:] or ["no output"]
        raise PdfExportError(f"Browser did not produce a PDF ({detail_text[0][:200]}). "
                             f"Open {html_path} and print it manually.")
    return pdf_path


def _wait_for_file(path: Path, timeout: int, poll: float = 1.0) -> None:
    """
    On Windows msedge.exe is a launcher that can return before the browser
    process it started has finished printing: wait until the PDF exists and its
    size has stopped changing (or the timeout passes).
    """
    import time

    deadline = time.time() + timeout
    last_size = -1
    while time.time() < deadline:
        size = path.stat().st_size if path.is_file() else -1
        if size > 0 and size == last_size:
            return
        last_size = size
        time.sleep(poll)

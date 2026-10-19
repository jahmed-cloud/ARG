"""
The 5-part subscription analysis for the Docker (cloud) version: after the worker's scanners ran for a subscription,
build the same report the local tool writes - README (decision summary), 01 current findings, 02 gap analysis,
03 cost drivers, 04 architectural critique, 05 deep dives (with the built-in reasoning and, when switched on, the
AI review), backlog.csv - from the scan's own scanner outputs plus the collection steps the scanners do not do
(inventory, cost, Defender summary, reliability, resource providers). Nothing is scanned twice.

build_from_scan() returns the text files (markdown, csv, summary.json) keyed by their relative path; the worker
stores them in the analysis_reports table and the API serves them (backend/api/routes/analysis.py).
"""

import json
import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from scripts.subscription_analysis.collector import (
    AnalysisData, add_output, collect_ai_deployments, collect_costs, collect_defender_summary, collect_inventory,
    collect_reliability, think_about,
)
from scripts.subscription_analysis.correlate import correlate
from scripts.subscription_analysis.settings import REPORT_SETTINGS

logger = logging.getLogger(__name__)

STORED_SUFFIXES = (".md", ".csv")
STORED_FILES = ("summary.json", "history.json")
MAX_FILE_CHARS = 2_000_000


def read_files(folder: Path) -> Dict[str, str]:
    """Every markdown / csv page of a written report (raw JSON datasets stay out: they are large and internal)."""
    files: Dict[str, str] = {}
    for path in sorted(folder.rglob("*")):
        rel = path.relative_to(folder).as_posix()
        if not path.is_file() or "/raw/" in f"/{rel}":
            continue
        if path.suffix.lower() in STORED_SUFFIXES or path.name in STORED_FILES:
            text = path.read_text(encoding="utf-8", errors="replace")
            files[rel] = text if len(text) <= MAX_FILE_CHARS else text[:MAX_FILE_CHARS] + "\n\n… (truncated)\n"
    return files


async def build_from_scan(context: Any, subscription: Dict[str, Any], completed: Iterable[Tuple[Any, Any]],
                          config: Dict[str, Any], credential: Any = None,
                          previous_findings: List[Dict[str, Any]] = None,
                          history: str = None) -> Dict[str, Any]:
    """The report files of one subscription from a finished scan. `completed`: (scanner instance, ScanOutput)."""
    from scanners.base.providers import get_provider_analysis
    from scripts.subscription_analysis.report import write_report

    data = AnalysisData(subscription=subscription, generated_at=datetime.now(timezone.utc),
                        settings={k: v for k, v in (config or {}).items()
                                  if k in REPORT_SETTINGS or k == "required_tags"})
    arm = getattr(context, "arm_client", None)
    steps = [("inventory", lambda: collect_inventory(context, arm, data)),
             ("AI deployments", lambda: collect_ai_deployments(arm, data)),
             ("reliability", lambda: collect_reliability(context, data)),
             ("Defender summary", lambda: collect_defender_summary(
                 context, data, bool((config or {}).get("defender_plan_recommendations")))),
             ("cost", lambda: collect_costs(context, data))]
    for name, step in steps:
        try:
            await step()
        except Exception as exc:   # a partial report beats none
            logger.warning("Cloud report: %s unavailable for %s: %s", name, subscription.get("id"), exc)
            data.warnings.append(f"{name} unavailable: {exc}")
    try:
        data.resource_providers = await get_provider_analysis(context) or {}
    except Exception as exc:
        data.warnings.append(f"resource providers unavailable: {exc}")
    for scanner, output in completed:
        add_output(data, type(scanner), output)
    data.findings, data.correlation = correlate(data.findings)
    if (config or {}).get("ai_reasoning") and credential is not None:
        data.thinking = await think_about(data, config, credential)
    with tempfile.TemporaryDirectory(prefix="arg-report-") as tmp:
        if history:   # the previous runs' trend (history.json, kept across runs like the local report folder)
            (Path(tmp) / "history.json").write_text(history, encoding="utf-8")
        model = write_report(data, Path(tmp), previous_findings)
        files = read_files(Path(tmp))
    summary = json.loads(files.get("summary.json") or "{}")
    reviews = [{"finding_type": f.get("finding_type"), "resource_id": f.get("resource_id"), "ai_review": f["ai_review"]}
               for f in model.findings if f.get("ai_review")]
    return {"files": files, "summary": summary, "thinking": data.thinking or {}, "ai_reviews": reviews,
            "findings": len(model.findings), "warnings": data.warnings[:50]}

"""
Analysis API - the 5-part subscription analysis the worker writes after each scan (AnalysisReport, built by
scripts/subscription_analysis/cloud_report.py): the same README, current findings, gap analysis, cost drivers,
architectural critique, deep dives (built-in reasoning, optional AI review) and backlog.csv the local tool writes.

Pages are served as sanitised HTML (scripts/local_portal/render.py: raw HTML from Azure-sourced values is
neutralised); links between pages stay relative and the Analysis page resolves them. Scoped users see their own
subscriptions only (404 otherwise, like every subscription-scoped route).
"""

import io
import posixpath
import zipfile
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from backend.api.dependencies.database import get_db
from backend.models.models import AnalysisReport, Subscription
from backend.services.access import AccessScope, get_access_scope

router = APIRouter(tags=["analysis"])

NOT_READY = ("No analysis yet for this subscription - it is written after each scan (Scans -> start a scan).")
SECTIONS = [
    ("README.md", "Summary - decisions"),
    ("01-current-findings/README.md", "01 - Current findings"),
    ("02-gap-analysis/README.md", "02 - Gap analysis"),
    ("03-cost-drivers/README.md", "03 - Cost drivers"),
    ("03-cost-drivers/savings-register.md", "03 - Savings register"),
    ("04-architectural-critique/README.md", "04 - Architectural critique"),
    ("05-deep-dive/README.md", "05 - Deep dives"),
    ("05-deep-dive/thinking.md", "Thinking mode - AI review"),
    ("01-current-findings/resource-inventory.md", "Resource inventory"),
    ("01-current-findings/resource-providers.md", "Resource providers"),
]


def _nav(files: Dict[str, str]) -> List[Dict[str, str]]:
    nav = [{"path": p, "title": t} for p, t in SECTIONS if p in files]
    deep = sorted(p for p in files if p.startswith("05-deep-dive/") and p.endswith("/README.md")
                  and p.count("/") == 2)
    nav += [{"path": p, "title": "05 · " + p.split("/")[1].replace("-", " ")} for p in deep]
    return nav


async def _subscription(db: AsyncSession, scope: AccessScope, subscription_id: str) -> Subscription:
    sub = (await db.execute(select(Subscription).where(Subscription.id == subscription_id))).scalar_one_or_none()
    if sub is None:
        raise HTTPException(status_code=404, detail="Not found")
    scope.require(sub.id)
    return sub


async def _latest(db: AsyncSession, subscription_id: str, light: bool = False) -> AnalysisReport:
    query = select(AnalysisReport).where(AnalysisReport.subscription_id == subscription_id)
    if light:
        query = query.options(defer(AnalysisReport.files))
    row = (await db.execute(query.order_by(AnalysisReport.generated_at.desc()).limit(1))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=NOT_READY)
    return row


@router.get("", response_model=list)
async def list_analyses(db: AsyncSession = Depends(get_db), scope: AccessScope = Depends(get_access_scope)) -> list:
    """The newest analysis of every subscription the caller can see."""
    newest = (select(AnalysisReport.subscription_id, func.max(AnalysisReport.generated_at).label("at"))
              .group_by(AnalysisReport.subscription_id).subquery())
    rows = (await db.execute(
        select(AnalysisReport, Subscription)
        .options(defer(AnalysisReport.files))
        .join(newest, (newest.c.subscription_id == AnalysisReport.subscription_id)
              & (newest.c.at == AnalysisReport.generated_at))
        .join(Subscription, Subscription.id == AnalysisReport.subscription_id)
        .where(scope.where(Subscription.id)))).all()
    out = []
    for report, sub in sorted(rows, key=lambda r: (r[1].display_name or "").lower()):
        summary = report.summary or {}
        out.append({"subscription_id": str(sub.id), "azure_subscription_id": sub.subscription_id,
                    "name": sub.display_name or sub.subscription_id, "generated_at": report.generated_at,
                    "status": report.status, "error": report.error_message, "findings": report.findings_count,
                    "cost_30d": summary.get("cost_30d"), "currency": summary.get("currency"),
                    "ai_review": (report.thinking or {}).get("status")})
    return out


@router.get("/{subscription_id}", response_model=dict)
async def analysis_page(subscription_id: str, path: str = Query("README.md", max_length=300),
                        db: AsyncSession = Depends(get_db), scope: AccessScope = Depends(get_access_scope)) -> dict:
    """One page of the newest analysis as sanitised HTML, with the section list for navigation."""
    from scripts.local_portal.render import render_markdown

    sub = await _subscription(db, scope, subscription_id)
    report = await _latest(db, sub.id)
    files = report.files or {}
    clean = posixpath.normpath(path).lstrip("/")
    meta: Dict[str, Any] = {"subscription": {"id": str(sub.id), "azure_subscription_id": sub.subscription_id,
                                             "name": sub.display_name},
                            "generated_at": report.generated_at, "status": report.status,
                            "error": report.error_message, "nav": _nav(files), "path": clean,
                            "thinking": {k: v for k, v in (report.thinking or {}).items()
                                         if k in ("status", "reason", "model", "generated_at", "reviewed", "sent")}}
    if report.status != "completed":
        return {**meta, "html": None}
    text = files.get(clean)
    if text is None or not clean.endswith(".md"):
        raise HTTPException(status_code=404, detail=f"{clean} is not part of this analysis (raw JSON datasets are "
                                                    f"only in the local report folder).")
    return {**meta, "html": render_markdown(text)}


@router.get("/{subscription_id}/file")
async def analysis_file(subscription_id: str, path: str = Query(..., max_length=300),
                        db: AsyncSession = Depends(get_db), scope: AccessScope = Depends(get_access_scope)):
    """A file of the newest analysis as it is (backlog.csv for Azure Boards, a page's markdown)."""
    sub = await _subscription(db, scope, subscription_id)
    report = await _latest(db, sub.id)
    clean = posixpath.normpath(path).lstrip("/")
    text = (report.files or {}).get(clean)
    if text is None:
        raise HTTPException(status_code=404, detail="Not found")
    media = "text/csv" if clean.endswith(".csv") else "text/markdown" if clean.endswith(".md") else "application/json"
    name = clean.replace("/", "_")
    return Response(text, media_type=f"{media}; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/{subscription_id}/download")
async def analysis_download(subscription_id: str, db: AsyncSession = Depends(get_db),
                            scope: AccessScope = Depends(get_access_scope)):
    """Every page of the newest analysis as a zip (the same folder layout as the local report)."""
    sub = await _subscription(db, scope, subscription_id)
    report = await _latest(db, sub.id)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for rel, text in sorted((report.files or {}).items()):
            archive.writestr(rel, text)
    stamp = report.generated_at.strftime("%Y-%m-%d") if report.generated_at else "latest"
    name = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in (sub.display_name or sub.subscription_id))
    return Response(buffer.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="analysis-{name}-{stamp}.zip"'})

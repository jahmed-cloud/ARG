"""
Estate API - the cross-subscription inventory behind the admin Estate page.

Admins only (admin, super_admin): the estate lists every resource in every connected subscription, regardless of
subscription-scoped access. The data is collected by the worker (workers/scan_worker.py refresh_estate, see
backend/services/estate.py) and stored as EstateSnapshot rows; these routes read the newest one and start
refreshes. Body format of GET /estate: the local portal's estate.json (format 2) plus `snapshot`.
"""

import asyncio
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from backend.api.dependencies.auth import require_admin
from backend.api.dependencies.database import get_db
from backend.models.models import EstateSnapshot, User
from backend.services.estate import COMPLETED, FAILED, RUNNING, RUNNING_STALE_AFTER, STALE_MESSAGE

logger = logging.getLogger(__name__)
router = APIRouter(tags=["estate"])

NOT_READY = "No estate inventory yet. Start one with Refresh inventory (about 5 minutes) or run a scan."


def _meta(s: EstateSnapshot | None) -> dict | None:
    if s is None:
        return None
    return {
        "id": str(s.id), "status": s.status, "triggered_by": s.triggered_by,
        "started_at": s.started_at, "completed_at": s.completed_at, "error_message": s.error_message,
        "subscriptions": s.subscriptions_count, "resources": s.resources_count, "suggestions": s.suggestions_count,
    }


def _light():
    return select(EstateSnapshot).options(defer(EstateSnapshot.data), defer(EstateSnapshot.overview_markdown))


async def _newest(db: AsyncSession, query) -> EstateSnapshot | None:
    return (await db.execute(query.order_by(EstateSnapshot.started_at.desc()).limit(1))).scalar_one_or_none()


async def _expire_stale(db: AsyncSession) -> None:
    now = datetime.now(timezone.utc)
    await db.execute(update(EstateSnapshot)
                     .where(EstateSnapshot.status == RUNNING, EstateSnapshot.started_at < now - RUNNING_STALE_AFTER)
                     .values(status=FAILED, completed_at=now, error_message=STALE_MESSAGE))


@router.get("/status", response_model=dict)
async def estate_status(db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)) -> dict:
    """The newest run (any state) and the newest completed one the page shows."""
    await _expire_stale(db)
    latest = await _newest(db, _light())
    available = latest if latest is not None and latest.status == COMPLETED else await _newest(
        db, _light().where(EstateSnapshot.status == COMPLETED))
    return {"running": latest is not None and latest.status == RUNNING, "latest": _meta(latest),
            "available": _meta(available)}


@router.get("")
async def get_estate(db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)):
    snapshot = await _newest(db, select(EstateSnapshot).options(defer(EstateSnapshot.overview_markdown))
                             .where(EstateSnapshot.status == COMPLETED))
    if snapshot is None or snapshot.data is None:
        raise HTTPException(status_code=404, detail=NOT_READY)
    # the policy collection (landing-zone view, about 1 MB) stays on the server
    body = {k: v for k, v in snapshot.data.items() if k != "policy"}
    return JSONResponse(content={**body, "snapshot": jsonable(_meta(snapshot))})


@router.get("/overview.md", response_class=PlainTextResponse)
async def estate_overview(db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)):
    snapshot = await _newest(db, select(EstateSnapshot).options(defer(EstateSnapshot.data))
                             .where(EstateSnapshot.status == COMPLETED))
    if snapshot is None or not snapshot.overview_markdown:
        raise HTTPException(status_code=404, detail=NOT_READY)
    stamp = (snapshot.completed_at or snapshot.started_at).strftime("%Y-%m-%d")
    return PlainTextResponse(snapshot.overview_markdown, media_type="text/markdown; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="estate-{stamp}.md"'})


@router.get("/telemetry", response_model=dict)
async def estate_telemetry(db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)) -> dict:
    """Overview charts from the newest completed inventory: spend by category / service / subscription, VM power
    state and CPU bands, PaaS network exposure, tag coverage, suggestions by severity (telemetry.py)."""
    from backend.models.models import GovernanceConfig
    from scanners.governance.governance_scanners import DEFAULT_REQUIRED_TAGS
    from scripts.subscription_analysis.telemetry import estate_telemetry as compute

    snapshot = await _newest(db, select(EstateSnapshot).options(defer(EstateSnapshot.overview_markdown))
                             .where(EstateSnapshot.status == COMPLETED))
    if snapshot is None or snapshot.data is None:
        raise HTTPException(status_code=404, detail=NOT_READY)
    config = await db.scalar(select(GovernanceConfig).where(GovernanceConfig.tenant_id.is_(None)).limit(1))
    tags = (config.required_tags if config is not None else None) or DEFAULT_REQUIRED_TAGS
    result = await asyncio.to_thread(compute, snapshot.data, tags)
    return {**result, "snapshot": jsonable(_meta(snapshot))}


@router.get("/architecture", response_model=dict)
async def estate_architecture_index(db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)) -> dict:
    """What the Architecture page's picker lists: the subscriptions in the newest completed inventory."""
    snapshot = await _newest(db, select(EstateSnapshot).options(defer(EstateSnapshot.overview_markdown))
                             .where(EstateSnapshot.status == COMPLETED))
    if snapshot is None or snapshot.data is None:
        raise HTTPException(status_code=404, detail=NOT_READY)
    data = snapshot.data
    arch = data.get("architecture") or {}
    groups = arch.get("management_groups") or {}
    parents = arch.get("subscription_parents") or {}
    subs = sorted(({"id": s["id"], "name": s.get("name") or s["id"],
                    "management_group": (groups.get((parents.get(s["id"]) or [""])[0]) or {}).get("displayName")}
                   for s in data.get("subscriptions") or []), key=lambda s: s["name"].lower())
    return {"subscriptions": subs, "management_groups": len(groups), "policies": len(arch.get("policies") or []),
            "architecture_collected": bool(parents), "snapshot": jsonable(_meta(snapshot))}


async def _landing_mapping(db: AsyncSession) -> list:
    """The landing_zone_mapping setting (Settings > Analysis settings)."""
    from backend.api.routes.governance_config import effective_settings
    from backend.models.models import GovernanceConfig

    config = await db.scalar(select(GovernanceConfig).where(GovernanceConfig.tenant_id.is_(None)).limit(1))
    return effective_settings(getattr(config, "scanner_settings", None) if config else None).get(
        "landing_zone_mapping") or []


@router.get("/architecture.svg")
async def estate_architecture(subscription: str = Query("", max_length=64),
                              view: str = Query("resources", pattern="^(resources|network|landing)$"),
                              db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)):
    """Architecture diagram from the newest completed inventory. view=resources: the tenant (management groups,
    subscriptions, Azure Policy guardrails) or one subscription (resource groups, services, what policy allows and
    denies). view=network: hub-and-spoke topology, or one subscription's VNets, subnets and PaaS exposure.
    view=landing: management groups, policy and hub network against Azure Landing Zones (tenant only).
    Drill-down is the data-subscription attribute; the page handles the click."""
    from scripts.subscription_analysis.network_diagram import architecture_svg

    snapshot = await _newest(db, select(EstateSnapshot).options(defer(EstateSnapshot.overview_markdown))
                             .where(EstateSnapshot.status == COMPLETED))
    if snapshot is None or snapshot.data is None:
        raise HTTPException(status_code=404, detail=NOT_READY)
    extra = ({"policy": snapshot.data.get("policy"), "mapping": await _landing_mapping(db)}
             if view == "landing" else {})
    try:
        svg = await asyncio.to_thread(architecture_svg, snapshot.data, "" if view == "landing" else subscription.lower(),
                                      view, None, **extra)
    except KeyError:
        raise HTTPException(status_code=404, detail="That subscription is not in the estate inventory.")
    return Response(svg, media_type="image/svg+xml", headers={"Cache-Control": "no-store"})


@router.get("/landing-zone", response_model=dict)
async def estate_landing_zone(db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)) -> dict:
    """The landing-zone details (Markdown and HTML): management groups against the Azure Landing Zones archetypes,
    ALZ controls per archetype, policy per management group, exemptions, connectivity."""
    from scripts.local_portal.render import render_markdown
    from scripts.subscription_analysis.landing_zone import analyse, markdown

    snapshot = await _newest(db, select(EstateSnapshot).options(defer(EstateSnapshot.overview_markdown))
                             .where(EstateSnapshot.status == COMPLETED))
    if snapshot is None or snapshot.data is None:
        raise HTTPException(status_code=404, detail=NOT_READY)
    mapping = await _landing_mapping(db)
    text = await asyncio.to_thread(lambda: markdown(analyse(snapshot.data, snapshot.data.get("policy"), mapping)))
    return {"markdown": text, "html": render_markdown(text), "snapshot": jsonable(_meta(snapshot))}


@router.post("/refresh", status_code=status.HTTP_202_ACCEPTED, response_model=dict)
async def refresh_estate(db: AsyncSession = Depends(get_db), admin: User = Depends(require_admin)) -> dict:
    """Start a refresh, or report the one already running (only one runs at a time)."""
    await _expire_stale(db)
    running = await _newest(db, _light().where(EstateSnapshot.status == RUNNING))
    if running is not None:
        return {"started": False, "snapshot": _meta(running)}
    snapshot = EstateSnapshot(status=RUNNING, triggered_by="manual", requested_by=admin.id,
                              started_at=datetime.now(timezone.utc))
    db.add(snapshot)
    try:
        await db.commit()
    except IntegrityError:  # another admin or a finished scan started one a moment ago
        await db.rollback()
        return {"started": False, "snapshot": _meta(await _newest(db, _light().where(EstateSnapshot.status == RUNNING)))}

    try:
        from workers.scan_worker import refresh_estate as refresh_task

        refresh_task.delay(snapshot_id=snapshot.id)
    except Exception as exc:
        logger.error(f"Could not queue estate refresh {snapshot.id}: {exc}")
        snapshot.status = FAILED
        snapshot.completed_at = datetime.now(timezone.utc)
        snapshot.error_message = f"Could not queue the refresh: {exc}"
        await db.commit()
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Could not queue the estate refresh. Check that the task queue is reachable.")
    return {"started": True, "snapshot": _meta(snapshot)}


def jsonable(meta: dict | None) -> dict | None:
    if meta is None:
        return None
    return {k: v.isoformat() if isinstance(v, datetime) else v for k, v in meta.items()}

"""
Findings API routes.

Findings are the core output of every scanner run. Resource details
(name, type, resource group, location) are NOT stored directly on the
Finding row — they live on the joined ResourceInventory row via
Finding.resource_id. We eager-load that relationship on every query to
avoid N+1 lookups when serializing a page of findings.

Status lifecycle (FindingStatus enum on the model):
  open -> acknowledged -> resolved
  open -> suppressed (sets suppressed_until / suppression_reason)
  open -> false_positive
  resolved -> open (re-opened automatically by the worker if a finding recurs)

Note: the model has no dedicated "acknowledged_at" timestamp or
"acknowledged_by" column — acknowledgement is tracked purely via the
status enum. If per-action audit trail is needed later, that belongs
in the existing AuditLog table rather than new columns here.
"""

import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import delete, select, func, and_, or_, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.api.dependencies.auth import require_admin, require_analyst
from backend.api.dependencies.database import get_db
from backend.api.routes.governance_config import effective_settings
from backend.models.models import (
    AuditLog, EstateSnapshot, Finding, FindingStatus, GovernanceConfig, ResourceInventory, SeverityLevel, Subscription,
    User,
)
from backend.services.access import AccessScope, get_access_scope
from scanners.base.base_scanner import ORPHAN_FINDING_TYPES
from scripts.subscription_analysis import reasoning
from scripts.subscription_analysis.ai_prompt import DEFAULT_MAX_FINDINGS, build_prompt
from scripts.subscription_analysis.guidance import implementation_analysis
from scripts.subscription_analysis.knowledge import CRITIQUES, DEEP_DIVE_FOLDERS, WAVE_NAMES, classify

logger = logging.getLogger(__name__)
router = APIRouter(tags=["findings"])

GATE_SEVERITIES = [s.value for s in SeverityLevel]  # most severe first
GATE_FIELDS = {"id", "finding_type", "title", "severity", "status", "resource_name", "resource_group",
               "azure_resource_id", "subscription_id", "estimated_monthly_savings_usd"}
PROMPT_ROW_LIMIT = 5000
RELATED_FINDINGS_LIMIT = 20


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class FindingListItem(BaseModel):
    id: str
    finding_type: str
    title: str
    description: str
    severity: str
    status: str
    category: str
    resource_name: str | None
    resource_type: str | None
    azure_resource_id: str | None
    subscription_id: str
    resource_group: str | None
    location: str | None
    estimated_monthly_savings_usd: float | None
    first_detected_at: datetime
    last_detected_at: datetime
    resolved_at: datetime | None


class FindingCritique(BaseModel):
    key: str
    title: str
    likely_rationale: str
    why_it_falls_short: str
    alternatives: list[str]


class FindingAnalysis(BaseModel):
    """The local report's classification of a finding (scripts/subscription_analysis/knowledge.py)."""
    area: str
    deep_dive: str
    deep_dive_title: str
    wave: int
    wave_name: str
    critique: FindingCritique | None


class FindingResourceContext(BaseModel):
    sku: dict | None
    tags: dict
    environment_tag: str | None
    owner_tag: str | None
    azure_created_at: datetime | None


class RelatedFinding(BaseModel):
    id: str
    finding_type: str
    title: str
    severity: str
    status: str


class FindingSubscription(BaseModel):
    name: str | None
    subscription_id: str | None  # the Azure subscription GUID (not ARG's internal ID)


class FindingImplementation(BaseModel):
    """scripts/subscription_analysis/guidance.py implementation_analysis(): why, when not, cost, references."""
    source: str
    why: str
    skip_when: str
    effort: str
    hours: list[float] | None
    monthly_usd: float | None
    run_cost: str
    saving_usd: float | None
    net_monthly_usd: float | None
    cost_included_in_saving: bool
    one_off_usd: list[float] | None
    prices_as_of: str
    references: list[dict]
    items: list[dict] = []
    decision: dict | None = None      # open endpoints: the target control (access_need.py)
    options: list[dict] = []          # every control considered, with its role and remaining exposure


class FindingDetail(FindingListItem):
    remediation_steps: str | None
    evidence: dict
    caf_control: str | None
    nist_control: str | None
    cis_control: str | None
    suppression_reason: str | None
    scan_job_id: str | None
    estimated_annual_savings_usd: float | None = None
    suppressed_until: datetime | None = None
    affected_resources: list = []
    azure_cli_script: str | None = None
    powershell_script: str | None = None
    analysis: FindingAnalysis | None = None
    implementation: FindingImplementation | None = None
    subscription: FindingSubscription | None = None
    resource_context: FindingResourceContext | None = None
    related_findings: list[RelatedFinding] = []
    reasoning: dict | None = None     # built-in thinking (scripts/subscription_analysis/reasoning.py)
    ai_review: dict | None = None     # optional Azure OpenAI review (thinking.py), when it ran


class FindingStatusUpdate(BaseModel):
    status: str  # acknowledged | suppressed | false_positive | open | resolved
    reason: str | None = None  # used as suppression_reason when status == suppressed


class FindingStats(BaseModel):
    total: int
    open: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    acknowledged: int
    resolved: int
    suppressed: int
    false_positive: int
    total_monthly_savings: float


def _serialize(f: Finding) -> dict:
    """Flatten a Finding + its joined ResourceInventory into API shape."""
    resource = f.resource  # may be None for findings not tied to a single resource (e.g. Entra)
    return {
        "id": str(f.id),
        "finding_type": f.finding_type,
        "title": f.title,
        "description": f.description,
        "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
        "status": f.status.value if hasattr(f.status, "value") else f.status,
        "category": f.category,
        "resource_name": resource.resource_name if resource else None,
        "resource_type": resource.resource_type if resource else None,
        "azure_resource_id": resource.azure_resource_id if resource else None,
        "subscription_id": str(f.subscription_id),
        "resource_group": resource.resource_group if resource else None,
        "location": resource.location if resource else None,
        "estimated_monthly_savings_usd": f.estimated_monthly_savings_usd,
        "first_detected_at": f.first_detected_at,
        "last_detected_at": f.last_detected_at,
        "resolved_at": f.resolved_at,
        "remediation_steps": f.remediation_steps,
        "evidence": f.evidence or {},
        "caf_control": f.caf_control,
        "nist_control": f.nist_control,
        "cis_control": f.cis_control,
        "suppression_reason": f.suppression_reason,
        "scan_job_id": str(f.scan_job_id) if f.scan_job_id else None,
    }


def _enum_value(value) -> str:
    return value.value if hasattr(value, "value") else value


def finding_analysis(finding_type: str, category: str) -> dict:
    """Same gap area / deep dive / savings wave / critique the local subscription report gives a finding."""
    c = classify(finding_type, category)
    critique = CRITIQUES.get(c.critique) if c.critique else None
    return {
        "area": c.area,
        "deep_dive": c.folder,
        "deep_dive_title": DEEP_DIVE_FOLDERS.get(c.folder, c.folder),
        "wave": c.wave,
        "wave_name": WAVE_NAMES.get(c.wave, f"Wave {c.wave}"),
        "critique": {"key": c.critique, "title": critique.title, "likely_rationale": critique.likely_rationale,
                     "why_it_falls_short": critique.why_it_falls_short,
                     "alternatives": list(critique.alternatives)} if critique else None,
    }


def finding_implementation(f: Finding, hourly_rate_usd: float | None = None) -> dict:
    """Why it is needed, when it is not, cost of implementation and references - same as the local report."""
    resource = f.resource
    return implementation_analysis(
        {"finding_type": f.finding_type, "description": f.description, "evidence": f.evidence or {},
         "estimated_monthly_savings_usd": f.estimated_monthly_savings_usd},
        resource_monthly_usd=getattr(resource, "monthly_cost_usd", None) if resource else None,
        hourly_rate_usd=hourly_rate_usd)


def _serialize_detail(f: Finding, related: list, hourly_rate_usd: float | None = None) -> dict:
    """Everything the expanded finding row shows: the list fields plus scripts, analysis and resource context."""
    resource = f.resource
    subscription = getattr(f, "subscription", None)
    implementation = finding_implementation(f, hourly_rate_usd)
    as_dict = {
        "finding_type": f.finding_type, "title": f.title, "description": f.description, "evidence": f.evidence or {},
        "remediation_steps": f.remediation_steps, "estimated_monthly_savings_usd": f.estimated_monthly_savings_usd,
        "resource_id": getattr(resource, "azure_resource_id", None) if resource else None,
        "resource_name": getattr(resource, "resource_name", None) if resource else None,
        "resource_type": getattr(resource, "resource_type", None) if resource else None,
        "resource_group": getattr(resource, "resource_group", None) if resource else None,
        "location": getattr(resource, "location", None) if resource else None,
        "subscription_id": getattr(subscription, "subscription_id", None) if subscription else None,
    }
    return {
        **_serialize(f),
        "estimated_annual_savings_usd": f.estimated_annual_savings_usd,
        "suppressed_until": f.suppressed_until,
        "affected_resources": f.affected_resources or [],
        "azure_cli_script": f.azure_cli_script,
        "powershell_script": f.powershell_script,
        "analysis": finding_analysis(f.finding_type, f.category),
        "implementation": implementation,
        "reasoning": reasoning.reason(as_dict, [r.title for r in related], implementation),
        "ai_review": (f.evidence or {}).get("ai_review"),
        "subscription": {"name": getattr(subscription, "display_name", None),
                         "subscription_id": getattr(subscription, "subscription_id", None)} if subscription else None,
        "resource_context": {
            "sku": resource.sku if isinstance(resource.sku, dict) else None,
            "tags": resource.tags or {},
            "environment_tag": resource.environment_tag,
            "owner_tag": resource.owner_tag,
            "azure_created_at": resource.azure_created_at,
        } if resource else None,
        "related_findings": [
            {"id": str(r.id), "finding_type": r.finding_type, "title": r.title,
             "severity": _enum_value(r.severity), "status": _enum_value(r.status)}
            for r in related
        ],
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

async def _scoped_filters(db: AsyncSession, scope: AccessScope, *, status: list[str] | None = None,
                          subscription_id: UUID | None = None, azure_subscription_id: str | None = None,
                          category: str | None = None, severity: list[str] | None = None,
                          finding_type: str | None = None, search: str | None = None,
                          resource_group: str | None = None, tenant_id: UUID | None = None):
    """Finding query + filters for the CI gate and the AI prompt; always inside the caller's access scope."""
    try:
        statuses = [FindingStatus(s) for s in (status or [])]
        severities = [SeverityLevel(s) for s in (severity or [])]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    query = select(Finding).options(selectinload(Finding.resource))
    filters = [scope.findings()]
    if resource_group:
        query = query.join(ResourceInventory, Finding.resource_id == ResourceInventory.id)
        filters.append(ResourceInventory.resource_group == resource_group)
    if tenant_id:
        query = query.join(Subscription, Finding.subscription_id == Subscription.id)
        filters.append(Subscription.tenant_id == str(tenant_id))
    if statuses:
        filters.append(Finding.status.in_(statuses))
    if severities:
        filters.append(Finding.severity.in_(severities))
    if subscription_id:
        scope.require(subscription_id)  # 404: a gate must never pass because the key cannot see the subscription
        filters.append(Finding.subscription_id == str(subscription_id))
    if azure_subscription_id:
        sub = (await db.execute(select(Subscription.id).where(
            func.lower(Subscription.subscription_id) == azure_subscription_id.lower()))).scalar_one_or_none()
        if sub is None or not scope.allows(sub):
            raise HTTPException(status_code=404, detail="Subscription not found")
        filters.append(Finding.subscription_id == sub)
    if category:
        filters.append(Finding.category == category)
    if finding_type:
        filters.append(Finding.finding_type == finding_type)
    if search:
        term = f"%{search}%"
        filters.append(or_(Finding.title.ilike(term), Finding.description.ilike(term)))
    return query, filters


@router.get("", response_model=dict)
async def list_findings(
    db: AsyncSession = Depends(get_db),
    scope: AccessScope = Depends(get_access_scope),
    severity: list[str] | None = Query(None),
    status: list[str] | None = Query(None),
    category: str | None = Query(None),
    subscription_id: UUID | None = Query(None),
    resource_group: str | None = Query(None),
    tenant_id: UUID | None = Query(None, description="ARG internal tenant ID — filters via the finding's subscription"),
    finding_type: str | None = Query(None),
    search: str | None = Query(None, description="Full-text search on title/description"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    sort_desc: bool = Query(True),
) -> dict:
    """List findings with filtering, pagination, and resource details joined in."""
    filters = [scope.findings()]
    if severity:
        filters.append(Finding.severity.in_(severity))
    if status:
        filters.append(Finding.status.in_(status))
    if category:
        filters.append(Finding.category == category)
    if subscription_id:
        filters.append(Finding.subscription_id == subscription_id)
    if finding_type:
        filters.append(Finding.finding_type == finding_type)
    if search:
        term = f"%{search}%"
        filters.append(or_(Finding.title.ilike(term), Finding.description.ilike(term)))

    base_query = select(Finding).options(selectinload(Finding.resource))
    count_query = select(func.count(Finding.id))

    # resource_group lives on ResourceInventory, not Finding — both
    # queries need the join, but only when this filter is actually used,
    # to avoid an unnecessary join on every findings list request.
    if resource_group:
        base_query = base_query.join(ResourceInventory, Finding.resource_id == ResourceInventory.id)
        count_query = count_query.join(ResourceInventory, Finding.resource_id == ResourceInventory.id)
        filters.append(ResourceInventory.resource_group == resource_group)

    # tenant_id isn't a column on Finding at all — a finding belongs to
    # a Subscription, which belongs to a Tenant, so filtering "by tenant"
    # means filtering findings whose subscription's tenant_id matches.
    if tenant_id:
        base_query = base_query.join(Subscription, Finding.subscription_id == Subscription.id)
        count_query = count_query.join(Subscription, Finding.subscription_id == Subscription.id)
        filters.append(Subscription.tenant_id == tenant_id)

    if filters:
        base_query = base_query.where(and_(*filters))
        count_query = count_query.where(and_(*filters))

    order_col = Finding.last_detected_at.desc() if sort_desc else Finding.last_detected_at.asc()
    base_query = base_query.order_by(order_col).offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(base_query)
    findings = result.scalars().all()
    total = (await db.execute(count_query)).scalar_one()

    return {
        "items": [_serialize(f) for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.get("/stats", response_model=FindingStats)
async def get_finding_stats(
    db: AsyncSession = Depends(get_db),
    scope: AccessScope = Depends(get_access_scope),
    subscription_id: UUID | None = Query(None),
) -> FindingStats:
    """Aggregate finding statistics for dashboard widgets."""
    q = select(Finding).where(scope.findings())
    if subscription_id:
        q = q.where(Finding.subscription_id == subscription_id)

    result = await db.execute(q)
    all_findings = result.scalars().all()

    def sev(s):
        return sum(1 for f in all_findings if f.severity == s)

    def st(s):
        return sum(1 for f in all_findings if f.status == s)

    total_savings = sum(
        (f.estimated_monthly_savings_usd or 0) for f in all_findings if f.status == FindingStatus.OPEN
    )

    return FindingStats(
        total=len(all_findings),
        open=st(FindingStatus.OPEN),
        critical=sev("critical"),
        high=sev("high"),
        medium=sev("medium"),
        low=sev("low"),
        info=sev("info"),
        acknowledged=st(FindingStatus.ACKNOWLEDGED),
        resolved=st(FindingStatus.RESOLVED),
        suppressed=st(FindingStatus.SUPPRESSED),
        false_positive=st(FindingStatus.FALSE_POSITIVE),
        total_monthly_savings=round(total_savings, 2),
    )


@router.get("/gate", response_model=dict)
async def findings_gate(
    db: AsyncSession = Depends(get_db),
    scope: AccessScope = Depends(get_access_scope),
    fail_on: str = Query("high", description="Fail on findings at or above this severity"),
    ignore: str | None = Query(None, description="Comma-separated finding types the gate ignores"),
    status: list[str] = Query(["open"], description="Finding statuses that count (default: open)"),
    subscription_id: UUID | None = Query(None, description="ARG internal subscription ID"),
    azure_subscription_id: str | None = Query(None, description="Azure subscription GUID"),
    category: str | None = Query(None),
) -> dict:
    """
    CI/CD gate over the findings you can see: `passed` is false when findings at or above `fail_on`
    remain. Always HTTP 200 - the pipeline decides what to do with `passed` (see docs/ci-cd.md).
    """
    if fail_on not in GATE_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"fail_on must be one of {', '.join(GATE_SEVERITIES)}")
    query, filters = await _scoped_filters(db, scope, status=status, subscription_id=subscription_id,
                                           azure_subscription_id=azure_subscription_id, category=category)
    counts = dict((await db.execute(
        select(Finding.severity, func.count(Finding.id)).where(and_(*filters)).group_by(Finding.severity))).all())
    by_severity = {s: int(counts.get(SeverityLevel(s), 0)) for s in GATE_SEVERITIES}
    ignored = [t.strip() for t in (ignore or "").split(",") if t.strip()]
    blocking_severities = [SeverityLevel(s) for s in GATE_SEVERITIES[:GATE_SEVERITIES.index(fail_on) + 1]]
    gate_filters = filters + [Finding.severity.in_(blocking_severities)]
    if ignored:
        gate_filters.append(Finding.finding_type.notin_(ignored))
    blocking_total = (await db.execute(select(func.count(Finding.id)).where(and_(*gate_filters)))).scalar_one()
    examples: list = []
    for sev in GATE_SEVERITIES[:GATE_SEVERITIES.index(fail_on) + 1]:
        if not blocking_total or len(examples) >= 50:
            break
        rows = (await db.execute(query.where(and_(*gate_filters), Finding.severity == SeverityLevel(sev))
                                 .order_by(Finding.estimated_monthly_savings_usd.desc().nulls_last())
                                 .limit(50 - len(examples)))).scalars().all()
        examples += [{k: v for k, v in _serialize(f).items() if k in GATE_FIELDS} for f in rows]
    return {
        "tool": "ARG", "fail_on": fail_on, "gate_ignore": ignored, "statuses": status,
        "passed": blocking_total == 0, "blocking": blocking_total, "total": sum(by_severity.values()),
        "findings_by_severity": by_severity, "blocking_findings": examples,
    }


@router.get("/ai-prompt", response_class=PlainTextResponse)
async def findings_ai_prompt(
    db: AsyncSession = Depends(get_db),
    scope: AccessScope = Depends(get_access_scope),
    severity: list[str] | None = Query(None),
    status: list[str] = Query(["open"]),
    category: str | None = Query(None),
    subscription_id: UUID | None = Query(None),
    azure_subscription_id: str | None = Query(None),
    finding_type: str | None = Query(None),
    search: str | None = Query(None),
    resource_group: str | None = Query(None),
    tenant_id: UUID | None = Query(None),
    max_findings: int = Query(DEFAULT_MAX_FINDINGS, ge=1, le=2000),
    mask_ids: bool = Query(True, description="Replace subscription / tenant / principal GUIDs with aliases"),
) -> PlainTextResponse:
    """Markdown prompt (instructions + context + findings) to paste into the AI assistant you use. Same filters as the list."""
    query, filters = await _scoped_filters(db, scope, status=status, subscription_id=subscription_id,
                                           azure_subscription_id=azure_subscription_id, category=category,
                                           severity=severity, finding_type=finding_type, search=search,
                                           resource_group=resource_group, tenant_id=tenant_id)
    rows = (await db.execute(query.where(and_(*filters))
                             .order_by(Finding.estimated_monthly_savings_usd.desc().nulls_last())
                             .limit(PROMPT_ROW_LIMIT))).scalars().all()
    findings = [_serialize(f) for f in rows]
    sev = {s: sum(1 for f in findings if f["severity"] == s) for s in GATE_SEVERITIES}
    subs = {f["subscription_id"] for f in findings}
    sub_info: dict = {"name": f"{len(subs)} subscription(s)" if len(subs) != 1 else None, "id": None}
    if len(subs) == 1:
        sub = (await db.execute(select(Subscription).where(Subscription.id == next(iter(subs))))).scalar_one_or_none()
        if sub:
            sub_info = {"name": sub.display_name, "id": sub.subscription_id}
    summary = {"subscription": sub_info, "findings": len(findings), "findings_by_severity": sev}
    text = build_prompt(summary, findings, max_findings=max_findings, mask_ids=mask_ids)
    if len(rows) >= PROMPT_ROW_LIMIT:
        text += f"\nOnly the first {PROMPT_ROW_LIMIT} findings of this view are included - narrow the filters.\n"
    return PlainTextResponse(text, media_type="text/markdown; charset=utf-8")


class FindingResetRequest(BaseModel):
    confirm: str  # must be exactly "RESET"


@router.post("/reset", response_model=dict)
async def reset_findings(
    body: FindingResetRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
) -> dict:
    """
    Delete every finding (their recommendations and remediation tasks go with them) and the estate snapshots built
    from them, so the next scan regenerates everything with the current scanners and settings. Admins only, needs
    {"confirm": "RESET"}, written to the audit log. Subscriptions, tenants, inventory and settings are kept.
    """
    if body.confirm != "RESET":
        raise HTTPException(status_code=400, detail='Send {"confirm": "RESET"} to delete all findings')
    findings_deleted = (await db.execute(delete(Finding))).rowcount or 0
    snapshots_deleted = (await db.execute(
        delete(EstateSnapshot).where(EstateSnapshot.status != "running"))).rowcount or 0
    await db.execute(update(ResourceInventory).values(is_orphaned=False))
    db.add(AuditLog(user_id=admin.id, action="findings.reset", resource_type="finding",
                    description=f"Deleted {findings_deleted} findings and {snapshots_deleted} estate snapshots",
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent", "")[:512], outcome="success"))
    await db.commit()
    logger.warning("User %s reset findings: %d findings, %d estate snapshots deleted", admin.id, findings_deleted,
                   snapshots_deleted)
    return {"findings_deleted": findings_deleted, "estate_snapshots_deleted": snapshots_deleted}


@router.get("/{finding_id}", response_model=FindingDetail)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    scope: AccessScope = Depends(get_access_scope),
) -> dict:
    result = await db.execute(
        select(Finding).options(selectinload(Finding.resource), selectinload(Finding.subscription))
        .where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    scope.require_finding(finding)  # also hides tenant-wide (identity) findings below contributor
    related: list = []
    if finding.resource_id:
        related = (await db.execute(
            select(Finding)
            .where(Finding.resource_id == finding.resource_id, Finding.id != finding.id, scope.findings())
            .order_by(Finding.severity, Finding.title)
            .limit(RELATED_FINDINGS_LIMIT)
        )).scalars().all()
    saved = (await db.execute(
        select(GovernanceConfig.scanner_settings).where(GovernanceConfig.tenant_id.is_(None)).limit(1)
    )).scalar_one_or_none()
    rate = effective_settings(saved).get("engineering_hourly_rate_usd")
    return _serialize_detail(finding, related, rate)


@router.patch("/{finding_id}/status", response_model=dict)
async def update_finding_status(
    finding_id: UUID,
    body: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> dict:
    """Update finding status. Tracks suppression reason and resolution timestamp."""
    allowed = {"acknowledged", "suppressed", "false_positive", "open", "resolved"}
    if body.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {', '.join(allowed)}")

    result = await db.execute(
        select(Finding).options(selectinload(Finding.resource)).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = FindingStatus(body.status)
    now = datetime.now(timezone.utc)

    if body.status == "resolved":
        finding.resolved_at = now
        # If this was an orphan-class finding, check whether the
        # resource has any other still-open orphan findings before
        # clearing is_orphaned — a resource can be flagged by more than
        # one orphan scanner (e.g. both "unused" and a naming check),
        # and resolving just one of them shouldn't un-flag it.
        if finding.resource and finding.finding_type in ORPHAN_FINDING_TYPES:
            other_open_orphan = await db.execute(
                select(Finding.id).where(
                    Finding.resource_id == finding.resource_id,
                    Finding.id != finding.id,
                    Finding.finding_type.in_(ORPHAN_FINDING_TYPES),
                    Finding.status == FindingStatus.OPEN,
                )
            )
            if not other_open_orphan.scalar_one_or_none():
                finding.resource.is_orphaned = False
    elif body.status == "suppressed":
        finding.suppression_reason = body.reason
    elif body.status == "open":
        finding.resolved_at = None
        finding.suppression_reason = None

    await db.commit()
    await db.refresh(finding, attribute_names=["resource"])
    return _serialize(finding)


@router.post("/bulk-status", response_model=dict)
async def bulk_update_status(
    finding_ids: list[UUID],
    body: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> dict:
    """Bulk update status for multiple findings (e.g. mass-acknowledge low severity)."""
    allowed = {"acknowledged", "suppressed", "false_positive", "open", "resolved"}
    if body.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")
    if len(finding_ids) > 500:
        raise HTTPException(status_code=400, detail="Cannot bulk-update more than 500 findings at once")

    update_data: dict = {"status": FindingStatus(body.status)}
    now = datetime.now(timezone.utc)
    if body.status == "resolved":
        update_data["resolved_at"] = now
    elif body.status == "suppressed":
        update_data["suppression_reason"] = body.reason

    stmt = update(Finding).where(Finding.id.in_(finding_ids)).values(**update_data)
    result = await db.execute(stmt)
    await db.commit()

    logger.info("User %s bulk-updated %d findings to '%s'", current_user.id, result.rowcount, body.status)
    return {"updated": result.rowcount}

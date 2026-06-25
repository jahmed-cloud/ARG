"""
Terraform drift detection API routes.

Two data sources are combined here:
  - TerraformState: one row per imported state file, holding aggregate
    counts (managed_count, unmanaged_count, missing_count, drifted_count)
    computed by the terraform scanner on each scan.
  - Finding (category="terraform"): per-resource drift findings, persisted
    the same way every other scanner's findings are (see workers/scan_worker.py
    _persist_finding). This is what the resource-level list page queries.

Aggregate stats come from summing TerraformState counts across all
imported state files rather than counting Finding rows directly, since
a state file may be imported even when zero drift findings exist for it
(a fully-managed, zero-drift environment should still show in the stats).
"""
import logging
import json
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Query, UploadFile, File, Form, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.api.dependencies.auth import require_analyst
from backend.api.dependencies.database import get_db
from backend.models.models import TerraformState, Finding, Subscription, User

logger = logging.getLogger(__name__)
router = APIRouter(tags=["drift"])


class DriftStats(BaseModel):
    total_resources: int
    managed: int
    unmanaged: int
    missing: int
    drifted: int
    state_files_imported: int


@router.get("/stats", response_model=DriftStats)
async def get_drift_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> DriftStats:
    """
    Aggregate drift statistics summed across all imported Terraform state
    files. Counts are computed by the terraform scanner on each scan run
    and cached on the TerraformState row (last_drift_check).
    """
    result = await db.execute(select(TerraformState))
    states = result.scalars().all()

    managed = sum(s.managed_count or 0 for s in states)
    unmanaged = sum(s.unmanaged_count or 0 for s in states)
    missing = sum(s.missing_count or 0 for s in states)
    drifted = sum(s.drifted_count or 0 for s in states)

    return DriftStats(
        total_resources=managed + unmanaged + missing + drifted,
        managed=managed,
        unmanaged=unmanaged,
        missing=missing,
        drifted=drifted,
        state_files_imported=len(states),
    )


@router.post("/import", status_code=201)
async def import_terraform_state(
    subscription_id: UUID = Form(...),
    workspace_name: str = Form(...),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> dict:
    """
    Import a Terraform state file (terraform.tfstate) for drift detection.

    Accepts the raw JSON state file Terraform itself produces — the same
    file you'd get from `terraform show -json` or a local/remote state
    backend. One workspace per subscription; re-importing the same
    subscription+workspace pair overwrites the previous import rather
    than creating a duplicate.

    The uploaded state is stored as-is in TerraformState.resources and
    read by the worker on the next scan (see workers/scan_worker.py,
    which loads this row and attaches it to ScanContext.terraform_state
    before running TerraformDriftScanner).
    """
    sub = await db.get(Subscription, subscription_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")

    if not file.filename.endswith((".json", ".tfstate")):
        raise HTTPException(
            status_code=400,
            detail="Expected a .tfstate or .json file (output of 'terraform show -json' "
            "or the raw state file from your backend).",
        )

    raw = await file.read()
    # 50MB cap — a state file this large is almost certainly the wrong
    # file; legitimate state files are typically well under a few MB
    # even for large environments.
    if len(raw) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="State file too large (max 50MB).")

    try:
        state_json = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"File is not valid JSON: {exc}")

    if not isinstance(state_json, dict) or "resources" not in state_json:
        raise HTTPException(
            status_code=400,
            detail="This doesn't look like a Terraform state file — expected a top-level "
            "'resources' key. Export one with: terraform show -json > state.json",
        )

    resource_count = 0
    for tf_resource in state_json.get("resources", []):
        resource_count += len(tf_resource.get("instances", []))

    existing = await db.execute(
        select(TerraformState).where(
            and_(
                TerraformState.subscription_id == subscription_id,
                TerraformState.workspace_name == workspace_name,
            )
        )
    )
    state_row = existing.scalar_one_or_none()

    if state_row:
        state_row.resources = state_json.get("resources", [])
        state_row.terraform_version = state_json.get("terraform_version")
        state_row.resource_count = resource_count
        state_row.state_file_path = file.filename
    else:
        state_row = TerraformState(
            subscription_id=subscription_id,
            workspace_name=workspace_name,
            state_file_path=file.filename,
            backend_type="uploaded",
            terraform_version=state_json.get("terraform_version"),
            resource_count=resource_count,
            resources=state_json.get("resources", []),
        )
        db.add(state_row)

    await db.commit()
    await db.refresh(state_row)

    logger.info(
        f"Imported Terraform state for subscription {subscription_id}, "
        f"workspace '{workspace_name}': {resource_count} resource instances"
    )

    return {
        "id": str(state_row.id),
        "workspace_name": state_row.workspace_name,
        "resource_count": state_row.resource_count,
        "terraform_version": state_row.terraform_version,
        "message": "State imported. Run a new scan to detect drift against this state.",
    }


@router.get("/findings", response_model=dict)
async def list_drift_findings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
    finding_type: str | None = Query(
        None, description="terraform_unmanaged_resource|terraform_missing_resource"
    ),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> dict:
    """
    List per-resource Terraform drift findings.

    These are persisted by the worker the same way as every other
    scanner's findings (category='terraform'), via the shared Finding
    table — not a separate per-resource drift table.
    """
    filters = [Finding.category == "terraform"]
    if finding_type:
        filters.append(Finding.finding_type == finding_type)

    q = select(Finding).options(selectinload(Finding.resource)).where(and_(*filters))
    count_q = select(func.count(Finding.id)).where(and_(*filters))

    q = q.order_by(Finding.last_detected_at.desc())
    q = q.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(q)
    findings = result.scalars().all()
    total = (await db.execute(count_q)).scalar_one()

    return {
        "items": [
            {
                "id": str(f.id),
                "finding_type": f.finding_type,
                "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                "status": f.status.value if hasattr(f.status, "value") else f.status,
                "title": f.title,
                "resource_name": f.resource.resource_name if f.resource else None,
                "resource_type": f.resource.resource_type if f.resource else None,
                "azure_resource_id": f.resource.azure_resource_id if f.resource else None,
                "recommendation": f.remediation_steps,
                "detected_at": f.last_detected_at,
            }
            for f in findings
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/state-files", response_model=dict)
async def list_state_files(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> dict:
    """List imported Terraform state files with their last drift check summary."""
    result = await db.execute(
        select(TerraformState).order_by(TerraformState.imported_at.desc())
    )
    states = result.scalars().all()
    return {
        "items": [
            {
                "id": str(s.id),
                "subscription_id": str(s.subscription_id),
                "workspace_name": s.workspace_name,
                "backend_type": s.backend_type,
                "terraform_version": s.terraform_version,
                "resource_count": s.resource_count,
                "managed_count": s.managed_count,
                "unmanaged_count": s.unmanaged_count,
                "missing_count": s.missing_count,
                "drifted_count": s.drifted_count,
                "last_drift_check": s.last_drift_check,
                "imported_at": s.imported_at,
            }
            for s in states
        ]
    }


@router.delete("/state-files/{state_id}", status_code=204)
async def delete_state_file(
    state_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Remove an imported Terraform state file. Safe to delete at any time —
    no other table has a foreign key to TerraformState.id (terraform
    drift findings are regular Finding rows keyed on subscription_id,
    not on a specific state file), so this can't orphan anything.
    The next scan for this subscription will simply report "no state
    imported" again until a new file is uploaded.
    """
    state = await db.get(TerraformState, str(state_id))
    if not state:
        raise HTTPException(status_code=404, detail="State file not found")

    await db.delete(state)
    await db.commit()

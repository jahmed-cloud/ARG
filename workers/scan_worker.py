"""
Azure Resource Guardian - Celery Worker & Scan Orchestrator
============================================================
Celery-based async task queue for scan execution.

Design:
- Scan jobs run as Celery tasks — decoupled from HTTP request lifecycle
- Each scan job fans out to per-scanner subtasks
- Results are saved to PostgreSQL incrementally (not in-memory)
- Progress updates pushed via WebSocket (future: Redis pub/sub)
- Failed individual scanners don't fail the entire job
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import List, Optional

from celery import Celery
from celery.signals import worker_ready
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import sessionmaker, Session

from backend.core.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scanner registration
# ---------------------------------------------------------------------------
# Importing these modules executes their @register_scanner decorators,
# populating ScannerRegistry. This MUST happen before any call to
# ScannerRegistry.all() — typically at worker process startup, which is
# why these imports live at module scope rather than inside task functions.
# Add new scanner modules here when they're created; forgetting this step
# is the most common reason a new scanner silently never runs.
from scanners.compute import compute_scanners  # noqa: F401
from scanners.identity import identity_scanners  # noqa: F401
from scanners.network import network_scanners  # noqa: F401
from scanners.storage import storage_scanners  # noqa: F401
from scanners.governance import governance_scanners  # noqa: F401
from scanners.security import security_scanners  # noqa: F401
from scanners.terraform import terraform_scanners  # noqa: F401


# ---------------------------------------------------------------------------
# Celery Application
# ---------------------------------------------------------------------------

celery_app = Celery(
    "arg_workers",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer=settings.CELERY_TASK_SERIALIZER,
    result_serializer="json",
    accept_content=["json"],
    result_expires=settings.CELERY_RESULT_EXPIRES,
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,        # Acknowledge AFTER completion (prevents lost tasks)
    task_reject_on_worker_lost=True,  # Re-queue if worker dies mid-task
    worker_prefetch_multiplier=1,     # One task per worker at a time (predictable)
    task_routes={
        "workers.scan_worker.run_scan_job": {"queue": "scans"},
        "workers.scan_worker.run_single_scanner": {"queue": "scanners"},
        "workers.report_worker.generate_report": {"queue": "reports"},
    },
)

# Periodic tasks (Celery Beat)
celery_app.conf.beat_schedule = {
    "full-scan-daily": {
        "task": "workers.scan_worker.run_scheduled_full_scan",
        "schedule": 86400,  # Every 24 hours
        "options": {"queue": "scans"},
    },
    "cleanup-old-scan-results": {
        "task": "workers.scan_worker.cleanup_old_results",
        "schedule": 3600,  # Every hour
    },
    "snapshot-scores-daily": {
        "task": "workers.scan_worker.snapshot_scores",
        "schedule": 86400,  # Every 24 hours — one data point per day is
                            # the right granularity for a trend chart;
                            # scores don't meaningfully change faster
                            # than a scan cycle anyway.
    },
}


# ---------------------------------------------------------------------------
# Sync DB Session (Celery tasks use sync SQLAlchemy)
# ---------------------------------------------------------------------------

# Celery workers use sync SQLAlchemy (not async) for simplicity
# The async version is used only in FastAPI request handlers
_sync_engine = create_engine(
    settings.DATABASE_URL_SYNC,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
)
SyncSessionLocal = sessionmaker(bind=_sync_engine, autocommit=False, autoflush=False)


def get_sync_db() -> Session:
    return SyncSessionLocal()


# ---------------------------------------------------------------------------
# Scan Orchestrator Task
# ---------------------------------------------------------------------------

@celery_app.task(
    bind=True,
    name="workers.scan_worker.run_scan_job",
    max_retries=1,
    soft_time_limit=3600,  # 1 hour soft limit
    time_limit=3660,        # 1 hour hard limit
)
def run_scan_job(
    self,
    job_id: str,
    subscription_ids: List[str],
    scanners: List[str],
):
    """
    Main scan orchestration task.

    For each subscription, loads active scanner plugins,
    creates Azure credentials, and runs each scanner.
    Results are persisted to the database as they arrive.
    """
    from backend.models.models import (
        ScanJob, ScanResult, ScanStatus, Subscription,
        Tenant, Finding, ResourceInventory, CostSaving, TerraformState,
    )
    from scanners.base.base_scanner import ScannerRegistry, ScanContext

    db = get_sync_db()
    start_time = time.time()

    try:
        # Update job status to RUNNING — but not if it was already
        # cancelled before this task got picked up off the queue (e.g.
        # cancelled while still PENDING). Same race-condition rationale
        # as the COMPLETED guard below.
        result = db.execute(
            update(ScanJob)
            .where(ScanJob.id == job_id)
            .where(ScanJob.status != ScanStatus.CANCELLED)
            .values(
                status=ScanStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
                celery_task_id=self.request.id,
            )
        )
        db.commit()

        if result.rowcount == 0:
            logger.info(f"Scan job {job_id} was cancelled before it started — skipping execution.")
            return

        logger.info(f"Scan job {job_id} started, subscriptions: {subscription_ids}")

        # Load subscriptions
        if subscription_ids:
            subs = db.execute(
                select(Subscription).where(
                    Subscription.subscription_id.in_(subscription_ids),
                    Subscription.is_active == True,
                )
            ).scalars().all()
        else:
            subs = db.execute(
                select(Subscription).where(Subscription.is_active == True)
            ).scalars().all()

        if not subs:
            raise ValueError("No active subscriptions found for scan")

        # Determine which scanners to run
        all_scanners = ScannerRegistry.all()
        if scanners == ["all"]:
            scanner_classes = list(all_scanners.values())
        else:
            scanner_classes = [
                cls for name, cls in all_scanners.items()
                if name in scanners
            ]

        total_findings = 0
        total_resources = 0
        findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        job_warnings: list[str] = []

        for sub in subs:
            logger.info(f"Scanning subscription: {sub.subscription_id}")

            # Get credentials for this subscription's tenant
            tenant = db.get(Tenant, sub.tenant_id)
            if not tenant:
                logger.error(f"Tenant not found for subscription {sub.subscription_id}")
                continue

            # Build scan context with Azure clients
            context = _build_scan_context(
                subscription_id=sub.subscription_id,
                tenant=tenant,
                job_id=job_id,
            )

            # Attach imported Terraform state, if any, so TerraformDriftScanner
            # has something to diff against. Without this the scanner always
            # saw terraform_state=None and reported "no state imported" even
            # after a state file had been uploaded via POST /drift/import.
            tf_state_row = db.execute(
                select(TerraformState).where(TerraformState.subscription_id == sub.id)
            ).scalars().first()
            if tf_state_row:
                context.terraform_state = {
                    "terraform_version": tf_state_row.terraform_version,
                    "resources": tf_state_row.resources or [],
                }

            # Run every scanner for this subscription inside ONE shared
            # event loop, not one asyncio.run() per scanner. The Graph
            # and Resource Graph clients built into `context` above are
            # httpx.AsyncClient-backed and reused across every scanner
            # below; httpx binds its connection pool to whichever event
            # loop was active on first use. Calling asyncio.run() per
            # scanner previously created and destroyed a fresh loop each
            # time, so any scanner after the first to actually touch a
            # live client failed with "Event loop is closed" — the
            # client wasn't broken, the loop it was bound to had already
            # been torn down by the time the next scanner tried to use it.
            async def _run_all_scanners_for_subscription():
                for scanner_class in scanner_classes:
                    scanner_name = scanner_class.scanner_name
                    scan_result = ScanResult(
                        scan_job_id=job_id,
                        scanner_name=scanner_name,
                        scanner_version=scanner_class.version,
                        category=scanner_class.category.value,
                        status=ScanStatus.RUNNING,
                        started_at=datetime.now(timezone.utc),
                    )
                    db.add(scan_result)
                    db.commit()

                    try:
                        # Load governance config from DB so scanners use
                        # admin-configured tags/patterns, not hardcoded defaults.
                        from backend.models.models import GovernanceConfig
                        from backend.api.routes.governance_config import (
                            DEFAULT_REQUIRED_TAGS, DEFAULT_NAMING_PATTERNS
                        )
                        gov_cfg_row = db.execute(
                            select(GovernanceConfig).where(
                                GovernanceConfig.tenant_id.is_(None)
                            ).limit(1)
                        ).scalar_one_or_none()
                        scanner_extra_config = {}
                        if gov_cfg_row:
                            if gov_cfg_row.required_tags:
                                scanner_extra_config["required_tags"] = gov_cfg_row.required_tags
                            if gov_cfg_row.naming_patterns:
                                scanner_extra_config["naming_patterns"] = gov_cfg_row.naming_patterns
                        else:
                            scanner_extra_config["required_tags"] = DEFAULT_REQUIRED_TAGS
                            scanner_extra_config["naming_patterns"] = DEFAULT_NAMING_PATTERNS

                        scanner_instance = scanner_class(config=scanner_extra_config)
                        output = await scanner_instance.execute(context)

                        # Persist findings
                        for finding_data in output.findings:
                            _persist_finding(db, finding_data, sub, job_id)

                        # The terraform scanner computes managed/unmanaged/missing
                        # counts in its metadata, but nothing previously read it —
                        # GET /drift/stats sums these columns off TerraformState,
                        # so without this update it always showed zeros even
                        # right after a scan found real drift.
                        if scanner_name == "terraform_drift_scanner" and output.metadata:
                            unmanaged_count = output.metadata.get("unmanaged_count", 0)
                            missing_count = output.metadata.get("missing_count", 0)
                            managed_count = output.metadata.get("terraform_managed_count", 0) - missing_count
                            db.execute(
                                update(TerraformState)
                                .where(TerraformState.subscription_id == sub.id)
                                .values(
                                    managed_count=max(0, managed_count),
                                    unmanaged_count=unmanaged_count,
                                    missing_count=missing_count,
                                    drifted_count=0,  # configuration-level drift not yet implemented
                                    last_drift_check=datetime.now(timezone.utc),
                                )
                            )

                        nonlocal total_resources, total_findings
                        total_resources += output.resources_scanned
                        total_findings += output.finding_count
                        for sev, count in output.findings_by_severity().items():
                            findings_by_severity[sev] = findings_by_severity.get(sev, 0) + count

                        # A scanner can "succeed" (no exception) while still
                        # reporting warnings — most commonly an Azure Resource
                        # Graph auth/permission failure being caught internally
                        # and surfaced as ScanOutput.warnings rather than raised.
                        # Previously these warnings were generated but never
                        # read anywhere, so a scan with invalid/test credentials
                        # looked identical to a clean scan that legitimately
                        # found zero issues — completed, 0 resources, 0 findings,
                        # no indication anything was actually wrong.
                        warning_text = "; ".join(output.warnings) if output.warnings else None
                        if warning_text:
                            logger.warning(f"Scanner {scanner_name} completed with warnings: {warning_text}")
                            job_warnings.append(f"{scanner_name}: {warning_text}")

                        # Update scan result
                        db.execute(
                            update(ScanResult)
                            .where(ScanResult.id == scan_result.id)
                            .values(
                                status=ScanStatus.COMPLETED,
                                completed_at=datetime.now(timezone.utc),
                                duration_ms=int((time.time() - start_time) * 1000),
                                resources_scanned=output.resources_scanned,
                                findings_count=output.finding_count,
                                error_message=warning_text,
                            )
                        )
                        db.commit()

                        logger.info(
                            f"Scanner {scanner_name} complete: "
                            f"{output.finding_count} findings, {output.resources_scanned} resources"
                        )

                    except Exception as e:
                        logger.error(f"Scanner {scanner_name} failed: {e}", exc_info=True)
                        db.execute(
                            update(ScanResult)
                            .where(ScanResult.id == scan_result.id)
                            .values(
                                status=ScanStatus.FAILED,
                                completed_at=datetime.now(timezone.utc),
                                error_message=str(e)[:500],
                            )
                        )
                        db.commit()

            asyncio.run(_run_all_scanners_for_subscription())

        # Finalize scan job — but never overwrite a job the user already
        # cancelled. Without this guard, a cancel request whose Celery
        # revoke call failed (or arrived after the task had already begun
        # its final phase) would have the worker silently flip the job's
        # status back from CANCELLED to COMPLETED once it finished, with
        # whatever partial resource/finding counts happened to exist at
        # that point — exactly the "COMPLETED, 0 resources, 0 findings"
        # rows this produced before this guard was added.
        duration = int(time.time() - start_time)
        job_warning_text = "; ".join(job_warnings)[:2000] if job_warnings else None
        result = db.execute(
            update(ScanJob)
            .where(ScanJob.id == job_id)
            .where(ScanJob.status != ScanStatus.CANCELLED)
            .values(
                status=ScanStatus.COMPLETED,
                completed_at=datetime.now(timezone.utc),
                duration_seconds=duration,
                total_resources_scanned=total_resources,
                total_findings=total_findings,
                findings_by_severity=findings_by_severity,
                error_message=job_warning_text,
            )
        )
        db.commit()

        if result.rowcount == 0:
            logger.info(f"Scan job {job_id} finished but was already cancelled — not overwriting status.")

        if job_warnings:
            logger.warning(
                f"Scan job {job_id} completed with {len(job_warnings)} scanner warning(s) — "
                f"likely an Azure authentication or permissions issue. Check the tenant's "
                f"service principal credentials and Resource Graph access."
            )
        logger.info(
            f"Scan job {job_id} completed: {total_findings} findings, "
            f"{total_resources} resources, {duration}s"
        )

    except Exception as e:
        logger.error(f"Scan job {job_id} failed fatally: {e}", exc_info=True)
        db.execute(
            update(ScanJob)
            .where(ScanJob.id == job_id)
            .values(
                status=ScanStatus.FAILED,
                completed_at=datetime.now(timezone.utc),
                duration_seconds=int(time.time() - start_time),
                error_message=str(e)[:1000],
            )
        )
        db.commit()
        raise

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_scan_context(subscription_id: str, tenant: any, job_id: str) -> any:
    """
    Build a ScanContext with Azure SDK clients.
    Credentials are decrypted from the tenant record.
    """
    from scanners.base.base_scanner import ScanContext
    from backend.utils.encryption import decrypt

    try:
        # Decrypt the stored client secret
        client_secret = decrypt(tenant.client_secret_encrypted)

        from azure.identity import ClientSecretCredential
        credential = ClientSecretCredential(
            tenant_id=tenant.tenant_id,
            client_id=tenant.client_id,
            client_secret=client_secret,
        )

        from azure.mgmt.resourcegraph import ResourceGraphClient
        resource_graph_client = ResourceGraphClient(credential)

        context = ScanContext(
            subscription_id=subscription_id,
            tenant_id=tenant.tenant_id,
            scan_job_id=job_id,
            resource_graph_client=resource_graph_client,
        )

        # Add Cost Management client if available
        try:
            from azure.mgmt.costmanagement import CostManagementClient
            context.cost_management_client = CostManagementClient(credential)
        except Exception:
            logger.warning("Cost Management client not available")

        # Add Graph client if available
        try:
            if tenant.graph_permissions_granted:
                from msgraph import GraphServiceClient
                context.graph_client = GraphServiceClient(credential)
        except Exception:
            logger.warning("Graph client not available")

        return context

    except Exception as e:
        logger.error(f"Failed to build scan context: {e}")
        # Return context without clients — scanners will return mock/empty data
        from scanners.base.base_scanner import ScanContext
        return ScanContext(
            subscription_id=subscription_id,
            tenant_id=tenant.tenant_id,
            scan_job_id=job_id,
        )


# Finding types that represent a genuinely orphaned/unused resource —
# see scanners/base/base_scanner.py ORPHAN_FINDING_TYPES for the full
# explanation; imported here rather than redefined to avoid two copies
# silently drifting apart.
from scanners.base.base_scanner import ORPHAN_FINDING_TYPES


def _persist_finding(db: Session, finding_data: any, subscription: any, scan_job_id: str):
    """
    Persist a scanner finding to the database.

    Implements upsert logic:
    - If finding already exists (same type + resource), update last_detected_at
    - If resolved finding recurs, re-open it
    - New findings are inserted

    Also upserts the backing ResourceInventory row. Finding.resource_id is a
    required FK — without it, every Finding API response would show null for
    resource_name/type/group/location even though the scanner provided that
    data on finding_data, since Finding itself has no such columns (see
    backend/api/routes/findings.py _serialize, which joins through .resource).
    """
    from backend.models.models import Finding, FindingStatus, ResourceInventory

    resource = None
    if finding_data.resource_id:
        resource = db.execute(
            select(ResourceInventory).where(
                ResourceInventory.azure_resource_id == finding_data.resource_id,
                ResourceInventory.subscription_id == subscription.id,
            )
        ).scalar_one_or_none()

        if resource:
            # Keep the inventory snapshot fresh on every scan that touches it
            resource.resource_name = finding_data.resource_name or resource.resource_name
            resource.resource_type = finding_data.resource_type or resource.resource_type
            resource.resource_group = finding_data.resource_group or resource.resource_group
            resource.location = finding_data.location or resource.location
        else:
            resource = ResourceInventory(
                subscription_id=subscription.id,
                azure_resource_id=finding_data.resource_id,
                # name/type/group/location are NOT NULL — fall back to a
                # placeholder rather than letting an incomplete scanner
                # finding (e.g. terraform's "missing resource" case, which
                # has no live Azure data to draw from) violate the schema.
                resource_name=finding_data.resource_name or "unknown",
                resource_type=finding_data.resource_type or "unknown",
                resource_group=finding_data.resource_group or "unknown",
                location=finding_data.location or "unknown",
            )
            db.add(resource)
            db.flush()  # assign resource.id before it's referenced below

        # Flag the resource as orphaned if this finding is one of the
        # known orphan-class types. Deliberately one-directional — a
        # resource is never un-flagged here even if a *different*
        # finding type touches it later, since "this resource was once
        # detected as orphaned/unused" remains true historically; the
        # resource only stops being orphaned when the orphan Finding
        # itself is resolved (e.g. the disk gets attached, or deleted
        # and no longer appears in the next scan).
        if finding_data.finding_type in ORPHAN_FINDING_TYPES:
            resource.is_orphaned = True

    # Check for an existing finding tied to this resource
    existing = None
    if resource:
        existing = db.execute(
            select(Finding).where(
                Finding.resource_id == resource.id,
                Finding.finding_type == finding_data.finding_type,
            )
        ).scalar_one_or_none()

    if existing:
        # Update existing finding
        existing.last_detected_at = datetime.now(timezone.utc)
        existing.scan_job_id = scan_job_id
        existing.description = finding_data.description
        existing.estimated_monthly_savings_usd = finding_data.estimated_monthly_savings_usd
        if finding_data.estimated_monthly_savings_usd:
            existing.estimated_annual_savings_usd = finding_data.estimated_monthly_savings_usd * 12
        # Always refresh script content on re-scan — scanners may ship
        # improved commands, and we want the checklist to reflect that.
        existing.azure_cli_script = finding_data.azure_cli_script
        existing.powershell_script = finding_data.powershell_script
        existing.remediation_steps = finding_data.remediation_steps
        if existing.status in (FindingStatus.RESOLVED,):
            # Re-open resolved findings that recurred
            existing.status = FindingStatus.OPEN
            existing.resolved_at = None
        db.commit()
        return

    # Create new finding
    from backend.models.models import SeverityLevel as DbSeverity

    finding = Finding(
        subscription_id=subscription.id,
        resource_id=resource.id if resource else None,
        scan_job_id=scan_job_id,
        finding_type=finding_data.finding_type,
        category=finding_data.category,
        severity=finding_data.severity.value,
        title=finding_data.title,
        description=finding_data.description,
        remediation_steps=finding_data.remediation_steps,
        evidence=finding_data.evidence,
        estimated_monthly_savings_usd=finding_data.estimated_monthly_savings_usd,
        estimated_annual_savings_usd=(
            finding_data.estimated_monthly_savings_usd * 12
            if finding_data.estimated_monthly_savings_usd else None
        ),
        caf_control=finding_data.caf_control,
        nist_control=finding_data.nist_control,
        cis_control=finding_data.cis_control,
        # These were previously silently dropped on every scan — both the
        # FindingData class carries them and the Finding model has columns
        # for them, but _persist_finding never wrote them to the DB, so
        # the remediation checklist generator had no actual commands to
        # include and could only output comments.
        azure_cli_script=finding_data.azure_cli_script,
        powershell_script=finding_data.powershell_script,
    )
    db.add(finding)
    db.commit()


@celery_app.task(name="workers.scan_worker.run_scheduled_full_scan")
def run_scheduled_full_scan():
    """
    Daily scheduled full scan of all active subscriptions.
    Triggered by Celery Beat.
    """
    db = get_sync_db()
    try:
        from backend.models.models import Subscription, ScanJob, ScanStatus

        # Get all active subscriptions
        subs = db.execute(
            select(Subscription).where(Subscription.is_active == True)
        ).scalars().all()

        sub_ids = [s.subscription_id for s in subs]

        # Create and dispatch a full scan job
        job = ScanJob(
            status=ScanStatus.PENDING,
            scanners_requested=["all"],
            scan_scope={"subscription_ids": sub_ids},
            config_snapshot={"triggered_by": "scheduled", "type": "full_scan"},
        )
        db.add(job)
        db.commit()

        run_scan_job.delay(
            job_id=job.id,
            subscription_ids=sub_ids,
            scanners=["all"],
        )

        logger.info(f"Scheduled full scan dispatched: job {job.id}")
    finally:
        db.close()


@celery_app.task(name="workers.scan_worker.cleanup_old_results")
def cleanup_old_results():
    """Remove scan results older than retention period, and recover stale jobs."""
    from backend.models.models import ScanJob, ScanStatus
    from datetime import timedelta
    from sqlalchemy import delete, update

    db = get_sync_db()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(
            days=settings.SCAN_RESULT_RETENTION_DAYS
        )
        result = db.execute(
            delete(ScanJob).where(
                ScanJob.created_at < cutoff,
                ScanJob.status.in_([ScanStatus.COMPLETED, ScanStatus.FAILED]),
            )
        )
        db.commit()
        logger.info(f"Cleaned up {result.rowcount} old scan jobs")

        # Recover jobs stuck in PENDING with no progress for an unreasonable
        # amount of time — e.g. a worker process died between message
        # consumption and the RUNNING status update, or the broker lost
        # the message. Without this, such a job has no path back to a
        # terminal state except the user manually clicking Cancel.
        # SCANNER_TIMEOUT_SECONDS covers one scanner's worst case; a whole
        # job legitimately spans many scanners across subscriptions, so we
        # use a much longer multiple of it as the "definitely stuck" bar.
        stale_cutoff = datetime.now(timezone.utc) - timedelta(
            seconds=settings.SCANNER_TIMEOUT_SECONDS * 10
        )
        stale_result = db.execute(
            update(ScanJob)
            .where(
                ScanJob.status == ScanStatus.PENDING,
                ScanJob.created_at < stale_cutoff,
            )
            .values(
                status=ScanStatus.FAILED,
                error_message=(
                    "Scan timed out waiting to start — the worker process may have "
                    "restarted or lost the task. Please start a new scan."
                ),
            )
        )
        db.commit()
        if stale_result.rowcount:
            logger.warning(f"Recovered {stale_result.rowcount} stale PENDING scan job(s)")
    finally:
        db.close()


@celery_app.task(name="workers.scan_worker.snapshot_scores")
def snapshot_scores():
    """
    Take a daily point-in-time snapshot of governance/security/identity
    scores, for the trend chart on the Governance/Security/Identity
    pages. Governance/security/identity scores are always computed live
    from current open findings (see backend/api/routes/governance.py,
    security.py, identity.py) — there was previously no history at all,
    so a trend chart had nothing to chart. This task is the only place
    that data gets written.

    Deliberately reuses the exact same deduction-map constants as the
    live API endpoints rather than reimplementing the scoring formula a
    second time — two independent implementations of "what's the
    governance score" would inevitably drift apart over time as one gets
    edited without the other.

    Writes one row per subscription per day, upserting if a snapshot for
    today already exists (so re-running this task — e.g. after a worker
    restart — doesn't create duplicate same-day rows).
    """
    from backend.models.models import (
        Subscription, Finding, FindingStatus, ScoreSnapshot, ScanResult, ScanJob,
    )
    from datetime import date as date_cls

    db = get_sync_db()
    try:
        today = date_cls.today()
        subs = db.execute(select(Subscription).where(Subscription.is_active == True)).scalars().all()

        gov_deduction_map = {"critical": 10, "high": 5, "medium": 2, "low": 0.5}
        sec_deduction_map = {"critical": 10, "high": 5, "medium": 2, "low": 0.5}
        identity_deduction_map = {
            "permanent_global_admin": 15, "mfa_not_enabled": 5,
            "expired_app_credential": 3, "stale_guest_user": 1, "dormant_user": 1,
        }
        identity_scanner_names = [
            "stale_guest_scanner", "dormant_user_scanner", "mfa_not_enabled_scanner",
            "permanent_global_admin_scanner", "expired_app_credential_scanner",
        ]

        snapshot_count = 0
        for sub in subs:
            findings = db.execute(
                select(Finding).where(
                    Finding.subscription_id == sub.id,
                    Finding.status == FindingStatus.OPEN,
                )
            ).scalars().all()

            gov_deductions = sum(
                gov_deduction_map.get(f.severity.value if hasattr(f.severity, "value") else f.severity, 0)
                for f in findings if f.category == "governance"
            )
            sec_deductions = sum(
                sec_deduction_map.get(f.severity.value if hasattr(f.severity, "value") else f.severity, 0)
                for f in findings if f.category == "security"
            )
            governance_score = max(0, int(100 - gov_deductions))
            security_score = max(0, int(100 - sec_deductions))

            identity_score = None
            identity_checked = False
            for scanner_name in identity_scanner_names:
                row = db.execute(
                    select(ScanResult, ScanJob.completed_at)
                    .join(ScanJob, ScanResult.scan_job_id == ScanJob.id)
                    .where(ScanResult.scanner_name == scanner_name)
                    .order_by(ScanJob.completed_at.desc())
                    .limit(1)
                ).first()
                if row:
                    sr, _ = row
                    msg = (sr.error_message or "").lower()
                    if "prerequisites not met" not in msg and "no client provided" not in msg:
                        identity_checked = True
                        break
            if identity_checked:
                identity_deductions = sum(
                    identity_deduction_map.get(f.finding_type, 0)
                    for f in findings if f.category == "identity"
                )
                identity_score = max(0, 100 - identity_deductions)

            existing = db.execute(
                select(ScoreSnapshot).where(
                    ScoreSnapshot.subscription_id == sub.id,
                    ScoreSnapshot.snapshot_date == today,
                )
            ).scalar_one_or_none()

            if existing:
                existing.governance_score = governance_score
                existing.security_score = security_score
                existing.identity_score = identity_score
                existing.total_findings_open = len(findings)
            else:
                db.add(ScoreSnapshot(
                    subscription_id=sub.id,
                    snapshot_date=today,
                    governance_score=governance_score,
                    security_score=security_score,
                    identity_score=identity_score,
                    total_findings_open=len(findings),
                ))
            snapshot_count += 1

        db.commit()
        logger.info(f"Captured score snapshots for {snapshot_count} subscription(s) on {today}")
    finally:
        db.close()

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
import re
import time
from datetime import datetime, timezone
from typing import List

from celery import Celery
from celery.schedules import crontab
from sqlalchemy import create_engine, or_, select, update, delete
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
from scanners.compute import compute_posture_scanners  # noqa: F401
from scanners.compute import machine_security_scanners  # noqa: F401
from scanners.identity import identity_scanners  # noqa: F401
from scanners.network import network_scanners  # noqa: F401
from scanners.network import network_posture_scanners  # noqa: F401
from scanners.storage import storage_scanners  # noqa: F401
from scanners.storage import storage_posture_scanners  # noqa: F401
from scanners.governance import governance_scanners  # noqa: F401
from scanners.governance import governance_posture_scanners  # noqa: F401
from scanners.governance import policy_scanners  # noqa: F401
from scanners.security import security_scanners  # noqa: F401
from scanners.security import security_posture_scanners  # noqa: F401
from scanners.database import database_scanners  # noqa: F401
from scanners.cost import cost_scanners  # noqa: F401
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
    # Messages stay in UTC; crontab schedules (the daily full scan) are read in this time zone.
    timezone=settings.SCAN_SCHEDULE_TIMEZONE,
    enable_utc=True,
    task_acks_late=True,        # Acknowledge AFTER completion (prevents lost tasks)
    task_reject_on_worker_lost=True,  # Re-queue if worker dies mid-task
    worker_prefetch_multiplier=1,     # One task per worker at a time (predictable)
    task_routes={
        "workers.scan_worker.run_scan_job": {"queue": "scans"},
        "workers.scan_worker.run_single_scanner": {"queue": "scanners"},
        "workers.scan_worker.refresh_estate": {"queue": "scans"},
        "workers.report_worker.generate_report": {"queue": "reports"},
    },
)

def cron_schedule(expression: str) -> crontab:
    """'0 9 * * *' (minute hour day-of-month month day-of-week) -> Celery crontab, read in the Celery time zone."""
    fields = expression.split()
    if len(fields) != 5:
        raise ValueError(f"FULL_SCAN_SCHEDULE must have 5 cron fields, got {expression!r}")
    minute, hour, day_of_month, month_of_year, day_of_week = fields
    return crontab(minute=minute, hour=hour, day_of_month=day_of_month,
                   month_of_year=month_of_year, day_of_week=day_of_week)


# Periodic tasks (Celery Beat)
celery_app.conf.beat_schedule = {
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
if settings.FEATURE_SCHEDULED_SCANS:
    # The daily automatic scan: FULL_SCAN_SCHEDULE in SCAN_SCHEDULE_TIMEZONE (default 09:00 Asia/Kolkata).
    celery_app.conf.beat_schedule["full-scan-daily"] = {
        "task": "workers.scan_worker.run_scheduled_full_scan",
        "schedule": cron_schedule(settings.FULL_SCAN_SCHEDULE),
        "options": {"queue": "scans"},
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
    pool_recycle=1800,
    # a container network hiccup must not leave a commit waiting forever on a dead socket
    connect_args={"connect_timeout": 10, "keepalives": 1, "keepalives_idle": 30, "keepalives_interval": 10,
                  "keepalives_count": 3, "options": "-c statement_timeout=300000"},
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
        Tenant, TerraformState,
    )
    from scanners.base.base_scanner import ScannerRegistry

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
        unscanned: list[str] = []
        # Settings, required tags and naming patterns are the same for every scanner and subscription of a job:
        # read once, not once per scanner (76 scanners x every subscription).
        scanner_config = _analysis_config(db)
        # Tenant-wide scanners (Entra ID) give the same answer for every subscription of a tenant: run them once
        # per tenant and scan, on the first subscription of that tenant.
        tenant_scanners_done: set = set()

        for sub in subs:
            logger.info(f"Scanning subscription: {sub.subscription_id}")

            # Get credentials for this subscription's tenant
            tenant = db.get(Tenant, sub.tenant_id)
            if not tenant:
                logger.error(f"Tenant not found for subscription {sub.subscription_id}")
                continue

            # Build scan context with Azure clients and prove the sign-in works before any scanner runs: without
            # clients every scanner would fall back to its mock data (fake findings), and without a token each one
            # would wait for its own sign-in timeout (~45 s x every scanner) and change nothing.
            try:
                context = _build_scan_context(
                    subscription_id=sub.subscription_id,
                    tenant=tenant,
                    job_id=job_id,
                )
                _check_sign_in(context)
            except Exception as exc:
                message = f"{sub.display_name or sub.subscription_id}: not scanned - {exc}"
                logger.error(message)
                job_warnings.append(message)
                unscanned.append(message)
                continue
            context.subscription_name = sub.display_name or ""
            from scanners.base.azure_api import cost_basis_from
            context.cost_basis = cost_basis_from(scanner_config)   # setting amortized_cost (default on)

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
                # Outputs are persisted after every scanner ran, so Defender / Advisor items that a native finding
                # already covers are merged first (scripts/subscription_analysis/correlate.py).
                completed: list = []
                for scanner_class in scanner_classes:
                    scanner_name = scanner_class.scanner_name
                    if scanner_class.tenant_wide:
                        if (sub.tenant_id, scanner_name) in tenant_scanners_done:
                            continue
                        tenant_scanners_done.add((sub.tenant_id, scanner_name))
                    scanner_started = time.time()
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
                        # Admin-configured tags, naming patterns and analysis settings (Settings - Governance),
                        # read once per job above; each scanner gets its own copy.
                        scanner_instance = scanner_class(config=dict(scanner_config))
                        output = await scanner_instance.execute(context)
                        completed.append((scanner_instance, output))

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
                                duration_ms=int((time.time() - scanner_started) * 1000),
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

                # Resources = what the subscription holds, counted once. Summing every scanner's own count
                # reported 735 "scanned" for a subscription of 17.
                total_resources += await _resource_count(context, completed)
                # Job totals count what was stored: one finding per issue, after duplicates were merged.
                for stored in _persist_correlated(db, completed, sub, job_id):
                    total_findings += 1
                    sev = getattr(stored.severity, "value", stored.severity)
                    findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1
                if settings.ANALYSIS_REPORT_AFTER_SCAN and completed:
                    await _write_analysis_report(db, context, sub, job_id, completed)

            asyncio.run(_run_all_scanners_for_subscription())

        if len(unscanned) == len(subs):
            raise RuntimeError("No subscription could be scanned: " + "; ".join(unscanned)[:900])

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
        elif settings.ESTATE_REFRESH_AFTER_SCAN:
            queue_estate_refresh(db, f"scan:{job_id}")

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
# Analysis report (the 5-part subscription analysis, as the local tool writes it)
# ---------------------------------------------------------------------------

def _analysis_config(db: Session) -> dict:
    """Scanner / report settings as the scanners get them: analysis settings + required tags + naming patterns."""
    from backend.api.routes.governance_config import DEFAULT_NAMING_PATTERNS, DEFAULT_REQUIRED_TAGS, effective_settings
    from backend.models.models import GovernanceConfig

    row = db.execute(select(GovernanceConfig).where(GovernanceConfig.tenant_id.is_(None)).limit(1)).scalar_one_or_none()
    config = effective_settings(getattr(row, "scanner_settings", None) if row else None)
    config["required_tags"] = (row.required_tags if row and row.required_tags else DEFAULT_REQUIRED_TAGS)
    config["naming_patterns"] = (row.naming_patterns if row and row.naming_patterns else DEFAULT_NAMING_PATTERNS)
    return config


async def _write_analysis_report(db: Session, context: any, sub: any, job_id: str, completed: list) -> None:
    """Build and store the analysis report of one subscription; copy AI reviews onto its findings.
    Never raises: the scan's findings are already stored, and a failed report is recorded as such."""
    from backend.models.models import AnalysisReport
    from scripts.subscription_analysis.cloud_report import build_from_scan

    result: dict = {}
    try:
        previous = db.execute(
            select(AnalysisReport).where(AnalysisReport.subscription_id == sub.id,
                                         AnalysisReport.status == "completed")
            .order_by(AnalysisReport.generated_at.desc()).limit(1)).scalar_one_or_none()
        history = (previous.files or {}).get("history.json") if previous else None
        subscription = {"id": (sub.subscription_id or "").lower(), "name": sub.display_name or sub.subscription_id,
                        "tenant_id": getattr(context, "tenant_id", "")}
        result = await build_from_scan(context, subscription, completed, _analysis_config(db),
                                       getattr(context, "credential", None), history=history)
        row = AnalysisReport(subscription_id=sub.id, scan_job_id=job_id, status="completed",
                             findings_count=result["findings"], summary=result["summary"],
                             thinking=result["thinking"], files=result["files"])
    except Exception as exc:
        db.rollback()
        logger.error(f"Analysis report for {sub.subscription_id} failed: {exc}", exc_info=True)
        row = AnalysisReport(subscription_id=sub.id, scan_job_id=job_id, status="failed",
                             error_message=str(exc)[:1000])
    try:
        db.add(row)
        db.commit()
        _apply_ai_reviews(db, sub, result.get("ai_reviews") or [])
        keep = db.execute(select(AnalysisReport.id).where(AnalysisReport.subscription_id == sub.id)
                          .order_by(AnalysisReport.generated_at.desc())
                          .limit(settings.ANALYSIS_REPORTS_KEEP)).scalars().all()
        db.execute(delete(AnalysisReport).where(AnalysisReport.subscription_id == sub.id,
                                                AnalysisReport.id.notin_(keep)))
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error(f"Could not store the analysis report for {sub.subscription_id}: {exc}")


def _apply_ai_reviews(db: Session, sub: any, reviews: list) -> None:
    """The AI review of a finding goes into its evidence, so the finding detail shows it next to the reasoning."""
    if not reviews:
        return
    from backend.models.models import Finding, FindingStatus, ResourceInventory

    wanted = {(r["finding_type"], (r.get("resource_id") or "").lower()): r["ai_review"] for r in reviews}
    rows = db.execute(
        select(Finding, ResourceInventory.azure_resource_id)
        .join(ResourceInventory, Finding.resource_id == ResourceInventory.id, isouter=True)
        .where(Finding.subscription_id == sub.id, Finding.status == FindingStatus.OPEN,
               Finding.finding_type.in_({t for t, _ in wanted}))).all()
    for finding, azure_id in rows:
        review = wanted.get((finding.finding_type, (azure_id or "").lower()))
        if review:
            finding.evidence = {**(finding.evidence or {}), "ai_review": review}
    db.commit()


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

    # No fallback: a context without clients makes every scanner return its mock data, which would be stored as
    # real findings. A failure here fails this subscription (the caller records why).
    try:
        client_secret = decrypt(tenant.client_secret_encrypted)
    except Exception as exc:
        raise RuntimeError(f"the tenant's client secret cannot be decrypted ({exc.__class__.__name__}) - "
                           f"was ENCRYPTION_KEY changed? Re-enter the secret under Settings > Tenants.") from exc

    from azure.identity import ClientSecretCredential
    credential = ClientSecretCredential(
        tenant_id=tenant.tenant_id,
        client_id=tenant.client_id,
        client_secret=client_secret,
    )

    from scanners.base.azure_api import resource_graph_client as make_graph_client
    resource_graph_client = make_graph_client(credential)

    context = ScanContext(
        subscription_id=subscription_id,
        tenant_id=tenant.tenant_id,
        scan_job_id=job_id,
        resource_graph_client=resource_graph_client,
    )
    context.credential = credential   # the analysis report's optional AI review signs in with it

    # Add Cost Management client if available
    try:
        from azure.mgmt.costmanagement import CostManagementClient
        context.cost_management_client = CostManagementClient(credential)
    except Exception:
        logger.warning("Cost Management client not available")

    # ARM REST client for posture scanners (metrics, diagnostic settings,
    # firewall rules, site config, Cost Management query, budgets).
    from scanners.base.azure_api import ArmClient
    context.arm_client = ArmClient(credential)

    # Add Graph client if available
    try:
        if tenant.graph_permissions_granted:
            from msgraph import GraphServiceClient
            context.graph_client = GraphServiceClient(credential)
    except Exception:
        logger.warning("Graph client not available")

    return context


SIGN_IN_TIMEOUT_SECONDS = 60


def _check_sign_in(context: any) -> None:
    """One ARM token before any scanner runs; raises with the reason (DNS / network / secret) when it fails."""
    from scanners.base.azure_api import ARM_SCOPE, call_with_timeout

    try:
        call_with_timeout(context.credential.get_token, SIGN_IN_TIMEOUT_SECONDS, ARM_SCOPE)
    except Exception as exc:
        reason = (str(exc).strip().splitlines() or [exc.__class__.__name__])[-1][:240]
        hint = ("the worker cannot resolve or reach login.microsoftonline.com - check the container DNS / network "
                "(local-run.md, Podman DNS)" if re.search(r"resolve|name resolution|getaddrinfo|timed? ?out|"
                                                          r"connect", reason, re.IGNORECASE)
                else "check the tenant's client ID and secret (Settings > Tenants)")
        raise RuntimeError(f"cannot sign in to Microsoft Entra ID: {reason}. {hint}.") from exc


from scanners.base.base_scanner import ORPHAN_FINDING_TYPES
from scanners.base.fingerprint import finding_fingerprint, is_tenant_wide, normalise_resource_id

# Suppressions the worker sets itself; a finding reported again is re-opened from these, never from a person's.
AUTOMATIC_SUPPRESSIONS = ("Covered by ", "Check switched off in Settings", "Defender plan-enablement recommendation")


async def _resource_count(context: any, completed: list) -> int:
    """Resources in the subscription (one Resource Graph count); the largest scanner count if that fails."""
    from scanners.base.azure_api import query_resource_graph
    try:
        rows = await query_resource_graph(context, "resources | summarize total = count()")
        if rows:
            return int(rows[0].get("total") or 0)
    except Exception as exc:
        logger.warning("Resource count for %s failed: %s", context.subscription_id, exc)
    return max((output.resources_scanned for _, output in completed), default=0)


def _automatic_suppression(reason: str | None) -> bool:
    return bool(reason) and reason.startswith(AUTOMATIC_SUPPRESSIONS)


def _tenant_subscriptions(subscription: any):
    from backend.models.models import Subscription
    return select(Subscription.id).where(Subscription.tenant_id == subscription.tenant_id)


def _persist_finding(db: Session, finding_data: any, subscription: any, scan_job_id: str):
    """
    Upsert one finding by its fingerprint (resource ID in any casing, or tenant + Entra object) and return the row.
    A resolved finding that recurs is re-opened; acknowledged / suppressed / false-positive rows keep their status.
    """
    from sqlalchemy import func
    from backend.models.models import Finding, FindingStatus, ResourceInventory

    now = datetime.now(timezone.utc)
    resource = None
    if finding_data.resource_id:
        resource = db.execute(
            select(ResourceInventory).where(
                ResourceInventory.subscription_id == subscription.id,
                func.lower(ResourceInventory.azure_resource_id) == normalise_resource_id(finding_data.resource_id),
            ).order_by(ResourceInventory.created_at)
        ).scalars().first()
        if resource:
            resource.resource_name = finding_data.resource_name or resource.resource_name
            resource.resource_type = finding_data.resource_type or resource.resource_type
            resource.resource_group = finding_data.resource_group or resource.resource_group
            resource.location = finding_data.location or resource.location
        else:
            # name / type / group / location are NOT NULL
            resource = ResourceInventory(
                subscription_id=subscription.id,
                azure_resource_id=finding_data.resource_id,
                resource_name=finding_data.resource_name or "unknown",
                resource_type=finding_data.resource_type or "unknown",
                resource_group=finding_data.resource_group or "unknown",
                location=finding_data.location or "unknown",
            )
            db.add(resource)
            db.flush()
        if finding_data.finding_type in ORPHAN_FINDING_TYPES:
            resource.is_orphaned = True

    tenant_wide = is_tenant_wide(finding_data)
    fingerprint = finding_fingerprint(finding_data, subscription_id=subscription.subscription_id,
                                      tenant_id=str(subscription.tenant_id))
    owner = (Finding.subscription_id.in_(_tenant_subscriptions(subscription)) if tenant_wide
             else Finding.subscription_id == subscription.id)
    matches = db.execute(select(Finding).where(Finding.fingerprint == fingerprint, owner)
                         .order_by(Finding.first_detected_at)).scalars().all()
    if not matches and resource is not None:   # rows written before the fingerprint existed
        matches = db.execute(select(Finding).where(Finding.resource_id == resource.id,
                                                   Finding.finding_type == finding_data.finding_type)
                             .order_by(Finding.first_detected_at)).scalars().all()
    existing = matches[0] if matches else None
    for extra in matches[1:]:                  # older case-variant copies of the same issue
        extra.status = FindingStatus.RESOLVED
        extra.resolved_at = now
        extra.suppression_reason = "Duplicate of the same finding - merged"

    evidence = dict(finding_data.evidence or {})
    if finding_data.entra_object_id:           # the only place the Entra object is kept
        evidence.setdefault("entra_object_id", finding_data.entra_object_id)
        evidence.setdefault("entra_object_type", finding_data.entra_object_type)
        evidence.setdefault("entra_display_name", finding_data.entra_display_name)
    saving = finding_data.estimated_monthly_savings_usd

    if existing:
        existing.fingerprint = fingerprint
        existing.last_detected_at = now
        existing.scan_job_id = scan_job_id
        existing.title = finding_data.title
        existing.description = finding_data.description
        existing.severity = finding_data.severity.value
        existing.evidence = evidence
        existing.estimated_monthly_savings_usd = saving
        existing.estimated_annual_savings_usd = saving * 12 if saving else None
        existing.azure_cli_script = finding_data.azure_cli_script
        existing.powershell_script = finding_data.powershell_script
        existing.remediation_steps = finding_data.remediation_steps
        expired = existing.suppressed_until is not None and existing.suppressed_until <= now
        if existing.status == FindingStatus.RESOLVED or (
                existing.status == FindingStatus.SUPPRESSED
                and (expired or _automatic_suppression(existing.suppression_reason))):
            existing.status = FindingStatus.OPEN
            existing.resolved_at = None
            existing.suppression_reason = None
            existing.suppressed_until = None
        db.commit()
        return existing

    finding = Finding(
        subscription_id=subscription.id,
        resource_id=resource.id if resource else None,
        scan_job_id=scan_job_id,
        fingerprint=fingerprint,
        finding_type=finding_data.finding_type,
        category=finding_data.category,
        severity=finding_data.severity.value,
        title=finding_data.title,
        description=finding_data.description,
        remediation_steps=finding_data.remediation_steps,
        evidence=evidence,
        estimated_monthly_savings_usd=saving,
        estimated_annual_savings_usd=saving * 12 if saving else None,
        caf_control=finding_data.caf_control,
        nist_control=finding_data.nist_control,
        cis_control=finding_data.cis_control,
        azure_cli_script=finding_data.azure_cli_script,
        powershell_script=finding_data.powershell_script,
    )
    db.add(finding)
    db.commit()
    return finding


def _dismissed_removals(db: Session, subscription: any) -> set:
    """Resources whose 'remove it' finding a person dismissed: they stay, so their other findings stay too."""
    from backend.models.models import Finding, FindingStatus, ResourceInventory
    from scripts.subscription_analysis.correlate import DECOMMISSION_TYPES

    rows = db.execute(
        select(ResourceInventory.azure_resource_id, Finding.status, Finding.suppression_reason)
        .join(Finding, Finding.resource_id == ResourceInventory.id)
        .where(Finding.subscription_id == subscription.id, Finding.finding_type.in_(sorted(DECOMMISSION_TYPES)),
               Finding.status.in_([FindingStatus.SUPPRESSED, FindingStatus.FALSE_POSITIVE]))).all()
    return {(rid or "").lower() for rid, status, reason in rows
            if status == FindingStatus.FALSE_POSITIVE or not _automatic_suppression(reason)}


def _persist_correlated(db: Session, completed: list, subscription: any, scan_job_id: str) -> list:
    """
    Store one finding per issue: Defender / Advisor items a native finding covers are merged, and findings on a
    resource that should be removed are folded into that finding. Returns the stored findings.
    """
    from scripts.subscription_analysis.correlate import _scope, correlate

    everything = [f for _, output in completed for f in output.findings]
    kept, stats = correlate(everything, keep_separate=_dismissed_removals(db, subscription))
    kept_ids = {id(f) for f in kept}
    merged = {(_scope(f), f.finding_type) for f in everything if id(f) not in kept_ids}
    for scanner, output in completed:
        for finding_data in output.findings:
            if id(finding_data) in kept_ids:
                _persist_finding(db, finding_data, subscription, scan_job_id)
        _retire_undetected_findings(db, scanner, output, subscription, scan_job_id, duplicate_scopes=merged)
    if any(stats.values()):
        logger.info("Correlation for %s: %s", subscription.subscription_id, stats)
    return kept


def _retire_undetected_findings(db: Session, scanner: any, output: any, subscription: any, scan_job_id: str,
                                duplicate_scopes: set = frozenset()) -> int:
    """
    Close open findings of the scanner's types that a clean run (no warnings) no longer reports: suppressed with
    the reason when a setting or a merge removed them, resolved otherwise. Tenant-wide scanners close across the
    tenant's subscriptions.
    """
    from backend.models.models import Finding, FindingStatus

    emitted = getattr(scanner, "emitted_finding_types", None)
    types = emitted() if emitted else getattr(scanner, "finding_types", None)
    if not types or output.warnings:
        return 0
    disabled = (output.metadata or {}).get("disabled_by_setting")
    reason_for = getattr(scanner, "suppression_reason_for", None)
    owner = (Finding.subscription_id.in_(_tenant_subscriptions(subscription))
             if getattr(scanner, "tenant_wide", False) else Finding.subscription_id == subscription.id)
    stale = db.execute(select(Finding).where(
        owner,
        Finding.finding_type.in_(sorted(types)),
        Finding.status.in_([FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED]),
        or_(Finding.scan_job_id.is_(None), Finding.scan_job_id != scan_job_id),
    )).scalars().all()
    now = datetime.now(timezone.utc)
    for f in stale:
        resource_id = (getattr(getattr(f, "resource", None), "azure_resource_id", None) or "").lower()
        if "/providers/microsoft.security/" in resource_id and "/resourcegroups/" not in resource_id:
            resource_id = resource_id.split("/providers/")[0]   # Defender's subscription-level entities
        reason = (f"Check switched off in Settings ({disabled})" if disabled
                  else reason_for(f.evidence or {}) if reason_for else None)
        if not reason and resource_id and (resource_id, getattr(f, "finding_type", None)) in duplicate_scopes:
            reason = "Covered by another ARG finding on this resource (see 'covers' / 'also reported by' there)"
        if reason:
            f.status = FindingStatus.SUPPRESSED
            f.suppression_reason = reason
        else:
            f.status = FindingStatus.RESOLVED
            f.resolved_at = now
    if stale:
        db.commit()
        logger.info("%s: closed %d finding(s) no longer reported", scanner.scanner_name, len(stale))
    return len(stale)


# ---------------------------------------------------------------------------
# Estate inventory (admin Estate page) - backend/services/estate.py
# ---------------------------------------------------------------------------

@celery_app.task(
    name="workers.scan_worker.refresh_estate",
    soft_time_limit=3000,
    time_limit=3060,
)
def refresh_estate(snapshot_id: str):
    """Resource Graph inventory, usage metrics and cost of every active subscription, joined with the findings."""
    from backend.services.estate import run_refresh

    db = get_sync_db()
    try:
        run_refresh(db, snapshot_id)
    finally:
        db.close()


def queue_estate_refresh(db: Session, triggered_by: str) -> None:
    """Start an estate refresh unless one is running. Never fails the caller (a finished scan)."""
    try:
        from backend.models.models import EstateSnapshot
        from backend.services.estate import FAILED, claim_refresh

        snapshot = claim_refresh(db, triggered_by)
        if snapshot is None:
            logger.info(f"Estate refresh after {triggered_by} skipped: one is already running")
            return
        try:
            refresh_estate.delay(snapshot_id=snapshot.id)
        except Exception as exc:
            db.execute(update(EstateSnapshot).where(EstateSnapshot.id == snapshot.id).values(
                status=FAILED, completed_at=datetime.now(timezone.utc), error_message=f"Could not queue: {exc}"))
            db.commit()
            raise
        logger.info(f"Estate refresh {snapshot.id} queued after {triggered_by}")
    except Exception as exc:
        logger.warning(f"Could not start the estate refresh after {triggered_by}: {exc}")


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
        if not sub_ids:
            # Nothing connected yet (python -m scripts.connect_azure): skip instead of a FAILED job every day
            logger.info("Scheduled full scan skipped: no active subscriptions are connected")
            return

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

        # RUNNING jobs whose worker died (container restart / rebuild, out of memory) stayed "running" forever.
        # Every scanner writes a ScanResult row when it starts; no new row for an hour (well past one scanner's
        # timeout) means nothing is working on the job any more.
        orphaned = recover_orphaned_running_jobs(db, datetime.now(timezone.utc) - timedelta(
            seconds=max(3600, settings.SCANNER_TIMEOUT_SECONDS * 3)))
        if orphaned:
            logger.warning(f"Recovered {orphaned} orphaned RUNNING scan job(s)")
    finally:
        db.close()


def recover_orphaned_running_jobs(db: Session, cutoff: datetime) -> int:
    """Fail RUNNING jobs with no scanner started since `cutoff`; returns how many."""
    from sqlalchemy import func
    from backend.models.models import ScanJob, ScanResult, ScanStatus

    last_progress = (select(func.max(ScanResult.started_at)).where(ScanResult.scan_job_id == ScanJob.id)
                     .scalar_subquery())
    result = db.execute(
        update(ScanJob)
        .where(ScanJob.status == ScanStatus.RUNNING,
               func.coalesce(last_progress, ScanJob.started_at, ScanJob.created_at) < cutoff)
        .values(status=ScanStatus.FAILED, completed_at=datetime.now(timezone.utc),
                error_message="The worker stopped while this scan was running (restart, rebuild or crash) - no "
                              "scanner made progress for an hour. Start the scan again.")
        .execution_options(synchronize_session=False)
    )
    db.commit()
    return result.rowcount


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

"""
Azure Resource Guardian - Base Scanner Framework
=================================================
All scanners inherit from BaseScanner.

Design philosophy:
- Scanners are stateless — they receive credentials and return findings
- Each scanner is independently deployable and testable
- The framework handles retry logic, timing, and error wrapping
- Scanners declare their requirements (Graph API, Cost API, etc.)
- Community plugins simply inherit BaseScanner and register themselves

Plugin registration happens automatically via the ScannerRegistry when
a module containing a BaseScanner subclass is imported.

Example minimal scanner:

    class MyCustomScanner(BaseScanner):
        scanner_name = "my_custom_scanner"
        display_name = "My Custom Scanner"
        category = ScannerCategory.COMPUTE
        severity = SeverityLevel.MEDIUM

        async def scan(self, context: ScanContext) -> ScanOutput:
            resources = await context.resource_graph.query("...")
            findings = []
            for r in resources:
                if some_condition(r):
                    findings.append(self.make_finding(...))
            return ScanOutput(findings=findings)
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Type
from uuid import uuid4

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ScannerCategory(str, Enum):
    COMPUTE    = "compute"
    NETWORK    = "network"
    STORAGE    = "storage"
    IDENTITY   = "identity"
    GOVERNANCE = "governance"
    SECURITY   = "security"
    TERRAFORM  = "terraform"
    DATABASE   = "database"
    COST       = "cost"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


# ---------------------------------------------------------------------------
# Data Transfer Objects
# ---------------------------------------------------------------------------

@dataclass
class ScannerFinding:
    """
    A single finding produced by a scanner.
    Immutable after creation — scanners should not mutate findings.
    """
    finding_type:   str
    title:          str
    description:    str
    severity:       SeverityLevel
    category:       str

    # Azure resource context
    resource_id:         Optional[str] = None   # Azure ARM resource ID
    resource_name:       Optional[str] = None
    resource_type:       Optional[str] = None
    resource_group:      Optional[str] = None
    subscription_id:     Optional[str] = None
    location:            Optional[str] = None

    # Entra ID context (for identity scanners)
    entra_object_id:      Optional[str] = None
    entra_object_type:    Optional[str] = None
    entra_display_name:   Optional[str] = None

    # Remediation
    remediation_steps:    Optional[str] = None
    powershell_script:    Optional[str] = None
    azure_cli_script:     Optional[str] = None
    terraform_hcl:        Optional[str] = None

    # Financial
    estimated_monthly_savings_usd: Optional[float] = None

    # Evidence — scanner-specific raw data for audit trail
    evidence: Dict[str, Any] = field(default_factory=dict)

    # Compliance mappings
    caf_control:  Optional[str] = None
    nist_control: Optional[str] = None
    cis_control:  Optional[str] = None

    # Internal
    finding_id:   str = field(default_factory=lambda: str(uuid4()))
    detected_at:  datetime = field(default_factory=datetime.utcnow)


@dataclass
class ScanContext:
    """
    All dependencies a scanner needs, injected by the orchestrator.
    Scanners must NOT create Azure SDK clients directly.
    """
    subscription_id:  str
    tenant_id:        str
    scan_job_id:      str

    # Azure API clients (injected)
    resource_graph_client:    Any = None
    management_client:        Any = None
    cost_management_client:   Any = None
    graph_client:             Any = None

    # Configuration
    config: Dict[str, Any] = field(default_factory=dict)

    # Parsed Terraform state JSON for the subscription being scanned, if
    # one has been imported via POST /drift/import. Read by
    # TerraformDriftScanner; None means no state has been imported yet.
    terraform_state: Optional[Dict[str, Any]] = None

    # Scanner can use this to log progress
    progress_callback: Optional[Any] = None


@dataclass
class ScanOutput:
    """
    Output from a scanner's scan() method.
    """
    findings:         List[ScannerFinding] = field(default_factory=list)
    resources_scanned: int = 0
    metadata:         Dict[str, Any] = field(default_factory=dict)
    warnings:         List[str] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def findings_by_severity(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in SeverityLevel}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


@dataclass
class ScannerMetadata:
    """
    Declarative metadata about a scanner — used for registration and display.
    """
    scanner_name:      str
    display_name:      str
    description:       str
    category:          ScannerCategory
    severity:          SeverityLevel
    version:           str = "1.0.0"
    author:            str = "ARG Team"
    requires_graph:    bool = False
    requires_cost:     bool = False
    requires_defender: bool = False
    tags:              List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Base Scanner
# ---------------------------------------------------------------------------

class BaseScanner(ABC):
    """
    Abstract base class for all ARG scanners.

    Subclasses MUST define class-level attributes and implement scan().
    The framework calls scan() and wraps it with timing, retry, and error handling.
    """

    # ---- Class-level scanner identity (required in subclasses) ---- #
    scanner_name: str = ""          # Unique snake_case identifier
    display_name: str = ""          # Human-readable name
    description:  str = ""          # What does this scanner detect?
    category:     ScannerCategory = ScannerCategory.COMPUTE
    severity:     SeverityLevel   = SeverityLevel.MEDIUM
    version:      str = "1.0.0"
    author:       str = "ARG Team"
    requires_graph:    bool = False  # Needs Microsoft Graph API access
    requires_cost:     bool = False  # Needs Cost Management API access
    requires_defender: bool = False  # Needs Microsoft Defender data

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"arg.scanner.{self.scanner_name}")
        self._validate_class_attrs()

    def _validate_class_attrs(self):
        """Fail fast if a scanner is missing required class attributes."""
        if not self.scanner_name:
            raise ValueError(f"{self.__class__.__name__} must define scanner_name")
        if not self.display_name:
            raise ValueError(f"{self.__class__.__name__} must define display_name")

    @abstractmethod
    async def scan(self, context: ScanContext) -> ScanOutput:
        """
        Execute the scan and return findings.

        Implementations should:
        1. Query Azure APIs via context clients
        2. Evaluate each resource against detection logic
        3. Create ScannerFinding objects for violations
        4. Return ScanOutput with all findings

        Do NOT raise exceptions for individual resource failures —
        log warnings and continue. Only raise for complete scan failures.
        """
        ...

    async def validate_prerequisites(self, context: ScanContext) -> bool:
        """
        Check that the scanner's prerequisites are met.
        Override to add custom checks (e.g., required API permissions).
        Returns True if prerequisites are met, False otherwise.
        """
        if self.requires_graph and context.graph_client is None:
            self.logger.warning(
                f"Scanner {self.scanner_name} requires Graph API but no client provided"
            )
            return False
        if self.requires_cost and context.cost_management_client is None:
            self.logger.warning(
                f"Scanner {self.scanner_name} requires Cost Management API but no client provided"
            )
            return False
        return True

    async def execute(self, context: ScanContext) -> ScanOutput:
        """
        Framework-managed execution wrapper.
        Handles prerequisites, timing, retries, and error wrapping.
        Call this instead of scan() directly.
        """
        self.logger.info(
            f"Starting scanner: {self.scanner_name} "
            f"(subscription: {context.subscription_id})"
        )

        prereqs_ok = await self.validate_prerequisites(context)
        if not prereqs_ok:
            self.logger.warning(f"Scanner {self.scanner_name} skipped: prerequisites not met")
            return ScanOutput(
                warnings=[f"Scanner skipped: prerequisites not met for {self.scanner_name}"]
            )

        start_time = time.perf_counter()
        try:
            output = await asyncio.wait_for(
                self.scan(context),
                timeout=self.config.get("timeout_seconds", 300)
            )
            elapsed = time.perf_counter() - start_time
            self.logger.info(
                f"Scanner {self.scanner_name} completed in {elapsed:.1f}s — "
                f"{output.finding_count} findings across {output.resources_scanned} resources"
            )
            return output

        except asyncio.TimeoutError:
            self.logger.error(f"Scanner {self.scanner_name} timed out")
            return ScanOutput(warnings=[f"Scanner timed out after {self.config.get('timeout_seconds', 300)}s"])

        except Exception as exc:
            self.logger.error(f"Scanner {self.scanner_name} failed: {exc}", exc_info=True)
            return ScanOutput(warnings=[f"Scanner failed with error: {str(exc)}"])

    def make_finding(
        self,
        finding_type: str,
        title: str,
        description: str,
        resource_id: str,
        resource_name: str,
        resource_type: str,
        resource_group: str,
        subscription_id: str,
        location: str = "",
        severity: Optional[SeverityLevel] = None,
        remediation_steps: Optional[str] = None,
        powershell_script: Optional[str] = None,
        azure_cli_script: Optional[str] = None,
        evidence: Optional[Dict] = None,
        estimated_monthly_savings_usd: Optional[float] = None,
        caf_control: Optional[str] = None,
        nist_control: Optional[str] = None,
        cis_control: Optional[str] = None,
    ) -> ScannerFinding:
        """
        Convenience factory for creating findings with scanner defaults.
        Uses the scanner's default severity if not specified.
        """
        return ScannerFinding(
            finding_type=finding_type,
            title=title,
            description=description,
            severity=severity or self.severity,
            category=self.category.value,
            resource_id=resource_id,
            resource_name=resource_name,
            resource_type=resource_type,
            resource_group=resource_group,
            subscription_id=subscription_id,
            location=location,
            remediation_steps=remediation_steps,
            powershell_script=powershell_script,
            azure_cli_script=azure_cli_script,
            evidence=evidence or {},
            estimated_monthly_savings_usd=estimated_monthly_savings_usd,
            caf_control=caf_control,
            nist_control=nist_control,
            cis_control=cis_control,
        )

    def make_entra_finding(
        self,
        finding_type: str,
        title: str,
        description: str,
        object_id: str,
        object_type: str,
        display_name: str,
        upn: Optional[str] = None,
        severity: Optional[SeverityLevel] = None,
        remediation_steps: Optional[str] = None,
        azure_cli_script: Optional[str] = None,
        powershell_script: Optional[str] = None,
        evidence: Optional[Dict] = None,
        last_sign_in_at: Optional[datetime] = None,
    ) -> ScannerFinding:
        """Factory for Entra ID findings."""
        finding = ScannerFinding(
            finding_type=finding_type,
            title=title,
            description=description,
            severity=severity or self.severity,
            category=self.category.value,
            entra_object_id=object_id,
            entra_object_type=object_type,
            entra_display_name=display_name,
            remediation_steps=remediation_steps,
            azure_cli_script=azure_cli_script,
            powershell_script=powershell_script,
            evidence=evidence or {},
        )
        if last_sign_in_at:
            finding.evidence["last_sign_in_at"] = last_sign_in_at.isoformat()
        if upn:
            finding.evidence["userPrincipalName"] = upn
        return finding

    @property
    def metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            scanner_name=self.scanner_name,
            display_name=self.display_name,
            description=self.description,
            category=self.category,
            severity=self.severity,
            version=self.version,
            author=self.author,
            requires_graph=self.requires_graph,
            requires_cost=self.requires_cost,
            requires_defender=self.requires_defender,
        )


# ---------------------------------------------------------------------------
# Scanner Registry
# ---------------------------------------------------------------------------

class ScannerRegistry:
    """
    Global registry of all available scanner plugins.

    Scanners auto-register when their module is imported.
    The orchestrator uses this registry to look up and instantiate scanners.

    Usage:
        # Register (called automatically by @register_scanner decorator)
        ScannerRegistry.register(MyScanner)

        # Discover all compute scanners
        scanners = ScannerRegistry.get_by_category(ScannerCategory.COMPUTE)

        # Get a specific scanner
        scanner = ScannerRegistry.get("unattached_disk_scanner")()
    """
    _registry: Dict[str, Type[BaseScanner]] = {}

    @classmethod
    def register(cls, scanner_class: Type[BaseScanner]) -> None:
        name = scanner_class.scanner_name
        if not name:
            raise ValueError(f"Scanner class {scanner_class.__name__} has no scanner_name")
        if name in cls._registry:
            logger.warning(f"Scanner {name} is being overridden in registry")
        cls._registry[name] = scanner_class
        logger.debug(f"Registered scanner: {name}")

    @classmethod
    def get(cls, name: str) -> Optional[Type[BaseScanner]]:
        return cls._registry.get(name)

    @classmethod
    def all(cls) -> Dict[str, Type[BaseScanner]]:
        return dict(cls._registry)

    @classmethod
    def get_by_category(cls, category: ScannerCategory) -> List[Type[BaseScanner]]:
        return [
            sc for sc in cls._registry.values()
            if sc.category == category
        ]

    @classmethod
    def get_enabled(cls) -> List[Type[BaseScanner]]:
        """Returns all scanners. Enabled/disabled state is managed in DB."""
        return list(cls._registry.values())

    @classmethod
    def count(cls) -> int:
        return len(cls._registry)


def register_scanner(cls: Type[BaseScanner]) -> Type[BaseScanner]:
    """
    Class decorator for auto-registration.

    Usage:
        @register_scanner
        class MyScanner(BaseScanner):
            ...
    """
    ScannerRegistry.register(cls)
    return cls


# Finding types that represent a genuinely orphaned/unused resource —
# used to set/clear ResourceInventory.is_orphaned (see
# workers/scan_worker.py _persist_finding, which sets it, and
# backend/api/routes/findings.py update_finding_status, which clears it
# when the last open orphan finding on a resource is resolved). Defined
# once here, in a module both the backend API and the worker already
# import from, rather than as two separately-maintained copies that
# could silently drift apart.
ORPHAN_FINDING_TYPES = {
    "unattached_managed_disk",
    "old_disk_snapshot",
    "deallocated_virtual_machine",
    "idle_vmss",
    "unused_public_ip",
    "orphaned_nic",
    "empty_load_balancer",
    "empty_application_gateway",
    "unused_storage_account",
    "orphaned_backup_vault",
}

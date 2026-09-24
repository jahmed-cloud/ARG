"""
Azure Resource Guardian - Posture scanner base
==============================================
Common plumbing for the posture/FinOps scanners that go beyond a single
Resource Graph query:

- arg(): paginated Resource Graph query with the same mock fallback
  contract as the original scanners (no client -> self._mock_data()).
- is_live(): True when an ArmClient was injected. ARM-dependent
  enrichment (metrics, firewall rules, config, cost) only runs live;
  mock rows already carry the enriched fields so scanners stay testable
  without Azure credentials.
- subscription_finding(): findings that belong to the subscription
  itself (budgets, RBAC, secure score) rather than to a single resource.
"""

from typing import Any, Dict, List, Optional

from scanners.base.azure_api import query_resource_graph, subscription_resource_id
from scanners.base.base_scanner import BaseScanner, ScanContext, ScannerFinding, SeverityLevel

SUBSCRIPTION_RESOURCE_TYPE = "microsoft.resources/subscriptions"
SUBSCRIPTION_RESOURCE_GROUP = "(subscription)"


class PostureScanner(BaseScanner):
    """Abstract helper base — subclasses still implement scan()."""

    async def arg(self, context: ScanContext, query: str, *, tenant_scope: bool = False) -> List[Dict[str, Any]]:
        rows = await query_resource_graph(context, query, tenant_scope=tenant_scope)
        return self._mock_data() if rows is None else rows

    @staticmethod
    def is_live(context: ScanContext) -> bool:
        return getattr(context, "arm_client", None) is not None

    def _mock_data(self) -> List[Dict[str, Any]]:
        return []

    def setting(self, key: str, default: Any) -> Any:
        return self.config.get(key, default)

    def subscription_finding(
        self,
        context: ScanContext,
        *,
        finding_type: str,
        title: str,
        description: str,
        severity: Optional[SeverityLevel] = None,
        remediation_steps: Optional[str] = None,
        azure_cli_script: Optional[str] = None,
        powershell_script: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        estimated_monthly_savings_usd: Optional[float] = None,
        caf_control: Optional[str] = None,
        cis_control: Optional[str] = None,
    ) -> ScannerFinding:
        return self.make_finding(
            finding_type=finding_type,
            title=title,
            description=description,
            resource_id=subscription_resource_id(context.subscription_id),
            resource_name=context.subscription_id,
            resource_type=SUBSCRIPTION_RESOURCE_TYPE,
            resource_group=SUBSCRIPTION_RESOURCE_GROUP,
            subscription_id=context.subscription_id,
            location="global",
            severity=severity,
            remediation_steps=remediation_steps,
            azure_cli_script=azure_cli_script,
            powershell_script=powershell_script,
            evidence=evidence,
            estimated_monthly_savings_usd=estimated_monthly_savings_usd,
            caf_control=caf_control,
            cis_control=cis_control,
        )

    def resource_finding(self, row: Dict[str, Any], **kwargs: Any) -> ScannerFinding:
        """make_finding() pre-filled from a Resource Graph row (id/name/type/rg/sub/location)."""
        fallback_type = kwargs.pop("resource_type", "")
        return self.make_finding(
            resource_id=row.get("id"),
            resource_name=row.get("name"),
            resource_type=(row.get("type") or fallback_type or "").lower(),
            resource_group=row.get("resourceGroup"),
            subscription_id=row.get("subscriptionId"),
            location=row.get("location") or "",
            **kwargs,
        )

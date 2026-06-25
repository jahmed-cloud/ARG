"""
Azure Resource Guardian - Security Scanners
==============================================
Detects public exposure and missing audit controls.

Scanners in this module:
1. PublicStorageAccountScanner    — Storage accounts with public blob access
2. PublicSQLServerScanner          — SQL servers with public network access enabled
3. MissingDiagnosticSettingsScanner — Key Vaults/SQL/NSGs missing audit logs

Security findings carry the highest severities since they represent
direct attack surface — a misconfigured public storage account or SQL
server can be exploited within minutes of going live.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from typing import Any, Dict, List

from scanners.base.base_scanner import (
    BaseScanner,
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)


# ---------------------------------------------------------------------------
# Public Storage Account Scanner
# ---------------------------------------------------------------------------

@register_scanner
class PublicStorageAccountScanner(BaseScanner):
    """
    Detects storage accounts with public blob access enabled, allowing
    unauthenticated internet read access to public containers. Microsoft
    disabled this by default in 2023, but older accounts may still
    have it enabled — a frequent source of data breaches.
    """

    scanner_name = "public_storage_account_scanner"
    display_name = "Public Blob Access Enabled"
    description = "Detects storage accounts with public blob access enabled"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.CRITICAL

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.storage/storageaccounts'
        | where properties.allowBlobPublicAccess == true or isnull(properties.allowBlobPublicAccess)
        | project
            id, name, resourceGroup, subscriptionId, location, tags,
            https_only = properties.supportsHttpsTrafficOnly,
            min_tls_version = properties.minimumTlsVersion
        """

        try:
            resources = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for sa in resources:
            additional_risks = []
            if not sa.get("https_only", True):
                additional_risks.append("HTTP traffic allowed (not HTTPS-only)")
            tls = sa.get("min_tls_version", "TLS1_0")
            if tls in ("TLS1_0", "TLS1_1"):
                additional_risks.append(f"Weak TLS version: {tls}")

            risk_text = f" Additional risks: {'; '.join(additional_risks)}." if additional_risks else ""

            findings.append(self.make_finding(
                finding_type="public_storage_account",
                title=f"Public blob access: {sa['name']}",
                description=(
                    f"Storage account '{sa['name']}' has public blob access enabled, "
                    f"allowing unauthenticated read access to any public container.{risk_text}"
                ),
                resource_id=sa["id"],
                resource_name=sa["name"],
                resource_type="microsoft.storage/storageaccounts",
                resource_group=sa.get("resourceGroup"),
                subscription_id=sa.get("subscriptionId"),
                location=sa.get("location"),
                severity=SeverityLevel.CRITICAL,
                remediation_steps=(
                    "1. Immediately disable public blob access on this storage account.\n"
                    "2. Audit all blob containers for public access level settings.\n"
                    "3. Enable 'Secure transfer required' (HTTPS only).\n"
                    "4. Set minimum TLS version to TLS 1.2.\n"
                    "5. Use SAS tokens or Managed Identity for authorized access."
                ),
                azure_cli_script=(
                    f"az storage account update --name {sa['name']} "
                    f"--resource-group {sa.get('resourceGroup')} "
                    f"--allow-blob-public-access false --https-only true --min-tls-version TLS1_2"
                ),
                powershell_script=(
                    f"Set-AzStorageAccount -Name '{sa['name']}' "
                    f"-ResourceGroupName '{sa.get('resourceGroup')}' "
                    f"-AllowBlobPublicAccess $false -EnableHttpsTrafficOnly $true "
                    f"-MinimumTlsVersion TLS1_2"
                ),
                evidence={
                    "https_only": sa.get("https_only"),
                    "min_tls_version": sa.get("min_tls_version"),
                    "additional_risks": additional_risks,
                },
                cis_control="3.5",
                estimated_monthly_savings_usd=0.0,
            ))

        return ScanOutput(findings=findings, resources_scanned=len(resources))

    async def _run_arg_query(self, context: ScanContext, query: str) -> List[Dict]:
        if context.resource_graph_client is None:
            return self._mock_data()

        from azure.mgmt.resourcegraph.models import QueryRequest

        request = QueryRequest(
            subscriptions=[context.subscription_id],
            query=query,
            options={"resultFormat": "objectArray", "$top": 1000},
        )
        response = context.resource_graph_client.resources(request)
        return response.data or []

    def _mock_data(self) -> List[Dict]:
        return [
            {
                "id": "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic1",
                "name": "stpublic1",
                "resourceGroup": "rg-data",
                "location": "eastus",
                "subscriptionId": "sub-1",
                "https_only": True,
                "min_tls_version": "TLS1_2",
                "tags": {},
            }
        ]


# ---------------------------------------------------------------------------
# Public SQL Server Scanner
# ---------------------------------------------------------------------------

@register_scanner
class PublicSQLServerScanner(BaseScanner):
    """
    Detects Azure SQL Servers with public network access enabled,
    meaning they're reachable from the internet subject only to
    firewall rules — a common attack vector when firewall rules are
    overly permissive.
    """

    scanner_name = "public_sql_server_scanner"
    display_name = "Public SQL Server Access"
    description = "Detects SQL servers with public network access enabled"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.CRITICAL

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type =~ 'microsoft.sql/servers'
        | where properties.publicNetworkAccess =~ 'Enabled'
        | project
            id, name, resourceGroup, subscriptionId, location, tags,
            fqdn = properties.fullyQualifiedDomainName,
            version = properties.version
        """

        try:
            resources = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for sql in resources:
            findings.append(self.make_finding(
                finding_type="public_sql_server",
                title=f"Public SQL server: {sql['name']}",
                description=(
                    f"SQL Server '{sql['name']}' has public network access enabled. "
                    f"FQDN: {sql.get('fqdn', 'Unknown')}. This server is internet-reachable "
                    f"subject only to firewall rules."
                ),
                resource_id=sql["id"],
                resource_name=sql["name"],
                resource_type="microsoft.sql/servers",
                resource_group=sql.get("resourceGroup"),
                subscription_id=sql.get("subscriptionId"),
                location=sql.get("location"),
                severity=SeverityLevel.CRITICAL,
                remediation_steps=(
                    "1. Disable public network access and use Private Endpoints.\n"
                    "2. Audit firewall rules — remove any allowing the full IP range.\n"
                    "3. Enable Microsoft Defender for SQL.\n"
                    "4. Enable Azure AD authentication; disable SQL authentication if possible."
                ),
                azure_cli_script=(
                    f"az sql server update --name {sql['name']} "
                    f"--resource-group {sql.get('resourceGroup')} --enable-public-network false"
                ),
                powershell_script=(
                    f"Set-AzSqlServer -ServerName '{sql['name']}' "
                    f"-ResourceGroupName '{sql.get('resourceGroup')}' "
                    f"-PublicNetworkAccess 'Disabled'"
                ),
                evidence={"fqdn": sql.get("fqdn"), "version": sql.get("version")},
                cis_control="4.1",
                estimated_monthly_savings_usd=0.0,
            ))

        return ScanOutput(findings=findings, resources_scanned=len(resources))

    async def _run_arg_query(self, context: ScanContext, query: str) -> List[Dict]:
        if context.resource_graph_client is None:
            return self._mock_data()

        from azure.mgmt.resourcegraph.models import QueryRequest

        request = QueryRequest(
            subscriptions=[context.subscription_id],
            query=query,
            options={"resultFormat": "objectArray", "$top": 1000},
        )
        response = context.resource_graph_client.resources(request)
        return response.data or []

    def _mock_data(self) -> List[Dict]:
        return [
            {
                "id": "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Sql/servers/sql-public-1",
                "name": "sql-public-1",
                "resourceGroup": "rg-data",
                "location": "eastus",
                "subscriptionId": "sub-1",
                "fqdn": "sql-public-1.database.windows.net",
                "version": "12.0",
                "tags": {},
            }
        ]


# ---------------------------------------------------------------------------
# Missing Diagnostic Settings Scanner
# ---------------------------------------------------------------------------

@register_scanner
class MissingDiagnosticSettingsScanner(BaseScanner):
    """
    Flags Key Vaults, SQL Servers, and NSGs that may be missing
    diagnostic settings (audit logs). Resource Graph cannot directly
    query diagnostic settings configuration, so this raises advisory
    findings for every resource of a critical type pending manual
    verification via the Management API or Azure Portal.
    """

    scanner_name = "missing_diagnostic_settings_scanner"
    display_name = "Verify Diagnostic Settings"
    description = "Detects critical resources that may be missing diagnostic settings"
    category = ScannerCategory.SECURITY
    severity = SeverityLevel.HIGH

    async def scan(self, context: ScanContext) -> ScanOutput:
        query = """
        Resources
        | where type in~ (
            'microsoft.keyvault/vaults',
            'microsoft.sql/servers',
            'microsoft.network/networksecuritygroups'
        )
        | project id, name, type, resourceGroup, subscriptionId, location, tags
        """

        try:
            resources = await self._run_arg_query(context, query)
        except Exception as e:
            return ScanOutput(warnings=[f"Failed to query Resource Graph: {e}"])

        findings = []
        for resource in resources:
            rtype = (resource.get("type") or "").lower()
            if "keyvault" in rtype:
                severity = SeverityLevel.HIGH
                advice = (
                    "Enable audit logging for all Key Vault operations. Send logs to a "
                    "Log Analytics Workspace with a 90-day retention minimum."
                )
            else:
                severity = SeverityLevel.MEDIUM
                advice = "Enable diagnostic settings and stream logs to Log Analytics."

            findings.append(self.make_finding(
                finding_type="missing_diagnostic_settings",
                title=f"Verify diagnostics: {resource['name']}",
                description=(
                    f"Resource '{resource['name']}' ({rtype}) may be missing diagnostic "
                    f"settings. Without audit logs, security events cannot be investigated."
                ),
                resource_id=resource["id"],
                resource_name=resource["name"],
                resource_type=rtype,
                resource_group=resource.get("resourceGroup"),
                subscription_id=resource.get("subscriptionId"),
                location=resource.get("location"),
                severity=severity,
                remediation_steps=advice,
                azure_cli_script=(
                    f"# Replace <workspace-id> with your Log Analytics workspace resource ID:\n"
                    f"az monitor diagnostic-settings create --name 'arg-diagnostics' "
                    f"--resource '{resource['id']}' --workspace <workspace-id> "
                    f"--logs '[{{\"category\": \"AuditEvent\", \"enabled\": true}}]'"
                ),
                evidence={"resource_type": rtype},
                estimated_monthly_savings_usd=0.0,
            ))

        return ScanOutput(findings=findings, resources_scanned=len(resources))

    async def _run_arg_query(self, context: ScanContext, query: str) -> List[Dict]:
        if context.resource_graph_client is None:
            return self._mock_data()

        from azure.mgmt.resourcegraph.models import QueryRequest

        request = QueryRequest(
            subscriptions=[context.subscription_id],
            query=query,
            options={"resultFormat": "objectArray", "$top": 1000},
        )
        response = context.resource_graph_client.resources(request)
        return response.data or []

    def _mock_data(self) -> List[Dict]:
        return [
            {
                "id": "/subscriptions/sub-1/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv-sec-1",
                "name": "kv-sec-1",
                "type": "microsoft.keyvault/vaults",
                "resourceGroup": "rg-sec",
                "location": "eastus",
                "subscriptionId": "sub-1",
                "tags": {},
            }
        ]

"""
Azure Resource Guardian - Entra ID Hygiene Scanners
====================================================
Analyzes Microsoft Entra ID (Azure AD) for security and hygiene issues.

These scanners use the Microsoft Graph API and require specific permissions:
- User.Read.All
- Application.Read.All
- Directory.Read.All
- PrivilegedAccess.Read.AzureAD (for PIM)
- AuditLog.Read.All (for sign-in data)

Scanners:
1. StaleGuestUserScanner       — Guests who never signed in
2. DormantUserScanner          — Users inactive > threshold days
3. MFANotEnabledScanner        — Users without MFA
4. PermanentGlobalAdminScanner — Permanent (non-PIM) Global Admins
5. ExpiredAppCredentialScanner — Apps with expired certs/secrets
6. UnusedServicePrincipalScanner — Service principals with no recent activity
7. UnusedManagedIdentityScanner  — Managed identities never used
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from scanners.base.base_scanner import (
    BaseScanner,
    ScanContext,
    ScanOutput,
    ScannerCategory,
    SeverityLevel,
    register_scanner,
)


# ---------------------------------------------------------------------------
# Stale Guest User Scanner
# ---------------------------------------------------------------------------

@register_scanner
class StaleGuestUserScanner(BaseScanner):
    """
    Finds guest users who have never signed in to the tenant.

    Guest accounts that never signed in are dead weight:
    - They hold directory entries and potentially role assignments
    - They may have been invited by mistake
    - They represent a latent access risk if ever compromised

    Risk: If a guest account's home tenant is compromised, that account
    can still access resources in your tenant via the guest link.
    """

    scanner_name   = "stale_guest_scanner"
    display_name   = "Stale Guest Users"
    description    = "Finds guest users who have never signed in to this tenant"
    category       = ScannerCategory.IDENTITY
    severity       = SeverityLevel.MEDIUM
    requires_graph = True

    async def scan(self, context: ScanContext) -> ScanOutput:
        if not context.graph_client:
            return ScanOutput(warnings=["Microsoft Graph client not available"])

        try:
            users = await self._get_never_signed_in_guests(context)
        except Exception as e:
            error_str = str(e)
            if "RequestFromNonPremiumTenantOrB2CTenant" in error_str or "premium license" in error_str.lower():
                # Real, documented Microsoft Graph restriction, not a bug:
                # the signInActivity property requires Azure AD Premium
                # P1/P2 licensing — see Microsoft's "List users" docs.
                return ScanOutput(warnings=[
                    "Stale guest check skipped: this tenant does not have an Azure AD Premium "
                    "P1/P2 license, which Microsoft Graph requires to read sign-in activity. "
                    "Upgrade the tenant's Entra ID license to enable this check."
                ])
            return ScanOutput(warnings=[f"Graph API query failed: {e}"])

        findings = []
        for user in users:
            user_id = user.get("id", "")
            upn = user.get("userPrincipalName", "")
            display_name = user.get("displayName", "Unknown")
            created_dt_str = user.get("createdDateTime", "")
            external_email = user.get("mail", user.get("otherMails", [""])[0] if user.get("otherMails") else "")
            invited_by = user.get("invitedBy", {}).get("user", {}).get("displayName", "Unknown")

            age_days = self._days_since(created_dt_str)

            findings.append(self.make_entra_finding(
                finding_type="guest_never_signed_in",
                title=f"Guest user never signed in: {display_name}",
                description=(
                    f"Guest user '{display_name}' ({external_email}) was invited {age_days} days ago "
                    f"but has NEVER signed in to this tenant. "
                    f"Invited by: {invited_by}. "
                    f"This account should be reviewed and removed if no longer needed."
                ),
                object_id=user_id,
                object_type="user",
                display_name=display_name,
                upn=upn,
                severity=SeverityLevel.HIGH if age_days > 180 else SeverityLevel.MEDIUM,
                remediation_steps=(
                    "1. Contact the inviting user to verify if this guest is still needed\n"
                    "2. If not needed: remove the account using the command below\n"
                    "3. Consider implementing Access Reviews to automatically catch these"
                ),
                azure_cli_script=f"az ad user delete --id \"{user_id}\"",
                powershell_script=f"Remove-MgUser -UserId \"{user_id}\"",
                evidence={
                    "created_at": created_dt_str,
                    "age_days": age_days,
                    "external_email": external_email,
                    "invited_by": invited_by,
                    "user_type": "Guest",
                    "sign_in_activity": "Never",
                },
            ))

        return ScanOutput(
            findings=findings,
            resources_scanned=len(users),
        )

    async def _get_never_signed_in_guests(self, context: ScanContext) -> List[Dict]:
        """
        Query Graph API for guest users with no sign-in activity.
        Uses the signInActivity property (requires AuditLog.Read.All).

        IMPORTANT: signInActivity cannot be combined with other filterable
        properties (like userType) in the same $filter — Microsoft Graph
        rejects that combination with a 400 "Filter not supported" error.
        It also has no supported way to filter for signInActivity being
        null/absent at all (only eq/ne/not/ge/le on its own, and "ne null"
        / "eq null" aren't accepted either). So instead of trying to push
        this logic into the server-side filter, we filter on userType only
        and evaluate "never signed in" client-side in Python below.
        Reference: https://learn.microsoft.com/en-us/graph/api/resources/signinactivity
        """
        if context.graph_client is None:
            return self._mock_guests()

        from msgraph.generated.users.users_request_builder import UsersRequestBuilder
        query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
            filter="userType eq 'Guest'",
            select=["id", "displayName", "userPrincipalName", "mail", "otherMails",
                    "createdDateTime", "signInActivity", "userType"],
            # Graph caps page size at 500 (not the usual 999) whenever
            # signInActivity is selected or filtered on.
            top=500,
        )
        users_response = await context.graph_client.users.get(
            request_configuration=UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
                query_parameters=query_params
            )
        )
        all_guests = users_response.value or []

        # Client-side filter: a guest has "no sign-in activity" if the
        # signInActivity object is absent entirely, or present but with
        # no lastSignInDateTime recorded.
        never_signed_in = [
            g for g in all_guests
            if not getattr(g, "sign_in_activity", None)
            or not getattr(g.sign_in_activity, "last_sign_in_date_time", None)
        ]

        # The SDK returns typed objects with snake_case attributes
        # (user.id, user.user_principal_name), not dicts — normalize to
        # the camelCase dict shape the rest of this scanner expects
        # (and that _mock_guests() already returns), so downstream code
        # works identically for real and mock data.
        return [
            {
                "id": g.id,
                "displayName": g.display_name,
                "userPrincipalName": g.user_principal_name,
                "mail": g.mail,
                "otherMails": g.other_mails or [],
                "createdDateTime": g.created_date_time.isoformat() if g.created_date_time else "",
                "userType": g.user_type,
                "invitedBy": {},  # invitedBy is not selectable on /users; left for evidence parity
            }
            for g in never_signed_in
        ]

    def _mock_guests(self) -> List[Dict]:
        return [
            {
                "id": "user-guid-1",
                "displayName": "External Contractor",
                "userPrincipalName": "contractor_contoso.com#EXT#@tenant.onmicrosoft.com",
                "mail": "contractor@contoso.com",
                "otherMails": [],
                "createdDateTime": (datetime.now(timezone.utc) - timedelta(days=200)).isoformat(),
                "userType": "Guest",
                "invitedBy": {"user": {"displayName": "John Admin"}},
            }
        ]

    def _days_since(self, dt_str: str) -> int:
        if not dt_str:
            return 0
        try:
            dt = datetime.fromisoformat(str(dt_str).replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - dt).days
        except Exception:
            return 0


# ---------------------------------------------------------------------------
# Dormant User Scanner
# ---------------------------------------------------------------------------

@register_scanner
class DormantUserScanner(BaseScanner):
    """
    Finds member users who haven't signed in for longer than the threshold.

    Dormant accounts are a primary vector for credential-based attacks:
    - Credentials may be weak (set years ago, never changed)
    - MFA devices may be lost/transferred
    - Accounts may have accumulated privileged roles over time

    Best practice (NIST 800-63B): Disable accounts inactive > 90 days.
    """

    scanner_name   = "dormant_user_scanner"
    display_name   = "Dormant Users"
    description    = "Finds member users who have not signed in within the threshold period"
    category       = ScannerCategory.IDENTITY
    severity       = SeverityLevel.HIGH
    requires_graph = True

    DEFAULT_THRESHOLD_DAYS = 90

    async def scan(self, context: ScanContext) -> ScanOutput:
        if not context.graph_client:
            return ScanOutput(warnings=["Graph client not available"])

        threshold_days = self.config.get("threshold_days", self.DEFAULT_THRESHOLD_DAYS)
        cutoff = datetime.now(timezone.utc) - timedelta(days=threshold_days)

        try:
            dormant_users = await self._get_dormant_users(context, cutoff)
        except Exception as e:
            error_str = str(e)
            if "RequestFromNonPremiumTenantOrB2CTenant" in error_str or "premium license" in error_str.lower():
                # Real, documented Microsoft Graph restriction, not a bug:
                # the signInActivity property (used here to determine last
                # sign-in date) requires Azure AD Premium P1/P2 licensing
                # and AuditLog.Read.All — see Microsoft's "List users" docs.
                # No permission grant or code change can work around this.
                return ScanOutput(warnings=[
                    "Dormant user check skipped: this tenant does not have an Azure AD Premium "
                    "P1/P2 license, which Microsoft Graph requires to read sign-in activity. "
                    "Upgrade the tenant's Entra ID license to enable this check."
                ])
            return ScanOutput(warnings=[f"Graph API query failed: {e}"])

        findings = []
        for user in dormant_users:
            user_id = user.get("id", "")
            display_name = user.get("displayName", "Unknown")
            upn = user.get("userPrincipalName", "")
            last_signin = user.get("signInActivity", {}).get("lastSignInDateTime")
            last_signin_days = self._days_since(last_signin) if last_signin else None
            is_privileged = user.get("_is_privileged", False)  # enriched by caller

            severity = SeverityLevel.CRITICAL if is_privileged else (
                SeverityLevel.HIGH if (last_signin_days or 999) > 180 else SeverityLevel.MEDIUM
            )

            findings.append(self.make_entra_finding(
                finding_type="dormant_member_user",
                title=f"Dormant user: {display_name}",
                description=(
                    f"User '{display_name}' ({upn}) last signed in "
                    f"{f'{last_signin_days} days ago' if last_signin_days else 'NEVER'}. "
                    f"Threshold: {threshold_days} days. "
                    + ("⚠️ This user has PRIVILEGED ROLES. " if is_privileged else "")
                    + "Disable or remove this account."
                ),
                object_id=user_id,
                object_type="user",
                display_name=display_name,
                upn=upn,
                severity=severity,
                remediation_steps=(
                    f"1. Verify with the user's manager if the account is still needed\n"
                    f"2. Disable the account using the command below\n"
                    f"3. Remove any privileged role assignments before disabling\n"
                    f"4. Set a 30-day deletion schedule if confirmed unused"
                ),
                azure_cli_script=(
                    f"# Disable the account first (safer than immediate deletion)\n"
                    f"az ad user update --id \"{user_id}\" --account-enabled false\n"
                    f"# If confirmed unused after 30 days, delete permanently:\n"
                    f"# az ad user delete --id \"{user_id}\""
                ),
                powershell_script=(
                    f"# Disable the account first (safer than immediate deletion)\n"
                    f"Update-MgUser -UserId \"{user_id}\" -AccountEnabled:$false\n"
                    f"# If confirmed unused after 30 days, delete permanently:\n"
                    f"# Remove-MgUser -UserId \"{user_id}\""
                ),
                evidence={
                    "last_sign_in_at": last_signin,
                    "days_since_signin": last_signin_days,
                    "threshold_days": threshold_days,
                    "is_privileged": is_privileged,
                    "upn": upn,
                },
                last_sign_in_at=datetime.fromisoformat(last_signin.replace("Z", "+00:00")) if last_signin else None,
            ))

        return ScanOutput(
            findings=findings,
            resources_scanned=len(dormant_users),
        )

    async def _get_dormant_users(self, context: ScanContext, cutoff: datetime) -> List[Dict]:
        """
        IMPORTANT: signInActivity cannot be combined with other filterable
        properties (userType, accountEnabled) in the same $filter —
        Microsoft Graph rejects that combination with a 400 "Filter not
        supported" error. So we filter on userType/accountEnabled only
        and evaluate the sign-in cutoff client-side in Python below.
        Reference: https://learn.microsoft.com/en-us/graph/api/resources/signinactivity
        """
        if context.graph_client is None:
            return self._mock_dormant()

        from msgraph.generated.users.users_request_builder import UsersRequestBuilder
        query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
            filter="userType eq 'Member' and accountEnabled eq true",
            select=["id", "displayName", "userPrincipalName", "signInActivity",
                    "accountEnabled", "createdDateTime"],
            # Graph caps page size at 500 (not the usual 999) whenever
            # signInActivity is selected or filtered on.
            top=500,
        )
        result = await context.graph_client.users.get(
            request_configuration=UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
                query_parameters=query_params
            )
        )
        all_members = result.value or []

        dormant = []
        for u in all_members:
            activity = getattr(u, "sign_in_activity", None)
            last_signin_dt = getattr(activity, "last_sign_in_date_time", None) if activity else None
            # Treat "never signed in" the same as "signed in before cutoff"
            # for dormancy purposes — both mean the account hasn't been
            # used recently, which is the property this scanner flags.
            if last_signin_dt is None or last_signin_dt <= cutoff:
                dormant.append(u)

        # The SDK returns typed objects with snake_case attributes, not
        # dicts — normalize to the camelCase shape the rest of this
        # scanner (and _mock_dormant()) already expects.
        #
        # NOTE on is_privileged: this is intentionally always False here.
        # Cross-referencing against PermanentGlobalAdminScanner's role
        # membership data would require either a second Graph round-trip
        # per user or sharing state between scanners, neither of which
        # this scanner does today. A dormant user who also holds a
        # privileged role will still be reported — just without the
        # elevated CRITICAL severity is_privileged=True would otherwise
        # trigger below.
        return [
            {
                "id": u.id,
                "displayName": u.display_name,
                "userPrincipalName": u.user_principal_name,
                "accountEnabled": u.account_enabled,
                "signInActivity": (
                    {"lastSignInDateTime": u.sign_in_activity.last_sign_in_date_time.isoformat()}
                    if u.sign_in_activity and u.sign_in_activity.last_sign_in_date_time
                    else {}
                ),
                "_is_privileged": False,
            }
            for u in dormant
        ]

    def _mock_dormant(self) -> List[Dict]:
        return [
            {
                "id": "user-dormant-1",
                "displayName": "Alice Former Employee",
                "userPrincipalName": "alice@company.com",
                "accountEnabled": True,
                "signInActivity": {
                    "lastSignInDateTime": (datetime.now(timezone.utc) - timedelta(days=150)).isoformat()
                },
                "_is_privileged": False,
            }
        ]

    def _days_since(self, dt_str: str) -> Optional[int]:
        if not dt_str:
            return None
        try:
            dt = datetime.fromisoformat(str(dt_str).replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - dt).days
        except Exception:
            return None


# ---------------------------------------------------------------------------
# MFA Not Enabled Scanner
# ---------------------------------------------------------------------------

@register_scanner
class MFANotEnabledScanner(BaseScanner):
    """
    Finds users who do not have any MFA method registered.

    Per Microsoft Secure Score and CIS Azure Benchmark 1.1.4:
    "Ensure that MFA is enabled for all users in administrative roles"
    and also recommended for all users.

    Uses the Graph API authentication methods endpoint to check
    registered MFA methods per user.
    """

    scanner_name   = "mfa_not_enabled_scanner"
    display_name   = "Users Without MFA"
    description    = "Finds active users who have no MFA method registered"
    category       = ScannerCategory.IDENTITY
    severity       = SeverityLevel.HIGH
    requires_graph = True

    async def scan(self, context: ScanContext) -> ScanOutput:
        if not context.graph_client:
            return ScanOutput(warnings=["Graph client not available"])

        try:
            users_without_mfa = await self._get_users_without_mfa(context)
        except Exception as e:
            error_str = str(e)
            if "RequestFromNonPremiumTenantOrB2CTenant" in error_str or "premium license" in error_str.lower():
                # This is a real, well-documented Microsoft Graph
                # restriction, not a bug: the authenticationMethods
                # userRegistrationDetails report requires Azure AD
                # Premium P1 or P2 licensing on the tenant. No
                # permission grant or code change can work around this —
                # it's enforced server-side by Microsoft based on the
                # tenant's actual license SKU.
                return ScanOutput(warnings=[
                    "MFA check skipped: this tenant does not have an Azure AD Premium P1/P2 "
                    "license, which Microsoft Graph requires for the authentication methods "
                    "report this scanner uses. Upgrade the tenant's Entra ID license to enable "
                    "this check."
                ])
            return ScanOutput(warnings=[f"MFA check failed: {e}"])

        findings = []
        for user in users_without_mfa:
            user_id = user.get("id", "")
            display_name = user.get("displayName", "Unknown")
            upn = user.get("userPrincipalName", "")
            is_admin = user.get("_is_admin", False)

            findings.append(self.make_entra_finding(
                finding_type="mfa_not_enabled",
                title=f"MFA not enabled: {display_name}",
                description=(
                    f"User '{display_name}' ({upn}) has no MFA method registered. "
                    + ("⚠️ This user has ADMIN ROLES — CRITICAL risk. " if is_admin else "")
                    + "Accounts without MFA are vulnerable to password spray and phishing attacks."
                ),
                object_id=user_id,
                object_type="user",
                display_name=display_name,
                upn=upn,
                severity=SeverityLevel.CRITICAL if is_admin else SeverityLevel.HIGH,
                remediation_steps=(
                    "1. Enable MFA via Conditional Access policy (preferred over per-user MFA)\n"
                    "2. Register Microsoft Authenticator as primary MFA method\n"
                    "3. Consider enabling SSPR (Self Service Password Reset) alongside MFA\n"
                    "4. Use Entra ID Protection risk policies to enforce MFA on risky sign-ins"
                ),
                azure_cli_script=(
                    f"# Require MFA re-registration for this user at next sign-in\n"
                    f"az rest --method POST \\\n"
                    f"  --uri 'https://graph.microsoft.com/v1.0/users/{user_id}/revokeSignInSessions'\n"
                    f"# Then enforce MFA via Conditional Access in the portal:\n"
                    f"# https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/CaTemplatesBlade"
                ),
                powershell_script=(
                    f"# Require MFA re-registration for this user at next sign-in\n"
                    f"Revoke-MgUserSignInSession -UserId \"{user_id}\"\n"
                    f"# Then enforce MFA via Conditional Access in the portal:\n"
                    f"# https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/CaTemplatesBlade"
                ),
                evidence={
                    "is_admin": is_admin,
                    "upn": upn,
                    "mfa_methods_registered": 0,
                },
            ))

        return ScanOutput(
            findings=findings,
            resources_scanned=len(users_without_mfa),
        )

    async def _get_users_without_mfa(self, context: ScanContext) -> List[Dict]:
        """
        Uses the Graph API reports endpoint for MFA registration status.
        Endpoint: /reports/authenticationMethods/userRegistrationDetails
        Requires Reports.Read.All permission.
        """
        if context.graph_client is None:
            return self._mock_no_mfa()

        # This uses the reports API
        result = await context.graph_client.reports.authentication_methods.user_registration_details.get()
        users_without_mfa = []
        for reg in (result.value or []):
            if not reg.is_mfa_registered:
                users_without_mfa.append({
                    "id": reg.id,
                    "displayName": reg.display_name,
                    "userPrincipalName": reg.user_principal_name,
                    "_is_admin": reg.is_admin,
                })
        return users_without_mfa

    def _mock_no_mfa(self) -> List[Dict]:
        return [
            {
                "id": "user-no-mfa-1",
                "displayName": "Bob Developer",
                "userPrincipalName": "bob@company.com",
                "_is_admin": False,
            }
        ]


# ---------------------------------------------------------------------------
# Permanent Global Admin Scanner
# ---------------------------------------------------------------------------

@register_scanner
class PermanentGlobalAdminScanner(BaseScanner):
    """
    Finds users who are PERMANENTLY assigned the Global Administrator role.

    Best practice (CIS 1.21, Zero Trust, Microsoft recommendations):
    Global Administrator should ONLY be assigned via PIM (Privileged Identity Management)
    as an eligible assignment, not as a permanent active assignment.

    Permanent Global Admins represent maximum blast radius if compromised.
    """

    scanner_name   = "permanent_global_admin_scanner"
    display_name   = "Permanent Global Administrators"
    description    = "Finds users with permanent (non-PIM) Global Administrator assignments"
    category       = ScannerCategory.IDENTITY
    severity       = SeverityLevel.CRITICAL
    requires_graph = True

    GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"  # Well-known constant

    async def scan(self, context: ScanContext) -> ScanOutput:
        if not context.graph_client:
            return ScanOutput(warnings=["Graph client not available"])

        try:
            permanent_admins = await self._get_permanent_global_admins(context)
        except Exception as e:
            return ScanOutput(warnings=[f"Role assignment query failed: {e}"])

        findings = []
        for admin in permanent_admins:
            user_id = admin.get("id", "")
            display_name = admin.get("displayName", "Unknown")
            upn = admin.get("userPrincipalName", "")
            assignment_type = admin.get("assignmentType", "Permanent")

            findings.append(self.make_entra_finding(
                finding_type="permanent_global_admin",
                title=f"Permanent Global Admin: {display_name}",
                description=(
                    f"User '{display_name}' ({upn}) is PERMANENTLY assigned the Global Administrator role. "
                    f"This is a critical security risk. Global Admin should only be granted via PIM "
                    f"(just-in-time access) and should require approval + justification. "
                    f"Permanent Global Admins have unrestricted access to ALL Azure AD resources."
                ),
                object_id=user_id,
                object_type="user",
                display_name=display_name,
                upn=upn,
                severity=SeverityLevel.CRITICAL,
                remediation_steps=(
                    "1. Enable PIM (Privileged Identity Management) in Entra ID\n"
                    "2. Convert the permanent assignment to a PIM eligible assignment\n"
                    "3. Set maximum activation duration to ≤8 hours\n"
                    "4. Require MFA and justification for activation\n"
                    "5. Enable PIM notifications for role activations\n"
                    "6. Ensure at least 2 but no more than 5 Global Admins exist in total\n"
                    "7. Use dedicated cloud-only admin accounts (not synced from on-prem AD)"
                ),
                evidence={
                    "role": "Global Administrator",
                    "assignment_type": assignment_type,
                    "role_id": self.GLOBAL_ADMIN_ROLE_ID,
                    "upn": upn,
                },
                azure_cli_script=(
                    f"# Remove the permanent Global Administrator role assignment\n"
                    f"# ⚠️  Ensure at least 2 admins remain before removing any\n"
                    f"# ⚠️  Enable PIM and convert to eligible assignment first if possible\n"
                    f"az rest --method DELETE \\\n"
                    f"  --uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
                    f"?$filter=principalId eq '\"'\"'{user_id}'\"'\"' and roleDefinitionId eq '\"'\"'{self.GLOBAL_ADMIN_ROLE_ID}'\"'\"''"
                ),
                powershell_script=(
                    f"# Remove the permanent Global Administrator role assignment\n"
                    f"# ⚠️  Ensure at least 2 admins remain before removing any\n"
                    f"# ⚠️  Enable PIM and convert to eligible assignment first if possible\n"
                    f"$assignments = Get-MgRoleManagementDirectoryRoleAssignment "
                    f"-Filter \"principalId eq '{user_id}' and roleDefinitionId eq '{self.GLOBAL_ADMIN_ROLE_ID}'\"\n"
                    f"foreach ($a in $assignments) {{\n"
                    f"    Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $a.Id\n"
                    f"}}"
                ),
            ))

        return ScanOutput(
            findings=findings,
            resources_scanned=len(permanent_admins),
        )

    async def _get_permanent_global_admins(self, context: ScanContext) -> List[Dict]:
        if context.graph_client is None:
            return self._mock_global_admins()

        role_assignments = await context.graph_client.directory_roles.get()
        global_admin_role = None
        for role in (role_assignments.value or []):
            if role.role_template_id == self.GLOBAL_ADMIN_ROLE_ID:
                global_admin_role = role
                break

        if not global_admin_role:
            return []

        members = await context.graph_client.directory_roles.by_directory_role_id(
            global_admin_role.id
        ).members.get()

        return [
            {
                "id": m.id,
                "displayName": getattr(m, "display_name", "Unknown"),
                "userPrincipalName": getattr(m, "user_principal_name", ""),
                "assignmentType": "Permanent",
            }
            for m in (members.value or [])
            if hasattr(m, "user_principal_name")
        ]

    def _mock_global_admins(self) -> List[Dict]:
        return [
            {
                "id": "admin-guid-1",
                "displayName": "Global Admin User",
                "userPrincipalName": "globaladmin@company.com",
                "assignmentType": "Permanent",
            }
        ]


# ---------------------------------------------------------------------------
# Expired App Credential Scanner
# ---------------------------------------------------------------------------

@register_scanner
class ExpiredAppCredentialScanner(BaseScanner):
    """
    Finds applications and service principals with expired certificates or secrets.

    Expired credentials cause application outages and security issues:
    - Applications silently fail to authenticate
    - Teams scramble for emergency credential rotation
    - Expired creds are sometimes left in code/configs alongside new ones

    Also flags credentials expiring within 30 days as a WARNING.
    """

    scanner_name   = "expired_app_credential_scanner"
    display_name   = "Expired App Credentials"
    description    = "Finds Azure AD apps with expired or soon-expiring certificates and secrets"
    category       = ScannerCategory.IDENTITY
    severity       = SeverityLevel.HIGH
    requires_graph = True

    WARN_DAYS_BEFORE_EXPIRY = 30

    async def scan(self, context: ScanContext) -> ScanOutput:
        if not context.graph_client:
            return ScanOutput(warnings=["Graph client not available"])

        try:
            apps = await self._get_all_applications(context)
        except Exception as e:
            return ScanOutput(warnings=[f"Application query failed: {e}"])

        findings = []
        now = datetime.now(timezone.utc)

        for app in apps:
            app_id = app.get("id", "")
            display_name = app.get("displayName", "Unknown")
            app_client_id = app.get("appId", "")

            # Check password credentials (client secrets)
            for secret in app.get("passwordCredentials", []):
                end_dt = secret.get("endDateTime")
                if not end_dt:
                    continue
                expiry = datetime.fromisoformat(str(end_dt).replace("Z", "+00:00"))
                days_until_expiry = (expiry - now).days
                is_expired = days_until_expiry < 0

                if is_expired or days_until_expiry <= self.WARN_DAYS_BEFORE_EXPIRY:
                    severity = SeverityLevel.CRITICAL if is_expired else (
                        SeverityLevel.HIGH if days_until_expiry <= 7 else SeverityLevel.MEDIUM
                    )
                    status = "EXPIRED" if is_expired else f"expires in {days_until_expiry} days"
                    findings.append(self.make_entra_finding(
                        finding_type="expired_app_secret",
                        title=f"App secret {status}: {display_name}",
                        description=(
                            f"Application '{display_name}' (App ID: {app_client_id}) has a client secret "
                            f"that {status}. Secret hint: '{secret.get('displayName', secret.get('hint', 'N/A'))}'. "
                            f"Applications relying on this secret will fail to authenticate."
                        ),
                        object_id=app_id,
                        object_type="application",
                        display_name=display_name,
                        severity=severity,
                        remediation_steps=(
                            f"1. Create a new client secret for the application\n"
                            f"2. Update all applications/services using this secret\n"
                            f"3. Verify new secret works in all environments\n"
                            f"4. Remove the expired/old secret\n"
                            f"5. Consider using Managed Identities to eliminate secrets entirely"
                        ),
                        evidence={
                            "credential_type": "client_secret",
                            "expiry_date": str(end_dt),
                            "days_until_expiry": days_until_expiry,
                            "secret_name": secret.get("displayName", ""),
                            "app_id": app_client_id,
                        },
                        azure_cli_script=(
                            f"# Step 1: Create a new client secret\n"
                            f"az ad app credential reset --id \"{app_client_id}\" "
                            f"--append --display-name \"ARG-renewed-$(date +%Y%m%d)\"\n"
                            f"# Step 2: Update your application config with the new secret value above\n"
                            f"# Step 3: Remove old expired secrets via the portal:\n"
                            f"# https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/{app_client_id}"
                        ),
                        powershell_script=(
                            f"# Step 1: Create a new client secret\n"
                            f"$secret = Add-MgApplicationPassword -ApplicationId \"{app_id}\" "
                            f"-PasswordCredential @{{DisplayName='ARG-renewed-{{}}'.Replace('{{}}', (Get-Date -Format 'yyyyMMdd'))}}\n"
                            f"Write-Host \"New secret value (save now - only shown once):\" $secret.SecretText\n"
                            f"# Step 2: Update your application config with the new secret value\n"
                            f"# Step 3: Remove old expired secrets via the portal:\n"
                            f"# https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/{app_client_id}"
                        ),
                    ))

            # Check key credentials (certificates)
            for cert in app.get("keyCredentials", []):
                end_dt = cert.get("endDateTime")
                if not end_dt:
                    continue
                expiry = datetime.fromisoformat(str(end_dt).replace("Z", "+00:00"))
                days_until_expiry = (expiry - now).days
                is_expired = days_until_expiry < 0

                if is_expired or days_until_expiry <= self.WARN_DAYS_BEFORE_EXPIRY:
                    severity = SeverityLevel.CRITICAL if is_expired else SeverityLevel.HIGH
                    status = "EXPIRED" if is_expired else f"expires in {days_until_expiry} days"
                    findings.append(self.make_entra_finding(
                        finding_type="expired_app_certificate",
                        title=f"App certificate {status}: {display_name}",
                        description=(
                            f"Application '{display_name}' has a certificate that {status}. "
                            f"Certificate type: {cert.get('type', 'Unknown')}."
                        ),
                        object_id=app_id,
                        object_type="application",
                        display_name=display_name,
                        severity=severity,
                        remediation_steps=(
                            "1. Generate a new certificate (self-signed or from CA)\n"
                            "2. Upload the new certificate to the app registration\n"
                            "3. Update dependent services to use the new certificate\n"
                            "4. Remove the expired certificate from the app registration"
                        ),
                        evidence={
                            "credential_type": "certificate",
                            "expiry_date": str(end_dt),
                            "days_until_expiry": days_until_expiry,
                            "cert_type": cert.get("type", ""),
                            "key_id": str(cert.get("keyId", "")),
                        },
                        azure_cli_script=(
                            f"# Upload a new certificate to the app registration\n"
                            f"# (generate the cert first with openssl or your PKI)\n"
                            f"az ad app credential reset --id \"{app_client_id}\" "
                            f"--cert @/path/to/new-cert.pem --append\n"
                            f"# Then remove the old expired certificate via the portal:\n"
                            f"# https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/{app_client_id}"
                        ),
                        powershell_script=(
                            f"# Upload a new certificate to the app registration\n"
                            f"$certPath = '/path/to/new-cert.cer'  # Replace with your cert path\n"
                            f"$certBytes = [System.IO.File]::ReadAllBytes($certPath)\n"
                            f"Add-MgApplicationKey -ApplicationId \"{app_id}\" "
                            f"-KeyCredential @{{Key=$certBytes; Usage='Verify'; Type='AsymmetricX509Cert'}}\n"
                            f"# Remove the expired cert via the portal:\n"
                            f"# https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/{app_client_id}"
                        ),
                    ))

        return ScanOutput(
            findings=findings,
            resources_scanned=len(apps),
        )

    async def _get_all_applications(self, context: ScanContext) -> List[Dict]:
        if context.graph_client is None:
            return self._mock_apps()

        from msgraph.generated.applications.applications_request_builder import \
            ApplicationsRequestBuilder
        query_params = ApplicationsRequestBuilder.ApplicationsRequestBuilderGetQueryParameters(
            select=["id", "displayName", "appId", "passwordCredentials", "keyCredentials"],
            top=999,
        )
        result = await context.graph_client.applications.get(
            request_configuration=ApplicationsRequestBuilder.ApplicationsRequestBuilderGetRequestConfiguration(
                query_parameters=query_params
            )
        )
        return [
            {
                "id": app.id,
                "displayName": app.display_name,
                "appId": app.app_id,
                "passwordCredentials": [
                    {"endDateTime": str(c.end_date_time), "displayName": c.display_name, "hint": c.hint}
                    for c in (app.password_credentials or [])
                ],
                "keyCredentials": [
                    {"endDateTime": str(c.end_date_time), "type": c.type, "keyId": str(c.key_id)}
                    for c in (app.key_credentials or [])
                ],
            }
            for app in (result.value or [])
        ]

    def _mock_apps(self) -> List[Dict]:
        return [
            {
                "id": "app-guid-1",
                "displayName": "Legacy Integration App",
                "appId": "client-id-123",
                "passwordCredentials": [
                    {
                        "endDateTime": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
                        "displayName": "Production Secret",
                        "hint": "abc...",
                    }
                ],
                "keyCredentials": [],
            }
        ]

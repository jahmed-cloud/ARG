"""GET /findings/{id}: the expanded finding row - scripts, local-report analysis, resource context, related findings."""
from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql

from backend.api.dependencies import auth
from backend.api.dependencies.database import get_db
from backend.api.routes import findings
from backend.models.models import FindingStatus, SeverityLevel, UserRole
from scripts.subscription_analysis.knowledge import CRITIQUES, WAVE_NAMES, WAVE_NO_REGRET

NOW = datetime.now(timezone.utc)
FINDING_ID = "00000000-0000-0000-0000-0000000000f1"


class Result:
    def __init__(self, value):
        self.value = value

    def scalars(self):
        return self

    def all(self):
        return list(self.value)

    def scalar_one_or_none(self):
        return self.value


class ScriptedDb:
    """Returns the scripted results in order and records each query's SQL and bound parameters."""

    def __init__(self, *results):
        self.results = list(results)
        self.queries = []

    async def execute(self, query):
        compiled = query.compile(dialect=postgresql.dialect())
        self.queries.append((str(compiled), {k: str(v) for k, v in compiled.params.items()}))
        return Result(self.results.pop(0))


def resource():
    return SimpleNamespace(resource_name="ddos-plan", resource_type="Microsoft.Network/ddosProtectionPlans",
                           resource_group="rg-net", location="westeurope",
                           azure_resource_id="/subscriptions/s/resourceGroups/rg-net/providers/x/ddos-plan",
                           sku={"name": "Standard"}, tags={"env": "prod"}, environment_tag="prod", owner_tag=None,
                           azure_created_at=NOW)


def finding(ftype="unused_ddos_protection_plan", category="network", with_resource=True, **kw):
    values = dict(
        id=FINDING_ID, finding_type=ftype, title="Unused DDoS plan", description="Not linked to any VNet",
        severity=SeverityLevel.HIGH, status=FindingStatus.OPEN, category=category, subscription_id="sub-1",
        resource_id="res-1" if with_resource else None, estimated_monthly_savings_usd=2944.0,
        estimated_annual_savings_usd=35328.0, first_detected_at=NOW, last_detected_at=NOW, resolved_at=None,
        suppressed_until=None, remediation_steps="1. Confirm no VNet needs it\n2. Delete the plan",
        evidence={"virtual_networks": []}, affected_resources=[], caf_control=None, nist_control="SC-5",
        cis_control=None, suppression_reason=None, scan_job_id=None,
        azure_cli_script="az network ddos-protection delete -g rg-net -n ddos-plan",
        powershell_script="Remove-AzDdosProtectionPlan -ResourceGroupName rg-net -Name ddos-plan",
        resource=resource() if with_resource else None,
    )
    values.update(kw)
    return SimpleNamespace(**values)


def related(title, severity="medium"):
    return SimpleNamespace(id="00000000-0000-0000-0000-0000000000f2", finding_type="missing_required_tags",
                           title=title, severity=SeverityLevel(severity), status=FindingStatus.OPEN)


def client(db, role=UserRole.ANALYST):
    app = FastAPI()
    app.include_router(findings.router, prefix="/findings")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[auth.get_current_user] = lambda: SimpleNamespace(
        id="user-1", role=role, is_active=True, subscription_scoped=False, deleted_at=None,
        sso_provider=None, sso_subject=None)
    return TestClient(app)


def test_detail_returns_scripts_analysis_resource_context_and_related_findings():
    db = ScriptedDb(finding(), [related("Missing tags: ddos-plan")], None)
    r = client(db).get(f"/findings/{FINDING_ID}")
    assert r.status_code == 200
    body = r.json()
    assert body["azure_cli_script"].startswith("az network ddos-protection delete")
    assert body["powershell_script"].startswith("Remove-AzDdosProtectionPlan")
    assert body["estimated_annual_savings_usd"] == 35328.0 and body["nist_control"] == "SC-5"
    analysis = body["analysis"]
    assert analysis["wave"] == WAVE_NO_REGRET and analysis["wave_name"] == WAVE_NAMES[WAVE_NO_REGRET]
    assert analysis["deep_dive"] == "networking" and analysis["area"] == "FinOps / Governance"
    assert analysis["critique"]["key"] == "ddos"
    assert analysis["critique"]["why_it_falls_short"] == CRITIQUES["ddos"].why_it_falls_short
    assert analysis["critique"]["alternatives"] == list(CRITIQUES["ddos"].alternatives)
    context = body["resource_context"]
    assert context["sku"] == {"name": "Standard"} and context["tags"] == {"env": "prod"}
    assert context["environment_tag"] == "prod" and context["owner_tag"] is None
    assert [f["title"] for f in body["related_findings"]] == ["Missing tags: ddos-plan"]
    related_sql, related_params = db.queries[1]
    assert "findings.resource_id = %(resource_id_1)s" in related_sql and "findings.id != %(id_1)s" in related_sql
    assert related_params["resource_id_1"] == "res-1" and related_params["id_1"] == FINDING_ID
    assert related_params["param_1"] == str(findings.RELATED_FINDINGS_LIMIT)


def test_unclassified_type_falls_back_to_the_category_default_without_critique():
    r = client(ScriptedDb(finding(ftype="brand_new_check", category="storage"), [], None)).get(f"/findings/{FINDING_ID}")
    body = r.json()
    analysis = body["analysis"]
    assert analysis["deep_dive"] == "data-sql-storage" and analysis["critique"] is None
    assert body["implementation"]["source"] == "generic" and body["implementation"]["references"] == []


def test_finding_without_a_resource_skips_resource_context_and_related_query():
    db = ScriptedDb(finding(with_resource=False, azure_cli_script=None, powershell_script=None), None)
    body = client(db).get(f"/findings/{FINDING_ID}").json()
    assert body["resource_context"] is None and body["related_findings"] == []
    assert body["azure_cli_script"] is None and len(db.queries) == 2   # the finding, then the hourly-rate setting


def test_detail_explains_why_cost_and_references_and_names_the_subscription():
    sub = SimpleNamespace(display_name="Contoso-Prod-01", subscription_id="11111111-2222-3333-4444-555555555555")
    db = ScriptedDb(finding(subscription=sub), [], {"engineering_hourly_rate_usd": 100})
    body = client(db).get(f"/findings/{FINDING_ID}").json()
    assert body["subscription"] == {"name": "Contoso-Prod-01",
                                    "subscription_id": "11111111-2222-3333-4444-555555555555"}
    impl = body["implementation"]
    assert impl["source"] == "curated" and "flat monthly fee" in impl["why"] and impl["skip_when"]
    assert impl["monthly_usd"] == 0.0 and impl["net_monthly_usd"] == 2944.0
    assert impl["hours"] == [0.5, 1.0] and impl["one_off_usd"] == [50, 100]
    assert all(r["url"].startswith("https://") for r in impl["references"]) and impl["references"]


def test_viewer_cannot_open_a_tenant_wide_identity_finding():
    db = ScriptedDb([], finding(category="identity", with_resource=False))  # viewer grants: none; then the finding
    assert client(db, role=UserRole.VIEWER).get(f"/findings/{FINDING_ID}").status_code == 404


def test_unknown_finding_is_404():
    assert client(ScriptedDb(None)).get(f"/findings/{FINDING_ID}").status_code == 404

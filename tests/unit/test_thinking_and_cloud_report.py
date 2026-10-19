"""Thinking mode's AI review (thinking.py, model call stubbed), the cloud analysis report the worker writes
(cloud_report.py) and the Analysis API that serves it (backend/api/routes/analysis.py)."""
import asyncio
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import scanners.storage.storage_posture_scanners  # noqa: F401 - registers the scanners used below
from scanners.base.base_scanner import ScanContext, ScannerRegistry
from scripts.subscription_analysis import settings as analysis_settings
from scripts.subscription_analysis import thinking

SUB_GUID = "aaaaaaaa-1111-2222-3333-444444444444"


def _findings():
    return [
        {"finding_type": "storage_public_network_access", "severity": "high", "title": "Storage open: stdata",
         "resource_id": f"/subscriptions/{SUB_GUID}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stdata",
         "resource_name": "stdata", "estimated_monthly_savings_usd": 0,
         "evidence": {"publicNetworkAccess": "Enabled", "data_operations_30d": 9000},
         "tags": {"OwnerContact": "someone@example.com"}},
        {"finding_type": "missing_required_tags", "severity": "low", "title": "Missing tags: x", "evidence": {}},
        {"finding_type": "deallocated_virtual_machine", "severity": "medium", "title": "Deallocated VM: vm-old",
         "resource_id": f"/subscriptions/{SUB_GUID}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-old",
         "estimated_monthly_savings_usd": 34.5, "evidence": {"days_deallocated": 120}},
    ]


ON = {"ai_reasoning": True, "ai_endpoint": "https://contoso-ai.openai.azure.com", "ai_deployment": "gpt-4.1"}


def test_settings_validation_and_text_kind():
    assert thinking.settings_ready({})[0] is False
    assert thinking.settings_ready({**ON, "ai_endpoint": "https://evil.example.com"})[1].startswith("ai_endpoint")
    assert thinking.settings_ready({**ON, "ai_deployment": "bad name!"})[1].startswith("ai_deployment")
    assert thinking.settings_ready(ON) == (True, "")
    normalized = analysis_settings.normalize({"ai_endpoint": "  https://x.openai.azure.com  ", "ai_reasoning": "on"})
    assert normalized == {"ai_endpoint": "https://x.openai.azure.com", "ai_reasoning": True}


def test_case_file_masks_guids_skips_hygiene_and_never_sends_tag_values():
    case, keys = thinking.build_case({"name": "sub-prod-app", "environment": "production"}, _findings(),
                                     cost={"currency": "CHF", "last30_by_rg_service": [
                                         {"ServiceName": "Storage", "Cost": 12.0}]})
    text = json.dumps(case)
    assert SUB_GUID not in text
    assert "someone@example.com" not in text                         # tag values are never sent
    assert [f["type"] for f in case["findings"]] == ["storage_public_network_access", "deallocated_virtual_machine"]
    assert set(keys) == {"K1", "K2"} and case["cost_last_30_days"]["by_service"] == {"Storage": 12.0}
    assert case["findings"][0]["built_in_recommendation"]


def test_think_attaches_reviews_and_themes(monkeypatch):
    async def fake_call(endpoint, deployment, case, credential, timeout=180.0):
        assert endpoint == ON["ai_endpoint"] and deployment == "gpt-4.1"
        return {"answer": {
            "summary": "stdata serves 9,000 operations a month from one app.",
            "themes": [{"title": "Network exposure", "evidence": "stdata open", "recommendation": "PE", "keys": ["K1"]}],
            "findings": [{"key": "K1", "agree": False, "recommendation": "Service endpoint first", "why": "no hub DNS",
                          "sequence": ["a", "b"], "risks": ["r"], "questions": ["q?"]},
                         {"key": "K99", "agree": True}],
            "questions_for_owner": ["Who reads stdata?"]},
            "usage": {"prompt_tokens": 1200, "completion_tokens": 300}}

    monkeypatch.setattr(thinking, "call_model", fake_call)
    findings = _findings()
    result = asyncio.run(thinking.think({"name": "sub-prod-app"}, findings, {}, ON, credential=object()))
    assert result["status"] == "ok" and result["reviewed"] == 1 and result["sent"] == 2
    review = findings[0]["ai_review"]
    assert review["agree"] is False and review["recommendation"] == "Service endpoint first"
    assert review["model"] == "Azure OpenAI gpt-4.1"
    findings[0].update(ref="F-001", folder="networking")
    md = thinking.markdown(result, findings)
    assert "## Themes across findings" in md and "[F-001](./networking/README.md#f-001)" in md
    assert "**challenges**" in md and "Who reads stdata?" in md
    assert "challenges the built-in recommendation" in "\n".join(thinking.finding_markdown(review))


def test_think_never_raises(monkeypatch):
    async def broken(*args, **kwargs):
        raise RuntimeError("Azure OpenAI returned 401: no role")

    monkeypatch.setattr(thinking, "call_model", broken)
    result = asyncio.run(thinking.think({"name": "x"}, _findings(), {}, ON, credential=object()))
    assert result["status"] == "error" and "401" in result["reason"]
    assert asyncio.run(thinking.think({"name": "x"}, _findings(), {}, {}, None))["status"] == "off"


# ---- cloud report --------------------------------------------------------------------------------------------------

def test_cloud_report_builds_the_five_parts_from_the_scan_outputs():
    from scripts.subscription_analysis.cloud_report import build_from_scan

    context = ScanContext(subscription_id="sub-1", tenant_id="t", scan_job_id="j", subscription_name="sub-prod-app")
    cls = ScannerRegistry.get("storage_access_hardening_scanner")
    scanner = cls(config={})
    output = asyncio.run(scanner.execute(context))
    result = asyncio.run(build_from_scan(context, {"id": "sub-1", "name": "sub-prod-app", "tenant_id": "t"},
                                         [(scanner, output)], {"required_tags": ["owner"]}, None,
                                         history='[{"generated_at": "2026-09-01T00:00:00+00:00", "findings": 9}]'))
    files = result["files"]
    for page in ("README.md", "01-current-findings/README.md", "02-gap-analysis/README.md",
                 "03-cost-drivers/README.md", "04-architectural-critique/README.md", "05-deep-dive/README.md",
                 "backlog.csv", "summary.json", "history.json"):
        assert page in files, page
    assert not any("/raw/" in f"/{p}" for p in files)                 # raw datasets stay out
    assert any("**How ARG reasoned**" in text for path, text in files.items() if path.startswith("05-deep-dive/"))
    assert result["findings"] == len(output.findings) and result["thinking"] == {}
    assert len(json.loads(files["history.json"])) == 2                # the previous run's trend is carried over


# ---- API -------------------------------------------------------------------------------------------------------------

class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def all(self):
        return self.value


class _Db:
    def __init__(self, *results):
        self.results = list(results)

    async def execute(self, query):
        return _Result(self.results.pop(0))


def _client(*results, role="admin"):
    from backend.api.dependencies import auth
    from backend.api.dependencies.database import get_db
    from backend.api.routes import analysis
    from backend.models.models import UserRole
    from backend.services.access import AccessScope, get_access_scope

    app = FastAPI()
    app.include_router(analysis.router, prefix="/analysis")
    user = SimpleNamespace(id="u1", role=UserRole(role), is_active=True)
    app.dependency_overrides[get_db] = lambda: _Db(*results)
    app.dependency_overrides[auth.get_current_user] = lambda: user
    app.dependency_overrides[get_access_scope] = lambda: AccessScope(user=user)
    return TestClient(app)


SUB = SimpleNamespace(id="00000000-0000-0000-0000-0000000000s1", subscription_id=SUB_GUID, display_name="sub-prod-app")


def _report(**kw):
    values = dict(status="completed", error_message=None, generated_at=datetime(2026, 10, 7, tzinfo=timezone.utc),
                  findings_count=3, summary={"cost_30d": 100.0, "currency": "CHF"}, thinking={"status": "off"},
                  files={"README.md": "# Summary\n\n[Gap](./02-gap-analysis/README.md)\n\nName <script>x</script>",
                         "02-gap-analysis/README.md": "# Gap", "05-deep-dive/networking/README.md": "# Net",
                         "backlog.csv": "Title\nFix\n"})
    values.update(kw)
    return SimpleNamespace(**values)


def test_analysis_page_is_sanitised_html_with_navigation():
    body = _client(SUB, _report()).get(f"/analysis/{SUB.id}").json()
    assert body["path"] == "README.md" and body["subscription"]["name"] == "sub-prod-app"
    assert "<script>" not in body["html"] and "&lt;script" in body["html"]
    assert [n["path"] for n in body["nav"]] == ["README.md", "02-gap-analysis/README.md",
                                                 "05-deep-dive/networking/README.md"]
    missing = _client(SUB, _report()).get(f"/analysis/{SUB.id}?path=05-deep-dive/raw/findings.json")
    assert missing.status_code == 404
    escape = _client(SUB, _report()).get(f"/analysis/{SUB.id}?path=../../etc/passwd")
    assert escape.status_code == 404


def test_analysis_downloads_and_not_ready():
    csv = _client(SUB, _report()).get(f"/analysis/{SUB.id}/file?path=backlog.csv")
    assert csv.status_code == 200 and csv.headers["content-type"].startswith("text/csv") and "Fix" in csv.text
    archive = _client(SUB, _report()).get(f"/analysis/{SUB.id}/download")
    assert archive.status_code == 200 and archive.headers["content-type"] == "application/zip"
    assert _client(SUB, None).get(f"/analysis/{SUB.id}").status_code == 404
    assert _client(None).get(f"/analysis/{SUB.id}").status_code == 404
    failed = _client(SUB, _report(status="failed", error_message="cost API throttled")).get(f"/analysis/{SUB.id}")
    assert failed.json()["html"] is None and failed.json()["error"] == "cost API throttled"


@pytest.mark.parametrize("path", ["README.md", "02-gap-analysis/README.md"])
def test_analysis_pages(path):
    assert _client(SUB, _report()).get(f"/analysis/{SUB.id}?path={path}").status_code == 200

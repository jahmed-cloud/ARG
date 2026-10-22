"""
Tests for the local portal: portal login, origin/host guards, analysis job
flow, report browsing and safe markdown rendering. Azure is faked - the
portal only ever talks to Azure through the az-login credential.
"""

import base64
import json
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("markdown")

from fastapi.testclient import TestClient  # noqa: E402

import scripts.subscription_analysis.collector as collector  # noqa: E402
from scripts.local_portal.app import create_app  # noqa: E402
from scripts.local_portal.azure_session import AzureCliSession, friendly_error, token_claims  # noqa: E402
from scripts.local_portal.jobs import JobManager  # noqa: E402
from scripts.local_portal.render import neutralise_html, render_markdown  # noqa: E402
from scripts.subscription_analysis.report import SUMMARY_FILE, write_index  # noqa: E402

SUB = {"id": "11111111-2222-3333-4444-555555555555", "name": "sub-demo", "tenant_id": "tenant-1", "state": "Enabled"}
ORIGIN = {"origin": "http://testserver"}


class FakeAzure:
    credential = object()

    def status(self, refresh: bool = False):
        return {"signed_in": True, "account": "user@contoso.com", "display_name": "User", "tenant_id": "tenant-1",
                "error": None}


def fake_runner(credential, subscription_id, reports_dir: Path, progress):
    progress("Scanner demo", 1, 2)
    folder = reports_dir / "sub-demo"
    (folder / "01-current-findings").mkdir(parents=True, exist_ok=True)
    (folder / "README.md").write_text("# Demo\n\n[Findings](./01-current-findings/README.md)\n", encoding="utf-8")
    (folder / "01-current-findings" / "README.md").write_text("# Findings\n\n| a | b |\n|---|---|\n| 1 | 2 |\n",
                                                              encoding="utf-8")
    (folder / SUMMARY_FILE).write_text(json.dumps({
        "subscription": SUB, "generated_at": "2026-09-24T10:00:00+00:00", "resources": 3, "findings": 2,
        "findings_by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
        "currency": "CHF", "cost_30d": 100.0, "savings_billing": {"wave_1": 10.0, "wave_2": 5.0},
    }), encoding="utf-8")
    write_index(reports_dir)
    return {"folder": "sub-demo", "findings": 2}


@pytest.fixture
def client(tmp_path, monkeypatch):
    async def fake_list(credential):
        return [SUB]

    monkeypatch.setattr(collector, "list_subscriptions", fake_list)
    jobs = JobManager(tmp_path, lambda: object(), max_workers=1, runner=fake_runner)
    app = create_app(reports_dir=tmp_path, username="admin", password="pw", azure=FakeAzure(), jobs=jobs,
                     allowed_hosts=["testserver"])
    with TestClient(app) as c:
        yield c


def _login(client):
    r = client.post("/login", data={"username": "admin", "password": "pw", "next": "/"}, headers=ORIGIN,
                    follow_redirects=False)
    assert r.status_code == 303 and "arg_portal_session" in r.cookies
    return r


def test_simultaneous_estate_refresh_starts_one_collection(client, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    import scripts.subscription_analysis.estate as estate

    _login(client)
    release = Event()
    calls = []

    def slow_status(refresh=False):
        time.sleep(0.05)
        return {"signed_in": True, "tenant_id": "tenant-1"}

    def fake_refresh(*args):
        calls.append(args)
        assert release.wait(timeout=5)

    monkeypatch.setattr(client.app.state.azure, 'status', slow_status)
    monkeypatch.setattr(estate, 'refresh_estate', fake_refresh)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda _: client.post('/api/estate/refresh', headers=ORIGIN), range(2)))
        assert all(r.status_code == 200 and r.json()['running'] for r in responses)
        for _ in range(100):
            if calls:
                break
            time.sleep(0.01)
        assert len(calls) == 1
    finally:
        release.set()
    for _ in range(100):
        if not client.get('/api/estate/status').json()['running']:
            break
        time.sleep(0.01)


def test_pages_and_api_require_portal_login(client):
    assert client.get("/", follow_redirects=False).headers["location"].startswith("/login")
    assert client.get("/api/state").status_code == 401
    assert client.get("/reports/README.md", follow_redirects=False).status_code == 303


def test_wrong_password_is_rejected(client, monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda s: None)
    r = client.post("/login", data={"username": "admin", "password": "nope"}, headers=ORIGIN, follow_redirects=False)
    assert "error=1" in r.headers["location"]
    assert client.get("/api/state").status_code == 401


def test_dashboard_shows_az_login_account_and_subscriptions(client):
    _login(client)
    page = client.get("/")
    assert page.status_code == 200
    assert "user@contoso.com" in page.text and "sub-demo" in page.text
    assert "Content-Security-Policy" in page.headers


def test_cross_origin_post_is_rejected(client):
    _login(client)
    r = client.post("/api/analyze", json={"subscription_ids": [SUB["id"]]}, headers={"origin": "https://evil.example"})
    assert r.status_code == 403


def test_unknown_host_is_rejected(client):
    assert client.get("/login", headers={"host": "evil.example"}).status_code == 400


def test_analyze_unknown_subscription_is_refused(client):
    _login(client)
    r = client.post("/api/analyze", json={"subscription_ids": ["not-visible"]}, headers=ORIGIN)
    assert r.status_code == 400


def test_analysis_job_writes_report_folder_and_index(client, tmp_path):
    _login(client)
    r = client.post("/api/analyze", json={"subscription_ids": [SUB["id"]]}, headers=ORIGIN)
    assert r.status_code == 200
    job_id = r.json()["jobs"][0]["id"]
    for _ in range(50):
        jobs = client.get("/api/state").json()["jobs"]
        if jobs[0]["status"] == "completed":
            break
        time.sleep(0.05)
    assert jobs[0]["id"] == job_id and jobs[0]["status"] == "completed" and jobs[0]["folder"] == "sub-demo"
    assert (tmp_path / "sub-demo" / "README.md").is_file()
    assert "sub-demo" in (tmp_path / "README.md").read_text(encoding="utf-8")

    page = client.get("/reports/sub-demo/01-current-findings/README.md")
    assert page.status_code == 200 and "<table>" in page.text
    assert client.get("/reports/sub-demo", follow_redirects=False).headers["location"] == "/reports/sub-demo/README.md"
    assert client.get("/reports/sub-demo/summary.json").status_code == 200
    dashboard = client.get("/")
    assert "/reports/sub-demo/README.md" in dashboard.text


def test_report_paths_cannot_escape_reports_dir(client, tmp_path):
    _login(client)
    (tmp_path.parent / "outside.md").write_text("secret", encoding="utf-8")
    assert client.get("/reports/%2e%2e/outside.md").status_code == 404


def test_estate_page_and_api(client, tmp_path):
    assert client.get("/estate", follow_redirects=False).status_code == 303
    assert client.get("/api/estate").status_code == 401
    _login(client)
    fake_runner(None, SUB["id"], tmp_path, lambda *a: None)
    page = client.get("/estate")
    assert page.status_code == 200 and "/static/estate.js" in page.text and "<script>" not in page.text
    assert "Junaid Ahmed" in page.text and "https://github.com/jahmed-cloud/ARG" in page.text
    data = client.get("/api/estate", headers={"accept-encoding": "gzip"})
    assert data.status_code == 200 and data.json()["format"] == 2
    assert [s["name"] for s in data.json()["subscriptions"]] == ["sub-demo"]
    assert (tmp_path / "_estate" / "README.md").is_file()
    assert client.get("/static/estate.js").status_code == 200


def test_compute_page_and_api(client, tmp_path):
    assert client.get("/compute", follow_redirects=False).status_code == 303
    assert client.get("/api/compute").status_code == 401
    _login(client)
    page = client.get("/compute")
    assert page.status_code == 200 and "/static/compute.js" in page.text and "<script>" not in page.text
    assert 'href="/compute" aria-current="page"' in page.text
    assert client.get("/api/compute").status_code == 404                  # before the first live refresh
    (tmp_path / "_estate").mkdir(exist_ok=True)
    (tmp_path / "_estate" / "compute.json").write_text(json.dumps({"machines": [], "summary": {"machines": 0}}),
                                                       encoding="utf-8")
    assert client.get("/api/compute").json()["summary"]["machines"] == 0
    assert client.get("/static/compute.js").status_code == 200


def test_policy_page_analysis_and_markdown(client, tmp_path):
    from tests.unit.test_policy_analyzer import estate as estate_data
    from tests.unit.test_policy_analyzer import policy as policy_data

    assert client.get("/policy", follow_redirects=False).status_code == 303
    assert client.get("/api/policy-analysis").status_code == 401
    _login(client)
    page = client.get("/policy")
    assert page.status_code == 200 and "/static/policy.js" in page.text and "<script>" not in page.text
    assert client.get("/api/policy-analysis").status_code == 404           # no estate / policy collection yet
    folder = tmp_path / "_estate"
    folder.mkdir(exist_ok=True)
    (folder / "estate.json").write_text(json.dumps(estate_data()), encoding="utf-8")
    (folder / "policy.json").write_text(json.dumps(policy_data()), encoding="utf-8")
    body = client.get("/api/policy-analysis").json()
    assert body["summary"]["assignments"] == 6 and body["issues"][0]["key"] == "no_identity"
    md = client.get("/api/policy.md")
    assert md.text.startswith("# Azure Policy analysis") and "attachment" in md.headers["content-disposition"]
    assert client.get("/static/policy.js").status_code == 200
    icon = client.get("/azure-icons/Management-Groups.svg")      # Microsoft's icon, unchanged, behind the login
    assert icon.status_code == 200 and icon.headers["content-type"].startswith("image/svg")
    from pathlib import Path
    original = Path(__file__).resolve().parents[2] / "scripts" / "subscription_analysis" / "azure_icons"
    assert icon.content == (original / "Management-Groups.svg").read_bytes()


def test_architecture_page_and_diagrams(client, tmp_path):
    assert client.get("/architecture", follow_redirects=False).status_code == 303
    assert client.get("/api/architecture.svg").status_code == 401
    _login(client)
    assert client.get("/api/architecture.svg").status_code == 404          # nothing analysed yet
    from scripts.subscription_analysis.estate import refresh_estate

    fake_runner(None, SUB["id"], tmp_path, lambda *a: None)
    refresh_estate(tmp_path)                                                # what the analysis job does after a run
    page = client.get("/architecture")
    assert page.status_code == 200 and "/static/architecture.js" in page.text and "<script>" not in page.text
    assert "onchange" not in page.text and "sub-demo" in page.text          # CSP: no inline handlers
    tenant = client.get("/api/architecture.svg")
    assert tenant.status_code == 200 and tenant.headers["content-type"].startswith("image/svg+xml")
    assert f'href="/architecture?subscription={SUB["id"]}"' in tenant.text
    sub = client.get(f"/api/architecture.svg?subscription={SUB['id']}")
    assert sub.status_code == 200 and "What is allowed" in sub.text and 'href="/architecture"' in sub.text
    assert client.get("/api/architecture.svg?subscription=nope").status_code == 404
    assert client.get("/static/architecture.js").status_code == 200


def test_network_view_and_dashboard_telemetry(client, tmp_path):
    from test_network import SUB_B, network_estate

    from scripts.subscription_analysis.estate import ESTATE_DIR, ESTATE_FILE

    (tmp_path / ESTATE_DIR).mkdir(exist_ok=True)
    (tmp_path / ESTATE_DIR / ESTATE_FILE).write_text(json.dumps(network_estate()), encoding="utf-8")
    _login(client)
    svg = client.get(f"/api/architecture.svg?view=network&subscription={SUB_B}")
    assert svg.status_code == 200 and "snet-app" in svg.text
    tenant = client.get("/api/architecture.svg?view=network")
    assert f'href="/architecture?view=network&amp;subscription={SUB_B}"' in tenant.text
    page = client.get(f"/architecture?view=network&subscription={SUB_B}")
    assert page.status_code == 200 and 'aria-current="page">Network</a>' in page.text
    assert 'name="view" value="network"' in page.text
    home = client.get("/")
    assert "Estate telemetry" in home.text and "Stopped, not deallocated: vm-2" in home.text


def test_estate_refresh_uses_the_az_login_session(client, tmp_path, monkeypatch):
    import scripts.subscription_analysis.estate as estate

    calls = []
    monkeypatch.setattr(estate, "refresh_estate", lambda reports, credential=None, subs=None: calls.append(
        (reports, credential, [s["id"] for s in subs or []])))
    _login(client)
    assert client.post("/api/estate/refresh", json={}, headers={"origin": "https://evil.example"}).status_code == 403
    r = client.post("/api/estate/refresh", json={}, headers=ORIGIN)
    assert r.status_code == 200 and r.json()["subscriptions"] == 1
    for _ in range(50):
        status = client.get("/api/estate/status").json()
        if not status["running"]:
            break
        time.sleep(0.05)
    assert status["error"] is None and calls and calls[0][2] == [SUB["id"]]


def test_markdown_rendering_neutralises_html_but_keeps_details():
    text = ("Name <script>alert(1)</script> `a<b>`\n\n<details><summary>Evidence</summary>\n\n"
            "```json\n{\"x\": \"<y>\"}\n```\n\n</details>\n")
    html = render_markdown(text)
    assert "<script>" not in html and "&lt;script" in html
    assert "<details>" in html and "<summary>Evidence</summary>" in html and "<pre>" in html
    assert "&lt;y&gt;" in html
    assert neutralise_html("<b>x</b><br/>") == "&lt;b>x&lt;/b><br/>"


def test_token_claims_and_friendly_errors():
    payload = base64.urlsafe_b64encode(json.dumps({"upn": "u@x.com", "tid": "t"}).encode()).decode().rstrip("=")
    assert token_claims(f"h.{payload}.s") == {"upn": "u@x.com", "tid": "t"}
    assert token_claims("garbage") == {}
    assert "az login" in friendly_error(RuntimeError("Please run 'az login' to setup account."))


def test_azure_cli_session_reports_not_signed_in():
    class Broken:
        def get_token(self, scope):
            raise RuntimeError("Please run 'az login' to setup account.")

    status = AzureCliSession(credential_factory=Broken).status()
    assert status["signed_in"] is False and "az login" in status["error"]


def test_cli_tokens_are_cached_until_near_expiry():
    from types import SimpleNamespace

    from scripts.local_portal.azure_session import CachedTokenCredential

    class Counting:
        calls = 0

        def get_token(self, *scopes, **kwargs):
            Counting.calls += 1
            return SimpleNamespace(token="t", expires_on=time.time() + 3600)

    cred = CachedTokenCredential(Counting())
    cred.get_token("https://management.azure.com/.default")
    cred.get_token("https://management.azure.com/.default")
    assert Counting.calls == 1
    cred.get_token("https://graph.microsoft.com/.default")
    assert Counting.calls == 2


def test_parallel_analyses_share_one_az_call_with_a_longer_timeout(monkeypatch):
    import threading
    from types import SimpleNamespace

    import azure.identity

    from scanners.base import azure_api
    from scripts.subscription_analysis.cli import make_credential

    created = {}

    class SlowCli:
        calls = 0

        def __init__(self, **kwargs):
            created.update(kwargs)

        def get_token(self, *scopes, **kwargs):
            SlowCli.calls += 1
            time.sleep(0.2)
            return SimpleNamespace(token="t", expires_on=time.time() + 3600)

    monkeypatch.setattr(azure.identity, "AzureCliCredential", SlowCli)
    cred = make_credential("cli", "tenant-1")
    threads = [threading.Thread(target=cred.get_token, args=("https://management.azure.com/.default",))
               for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert SlowCli.calls == 1
    assert created == {"tenant_id": "tenant-1", "process_timeout": azure_api.AZ_CLI_TIMEOUT_SECONDS}
    assert azure_api.AZ_CLI_TIMEOUT_SECONDS > 10  # azure-identity's default of 10 s fails under parallel load


def test_cli_rejects_output_with_multiple_subscriptions():
    from scripts.subscription_analysis.cli import main

    with pytest.raises(SystemExit):
        main(["--all", "--output", "x"])


def test_pdf_export_endpoint_print_view_and_pdf_download(client, tmp_path, monkeypatch):
    import scripts.subscription_analysis.export as export

    _login(client)
    r = client.post("/api/analyze", json={"subscription_ids": [SUB["id"]]}, headers=ORIGIN)
    for _ in range(50):
        if client.get("/api/state").json()["jobs"][0]["status"] == "completed":
            break
        time.sleep(0.05)

    def fake_export(target, detail):
        pdf = Path(target) / f"report-{detail}.pdf"
        pdf.write_bytes(b"%PDF-1.4 fake")
        return pdf

    monkeypatch.setattr(export, "export_pdf", fake_export)
    r = client.post("/api/export-pdf", json={"folder": "sub-demo", "detail": "summary"}, headers=ORIGIN)
    assert r.status_code == 200 and r.json()["url"] == "/reports/sub-demo/report-summary.pdf"
    pdf = client.get("/reports/sub-demo/report-summary.pdf")
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf"
    assert "PDF (summary)" in client.get("/").text
    page = client.get("/reports/sub-demo/README.md")
    assert "Export PDF (summary)" in page.text
    assert client.get("/print/sub-demo?detail=full").status_code == 200
    assert client.post("/api/export-pdf", json={"folder": "..", "detail": "summary"}, headers=ORIGIN).status_code == 400
    assert client.get("/print/nope").status_code == 404


def test_stale_code_import_error_says_restart_the_portal(tmp_path):
    def stale_runner(credential, subscription_id, reports_dir, progress):
        raise ImportError("cannot import name 'HOURS_BILLED_PER_MONTH' from 'scanners.base.azure_api'")

    jobs = JobManager(tmp_path, lambda: object(), max_workers=1, runner=stale_runner)
    job = jobs.submit("sub-1", "sub")
    for _ in range(50):
        if jobs.get(job.id).status == "failed":
            break
        time.sleep(0.02)
    jobs.shutdown()
    assert jobs.get(job.id).status == "failed"
    assert jobs.get(job.id).error.endswith("restart the portal and try again.")


# ---- versioned API for scripts / CI and the AI prompt ------------------------------------

API_TOKEN = "t" * 32


def _api_report(root: Path) -> None:
    folder = root / "sub-demo"
    (folder / "05-deep-dive" / "raw").mkdir(parents=True)
    (folder / "README.md").write_text("# Demo\n", encoding="utf-8")
    (folder / SUMMARY_FILE).write_text(json.dumps({
        "subscription": SUB, "generated_at": "2026-09-24T10:00:00+00:00", "resources": 3, "findings": 2,
        "findings_by_severity": {"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0},
        "currency": "CHF", "cost_30d": 100.0, "savings_billing": {"wave_1": 10.0, "wave_2": 5.0},
    }), encoding="utf-8")
    (folder / "05-deep-dive" / "raw" / "findings.json").write_text(json.dumps([
        {"ref": "F-001", "severity": "critical", "finding_type": "public_storage", "title": "Public storage st1",
         "resource_name": "st1", "resource_id": f"/subscriptions/{SUB['id']}/x/st1", "subscription_id": SUB["id"]},
        {"ref": "F-002", "severity": "medium", "finding_type": "missing_tags", "title": "Tags on vm1",
         "resource_name": "vm1", "resource_id": f"/subscriptions/{SUB['id']}/x/vm1", "subscription_id": SUB["id"]},
    ]), encoding="utf-8")


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    async def fake_list(credential):
        return [SUB]

    monkeypatch.setattr(collector, "list_subscriptions", fake_list)
    _api_report(tmp_path)
    jobs = JobManager(tmp_path, lambda: object(), max_workers=1, runner=fake_runner)
    app = create_app(reports_dir=tmp_path, username="admin", password="pw", azure=FakeAzure(), jobs=jobs,
                     allowed_hosts=["testserver"], api_token=API_TOKEN)
    with TestClient(app) as c:
        yield c


BEARER = {"authorization": f"Bearer {API_TOKEN}"}


def test_api_token_authenticates_api_calls_only(api_client):
    assert api_client.get("/api/v1/reports").status_code == 401
    assert api_client.get("/api/v1/reports", headers={"authorization": "Bearer wrong-token"}).status_code == 401
    r = api_client.get("/api/v1/reports", headers=BEARER)
    assert r.status_code == 200 and r.json()["reports"][0]["folder"] == "sub-demo"
    # the token never opens the HTML portal
    assert api_client.get("/", headers=BEARER, follow_redirects=False).status_code == 303
    with pytest.raises(ValueError):
        create_app(reports_dir=Path("."), username="a", password="b", azure=FakeAzure(), api_token="short")


def test_api_reports_findings_and_gate_by_folder_id_or_name(api_client):
    for key in ("sub-demo", SUB["id"], SUB["id"].upper(), "SUB-DEMO"):
        assert api_client.get(f"/api/v1/reports/{key}", headers=BEARER).json()["folder"] == "sub-demo"
    assert api_client.get("/api/v1/reports/nope", headers=BEARER).status_code == 404
    assert api_client.get("/api/v1/reports/..", headers=BEARER).status_code == 404
    findings = api_client.get("/api/v1/reports/sub-demo/findings?min_severity=high", headers=BEARER).json()
    assert findings["total"] == 1 and findings["items"][0]["ref"] == "F-001"
    assert api_client.get("/api/v1/reports/sub-demo/findings?min_severity=bad", headers=BEARER).status_code == 400
    gate = api_client.get("/api/v1/reports/sub-demo/gate?fail_on=critical", headers=BEARER).json()
    assert gate["passed"] is False and gate["blocking"] == 1
    gate = api_client.get("/api/v1/reports/sub-demo/gate?fail_on=critical&ignore=public_storage", headers=BEARER).json()
    assert gate["passed"] is True
    sarif = api_client.get("/api/v1/reports/sub-demo/sarif", headers=BEARER)
    assert sarif.headers["content-type"].startswith("application/sarif+json") and sarif.json()["version"] == "2.1.0"
    junit = api_client.get("/api/v1/reports/sub-demo/junit?fail_on=medium", headers=BEARER)
    assert 'failures="2"' in junit.text
    spec = api_client.get("/api/v1/openapi.json", headers=BEARER).json()
    assert "/api/v1/reports/{key}/gate" in spec["paths"] and "/" not in spec["paths"]


def test_api_starts_analyses_by_name_and_reports_job_status(api_client):
    subs = api_client.get("/api/v1/subscriptions", headers=BEARER).json()
    assert subs["subscriptions"][0]["report_folder"] == "sub-demo"
    assert api_client.post("/api/v1/analyses", json={"subscriptions": ["ghost"]}, headers=BEARER).status_code == 400
    r = api_client.post("/api/v1/analyses", json={"subscriptions": ["sub-demo"]}, headers=BEARER)
    assert r.status_code == 202
    job_id = r.json()["jobs"][0]["id"]
    for _ in range(50):
        job = api_client.get(f"/api/v1/analyses/{job_id}", headers=BEARER).json()
        if job["status"] == "completed":
            break
        time.sleep(0.05)
    assert job["status"] == "completed" and job["folder"] == "sub-demo"
    assert api_client.get("/api/v1/analyses/nope", headers=BEARER).status_code == 404
    # a cross-origin browser request is still refused, token or not
    assert api_client.post("/api/v1/analyses", json={"subscriptions": ["sub-demo"]},
                           headers={**BEARER, "origin": "https://evil.example"}).status_code == 403


def test_ai_prompt_api_is_kept_but_not_shown_in_the_ui(api_client):
    r = api_client.get("/api/v1/reports/sub-demo/ai-prompt", headers=BEARER)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/markdown")
    assert "F-001" in r.text and SUB["id"] not in r.text and "<id-1>" in r.text
    assert "content-disposition" not in r.headers
    r = api_client.get("/api/v1/reports/sub-demo/ai-prompt?download=1&min_severity=critical&mask_ids=false", headers=BEARER)
    assert "attachment" in r.headers["content-disposition"] and SUB["id"] in r.text and "F-002" not in r.text
    _login(api_client)
    page = api_client.get("/reports/sub-demo/README.md").text
    assert "Export PDF (summary)" in page and 'aria-current="page"' in page
    assert "ai-chat" not in page and "ai-prompt" not in page
    assert "ai-chat" not in api_client.get("/").text


def test_settings_page_saves_and_feeds_the_next_analysis(client, tmp_path):
    _login(client)
    page = client.get("/settings")
    assert page.status_code == 200 and "Naming convention check" in page.text
    assert "Defender plan-enablement recommendations" in page.text
    r = client.post("/settings", data={"blocked_resource_providers": "Microsoft.ClassicCompute\nMicrosoft.Batch",
                                       "engineering_hourly_rate_usd": "110", "ai_gateway_sku": "Standard v2"},
                    headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/settings?saved=1"
    saved = client.get("/api/settings").json()
    assert saved["naming_convention_enabled"] is False          # unchecked box
    assert saved["report_unused_providers"] is False
    assert saved["blocked_resource_providers"] == ["Microsoft.Batch", "Microsoft.ClassicCompute"]
    assert saved["engineering_hourly_rate_usd"] == 110.0 and saved["ai_gateway_sku"] == "Standard v2"
    assert client.put("/api/settings", json={"naming_convention_enabled": True},
                      headers=ORIGIN).json()["naming_convention_enabled"] is True

    from scripts.subscription_analysis.cli import default_config

    assert default_config(reports_dir=tmp_path)["engineering_hourly_rate_usd"] == 110.0


def test_menu_groups_estate_and_governance_and_marks_the_current_page(client):
    import re

    _login(client)

    def current(path):
        page = client.get(path).text
        page = page.split('<nav aria-label="Main navigation"')[1].split("</nav>")[0]   # the main menu only
        groups = re.findall(r'<details class="nav-menu( current)?">\s*<summary>(\w+)</summary>', page)
        return {name for flag, name in groups if flag}, re.findall(r'<a href="([^"]+)" aria-current="page"', page)

    assert current("/compute") == ({"Estate"}, ["/compute"])
    assert current("/policy") == ({"Governance"}, ["/policy"])
    assert current("/architecture?view=landing") == ({"Governance"}, ["/architecture?view=landing"])
    assert current("/architecture") == ({"Estate"}, ["/architecture"])
    assert current("/") == (set(), ["/"])
    assert client.get("/static/nav.js").status_code == 200

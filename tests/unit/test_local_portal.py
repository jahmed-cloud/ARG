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

"""
Tests for PDF export, bounded concurrency and the scanner logic fixes made
during validation (workload counting, verified backup vaults, idle rules).
"""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("markdown")

import scanners.governance.governance_posture_scanners  # noqa: E402,F401
import scanners.storage.storage_scanners  # noqa: E402,F401
from scanners.base.azure_api import gather_limited  # noqa: E402
from scanners.base.base_scanner import ScanContext, ScannerRegistry  # noqa: E402
from scripts.subscription_analysis import export  # noqa: E402


def _report(tmp_path: Path) -> Path:
    root = tmp_path / "sub-demo"
    (root / "01-current-findings").mkdir(parents=True)
    (root / "05-deep-dive" / "networking").mkdir(parents=True)
    (root / "README.md").write_text("# Summary `sub-demo`\n\nSee [findings](./01-current-findings/README.md) "
                                    "and [F-001](./05-deep-dive/networking/README.md#f-001).\n\n## Top risks\n",
                                    encoding="utf-8")
    (root / "01-current-findings" / "README.md").write_text("# 01 - Current\n\n[back](../README.md)\n", encoding="utf-8")
    (root / "01-current-findings" / "resource-inventory.md").write_text("# Inventory\n", encoding="utf-8")
    (root / "05-deep-dive" / "networking" / "README.md").write_text("# Networking\n\n## F-001\n\ntext\n",
                                                                    encoding="utf-8")
    (root / "summary.json").write_text(json.dumps({"subscription": {"id": "s", "name": "sub-demo"}}), encoding="utf-8")
    return root


def test_report_pages_summary_vs_full(tmp_path):
    root = _report(tmp_path)
    assert export.report_pages(root, "summary") == ["README.md", "01-current-findings/README.md"]
    full = export.report_pages(root, "full")
    assert "01-current-findings/resource-inventory.md" in full and "05-deep-dive/networking/README.md" in full
    with pytest.raises(ValueError):
        export.report_pages(root, "everything")


def test_print_body_rewrites_links_to_in_document_anchors(tmp_path):
    root = _report(tmp_path)
    title, body = export.build_print_body(root, "full")
    assert title == "Subscription Analysis - sub-demo"
    assert 'href="#page-01-current-findings-readme-md"' in body
    assert 'href="#page-05-deep-dive-networking-readme-md--f-001"' in body
    assert 'id="page-05-deep-dive-networking-readme-md--f-001"' in body
    assert "Summary sub-demo" in body  # TOC uses page titles
    assert "Author: Junaid Ahmed" in body and "github.com/jahmed-cloud/ARG" in body


def test_export_pdf_with_fake_browser(tmp_path, monkeypatch):
    root = _report(tmp_path)
    monkeypatch.setattr(export, "find_browser", lambda explicit=None: "fake-browser")
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        target = next(a.split("=", 1)[1] for a in command if a.startswith("--print-to-pdf="))
        Path(target).write_bytes(b"%PDF-1.4 fake")
        return SimpleNamespace(returncode=0, stderr="")

    pdf = export.export_pdf(root, "summary", runner=fake_run)
    assert pdf.name == "report-summary.pdf" and pdf.read_bytes().startswith(b"%PDF")
    assert (root / "report-summary.html").is_file()
    assert "--headless=new" in seen["command"] and any(a.startswith("--user-data-dir=") for a in seen["command"])


def test_export_pdf_without_browser_keeps_printable_html(tmp_path, monkeypatch):
    root = _report(tmp_path)
    monkeypatch.setattr(export, "find_browser", lambda explicit=None: None)
    with pytest.raises(export.PdfExportError, match="Save as PDF"):
        export.export_pdf(root, "summary")
    assert (root / "report-summary.html").is_file()


def test_gather_limited_bounds_concurrency_and_keeps_order():
    state = {"now": 0, "peak": 0}

    async def work(i):
        state["now"] += 1
        state["peak"] = max(state["peak"], state["now"])
        await asyncio.sleep(0.01)
        state["now"] -= 1
        return i * 2

    result = asyncio.run(gather_limited(range(20), work, limit=3))
    assert result == [i * 2 for i in range(20)] and state["peak"] <= 3


def test_workload_count_prefers_project_over_application_tags():
    cls = ScannerRegistry.get("subscription_workload_sprawl_scanner")
    assert cls.workload_of({"projectName": "APPtimize", "Application": "APPtimizeClient"}) == "apptimize"
    assert cls.workload_of({"Application": "BOT"}) == "bot"
    finding = asyncio.run(cls().execute(ScanContext(subscription_id="sub-1", tenant_id="t", scan_job_id="j"))).findings[0]
    assert finding.evidence["workloads"] == ["apptimize", "bot", "machine-management", "twincat coagent"]


class _VaultArm:
    def __init__(self, items):
        self.items = items

    async def get_all(self, path, api_version, params=None):
        return self.items


@pytest.mark.parametrize("items, expected", [([{"name": "share1"}], 0), ([], 1)])
def test_backup_vault_with_protected_items_is_not_orphaned(items, expected):
    ctx = ScanContext(subscription_id="sub-1", tenant_id="t", scan_job_id="j")
    ctx.resource_graph_client = None  # mock vault rows
    ctx.arm_client = _VaultArm(items)
    output = asyncio.run(ScannerRegistry.get("orphaned_backup_vault_scanner")().execute(ctx))
    assert output.finding_count == expected
    if expected:
        assert output.findings[0].title.startswith("Empty vault")

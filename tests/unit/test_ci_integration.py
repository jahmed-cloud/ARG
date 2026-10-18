"""
CI/CD integration (severity gate, SARIF, JUnit, pipeline summaries) and the AI prompt - offline,
on hand-made report folders.
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from scripts.subscription_analysis import ci
from scripts.subscription_analysis.ai_prompt import build_prompt
from scripts.subscription_analysis.cli import main as cli_main

SUB_ID = "11111111-2222-3333-4444-555555555555"
OTHER_GUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _finding(ref, severity, ftype, name, saving=0.0, folder="cost-finops"):
    return {
        "ref": ref, "severity": severity, "finding_type": ftype, "category": "cost", "area": "Cost & FinOps",
        "folder": folder, "title": f"{ftype} on {name}", "description": f"Principal {OTHER_GUID} owns it.",
        "resource_id": f"/subscriptions/{SUB_ID}/resourcegroups/rg-app/providers/microsoft.compute/disks/{name}",
        "resource_name": name, "resource_group": "rg-app", "resource_type": "microsoft.compute/disks",
        "subscription_id": SUB_ID, "estimated_monthly_savings_usd": saving,
    }


FINDINGS = [
    _finding("F-001", "medium", "missing_tags", "disk-a"),
    _finding("F-002", "critical", "public_storage", "stpublic", folder="security-identity"),
    _finding("F-003", "high", "unattached_disk", "disk-b", saving=40.0),
    _finding("F-004", "high", "unattached_disk", "disk-c", saving=90.0),
    _finding("F-005", "low", "naming_convention", "disk-d"),
]


def make_report(root: Path, name="sub-demo", findings=FINDINGS) -> Path:
    folder = root / name
    (folder / "05-deep-dive" / "raw").mkdir(parents=True)
    (folder / "05-deep-dive" / "cost-finops").mkdir()
    (folder / "05-deep-dive" / "cost-finops" / "README.md").write_text("# Cost\n", encoding="utf-8")
    (folder / "README.md").write_text("# Demo\n", encoding="utf-8")
    sev = {s: sum(1 for f in findings if f["severity"] == s) for s in ci.SEVERITIES}
    (folder / "summary.json").write_text(json.dumps({
        "subscription": {"id": SUB_ID, "name": name, "tenant_id": OTHER_GUID, "state": "Enabled"},
        "generated_at": "2026-10-01T08:00:00+00:00", "resources": 12, "resource_groups": 2,
        "findings": len(findings), "findings_by_severity": sev, "currency": "CHF", "cost_30d": 1234.5,
        "savings_billing": {"wave_1": 100.0, "wave_2": 30.0},
    }), encoding="utf-8")
    (folder / "05-deep-dive" / "raw" / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    return folder


# ---- AI prompt -------------------------------------------------------------------------------

def test_prompt_masks_guids_consistently_and_ranks_by_severity_then_saving(tmp_path):
    report = ci.load_report(make_report(tmp_path))
    prompt = build_prompt(report["summary"], report["findings"])
    assert SUB_ID not in prompt and "<id-1>" in prompt
    assert build_prompt({}, [{"title": f"{OTHER_GUID} and {SUB_ID} then {OTHER_GUID.upper()}"}]).count("<id-1>") == 2
    assert "stpublic" in prompt and "rg-app" in prompt  # resource names stay: the analysis needs them
    order = [prompt.index(ref) for ref in ("F-002", "F-004", "F-003", "F-001", "F-005")]
    assert order == sorted(order)
    assert "Never recommend deleting" in prompt and "ARG (Azure Resource Guardian)" in prompt
    assert "\u2013" not in prompt and "\u2014" not in prompt  # generated text uses plain dashes


def test_prompt_filters_truncates_and_can_keep_ids(tmp_path):
    report = ci.load_report(make_report(tmp_path))
    prompt = build_prompt(report["summary"], report["findings"], max_findings=2, min_severity="high")
    assert "F-002" in prompt and "F-004" in prompt and "F-003" not in prompt.split("most severe first")[1]
    assert "1 more findings are not listed" in prompt
    assert "F-001" not in prompt  # medium is below the floor
    assert SUB_ID in build_prompt(report["summary"], report["findings"], mask_ids=False)
    capped = build_prompt(report["summary"], report["findings"], per_type=1).split("most severe first")[1]
    assert "F-004" in capped and "F-003" not in capped  # one per type: the bigger saving wins
    assert "wave 1 (no-regret) 100 CHF" in build_prompt(report["summary"], [])
    assert "wave 1 (no-regret) 0 CHF" in build_prompt({"savings_billing": {"wave_1": 0.0, "wave_2": 0.0}, "currency": "CHF"}, [])


def test_prompt_handles_docker_api_findings_without_ref_or_area():
    prompt = build_prompt({"subscription": {"name": "x"}}, [
        {"severity": "high", "finding_type": "t", "category": "network", "title": "a | b\nc", "resource_name": "r"}])
    assert "| #1 | high | network | t | r |" in prompt and "a / b c" in prompt


# ---- gate and artefacts ----------------------------------------------------------------------

def test_gate_counts_findings_at_or_above_threshold_minus_ignored_types(tmp_path):
    reports = [ci.load_report(make_report(tmp_path))]
    assert len(ci.blocking(reports[0]["findings"], "high")) == 3
    assert len(ci.blocking(reports[0]["findings"], "high", ["unattached_disk"])) == 1
    assert ci.blocking(reports[0]["findings"], None) == []
    result = ci.ci_summary(reports, "critical")
    assert result["blocking"] == 1 and not result["passed"]
    assert result["subscriptions"][0]["blocking_findings"][0]["ref"] == "F-002"
    assert ci.ci_summary(reports, "critical", ["public_storage"])["passed"]
    assert not ci.ci_summary(reports, None, failures=["sub-x"])["passed"]


def test_sarif_has_one_rule_per_type_stable_fingerprints_and_report_locations(tmp_path):
    reports = [ci.load_report(make_report(tmp_path))]
    sarif = ci.to_sarif(reports, base=tmp_path)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "ARG"
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert set(rules) == {f["finding_type"] for f in FINDINGS}
    assert rules["public_storage"]["defaultConfiguration"]["level"] == "error"
    assert rules["public_storage"]["properties"]["security-severity"] == "9.5"
    levels = {r["properties"]["ref"]: r["level"] for r in run["results"]}
    assert levels == {"F-001": "warning", "F-002": "error", "F-003": "error", "F-004": "error", "F-005": "note"}
    by_ref = {r["properties"]["ref"]: r for r in run["results"]}
    assert by_ref["F-003"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == \
        "sub-demo/05-deep-dive/cost-finops/README.md"
    assert by_ref["F-002"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "sub-demo/README.md"
    again = ci.to_sarif(reports, base=tmp_path)["runs"][0]["results"]
    assert [r["partialFingerprints"] for r in again] == [r["partialFingerprints"] for r in run["results"]]


def test_junit_fails_only_blocking_finding_types(tmp_path):
    reports = [ci.load_report(make_report(tmp_path))]
    root = ET.fromstring(ci.to_junit(reports, "high"))
    suite = root.find("testsuite")
    cases = {c.get("name").split(" ")[0]: c for c in suite.findall("testcase")}
    assert root.get("tests") == "4" and root.get("failures") == "2"
    assert cases["unattached_disk"].find("failure") is not None
    assert "F-004" in cases["unattached_disk"].find("failure").text
    assert cases["missing_tags"].find("failure") is None
    assert ET.fromstring(ci.to_junit(reports, None)).get("failures") == "0"


def test_pipeline_output_for_github_and_azure_devops(tmp_path):
    result = ci.ci_summary([ci.load_report(make_report(tmp_path))], "high")
    lines, summary = [], tmp_path / "step-summary.md"
    ci.emit_pipeline_output(result, env={"GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": str(summary)}, out=lines.append)
    assert any(line.startswith("::error title=ARG public_storage::") for line in lines)
    assert "Gate **FAILED**" in summary.read_text(encoding="utf-8")
    lines = []
    ci.emit_pipeline_output(result, env={"TF_BUILD": "True"}, summary_dir=tmp_path, out=lines.append)
    assert any(line.startswith("##vso[task.logissue type=error]") for line in lines)
    assert lines[-1].startswith("##vso[task.uploadsummary]") and (tmp_path / "arg-summary.md").is_file()
    lines = []
    ci.emit_pipeline_output(result, env={}, out=lines.append)
    assert lines == []


def test_cli_gate_only_exit_codes_and_artefacts(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("TF_BUILD", raising=False)
    make_report(tmp_path / "reports")
    out = tmp_path / "out"
    args = ["--reports-dir", str(tmp_path / "reports"), "--gate-only", "-s", SUB_ID]
    code = cli_main(args + ["--fail-on", "high", "--sarif", str(out / "b.sarif"), "--junit", str(out / "b.xml"),
                            "--ci-json", str(out / "b.json")])
    assert code == ci.GATE_EXIT_CODE
    assert json.loads((out / "b.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert json.loads((out / "b.json").read_text(encoding="utf-8"))["blocking"] == 3
    assert ET.parse(out / "b.xml").getroot().get("failures") == "2"
    assert cli_main(args + ["--fail-on", "critical", "--gate-ignore", "public_storage"]) == 0
    assert cli_main(args) == 0  # no gate configured
    with pytest.raises(SystemExit):
        cli_main(["--reports-dir", str(tmp_path / "reports"), "--gate-only", "-s", "unknown-sub"])

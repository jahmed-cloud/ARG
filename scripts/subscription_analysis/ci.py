"""
CI/CD integration for the subscription analysis: a severity gate plus machine-readable output.

    python -m scripts.subscription_analysis -s <sub> --fail-on high --sarif arg.sarif --junit arg.xml

- Gate: findings at or above --fail-on (minus --gate-ignore types) make the run exit with GATE_EXIT_CODE.
- SARIF 2.1.0 (GitHub code scanning, Azure DevOps SARIF viewer), JUnit XML (Azure DevOps "Publish Test
  Results", GitHub test reporters) and a compact JSON summary.
- Pipeline summaries: GitHub Actions ($GITHUB_STEP_SUMMARY, ::error annotations) and Azure DevOps
  (##vso logissue / uploadsummary) are detected from their environment variables.

Pure functions over report folders (summary.json + 05-deep-dive/raw/findings.json), so the Docker API and
--gate-only (no Azure calls) reuse them. Output contains resource IDs: treat it like the reports.
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from xml.sax.saxutils import escape, quoteattr

SEVERITIES = ["critical", "high", "medium", "low", "info"]
GATE_EXIT_CODE = 2
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
FINDINGS_FILE = Path("05-deep-dive") / "raw" / "findings.json"
TOOL_URI = "https://github.com/jahmed-cloud/ARG"


def sev_rank(severity: Optional[str]) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def parse_types(value: Optional[str]) -> List[str]:
    return [t.strip() for t in (value or "").split(",") if t.strip()]


def load_report(folder: Path) -> Dict[str, Any]:
    """One analysed subscription: {'folder', 'summary', 'findings'} from a report folder."""
    folder = Path(folder)
    summary = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
    path = folder / FINDINGS_FILE
    findings = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []
    return {"folder": folder, "summary": summary, "findings": findings}


def blocking(findings: Iterable[Dict[str, Any]], fail_on: Optional[str],
             ignore: Iterable[str] = ()) -> List[Dict[str, Any]]:
    """Findings that fail the gate: severity at or above fail_on, finding type not ignored."""
    if fail_on not in SEVERITIES:
        return []
    ignored = {t.lower() for t in ignore}
    limit = sev_rank(fail_on)
    return [f for f in findings
            if sev_rank(f.get("severity")) <= limit and str(f.get("finding_type") or "").lower() not in ignored]


def _brief(f: Dict[str, Any]) -> Dict[str, Any]:
    return {k: f.get(k) for k in ("ref", "severity", "finding_type", "title", "resource_name", "resource_group",
                                  "resource_id", "estimated_monthly_savings_usd")}


def ci_summary(reports: List[Dict[str, Any]], fail_on: Optional[str] = None, ignore: Iterable[str] = (),
               failures: Iterable[str] = ()) -> Dict[str, Any]:
    """Gate result for every analysed subscription; `failures` are subscriptions whose analysis failed."""
    ignore = list(ignore)
    subs, total_blocking = [], 0
    for r in reports:
        s = r["summary"]
        sub = s.get("subscription") or {}
        block = blocking(r["findings"], fail_on, ignore)
        total_blocking += len(block)
        subs.append({
            "name": sub.get("name"), "id": sub.get("id"), "folder": str(r["folder"]),
            "generated_at": s.get("generated_at"), "resources": s.get("resources"), "findings": s.get("findings"),
            "findings_by_severity": s.get("findings_by_severity") or {}, "currency": s.get("currency"),
            "cost_30d": s.get("cost_30d"), "savings_billing": s.get("savings_billing") or {},
            "blocking": len(block), "blocking_findings": [_brief(f) for f in block[:50]],
        })
    failures = list(failures)
    return {
        "tool": "ARG", "fail_on": fail_on, "gate_ignore": ignore,
        "passed": total_blocking == 0 and not failures,
        "blocking": total_blocking, "analysis_failures": failures, "subscriptions": subs,
    }


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------

def _fingerprint(f: Dict[str, Any]) -> str:
    key = f"{(f.get('resource_id') or f.get('subscription_id') or '').lower()}|{f.get('finding_type')}"
    return hashlib.sha256(key.encode()).hexdigest()


def _report_page(folder: Path, f: Dict[str, Any]) -> Path:
    page = folder / "05-deep-dive" / str(f.get("folder") or "") / "README.md"
    return page if f.get("folder") and page.is_file() else folder / "README.md"


def _uri(path: Path, base: Optional[Path]) -> str:
    try:
        return path.resolve().relative_to((base or Path.cwd()).resolve()).as_posix()
    except ValueError:
        return path.resolve().as_uri()


def to_sarif(reports: List[Dict[str, Any]], base: Optional[Path] = None) -> Dict[str, Any]:
    """
    One run, one rule per finding type, one result per finding. Azure resources have no source file, so
    the location points at the report page of the finding; the resource ID is the logical location and
    the fingerprint (resource + finding type) keeps alerts stable across runs.
    """
    rules: Dict[str, Dict[str, Any]] = {}
    results = []
    for r in reports:
        for f in r["findings"]:
            ftype = str(f.get("finding_type") or "unknown")
            severity = f.get("severity") or "info"
            rule = rules.setdefault(ftype, {
                "id": ftype, "name": "".join(p.title() for p in ftype.split("_")),
                "shortDescription": {"text": ftype.replace("_", " ")},
                "properties": {"tags": [t for t in (f.get("category"), f.get("area")) if t], "severity": severity},
            })
            if sev_rank(severity) < sev_rank(rule["properties"]["severity"]):
                rule["properties"]["severity"] = severity
            text = f.get("title") or ftype
            if f.get("description"):
                text = f"{text}. {f['description']}"
            if f.get("estimated_monthly_savings_usd"):
                text += f" Estimated saving: USD {float(f['estimated_monthly_savings_usd']):,.0f}/month."
            result = {
                "ruleId": ftype, "level": SARIF_LEVEL.get(severity, "note"), "message": {"text": text[:4000]},
                "locations": [{
                    "physicalLocation": {"artifactLocation": {"uri": _uri(_report_page(r["folder"], f), base)},
                                         "region": {"startLine": 1}},
                    "logicalLocations": [{"fullyQualifiedName": f.get("resource_id") or f.get("subscription_id") or "",
                                          "name": f.get("resource_name") or "", "kind": "resource"}],
                }],
                "partialFingerprints": {"bArgFinding/v1": _fingerprint(f)},
                "properties": {k: v for k, v in {
                    "ref": f.get("ref"), "severity": severity, "resourceGroup": f.get("resource_group"),
                    "resourceType": f.get("resource_type"), "subscriptionId": f.get("subscription_id"),
                    "estimatedMonthlySavingsUsd": f.get("estimated_monthly_savings_usd"),
                    "remediation": f.get("remediation_steps"),
                }.items() if v not in (None, "")},
            }
            results.append(result)
    for rule in rules.values():
        sev = rule["properties"]["severity"]
        rule["defaultConfiguration"] = {"level": SARIF_LEVEL.get(sev, "note")}
        rule["properties"]["security-severity"] = SECURITY_SEVERITY.get(sev, "0.0")
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "ARG", "fullName": "ARG - Azure Resource Guardian",
                                      "informationUri": TOOL_URI, "rules": sorted(rules.values(), key=lambda x: x["id"])}},
                  "results": results}],
    }


# ---------------------------------------------------------------------------
# JUnit XML
# ---------------------------------------------------------------------------

def to_junit(reports: List[Dict[str, Any]], fail_on: Optional[str] = None, ignore: Iterable[str] = ()) -> str:
    """One test suite per subscription, one test case per finding type; blocking types fail."""
    ignore = list(ignore)
    suites, total_tests, total_failures = [], 0, 0
    for r in reports:
        sub = r["summary"].get("subscription") or {}
        name = sub.get("name") or r["folder"].name
        block_ids = {id(f) for f in blocking(r["findings"], fail_on, ignore)}
        by_type: Dict[str, List[Dict[str, Any]]] = {}
        for f in r["findings"]:
            by_type.setdefault(str(f.get("finding_type") or "unknown"), []).append(f)
        cases = []
        for ftype in sorted(by_type):
            items = by_type[ftype]
            failed = [f for f in items if id(f) in block_ids]
            worst = min((f.get("severity") or "info" for f in items), key=sev_rank)
            case = f'    <testcase classname={quoteattr("arg." + name)} name={quoteattr(f"{ftype} ({len(items)} x {worst})")}'
            if failed:
                lines = "\n".join(f"{f.get('ref') or '-'} [{f.get('severity')}] {f.get('resource_name') or '-'}: "
                                  f"{f.get('title') or ''}" for f in failed[:200])
                case += (f">\n      <failure message={quoteattr(f'{len(failed)} finding(s) at or above {fail_on}')} "
                         f"type={quoteattr(worst)}>{escape(lines)}</failure>\n    </testcase>")
            else:
                case += " />"
            cases.append(case)
        if not cases:
            cases.append(f'    <testcase classname={quoteattr("arg." + name)} name="no findings" />')
        failures = sum(1 for c in cases if "<failure" in c)
        total_tests += len(cases)
        total_failures += failures
        suites.append(f'  <testsuite name={quoteattr(f"ARG {name}")} tests="{len(cases)}" failures="{failures}" '
                      f'errors="0" skipped="0" timestamp={quoteattr(str(r["summary"].get("generated_at") or ""))}>\n'
                      + "\n".join(cases) + "\n  </testsuite>")
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuites name="ARG" tests="{total_tests}" failures="{total_failures}">\n'
            + "\n".join(suites) + "\n</testsuites>\n")


# ---------------------------------------------------------------------------
# Pipeline summaries and annotations
# ---------------------------------------------------------------------------

def summary_markdown(result: Dict[str, Any]) -> str:
    gate = (f"Gate **{'passed' if result['passed'] else 'FAILED'}** - fail on {result['fail_on']} and above, "
            f"{result['blocking']} blocking finding(s)." if result.get("fail_on")
            else "No gate configured (use --fail-on).")
    lines = ["## ARG analysis", "", gate, "",
             "| Subscription | Critical | High | Medium | Low | Blocking | Last 30 days | Est. savings / month |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for s in result["subscriptions"]:
        sev = s["findings_by_severity"]
        sav = s["savings_billing"]
        total = (sav.get("wave_1") or 0) + (sav.get("wave_2") or 0)
        cur = s.get("currency") or ""
        lines.append(f"| {s['name']} | {sev.get('critical', 0)} | {sev.get('high', 0)} | {sev.get('medium', 0)} | "
                     f"{sev.get('low', 0)} | {s['blocking']} | {(s.get('cost_30d') or 0):,.0f} {cur} | {total:,.0f} {cur} |")
    for name in result.get("analysis_failures") or []:
        lines.append(f"| {name} | - | - | - | - | analysis failed | - | - |")
    return "\n".join(lines) + "\n"


def emit_pipeline_output(result: Dict[str, Any], env: Optional[Dict[str, str]] = None,
                         summary_dir: Optional[Path] = None, out=print) -> None:
    """GitHub Actions / Azure DevOps annotations and job summary (no-op on other systems)."""
    env = os.environ if env is None else env
    github = bool(env.get("GITHUB_ACTIONS"))
    devops = bool(env.get("TF_BUILD"))
    if not (github or devops):
        return
    for s in result["subscriptions"]:
        for f in s["blocking_findings"][:20]:
            message = f"ARG {s['name']}: {f.get('ref') or ''} [{f.get('severity')}] {f.get('title') or ''}"
            message = " ".join(message.split())
            out(f"::error title=ARG {f.get('finding_type')}::{message}" if github
                else f"##vso[task.logissue type=error]{message}")
    markdown = summary_markdown(result)
    if github and env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(markdown)
    if devops:
        target = Path(summary_dir or env.get("AGENT_TEMPDIRECTORY") or ".") / "arg-summary.md"
        target.write_text(markdown, encoding="utf-8")
        out(f"##vso[task.uploadsummary]{target.resolve()}")


def write_outputs(result: Dict[str, Any], reports: List[Dict[str, Any]], *, ci_json: Optional[str] = None,
                  sarif: Optional[str] = None, junit: Optional[str] = None) -> List[Path]:
    written = []
    for path, content in ((ci_json, lambda: json.dumps(result, indent=2, default=str)),
                          (sarif, lambda: json.dumps(to_sarif(reports), indent=2, default=str)),
                          (junit, lambda: to_junit(reports, result.get("fail_on"), result.get("gate_ignore") or []))):
        if path:
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content(), encoding="utf-8")
            written.append(target)
    return written

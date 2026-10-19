"""
Docker worker: open findings a clean scanner run no longer reports are resolved - or suppressed with the reason when
a setting (a switched-off check, an excluded Defender plan recommendation) removed them rather than a fix.
"""

from types import SimpleNamespace

import pytest

pytest.importorskip("celery")

from backend.models.models import FindingStatus  # noqa: E402
from scanners.base.base_scanner import ScannerRegistry, ScanOutput  # noqa: E402
from workers import scan_worker  # noqa: E402


class FakeDb:
    def __init__(self, rows):
        self.rows, self.commits, self.queries = rows, 0, []

    def execute(self, query):
        self.queries.append(str(query))
        rows = self.rows

        class Result:
            def scalars(self):
                return self

            def all(self):
                return rows

        return Result()

    def commit(self):
        self.commits += 1


def stale(**evidence):
    return SimpleNamespace(status=FindingStatus.OPEN, resolved_at=None, suppression_reason=None, evidence=evidence)


SUB = SimpleNamespace(id="sub-row-1")


def test_switched_off_check_suppresses_its_findings_with_the_reason():
    rows = [stale(), stale()]
    scanner = ScannerRegistry.get("naming_convention_scanner")(config={"naming_convention_enabled": False})
    out = ScanOutput(metadata={"disabled_by_setting": "naming_convention_enabled"})
    assert scan_worker._retire_undetected_findings(FakeDb(rows), scanner, out, SUB, "job-2") == 2
    assert all(r.status == FindingStatus.SUPPRESSED for r in rows)
    assert rows[0].suppression_reason == "Check switched off in Settings (naming_convention_enabled)"


def test_defender_plan_only_findings_are_suppressed_and_fixed_ones_resolved():
    plan_only = stale(assessments=[{"assessment": "Microsoft Defender CSPM should be enabled"}])
    fixed = stale(assessments=[{"assessment": "Storage accounts should prevent shared key access"}])
    db = FakeDb([plan_only, fixed])
    scanner = ScannerRegistry.get("defender_recommendations_scanner")(config={})
    scan_worker._retire_undetected_findings(db, scanner, ScanOutput(), SUB, "job-2")
    assert plan_only.status == FindingStatus.SUPPRESSED and "defender_plan_recommendations" in plan_only.suppression_reason
    assert fixed.status == FindingStatus.RESOLVED and fixed.resolved_at is not None
    assert db.commits == 1 and "findings.finding_type IN" in db.queries[0]


def test_nothing_is_closed_after_a_run_with_warnings():
    rows = [stale()]
    for name in ("defender_recommendations_scanner", "unattached_disk_scanner"):
        scanner = ScannerRegistry.get(name)(config={})
        assert scan_worker._retire_undetected_findings(FakeDb(rows), scanner, ScanOutput(warnings=["ARG failed"]),
                                                       SUB, "job-2") == 0
    assert rows[0].status == FindingStatus.OPEN


def test_scanner_without_declared_types_closes_its_fixed_findings():
    """The types come from the scanner's source - a fixed issue no longer lingers in the UI."""
    rows = [stale()]
    db = FakeDb(rows)
    plain = ScannerRegistry.get("storage_access_hardening_scanner")(config={})
    assert plain.emitted_finding_types() == {"storage_shared_key_access_enabled", "storage_public_network_access",
                                             "storage_blob_soft_delete_disabled"}
    assert scan_worker._retire_undetected_findings(db, plain, ScanOutput(), SUB, "job-2") == 1
    assert rows[0].status == FindingStatus.RESOLVED and db.commits == 1


def test_every_scanner_knows_its_finding_types():
    """A scanner whose types cannot be found would never close a fixed finding."""
    import scripts.subscription_analysis.collector as collector

    collector.load_scanners()
    unknown = [name for name, cls in ScannerRegistry.all().items()
               if not cls.emitted_finding_types() and not cls.requires_graph and name != "terraform_drift_scanner"]
    assert unknown == []

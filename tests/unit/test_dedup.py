"""One finding per issue: stable fingerprints, folding into 'remove it' findings, one finding per app."""

from datetime import datetime, timedelta, timezone

from scanners.base.base_scanner import ScannerFinding, SeverityLevel
from scanners.base.fingerprint import finding_fingerprint, is_tenant_wide
from scanners.identity.identity_scanners import ExpiredAppCredentialScanner
from scripts.subscription_analysis.correlate import correlate

RID = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/old"


def finding(ftype, rid=RID, severity="low", **extra):
    return {"finding_type": ftype, "resource_id": rid, "severity": severity, "title": ftype, "evidence": {}, **extra}


def test_fingerprint_ignores_resource_id_casing_and_trailing_slash():
    a = finding_fingerprint(finding("missing_required_tags"))
    assert a == finding_fingerprint(finding("missing_required_tags", RID.upper() + "/"))
    assert a != finding_fingerprint(finding("naming_convention_violation"))


def test_entra_finding_is_tenant_wide_and_the_same_in_every_subscription():
    f = ScannerFinding(finding_type="mfa_not_enabled", title="t", description="d", severity=SeverityLevel.HIGH,
                       category="identity", entra_object_id="USER-1")
    assert is_tenant_wide(f)
    assert finding_fingerprint(f, subscription_id="sub-a", tenant_id="t1") == \
        finding_fingerprint(f, subscription_id="sub-b", tenant_id="t1")
    assert finding_fingerprint(f, tenant_id="t1") != finding_fingerprint(f, tenant_id="t2")


def test_findings_on_a_resource_to_remove_are_folded_and_the_urgency_kept():
    kept, stats = correlate([finding("unused_storage_account", severity="medium"),
                             finding("missing_required_tags", RID.lower()),
                             finding("public_storage_account", severity="critical"),
                             finding("missing_required_tags", RID + "2")])
    assert [(k["finding_type"], k["severity"]) for k in kept] == [("unused_storage_account", "critical"),
                                                                  ("missing_required_tags", "low")]
    assert stats["covered_by_decommission"] == 2
    assert [c["finding_type"] for c in kept[0]["evidence"]["covers"]] == ["missing_required_tags",
                                                                         "public_storage_account"]


def test_nothing_is_folded_when_the_removal_was_dismissed_or_for_terraform_drift():
    items = [finding("unused_storage_account"), finding("missing_required_tags")]
    assert len(correlate(items, keep_separate=[RID])[0]) == 2
    kept, _ = correlate([finding("unused_storage_account"), finding("terraform_unmanaged_resource")])
    assert len(kept) == 2


def test_an_app_with_several_expired_secrets_is_one_finding():
    scanner = ExpiredAppCredentialScanner()
    now = datetime.now(timezone.utc)
    due = scanner._due([{"endDateTime": (now - timedelta(days=40)).isoformat(), "displayName": "old"},
                        {"endDateTime": (now + timedelta(days=5)).isoformat(), "displayName": "soon"},
                        {"endDateTime": (now + timedelta(days=300)).isoformat(), "displayName": "fine"},
                        {"endDateTime": "None"}], now)
    assert [c["name"] for c in due] == ["old", "soon"]
    assert scanner._headline(due, "App secret", "app secrets") == "2 app secrets expired or expiring (1 expired)"
    assert scanner._summary(due, "client secret") == "1 expired client secret and 1 client secret expiring soon"

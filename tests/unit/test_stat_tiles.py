"""A stat tile that counts a finding type no scanner emits always shows 0 - which reads as 'nothing wrong'."""

import scripts.subscription_analysis.collector as collector
from backend.api.routes import governance, identity, security
from scanners.base.base_scanner import ScannerRegistry


def test_every_tile_counts_finding_types_a_scanner_emits():
    collector.load_scanners()
    emitted = {t for cls in ScannerRegistry.all().values() for t in cls.emitted_finding_types()}
    tiles = (security.PUBLIC_EXPOSURE_TYPES + security.DATA_PROTECTION_TYPES + security.UNSUPPORTED_TYPES
             + governance.POLICY_FINDING_TYPES + governance.MONITORING_TYPES + governance.TAG_QUALITY_TYPES
             + identity.EXPIRED_CREDENTIAL_TYPES + identity.STANDING_ACCESS_TYPES
             + ("guest_never_signed_in", "dormant_member_user", "mfa_not_enabled", "permanent_global_admin",
                "defender_plan_disabled", "missing_diagnostic_settings", "missing_required_tags",
                "naming_convention_violation", "missing_resource_lock"))
    assert sorted(set(tiles) - emitted) == []

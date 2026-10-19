"""
Implementation analysis per finding (scripts/subscription_analysis/guidance.py): every finding type explains why it
is needed, when it is not, what implementing it costs and where to read more; settings shared by CLI, portal and
Docker (scripts/subscription_analysis/settings.py).
"""

import json

import pytest

from scanners.base.guidance import html_links, html_to_text, portal_link
from scanners.security import defender_guidance
from scripts.subscription_analysis import settings
from scripts.subscription_analysis.guidance import GUIDANCE, cost_summary, implementation_analysis
from scripts.subscription_analysis.knowledge import FINDING_CLASSIFICATION

IDENTITY_TYPES = {"dormant_member_user", "guest_never_signed_in", "mfa_not_enabled", "permanent_global_admin",
                  "expired_app_secret", "expired_app_certificate"}


@pytest.mark.parametrize("ftype", sorted(set(FINDING_CLASSIFICATION) | IDENTITY_TYPES))
def test_every_finding_type_has_specific_guidance_with_references(ftype):
    g = GUIDANCE.get(ftype)
    assert g is not None, f"no guidance for {ftype}"
    assert g.why and g.skip_when and g.effort and g.run_cost
    assert 0 < g.hours[0] <= g.hours[1]
    assert g.references and all(url.startswith("https://") for _, url in g.references)


def test_defender_catalogue_entries_are_complete():
    for _, entry in defender_guidance._CATALOGUE:
        g = entry.guidance
        assert g.why and g.skip_when and g.effort and g.references and entry.steps, entry.key
        assert all(url.startswith("https://") for _, url in g.references)


def test_defender_catalogue_matches_the_estate_recommendations():
    cases = {
        "Linux virtual machines should enable Azure Disk Encryption or EncryptionAtHost.": "encryption_at_host",
        "Windows virtual machines should enable Azure Disk Encryption or EncryptionAtHost.": "encryption_at_host",
        "Virtual machines and virtual machine scale sets should have encryption at host enabled": "encryption_at_host",
        "Machines should be configured to periodically check for missing system updates": "periodic_assessment",
        "Guest accounts with read permissions on Azure resources should be removed": "guest_rbac",
        "Storage accounts should prevent shared key access": "storage_shared_key",
        "Microsoft Foundry resources should have key access disabled (disable local authentication)": "ai_local_auth",
        "Virtual networks should be protected by Azure Firewall": "azure_firewall",
        "Update openssl": "system_updates",
    }
    for name, key in cases.items():
        entry = defender_guidance.match(name)
        assert entry is not None and entry.key == key, name


def test_cli_template_is_filled_for_the_resource_type():
    entry = defender_guidance.by_key("encryption_at_host")
    vm = "/subscriptions/s1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1"
    script = defender_guidance.cli_for(entry, vm, "s1")
    assert "az vm deallocate -g rg-1 -n vm-1" in script and "--subscription s1" in script
    assert defender_guidance.cli_for(entry, "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/a",
                                     "s1") is None


def test_defender_finding_combines_curated_and_microsoft_guidance():
    finding = {"finding_type": "defender_recommendations", "evidence": {"assessments": [
        {"label": "Linux virtual machines should enable Azure Disk Encryption or EncryptionAtHost.",
         "assessment": "Linux virtual machines should enable Azure Disk Encryption or EncryptionAtHost.",
         "guidance_key": "encryption_at_host", "portal": "https://portal.azure.com/#blade/x"},
        {"label": "Some brand-new recommendation", "assessment": "Some brand-new recommendation", "effort": "Moderate",
         "ms_description": "Why Microsoft thinks it matters.",
         "ms_links": [["Docs", "https://learn.microsoft.com/azure/new-thing"]]},
    ]}}
    a = implementation_analysis(finding)
    assert a["source"] == "defender" and len(a["items"]) == 2
    assert "temporary (resource) disk" in a["why"] and "Why Microsoft thinks it matters." in a["why"]
    assert a["hours"] == [1.5, 5.0]                    # 0.5-1 curated + 1-4 for Microsoft's "Moderate"
    assert a["partial_cost"] is True and a["monthly_usd"] is None
    urls = [r["url"] for r in a["references"]]
    assert "https://learn.microsoft.com/azure/virtual-machines/disk-encryption-migrate" in urls
    assert "https://learn.microsoft.com/azure/new-thing" in urls and "https://portal.azure.com/#blade/x" in urls


def test_net_effect_subtracts_run_cost_unless_the_saving_is_already_net():
    free = implementation_analysis({"finding_type": "storage_public_network_access", "evidence": {}})
    assert free["monthly_usd"] == 0.0                                  # the control is chosen per resource
    pe = implementation_analysis({"finding_type": "storage_public_network_access", "evidence": {
        "cost_of_change": {"monthly_usd": 7.80, "basis": "private endpoint + private dns"},
        "access_decision": {"option": "private_endpoint", "title": "Private endpoint + private DNS", "hours": [1, 4],
                            "why": "tagged DataClassification=Confidential", "monthly_usd": 7.80, "alternatives": [{"option": "x"}]}}})
    assert pe["monthly_usd"] == pytest.approx(7.80) and pe["net_monthly_usd"] is None
    assert pe["decision"]["option"] == "private_endpoint" and pe["options"] == [{"option": "x"}] and pe["hours"] == [1, 4]
    gateway = implementation_analysis({"finding_type": "ai_spend_without_gateway", "estimated_monthly_savings_usd": 189.57,
                                       "evidence": {"cost_of_change": {"monthly_usd": 140.43, "included_in_saving": True,
                                                                       "basis": "APIM"}}})
    assert gateway["monthly_usd"] == 140.43 and gateway["net_monthly_usd"] == 189.57
    assert "(in saving)" in cost_summary(gateway)
    plans = implementation_analysis({"finding_type": "defender_plan_disabled", "estimated_monthly_savings_usd": 0,
                                     "evidence": {"cost_of_change": {"monthly_usd": 185.0, "basis": "plans"}}})
    assert plans["monthly_usd"] == 185.0 and plans["run_cost"].startswith("About USD 185.00/month")


def test_cost_factor_uses_the_resource_cost_and_hourly_rate_gives_a_one_off_amount():
    a = implementation_analysis({"finding_type": "app_service_plan_single_instance", "evidence": {}},
                                resource_monthly_usd=120.0, hourly_rate_usd=100)
    assert a["monthly_usd"] == 120.0 and "about USD 120.00/month" in a["run_cost"]
    assert a["one_off_usd"] == [25, 50]
    assert cost_summary(a) == ("+USD 120.00/month · 1 SP (4h / 0.5 days / 0.03 sprints) (generic estimate) "
                               "(≈ USD 25-50)")
    unknown = implementation_analysis({"finding_type": "app_service_plan_single_instance", "evidence": {}})
    assert unknown["monthly_usd"] is None and cost_summary(unknown).startswith("run cost: usage-based")


def test_html_helpers_keep_text_and_documentation_links_only():
    raw = ('Disks are encrypted.<br>See <a target="_blank" href="https://learn.microsoft.com/x">the docs</a> or '
           '<a href="https://portal.azure.com/#blade/abc">clicking here</a>.<ol><li>One</li><li>Two</li></ol>')
    text = html_to_text(raw)
    assert "Disks are encrypted." in text and "- One" in text and "<" not in text
    assert html_links(raw) == [("the docs", "https://learn.microsoft.com/x")]
    assert portal_link("portal.azure.com/#blade/x") == "https://portal.azure.com/#blade/x"


def test_settings_normalize_load_save_and_cli_config(tmp_path):
    clean = settings.normalize({"naming_convention_enabled": "off", "blocked_resource_providers": "A, b\nA",
                                "engineering_hourly_rate_usd": "120", "ai_gateway_sku": "Gold", "unknown": 1})
    assert clean == {"naming_convention_enabled": False, "blocked_resource_providers": ["A", "b"],
                     "engineering_hourly_rate_usd": 120.0}
    settings.save(tmp_path, {"naming_convention_enabled": False})
    assert json.loads((tmp_path / settings.SETTINGS_FILE).read_text()) == {"naming_convention_enabled": False}
    assert settings.effective(tmp_path)["defender_plan_recommendations"] is False

    from scripts.subscription_analysis.cli import default_config

    config = default_config(reports_dir=tmp_path)
    assert config["naming_convention_enabled"] is False and config["defender_plan_coverage"] is False
    override = tmp_path / "override.json"
    override.write_text(json.dumps({"naming_convention_enabled": True}))
    assert default_config(str(override), tmp_path)["naming_convention_enabled"] is True

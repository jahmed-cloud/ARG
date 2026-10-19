"""Network topology (network.py), its diagrams (network_diagram.py), the VM power-state highlight, the estate
telemetry (telemetry.py / telemetry_svg.py) and the routes that serve them."""
import copy

import pytest

from scripts.subscription_analysis import diagram, network_diagram
from scripts.subscription_analysis.network import (
    APP_PUBLIC, CLOSED, OPEN, PRIVATE, RESTRICTED, UNVERIFIED, build_network, default_route, exposure, subnet_ids,
)
from scripts.subscription_analysis.telemetry import estate_telemetry, utilisation_band
from scripts.subscription_analysis.telemetry_svg import telemetry_html
from test_architecture import SUB_A, SUB_B, _docker_client, _snapshot, estate

VNET_HUB = f"/subscriptions/{SUB_A}/resourcegroups/rg-net/providers/microsoft.network/virtualnetworks/hub"
VNET_SPOKE = f"/subscriptions/{SUB_B}/resourcegroups/rg-app/providers/microsoft.network/virtualnetworks/spoke"
SNET_APP = VNET_SPOKE + "/subnets/snet-app"
SNET_PE = VNET_SPOKE + "/subnets/snet-pe"
VM = f"/subscriptions/{SUB_B}/resourcegroups/rg-app/providers/microsoft.compute/virtualmachines/vm-1"
STORAGE = f"/subscriptions/{SUB_B}/resourcegroups/rg-app/providers/microsoft.storage/storageaccounts/stapp"
APP = f"/subscriptions/{SUB_B}/resourcegroups/rg-app/providers/microsoft.web/sites/app-1"


def network_estate():
    data = copy.deepcopy(estate())
    data["resources"][2]["state"] = "deallocated"       # vm-1
    data["resources"].append({"id": VM.replace("vm-1", "vm-2"), "name": "vm-2", "s": 1, "rg": "rg-app",
                              "type": "microsoft.compute/virtualmachines", "state": "stopped", "cpu95": 1.0})
    arch = data["architecture"]
    hub = arch["vnets"][0]
    hub["subnet_list"] = [{"id": VNET_HUB + "/subnets/gatewaysubnet", "name": "GatewaySubnet", "prefix": "10.0.0.0/27"}]
    arch["vnets"].append({"id": VNET_SPOKE, "name": "spoke", "subscriptionId": SUB_B, "resourceGroup": "rg-app",
                          "location": "westeurope", "space": ["10.1.0.0/16"],
                          "subnet_list": [{"id": SNET_APP, "name": "snet-app", "prefix": "10.1.0.0/24", "nsg": None},
                                          {"id": SNET_PE, "name": "snet-pe", "prefix": "10.1.1.0/24", "nsg": None}],
                          "peerings": [{"remote": VNET_HUB, "state": "Connected", "remote_gateways": True}]})
    arch["vnets"].append({"id": VNET_SPOKE.replace("spoke", "lonely"), "name": "lonely", "subscriptionId": SUB_B,
                          "location": "westeurope", "space": ["10.1.0.0/16"], "subnet_list": [], "peerings": []})
    arch["network"] = build_network(
        [{"id": "pe-1", "name": "pe-st", "subscriptionId": SUB_B, "subnet": SNET_PE, "target": STORAGE,
          "group_id": "blob"}],
        [{"vm": VM, "subscriptionId": SUB_B, "subnet": SNET_APP, "public_ip": True},
         {"vm": VM.replace("vm-1", "vm-2"), "subscriptionId": SUB_B, "subnet": SNET_APP, "public_ip": False}],
        [{"id": "gw", "name": "vpngw", "t": "microsoft.network/virtualnetworkgateways", "subscriptionId": SUB_A,
          "refs": [[{"properties": {"subnet": {"id": VNET_HUB + "/subnets/GatewaySubnet"}}}]]}],
        [{"id": "rt", "subscriptionId": SUB_B, "subnets": [{"id": SNET_APP}],
          "routes": [{"properties": {"addressPrefix": "0.0.0.0/0", "nextHopType": "VirtualAppliance",
                                     "nextHopIpAddress": "10.0.0.4"}}]}],
        [{"id": STORAGE, "name": "stapp", "t": "microsoft.storage/storageaccounts", "subscriptionId": SUB_B,
          "public": "Disabled", "pe": 1},
         {"id": STORAGE.replace("stapp", "stopen"), "name": "stopen", "t": "microsoft.storage/storageaccounts",
          "subscriptionId": SUB_B, "public": "Enabled", "acl": "Allow"},
         {"id": APP, "name": "app-1", "t": "microsoft.web/sites", "subscriptionId": SUB_B, "integration": SNET_APP}],
        [{"id": "pip-1", "name": "pip-1", "subscriptionId": SUB_B,
          "owner": f"/subscriptions/{SUB_B}/resourcegroups/rg-app/providers/microsoft.network/networkinterfaces/nic"}])
    return data


# ---- collection and classification ----------------------------------------------------------------------------

def test_subnet_ids_are_found_anywhere_in_a_nested_value():
    value = [{"properties": {"subnet": {"id": SNET_APP.upper()}}}, None, {"x": [f"prefix {SNET_PE}/ipConfigurations/1"]}]
    assert subnet_ids(value) == sorted({SNET_APP, SNET_PE})


def test_default_route_and_build_network():
    assert default_route([{"properties": {"addressPrefix": "0.0.0.0/0", "nextHopType": "Internet"}}]) == "Internet"
    assert default_route([]) is None
    net = network_estate()["architecture"]["network"]
    assert net["private_endpoints"][0]["targets"] == [{"id": STORAGE, "group": "blob", "state": None}]
    assert net["edge"][0]["subnets"] == [VNET_HUB + "/subnets/gatewaysubnet"]
    assert net["route_tables"][0]["default_route"] == "VirtualAppliance 10.0.0.4"
    assert {v["id"]: v["public_ip"] for v in net["vms"]}[VM] is True


@pytest.mark.parametrize("item, expected", [
    ({"type": "microsoft.storage/storageaccounts", "public": "Enabled", "acl": "Allow"}, OPEN),
    ({"type": "microsoft.storage/storageaccounts", "public": "Enabled", "acl": "Allow", "pe": 2}, OPEN),
    ({"type": "microsoft.storage/storageaccounts", "public": "Enabled", "acl": "Deny"}, RESTRICTED),
    ({"type": "microsoft.keyvault/vaults", "ip_rules": 3}, RESTRICTED),
    ({"type": "microsoft.storage/storageaccounts", "public": "Disabled", "pe": 1}, PRIVATE),
    ({"type": "microsoft.storage/storageaccounts", "public": "Disabled"}, CLOSED),
    ({"type": "microsoft.sql/servers", "public": "Enabled"}, RESTRICTED),
    ({"type": "microsoft.servicebus/namespaces", "public": "Enabled"}, UNVERIFIED),
    ({"type": "microsoft.web/sites"}, APP_PUBLIC),
    ({"type": "microsoft.web/sites", "pe": 1}, PRIVATE),
    ({"type": "microsoft.logic/workflows", "access_control": True}, RESTRICTED),
])
def test_exposure(item, expected):
    assert exposure(item) == expected


# ---- diagrams ------------------------------------------------------------------------------------------------------

def test_tenant_network_draws_hubs_spokes_isolated_and_only_counts_connected_overlaps():
    svg = network_diagram.render_network_tenant(network_estate(), "/architecture?view=network&subscription={id}")
    assert "Hub and spoke (1 hub(s))" in svg and "Isolated VNets (1)" in svg
    assert ">0</tspan><tspan class=\"muted\"> overlaps between connected VNets" in svg   # spoke and lonely: not peered
    assert "reuse an address range used elsewhere" in svg
    assert f'href="/architecture?view=network&amp;subscription={SUB_B}"' in svg


def test_subscription_network_shows_subnets_vm_state_private_endpoints_and_exposure():
    svg = network_diagram.render_network(network_estate(), SUB_B, "/architecture?view=network")
    for text in ("snet-app", "0.0.0.0/0 → VirtualAppliance 10.0.0.4", "no NSG", "VNet integration: 1 app(s)",
                 "no NSG (private endpoints only)", "stapp · blob", "Open to all networks", "stopen",
                 "Apps (App Service, Functions, Logic Apps) - public endpoint", "On-premises",
                 "stopped, NOT deallocated - compute still billed", "1 deallocated - disks still billed"):
        assert text in svg, text
    assert 'fill="#FFF4CE"' in svg and 'fill="#FDE7E9"' in svg      # deallocated and stopped VM chips
    assert 'stroke-dasharray="4,3"' in svg                           # private endpoint -> target line
    with pytest.raises(KeyError):
        network_diagram.render_network(network_estate(), "nope")


def test_resource_view_tiles_highlight_deallocated_and_stopped_vms():
    svg = diagram.render_subscription(network_estate(), SUB_B)
    assert "1 deallocated · 1 stopped, billed" in svg and "Stopped (not deallocated) VMs are still billed" in svg


def test_architecture_svg_dispatches_views():
    data = network_estate()
    assert "Tenant network topology" in network_diagram.architecture_svg(data, "", "network")
    assert "Tenant architecture" in network_diagram.architecture_svg(data, "", "resources")
    assert "spoke" in network_diagram.architecture_svg(data, SUB_B, "network", "/architecture")


# ---- telemetry -----------------------------------------------------------------------------------------------------

def test_estate_telemetry_and_its_charts():
    t = estate_telemetry(network_estate(), ["owner"])
    assert t["vm_power"] == {"running": 0, "deallocated": 1, "stopped": 1}
    assert t["vm_stopped"][0]["name"] == "vm-2"
    assert t["network"]["data"] == {"private": 1, "open": 1} and t["network"]["apps"] == {"app-public": 1}
    assert t["network"]["vms_with_public_ip"] == 1 and t["network"]["isolated_vnets"] == 1
    assert t["tag_coverage"]["resources_pct"] == 0.0 and t["spend_30d"] == pytest.approx(151.0)
    html = telemetry_html(t)
    assert "Stopped, not deallocated: vm-2" in html and "data services open to all networks" in html
    assert "<script" not in html and "corp-app-&lt;script&gt;-dev" in html          # names are escaped
    assert utilisation_band({"cpu95": 2}) == "idle" and utilisation_band({"cpu": 90}) == "hot"
    assert utilisation_band({}) == "no data"


# ---- routes --------------------------------------------------------------------------------------------------------

def test_docker_network_view_and_telemetry_routes():
    client = _docker_client(_snapshot(network_estate()))
    net = client.get(f"/estate/architecture.svg?view=network&subscription={SUB_B}")
    assert net.status_code == 200 and "snet-app" in net.text and 'href="/architecture' not in net.text
    assert client.get("/estate/architecture.svg?view=bogus").status_code == 422
    t = client.get("/estate/telemetry")
    assert t.status_code == 200 and t.json()["vm_power"]["stopped"] == 1

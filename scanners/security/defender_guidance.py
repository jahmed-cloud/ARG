"""
Azure Resource Guardian - Defender for Cloud assessment guidance
================================================================
DefenderRecommendationsScanner imports unhealthy Defender assessments. Defender's own text tells you where to click;
this catalogue adds, for the recommendations seen most across the estate, why the change matters (and when it does
not), what it costs to implement, the commands for the affected resource and Microsoft Learn references.
Assessments not listed here fall back to Microsoft's description and remediation text from the assessment metadata.

Plan-enablement recommendations ("Microsoft Defender for Storage plan should be enabled ...", "Microsoft Defender
CSPM should be enabled", ...) are upsells of paid plans, not configuration gaps. Which plans to buy is a central,
cost-driven decision, so the scanner leaves them out unless `defender_plan_recommendations` is switched on.
"""

import re
from typing import Dict, List, NamedTuple, Optional, Pattern, Tuple

from scanners.base.guidance import PRICE, Guidance, pricing

# "Microsoft Defender for Storage plan should be enabled with ...", "Microsoft Defender CSPM should be enabled",
# "Microsoft Defender for SQL should be enabled for unprotected Azure SQL servers", "Azure Kubernetes Service clusters
# should have Defender profile enabled" - but not "Windows Defender Exploit Guard should be enabled on machines".
PLAN_RECOMMENDATION = re.compile(
    r"^(microsoft|azure) defender (for\b|cspm\b).*\bshould be enabled|should have (the )?defender (profile|extension)",
    re.I)
# Per-package OS update assessments ("Update openssl", "Update libc6", ...): collapsed into one entry per machine.
SYSTEM_UPDATE = re.compile(r"^update \S+$", re.I)


def is_plan_recommendation(name: str) -> bool:
    return bool(PLAN_RECOMMENDATION.search(name or ""))


def is_system_update(name: str, recommendation_category: str = "") -> bool:
    return (recommendation_category or "").lower() == "systemupdate" or bool(SYSTEM_UPDATE.match(name or ""))


class AssessmentGuidance(NamedTuple):
    key: str
    guidance: Guidance
    steps: str
    # resource-type prefix -> Azure CLI template ({rg}, {name}, {id}, {sub} are filled in)
    cli: Dict[str, str] = {}


VM = "microsoft.compute/virtualmachines"
VMSS = "microsoft.compute/virtualmachinescalesets"
ANY = ""

_PE_STEPS = ("1. Create a private endpoint in the workload's spoke VNet and link the matching privatelink.* private DNS "
             "zone (central zones in the hub where they exist).\n"
             "2. Check that every client resolves the private IP (App Service needs VNet integration).\n"
             "3. Then disable public network access.")

_CATALOGUE: List[Tuple[Pattern, AssessmentGuidance]] = []


def _add(pattern: str, key: str, guidance: Guidance, steps: str, cli: Optional[Dict[str, str]] = None) -> None:
    _CATALOGUE.append((re.compile(pattern, re.I), AssessmentGuidance(key, guidance, steps, cli or {})))


# --- Compute --------------------------------------------------------------------------------------------------

_add(r"enable azure disk encryption or encryptionathost|should have encryption at host enabled|encrypt temp disks",
     "encryption_at_host",
     Guidance(
         why=("OS and data managed disks are already encrypted at rest by Azure Storage (platform-managed keys). What "
              "is NOT encrypted is the temporary (resource) disk, the OS / data disk caches on the host, and the data "
              "flowing between the host and storage. Encryption at host closes exactly that gap on the hypervisor: no "
              "agent, no CPU cost inside the VM, no Key Vault to run. Do not choose Azure Disk Encryption (BitLocker / "
              "dm-crypt in the guest): it retires on 15 September 2028, after which ADE-encrypted disks no longer "
              "unlock on reboot."),
         skip_when=("The VM processes no confidential data and is short-lived (dev/test, build agents): document an "
                    "exemption in Defender instead. Not possible on VM sizes without the EncryptionAtHostSupported "
                    "capability, nor on a VM that has ever had Azure Disk Encryption - those need the documented "
                    "migration (new disks), not a switch."),
         effort=("Once per subscription: register the EncryptionAtHost feature (takes ~15 minutes). Per VM: deallocate, "
                 "update, start - a 5-10 minute outage, so plan a maintenance window. Roll out for new VMs through "
                 "IaC / Azure Policy."),
         hours=(0.5, 1.0),
         monthly_usd=0.0,
         run_cost="No additional Azure charge - encryption at host is free; only the restart window costs time.",
         references=(
             ("Encryption at host - enable with Azure CLI",
              "https://learn.microsoft.com/azure/virtual-machines/linux/disks-enable-host-based-encryption-cli"),
             ("Encryption at host - Azure portal",
              "https://learn.microsoft.com/azure/virtual-machines/disks-enable-host-based-encryption-portal"),
             ("Overview of managed disk encryption options",
              "https://learn.microsoft.com/azure/virtual-machines/disk-encryption-overview"),
             ("Migrate from Azure Disk Encryption to encryption at host",
              "https://learn.microsoft.com/azure/virtual-machines/disk-encryption-migrate"),
         )),
     steps=("1. Register the feature once per subscription and wait until it shows 'Registered'.\n"
            "2. Check the VM size supports it (capability EncryptionAtHostSupported).\n"
            "3. In a maintenance window: deallocate the VM, set securityProfile.encryptionAtHost=true, start it.\n"
            "4. Make it the default for new VMs in IaC (Terraform: encryption_at_host_enabled = true)."),
     cli={VM: ("# once per subscription\n"
               "az feature register --namespace Microsoft.Compute --name EncryptionAtHost --subscription {sub}\n"
               "az feature show --namespace Microsoft.Compute --name EncryptionAtHost --subscription {sub} "
               "--query properties.state\n"
               "az provider register -n Microsoft.Compute --subscription {sub}\n"
               "# per VM (5-10 minutes downtime)\n"
               "az vm deallocate -g {rg} -n {name}\n"
               "az vm update -g {rg} -n {name} --set securityProfile.encryptionAtHost=true\n"
               "az vm start -g {rg} -n {name}"),
          VMSS: ("az feature register --namespace Microsoft.Compute --name EncryptionAtHost --subscription {sub}\n"
                 "az vmss deallocate -g {rg} -n {name}\n"
                 "az vmss update -g {rg} -n {name} --set virtualMachineProfile.securityProfile.encryptionAtHost=true\n"
                 "az vmss update-instances -g {rg} -n {name} --instance-ids '*'\n"
                 "az vmss start -g {rg} -n {name}")})

_add(r"^update \S+$|system updates should be installed|machines should have vulnerability findings resolved|"
     r"should have vulnerability findings resolved",
     "system_updates",
     Guidance(
         why=("Defender found packages with published security fixes that are not installed. Unpatched OS and library "
              "vulnerabilities are the most common way in after stolen credentials; the longer they stay open, the "
              "more likely an exploit exists."),
         skip_when=("Never skip; defer only when the vendor of the installed application has not certified the update "
                    "yet - then record the exception with an end date. Machines rebuilt from a patched image every "
                    "few weeks can be fixed in the image pipeline instead of in place."),
         effort=("Install through Azure Update Manager (one-off or on a maintenance schedule); a reboot may be "
                 "needed. After that, a recurring maintenance configuration keeps the machine current."),
         hours=(0.5, 2.0),
         monthly_usd=0.0,
         run_cost=("No charge for Azure VMs - Azure Update Manager is free for them (Azure Arc-enabled servers are "
                   "billed per server)."),
         references=(
             ("Azure Update Manager overview", "https://learn.microsoft.com/azure/update-manager/overview"),
             ("Update Manager assessment options", "https://learn.microsoft.com/azure/update-manager/assessment-options"),
             pricing("update_manager"),
         )),
     steps=("1. Install the missing security and critical updates now (Update Manager → One-time update), with the "
            "reboot setting the workload allows.\n"
            "2. Attach the machine to a maintenance configuration (weekly / monthly schedule) so it stays patched.\n"
            "3. For container images: rebuild on a patched base image and redeploy."),
     cli={VM: ("az vm assess-patches -g {rg} -n {name}\n"
               "# Linux\n"
               "az vm install-patches -g {rg} -n {name} --maximum-duration PT2H --reboot-setting IfRequired "
               "--classifications-to-include-linux Critical Security\n"
               "# Windows\n"
               "az vm install-patches -g {rg} -n {name} --maximum-duration PT2H --reboot-setting IfRequired "
               "--classifications-to-include-win Critical Security")})

_add(r"periodically check for missing system updates",
     "periodic_assessment",
     Guidance(
         why=("Without periodic assessment, Azure only knows a machine's patch state when someone checks by hand, so "
              "missing security updates go unnoticed and patch compliance cannot be reported."),
         skip_when="Machines whose patching is fully handled by another tool that reports compliance centrally.",
         effort="A property change on the VM, no restart. Assign the built-in policy to cover new VMs automatically.",
         hours=(0.1, 0.25),
         monthly_usd=0.0,
         run_cost="No charge for Azure VMs.",
         references=(
             ("Update Manager assessment options", "https://learn.microsoft.com/azure/update-manager/assessment-options"),
             ("Azure Update Manager overview", "https://learn.microsoft.com/azure/update-manager/overview"),
         )),
     steps="Set patchSettings.assessmentMode to AutomaticByPlatform (Linux or Windows section of the OS profile).",
     cli={VM: ("# Linux VM\n"
               "az vm update -g {rg} -n {name} --set "
               "osProfile.linuxConfiguration.patchSettings.assessmentMode=AutomaticByPlatform\n"
               "# Windows VM\n"
               "az vm update -g {rg} -n {name} --set "
               "osProfile.windowsConfiguration.patchSettings.assessmentMode=AutomaticByPlatform")})

_add(r"guest configuration extension should be installed|guest attestation extension should be installed",
     "guest_configuration",
     Guidance(
         why=("The machine configuration (guest configuration) extension lets Azure Policy audit settings inside the "
              "OS - password policy, TLS protocols, installed software. Without it those policies report "
              "'not applicable' and the VM is invisible to in-guest compliance."),
         skip_when="VMs that are not in scope of any in-guest policy and are about to be decommissioned.",
         effort="Assign a system-assigned managed identity and install the extension; no restart.",
         hours=(0.1, 0.5),
         monthly_usd=0.0,
         run_cost="No charge for Azure VMs (Azure Arc-enabled servers are billed per server).",
         references=(("Azure Machine Configuration overview",
                      "https://learn.microsoft.com/azure/governance/machine-configuration/overview/01-overview-concepts"),)),
     steps="Assign a system-assigned identity, then install ConfigurationforLinux / ConfigurationforWindows.",
     cli={VM: ("az vm identity assign -g {rg} -n {name}\n"
               "# Linux (use ConfigurationforWindows on Windows)\n"
               "az vm extension set -g {rg} --vm-name {name} --publisher Microsoft.GuestConfiguration "
               "--name ConfigurationforLinux --enable-auto-upgrade true")})

_add(r"azure backup should be enabled for virtual machines",
     "vm_backup",
     Guidance(
         why=("Managed disks are replicated but not backed up: a deletion, ransomware encryption or a bad change is "
              "replicated too. Azure Backup keeps restore points outside the VM's control."),
         skip_when=("Stateless VMs rebuilt from IaC and an image (build agents, scale-out web nodes) - their data "
                    "lives elsewhere. Back up the data store instead."),
         effort="Add the VM to a Recovery Services vault policy; the first backup runs without downtime.",
         hours=(0.25, 0.5),
         monthly_usd=None,
         run_cost=("A protected-instance fee per VM (USD 5 up to 50 GB, USD 10 up to 500 GB) plus backup storage "
                   "per GB - depends on disk size, churn and retention."),
         references=(("About Azure VM backup", "https://learn.microsoft.com/azure/backup/backup-azure-vms-introduction"),
                     pricing("backup"))),
     steps="Choose (or create) a Recovery Services vault and a policy that matches the VM's RPO / retention.",
     cli={VM: "az backup protection enable-for-vm -g <vault-rg> --vault-name <vault> --vm {id} --policy-name DefaultPolicy"})

_add(r"management ports of virtual machines should be protected with just-in-time|management ports should be closed",
     "jit",
     Guidance(
         why=("RDP / SSH reachable from the internet are brute-forced within hours of exposure and are a leading "
              "initial-access path."),
         skip_when="Never leave them open to the internet; if no access is needed at all, simply remove the rule.",
         effort="Remove the inbound rule and use Azure Bastion, or JIT (needs Defender for Servers Plan 2).",
         hours=(0.5, 2.0),
         monthly_usd=0.0,
         run_cost=(f"No change if a Bastion already serves the VNet (Bastion Developer is free; Basic is about "
                   f"USD {PRICE['bastion_basic']:,.0f}/month). JIT requires Defender for Servers Plan 2 "
                   f"(about USD {PRICE['defender_servers_p2']:.2f} per server per month)."),
         references=(("Enable just-in-time access",
                      "https://learn.microsoft.com/azure/defender-for-cloud/enable-just-in-time-access"),
                     ("Azure Bastion overview", "https://learn.microsoft.com/azure/bastion/bastion-overview"),
                     pricing("bastion"))),
     steps="Delete the internet-facing inbound rule for 22 / 3389 and connect through Bastion.")

_add(r"internet-facing virtual machines should be protected with network security groups|"
     r"non-internet-facing virtual machines should be protected with network security groups|"
     r"all network ports should be restricted on network security groups",
     "vm_nsg",
     Guidance(
         why=("Without an NSG (or with broad allow rules) every port the OS listens on is reachable from the VNet - "
              "and from the internet when the VM has a public IP - so one compromised workload can reach all others."),
         skip_when="VMs in a subnet whose NSG already enforces the needed rules (Defender evaluates the NIC and subnet).",
         effort="Attach an NSG with deny-by-default and only the required inbound ports; test the application.",
         hours=(0.5, 2.0),
         monthly_usd=0.0,
         run_cost="NSGs are free (NSG / VNet flow logs, if enabled, are billed per GB).",
         references=(("Network security groups",
                      "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview"),
                     ("Microsoft cloud security benchmark - network security",
                      "https://learn.microsoft.com/security/benchmark/azure/mcsb-network-security"))),
     steps="Create an NSG for the subnet (preferred) or NIC, allow only required sources and ports, deny the rest.")

_add(r"windows servers should be configured to use secure communication protocols",
     "windows_tls",
     Guidance(
         why=("TLS 1.0 / 1.1 and SSL 3.0 have known weaknesses; leaving them enabled lets clients and attackers "
              "negotiate a weak protocol."),
         skip_when="Servers that must still talk to a legacy client that cannot do TLS 1.2 - fix the client first.",
         effort="Registry / GPO change (or a machine configuration assignment) and a reboot; test old clients first.",
         hours=(0.5, 2.0),
         monthly_usd=0.0,
         run_cost="No Azure cost.",
         references=(("TLS registry settings",
                      "https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings"),)),
     steps="Disable SSL 3.0, TLS 1.0 and TLS 1.1 (Server and Client keys), keep TLS 1.2 / 1.3, reboot.")

_add(r"windows defender exploit guard should be enabled",
     "exploit_guard",
     Guidance(
         why="Exploit protection mitigates memory-corruption exploits in Windows processes before they run code.",
         skip_when="Machines where an equivalent EDR / hardening product is already enforced.",
         effort="Configure exploit protection through Intune, GPO or Defender for Endpoint; test line-of-business apps.",
         hours=(1.0, 4.0),
         monthly_usd=0.0,
         run_cost="No Azure cost when Defender for Endpoint is already licensed.",
         references=(("Exploit protection", "https://learn.microsoft.com/defender-endpoint/exploit-protection"),)),
     steps="Deploy an exploit protection configuration in audit mode first, then enforce.")

_add(r"edr solution should be installed|endpoint protection should be installed",
     "edr",
     Guidance(
         why="Without EDR, malware and hands-on-keyboard activity on the machine go undetected.",
         skip_when="Machines already covered by another approved EDR product (record it as an exception in Defender).",
         effort="Onboard to Defender for Endpoint (automatic with Defender for Servers) or the company EDR.",
         hours=(0.5, 1.0),
         monthly_usd=PRICE["defender_servers_p1"],
         run_cost=(f"Defender for Servers Plan 1 (includes Defender for Endpoint) is about USD "
                   f"{PRICE['defender_servers_p1']:.2f} per server per month, unless servers are already licensed."),
         references=(("Select a Defender for Servers plan",
                      "https://learn.microsoft.com/azure/defender-for-cloud/plan-defender-for-servers-select-plan"),
                     pricing("defender"))),
     steps="Confirm which EDR the company standard uses, then onboard the machine to it.")

_add(r"machines should have a vulnerability assessment solution",
     "vulnerability_assessment",
     Guidance(
         why="Without vulnerability assessment nobody sees which installed software has known CVEs.",
         skip_when="Machines already scanned by an approved third-party scanner whose results are reviewed.",
         effort="Enable Defender Vulnerability Management (agentless with Defender CSPM or Defender for Servers).",
         hours=(0.25, 1.0),
         monthly_usd=None,
         run_cost=(f"Comes with Defender for Servers (Plan 1 about USD {PRICE['defender_servers_p1']:.2f}, Plan 2 about "
                   f"USD {PRICE['defender_servers_p2']:.2f} per server per month) or Defender CSPM - a plan decision, "
                   f"not a per-VM change."),
         references=(("Defender Vulnerability Management for machines",
                      "https://learn.microsoft.com/azure/defender-for-cloud/"
                      "deploy-vulnerability-assessment-defender-vulnerability-management"),
                     pricing("defender"))),
     steps="Decide centrally which plan covers vulnerability assessment; then this recommendation clears itself.")

# --- Identity & access ------------------------------------------------------------------------------------------

_add(r"guest accounts with .*permissions on azure resources should be removed",
     "guest_rbac",
     Guidance(
         why=("Guest (B2B) accounts are managed by another organisation: their MFA, joiner/leaver process and device "
              "security are outside your control, so a role assignment to a guest is access you cannot govern."),
         skip_when=("Partners who genuinely operate the workload - then keep the assignment, scope it to the resource "
                    "group, make it time-bound in PIM and cover it with an access review."),
         effort="List guest role assignments, confirm with the owner, remove or move them to a reviewed group.",
         hours=(0.25, 1.0),
         monthly_usd=0.0,
         run_cost="No Azure cost.",
         references=(("Azure RBAC best practices",
                      "https://learn.microsoft.com/azure/role-based-access-control/best-practices"),
                     ("Access reviews", "https://learn.microsoft.com/entra/id-governance/access-reviews-overview"))),
     steps="Remove role assignments of #EXT# accounts that have no documented business need.",
     cli={ANY: ("az role assignment list --scope /subscriptions/{sub} --include-inherited "
                "--query \"[?contains(principalName, '#EXT#')].{{who:principalName, role:roleDefinitionName, "
                "scope:scope}}\" -o table")})

_add(r"(disabled|blocked) accounts with .*permissions on azure resources should be removed",
     "disabled_rbac",
     Guidance(
         why=("Role assignments of disabled accounts are leftovers of leavers. They do nothing today but are restored "
              "the moment the account is re-enabled, and they clutter access reviews."),
         skip_when="Never needed - re-grant when an account is legitimately re-enabled.",
         effort="Remove the role assignments of the disabled accounts.",
         hours=(0.1, 0.5),
         monthly_usd=0.0,
         run_cost="No Azure cost.",
         references=(("Azure RBAC best practices",
                      "https://learn.microsoft.com/azure/role-based-access-control/best-practices"),)),
     steps="Find the disabled principals Defender lists and delete their role assignments.",
     cli={ANY: "az role assignment list --scope /subscriptions/{sub} --include-inherited -o table"})

_add(r"maximum of 3 owners should be designated|should be more than one owner",
     "owners",
     Guidance(
         why=("Every Owner can change any resource and grant access to anyone. More than three standing Owners "
              "multiplies the accounts an attacker can phish to take over the subscription."),
         skip_when="Owners that are PIM-eligible (not active) do not count - make them eligible rather than removing them.",
         effort="Move Owners to an Entra group with PIM-eligible, approval-based activation; keep at most three.",
         hours=(1.0, 3.0),
         monthly_usd=0.0,
         run_cost="No Azure cost; PIM needs Microsoft Entra ID P2 / ID Governance licences for the eligible users.",
         references=(("Azure RBAC best practices",
                      "https://learn.microsoft.com/azure/role-based-access-control/best-practices"),
                     ("Configure Privileged Identity Management",
                      "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure"))),
     steps="Review the Owners, convert them to PIM-eligible assignments, remove direct ones.",
     cli={ANY: "az role assignment list --scope /subscriptions/{sub} --role Owner --include-inherited -o table"})

_add(r"privileged roles should not have permanent access",
     "pim",
     Guidance(
         why=("Permanent privileged roles are usable 24/7 by anyone who steals the session or credentials. "
              "Just-in-time activation limits the window and adds approval and an audit trail."),
         skip_when="Break-glass accounts (excluded and monitored separately) and automation that must run unattended.",
         effort="Convert active assignments to PIM-eligible ones with activation limits.",
         hours=(1.0, 3.0),
         monthly_usd=0.0,
         run_cost="No Azure cost; PIM needs Microsoft Entra ID P2 / ID Governance licences for the eligible users.",
         references=(("Configure Privileged Identity Management",
                      "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure"),)),
     steps="Make the listed assignments eligible in PIM (max activation 8 h, justification, approval for Owner).")

_add(r"overprovisioned identities should have only the necessary permissions",
     "least_privilege",
     Guidance(
         why="Identities that hold permissions they never use widen the blast radius of a compromise for no benefit.",
         skip_when="Rarely-used but required duties (DR, year-end) - document them and keep them PIM-eligible.",
         effort="Replace broad roles with the narrowest built-in role that covers the actions actually used.",
         hours=(1.0, 4.0),
         monthly_usd=0.0,
         run_cost="No Azure cost.",
         references=(("Azure RBAC best practices",
                      "https://learn.microsoft.com/azure/role-based-access-control/best-practices"),)),
     steps="Compare granted vs used permissions in Defender (CIEM) and right-size the role assignments.")

_add(r"managed identity should be enabled on (web|function|api) apps",
     "webapp_identity",
     Guidance(
         why=("Without a managed identity the app reaches SQL, Storage and Key Vault with connection strings and keys "
              "kept in settings - secrets that leak, never rotate and identify no caller."),
         skip_when="Apps that call no Azure service.",
         effort="Assign the identity (no restart), grant it data-plane roles, then switch the app's connections.",
         hours=(0.5, 8.0),
         monthly_usd=0.0,
         run_cost="No Azure cost.",
         references=(("Managed identities for App Service",
                      "https://learn.microsoft.com/azure/app-service/overview-managed-identity"),)),
     steps="Assign a system-assigned identity, grant roles, move connection strings to identity-based auth.",
     cli={"microsoft.web/sites": "az webapp identity assign -g {rg} -n {name}"})

# --- Storage --------------------------------------------------------------------------------------------------

_add(r"storage accounts should prevent shared key access",
     "storage_shared_key",
     Guidance(
         why=("An account key grants full control of all data in the account, never expires and identifies nobody; "
              "SAS tokens signed with it inherit that. Entra ID authorisation gives per-identity access and an "
              "audit trail."),
         skip_when=("Clients that still need keys: Azure Files SMB with storage-key mounts, Functions / Logic Apps "
                    "whose runtime storage is not identity-based, some backup and third-party tools. Check the "
                    "account's Transactions metric split by Authentication type before switching off."),
         effort="Move every client to Entra ID (managed identity), confirm no SharedKey traffic remains, then disable.",
         hours=(0.5, 8.0),
         monthly_usd=0.0,
         run_cost="No Azure cost.",
         references=(("Prevent Shared Key authorization",
                      "https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent"),)),
     steps="Verify no SharedKey requests in the last 7 days (metrics), then disable shared key access.",
     cli={"microsoft.storage/storageaccounts": "az storage account update -g {rg} -n {name} --allow-shared-key-access false"})

_add(r"storage account should use a private link connection|storage accounts should restrict network access|"
     r"access to storage accounts with firewall and virtual network configurations should be restricted",
     "storage_network",
     Guidance(
         why=("A storage account reachable from every network relies on keys / SAS alone; a leaked token works from "
              "anywhere. A private endpoint or firewall makes the network a second barrier."),
         skip_when=("Accounts that must be public by design (static website, public downloads - put Front Door / CDN "
                    "in front) or that only hold diagnostics. Platform services that write to it need the 'trusted "
                    "Microsoft services' exception."),
         effort="Private endpoint + private DNS for each used sub-resource (blob, file, ...), then default action Deny.",
         hours=(1.0, 4.0),
         monthly_usd=PRICE["private_endpoint"],
         run_cost=(f"About USD {PRICE['private_endpoint']:.2f} per private endpoint per month (+ USD 0.01 per GB "
                   f"processed), one per sub-resource used; a firewall rule alone is free."),
         references=(("Use private endpoints for Azure Storage",
                      "https://learn.microsoft.com/azure/storage/common/storage-private-endpoints"),
                     ("Azure Storage network security",
                      "https://learn.microsoft.com/azure/storage/common/storage-network-security"),
                     pricing("private_link"))),
     steps=_PE_STEPS,
     cli={"microsoft.storage/storageaccounts": (
         "az network private-endpoint create -g {rg} -n pe-{name}-blob --vnet-name <vnet> --subnet <subnet> "
         "--private-connection-resource-id {id} --group-id blob --connection-name {name}-blob\n"
         "az storage account update -g {rg} -n {name} --default-action Deny --bypass AzureServices")})

_add(r"secure transfer to storage accounts should be enabled",
     "storage_https",
     Guidance(
         why="Without secure transfer the account accepts plain HTTP, exposing data and SAS tokens in transit.",
         skip_when="Never; NFS 3.0 accounts are the only documented exception.",
         effort="One property change, no downtime for HTTPS clients.",
         hours=(0.1, 0.25),
         monthly_usd=0.0,
         run_cost="No Azure cost.",
         references=(("Azure Storage network security",
                      "https://learn.microsoft.com/azure/storage/common/storage-network-security"),)),
     steps="Enable 'Secure transfer required'.",
     cli={"microsoft.storage/storageaccounts": "az storage account update -g {rg} -n {name} --https-only true"})

_add(r"storage account public access should be disallowed|anonymous access",
     "storage_anonymous",
     Guidance(
         why="Anonymous blob access lets anyone with the URL read the data - no key, no log of who it was.",
         skip_when="Content that is meant to be public; serve it through Front Door / CDN from a dedicated account.",
         effort="Disallow blob anonymous access on the account after confirming no container is meant to be public.",
         hours=(0.25, 1.0),
         monthly_usd=0.0,
         run_cost="No Azure cost.",
         references=(("Prevent anonymous read access to blobs",
                      "https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent"),)),
     steps="Set allowBlobPublicAccess=false.",
     cli={"microsoft.storage/storageaccounts": "az storage account update -g {rg} -n {name} --allow-blob-public-access false"})

# --- Key Vault ------------------------------------------------------------------------------------------------

_add(r"key vaults should have (deletion|purge) protection enabled",
     "kv_purge",
     Guidance(
         why=("Without purge protection anyone with delete rights - or an attacker - can permanently destroy keys "
              "and secrets, including keys that encrypt data elsewhere (CMK), during the soft-delete window."),
         skip_when=("Short-lived test vaults that automation deletes and re-creates with the same name (purge "
                    "protection blocks reusing the name for the retention period)."),
         effort="One irreversible property change, no downtime.",
         hours=(0.1, 0.25),
         monthly_usd=0.0,
         run_cost="No Azure cost.",
         references=(("Key Vault soft-delete and purge protection",
                      "https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview"),)),
     steps="Enable purge protection (cannot be turned off again).",
     cli={"microsoft.keyvault/vaults": "az keyvault update -g {rg} -n {name} --enable-purge-protection true"})

_add(r"key vaults should use private link|firewall should be enabled on key vault",
     "kv_network",
     Guidance(
         why="A vault open to all networks is protected only by Entra tokens; a stolen token works from anywhere.",
         skip_when=("Vaults read by services that cannot use private networking (some SaaS integrations) - use IP "
                    "rules or the trusted-services exception for them."),
         effort="Private endpoint + privatelink.vaultcore.azure.net DNS, then firewall default action Deny.",
         hours=(1.0, 3.0),
         monthly_usd=PRICE["private_endpoint"],
         run_cost=f"About USD {PRICE['private_endpoint']:.2f} per private endpoint per month; IP rules alone are free.",
         references=(("Key Vault private link", "https://learn.microsoft.com/azure/key-vault/general/private-link-service"),
                     ("Key Vault network security", "https://learn.microsoft.com/azure/key-vault/general/network-security"),
                     pricing("private_link"))),
     steps=_PE_STEPS,
     cli={"microsoft.keyvault/vaults": "az keyvault update -g {rg} -n {name} --default-action Deny --bypass AzureServices"})

_add(r"role-based access control should be used on azure keyvault",
     "kv_rbac",
     Guidance(
         why=("Access policies are invisible to Azure RBAC tooling, cannot be PIM-managed, and any vault Contributor "
              "can grant themselves data access."),
         skip_when="Never for new vaults; for old ones plan the switch so no application loses access.",
         effort="Map each access policy to an RBAC role (Key Vault Secrets User, ...), then switch the permission model.",
         hours=(0.5, 2.0),
         monthly_usd=0.0,
         run_cost="No Azure cost.",
         references=(("Migrate from access policies to Azure RBAC",
                      "https://learn.microsoft.com/azure/key-vault/general/rbac-migration"),)),
     steps="Create equivalent role assignments first, then enable RBAC authorization.",
     cli={"microsoft.keyvault/vaults": "az keyvault update -g {rg} -n {name} --enable-rbac-authorization true"})

_add(r"diagnostic logs in .* should be enabled|resource logs in .* should be enabled",
     "diagnostic_logs",
     Guidance(
         why=("Without resource logs there is no record of who read a secret, called a model or changed data - "
              "incident response and audits have nothing to work with."),
         skip_when=("Non-production resources with no sensitive data, or resources already covered by a central "
                    "diagnostic-settings policy that just has not reached them yet."),
         effort="One diagnostic setting per resource (better: a DeployIfNotExists policy for the resource type).",
         hours=(0.1, 0.5),
         monthly_usd=None,
         run_cost=(f"Log Analytics ingestion at about USD {PRICE['log_analytics_gb']:.2f} per GB (first 5 GB per "
                   f"month free); audit logs are usually small - send verbose categories to storage or Basic logs."),
         references=(("Diagnostic settings in Azure Monitor",
                      "https://learn.microsoft.com/azure/azure-monitor/data-collection/diagnostic-settings"),
                     ("Azure Monitor cost best practices",
                      "https://learn.microsoft.com/azure/azure-monitor/fundamentals/best-practices-cost"),
                     pricing("monitor"))),
     steps="Send the 'audit' category group to the central Log Analytics workspace.",
     cli={ANY: ("az monitor diagnostic-settings create --name to-central-law --resource {id} "
                "--workspace <log-analytics-workspace-resource-id> --logs '[{{\"categoryGroup\":\"audit\",\"enabled\":true}}]'")})

# --- AI / Foundry ---------------------------------------------------------------------------------------------

_add(r"(foundry|ai services|cognitive services) resources should have key access disabled",
     "ai_local_auth",
     Guidance(
         why=("API keys are shared secrets: every caller looks the same, so token spend and abuse cannot be "
              "attributed, and a leaked key works until someone rotates it."),
         skip_when="Clients that cannot use Entra ID yet - give them a deadline and rotate the keys meanwhile.",
         effort="Give callers managed identities with 'Cognitive Services OpenAI User' / 'Azure AI User', then disable keys.",
         hours=(1.0, 8.0),
         monthly_usd=0.0,
         run_cost="No Azure cost.",
         references=(("Disable local authentication in Azure AI services",
                      "https://learn.microsoft.com/azure/ai-services/disable-local-auth"),)),
     steps="Switch every caller to Entra ID, then set disableLocalAuth=true.",
     cli={"microsoft.cognitiveservices/accounts": "az resource update --ids {id} --set properties.disableLocalAuth=true"})

_add(r"(foundry|ai services|cognitive services) resources should (use azure private link|restrict network access)",
     "ai_network",
     Guidance(
         why="A model endpoint open to all networks can be called (and billed) from anywhere a key or token leaks to.",
         skip_when="Public-facing apps calling the endpoint from outside Azure - use IP rules or a gateway instead.",
         effort="Private endpoint + privatelink DNS (or IP rules), then default action Deny.",
         hours=(1.0, 3.0),
         monthly_usd=PRICE["private_endpoint"],
         run_cost=f"About USD {PRICE['private_endpoint']:.2f} per private endpoint per month; IP rules alone are free.",
         references=(("Configure virtual networks for Azure AI services",
                      "https://learn.microsoft.com/azure/ai-services/cognitive-services-virtual-networks"),
                     pricing("private_link"))),
     steps=_PE_STEPS,
     cli={"microsoft.cognitiveservices/accounts":
          "az resource update --ids {id} --set properties.networkAcls.defaultAction=Deny"})

# --- SQL ------------------------------------------------------------------------------------------------------

_add(r"public network access on azure sql database should be disabled|"
     r"private endpoint connections on azure sql database should be enabled",
     "sql_network",
     Guidance(
         why=("A public SQL endpoint is protected by firewall rules and credentials only; 'Allow Azure services' "
              "rules admit every Azure tenant. A private endpoint removes the public path."),
         skip_when="Servers reached by clients outside Azure without VPN / ExpressRoute - restrict IP rules tightly.",
         effort="Private endpoint + privatelink.database.windows.net DNS; App Service needs VNet integration.",
         hours=(1.0, 4.0),
         monthly_usd=PRICE["private_endpoint"],
         run_cost=f"About USD {PRICE['private_endpoint']:.2f} per private endpoint per month.",
         references=(("Azure SQL private endpoints",
                      "https://learn.microsoft.com/azure/azure-sql/database/private-endpoint-overview"),
                     ("Azure SQL connectivity settings",
                      "https://learn.microsoft.com/azure/azure-sql/database/connectivity-settings"),
                     pricing("private_link"))),
     steps=_PE_STEPS,
     cli={"microsoft.sql/servers": "az sql server update -g {rg} -n {name} --enable-public-network false"})

_add(r"azure sql database should have (azure active directory|microsoft entra)( id)? only authentication enabled",
     "sql_entra_only",
     Guidance(
         why="SQL logins are passwords outside Entra ID: no MFA, no Conditional Access, no central offboarding.",
         skip_when="Applications that cannot authenticate with Entra ID yet - migrate them first, then enable.",
         effort="Move applications to managed identities and users to Entra groups, then enable Entra-only auth.",
         hours=(2.0, 16.0),
         monthly_usd=0.0,
         run_cost="No Azure cost.",
         references=(("Microsoft Entra-only authentication with Azure SQL",
                      "https://learn.microsoft.com/azure/azure-sql/database/authentication-azure-ad-only-authentication"),)),
     steps="Inventory SQL logins in use, migrate them, then enable Entra-only authentication.",
     cli={"microsoft.sql/servers": "az sql server ad-only-auth enable -g {rg} -n {name}"})

_add(r"auditing on sql server should be enabled",
     "sql_auditing",
     Guidance(
         why="Without auditing there is no record of logins, permission changes or data access on the server.",
         skip_when="Non-production servers without sensitive data.",
         effort="Enable server-level auditing to the central Log Analytics workspace.",
         hours=(0.25, 0.5),
         monthly_usd=None,
         run_cost=f"Log Analytics ingestion at about USD {PRICE['log_analytics_gb']:.2f} per GB of audit records.",
         references=(("Azure SQL auditing", "https://learn.microsoft.com/azure/azure-sql/database/auditing-overview"),
                     pricing("monitor"))),
     steps="Enable auditing with the default action groups to Log Analytics.",
     cli={"microsoft.sql/servers": ("az sql server audit-policy update -g {rg} -n {name} --state Enabled "
                                    "--log-analytics-target-state Enabled "
                                    "--log-analytics-workspace-resource-id <workspace-resource-id>")})

_add(r"sql servers should have vulnerability assessment configured|"
     r"sql databases should have vulnerability findings resolved",
     "sql_va",
     Guidance(
         why="SQL vulnerability assessment flags excessive permissions, risky configuration and unprotected data.",
         skip_when="Non-production servers without sensitive data.",
         effort="Comes with Microsoft Defender for SQL (express configuration); then review and baseline the findings.",
         hours=(1.0, 4.0),
         monthly_usd=PRICE["defender_sql_server"],
         run_cost=(f"Requires Defender for SQL - about USD {PRICE['defender_sql_server']:.0f} per logical server per "
                   f"month. Decide per server, not by default."),
         references=(("SQL vulnerability assessment",
                      "https://learn.microsoft.com/azure/defender-for-cloud/sql-azure-vulnerability-assessment-overview"),
                     pricing("defender"))),
     steps="Decide whether the server's data justifies Defender for SQL; if yes, enable it and review the scan.")

_add(r"'dbo' user should not be used",
     "sql_dbo",
     Guidance(
         why="Applications connecting as dbo can alter schema and permissions - a SQL injection becomes full control.",
         skip_when="Deployment pipelines that run schema migrations (not the application runtime).",
         effort="Create a least-privilege database user / role for the app and switch its connection.",
         hours=(1.0, 4.0),
         monthly_usd=0.0,
         run_cost="No Azure cost.",
         references=(("Azure SQL security best practices",
                      "https://learn.microsoft.com/azure/azure-sql/database/security-best-practice"),)),
     steps="Grant the app db_datareader / db_datawriter (or a custom role) instead of dbo.")

# --- Containers & network edge ----------------------------------------------------------------------------------

_add(r"container registries should (use private link|not allow unrestricted network access)",
     "acr_network",
     Guidance(
         why="A registry open to all networks lets anyone with a token pull images (and the secrets baked into them).",
         skip_when="Registries that publish images to customers or CI systems outside your network.",
         effort="Private endpoints need the Premium SKU; then private DNS and default action Deny.",
         hours=(1.0, 3.0),
         monthly_usd=round(PRICE["acr_premium"] - PRICE["acr_basic"] + PRICE["private_endpoint"], 2),
         run_cost=(f"Premium is about USD {PRICE['acr_premium']:.2f}/month vs USD {PRICE['acr_basic']:.2f} for Basic "
                   f"(+ USD {PRICE['private_endpoint']:.2f} per private endpoint) - weigh it against the images' "
                   f"sensitivity."),
         references=(("Connect privately to a container registry",
                      "https://learn.microsoft.com/azure/container-registry/container-registry-private-endpoints"),
                     pricing("acr"))),
     steps="Upgrade to Premium only if a private registry is required; otherwise restrict with tokens and scope maps.",
     cli={"microsoft.containerregistry/registries": ("az acr update -n {name} --sku Premium\n"
                                                     "az acr update -n {name} --public-network-enabled false")})

_add(r"virtual networks should be protected by azure firewall",
     "azure_firewall",
     Guidance(
         why="Without central egress filtering a compromised workload can reach any internet destination.",
         skip_when=("Spokes whose default route (UDR 0.0.0.0/0) already points to the hub firewall or an NVA - "
                    "Defender only checks for a firewall in the VNet itself. A firewall per spoke is rarely justified."),
         effort="Route the spoke through the hub firewall (UDR) rather than deploying one per VNet.",
         hours=(2.0, 8.0),
         monthly_usd=0.0,
         run_cost=(f"No change when routing to the existing hub firewall. A dedicated Azure Firewall would be about "
                   f"USD {PRICE['firewall_basic']:,.0f} (Basic) to {PRICE['firewall_standard']:,.0f} (Standard) per "
                   f"month plus data processing."),
         references=(("Azure Firewall overview", "https://learn.microsoft.com/azure/firewall/overview"),
                     pricing("firewall"))),
     steps="Check the subnet route tables; if traffic already goes to the hub firewall, exempt the recommendation.")

# --- Defender / tenant settings -------------------------------------------------------------------------------

_add(r"subscriptions should have a contact email address for security issues|"
     r"email notification (to subscription owner )?for high severity alerts should be enabled",
     "security_contacts",
     Guidance(
         why="Defender alerts and Microsoft security notifications for the subscription reach nobody.",
         skip_when="Never - but set it centrally (policy / management group), not per subscription by hand.",
         effort="Set the security contact and alert notifications in Defender → Environment settings → Email notifications.",
         hours=(0.1, 0.25),
         monthly_usd=0.0,
         run_cost="No Azure cost.",
         references=(("Configure email notifications for alerts",
                      "https://learn.microsoft.com/azure/defender-for-cloud/configure-email-notifications"),)),
     steps="Add the security team's distribution list and enable notifications for High alerts to Owners.")


def match(name: str) -> Optional[AssessmentGuidance]:
    """Curated guidance for a Defender assessment display name, or None."""
    for pattern, entry in _CATALOGUE:
        if pattern.search(name or ""):
            return entry
    return None


def by_key(key: str) -> Optional[AssessmentGuidance]:
    return next((entry for _, entry in _CATALOGUE if entry.key == key), None)


def cli_for(entry: AssessmentGuidance, resource_id: str, subscription_id: str) -> Optional[str]:
    """The entry's CLI template for the resource's type, filled in; None when no template applies."""
    rid = resource_id or ""
    parts = rid.split("/")
    lowered = [p.lower() for p in parts]
    rtype = ""
    if "providers" in lowered:
        i = lowered.index("providers")
        rtype = "/".join(lowered[i + 1:i + 3])
    template = next((t for prefix, t in entry.cli.items() if prefix and rtype == prefix), entry.cli.get(ANY))
    if not template:
        return None
    rg = parts[lowered.index("resourcegroups") + 1] if "resourcegroups" in lowered else "<resource-group>"
    return template.format(rg=rg, name=parts[-1] if rtype else "<name>", id=rid, sub=subscription_id)

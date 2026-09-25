"""
Estate inventory: one architecture-level view of every subscription.

The per-subscription reports answer "what is wrong in this subscription". The
estate answers "what do we run, where, at what size, and what should change":

- inventory: one paginated Resource Graph query across all subscriptions
  (VM sizes and OS images, power state, disk SKUs and sizes, storage SKU /
  kind / tier, App Service plan SKUs, SQL SKUs, AKS versions and node pools,
  Redis SKUs, ...), normalised into categories and readable type names;
- suggestions: the findings of the per-subscription reports, joined by
  resource ID (subscription-level findings stay with the subscription);
- cost: the reports' last-30-days cost per resource.

Output: <reports>/_estate/estate.json (read by the portal's Estate page, which
filters and groups it in the browser) and <reports>/_estate/README.md (the same
overview as markdown). The inventory is kept in _estate/inventory.json so the
join can be rebuilt offline whenever a report changes.
"""

import asyncio
import json
import threading
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from scanners.base.naming import env_from_name, env_from_tags

ESTATE_DIR = "_estate"
ESTATE_FILE = "estate.json"
INVENTORY_FILE = "inventory.json"
SUBSCRIPTIONS_PER_QUERY = 1000
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_WRITE_LOCK = threading.Lock()

# Shared by the per-subscription inventory and the estate query: the properties that drive sizing decisions.
RESOURCE_DETAILS = """
| extend vmSize = tostring(properties.hardwareProfile.vmSize),
         osType = tostring(coalesce(properties.storageProfile.osDisk.osType,
                                    properties.virtualMachineProfile.storageProfile.osDisk.osType, properties.osType)),
         imageOffer = tostring(coalesce(properties.storageProfile.imageReference.offer,
                                        properties.virtualMachineProfile.storageProfile.imageReference.offer)),
         imageSku = tostring(coalesce(properties.storageProfile.imageReference.sku,
                                      properties.virtualMachineProfile.storageProfile.imageReference.sku)),
         powerState = tostring(properties.extended.instanceView.powerState.code),
         diskSizeGB = toint(properties.diskSizeGB),
         diskState = tostring(properties.diskState),
         accessTier = tostring(properties.accessTier),
         k8sVersion = tostring(properties.kubernetesVersion),
         agentPools = iff(type =~ 'microsoft.containerservice/managedclusters', properties.agentPoolProfiles, dynamic(null)),
         innerSku = trim(' ', strcat(tostring(properties.sku.name), ' ', tostring(properties.sku.family),
                                     tostring(properties.sku.capacity))),
         resourceState = tostring(coalesce(properties.state, properties.status, properties.provisioningState)),
         licenseType = tostring(coalesce(properties.licenseType, properties.sqlServerLicenseType)),
         osSku = tostring(coalesce(properties.osSku, properties.osName)),
         edition = tostring(coalesce(properties.edition, properties.sqlImageSku)),
         productVersion = tostring(properties.version),
         vCores = tostring(properties.vCore)
""" + """
| extend cfg = case(
    type in~ ('microsoft.compute/virtualmachines/extensions', 'microsoft.hybridcompute/machines/extensions'),
        pack('publisher', properties.publisher, 'ext', properties.type, 'ver', properties.typeHandlerVersion,
             'auto', properties.enableAutomaticUpgrade),
    type =~ 'microsoft.desktopvirtualization/hostpools',
        pack('pool', properties.hostPoolType, 'lb', properties.loadBalancerType, 'max', properties.maxSessionLimit,
             'app', properties.preferredAppGroupType, 'pna', properties.publicNetworkAccess),
    type =~ 'microsoft.desktopvirtualization/applicationgroups',
        pack('agtype', properties.applicationGroupType, 'hostpool', properties.hostPoolArmPath),
    type =~ 'microsoft.desktopvirtualization/workspaces',
        pack('groups', array_length(properties.applicationGroupReferences), 'pna', properties.publicNetworkAccess),
    type =~ 'microsoft.desktopvirtualization/scalingplans',
        pack('pool', properties.hostPoolType, 'tz', properties.timeZone, 'schedules', array_length(properties.schedules),
             'pools', array_length(properties.hostPoolReferences)),
    type =~ 'microsoft.compute/restorepointcollections', pack('source', properties.source.id),
    type =~ 'microsoft.compute/galleries/images/versions',
        pack('regions', array_length(properties.publishingProfile.targetRegions),
             'replicas', properties.publishingProfile.replicaCount, 'gb', properties.storageProfile.osDiskImage.sizeInGB,
             'eol', properties.publishingProfile.endOfLifeDate),
    type =~ 'microsoft.compute/galleries/images',
        pack('os', properties.osType, 'osState', properties.osState, 'gen', properties.hyperVGeneration),
    type =~ 'microsoft.compute/virtualmachinescalesets', pack('mode', properties.orchestrationMode, 'zones', zones),
    type =~ 'microsoft.compute/virtualmachines',
        pack('zones', zones, 'data', array_length(properties.storageProfile.dataDisks),
             'nics', array_length(properties.networkProfile.networkInterfaces), 'priority', properties.priority,
             'avset', properties.availabilitySet.id, 'host', properties.osProfile.computerName),
    type =~ 'microsoft.compute/images', pack('source', properties.sourceVirtualMachine.id),
    type in~ ('microsoft.web/sites', 'microsoft.web/sites/slots'),
        pack('plan', properties.serverFarmId, 'fx', coalesce(properties.siteConfig.linuxFxVersion,
             properties.siteConfig.windowsFxVersion), 'https', properties.httpsOnly),
    type =~ 'microsoft.web/certificates',
        pack('expires', properties.expirationDate, 'subject', properties.subjectName),
    type =~ 'microsoft.web/connections', pack('api', properties.api.name, 'status', properties.statuses[0].status),
    type in~ ('microsoft.app/containerapps', 'microsoft.app/jobs'),
        pack('cpu', properties.template.containers[0].resources.cpu, 'mem', properties.template.containers[0].resources.memory,
             'image', properties.template.containers[0].image, 'min', properties.template.scale.minReplicas,
             'max', properties.template.scale.maxReplicas, 'wp', properties.workloadProfileName,
             'trigger', properties.configuration.triggerType, 'running', properties.runningStatus),
    type =~ 'microsoft.app/managedenvironments',
        pack('profiles', array_length(properties.workloadProfiles), 'zr', properties.zoneRedundant),
    type =~ 'microsoft.containerinstance/containergroups',
        pack('cpu', properties.containers[0].properties.resources.requests.cpu,
             'mem', properties.containers[0].properties.resources.requests.memoryInGB,
             'n', array_length(properties.containers), 'image', properties.containers[0].properties.image,
             'st', properties.instanceView.state, 'restart', properties.restartPolicy),
    type =~ 'microsoft.sql/servers',
        pack('ver', properties.version, 'pna', properties.publicNetworkAccess, 'tls', properties.minimalTlsVersion),
    type =~ 'microsoft.documentdb/databaseaccounts',
        pack('cons', properties.consistencyPolicy.defaultConsistencyLevel, 'caps', properties.capabilities,
             'locs', array_length(properties.locations)),
    type =~ 'microsoft.azurearcdata/sqlserverinstances/databases',
        pack('mb', properties.sizeMB, 'rec', properties.recoveryMode, 'compat', properties.compatibilityLevel),
    type =~ 'microsoft.hybridcompute/machines/licenseprofiles',
        pack('sa', properties.softwareAssurance.softwareAssuranceCustomer, 'esu', properties.esuProfile.esuEligibility,
             'product', properties.productProfile.productType),
    type =~ 'microsoft.hybridcompute/machines',
        pack('agent', properties.agentVersion, 'cores', properties.detectedProperties.logicalCoreCount,
             'mfr', properties.detectedProperties.manufacturer, 'model', properties.detectedProperties.model),
    type =~ 'microsoft.network/networkinterfaces',
        pack('vm', properties.virtualMachine.id, 'pe', properties.privateEndpoint.id,
             'ip', properties.ipConfigurations[0].properties.privateIPAddress, 'accel', properties.enableAcceleratedNetworking),
    type =~ 'microsoft.network/publicipaddresses',
        pack('ip', properties.ipAddress, 'alloc', properties.publicIPAllocationMethod, 'cfg', properties.ipConfiguration.id,
             'nat', properties.natGateway.id),
    type =~ 'microsoft.network/virtualnetworks',
        pack('space', properties.addressSpace.addressPrefixes, 'subnets', array_length(properties.subnets),
             'peerings', array_length(properties.virtualNetworkPeerings)),
    type =~ 'microsoft.network/networksecuritygroups',
        pack('rules', array_length(properties.securityRules), 'subnets', array_length(properties.subnets),
             'nics', array_length(properties.networkInterfaces)),
    type =~ 'microsoft.network/privateendpoints',
        pack('target', coalesce(properties.privateLinkServiceConnections[0].properties.privateLinkServiceId,
                                properties.manualPrivateLinkServiceConnections[0].properties.privateLinkServiceId),
             'group', coalesce(properties.privateLinkServiceConnections[0].properties.groupIds[0],
                               properties.manualPrivateLinkServiceConnections[0].properties.groupIds[0]),
             'status', coalesce(properties.privateLinkServiceConnections[0].properties.privateLinkServiceConnectionState.status,
                                properties.manualPrivateLinkServiceConnections[0].properties.privateLinkServiceConnectionState.status)),
    type =~ 'microsoft.network/privatednszones',
        pack('records', properties.numberOfRecordSets, 'links', properties.numberOfVirtualNetworkLinks),
    type =~ 'microsoft.network/dnszones', pack('records', properties.numberOfRecordSets),
    type =~ 'microsoft.network/privatednszones/virtualnetworklinks',
        pack('vnet', properties.virtualNetwork.id, 'reg', properties.registrationEnabled, 'st', properties.virtualNetworkLinkState),
    type =~ 'microsoft.network/routetables',
        pack('routes', array_length(properties.routes), 'subnets', array_length(properties.subnets)),
    type =~ 'microsoft.network/loadbalancers',
        pack('fe', array_length(properties.frontendIPConfigurations), 'be', array_length(properties.backendAddressPools),
             'rules', array_length(properties.loadBalancingRules)),
    type =~ 'microsoft.network/applicationgateways',
        pack('min', properties.autoscaleConfiguration.minCapacity, 'maxc', properties.autoscaleConfiguration.maxCapacity,
             'waf', properties.firewallPolicy.id),
    type =~ 'microsoft.network/privatelinkservices', pack('conns', array_length(properties.privateEndpointConnections)),
    type =~ 'microsoft.keyvault/vaults',
        pack('rbac', properties.enableRbacAuthorization, 'purge', properties.enablePurgeProtection),
    type in~ ('microsoft.insights/metricalerts', 'microsoft.insights/scheduledqueryrules'),
        pack('sev', properties.severity, 'on', properties.enabled, 'freq', properties.evaluationFrequency),
    type =~ 'microsoft.insights/activitylogalerts', pack('on', properties.enabled),
    type =~ 'microsoft.insights/actiongroups',
        pack('on', properties.enabled, 'email', array_length(properties.emailReceivers),
             'sms', array_length(properties.smsReceivers), 'hook', array_length(properties.webhookReceivers),
             'arm', array_length(properties.armRoleReceivers), 'logic', array_length(properties.logicAppReceivers)),
    type =~ 'microsoft.insights/webtests',
        pack('kind', properties.Kind, 'freq', properties.Frequency, 'locs', array_length(properties.Locations),
             'on', properties.Enabled),
    type =~ 'microsoft.insights/components',
        pack('mode', properties.IngestionMode, 'ws', properties.WorkspaceResourceId, 'ret', properties.RetentionInDays,
             'app', properties.Application_Type),
    type =~ 'microsoft.operationalinsights/workspaces',
        pack('ret', properties.retentionInDays, 'cap', properties.workspaceCapping.dailyQuotaGb),
    type =~ 'microsoft.alertsmanagement/smartdetectoralertrules', pack('sev', properties.severity),
    type =~ 'microsoft.insights/datacollectionrules', pack('flows', array_length(properties.dataFlows)),
    type =~ 'microsoft.eventgrid/systemtopics', pack('topic', properties.topicType),
    type =~ 'microsoft.dataprotection/backupvaults', pack('redundancy', properties.storageSettings[0].type),
    type =~ 'microsoft.recoveryservices/vaults',
        pack('redundancy', properties.redundancySettings.standardTierStorageRedundancy),
    type =~ 'microsoft.storage/storageaccounts', pack('hns', properties.isHnsEnabled),
    type =~ 'microsoft.automation/automationaccounts/runbooks', pack('rtype', properties.runbookType),
    type =~ 'microsoft.devtestlab/schedules',
        pack('task', properties.taskType, 'at', properties.dailyRecurrence['time'], 'tz', properties.timeZoneId,
             'target', properties.targetResourceId),
    type =~ 'microsoft.datafactory/factories', pack('git', properties.repoConfiguration.type),
    type =~ 'microsoft.logic/workflows', pack('lsku', properties.sku.name),
    dynamic(null))
"""
DETAIL_COLUMNS = ("vmSize, osType, imageOffer, imageSku, powerState, diskSizeGB, diskState, accessTier, k8sVersion, "
                  "agentPools, innerSku, resourceState, licenseType, osSku, edition, productVersion, vCores, cfg")
ESTATE_QUERY = ("Resources" + RESOURCE_DETAILS
                + f"| project id, name, type, location, kind, sku, tags, resourceGroup, subscriptionId, managedBy, "
                  f"{DETAIL_COLUMNS}")

CATEGORY_BY_PROVIDER = {
    "microsoft.compute": "Compute",
    "microsoft.classiccompute": "Compute",
    "microsoft.desktopvirtualization": "Compute",
    "microsoft.batch": "Compute",
    "microsoft.containerservice": "Containers",
    "microsoft.containerregistry": "Containers",
    "microsoft.containerinstance": "Containers",
    "microsoft.app": "Containers",
    "microsoft.web": "Web & App Service",
    "microsoft.certificateregistration": "Web & App Service",
    "microsoft.domainregistration": "Web & App Service",
    "microsoft.storage": "Storage",
    "microsoft.classicstorage": "Storage",
    "microsoft.storagesync": "Storage",
    "microsoft.netapp": "Storage",
    "microsoft.elasticsan": "Storage",
    "microsoft.sql": "Databases",
    "microsoft.dbforpostgresql": "Databases",
    "microsoft.dbformysql": "Databases",
    "microsoft.dbformariadb": "Databases",
    "microsoft.documentdb": "Databases",
    "microsoft.cache": "Databases",
    "microsoft.network": "Networking",
    "microsoft.cdn": "Networking",
    "microsoft.classicnetwork": "Networking",
    "microsoft.cognitiveservices": "AI & Machine Learning",
    "microsoft.machinelearningservices": "AI & Machine Learning",
    "microsoft.search": "AI & Machine Learning",
    "microsoft.botservice": "AI & Machine Learning",
    "microsoft.databricks": "Analytics & Data",
    "microsoft.synapse": "Analytics & Data",
    "microsoft.datafactory": "Analytics & Data",
    "microsoft.kusto": "Analytics & Data",
    "microsoft.purview": "Analytics & Data",
    "microsoft.fabric": "Analytics & Data",
    "microsoft.powerbidedicated": "Analytics & Data",
    "microsoft.streamanalytics": "Analytics & Data",
    "microsoft.analysisservices": "Analytics & Data",
    "microsoft.datalakestore": "Analytics & Data",
    "microsoft.servicebus": "Integration & Messaging",
    "microsoft.eventhub": "Integration & Messaging",
    "microsoft.eventgrid": "Integration & Messaging",
    "microsoft.logic": "Integration & Messaging",
    "microsoft.apimanagement": "Integration & Messaging",
    "microsoft.relay": "Integration & Messaging",
    "microsoft.notificationhubs": "Integration & Messaging",
    "microsoft.signalrservice": "Integration & Messaging",
    "microsoft.communication": "Integration & Messaging",
    "microsoft.keyvault": "Security & Identity",
    "microsoft.managedidentity": "Security & Identity",
    "microsoft.security": "Security & Identity",
    "microsoft.aad": "Security & Identity",
    "microsoft.azureactivedirectory": "Security & Identity",
    "microsoft.insights": "Monitoring & Management",
    "microsoft.operationalinsights": "Monitoring & Management",
    "microsoft.operationsmanagement": "Monitoring & Management",
    "microsoft.alertsmanagement": "Monitoring & Management",
    "microsoft.automation": "Monitoring & Management",
    "microsoft.maintenance": "Monitoring & Management",
    "microsoft.dashboard": "Monitoring & Management",
    "microsoft.monitor": "Monitoring & Management",
    "microsoft.portal": "Monitoring & Management",
    "microsoft.resources": "Monitoring & Management",
    "microsoft.managedservices": "Monitoring & Management",
    "microsoft.recoveryservices": "Backup & Recovery",
    "microsoft.dataprotection": "Backup & Recovery",
    "microsoft.devices": "IoT",
    "microsoft.iotcentral": "IoT",
    "microsoft.digitaltwins": "IoT",
    "microsoft.saas": "Marketplace SaaS",
    "microsoft.hybridcompute": "Hybrid & Arc",
    "microsoft.azurearcdata": "Hybrid & Arc",
    "microsoft.kubernetes": "Hybrid & Arc",
    "microsoft.kubernetesconfiguration": "Hybrid & Arc",
    "microsoft.extendedlocation": "Hybrid & Arc",
    "microsoft.sqlvirtualmachine": "Databases",
    "microsoft.devtestlab": "Developer tools",
    "microsoft.devcenter": "Developer tools",
    "microsoft.devopsinfrastructure": "Developer tools",
    "microsoft.visualstudio": "Developer tools",
    "microsoft.loadtestservice": "Developer tools",
    "microsoft.appconfiguration": "Integration & Messaging",
    "microsoft.billingbenefits": "Billing & commitments",
    "microsoft.capacity": "Billing & commitments",
    "microsoft.resourcegraph": "Monitoring & Management",
    "microsoft.elastic": "Monitoring & Management",
    "microsoft.bing": "AI & Machine Learning",
    "microsoft.videoindexer": "AI & Machine Learning",
    "microsoft.maps": "Integration & Messaging",
    "microsoft.powerplatform": "Integration & Messaging",
    "microsoft.syntex": "AI & Machine Learning",
}
CATEGORY_BY_TYPE = {
    "microsoft.compute/disks": "Storage",
    "microsoft.compute/snapshots": "Storage",
    "microsoft.network/privatednszones": "Networking",
}
TYPE_LABELS = {
    "microsoft.compute/virtualmachines": "Virtual machine",
    "microsoft.compute/virtualmachinescalesets": "VM scale set",
    "microsoft.compute/disks": "Managed disk",
    "microsoft.compute/snapshots": "Disk snapshot",
    "microsoft.compute/images": "VM image",
    "microsoft.compute/availabilitysets": "Availability set",
    "microsoft.compute/virtualmachines/extensions": "VM extension",
    "microsoft.containerservice/managedclusters": "AKS cluster",
    "microsoft.containerregistry/registries": "Container registry",
    "microsoft.app/containerapps": "Container app",
    "microsoft.app/managedenvironments": "Container Apps environment",
    "microsoft.web/sites": "App Service / Function app",
    "microsoft.web/sites/slots": "App Service slot",
    "microsoft.web/serverfarms": "App Service plan",
    "microsoft.web/staticsites": "Static web app",
    "microsoft.web/connections": "API connection",
    "microsoft.storage/storageaccounts": "Storage account",
    "microsoft.sql/servers": "SQL server",
    "microsoft.sql/servers/databases": "SQL database",
    "microsoft.sql/servers/elasticpools": "SQL elastic pool",
    "microsoft.sql/managedinstances": "SQL managed instance",
    "microsoft.dbforpostgresql/flexibleservers": "PostgreSQL flexible server",
    "microsoft.dbformysql/flexibleservers": "MySQL flexible server",
    "microsoft.documentdb/databaseaccounts": "Cosmos DB account",
    "microsoft.cache/redis": "Azure Cache for Redis",
    "microsoft.network/virtualnetworks": "Virtual network",
    "microsoft.network/networkinterfaces": "Network interface",
    "microsoft.network/networksecuritygroups": "Network security group",
    "microsoft.network/publicipaddresses": "Public IP address",
    "microsoft.network/privateendpoints": "Private endpoint",
    "microsoft.network/privatednszones": "Private DNS zone",
    "microsoft.network/loadbalancers": "Load balancer",
    "microsoft.network/applicationgateways": "Application gateway",
    "microsoft.network/azurefirewalls": "Azure Firewall",
    "microsoft.network/bastionhosts": "Bastion",
    "microsoft.network/virtualnetworkgateways": "VPN / ExpressRoute gateway",
    "microsoft.network/frontdoors": "Front Door (classic)",
    "microsoft.cdn/profiles": "Front Door / CDN profile",
    "microsoft.network/dnszones": "Public DNS zone",
    "microsoft.network/ddosprotectionplans": "DDoS protection plan",
    "microsoft.network/natgateways": "NAT gateway",
    "microsoft.network/routetables": "Route table",
    "microsoft.network/networkwatchers": "Network Watcher",
    "microsoft.cognitiveservices/accounts": "AI Services / Azure OpenAI",
    "microsoft.machinelearningservices/workspaces": "ML / Foundry workspace",
    "microsoft.search/searchservices": "AI Search",
    "microsoft.databricks/workspaces": "Databricks workspace",
    "microsoft.synapse/workspaces": "Synapse workspace",
    "microsoft.datafactory/factories": "Data Factory",
    "microsoft.kusto/clusters": "Data Explorer cluster",
    "microsoft.servicebus/namespaces": "Service Bus namespace",
    "microsoft.eventhub/namespaces": "Event Hubs namespace",
    "microsoft.eventgrid/systemtopics": "Event Grid system topic",
    "microsoft.eventgrid/topics": "Event Grid topic",
    "microsoft.logic/workflows": "Logic app",
    "microsoft.apimanagement/service": "API Management",
    "microsoft.keyvault/vaults": "Key Vault",
    "microsoft.managedidentity/userassignedidentities": "Managed identity",
    "microsoft.insights/components": "Application Insights",
    "microsoft.insights/actiongroups": "Action group",
    "microsoft.insights/metricalerts": "Metric alert",
    "microsoft.insights/activitylogalerts": "Activity log alert",
    "microsoft.insights/scheduledqueryrules": "Log alert",
    "microsoft.insights/datacollectionrules": "Data collection rule",
    "microsoft.insights/workbooks": "Workbook",
    "microsoft.operationalinsights/workspaces": "Log Analytics workspace",
    "microsoft.operationsmanagement/solutions": "Monitoring solution",
    "microsoft.automation/automationaccounts": "Automation account",
    "microsoft.recoveryservices/vaults": "Recovery Services vault",
    "microsoft.dataprotection/backupvaults": "Backup vault",
    "microsoft.devices/iothubs": "IoT Hub",
    "microsoft.saas/resources": "Marketplace SaaS",
    "microsoft.portal/dashboards": "Portal dashboard",
    "microsoft.web/certificates": "App Service certificate",
    "microsoft.alertsmanagement/smartdetectoralertrules": "Smart detector alert",
    "microsoft.hybridcompute/machines": "Arc-enabled server",
    "microsoft.hybridcompute/machines/extensions": "Arc server extension",
    "microsoft.hybridcompute/machines/licenseprofiles": "Arc server license profile",
    "microsoft.azurearcdata/sqlserverinstances": "Arc SQL Server instance",
    "microsoft.azurearcdata/sqlserverinstances/databases": "Arc SQL Server database",
    "microsoft.kubernetes/connectedclusters": "Arc-enabled Kubernetes",
    "microsoft.sqlvirtualmachine/sqlvirtualmachines": "SQL Server on VM",
    "microsoft.insights/webtests": "Availability test",
    "microsoft.insights/autoscalesettings": "Autoscale setting",
    "microsoft.insights/datacollectionendpoints": "Data collection endpoint",
    "microsoft.network/privatednszones/virtualnetworklinks": "Private DNS zone VNet link",
    "microsoft.network/applicationsecuritygroups": "Application security group",
    "microsoft.network/privatelinkservices": "Private Link service",
    "microsoft.network/vpnsites": "VPN site",
    "microsoft.network/virtualhubs": "Virtual WAN hub",
    "microsoft.network/virtualwans": "Virtual WAN",
    "microsoft.network/publicipprefixes": "Public IP prefix",
    "microsoft.network/dnsresolvers": "DNS private resolver",
    "microsoft.network/frontdoorwebapplicationfirewallpolicies": "Front Door WAF policy",
    "microsoft.network/applicationgatewaywebapplicationfirewallpolicies": "Application Gateway WAF policy",
    "microsoft.network/connections": "VPN / ExpressRoute connection",
    "microsoft.network/localnetworkgateways": "Local network gateway",
    "microsoft.containerinstance/containergroups": "Container instance",
    "microsoft.app/jobs": "Container Apps job",
    "microsoft.automation/automationaccounts/runbooks": "Automation runbook",
    "microsoft.cognitiveservices/accounts/projects": "Foundry project",
    "microsoft.compute/sshpublickeys": "SSH public key",
    "microsoft.compute/restorepointcollections": "Restore point collection",
    "microsoft.compute/galleries": "Compute gallery",
    "microsoft.compute/galleries/images": "Gallery image definition",
    "microsoft.compute/galleries/images/versions": "Gallery image version",
    "microsoft.communication/communicationservices": "Communication Services",
    "microsoft.communication/emailservices": "Email Communication Service",
    "microsoft.communication/emailservices/domains": "Email domain",
    "microsoft.operationalinsights/querypacks": "Log Analytics query pack",
    "microsoft.botservice/botservices": "Bot service",
    "microsoft.cdn/profiles/afdendpoints": "Front Door endpoint",
    "microsoft.devtestlab/schedules": "Auto-shutdown schedule",
    "microsoft.resourcegraph/queries": "Resource Graph shared query",
    "microsoft.appconfiguration/configurationstores": "App Configuration",
    "microsoft.maintenance/maintenanceconfigurations": "Maintenance configuration",
    "microsoft.desktopvirtualization/hostpools": "AVD host pool",
    "microsoft.desktopvirtualization/applicationgroups": "AVD application group",
    "microsoft.desktopvirtualization/workspaces": "AVD workspace",
    "microsoft.desktopvirtualization/scalingplans": "AVD scaling plan",
    "microsoft.fabric/capacities": "Fabric capacity",
    "microsoft.signalrservice/signalr": "SignalR Service",
    "microsoft.notificationhubs/namespaces": "Notification Hubs namespace",
    "microsoft.devices/provisioningservices": "IoT Hub DPS",
    "microsoft.billingbenefits/maccs": "MACC commitment",
    "microsoft.billingbenefits/credits": "Azure credit",
}
# Findings about tags and naming are real, but they sit on almost every resource; keeping them apart lets
# the estate filter on suggestions that change cost, risk or architecture.
HYGIENE_TYPES = {"missing_required_tags", "naming_convention_violation", "tag_key_typo"}
AHB_LICENSES = {"windows_server", "windows_client", "rhel_byos", "sles_byos", "ahub"}
METRIC_TYPES = {"microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets"}
# Agents and settings that live *on* a machine; hidden in the estate view unless asked for.
MACHINE_SUB_RESOURCES = {"microsoft.compute/virtualmachines/extensions", "microsoft.hybridcompute/machines/extensions",
                         "microsoft.hybridcompute/machines/licenseprofiles", "microsoft.hybridcompute/machines/runcommands"}


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

def category_of(rtype: str) -> str:
    rtype = (rtype or "").lower()
    return CATEGORY_BY_TYPE.get(rtype) or CATEGORY_BY_PROVIDER.get(rtype.split("/")[0], "Other")


def type_label(rtype: str) -> str:
    rtype = (rtype or "").lower()
    if rtype in TYPE_LABELS:
        return TYPE_LABELS[rtype]
    parts = rtype.split("/")
    if len(parts) > 2 and "/".join(parts[:-1]) in TYPE_LABELS:
        return f"{TYPE_LABELS['/'.join(parts[:-1])]} › {parts[-1]}"
    return rtype.replace("microsoft.", "") or "unknown"


def _sku(row: Dict[str, Any]) -> Dict[str, Any]:
    return row.get("sku") if isinstance(row.get("sku"), dict) else {}


def _base_size(row: Dict[str, Any]) -> str:
    """The sizing that matters for each type: VM size, disk SKU + GB, storage SKU/kind/tier, plan SKU × instances..."""
    rtype = (row.get("type") or "").lower()
    sku = _sku(row)
    name, tier, capacity = sku.get("name"), sku.get("tier"), sku.get("capacity")
    if rtype == "microsoft.compute/virtualmachines":
        return row.get("vmSize") or ""
    if rtype == "microsoft.compute/virtualmachinescalesets":
        return f"{name} × {capacity}" if name and capacity is not None else (name or "")
    if rtype in ("microsoft.compute/disks", "microsoft.compute/snapshots"):
        return " ".join(x for x in (name, f"{row['diskSizeGB']} GB" if row.get("diskSizeGB") else None) if x)
    if rtype == "microsoft.storage/storageaccounts":
        return " · ".join(x for x in (name, row.get("kind"), row.get("accessTier")) if x)
    if rtype == "microsoft.web/serverfarms":
        label = f"{name} ({tier})" if name and tier and tier != name else (name or "")
        return f"{label} × {capacity}" if label and capacity else label
    if rtype == "microsoft.containerservice/managedclusters":
        pools = row.get("agentPools") or []
        nodes = sum(int(p.get("count") or 0) for p in pools)
        sizes = sorted({p.get("vmSize") for p in pools if p.get("vmSize")})
        parts = [f"k8s {row['k8sVersion']}" if row.get("k8sVersion") else None,
                 f"{len(pools)} pool(s), {nodes} node(s)" if pools else None, ", ".join(sizes) or None]
        return " · ".join(x for x in parts if x)
    if rtype == "microsoft.azurearcdata/sqlserverinstances":
        version = row.get("productVersion") or ""
        parts = [version if version.lower().startswith("sql") else (f"SQL {version}" if version else None),
                 row.get("edition") or None, f"{row['vCores']} vCores" if row.get("vCores") else None]
        return " · ".join(x for x in parts if x)
    if rtype == "microsoft.sqlvirtualmachine/sqlvirtualmachines":
        return " · ".join(x for x in (row.get("edition"), row.get("licenseType")) if x)
    if not name and row.get("innerSku"):
        return row["innerSku"]
    parts = [name, tier if tier and tier != name else None, str(capacity) if capacity not in (None, "") else None]
    return " / ".join(x for x in parts if x)


def size_of(row: Dict[str, Any]) -> str:
    """Groupable "what is it / how big": the SKU sizing, else the type's key setting (host pool type, extension...)."""
    base, extra = _base_size(row), _profile(row)["size"]
    return " · ".join(x for x in (base, extra) if x) if extra and extra not in base else base


def config_of(row: Dict[str, Any]) -> str:
    """Per-resource configuration details (attachment, counts, expiry, scale range...)."""
    config = _profile(row)["config"]
    if not config and (row.get("type") or "").lower() in KIND_IS_CONFIG and row.get("kind"):
        config = KIND_LABELS.get(str(row["kind"]).lower(), row["kind"])
    return config


# Types whose 'kind' is the key configuration fact (OpenAI vs AI Services, hub vs project, Linux vs Windows plan).
KIND_IS_CONFIG = {"microsoft.cognitiveservices/accounts", "microsoft.machinelearningservices/workspaces",
                  "microsoft.web/serverfarms", "microsoft.search/searchservices", "microsoft.botservice/botservices"}
KIND_LABELS = {"linux": "Linux", "app": "Windows", "windows": "Windows", "functionapp": "Functions (Windows)",
               "functionapp,linux": "Functions (Linux)", "elastic": "Functions Premium (elastic)",
               "workflowapp": "Logic Apps Standard", "hub": "Foundry hub", "project": "Foundry project",
               "default": "ML workspace", "openai": "Azure OpenAI", "aiservices": "AI Services (Foundry)"}


def _leaf(resource_id: Any) -> str:
    return str(resource_id or "").rstrip("/").split("/")[-1]


def _join(*parts: Any) -> str:
    return " · ".join(str(p) for p in parts if p not in (None, "", [], False))


def _count(n: Any, word: str) -> Optional[str]:
    try:
        n = int(n or 0)
    except (TypeError, ValueError):
        return None
    return f"{n} {word}{'' if n == 1 else 's'}"


def _zones(zones: Any) -> Optional[str]:
    if isinstance(zones, list) and zones:
        return ("zone " if len(zones) == 1 else "zones ") + ", ".join(str(z) for z in zones)
    return None


RUNTIME_NAMES = {"dotnetcore": ".NET", "dotnet": ".NET", "node": "Node", "python": "Python", "php": "PHP",
                 "java": "Java", "tomcat": "Tomcat", "docker": "Container", "compose": "Compose", "powershell": "PowerShell"}


def _runtime(fx: Any, kind: str) -> str:
    """'DOTNETCORE|8.0' -> '.NET 8.0'; 'DOCKER|acr.io/app:1' -> 'Container acr.io/app:1'."""
    fx = str(fx or "")
    os_name = "Linux" if "linux" in (kind or "").lower() else "Windows"
    if "|" in fx:
        stack, version = fx.split("|", 1)
        return f"{os_name} · {RUNTIME_NAMES.get(stack.lower(), stack)} {version}"
    return os_name


def _profile(row: Dict[str, Any]) -> Dict[str, str]:
    """size / config / runtime / state for types whose key facts are not in the SKU (see RESOURCE_DETAILS 'cfg')."""
    rtype = (row.get("type") or "").lower()
    c = row.get("cfg") if isinstance(row.get("cfg"), dict) else {}
    out = {"size": "", "config": "", "runtime": "", "state": ""}
    if not c:
        return out
    if rtype in ("microsoft.compute/virtualmachines/extensions", "microsoft.hybridcompute/machines/extensions"):
        out["size"] = _join(f"extension {c['ext']}" if c.get("ext") else None, c.get("ver"))
        out["config"] = _join(c.get("publisher"), "auto-upgrade" if c.get("auto") else None)
    elif rtype == "microsoft.desktopvirtualization/hostpools":
        out["size"] = _join(c.get("pool"), c.get("lb"))
        sessions = c.get("max")
        out["config"] = _join(f"max {sessions} sessions" if sessions and int(sessions) < 999999 else None, c.get("app"),
                              "private access only" if c.get("pna") == "Disabled" else None)
    elif rtype == "microsoft.desktopvirtualization/applicationgroups":
        out["size"] = c.get("agtype") or ""
        out["config"] = f"host pool {_leaf(c.get('hostpool'))}" if c.get("hostpool") else ""
    elif rtype == "microsoft.desktopvirtualization/workspaces":
        out["config"] = _join(_count(c.get("groups"), "application group"),
                              "private access only" if c.get("pna") == "Disabled" else None)
        out["state"] = "No application groups" if not c.get("groups") else ""
    elif rtype == "microsoft.desktopvirtualization/scalingplans":
        out["size"] = c.get("pool") or ""
        out["config"] = _join(_count(c.get("schedules"), "schedule"), _count(c.get("pools"), "host pool"), c.get("tz"))
        out["state"] = "No schedules" if not c.get("schedules") else ""
    elif rtype == "microsoft.compute/restorepointcollections":
        out["config"] = f"source VM {_leaf(c.get('source'))}" if c.get("source") else ""
    elif rtype == "microsoft.compute/galleries/images/versions":
        out["size"] = f"{c['gb']} GB" if c.get("gb") else ""
        out["config"] = _join(_count(c.get("regions"), "region"), _count(c.get("replicas"), "replica"),
                              f"end of life {str(c['eol'])[:10]}" if c.get("eol") else None)
    elif rtype == "microsoft.compute/galleries/images":
        out["size"] = _join(c.get("os"), c.get("gen"))
        out["config"] = c.get("osState") or ""
    elif rtype == "microsoft.compute/virtualmachinescalesets":
        out["config"] = _join(f"{c['mode']} orchestration" if c.get("mode") else None, _zones(c.get("zones")))
    elif rtype == "microsoft.compute/virtualmachines":
        nics = c.get("nics") or 0
        out["config"] = _join(_zones(c.get("zones")), _count(c.get("data"), "data disk") if c.get("data") else None,
                              _count(nics, "NIC") if nics > 1 else None,
                              "Spot" if c.get("priority") == "Spot" else None,
                              f"availability set {_leaf(c['avset'])}" if c.get("avset") else None)
    elif rtype == "microsoft.compute/images":
        out["config"] = f"from VM {_leaf(c['source'])}" if c.get("source") else ""
    elif rtype in ("microsoft.web/sites", "microsoft.web/sites/slots"):
        out["size"] = f"plan {_leaf(c.get('plan'))}" if c.get("plan") else ""
        out["config"] = "HTTPS only" if c.get("https") else "HTTP allowed"
        out["runtime"] = _runtime(c.get("fx"), row.get("kind") or "")
    elif rtype == "microsoft.web/certificates":
        expires = str(c.get("expires") or "")[:10]
        out["config"] = _join(f"expires {expires}" if expires else None, c.get("subject"))
        if expires:
            days = (datetime.fromisoformat(expires).date() - datetime.now(timezone.utc).date()).days
            out["state"] = "Expired" if days < 0 else ("Expires within 30 days" if days <= 30 else "")
    elif rtype == "microsoft.web/connections":
        out["size"] = c.get("api") or ""
        status = c.get("status") or ""
        out["state"] = "" if status in ("Connected", "Ready") else status
    elif rtype in ("microsoft.app/containerapps", "microsoft.app/jobs"):
        out["size"] = f"{c['cpu']} vCPU / {c['mem']}" if c.get("cpu") else ""
        scale = f"scale {c.get('min') or 0}-{c['max']}" if c.get("max") is not None else None
        out["config"] = _join(scale, c.get("wp"), f"{c['trigger']} trigger" if c.get("trigger") else None)
        out["runtime"] = f"Container {c['image']}" if c.get("image") else ""
        running = c.get("running") or ""
        out["state"] = "" if running in ("", "Running", "Ready") else running
    elif rtype == "microsoft.app/managedenvironments":
        out["config"] = _join(_count(c.get("profiles"), "workload profile"),
                              "zone-redundant" if c.get("zr") else None)
    elif rtype == "microsoft.containerinstance/containergroups":
        out["size"] = f"{c['cpu']} vCPU / {c['mem']} GB" if c.get("cpu") else ""
        out["config"] = _join(_count(c.get("n"), "container"),
                              f"restart {c['restart']}" if c.get("restart") else None)
        out["runtime"] = f"Container {c['image']}" if c.get("image") else ""
        out["state"] = "" if (c.get("st") or "Running") == "Running" else c["st"]
    elif rtype == "microsoft.sql/servers":
        out["size"] = f"v{c['ver']}" if c.get("ver") else ""
        out["config"] = _join(f"public access {c['pna']}" if c.get("pna") else None,
                              f"TLS {c['tls']}" if c.get("tls") else None)
    elif rtype == "microsoft.documentdb/databaseaccounts":
        caps = {str(x.get("name")) for x in (c.get("caps") or []) if isinstance(x, dict)}
        api = {"MongoDB": "MongoDB", "GlobalDocumentDB": "NoSQL", "Parse": "Parse"}.get(row.get("kind") or "", row.get("kind"))
        if "EnableCassandra" in caps:
            api = "Cassandra"
        elif "EnableTable" in caps:
            api = "Table"
        elif "EnableGremlin" in caps:
            api = "Gremlin"
        out["size"] = _join(api, "Serverless" if "EnableServerless" in caps else "Provisioned")
        out["config"] = _join(f"{c['cons']} consistency" if c.get("cons") else None, _count(c.get("locs"), "region"))
    elif rtype == "microsoft.azurearcdata/sqlserverinstances/databases":
        mb = c.get("mb")
        out["config"] = _join(f"{float(mb) / 1024:,.1f} GB" if mb else None,
                              f"{c['rec']} recovery" if c.get("rec") else None,
                              f"compat {c['compat']}" if c.get("compat") else None)
        out["size"] = f"{c['rec']} recovery" if c.get("rec") else ""
    elif rtype == "microsoft.hybridcompute/machines/licenseprofiles":
        out["size"] = c.get("product") or ""
        out["config"] = _join("Software Assurance" if c.get("sa") else "no Software Assurance",
                              f"ESU {c['esu']}" if c.get("esu") else None)
    elif rtype == "microsoft.hybridcompute/machines":
        out["size"] = f"{c['cores']} cores" if c.get("cores") else ""
        out["config"] = _join(" ".join(x for x in (c.get("mfr"), c.get("model")) if x),
                              f"agent {c['agent']}" if c.get("agent") else None)
    elif rtype == "microsoft.network/networkinterfaces":
        attached = c.get("vm") or c.get("pe")
        out["size"] = "Accelerated networking" if c.get("accel") else ""
        out["config"] = _join(f"VM {_leaf(c['vm'])}" if c.get("vm") else (f"private endpoint {_leaf(c['pe'])}"
                              if c.get("pe") else None), c.get("ip"))
        out["state"] = "Attached" if attached else "Unattached"
    elif rtype == "microsoft.network/publicipaddresses":
        out["config"] = _join(c.get("ip"), c.get("alloc"),
                              f"on {_leaf(str(c['cfg']).split('/ipConfigurations/')[0])}" if c.get("cfg") else None,
                              f"NAT gateway {_leaf(c['nat'])}" if c.get("nat") else None)
        out["state"] = "Associated" if c.get("cfg") or c.get("nat") else "Unassociated"
    elif rtype == "microsoft.network/virtualnetworks":
        space = c.get("space") or []
        out["config"] = _join(", ".join(space) if isinstance(space, list) else space,
                              _count(c.get("subnets"), "subnet"), _count(c.get("peerings"), "peering"))
    elif rtype == "microsoft.network/networksecuritygroups":
        out["config"] = _join(_count(c.get("rules"), "custom rule"), _count(c.get("subnets"), "subnet"),
                              _count(c.get("nics"), "NIC"))
        out["state"] = "Unassociated" if not c.get("subnets") and not c.get("nics") else "Associated"
    elif rtype == "microsoft.network/privateendpoints":
        out["size"] = c.get("group") or ""
        out["config"] = f"→ {_leaf(c['target'])}" if c.get("target") else ""
        status = c.get("status") or ""
        out["state"] = "" if status in ("", "Approved") else status
    elif rtype == "microsoft.network/privatednszones":
        out["config"] = _join(_count(c.get("records"), "record set"), _count(c.get("links"), "VNet link"))
        out["state"] = "No VNet links" if not c.get("links") else ""
    elif rtype == "microsoft.network/dnszones":
        out["config"] = _count(c.get("records"), "record set") or ""
    elif rtype == "microsoft.network/privatednszones/virtualnetworklinks":
        out["size"] = "Auto-registration" if c.get("reg") else ""
        out["config"] = f"VNet {_leaf(c['vnet'])}" if c.get("vnet") else ""
        out["state"] = "" if (c.get("st") or "Completed") == "Completed" else c["st"]
    elif rtype == "microsoft.network/routetables":
        out["config"] = _join(_count(c.get("routes"), "route"), _count(c.get("subnets"), "subnet"))
        out["state"] = "Unassociated" if not c.get("subnets") else ""
    elif rtype == "microsoft.network/loadbalancers":
        out["config"] = _join(_count(c.get("fe"), "frontend"), _count(c.get("be"), "backend pool"),
                              _count(c.get("rules"), "rule"))
        out["state"] = "No backend pools" if not c.get("be") else ""
    elif rtype == "microsoft.network/applicationgateways":
        out["config"] = _join(f"autoscale {c.get('min') or 0}-{c['maxc']}" if c.get("maxc") else None,
                              f"WAF policy {_leaf(c['waf'])}" if c.get("waf") else None)
    elif rtype == "microsoft.network/privatelinkservices":
        out["config"] = _count(c.get("conns"), "connection") or ""
    elif rtype == "microsoft.keyvault/vaults":
        out["config"] = _join("RBAC" if c.get("rbac") else "access policies",
                              "purge protection" if c.get("purge") else None)
    elif rtype in ("microsoft.insights/metricalerts", "microsoft.insights/scheduledqueryrules"):
        out["size"] = f"Sev {c['sev']}" if c.get("sev") is not None else ""
        out["config"] = f"every {str(c['freq']).replace('PT', '').lower()}" if c.get("freq") else ""
        out["state"] = "Disabled" if c.get("on") is False else ""
    elif rtype == "microsoft.insights/activitylogalerts":
        out["state"] = "Disabled" if c.get("on") is False else ""
    elif rtype == "microsoft.insights/actiongroups":
        receivers = [(_count(c.get(k), label)) for k, label in (("email", "email"), ("sms", "SMS"), ("hook", "webhook"),
                                                                  ("arm", "ARM role"), ("logic", "logic app")) if c.get(k)]
        out["config"] = _join(*receivers) or "no receivers"
        out["state"] = "Disabled" if c.get("on") is False else ("No receivers" if not receivers else "")
    elif rtype == "microsoft.insights/webtests":
        out["size"] = (c.get("kind") or "").title()
        out["config"] = _join(f"every {int(c['freq']) // 60} min" if c.get("freq") else None,
                              _count(c.get("locs"), "location"))
        out["state"] = "Disabled" if c.get("on") is False else ""
    elif rtype == "microsoft.insights/components":
        out["size"] = "Workspace-based" if c.get("ws") else "Classic"
        out["config"] = _join(c.get("app"), f"{c['ret']} days" if c.get("ret") else None,
                              f"workspace {_leaf(c['ws'])}" if c.get("ws") else None)
    elif rtype == "microsoft.operationalinsights/workspaces":
        cap = c.get("cap")
        out["config"] = _join(f"{c['ret']} days retention" if c.get("ret") else None,
                              f"daily cap {cap} GB" if cap not in (None, -1, -1.0) else None)
    elif rtype == "microsoft.alertsmanagement/smartdetectoralertrules":
        out["size"] = str(c.get("sev") or "").replace("Sev", "Sev ")
    elif rtype == "microsoft.insights/datacollectionrules":
        out["config"] = _count(c.get("flows"), "data flow") or ""
    elif rtype == "microsoft.eventgrid/systemtopics":
        out["size"] = c.get("topic") or ""
    elif rtype == "microsoft.dataprotection/backupvaults":
        out["size"] = c.get("redundancy") or ""
    elif rtype == "microsoft.recoveryservices/vaults":
        out["config"] = c.get("redundancy") or ""
    elif rtype == "microsoft.storage/storageaccounts":
        out["config"] = "ADLS Gen2 (hierarchical namespace)" if c.get("hns") else ""
    elif rtype == "microsoft.automation/automationaccounts/runbooks":
        out["size"] = c.get("rtype") or ""
    elif rtype == "microsoft.devtestlab/schedules":
        at = str(c.get("at") or "")
        out["size"] = c.get("task") or ""
        out["config"] = _join(f"{at[:2]}:{at[2:]}" if len(at) == 4 else at or None, c.get("tz"),
                              _leaf(c.get("target")) if c.get("target") else None)
    elif rtype == "microsoft.datafactory/factories":
        out["config"] = f"Git: {c['git']}" if c.get("git") else "no Git integration"
    elif rtype == "microsoft.logic/workflows":
        out["size"] = c.get("lsku") or "Consumption"
    return out


def os_of(row: Dict[str, Any]) -> str:
    """OS image (+ Azure Hybrid Benefit) for machines; runtime stack or container image for apps."""
    offer, sku = row.get("imageOffer") or "", row.get("imageSku") or ""
    image = " ".join(x for x in (offer, sku) if x) or row.get("osSku") or ""
    os_type = row.get("osType") or ""
    label = f"{os_type} ({image})" if image and os_type else (os_type or image)
    if label and (row.get("licenseType") or "").lower() in AHB_LICENSES:
        label += " · AHB"
    return label or _profile(row)["runtime"]


def state_of(row: Dict[str, Any]) -> str:
    power = row.get("powerState") or ""
    if power:
        return power.split("/")[-1]
    if row.get("diskState"):
        return row["diskState"]
    derived = _profile(row)["state"]
    if derived:
        return derived
    state = row.get("resourceState") or ""
    return "" if state.lower() in ("succeeded", "ready", "running", "online") else state


def environment_of(row: Dict[str, Any]) -> str:
    env = env_from_tags(row.get("tags")) or env_from_name(row.get("name") or "")
    if not env:
        env = env_from_name(row.get("resourceGroup") or "")
    return {"prod": "Production", "nonprod": "Non-production"}.get(env or "", "Unknown")


def display_name(row: Dict[str, Any]) -> str:
    """Child resources read like the Azure portal: 'vm-app-01 › DSC' instead of just 'DSC'."""
    rtype = (row.get("type") or "").lower()
    parts = (row.get("id") or "").rstrip("/").split("/")
    if rtype.count("/") >= 2 and len(parts) >= 3 and parts[-1]:
        return f"{parts[-3]} › {parts[-1]}"
    return row.get("name") or ""


def normalise(row: Dict[str, Any], sub_names: Dict[str, str]) -> Dict[str, Any]:
    rtype = (row.get("type") or "").lower()
    id_parts = (row.get("id") or "").split("/")
    sub_id = (row.get("subscriptionId") or (id_parts[2] if len(id_parts) > 2 else "")).lower()
    rg = row.get("resourceGroup") or (id_parts[4] if len(id_parts) > 4 else "")
    return {
        "id": row.get("id") or "",
        "name": display_name(row),
        "type": rtype,
        "typeLabel": type_label(rtype),
        "category": category_of(rtype),
        "subResource": rtype in MACHINE_SUB_RESOURCES,
        "subscriptionId": sub_id,
        "subscription": sub_names.get(sub_id) or sub_id,
        "resourceGroup": rg,
        "location": (row.get("location") or "").lower(),
        "kind": row.get("kind") or "",
        "size": size_of(row),
        "config": config_of(row),
        "os": os_of(row),
        "state": state_of(row),
        "env": environment_of(row),
        "managedBy": row.get("managedBy") or "",
        "sizeGB": int(row["diskSizeGB"]) if str(row.get("diskSizeGB") or "").isdigit() else None,
        "vcpu": row.get("vcpu"),
        "ramGB": row.get("ramGB"),
        "cpuAvg": row.get("cpuAvg"),
        "cpuMax": row.get("cpuMax"),
        "memAvg": row.get("memAvg"),
        "tags": row.get("tags") if isinstance(row.get("tags"), dict) else {},
    }


# ---------------------------------------------------------------------------
# Live inventory (Resource Graph, all subscriptions)
# ---------------------------------------------------------------------------

async def query_estate(credential: Any, subscription_ids: List[str], page_size: int = 1000) -> List[Dict[str, Any]]:
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

    client = ResourceGraphClient(credential)
    rows: List[Dict[str, Any]] = []
    for i in range(0, len(subscription_ids), SUBSCRIPTIONS_PER_QUERY):
        batch = subscription_ids[i:i + SUBSCRIPTIONS_PER_QUERY]
        skip_token: Optional[str] = None
        while True:
            request = QueryRequest(subscriptions=batch, query=ESTATE_QUERY, options=QueryRequestOptions(
                result_format="objectArray", top=page_size, skip_token=skip_token))
            response = await asyncio.to_thread(client.resources, request)
            rows.extend(response.data or [])
            skip_token = getattr(response, "skip_token", None)
            if not skip_token:
                break
    for row in rows:
        if row.get("agentPools"):
            row["agentPools"] = [{k: p.get(k) for k in ("name", "vmSize", "count", "mode", "osType")}
                                 for p in row["agentPools"] if isinstance(p, dict)]
    return rows


def collect_inventory(credential: Any, subscriptions: List[Dict[str, Any]]) -> Dict[str, Any]:
    ids = [s["id"] for s in subscriptions]
    rows = asyncio.run(query_estate(credential, ids)) if ids else []
    if rows:
        asyncio.run(enrich_compute(credential, rows))
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "source": "resource-graph",
            "subscriptions": [{"id": s["id"].lower(), "name": s.get("name")} for s in subscriptions],
            "resources": rows}


async def enrich_compute(credential: Any, rows: List[Dict[str, Any]], days: int = 30, concurrency: int = 8) -> None:
    """
    vCPU / RAM from the Compute SKU catalogue (one call per region) and the 30-day average CPU % and memory used %
    from Azure Monitor platform metrics ('Percentage CPU', 'Available Memory Bytes') for VMs and scale sets.
    Deallocated VMs have no metrics and are skipped. Failures leave the fields empty.
    """
    from scanners.base.azure_api import ArmClient, gather_limited

    targets = [r for r in rows if (r.get("type") or "").lower() in METRIC_TYPES]
    if not targets:
        return
    arm = ArmClient(credential)
    try:
        specs: Dict[Any, Any] = {}
        regions: Dict[str, str] = {}
        for r in targets:
            regions.setdefault((r.get("location") or "").lower(), r.get("subscriptionId") or "")
        for location, sub in regions.items():
            try:
                skus = await arm.get_all(f"/subscriptions/{sub}/providers/Microsoft.Compute/skus", "2021-07-01",
                                         {"$filter": f"location eq '{location}'"})
            except Exception:
                continue
            for s in skus:
                if s.get("resourceType") != "virtualMachines":
                    continue
                caps = {c.get("name"): c.get("value") for c in s.get("capabilities") or []}
                try:
                    spec = (int(caps["vCPUs"]), float(caps["MemoryGB"]))
                except (KeyError, TypeError, ValueError):
                    continue
                specs[(location, s["name"].lower())] = spec
                specs.setdefault(s["name"].lower(), spec)

        async def one(r: Dict[str, Any]) -> None:
            size = (r.get("vmSize") or (r.get("sku") or {}).get("name") or "").lower()
            spec = specs.get(((r.get("location") or "").lower(), size)) or specs.get(size)
            if spec:
                r["vcpu"], r["ramGB"] = spec
            if (r.get("powerState") or "").split("/")[-1] in ("deallocated", "stopped"):
                return
            try:
                m = await arm.metrics_summary(r["id"], ["Percentage CPU", "Available Memory Bytes"], days=days,
                                              interval="P1D", aggregation="Average,Maximum")
            except Exception:
                return
            cpu = m.get("Percentage CPU") or {}
            if cpu.get("average") is not None:
                r["cpuAvg"], r["cpuMax"] = round(cpu["average"], 1), round(cpu.get("maximum") or 0.0, 1)
            available = (m.get("Available Memory Bytes") or {}).get("average")
            if available is not None and spec and spec[1]:
                r["memAvg"] = round(min(100.0, max(0.0, 100 * (1 - available / (spec[1] * 1024 ** 3)))), 1)

        await gather_limited(targets, one, concurrency)
    finally:
        arm.close()


# ---------------------------------------------------------------------------
# Join with the per-subscription reports
# ---------------------------------------------------------------------------

def _load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _reports(reports_dir: Path) -> Dict[str, Dict[str, Any]]:
    """sub_id -> {folder, name, generated_at, currency, findings, costs, resources} from each report folder."""
    from scripts.subscription_analysis.report import SUMMARY_FILE

    result: Dict[str, Dict[str, Any]] = {}
    if not reports_dir.is_dir():
        return result
    for child in sorted(p for p in reports_dir.iterdir() if p.is_dir() and p.name != ESTATE_DIR):
        summary = _load_json(child / SUMMARY_FILE, None)
        if not summary:
            continue
        sub = summary.get("subscription") or {}
        raw = child / "05-deep-dive" / "raw"
        result[(sub.get("id") or "").lower()] = {
            "folder": child.name, "name": sub.get("name"), "generated_at": summary.get("generated_at"),
            "currency": summary.get("currency") or "",
            "findings": _load_json(raw / "findings.json", []),
            "costs": _load_json(raw / "cost" / "last30_by_resource.json", {}),
            "resources": _load_json(raw / "inventory" / "resources.json", []),
        }
    return result


def _suggestion(f: Dict[str, Any], sub_id: str, folder: str, resource: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "ref": f.get("ref"), "title": f.get("title"), "severity": (f.get("severity") or "info").lower(),
        "type": f.get("finding_type"), "area": f.get("area"), "wave": f.get("wave"),
        "hygiene": f.get("finding_type") in HYGIENE_TYPES,
        "savingsUsd": f.get("estimated_monthly_savings_usd"),
        "link": f"/reports/{folder}/05-deep-dive/{f['folder']}/README.md" if f.get("folder") else f"/reports/{folder}/README.md",
        "subscriptionId": sub_id, "resourceId": (resource or {}).get("id") or "",
        "resourceName": (resource or {}).get("name") or f.get("resource_name") or "(subscription)",
        "category": (resource or {}).get("category") or "Subscription",
        "typeLabel": (resource or {}).get("typeLabel") or "Subscription",
    }


def build_estate(reports_dir: Path, inventory: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Join the inventory with the reports. Without a live inventory (none passed and no _estate/inventory.json),
    the reports' own resources.json files are used, so the estate always covers every analysed subscription.
    """
    reports = _reports(reports_dir)
    if inventory is None:
        inventory = _load_json(reports_dir / ESTATE_DIR / INVENTORY_FILE, None)
    if inventory is None:
        inventory = {"generated_at": None, "source": "reports",
                     "subscriptions": [{"id": k, "name": v["name"]} for k, v in reports.items()],
                     "resources": [r for v in reports.values() for r in v["resources"]]}

    sub_names = {s["id"].lower(): s.get("name") or s["id"] for s in inventory.get("subscriptions") or []}
    sub_names.update({k: v["name"] for k, v in reports.items() if v.get("name")})
    resources = [normalise(r, sub_names) for r in inventory.get("resources") or [] if r.get("id")]
    by_id = {r["id"].lower(): r for r in resources}

    suggestions: List[Dict[str, Any]] = []
    for sub_id, rep in reports.items():
        costs = {k.lower(): v for k, v in (rep["costs"] or {}).items()}
        for rid, entry in costs.items():
            if rid in by_id:
                by_id[rid]["cost30"] = round(float(entry.get("cost") or 0.0), 2)
                by_id[rid]["currency"] = entry.get("currency") or rep["currency"]
        for f in rep["findings"]:
            resource = by_id.get((f.get("resource_id") or "").lower())
            suggestions.append(_suggestion(f, sub_id, rep["folder"], resource))

    counts: Dict[str, Counter] = defaultdict(Counter)
    hygiene: Counter = Counter()
    for s in suggestions:
        if not s["resourceId"]:
            continue
        if s["hygiene"]:
            hygiene[s["resourceId"].lower()] += 1
        else:
            counts[s["resourceId"].lower()][s["severity"]] += 1
    for r in resources:
        c = counts.get(r["id"].lower())
        r["suggestions"] = sum(c.values()) if c else 0
        r["hygiene"] = hygiene.get(r["id"].lower(), 0)
        r["maxSeverity"] = next((s for s in SEVERITY_ORDER if c and c.get(s)), "")
        r["folder"] = (reports.get(r["subscriptionId"]) or {}).get("folder") or ""

    subscriptions = []
    for sub_id in sorted(set(sub_names) | set(reports), key=lambda k: (sub_names.get(k) or k).lower()):
        rep = reports.get(sub_id) or {}
        subscriptions.append({
            "id": sub_id, "name": sub_names.get(sub_id) or sub_id, "folder": rep.get("folder") or "",
            "analysedAt": rep.get("generated_at"), "currency": rep.get("currency") or "",
            "resources": sum(1 for r in resources if r["subscriptionId"] == sub_id),
            "suggestions": sum(1 for s in suggestions if s["subscriptionId"] == sub_id),
        })
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inventory_at": inventory.get("generated_at"),
        "source": inventory.get("source") or "reports",
        "subscriptions": subscriptions,
        "resources": sorted(resources, key=lambda r: (r["category"], r["typeLabel"], r["subscription"].lower(), r["name"].lower())),
        "suggestions": suggestions,
    }


def compact(estate: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wire format for estate.json: subscriptions and types are listed once and referenced by index, empty fields
    are dropped and report links are rebuilt in the browser - about half the size of the expanded form.
    """
    sub_index = {s["id"]: i for i, s in enumerate(estate["subscriptions"])}
    types: Dict[str, Dict[str, str]] = {}
    res_index: Dict[str, int] = {}
    resources = []
    for i, r in enumerate(estate["resources"]):
        res_index[r["id"].lower()] = i
        types.setdefault(r["type"], {"label": r["typeLabel"], "category": r["category"]})
        row = {"id": r["id"], "name": r["name"], "type": r["type"], "s": sub_index.get(r["subscriptionId"], -1),
               "rg": r["resourceGroup"], "loc": r["location"], "kind": r["kind"], "size": r["size"],
               "cfg": r.get("config"), "os": r["os"],
               "state": r["state"], "env": r["env"], "mb": r["managedBy"], "gb": r.get("sizeGB"), "tags": r["tags"],
               "vcpu": r.get("vcpu"), "ram": r.get("ramGB"), "cpu": r.get("cpuAvg"), "cpuMax": r.get("cpuMax"),
               "mem": r.get("memAvg"), "sub": 1 if r.get("subResource") else None,
               "cost": r.get("cost30"), "cur": r.get("currency"), "n": r["suggestions"], "h": r.get("hygiene"),
               "sev": r["maxSeverity"]}
        resources.append({k: v for k, v in row.items()
                          if v not in (None, "", {}, 0) or k == "s" or (k in ("cpu", "cpuMax", "mem") and v is not None)})
    suggestions = []
    for s in estate["suggestions"]:
        link = s["link"]
        area = link.split("/05-deep-dive/")[1].split("/")[0] if "/05-deep-dive/" in link else ""
        row = {"ref": s["ref"], "title": s["title"], "sev": s["severity"], "type": s["type"], "wave": s["wave"],
               "usd": s["savingsUsd"], "r": res_index.get((s["resourceId"] or "").lower()),
               "s": sub_index.get(s["subscriptionId"], -1), "af": area, "hy": 1 if s["hygiene"] else None,
               "name": None if s["resourceId"] else s["resourceName"]}
        suggestions.append({k: v for k, v in row.items() if v not in (None, "") or k == "s"})
    return {"format": 2, "generated_at": estate["generated_at"], "inventory_at": estate["inventory_at"],
            "source": estate["source"], "subscriptions": estate["subscriptions"], "types": types,
            "resources": resources, "suggestions": suggestions}


def write_estate(reports_dir: Path, estate: Dict[str, Any], inventory: Optional[Dict[str, Any]] = None) -> Path:
    folder = reports_dir / ESTATE_DIR
    folder.mkdir(parents=True, exist_ok=True)
    if inventory is not None:
        (folder / INVENTORY_FILE).write_text(json.dumps(inventory, default=str), encoding="utf-8")
    (folder / ESTATE_FILE).write_text(json.dumps(compact(estate), default=str, ensure_ascii=False,
                                                 separators=(",", ":")), encoding="utf-8")
    (folder / "README.md").write_text(render_estate_markdown(estate) + "\n", encoding="utf-8")
    return folder


def refresh_estate(reports_dir: Path, credential: Any = None,
                   subscriptions: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Live refresh (Resource Graph) when a credential and subscriptions are given, else re-join offline."""
    inventory = collect_inventory(credential, subscriptions) if credential is not None and subscriptions else None
    with _WRITE_LOCK:
        estate = build_estate(reports_dir, inventory)
        write_estate(reports_dir, estate, inventory)
    return estate


# ---------------------------------------------------------------------------
# Markdown overview
# ---------------------------------------------------------------------------

def _table(headers: List[str], rows: Iterable[Iterable[Any]], align: Optional[List[str]] = None) -> str:
    from scripts.subscription_analysis.report import md_table

    return md_table(headers, rows, align)


def _cost_label(values: Iterable[Dict[str, Any]]) -> str:
    totals: Dict[str, float] = defaultdict(float)
    for r in values:
        if r.get("cost30"):
            totals[r.get("currency") or ""] += r["cost30"]
    return " + ".join(f"{v:,.0f} {k}".strip() for k, v in sorted(totals.items(), key=lambda kv: -kv[1])) or "-"


def _sizes(resources: List[Dict[str, Any]], rtype: str, title: str, extra=None, key: str = "size",
           key_label: str = "Size / SKU") -> List[str]:
    items = [r for r in resources if r["type"] == rtype]
    if not items:
        return []
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in items:
        groups[r[key] or "(not reported)"].append(r)
    headers = [key_label, "Count", "Subscriptions"] + ([h for h, _ in extra] if extra else []) + ["Last 30 days"]
    rows = []
    for size, group in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        rows.append([size, len(group), len({r["subscriptionId"] for r in group})]
                    + ([fn(group) for _, fn in extra] if extra else []) + [_cost_label(group)])
    return [f"### {title} ({len(items)})", "",
            _table(headers, rows, ["---", "---:", "---:"] + ["---"] * len(extra or []) + ["---:"]), ""]


CPU_BANDS = [(5, "under 5 %"), (20, "5-20 %"), (50, "20-50 %"), (80, "50-80 %"), (101, "80 % and more")]


def cpu_band(value: Optional[float]) -> str:
    if value is None:
        return "no data"
    return next(label for limit, label in CPU_BANDS if value < limit)


def _utilisation(resources: List[Dict[str, Any]]) -> List[str]:
    """Running VMs by 30-day average CPU, and the largest ones that barely use their CPU (right-sizing candidates)."""
    vms = [r for r in resources if r["type"] == "microsoft.compute/virtualmachines" and r["state"] == "running"]
    if not vms:
        return []
    bands = Counter(cpu_band(r.get("cpuAvg")) for r in vms)
    order = [label for _, label in CPU_BANDS] + ["no data"]
    idle = sorted((r for r in vms if r.get("cpuAvg") is not None and r["cpuAvg"] < 5 and (r.get("vcpu") or 0) >= 4),
                  key=lambda r: (-(r.get("vcpu") or 0), r["cpuAvg"]))
    lines = ["### Running VMs by average CPU (last 30 days)", "",
             _table(["Average CPU", "VMs"], [[b, bands[b]] for b in order if bands.get(b)], ["---", "---:"]), ""]
    if idle:
        lines += [f"### Right-sizing candidates: {len(idle)} running VM(s) with 4+ vCPU and under 5 % average CPU", "",
                  _table(["VM", "Size", "vCPU / RAM", "Avg CPU", "Peak CPU", "Avg memory", "Subscription"], [
                      [r["name"], r["size"], f"{r['vcpu']} / {r['ramGB']:g} GB", f"{r['cpuAvg']} %",
                       f"{r.get('cpuMax')} %" if r.get("cpuMax") is not None else "-",
                       f"{r['memAvg']} %" if r.get("memAvg") is not None else "-", r["subscription"]]
                      for r in idle[:25]], ["---", "---", "---", "---:", "---:", "---:", "---"]),
                  "", "_Check the peak and memory before downsizing: a low average can hide batch jobs._", ""]
    return lines


def render_estate_markdown(estate: Dict[str, Any]) -> str:
    resources, suggestions = estate["resources"], estate["suggestions"]
    subs = estate["subscriptions"]
    actionable = [s for s in suggestions if not s["hygiene"]]
    sev = Counter(s["severity"] for s in actionable)
    inventory_note = (f"live Resource Graph inventory of {str(estate.get('inventory_at'))[:16].replace('T', ' ')} UTC"
                      if estate.get("source") == "resource-graph" else "inventory taken from the subscription reports")
    lines = [
        "# Estate Inventory", "",
        "[← All subscriptions](../README.md)", "",
        f"Every resource across {len(subs)} subscription(s), grouped by what it is, how it is sized and what the "
        f"reports suggest - {inventory_note}. **Filter, sort and drill down interactively on the local portal's "
        f"[Estate](/estate) page.** Raw data: [estate.json](./estate.json).", "",
        "## Overview", "",
        _table(["Metric", "Value"], [
            ["Resources", f"{len(resources):,}"],
            ["Subscriptions", len(subs)],
            ["Regions", len({r["location"] for r in resources if r["location"]})],
            ["Resource types", len({r["type"] for r in resources})],
            ["Resources with actionable suggestions", f"{sum(1 for r in resources if r['suggestions']):,}"],
            ["Actionable suggestions (critical / high / medium / low)",
             f"{sev.get('critical', 0)} / {sev.get('high', 0)} / {sev.get('medium', 0)} / {sev.get('low', 0)}"],
            ["Tag / naming hygiene findings (listed separately)", f"{len(suggestions) - len(actionable):,}"],
            ["Last 30 days (resources with cost data)", _cost_label(resources)],
        ]), "",
        "## By category", "",
    ]
    by_cat: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in resources:
        by_cat[r["category"]].append(r)
    lines.append(_table(["Category", "Resources", "Types", "Subscriptions", "With suggestions", "Last 30 days"], [
        [c, len(g), len({r["type"] for r in g}), len({r["subscriptionId"] for r in g}),
         sum(1 for r in g if r["suggestions"]), _cost_label(g)]
        for c, g in sorted(by_cat.items(), key=lambda kv: -len(kv[1]))
    ], ["---", "---:", "---:", "---:", "---:", "---:"]))

    by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in resources:
        by_type[r["type"]].append(r)
    lines += ["", "## Top resource types", "", _table(
        ["Type", "Category", "Count", "Subscriptions", "Regions", "With suggestions", "Last 30 days"], [
            [g[0]["typeLabel"], g[0]["category"], len(g), len({r["subscriptionId"] for r in g}),
             len({r["location"] for r in g}), sum(1 for r in g if r["suggestions"]), _cost_label(g)]
            for t, g in sorted(by_type.items(), key=lambda kv: -len(kv[1]))[:30]
        ], ["---", "---", "---:", "---:", "---:", "---:", "---:"]), ""]

    def running(group):
        states = Counter(r["state"] or "?" for r in group)
        return ", ".join(f"{k} {v}" for k, v in states.most_common())

    def os_mix(group):
        return ", ".join(f"{k} {v}" for k, v in Counter((r["os"] or "?").split(" (")[0] for r in group).most_common())

    def total_gb(group):
        return f"{sum(r.get('sizeGB') or 0 for r in group):,} GB"

    def unattached(group):
        return sum(1 for r in group if r["state"].lower() == "unattached")

    def spec(group):
        r = group[0]
        return f"{r['vcpu']} vCPU / {r['ramGB']:g} GB" if r.get("vcpu") else "-"

    def avg_of(key):
        def fn(group):
            values = [r[key] for r in group if r.get(key) is not None]
            return f"{sum(values) / len(values):.1f} %" if values else "-"
        return fn

    lines += ["## Sizing - what we run", ""]
    lines += _sizes(resources, "microsoft.compute/virtualmachines", "Virtual machines by size",
                    [("vCPU / RAM", spec), ("Avg CPU (30 d)", avg_of("cpuAvg")), ("Avg memory (30 d)", avg_of("memAvg")),
                     ("Power state", running), ("OS", os_mix)])
    lines += _sizes(resources, "microsoft.compute/virtualmachinescalesets", "VM scale sets by SKU × instances",
                    [("Avg CPU (30 d)", avg_of("cpuAvg"))])
    lines += _sizes(resources, "microsoft.containerservice/managedclusters", "AKS clusters")
    lines += _sizes(resources, "microsoft.web/serverfarms", "App Service plans by SKU × instances")
    lines += _sizes(resources, "microsoft.sql/servers/databases", "SQL databases by SKU")
    lines += _sizes(resources, "microsoft.sql/servers/elasticpools", "SQL elastic pools by SKU")
    lines += _sizes(resources, "microsoft.dbforpostgresql/flexibleservers", "PostgreSQL flexible servers by SKU")
    lines += _sizes(resources, "microsoft.cache/redis", "Redis caches by SKU")
    lines += _sizes(resources, "microsoft.storage/storageaccounts", "Storage accounts by SKU · kind · tier")
    lines += _sizes(resources, "microsoft.compute/disks", "Managed disks by SKU and size",
                    [("Total", total_gb), ("Unattached", unattached)])
    lines += _sizes(resources, "microsoft.cognitiveservices/accounts", "AI Services / Azure OpenAI by SKU")
    lines += _sizes(resources, "microsoft.hybridcompute/machines", "Arc-enabled servers by OS", [("Status", running)],
                    key="os", key_label="OS")
    lines += _sizes(resources, "microsoft.azurearcdata/sqlserverinstances",
                    "Arc SQL Server instances by version · edition · vCores")
    lines += _sizes(resources, "microsoft.sqlvirtualmachine/sqlvirtualmachines", "SQL Server on VMs by edition · license")
    lines += _utilisation(resources)

    regions = Counter(r["location"] or "(none)" for r in resources)
    envs = Counter(r["env"] for r in resources)
    lines += ["## Regions and environments", "",
              _table(["Region", "Resources", "Subscriptions"], [
                  [loc, n, len({r["subscriptionId"] for r in resources if (r["location"] or "(none)") == loc})]
                  for loc, n in regions.most_common()], ["---", "---:", "---:"]), "",
              _table(["Environment (from tags / names)", "Resources"], [[e, n] for e, n in envs.most_common()],
                     ["---", "---:"]), ""]

    by_finding: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for s in suggestions:
        by_finding[s["type"] or "?"].append(s)
    lines += ["## Most common suggestions", "", _table(
        ["Suggestion type", "Worst severity", "Count", "Subscriptions", "Est. saving / month (USD)"], [
            [t, next((x for x in SEVERITY_ORDER if any(s["severity"] == x for s in g)), ""), len(g),
             len({s["subscriptionId"] for s in g}),
             f"{sum(s['savingsUsd'] or 0 for s in g):,.0f}" if any(s["savingsUsd"] for s in g) else "-"]
            for t, g in sorted(by_finding.items(), key=lambda kv: (SEVERITY_ORDER.index(
                next((x for x in SEVERITY_ORDER if any(s["severity"] == x for s in kv[1])), "info")), -len(kv[1])))[:40]
        ], ["---", "---", "---:", "---:", "---:"]), ""]

    lines += ["## Subscriptions", "", _table(
        ["Subscription", "Resources", "Suggestions", "Analysed"], [
            [f"[{s['name']}](../{s['folder']}/README.md)" if s["folder"] else s["name"], s["resources"],
             s["suggestions"], str(s.get("analysedAt") or "not analysed")[:10]]
            for s in sorted(subs, key=lambda s: -s["resources"])
        ], ["---", "---:", "---:", "---"]), ""]
    from scripts.subscription_analysis.report import BRAND_CREDIT

    lines += [f"_{BRAND_CREDIT}._"]
    return "\n".join(lines)

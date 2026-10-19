"""
Azure resource type -> official Microsoft Azure architecture icon and the service name shown next to it.

The icons (scripts/subscription_analysis/azure_icons/, copied unchanged from Microsoft's Azure Public Service Icons
V24, https://learn.microsoft.com/azure/architecture/icons/) may only represent the service they were designed for,
must not be altered, and are always labelled with the service name - see azure_icons/NOTICE.md.
"""

from typing import Dict, Optional, Tuple

# icon file stem (pack name without its number prefix) per resource type, and the label shown under it
TYPE_ICONS: Dict[str, Tuple[str, str]] = {
    # compute
    "microsoft.compute/virtualmachines": ("Virtual-Machine", "Virtual machines"),
    "microsoft.compute/virtualmachinescalesets": ("VM-Scale-Sets", "VM scale sets"),
    "microsoft.compute/disks": ("Disks", "Managed disks"),
    "microsoft.compute/snapshots": ("Disks-Snapshots", "Disk snapshots"),
    "microsoft.compute/availabilitysets": ("Availability-Sets", "Availability sets"),
    "microsoft.compute/galleries": ("Azure-Compute-Galleries", "Compute galleries"),
    "microsoft.compute/images": ("Images", "Images"),
    "microsoft.compute/diskencryptionsets": ("Disk-Encryption-Sets", "Disk encryption sets"),
    "microsoft.compute/hostgroups": ("Host-Groups", "Host groups"),
    "microsoft.compute/proximityplacementgroups": ("Proximity-Placement-Groups", "Proximity placement groups"),
    "microsoft.batch/batchaccounts": ("Batch-Accounts", "Batch accounts"),
    "microsoft.desktopvirtualization/hostpools": ("Host-Pools", "Host pools"),
    # containers
    "microsoft.containerservice/managedclusters": ("Kubernetes-Services", "Kubernetes services"),
    "microsoft.containerregistry/registries": ("Container-Registries", "Container registries"),
    "microsoft.containerinstance/containergroups": ("Container-Instances", "Container instances"),
    "microsoft.app/managedenvironments": ("Container-Apps-Environments", "Container Apps environments"),
    "microsoft.redhatopenshift/openshiftclusters": ("Azure-Red-Hat-OpenShift", "Azure Red Hat OpenShift"),
    # web
    "microsoft.web/sites": ("App-Services", "App Services"),
    "microsoft.web/sites#functionapp": ("Function-Apps", "Function Apps"),
    "microsoft.web/sites#workflowapp": ("Logic-Apps", "Logic Apps (Standard)"),
    "microsoft.web/serverfarms": ("App-Service-Plans", "App Service plans"),
    "microsoft.web/staticsites": ("Static-Apps", "Static Web Apps"),
    "microsoft.web/certificates": ("App-Service-Certificates", "App Service certificates"),
    "microsoft.web/hostingenvironments": ("App-Service-Environments", "App Service environments"),
    "microsoft.signalrservice/signalr": ("SignalR", "SignalR"),
    "microsoft.notificationhubs/namespaces": ("Notification-Hub-Namespaces", "Notification Hub namespaces"),
    "microsoft.apimanagement/service": ("API-Management-Services", "API Management"),
    "microsoft.cdn/profiles": ("Front-Door-and-CDN-Profiles", "Front Door and CDN profiles"),
    "microsoft.network/frontdoors": ("Front-Door-and-CDN-Profiles", "Front Door"),
    # storage
    "microsoft.storage/storageaccounts": ("Storage-Accounts", "Storage accounts"),
    "microsoft.netapp/netappaccounts": ("Azure-NetApp-Files", "Azure NetApp Files"),
    "microsoft.storagesync/storagesyncservices": ("Storage-Sync-Services", "Storage Sync services"),
    "microsoft.recoveryservices/vaults": ("Recovery-Services-Vaults", "Recovery Services vaults"),
    "microsoft.dataprotection/backupvaults": ("Backup-Vault", "Backup vaults"),
    # databases & analytics
    "microsoft.sql/servers": ("SQL-Server", "SQL servers"),
    "microsoft.sql/servers/databases": ("SQL-Database", "SQL databases"),
    "microsoft.sql/servers/elasticpools": ("SQL-Elastic-Pools", "SQL elastic pools"),
    "microsoft.sql/managedinstances": ("SQL-Managed-Instance", "SQL managed instances"),
    "microsoft.sqlvirtualmachine/sqlvirtualmachines": ("Azure-SQL-VM", "SQL virtual machines"),
    "microsoft.documentdb/databaseaccounts": ("Azure-Cosmos-DB", "Azure Cosmos DB"),
    "microsoft.dbforpostgresql/flexibleservers": ("Azure-Database-PostgreSQL-Server", "PostgreSQL flexible servers"),
    "microsoft.dbforpostgresql/servers": ("Azure-Database-PostgreSQL-Server", "PostgreSQL servers"),
    "microsoft.dbformysql/flexibleservers": ("Azure-Database-MySQL-Server", "MySQL flexible servers"),
    "microsoft.cache/redis": ("Cache-Redis", "Azure Cache for Redis"),
    "microsoft.cache/redisenterprise": ("Azure-Managed-Redis", "Azure Managed Redis"),
    "microsoft.kusto/clusters": ("Azure-Data-Explorer-Clusters", "Data Explorer clusters"),
    "microsoft.datafactory/factories": ("Data-Factories", "Data factories"),
    "microsoft.databricks/workspaces": ("Azure-Databricks", "Azure Databricks"),
    "microsoft.synapse/workspaces": ("Azure-Synapse-Analytics", "Azure Synapse Analytics"),
    "microsoft.streamanalytics/streamingjobs": ("Stream-Analytics-Jobs", "Stream Analytics jobs"),
    "microsoft.timeseriesinsights/environments": ("Time-Series-Insights-Environments", "Time Series Insights"),
    # integration & IoT
    "microsoft.eventhub/namespaces": ("Event-Hubs", "Event Hubs"),
    "microsoft.servicebus/namespaces": ("Azure-Service-Bus", "Service Bus"),
    "microsoft.eventgrid/topics": ("Event-Grid-Topics", "Event Grid topics"),
    "microsoft.eventgrid/systemtopics": ("Event-Grid-Topics", "Event Grid system topics"),
    "microsoft.eventgrid/domains": ("Event-Grid-Domains", "Event Grid domains"),
    "microsoft.logic/workflows": ("Logic-Apps", "Logic Apps"),
    "microsoft.web/connections": ("API-Connections", "API connections"),
    "microsoft.devices/iothubs": ("IoT-Hub", "IoT Hub"),
    "microsoft.devices/provisioningservices": ("Device-Provisioning-Services", "Device Provisioning Services"),
    "microsoft.digitaltwins/digitaltwinsinstances": ("Digital-Twins", "Digital Twins"),
    "microsoft.iotcentral/iotapps": ("IoT-Central-Applications", "IoT Central"),
    "microsoft.maps/accounts": ("Azure-Maps-Accounts", "Azure Maps"),
    "microsoft.communication/communicationservices": ("Azure-Communication-Services", "Communication Services"),
    # AI
    "microsoft.cognitiveservices/accounts": ("Cognitive-Services", "Azure AI services"),
    "microsoft.cognitiveservices/accounts#openai": ("Azure-OpenAI", "Azure OpenAI"),
    "microsoft.cognitiveservices/accounts#aiservices": ("AI-Foundry", "Microsoft Foundry"),
    "microsoft.machinelearningservices/workspaces": ("Machine-Learning", "Azure Machine Learning"),
    "microsoft.search/searchservices": ("Cognitive-Search", "Azure AI Search"),
    "microsoft.botservice/botservices": ("Bot-Services", "Bot services"),
    # networking
    "microsoft.network/virtualnetworks": ("Virtual-Networks", "Virtual networks"),
    "microsoft.network/networksecuritygroups": ("Network-Security-Groups", "Network security groups"),
    "microsoft.network/networkinterfaces": ("Network-Interfaces", "Network interfaces"),
    "microsoft.network/publicipaddresses": ("Public-IP-Addresses", "Public IP addresses"),
    "microsoft.network/publicipprefixes": ("Public-IP-Prefixes", "Public IP prefixes"),
    "microsoft.network/loadbalancers": ("Load-Balancers", "Load balancers"),
    "microsoft.network/applicationgateways": ("Application-Gateways", "Application gateways"),
    "microsoft.network/applicationgatewaywebapplicationfirewallpolicies": (
        "Web-Application-Firewall-Policies(WAF)", "WAF policies"),
    "microsoft.network/frontdoorwebapplicationfirewallpolicies": ("Web-Application-Firewall-Policies(WAF)",
                                                                  "Front Door WAF policies"),
    "microsoft.network/azurefirewalls": ("Firewalls", "Azure Firewall"),
    "microsoft.network/firewallpolicies": ("Azure-Firewall-Policy", "Firewall policies"),
    "microsoft.network/bastionhosts": ("Bastions", "Bastions"),
    "microsoft.network/privateendpoints": ("Private-Endpoints", "Private endpoints"),
    "microsoft.network/privatelinkservices": ("Private-Link-Service", "Private Link services"),
    "microsoft.network/privatednszones": ("DNS-Zones", "Private DNS zones"),
    "microsoft.network/dnszones": ("DNS-Zones", "DNS zones"),
    "microsoft.network/dnsresolvers": ("DNS-Private-Resolver", "DNS private resolvers"),
    "microsoft.network/natgateways": ("NAT", "NAT gateways"),
    "microsoft.network/routetables": ("Route-Tables", "Route tables"),
    "microsoft.network/virtualnetworkgateways": ("Virtual-Network-Gateways", "Virtual network gateways"),
    "microsoft.network/expressroutecircuits": ("ExpressRoute-Circuits", "ExpressRoute circuits"),
    "microsoft.network/ddosprotectionplans": ("DDoS-Protection-Plans", "DDoS protection plans"),
    "microsoft.network/trafficmanagerprofiles": ("Traffic-Manager-Profiles", "Traffic Manager profiles"),
    "microsoft.network/networkwatchers": ("Network-Watcher", "Network Watcher"),
    "microsoft.network/applicationsecuritygroups": ("Application-Security-Groups", "Application security groups"),
    # identity, security, governance, monitoring
    "microsoft.keyvault/vaults": ("Key-Vaults", "Key vaults"),
    "microsoft.managedidentity/userassignedidentities": ("Managed-Identities", "Managed identities"),
    "microsoft.operationalinsights/workspaces": ("Log-Analytics-Workspaces", "Log Analytics workspaces"),
    "microsoft.insights/components": ("Application-Insights", "Application Insights"),
    "microsoft.insights/workbooks": ("Azure-Workbooks", "Workbooks"),
    "microsoft.insights/actiongroups": ("Alerts", "Action groups (Azure Monitor alerts)"),
    "microsoft.insights/metricalerts": ("Alerts", "Metric alerts"),
    "microsoft.insights/scheduledqueryrules": ("Alerts", "Log alerts"),
    "microsoft.insights/activitylogalerts": ("Alerts", "Activity log alerts"),
    "microsoft.insights/datacollectionrules": ("Monitor", "Data collection rules (Azure Monitor)"),
    "microsoft.insights/datacollectionendpoints": ("Monitor", "Data collection endpoints (Azure Monitor)"),
    "microsoft.alertsmanagement/smartdetectoralertrules": ("Alerts", "Smart detector alerts"),
    "microsoft.alertsmanagement/actionrules": ("Alerts", "Alert processing rules"),
    "microsoft.automation/automationaccounts": ("Automation-Accounts", "Automation accounts"),
    "microsoft.dashboard/grafana": ("Azure-Managed-Grafana", "Managed Grafana"),
    "microsoft.portal/dashboards": ("Dashboard", "Dashboards"),
    "microsoft.operationsmanagement/solutions": ("Solutions", "Solutions"),
    "microsoft.hybridcompute/machines": ("Arc-Machines", "Arc-enabled servers"),
    "microsoft.kubernetes/connectedclusters": ("Arc-Kubernetes", "Arc-enabled Kubernetes"),
    "microsoft.security/pricings": ("Microsoft-Defender-for-Cloud", "Defender for Cloud"),
    "microsoft.securityinsights/workspaces": ("Azure-Sentinel", "Microsoft Sentinel"),
    "microsoft.app/containerapps": ("Worker-Container-App", "Container apps"),
    "microsoft.app/jobs": ("Worker-Container-App", "Container Apps jobs"),
    "microsoft.azurearcdata/sqlserverinstances": ("Arc-SQL-Server", "SQL Server enabled by Azure Arc"),
    "microsoft.azurearcdata/sqlmanagedinstances": ("Arc-SQL-Managed-Instance", "SQL Managed Instance (Azure Arc)"),
    "microsoft.insights/webtests": ("Web-Test", "Availability tests"),
    "microsoft.compute/sshpublickeys": ("SSH-Keys", "SSH keys"),
    "microsoft.compute/restorepointcollections": ("Restore-Points-Collections", "Restore point collections"),
    "microsoft.compute/galleries/images": ("Image-Definitions", "VM image definitions"),
    "microsoft.compute/galleries/images/versions": ("Image-Versions", "VM image versions"),
    "microsoft.resourcegraph/queries": ("Resource-Graph-Explorer", "Resource Graph queries"),
    "microsoft.operationalinsights/querypacks": ("Log-Analytics-Query-Pack", "Log Analytics query packs"),
    "microsoft.devopsinfrastructure/pools": ("Managed-DevOps-Pools", "Managed DevOps Pools"),
    "microsoft.appconfiguration/configurationstores": ("App-Configuration", "App Configuration"),
    "microsoft.maintenance/maintenanceconfigurations": ("Maintenance-Configuration", "Maintenance configurations"),
    "microsoft.network/virtualwans": ("Virtual-WANs", "Virtual WANs"),
    "microsoft.network/virtualhubs": ("Virtual-WAN-Hub", "Virtual WAN hubs"),
    "microsoft.desktopvirtualization/applicationgroups": ("Application-Group", "AVD application groups"),
    "microsoft.desktopvirtualization/workspaces": ("Workspaces", "AVD workspaces"),
    "microsoft.azureactivedirectory/ciamdirectories": ("External-Identities", "Entra External ID tenants"),
    "microsoft.azureactivedirectory/b2cdirectories": ("Azure-AD-B2C", "Azure AD B2C tenants"),
    "microsoft.network/localnetworkgateways": ("Local-Network-Gateways", "Local network gateways (on-premises)"),
    "microsoft.network/connections": ("Connections", "VPN / ExpressRoute connections"),
    "microsoft.network/networkvirtualappliances": ("VNet-Appliance", "Network virtual appliances"),
}

# scopes and concepts drawn in the diagrams
TENANT_ICON = ("Management-Groups", "Management group")
SUBSCRIPTION_ICON = ("Subscriptions", "Subscription")
RESOURCE_GROUP_ICON = ("Resource-Groups", "Resource group")
POLICY_ICON = ("Policy", "Azure Policy")
SUBNET_ICON = ("Subnet", "Subnet")
ONPREM_ICON = ("Local-Network-Gateways", "On-premises (local network gateway)")

# child resource types worth showing on their own (others - extensions, firewall rules, ... - are folded away)
SHOWN_CHILD_TYPES = {"microsoft.sql/servers/databases", "microsoft.sql/servers/elasticpools"}


def icon_for(rtype: str, kind: Optional[str] = None) -> Optional[Tuple[str, str]]:
    """(icon stem, service label) for a resource type, refined by kind (Function Apps, Azure OpenAI)."""
    rtype = (rtype or "").lower()
    kind = (kind or "").lower()
    if rtype == "microsoft.web/sites":
        if "workflowapp" in kind:
            return TYPE_ICONS["microsoft.web/sites#workflowapp"]
        if "functionapp" in kind:
            return TYPE_ICONS["microsoft.web/sites#functionapp"]
    if rtype == "microsoft.cognitiveservices/accounts" and kind in ("openai", "aiservices"):
        return TYPE_ICONS[f"{rtype}#{kind}"]
    return TYPE_ICONS.get(rtype)


def icon_stems() -> set:
    return {stem for stem, _ in TYPE_ICONS.values()} | {
        TENANT_ICON[0], SUBSCRIPTION_ICON[0], RESOURCE_GROUP_ICON[0], POLICY_ICON[0], SUBNET_ICON[0],
        ONPREM_ICON[0]}

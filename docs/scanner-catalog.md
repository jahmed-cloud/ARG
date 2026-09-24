# Scanner Catalog

Every scanner registered in ARG, generated from the scanner registry. The **Local** column shows whether the
scanner runs in the CLI / local portal (`az login`). Microsoft Graph scanners need the Docker stack with a
service principal and Graph consent.

Total: **62 scanners**.


## Compute

| Scanner | What it detects | Default severity | Finding types | Data sources | Local |
|---|---|---|---|---|---|
| `app_service_plan_generation_scanner` | App Service Plan Generation & Redundancy | medium | `app_service_plan_previous_generation`<br>`app_service_plan_single_instance` | Resource Graph | yes |
| `app_service_plan_utilization_scanner` | App Service Plan CPU Saturation | high | `app_service_plan_cpu_saturated` | Resource Graph, Azure Monitor metrics | yes |
| `deallocated_vm_scanner` | Deallocated Virtual Machines | medium | `deallocated_virtual_machine` | Resource Graph | yes |
| `idle_vmss_scanner` | Idle VM Scale Sets | low | `idle_vmss` | Resource Graph | yes |
| `old_snapshot_scanner` | Old Disk Snapshots | medium | `old_disk_snapshot` | Resource Graph, Cost Management | yes |
| `unattached_disk_scanner` | Unattached Managed Disks | high | `unattached_managed_disk` | Resource Graph, Cost Management | yes |
| `web_app_configuration_scanner` | Web App Runtime & Configuration | high | `web_app_32bit_worker`<br>`web_app_eol_runtime`<br>`web_app_ftp_enabled`<br>`web_app_health_check_missing`<br>`web_app_weak_tls` | Resource Graph, ARM REST | yes |

## Cost

| Scanner | What it detects | Default severity | Finding types | Data sources | Local |
|---|---|---|---|---|---|
| `ai_spend_governance_scanner` | AI Spend Governance | high | `ai_account_sprawl`<br>`ai_spend_without_gateway` | Resource Graph, Cost Management, ARM REST | yes |
| `budget_scanner` | Budget Coverage & Overrun | high | `budget_consistently_exceeded`<br>`budget_missing` | Cost Management, ARM REST | yes |
| `commitment_discount_scanner` | Commitment Discount Opportunities | medium | `commitment_discount_opportunity` | Resource Graph, Advisor | yes |
| `idle_iot_hub_scanner` | Idle IoT Hubs | medium | `idle_iot_hub` | Resource Graph, Azure Monitor metrics | yes |
| `sql_hyperscale_legacy_pricing_scanner` | Hyperscale Legacy Storage Pricing | medium | `sql_hyperscale_legacy_storage_pricing` | Resource Graph, Cost Management | yes |
| `storage_account_sprawl_scanner` | Storage Account Sprawl | low | `storage_account_sprawl` | Resource Graph, Defender for Cloud | yes |
| `storage_transaction_hotspot_scanner` | Storage Transaction Hotspot | low | `storage_transaction_hotspot` | Resource Graph, Azure Monitor metrics, Cost Management | yes |

## Database

| Scanner | What it detects | Default severity | Finding types | Data sources | Local |
|---|---|---|---|---|---|
| `cosmos_db_scanner` | Cosmos DB Exposure & Usage | medium | `cosmos_public_network_access`<br>`idle_cosmos_db` | Resource Graph, Azure Monitor metrics | yes |
| `cross_region_app_data_scanner` | Cross-Region App and Data Tier | medium | `cross_region_app_data_tier` | Resource Graph | yes |
| `sql_database_utilization_scanner` | SQL Database Utilization | medium | `idle_sql_database`<br>`sql_database_cpu_saturated` | Resource Graph, Azure Monitor metrics, Cost Management | yes |
| `sql_entra_auth_scanner` | SQL Server Entra Authentication | medium | `sql_entra_admin_individual_user`<br>`sql_entra_admin_missing`<br>`sql_entra_only_auth_disabled` | Resource Graph | yes |
| `sql_firewall_scanner` | SQL Server Firewall Rules | high | `sql_firewall_allow_all_azure_services`<br>`sql_firewall_individual_ip_rules`<br>`sql_firewall_wide_ip_range` | Resource Graph, ARM REST | yes |

## Governance

| Scanner | What it detects | Default severity | Finding types | Data sources | Local |
|---|---|---|---|---|---|
| `app_insights_workspace_scanner` | Application Insights Workspace Link | high | `app_insights_classic_mode`<br>`app_insights_workspace_missing` | Resource Graph | yes |
| `app_service_mixed_environment_scanner` | Mixed Environments on One App Service Plan | high | `app_service_plan_mixed_environments` | Resource Graph | yes |
| `empty_resource_group_scanner` | Empty Resource Groups | low | `empty_resource_group` | Resource Graph | yes |
| `environment_tag_mismatch_scanner` | Environment Tag / Name Mismatch | medium | `environment_tag_name_mismatch` | Resource Graph | yes |
| `log_analytics_scanner` | Log Analytics Caps & Sprawl | high | `log_analytics_restrictive_daily_cap`<br>`log_analytics_workspace_sprawl` | Resource Graph | yes |
| `missing_required_tags_scanner` | Missing Required Tags | medium | `missing_required_tags` | Resource Graph | yes |
| `missing_resource_lock_scanner` | Verify Resource Locks | high | `missing_resource_lock` | Resource Graph | yes |
| `naming_convention_scanner` | Naming Convention Violations | low | `naming_convention_violation` | Resource Graph | yes |
| `service_health_alert_scanner` | Service Health Alert | medium | `service_health_alert_missing` | Resource Graph | yes |
| `subscription_workload_sprawl_scanner` | Multiple Workloads per Subscription | low | `subscription_multiple_workloads` | Resource Graph | yes |
| `tag_key_typo_scanner` | Tag Key Typos | low | `tag_key_typo` | Resource Graph | yes |

## Identity

| Scanner | What it detects | Default severity | Finding types | Data sources | Local |
|---|---|---|---|---|---|
| `dormant_user_scanner` | Dormant Users | high | `dormant_member_user` | Microsoft Graph | no |
| `expired_app_credential_scanner` | Expired App Credentials | high | `expired_app_certificate`<br>`expired_app_secret` | Microsoft Graph | no |
| `mfa_not_enabled_scanner` | Users Without MFA | high | `mfa_not_enabled` | Microsoft Graph | no |
| `permanent_global_admin_scanner` | Permanent Global Administrators | critical | `permanent_global_admin` | Microsoft Graph | no |
| `privileged_role_assignment_scanner` | Privileged Subscription Role Assignments | high | `excessive_subscription_owners`<br>`service_principal_privileged_role`<br>`standing_user_access_administrator` | Resource Graph, RBAC | yes |
| `stale_guest_scanner` | Stale Guest Users | medium | `guest_never_signed_in` | Microsoft Graph | no |

## Network

| Scanner | What it detects | Default severity | Finding types | Data sources | Local |
|---|---|---|---|---|---|
| `empty_application_gateway_scanner` | Empty Application Gateways | critical | `empty_application_gateway` | Resource Graph, Cost Management | yes |
| `empty_load_balancer_scanner` | Empty Load Balancers | high | `empty_load_balancer` | Resource Graph, Cost Management | yes |
| `orphaned_nic_scanner` | Orphaned Network Interfaces | medium | `orphaned_nic` | Resource Graph | yes |
| `orphaned_nsg_scanner` | Orphaned Network Security Groups | low | `orphaned_nsg` | Resource Graph | yes |
| `private_dns_zone_without_endpoints_scanner` | Unused Private Link DNS Zone | low | `private_dns_zone_without_endpoints` | Resource Graph | yes |
| `public_ip_on_orphaned_nic_scanner` | Public IP on Orphaned NIC | medium | `public_ip_on_orphaned_nic` | Resource Graph | yes |
| `subnet_without_nsg_scanner` | Subnets Without NSG | medium | `subnet_without_nsg` | Resource Graph | yes |
| `unassociated_ddos_plan_scanner` | Unassociated DDoS Protection Plan | critical | `unused_ddos_protection_plan` | Resource Graph, Cost Management | yes |
| `unused_public_ip_scanner` | Unused Public IP Addresses | high | `unused_public_ip` | Resource Graph, Cost Management | yes |

## Security

| Scanner | What it detects | Default severity | Finding types | Data sources | Local |
|---|---|---|---|---|---|
| `ai_services_hardening_scanner` | AI Services (Foundry / OpenAI) Hardening | high | `ai_services_local_auth_enabled`<br>`ai_services_public_network_open` | Resource Graph | yes |
| `defender_plan_coverage_scanner` | Defender for Cloud Plan Coverage | medium | `defender_plan_disabled` | Resource Graph, Defender for Cloud | yes |
| `defender_recommendations_scanner` | Defender for Cloud Recommendations | high | `defender_recommendations` | Resource Graph, Defender for Cloud | yes |
| `key_vault_hardening_scanner` | Key Vault Hardening | high | `key_vault_access_policy_model`<br>`key_vault_public_network_open`<br>`key_vault_purge_protection_disabled`<br>`key_vault_soft_delete_disabled` | Resource Graph | yes |
| `managed_disk_network_access_scanner` | Managed Disk Open Network Access | low | `managed_disk_public_network_access` | Resource Graph | yes |
| `missing_diagnostic_settings_scanner` | Verify Diagnostic Settings | high | `missing_diagnostic_settings` | Resource Graph | yes |
| `open_management_port_scanner` | Management Ports Open to Internet | high | `nsg_management_port_open_to_internet` | Resource Graph | yes |
| `public_sql_server_scanner` | Public SQL Server Access | critical | `public_sql_server` | Resource Graph | yes |
| `public_storage_account_scanner` | Public Blob Access Enabled | critical | `public_storage_account` | Resource Graph | yes |
| `secure_score_scanner` | Defender Secure Score | medium | `low_secure_score` | Resource Graph, Defender for Cloud | yes |
| `storage_access_hardening_scanner` | Storage Account Access Hardening | medium | `storage_blob_soft_delete_disabled`<br>`storage_public_network_access`<br>`storage_shared_key_access_enabled` | Resource Graph, ARM REST | yes |
| `unsupported_os_image_scanner` | End-of-Support Operating System | critical | `vm_unsupported_os` | Resource Graph | yes |
| `vm_public_ip_with_bastion_scanner` | VM Public IP Bypasses Bastion | high | `vm_public_ip_bypasses_bastion` | Resource Graph | yes |
| `web_app_https_identity_scanner` | Web App HTTPS & Managed Identity | high | `web_app_https_not_enforced`<br>`web_app_managed_identity_missing` | Resource Graph | yes |

## Storage

| Scanner | What it detects | Default severity | Finding types | Data sources | Local |
|---|---|---|---|---|---|
| `orphaned_backup_vault_scanner` | Potentially Empty Recovery Services Vaults | low | `orphaned_backup_vault` | Resource Graph | yes |
| `unused_storage_account_scanner` | Potentially Unused Storage Accounts | medium | `unused_storage_account` | Resource Graph, Azure Monitor metrics, Cost Management | yes |

## Terraform

| Scanner | What it detects | Default severity | Finding types | Data sources | Local |
|---|---|---|---|---|---|
| `terraform_drift_scanner` | Terraform Drift Detection | medium | `terraform_missing_resource`<br>`terraform_unmanaged_resource` | Imported Terraform state | yes |

## Finding type → report placement

How the subscription analysis report files each finding type (gap-analysis area, deep-dive folder, savings wave).

| Finding type | Gap area | Deep-dive folder | Wave |
|---|---|---|---|
| `ai_account_sprawl` | Structural / Architecture | `ai-foundry` | Wave 2 - Optimisation |
| `ai_services_local_auth_enabled` | Security & Identity | `ai-foundry` | Wave 2 - Optimisation |
| `ai_services_public_network_open` | Security & Identity | `ai-foundry` | Wave 1 - No-regret cleanup |
| `ai_spend_without_gateway` | FinOps / Governance | `ai-foundry` | Wave 2 - Optimisation |
| `app_insights_classic_mode` | Operational / Observability | `observability-operations` | Wave 2 - Optimisation |
| `app_insights_workspace_missing` | Operational / Observability | `observability-operations` | Wave 1 - No-regret cleanup |
| `app_service_plan_cpu_saturated` | Performance & Resilience | `compute-appservice` | Wave 2 - Optimisation |
| `app_service_plan_mixed_environments` | Structural / Architecture | `compute-appservice` | Wave 2 - Optimisation |
| `app_service_plan_previous_generation` | FinOps / Governance | `compute-appservice` | Wave 2 - Optimisation |
| `app_service_plan_single_instance` | Performance & Resilience | `compute-appservice` | Wave 2 - Optimisation |
| `budget_consistently_exceeded` | FinOps / Governance | `cost-finops` | Wave 1 - No-regret cleanup |
| `budget_missing` | FinOps / Governance | `cost-finops` | Wave 1 - No-regret cleanup |
| `commitment_discount_opportunity` | FinOps / Governance | `cost-finops` | Wave 2 - Optimisation |
| `cosmos_public_network_access` | Security & Identity | `data-sql-storage` | Wave 2 - Optimisation |
| `cross_region_app_data_tier` | Structural / Architecture | `data-sql-storage` | Wave 3 - Structural |
| `deallocated_virtual_machine` | FinOps / Governance | `compute-appservice` | Wave 1 - No-regret cleanup |
| `defender_plan_disabled` | Security & Identity | `security-identity` | Wave 2 - Optimisation |
| `defender_recommendations` | Security & Identity | `security-identity` | Wave 2 - Optimisation |
| `dormant_member_user` | Operational / Observability | `observability-operations` | Wave 3 - Structural |
| `empty_application_gateway` | FinOps / Governance | `networking` | Wave 1 - No-regret cleanup |
| `empty_load_balancer` | FinOps / Governance | `networking` | Wave 1 - No-regret cleanup |
| `empty_resource_group` | FinOps / Governance | `observability-operations` | Wave 1 - No-regret cleanup |
| `environment_tag_name_mismatch` | Structural / Architecture | `observability-operations` | Wave 1 - No-regret cleanup |
| `excessive_subscription_owners` | Security & Identity | `security-identity` | Wave 1 - No-regret cleanup |
| `expired_app_certificate` | Operational / Observability | `observability-operations` | Wave 3 - Structural |
| `expired_app_secret` | Operational / Observability | `observability-operations` | Wave 3 - Structural |
| `guest_never_signed_in` | Operational / Observability | `observability-operations` | Wave 3 - Structural |
| `idle_cosmos_db` | FinOps / Governance | `data-sql-storage` | Wave 1 - No-regret cleanup |
| `idle_iot_hub` | FinOps / Governance | `cost-finops` | Wave 1 - No-regret cleanup |
| `idle_sql_database` | FinOps / Governance | `data-sql-storage` | Wave 1 - No-regret cleanup |
| `idle_vmss` | FinOps / Governance | `compute-appservice` | Wave 1 - No-regret cleanup |
| `key_vault_access_policy_model` | Security & Identity | `security-identity` | Wave 2 - Optimisation |
| `key_vault_public_network_open` | Security & Identity | `security-identity` | Wave 2 - Optimisation |
| `key_vault_purge_protection_disabled` | Security & Identity | `security-identity` | Wave 1 - No-regret cleanup |
| `key_vault_soft_delete_disabled` | Security & Identity | `security-identity` | Wave 1 - No-regret cleanup |
| `log_analytics_restrictive_daily_cap` | Operational / Observability | `observability-operations` | Wave 1 - No-regret cleanup |
| `log_analytics_workspace_sprawl` | Operational / Observability | `observability-operations` | Wave 2 - Optimisation |
| `low_secure_score` | Security & Identity | `security-identity` | Wave 2 - Optimisation |
| `managed_disk_public_network_access` | Security & Identity | `compute-appservice` | Wave 1 - No-regret cleanup |
| `mfa_not_enabled` | Operational / Observability | `observability-operations` | Wave 3 - Structural |
| `missing_diagnostic_settings` | Operational / Observability | `observability-operations` | Wave 2 - Optimisation |
| `missing_required_tags` | FinOps / Governance | `observability-operations` | Wave 2 - Optimisation |
| `missing_resource_lock` | Operational / Observability | `observability-operations` | Wave 2 - Optimisation |
| `naming_convention_violation` | FinOps / Governance | `observability-operations` | Wave 3 - Structural |
| `nsg_management_port_open_to_internet` | Security & Identity | `networking` | Wave 1 - No-regret cleanup |
| `old_disk_snapshot` | FinOps / Governance | `compute-appservice` | Wave 1 - No-regret cleanup |
| `orphaned_backup_vault` | FinOps / Governance | `data-sql-storage` | Wave 1 - No-regret cleanup |
| `orphaned_nic` | FinOps / Governance | `networking` | Wave 1 - No-regret cleanup |
| `orphaned_nsg` | FinOps / Governance | `networking` | Wave 1 - No-regret cleanup |
| `permanent_global_admin` | Operational / Observability | `observability-operations` | Wave 3 - Structural |
| `private_dns_zone_without_endpoints` | Structural / Architecture | `networking` | Wave 1 - No-regret cleanup |
| `public_ip_on_orphaned_nic` | FinOps / Governance | `networking` | Wave 1 - No-regret cleanup |
| `public_sql_server` | Security & Identity | `data-sql-storage` | Wave 2 - Optimisation |
| `public_storage_account` | Security & Identity | `data-sql-storage` | Wave 1 - No-regret cleanup |
| `service_health_alert_missing` | Operational / Observability | `observability-operations` | Wave 1 - No-regret cleanup |
| `service_principal_privileged_role` | Security & Identity | `security-identity` | Wave 2 - Optimisation |
| `sql_database_cpu_saturated` | Performance & Resilience | `data-sql-storage` | Wave 2 - Optimisation |
| `sql_entra_admin_individual_user` | Security & Identity | `data-sql-storage` | Wave 1 - No-regret cleanup |
| `sql_entra_admin_missing` | Security & Identity | `data-sql-storage` | Wave 1 - No-regret cleanup |
| `sql_entra_only_auth_disabled` | Security & Identity | `data-sql-storage` | Wave 2 - Optimisation |
| `sql_firewall_allow_all_azure_services` | Security & Identity | `data-sql-storage` | Wave 1 - No-regret cleanup |
| `sql_firewall_individual_ip_rules` | Security & Identity | `data-sql-storage` | Wave 1 - No-regret cleanup |
| `sql_firewall_wide_ip_range` | Security & Identity | `data-sql-storage` | Wave 1 - No-regret cleanup |
| `sql_hyperscale_legacy_storage_pricing` | FinOps / Governance | `data-sql-storage` | Wave 2 - Optimisation |
| `standing_user_access_administrator` | Security & Identity | `security-identity` | Wave 1 - No-regret cleanup |
| `storage_account_sprawl` | Structural / Architecture | `data-sql-storage` | Wave 2 - Optimisation |
| `storage_blob_soft_delete_disabled` | Performance & Resilience | `data-sql-storage` | Wave 1 - No-regret cleanup |
| `storage_public_network_access` | Security & Identity | `data-sql-storage` | Wave 2 - Optimisation |
| `storage_shared_key_access_enabled` | Security & Identity | `data-sql-storage` | Wave 2 - Optimisation |
| `storage_transaction_hotspot` | Performance & Resilience | `data-sql-storage` | Wave 2 - Optimisation |
| `subnet_without_nsg` | Structural / Architecture | `networking` | Wave 3 - Structural |
| `subscription_multiple_workloads` | Structural / Architecture | `observability-operations` | Wave 3 - Structural |
| `tag_key_typo` | FinOps / Governance | `observability-operations` | Wave 1 - No-regret cleanup |
| `terraform_missing_resource` | Operational / Observability | `observability-operations` | Wave 3 - Structural |
| `terraform_unmanaged_resource` | Operational / Observability | `observability-operations` | Wave 3 - Structural |
| `unattached_managed_disk` | FinOps / Governance | `compute-appservice` | Wave 1 - No-regret cleanup |
| `unused_ddos_protection_plan` | FinOps / Governance | `networking` | Wave 1 - No-regret cleanup |
| `unused_public_ip` | FinOps / Governance | `networking` | Wave 1 - No-regret cleanup |
| `unused_storage_account` | FinOps / Governance | `data-sql-storage` | Wave 1 - No-regret cleanup |
| `vm_public_ip_bypasses_bastion` | Security & Identity | `networking` | Wave 1 - No-regret cleanup |
| `vm_unsupported_os` | Security & Identity | `compute-appservice` | Wave 1 - No-regret cleanup |
| `web_app_32bit_worker` | Performance & Resilience | `compute-appservice` | Wave 2 - Optimisation |
| `web_app_eol_runtime` | Security & Identity | `compute-appservice` | Wave 2 - Optimisation |
| `web_app_ftp_enabled` | Security & Identity | `compute-appservice` | Wave 1 - No-regret cleanup |
| `web_app_health_check_missing` | Operational / Observability | `compute-appservice` | Wave 2 - Optimisation |
| `web_app_https_not_enforced` | Security & Identity | `compute-appservice` | Wave 1 - No-regret cleanup |
| `web_app_managed_identity_missing` | Security & Identity | `compute-appservice` | Wave 2 - Optimisation |
| `web_app_weak_tls` | Security & Identity | `compute-appservice` | Wave 1 - No-regret cleanup |

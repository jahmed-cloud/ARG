# Azure Policy Limits and Restrictions

Reference for hard limits enforced by Azure across policy definitions, initiatives, assignments, exemptions, and policy rules.

## Sources

| Topic | URL |
| --- | --- |
| Azure subscription service limits | <https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits> |
| Assignment structure | <https://learn.microsoft.com/en-us/azure/governance/policy/concepts/assignment-structure> |
| Initiative definition structure | <https://learn.microsoft.com/en-us/azure/governance/policy/concepts/initiative-definition-structure> |
| Exemption structure | <https://learn.microsoft.com/en-us/azure/governance/policy/concepts/exemption-structure> |
| Definition structure basics | <https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-basics> |
| Policy rule limits | <https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#policy-rule-limits> |

---

## Azure Policy Quotas

Scope means a management group or subscription for definitions; for assignments and exemptions it includes resource groups and individual resources.

| Resource | Maximum |
| --- | --- |
| Policy definitions per scope | 500 |
| Initiative definitions per scope | 200 |
| Initiative definitions per tenant | 2,500 |
| Policy or initiative assignments per scope | 200 |
| Exemptions per scope | 1,000 |
| Parameters per policy definition | 20 |
| Policies per initiative definition | 1,000 |
| Parameters per initiative definition | 400 |
| `notScopes` exclusions per assignment | 400 |
| Nested conditionals in a policy rule | 512 |
| Resources per remediation task | 50,000 |
| Request body (definition, initiative, or assignment) | 1,048,576 bytes |

---

## Policy Definition

| Field | Limit |
| --- | --- |
| `displayName` | 128 characters |
| `description` | 512 characters |
| Each `metadata` property value | 1,024 characters |

---

## Initiative Definition

| Field | Limit |
| --- | --- |
| `displayName` | 128 characters |
| `description` | 512 characters |
| Each `metadata` property value | 1,024 characters |

---

## Assignment

| Field / Property | Limit |
| --- | --- |
| `displayName` | 128 characters |
| `description` | 512 characters |
| Each `metadata` property value | 1,024 characters |
| `resourceSelectors` per assignment | 10 |
| `in` / `notIn` values per resource selector | 50 |
| `overrides` per assignment | 10 |
| `policyDefinitionReferenceId` entries per override | 50 |
| `in` / `notIn` values per override selector | 50 |

---

## Exemption

| Field / Property | Limit |
| --- | --- |
| `displayName` | 128 characters |
| `description` | 512 characters |
| `resourceSelectors` per exemption | 10 |
| `in` / `notIn` values per resource selector | 50 |
| Exemption categories | 2 (`Mitigated`, `Waiver`) |

---

## Policy Rule — Authoring-Time Limits

Violations cause the create or assign operation to fail immediately.

| Limit | Value |
| --- | --- |
| Condition expressions in the `if` block | 4,096 |
| Condition expressions in the `then` block (`existenceCondition`) | 128 |
| Policy functions per policy rule | 2,048 |
| Parameters per policy function call | 128 |
| Nested function depth | 64 |
| Policy function expression string length | 81,920 characters |
| `field count` expressions per array alias | 5 |
| `value count` expressions per policy rule | 10 |
| `value count` iteration count (including nested) | 100 |

---

## Policy Rule — Evaluation-Time Limits

These limits cannot always be caught at authoring time because they depend on the values of evaluated resources. **A policy that exceeds these limits during evaluation becomes an implicit `deny`** and can block incoming resource requests.

| Limit | Value |
| --- | --- |
| String length returned by a policy function | 131,072 characters |
| Depth of complex objects passed to or returned by a function | 128 |
| Number of nodes in complex objects passed to or returned by a function | 32,768 |

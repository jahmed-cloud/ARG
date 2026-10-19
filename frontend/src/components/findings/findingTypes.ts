/** GET /findings/{id} - the per-finding analysis the local subscription report shows (backend/api/routes/findings.py). */

export interface Critique {
  key: string;
  title: string;
  likely_rationale: string;
  why_it_falls_short: string;
  alternatives: string[];
}

export interface Analysis {
  area: string;
  deep_dive: string;
  deep_dive_title: string;
  wave: number;
  wave_name: string;
  critique: Critique | null;
}

export interface ResourceContext {
  sku: Record<string, unknown> | null;
  tags: Record<string, string>;
  environment_tag: string | null;
  owner_tag: string | null;
  azure_created_at: string | null;
}

export interface RelatedFinding {
  id: string;
  finding_type: string;
  title: string;
  severity: string;
  status: string;
}

export interface Reference {
  title: string;
  url: string;
}

export interface ImplementationItem {
  label: string;
  why: string;
  skip_when: string;
  effort: string;
  hours: number[];
  monthly_usd: number | null;
  run_cost: string;
}

export interface ImplementationOption {
  option: string;
  title: string;
  monthly_usd: number;
  fits: boolean;
  chosen: boolean;
  note: string;
}

export interface Implementation {
  source: string;
  why: string;
  skip_when: string;
  effort: string;
  hours: number[] | null;
  monthly_usd: number | null;
  run_cost: string;
  saving_usd: number | null;
  net_monthly_usd: number | null;
  cost_included_in_saving: boolean;
  one_off_usd: number[] | null;
  prices_as_of: string;
  references: Reference[];
  items: ImplementationItem[];
  decision?: { option: string; title: string; why: string; monthly_usd: number } | null;
  options?: ImplementationOption[];
}

export interface ReasoningOption {
  option: string;
  role: string;
  run_cost: number | null;
  exposure_after?: string | null;
  why: string;
}

export interface Reasoning {
  observed: string[];
  context: string[];
  considered: ReasoningOption[];
  recommendation: string;
  sequence: string[];
  risks: string[];
  verify: string[];
  confidence: { level: string; why: string };
}

export interface AiReview {
  agree?: boolean;
  recommendation?: string;
  why?: string;
  sequence?: string[];
  risks?: string[];
  questions?: string[];
  model?: string;
  generated_at?: string;
}

export interface FindingDetail {
  id: string;
  finding_type: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  category: string;
  resource_name: string | null;
  resource_type: string | null;
  azure_resource_id: string | null;
  resource_group: string | null;
  location: string | null;
  estimated_monthly_savings_usd: number | null;
  estimated_annual_savings_usd: number | null;
  first_detected_at: string;
  last_detected_at: string;
  resolved_at: string | null;
  suppressed_until: string | null;
  suppression_reason: string | null;
  remediation_steps: string | null;
  evidence: Record<string, unknown>;
  affected_resources: string[];
  caf_control: string | null;
  nist_control: string | null;
  cis_control: string | null;
  azure_cli_script: string | null;
  powershell_script: string | null;
  analysis: Analysis | null;
  implementation: Implementation | null;
  subscription: { name: string | null; subscription_id: string | null } | null;
  resource_context: ResourceContext | null;
  related_findings: RelatedFinding[];
  reasoning?: Reasoning | null;
  ai_review?: AiReview | null;
}

/** Fibonacci story points by the upper hour estimate - a generic size of the change, not measured hours. */
const STORY_POINTS: [number, number][] = [[1, 4], [2, 8], [3, 12], [5, 20], [8, 32], [13, 52], [21, 84], [55, 220], [89, 356]];

export function effortLabel(hours: number[] | null | undefined): string {
  if (!hours || !hours.length) return '—';
  const high = hours[hours.length - 1];
  const row = STORY_POINTS.find(([, limit]) => high <= limit);
  const [points] = row ?? STORY_POINTS[STORY_POINTS.length - 1];
  const range = hours.length > 1 && hours[0] !== high ? `${hours[0]}-${high} h` : `${high} h`;
  return `${points}${row ? '' : '+'} SP · ${range}`;
}

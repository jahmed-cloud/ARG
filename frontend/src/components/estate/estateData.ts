/**
 * Estate data model and filtering - a port of the local portal's estate.js
 * (scripts/local_portal/static/estate.js) so the admin Estate page behaves the same:
 * same estate.json format 2, filters, facet counts, hygiene / extension hiding, CPU and
 * activity bands, sorting and CSV export. No React in here.
 */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const PAGE_SIZE = 100;
export const FILTER_KEYS = [
  'q', 'category', 'type', 'size', 'sub', 'region', 'env', 'state', 'exp', 'has', 'stype', 'sev', 'hyg', 'ext', 'cpu', 'act',
] as const;
export type FilterKey = (typeof FILTER_KEYS)[number];
export type Filters = Partial<Record<FilterKey, string>>;
export type View = 'resources' | 'suggestions';

export interface EstateSubscription {
  id: string;
  name: string;
  analysedAt?: string | null;
  currency?: string;
  resources?: number;
  suggestions?: number;
}

export interface SnapshotMeta {
  id: string;
  status: string;
  triggered_by: string;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
  subscriptions: number | null;
  resources: number | null;
  suggestions: number | null;
}

/* Wire format (scripts/subscription_analysis/estate.compact). */
interface RawResource {
  id: string; name: string; type: string; s: number; rg?: string; loc?: string; kind?: string; size?: string;
  cfg?: string; os?: string; state?: string; env?: string; mb?: string; gb?: number; tags?: Record<string, string>;
  vcpu?: number; ram?: number; cpu?: number; cpuMax?: number; mem?: number; sub?: number; cpuHr?: number;
  cpu95?: number; burst?: number; memHr?: number; act?: number; use?: string; idle?: number; dor?: number;
  nva?: number; cost?: number; cur?: string; n?: number; h?: number; sev?: string;
  ep?: { h?: string; d?: string[]; x?: string; i?: number };
}

interface RawSuggestion {
  ref?: string; title?: string; sev?: string; type?: string; wave?: number; usd?: number; r?: number; s: number;
  af?: string; hy?: number; name?: string;
}

export interface RawEstate {
  format: number;
  generated_at: string;
  inventory_at: string | null;
  source: string;
  subscriptions: EstateSubscription[];
  types: Record<string, { label: string; category: string }>;
  resources: RawResource[];
  suggestions: RawSuggestion[];
  cost_unavailable?: string[];
  snapshot?: SnapshotMeta;
}

export interface Resource {
  id: string; key: string; name: string; type: string; typeLabel: string; category: string;
  subscriptionId: string; subscription: string; resourceGroup: string; location: string; kind: string;
  size: string; config: string; os: string; state: string; env: string; managedBy: string;
  tags: Record<string, string>; cost30: number | null; currency: string; suggestions: number; hygiene: number;
  maxSeverity: string; vcpu: number | null; ramGB: number | null; cpuAvg: number | null; cpuMax: number | null;
  memAvg: number | null; subResource: boolean; cpuPeakHour: number | null; cpuP95: number | null;
  burstHours: number | null; memPeakHour: number | null; activity: number | null; usage: string; idle: boolean;
  dormant: boolean; nva: boolean; text: string;
  endpoint: Endpoint | null; host: string; domains: string; webExposure: string;
}

/* Web endpoint of an App Service app / slot, Static Web App or Container App (network.web_endpoint). */
export interface Endpoint {
  host: string;
  domains: string[];
  exposure: string;
  internet: boolean;
}

export const CUSTOM_DOMAIN = 'custom';
export const expLabel = (v: string) => (v === CUSTOM_DOMAIN ? 'With a custom domain' : v);
export const ENDPOINT_CAVEAT = 'Resource Graph does not show App Service access restrictions, Front Door / Application Gateway in '
  + 'front of the app or sign-in: a public endpoint is reachable at network level, not necessarily open to everyone.';

export interface Suggestion {
  findingId: string; title: string; severity: string; type: string; wave: number | null; hygiene: boolean;
  savingsUsd: number; subscriptionId: string; subscription: string; resourceId: string; resourceName: string;
  category: string; typeLabel: string;
}

export interface Estate {
  generatedAt: string;
  inventoryAt: string | null;
  source: string;
  subscriptions: EstateSubscription[];
  resources: Resource[];
  suggestions: Suggestion[];
  byResource: Map<string, Suggestion[]>;
  resourceIndex: Map<string, Resource>;
  costUnavailable: string[];
  snapshot: SnapshotMeta | null;
}

const num = (v: number | undefined) => (v === undefined ? null : v);

export function expand(data: RawEstate): Estate {
  const subs = data.subscriptions || [];
  const types = data.types || {};
  const resources: Resource[] = (data.resources || []).map((r) => {
    const sub = subs[r.s] || ({} as EstateSubscription);
    const t = types[r.type] || { label: r.type, category: 'Other' };
    const tags = r.tags || {};
    const res: Resource = {
      id: r.id, key: r.id.toLowerCase(), name: r.name, type: r.type, typeLabel: t.label || r.type,
      category: t.category || 'Other', subscriptionId: sub.id || '', subscription: sub.name || sub.id || '',
      resourceGroup: r.rg || '', location: r.loc || '', kind: r.kind || '', size: r.size || '', config: r.cfg || '',
      os: r.os || '', state: r.state || '', env: r.env || 'Unknown', managedBy: r.mb || '', tags,
      cost30: num(r.cost), currency: r.cur || '', suggestions: r.n || 0, hygiene: r.h || 0, maxSeverity: r.sev || '',
      vcpu: r.vcpu || null, ramGB: r.ram || null, cpuAvg: num(r.cpu), cpuMax: num(r.cpuMax), memAvg: num(r.mem),
      subResource: !!r.sub, cpuPeakHour: num(r.cpuHr), cpuP95: num(r.cpu95), burstHours: num(r.burst),
      memPeakHour: num(r.memHr), activity: num(r.act), usage: r.use || '', idle: !!r.idle, dormant: !!r.dor,
      nva: !!r.nva, text: '',
      endpoint: r.ep ? { host: r.ep.h || '', domains: r.ep.d || [], exposure: r.ep.x || '', internet: !!r.ep.i } : null,
      host: r.ep?.h || '', domains: (r.ep?.d || []).join(' '), webExposure: r.ep?.x || '',
    };
    const tagText = Object.entries(tags).map(([k, v]) => `${k}=${v}`).join(' ');
    res.text = [res.name, res.resourceGroup, res.typeLabel, res.size, res.config, res.os, res.state, res.kind,
      res.subscription, tagText, res.host, res.domains].join(' ').toLowerCase();
    return res;
  });
  const suggestions: Suggestion[] = (data.suggestions || []).map((s) => {
    const sub = subs[s.s] || ({} as EstateSubscription);
    const r = s.r === undefined || s.r === null ? null : resources[s.r];
    return {
      findingId: s.ref || '', title: s.title || '', severity: s.sev || 'info', type: s.type || '',
      wave: s.wave || null, hygiene: !!s.hy, savingsUsd: s.usd || 0, subscriptionId: sub.id || '',
      subscription: sub.name || sub.id || '', resourceId: r ? r.id : '', resourceName: r ? r.name : s.name || '(subscription)',
      category: r ? r.category : 'Subscription', typeLabel: r ? r.typeLabel : 'Subscription',
    };
  });
  const byResource = new Map<string, Suggestion[]>();
  suggestions.forEach((s) => {
    if (!s.resourceId) return;
    const key = s.resourceId.toLowerCase();
    if (!byResource.has(key)) byResource.set(key, []);
    byResource.get(key)!.push(s);
  });
  return {
    generatedAt: data.generated_at, inventoryAt: data.inventory_at, source: data.source, subscriptions: subs,
    resources, suggestions, byResource, resourceIndex: new Map(resources.map((r) => [r.key, r])),
    costUnavailable: data.cost_unavailable || [], snapshot: data.snapshot || null,
  };
}

// ---- bands -------------------------------------------------------------------------------------

export const CPU_BANDS: [number, string][] = [
  [5, 'under 5 %'], [20, '5-20 %'], [50, '20-50 %'], [80, '50-80 %'], [101, '80 % and more'],
];
export const cpuBand = (v: number | null) =>
  v === null ? 'no data' : (CPU_BANDS.find(([limit]) => v < limit) || CPU_BANDS[CPU_BANDS.length - 1])[1];
export const hasCompute = (r: Resource) =>
  r.type === 'microsoft.compute/virtualmachines' || r.type === 'microsoft.compute/virtualmachinescalesets';
export const hasCpu = (r: Resource) => hasCompute(r) || r.cpuAvg !== null || r.memAvg !== null;
export const activityBand = (r: Resource): string | null =>
  r.dormant ? 'Dormant data - no reads / writes in 30 d'
    : r.idle ? 'Idle - no activity in 30 d' : r.activity !== null ? 'Active' : null;
export const sevRank = (s: string) => {
  const i = SEVERITIES.indexOf(s);
  return i < 0 ? 9 : i;
};

// ---- filtering ---------------------------------------------------------------------------------

// VM / Arc extensions and license profiles sit on a machine; hidden unless ticked or their type is picked.
export const shownByDefault = (r: Resource, f: Filters) => !r.subResource || !!f.ext || (!!f.type && f.type === r.typeLabel);

// Tag / naming findings are on almost every resource: hidden unless asked for (checkbox or suggestion type).
export const visibleSuggestion = (s: Suggestion, f: Filters) => !s.hygiene || !!f.hyg || (!!f.stype && f.stype === s.type);

export function resourceMatches(e: Estate, r: Resource, f: Filters, skip?: FilterKey): boolean {
  if (!shownByDefault(r, f)) return false;
  if (f.q && skip !== 'q' && !r.text.includes(f.q.toLowerCase())) return false;
  if (f.cpu && skip !== 'cpu' && (!hasCpu(r) || cpuBand(r.cpuAvg) !== f.cpu)) return false;
  if (f.act && skip !== 'act' && activityBand(r) !== f.act) return false;
  if (f.category && skip !== 'category' && r.category !== f.category) return false;
  if (f.type && skip !== 'type' && r.typeLabel !== f.type) return false;
  if (f.size && skip !== 'size' && (r.size || '(none)') !== f.size) return false;
  if (f.sub && skip !== 'sub' && r.subscriptionId !== f.sub) return false;
  if (f.region && skip !== 'region' && (r.location || '(none)') !== f.region) return false;
  if (f.env && skip !== 'env' && r.env !== f.env) return false;
  if (f.state && skip !== 'state' && (r.state || '(none)') !== f.state) return false;
  if (f.exp && skip !== 'exp') {
    if (!r.endpoint) return false;
    if (f.exp === CUSTOM_DOMAIN ? !r.endpoint.domains.length : r.endpoint.exposure !== f.exp) return false;
  }
  if (f.has && skip !== 'has') {
    if (f.has === 'any' && !r.suggestions) return false;
    if (f.has === 'none' && r.suggestions) return false;
    if (f.has === 'crit-high' && !['critical', 'high'].includes(r.maxSeverity)) return false;
    if (f.has === 'hygiene' && (r.suggestions || !r.hygiene)) return false;
  }
  if ((f.stype && skip !== 'stype') || (f.sev && skip !== 'sev')) {
    const list = e.byResource.get(r.key) || [];
    if (!list.some((s) => (!f.stype || skip === 'stype' || s.type === f.stype)
      && (!f.sev || skip === 'sev' || s.severity === f.sev)
      && (!!f.stype || !!f.hyg || !s.hygiene))) return false;
  }
  return true;
}

const RESOURCE_ONLY: FilterKey[] = ['size', 'region', 'env', 'state', 'exp', 'has'];

export function suggestionMatches(e: Estate, s: Suggestion, f: Filters, skip?: FilterKey): boolean {
  if (!visibleSuggestion(s, f)) return false;
  if (f.q && skip !== 'q'
    && !`${s.title} ${s.resourceName} ${s.type} ${s.subscription}`.toLowerCase().includes(f.q.toLowerCase())) return false;
  if (f.sub && skip !== 'sub' && s.subscriptionId !== f.sub) return false;
  if (f.stype && skip !== 'stype' && s.type !== f.stype) return false;
  if (f.sev && skip !== 'sev' && s.severity !== f.sev) return false;
  if (f.category && skip !== 'category' && s.category !== f.category) return false;
  if (f.type && skip !== 'type' && s.typeLabel !== f.type) return false;
  const other = RESOURCE_ONLY.filter((k) => f[k] && k !== skip);
  if (other.length) {
    const r = s.resourceId ? e.resourceIndex.get(s.resourceId.toLowerCase()) : undefined;
    if (!r) return false;
    const sub: Filters = Object.fromEntries(other.map((k) => [k, f[k]]));
    if (!resourceMatches(e, r, sub)) return false;
  }
  return true;
}

export function countBy<T>(items: T[], fn: (x: T) => string | null | undefined): [string, number][] {
  const counts = new Map<string, number>();
  items.forEach((x) => {
    const k = fn(x);
    if (k === undefined || k === null) return;
    counts.set(k, (counts.get(k) || 0) + 1);
  });
  return Array.from(counts.entries()).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

// Exposure of the web endpoints among these resources, plus how many answer on a custom domain.
export function exposureEntries(list: Resource[]): [string, number][] {
  const web = list.filter((r) => r.endpoint);
  const entries = countBy(web, (r) => r.endpoint!.exposure || null);
  const custom = web.filter((r) => r.endpoint!.domains.length).length;
  return custom ? entries.concat([[CUSTOM_DOMAIN, custom]]) : entries;
}

// ---- columns, sorting, CSV ---------------------------------------------------------------------

export interface Column {
  key: string;
  label: string;
  num?: boolean;
  compute?: boolean;
  pct?: boolean;
  usage?: boolean;
  sortKey?: string;
}

export const RESOURCE_COLUMNS: Column[] = [
  { key: 'name', label: 'Name' }, { key: 'typeLabel', label: 'Type' }, { key: 'size', label: 'Size / SKU' },
  { key: 'vcpu', label: 'vCPU', num: true, compute: true }, { key: 'ramGB', label: 'RAM (GB)', num: true, compute: true },
  { key: 'cpuAvg', label: 'CPU avg 30 d', num: true, compute: true, pct: true },
  { key: 'cpuPeakHour', label: 'CPU busiest hour', num: true, compute: true, pct: true },
  { key: 'memAvg', label: 'Memory avg 30 d', num: true, compute: true, pct: true },
  { key: 'usage', label: 'Usage (30 d)', sortKey: 'activity', usage: true },
  { key: 'config', label: 'Configuration' }, { key: 'os', label: 'OS / runtime' }, { key: 'state', label: 'State' },
  { key: 'env', label: 'Environment' }, { key: 'location', label: 'Region' }, { key: 'subscription', label: 'Subscription' },
  { key: 'resourceGroup', label: 'Resource group' }, { key: 'cost30', label: 'Last 30 d', num: true },
  { key: 'suggestions', label: 'Suggestions', num: true },
];

export const SUGGESTION_COLUMNS: Column[] = [
  { key: 'severity', label: 'Severity' }, { key: 'title', label: 'Suggestion' }, { key: 'type', label: 'Suggestion type' },
  { key: 'resourceName', label: 'Resource' }, { key: 'typeLabel', label: 'Resource type' },
  { key: 'subscription', label: 'Subscription' }, { key: 'savingsUsd', label: 'Est. saving / month', num: true },
  { key: 'wave', label: 'Wave', num: true },
];

// Why a cell is empty: shown as a muted "-" with this explanation instead of a blank.
export const BLANK_REASON: Record<string, string> = {
  cost30: 'No cost data: the app registration has no Cost Management Reader role on this subscription',
  usage: 'Azure Monitor has no activity metric for this type, or no data in 30 days',
  vcpu: 'Only for VMs and scale sets', ramGB: 'Only for VMs and scale sets',
  cpuAvg: 'No CPU metric (not a VM, or not running in 30 days)',
  cpuPeakHour: 'No CPU metric (not a VM, or not running in 30 days)',
  memAvg: 'No memory metric (not a VM, or not running in 30 days)',
  size: 'This type has no SKU or size', config: 'Nothing to configure beyond the defaults for this type',
  os: 'Only for machines, apps and containers', state: 'No state reported: running / provisioned normally',
};

export type Sort = { key: string; dir: 1 | -1 };

type Row = Resource | Suggestion;
const field = (x: Row, key: string) => (x as unknown as Record<string, unknown>)[key];

export function sortRows<T extends Row>(items: T[], columns: Column[], sort: Sort, view: View): T[] {
  const col = columns.find((c) => c.key === sort.key);
  if (!col) {
    return view === 'suggestions'
      ? items.sort((a, b) => sevRank((a as Suggestion).severity) - sevRank((b as Suggestion).severity)
        || ((b as Suggestion).savingsUsd || 0) - ((a as Suggestion).savingsUsd || 0))
      : items;
  }
  const key = col.sortKey || col.key;
  const numeric = col.num || !!col.sortKey || col.key === 'severity';
  const value = (x: T) => (col.key === 'severity' ? sevRank((x as Suggestion).severity) : field(x, key));
  return items.sort((a, b) => {
    const va = value(a);
    const vb = value(b);
    if (numeric) {
      return ((va === null || va === undefined ? -1 : Number(va)) - (vb === null || vb === undefined ? -1 : Number(vb))) * sort.dir;
    }
    return String(va ?? '').localeCompare(String(vb ?? '')) * sort.dir;
  });
}

export function cpuProfile(r: Resource): string {
  return [
    r.cpuAvg !== null ? `30-day average ${r.cpuAvg.toFixed(1)} %` : null,
    r.cpuPeakHour !== null ? `busiest hour ${r.cpuPeakHour.toFixed(1)} %` : null,
    r.cpuP95 !== null ? `95 % of hours at or below ${r.cpuP95.toFixed(1)} %` : null,
    r.cpuMax !== null
      ? `1-minute peak ${r.cpuMax.toFixed(0)} %${r.burstHours ? ` (bursts of 90 %+ in ${r.burstHours} hours)` : ''}` : null,
  ].filter(Boolean).join(', ');
}

export const fmt = (n: number | null | undefined) =>
  n === undefined || n === null ? '' : Number(n).toLocaleString(undefined, { maximumFractionDigits: 0 });

export function cellText(r: Resource, c: Column): string {
  const v = field(r, c.key) as string | number | null | undefined;
  if (c.key === 'cost30') return v === null || v === undefined ? '' : `${v ? fmt(v as number) : '0'} ${r.currency}`.trim();
  if (c.pct) return v === null || v === undefined ? '' : `${(v as number).toFixed(1)} %`;
  if (c.key === 'ramGB') return v ? String(v) : '';
  return v === null || v === undefined ? '' : String(v);
}

const RESOURCE_CSV = ['name', 'typeLabel', 'category', 'size', 'vcpu', 'ramGB', 'cpuAvg', 'cpuPeakHour', 'cpuP95', 'cpuMax',
  'burstHours', 'memAvg', 'usage', 'activity', 'idle', 'config', 'os', 'state', 'host', 'domains', 'webExposure', 'env',
  'location', 'subscription',
  'resourceGroup', 'cost30', 'currency', 'suggestions', 'maxSeverity', 'id'];
const SUGGESTION_CSV = ['severity', 'title', 'type', 'resourceName', 'typeLabel', 'category', 'subscription', 'savingsUsd',
  'wave', 'resourceId', 'findingId'];

export function toCsv(rows: Row[], view: View): string {
  const columns = view === 'resources' ? RESOURCE_CSV : SUGGESTION_CSV;
  const escape = (v: unknown) => {
    let text = v === undefined || v === null ? '' : String(v);
    if (/^[=+\-@]/.test(text)) text = `'${text}`; // no formula injection when opened in Excel
    return /[",\n;]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  const lines = [columns.join(',')].concat(rows.map((r) => columns.map((c) => escape(field(r, c))).join(',')));
  return `\ufeff${lines.join('\r\n')}`;
}

/**
 * Compute data model (GET /estate/compute, collected by the estate refresh: scripts/subscription_analysis/compute.py,
 * scanners/compute/machine_inventory.py) - row shaping, filters, facet counts and CSV. No React in here.
 */

export interface SqlInstance {
  id: string; name: string; machine: string; product: string; edition: string; build: string; service: string;
  status: string; license: string; support: string; supportEnds: string | null; supportNote: string; esu: string;
  esuEnabled: boolean | null; subscription?: string; resourceGroup: string;
}

export interface Machine {
  id: string; name: string; kind: 'vm' | 'arc'; subscription: string; resourceGroup: string; location: string;
  env: string; running: boolean; state: string; lastSeen: string | null; computer: string; os: string;
  osReported: string; osSource: string; image: string; family: string; support: string; supportEnds: string | null;
  supportNote: string; esu: string; publicIp: boolean | null; defenderPlan: string; agents: string[]; scanner: string;
  scannerNote: string; patchAssessment: string | null;
  patches: { security: number; critical: number; other: number; reboot: boolean; assessed: string | null; names: string[]; more: number } | null;
  packages: { count: number; high: number; names: string[]; more: number } | null;
  cves: { count: number; critical: number; high: number; ids: string[] } | null;
  sql: SqlInstance[]; criticalPath: boolean; reasons: string[];
}

export interface AppRuntime {
  id: string; name: string; subscription: string; resourceGroup: string; kind: string; stack: string; version: string;
  runtime: string; support: string; supportEnds: string | null; supportNote: string; exposure: string; state: string;
  internet?: boolean; urls?: string[];
}

/** One container of a Container App, Container Apps job, Container Instance or App Service custom container. */
export interface ContainerImage {
  id: string; name: string; workload: string; kind: string; subscription: string; resourceGroup: string; image: string;
  registry: string; registryLabel: string; repository: string; tag: string; digest: string; exposed: boolean;
  exposure: string; url: string; running: boolean; state: string; scan: string; packages: string[]; high: number;
}

export interface ComputeSummary {
  machines: number; vms: number; arc: number; support: Record<string, number>; noScanner: number;
  noScannerExposed: number; criticalPath: number; pendingSecurity: number; arcStale: number;
  sources: Record<string, number>; sql: { instances: number; ended: number; ending: number; esu: number };
  apps: { total: number; ended: number; ending: number };
  images?: { total: number; distinct: number; exposed: number; withFindings: number; noFindings: number; outsideAcr: number };
}

export interface ComputeData {
  collected_at: string | null; machines: Machine[]; sql: SqlInstance[]; apps: AppRuntime[]; images?: ContainerImage[];
  summary: ComputeSummary; warnings: string[];
}

export type ComputeView = 'machines' | 'sql' | 'apps' | 'images';
export type Row = Record<string, any>;   // eslint-disable-line @typescript-eslint/no-explicit-any

export const FILTER_KEYS = ['view', 'q', 'sub', 'family', 'support', 'kind', 'state', 'exposure', 'scanner', 'env', 'critical', 'pending',
  'cve'];
export const SUPPORT_ORDER = ['ended', 'ending', 'esu', 'unknown', 'appliance', 'supported'];
export const SUPPORT_LABELS: Record<string, string> = {
  ended: 'Support ended', ending: 'Ending soon', esu: 'On ESU', supported: 'Supported', unknown: 'Not identified',
  appliance: 'Network appliance',
};
export const SUPPORT_SEVERITY: Record<string, string> = {
  ended: 'critical', ending: 'high', esu: 'medium', supported: 'low', unknown: 'info', appliance: 'info',
};
export const SCANNER_LABELS: Record<string, string> = { covered: 'Covered', none: 'None', unverified: 'Not verified' };
/** What a container's Defender scan status means - an image without findings is not proof it was scanned. */
export const SCAN_NOTES: Record<string, string> = {
  'no Defender findings':
    'up to date, or not scanned: Defender for Containers / CSPM scans images in Azure Container Registry and reports only outdated packages',
  'not in Azure Container Registry': 'Defender does not scan this registry; pull it through Azure Container Registry to get it scanned',
  'no findings for this tag': 'other tags of this repository have findings, this one has none',
};

const leaf = (id: string) => (id || '').split('/').filter(Boolean).pop() || '';
/** First URL without the scheme, plus how many more: "app.example.com (+1)". */
export const urlLabel = (urls?: string[]) =>
  urls && urls.length ? urls[0].replace(/^https:\/\//, '') + (urls.length > 1 ? ` (+${urls.length - 1})` : '') : '';
/** A container row is one container of a workload, so the resource ID alone is not unique. */
export const rowKey = (view: ComputeView, r: Row) => (view === 'images' ? `${r.id}|${r.name}` : r.id);
export const supportRank = (s: string) => {
  const i = SUPPORT_ORDER.indexOf(s);
  return i < 0 ? 9 : i;
};

export function prepare(d: ComputeData): Record<ComputeView, Row[]> {
  const machines = (d.machines || []).map((m) => {
    const p = m.patches;
    const sql = m.sql || [];
    const haystack = [m.name, m.computer, m.os, m.osReported, m.image, m.family, m.supportNote, m.subscription,
      m.resourceGroup, m.env, (m.agents || []).join(' '), (p?.names || []).join(' '), (m.packages?.names || []).join(' '),
      (m.cves?.ids || []).join(' '), sql.map((s) => `${s.name} ${s.product} ${s.edition} ${s.build}`).join(' ')]
      .join(' ').toLowerCase();
    return {
      ...m,
      kindLabel: m.kind === 'arc' ? 'Arc server' : 'Azure VM',
      supportRank: supportRank(m.support),
      exposureLabel: m.publicIp === null ? 'n/a (on-premises)' : m.publicIp ? (m.running ? 'Yes' : 'Yes (stopped)') : 'No',
      scannerLabel: SCANNER_LABELS[m.scanner] ?? m.scanner,
      updates: p ? (p.security || 0) + (p.critical || 0) : null,
      outdated: m.packages ? m.packages.count : null,
      cveCount: m.cves ? m.cves.count : null,
      sqlLabel: sql.length ? Array.from(new Set(sql.map((s) => s.product))).join(', ') + (sql.length > 1 ? ` (${sql.length})` : '') : '',
      haystack,
    };
  });
  const sql = (d.sql || []).map((s) => ({
    ...s,
    host: leaf(s.machine),
    supportRank: supportRank(s.support),
    esuLabel: s.support === 'esu' ? 'Enrolled' : s.esuEnabled ? 'Enabled' : s.esu ? 'Not enrolled' : '',
    haystack: [s.name, leaf(s.machine), s.product, s.edition, s.build, s.service, s.supportNote, s.subscription, s.resourceGroup]
      .join(' ').toLowerCase(),
  }));
  const apps = (d.apps || []).map((a) => ({
    ...a,
    supportRank: supportRank(a.support),
    urlLabel: urlLabel(a.urls),
    haystack: [a.name, a.kind, a.runtime, a.stack, a.version, a.supportNote, a.subscription, a.resourceGroup, a.exposure,
      (a.urls || []).join(' ')].join(' ').toLowerCase(),
  }));
  const images = (d.images || []).map((i) => ({
    ...i,
    packageCount: (i.packages || []).length || null,
    high: i.high || null,
    haystack: [i.name, i.kind, i.image, i.registry, i.registryLabel, i.tag, i.exposure, i.scan, i.url,
      (i.packages || []).join(' '), i.subscription, i.resourceGroup].join(' ').toLowerCase(),
  }));
  return { machines, sql, apps, images };
}

export const familyOf = (view: ComputeView, r: Row): string =>
  (view === 'machines' ? r.family || 'Not identified' : view === 'sql' ? r.product : view === 'images' ? r.registryLabel : r.stack);

/** The support status of a row; for a container its Defender scan status. */
export const statusOf = (view: ComputeView, r: Row): string => (view === 'images' ? r.scan : r.support);

/** Software / CVE search (every term must match) and the facet filters; `skip` leaves one out for facet counts. */
export function matches(view: ComputeView, r: Row, f: Record<string, string>, skip?: string): boolean {
  const want = (k: string) => k !== skip && !!f[k];
  if (want('q') && !f.q.toLowerCase().split(/\s+/).filter(Boolean).every((t) => r.haystack.includes(t))) return false;
  if (want('sub') && r.subscription !== f.sub) return false;
  if (want('support') && statusOf(view, r) !== f.support) return false;
  if (want('family') && familyOf(view, r) !== f.family) return false;
  if (view === 'images') {
    if (want('state') && (f.state === 'running') !== !!r.running) return false;
    if (want('exposure') && (f.exposure === 'public') !== !!r.exposed) return false;
  }
  if (view === 'machines') {
    if (want('kind') && r.kind !== f.kind) return false;
    if (want('state') && (f.state === 'running') !== !!r.running) return false;
    if (want('exposure') && (f.exposure === 'public' ? !(r.publicIp && r.running) : !!r.publicIp)) return false;
    if (want('scanner') && r.scanner !== f.scanner) return false;
    if (want('env') && r.env !== f.env) return false;
    if (want('critical') && !r.criticalPath) return false;
    if (want('pending') && !(r.updates > 0)) return false;
  }
  return true;
}

export function countBy(rows: Row[], fn: (r: Row) => string): [string, number][] {
  const counts = new Map<string, number>();
  rows.forEach((r) => {
    const k = fn(r);
    if (k) counts.set(k, (counts.get(k) || 0) + 1);
  });
  return Array.from(counts.entries()).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

/** Critical path (machines) or internet-facing and most outdated packages (containers) first, then by support status,
 *  then by name. */
export function defaultOrder(view: ComputeView, rows: Row[]): Row[] {
  return rows.slice().sort((a, b) =>
    (view === 'machines' ? (b.criticalPath ? 1 : 0) - (a.criticalPath ? 1 : 0) : 0)
    || (view === 'images' ? (b.exposed ? 1 : 0) - (a.exposed ? 1 : 0) || (b.packageCount || 0) - (a.packageCount || 0) : 0)
    || (a.supportRank || 0) - (b.supportRank || 0) || String(a.name).localeCompare(String(b.name)));
}

const CSV_COLUMNS: Record<ComputeView, string[]> = {
  machines: ['name', 'kindLabel', 'os', 'osReported', 'image', 'family', 'support', 'supportEnds', 'supportNote', 'esu',
    'exposureLabel', 'scannerLabel', 'scannerNote', 'defenderPlan', 'updates', 'outdated', 'cveCount', 'sqlLabel',
    'criticalPath', 'state', 'env', 'subscription', 'resourceGroup', 'location', 'id'],
  sql: ['name', 'host', 'product', 'edition', 'build', 'service', 'support', 'supportEnds', 'supportNote', 'esuLabel',
    'status', 'license', 'subscription', 'resourceGroup', 'id'],
  apps: ['name', 'kind', 'runtime', 'support', 'supportEnds', 'supportNote', 'exposure', 'urls', 'state', 'subscription',
    'resourceGroup', 'id'],
  images: ['name', 'workload', 'kind', 'image', 'registry', 'repository', 'tag', 'digest', 'exposure', 'url', 'scan',
    'packages', 'high', 'state', 'subscription', 'resourceGroup', 'id'],
};

export function toCsv(rows: Row[], view: ComputeView): string {
  const columns = CSV_COLUMNS[view];
  const escape = (v: unknown) => {
    let text = v === undefined || v === null ? '' : Array.isArray(v) ? v.join(' ') : String(v);
    if (/^[=+\-@]/.test(text)) text = `'${text}`;   // no formula injection when opened in Excel
    return /[",\n;]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  return '﻿' + [columns.join(',')].concat(rows.map((r) => columns.map((c) => escape(r[c])).join(','))).join('\r\n');
}

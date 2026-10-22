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
}

export interface ComputeSummary {
  machines: number; vms: number; arc: number; support: Record<string, number>; noScanner: number;
  noScannerExposed: number; criticalPath: number; pendingSecurity: number; arcStale: number;
  sources: Record<string, number>; sql: { instances: number; ended: number; ending: number; esu: number };
  apps: { total: number; ended: number; ending: number };
}

export interface ComputeData {
  collected_at: string | null; machines: Machine[]; sql: SqlInstance[]; apps: AppRuntime[]; summary: ComputeSummary;
  warnings: string[];
}

export type ComputeView = 'machines' | 'sql' | 'apps';
export type Row = Record<string, any>;   // eslint-disable-line @typescript-eslint/no-explicit-any

export const FILTER_KEYS = ['view', 'q', 'sub', 'family', 'support', 'kind', 'state', 'exposure', 'scanner', 'env', 'critical', 'pending'];
export const SUPPORT_ORDER = ['ended', 'ending', 'esu', 'unknown', 'appliance', 'supported'];
export const SUPPORT_LABELS: Record<string, string> = {
  ended: 'Support ended', ending: 'Ending soon', esu: 'On ESU', supported: 'Supported', unknown: 'Not identified',
  appliance: 'Network appliance',
};
export const SUPPORT_SEVERITY: Record<string, string> = {
  ended: 'critical', ending: 'high', esu: 'medium', supported: 'low', unknown: 'info', appliance: 'info',
};
export const SCANNER_LABELS: Record<string, string> = { covered: 'Covered', none: 'None', unverified: 'Not verified' };

const leaf = (id: string) => (id || '').split('/').filter(Boolean).pop() || '';
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
    haystack: [a.name, a.kind, a.runtime, a.stack, a.version, a.supportNote, a.subscription, a.resourceGroup, a.exposure]
      .join(' ').toLowerCase(),
  }));
  return { machines, sql, apps };
}

export const familyOf = (view: ComputeView, r: Row): string =>
  (view === 'machines' ? r.family || 'Not identified' : view === 'sql' ? r.product : r.stack);

/** Software / CVE search (every term must match) and the facet filters; `skip` leaves one out for facet counts. */
export function matches(view: ComputeView, r: Row, f: Record<string, string>, skip?: string): boolean {
  const want = (k: string) => k !== skip && !!f[k];
  if (want('q') && !f.q.toLowerCase().split(/\s+/).filter(Boolean).every((t) => r.haystack.includes(t))) return false;
  if (want('sub') && r.subscription !== f.sub) return false;
  if (want('support') && r.support !== f.support) return false;
  if (want('family') && familyOf(view, r) !== f.family) return false;
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

/** Critical path first, then by support status, then by name. */
export function defaultOrder(view: ComputeView, rows: Row[]): Row[] {
  return rows.slice().sort((a, b) =>
    (view === 'machines' ? (b.criticalPath ? 1 : 0) - (a.criticalPath ? 1 : 0) : 0)
    || a.supportRank - b.supportRank || String(a.name).localeCompare(String(b.name)));
}

const CSV_COLUMNS: Record<ComputeView, string[]> = {
  machines: ['name', 'kindLabel', 'os', 'osReported', 'image', 'family', 'support', 'supportEnds', 'supportNote', 'esu',
    'exposureLabel', 'scannerLabel', 'scannerNote', 'defenderPlan', 'updates', 'outdated', 'cveCount', 'sqlLabel',
    'criticalPath', 'state', 'env', 'subscription', 'resourceGroup', 'location', 'id'],
  sql: ['name', 'host', 'product', 'edition', 'build', 'service', 'support', 'supportEnds', 'supportNote', 'esuLabel',
    'status', 'license', 'subscription', 'resourceGroup', 'id'],
  apps: ['name', 'kind', 'runtime', 'support', 'supportEnds', 'supportNote', 'exposure', 'state', 'subscription',
    'resourceGroup', 'id'],
};

export function toCsv(rows: Row[], view: ComputeView): string {
  const columns = CSV_COLUMNS[view];
  const escape = (v: unknown) => {
    let text = v === undefined || v === null ? '' : String(v);
    if (/^[=+\-@]/.test(text)) text = `'${text}`;   // no formula injection when opened in Excel
    return /[",\n;]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  return '﻿' + [columns.join(',')].concat(rows.map((r) => columns.map((c) => escape(r[c])).join(','))).join('\r\n');
}

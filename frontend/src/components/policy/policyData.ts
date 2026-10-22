/**
 * Azure Policy analysis data model (GET /estate/policy, built by scripts/subscription_analysis/policy_analyzer.py over
 * the estate refresh's policy collection) - row shaping, filters, facet counts, the assignment tree's inheritance and
 * CSV. No React in here.
 */

export type PolicyView = 'issues' | 'tree' | 'assignments' | 'subscriptions' | 'policies' | 'exemptions';
export type Row = Record<string, any>;   // eslint-disable-line @typescript-eslint/no-explicit-any

export interface Issue {
  key: string; severity: string; title: string; detail: string; count: number; items: string[]; fix: string;
}

export interface TreeNode {
  id: string; kind: string; label: string; parent: string | null; scope: string; children: string[];
  assigned: string[]; inherited: number; effects: Record<string, number>; notEnforced: number; issues: number;
  subscriptions: number; assignedBelow: number;
}

export interface Tree { roots: string[]; nodes: Record<string, TreeNode> }

export interface PolicyAnalysis {
  collected_at: string | null;
  summary: {
    assignments: number; initiatives: number; byScope: Record<string, number>; policies: number;
    byEffect: Record<string, number>; subscriptions: number; subscriptionsWithoutDeny: number; noncompliant: number;
    evaluated: number; compliance: number | null; exemptions: number; exemptionsNoExpiry: number;
    issues: Record<string, number>; complianceDetail: boolean;
  };
  issues: Issue[];
  assignments: Row[];
  profiles: Record<string, [string, string][]>;
  tree?: Tree;
  subscriptions: Row[];
  policies: Row[];
  exemptions: Row[];
}

export const VIEWS: PolicyView[] = ['issues', 'tree', 'assignments', 'subscriptions', 'policies', 'exemptions'];
export const VIEW_LABELS: Record<PolicyView, string> = {
  issues: 'Issues', tree: 'Tree', assignments: 'Assignments', subscriptions: 'Subscriptions', policies: 'Policies',
  exemptions: 'Exemptions',
};
export const FILTER_KEYS = ['view', 'q', 'scope', 'effect', 'source', 'category', 'enforcement', 'status', 'issues',
  'hidesubs', 'node'];
/** The views each facet filter applies to. */
export const APPLIES: Record<string, PolicyView[]> = {
  scope: ['assignments', 'exemptions'], effect: ['assignments', 'subscriptions', 'policies'],
  source: ['assignments', 'policies'], category: ['assignments', 'policies'], enforcement: ['assignments'],
  status: ['exemptions'], issues: ['assignments', 'subscriptions', 'policies'],
};

export interface Column { key: string; label: string; num?: boolean; pct?: boolean }

export const COLUMNS: Record<Exclude<PolicyView, 'issues' | 'tree'>, Column[]> = {
  assignments: [
    { key: 'display', label: 'Assignment' }, { key: 'scopeText', label: 'Scope' }, { key: 'definition', label: 'Definition' },
    { key: 'typeLabel', label: 'Type' }, { key: 'policies', label: 'Policies', num: true }, { key: 'effectsText', label: 'Effects' },
    { key: 'enforcement', label: 'Enforcement' }, { key: 'identity', label: 'Identity' },
    { key: 'noncompliant', label: 'Non-compliant', num: true }, { key: 'compliance', label: 'Compliance %', num: true, pct: true },
    { key: 'exemptions', label: 'Exemptions', num: true }, { key: 'issuesText', label: 'Issues' },
  ],
  subscriptions: [
    { key: 'name', label: 'Subscription' }, { key: 'path', label: 'Management groups' },
    { key: 'inherited', label: 'Inherited', num: true }, { key: 'direct', label: 'Direct', num: true },
    { key: 'policies', label: 'Policies', num: true }, { key: 'deny', label: 'Deny', num: true },
    { key: 'remediate', label: 'Remediate', num: true }, { key: 'audit', label: 'Audit', num: true },
    { key: 'compliance', label: 'Compliance %', num: true, pct: true }, { key: 'noncompliant', label: 'Non-compliant', num: true },
    { key: 'issuesText', label: 'Issues' },
  ],
  policies: [
    { key: 'display', label: 'Policy' }, { key: 'category', label: 'Category' }, { key: 'source', label: 'Source' },
    { key: 'strongest', label: 'Strongest effect' }, { key: 'effectsText', label: 'Effects' },
    { key: 'assignments', label: 'Assignments', num: true }, { key: 'scopesText', label: 'Assigned at' },
    { key: 'noncompliant', label: 'Non-compliant', num: true }, { key: 'flags', label: 'Flags' },
  ],
  exemptions: [
    { key: 'display', label: 'Exemption' }, { key: 'category', label: 'Category' }, { key: 'scopeText', label: 'Scope' },
    { key: 'assignment', label: 'Assignment' }, { key: 'policiesText', label: 'Policies' }, { key: 'expires', label: 'Expires' },
    { key: 'status', label: 'Status' },
  ],
};

/** Effect classes, strongest first. */
export const EFFECT_CLASSES = ['deny', 'remediate', 'audit', 'disabled'];
export const EFFECT_SEVERITY: Record<string, string> = { deny: 'critical', remediate: 'high', audit: 'low', disabled: 'info' };

export const effectsText = (e: Record<string, number> | undefined) =>
  Object.entries(e || {}).map(([k, n]) => `${n} ${k}`).join(' · ');

export const effectClass = (effect: string) => {
  const e = (effect || '').toLowerCase();
  if (e === 'deny' || e === 'denyaction') return 'deny';
  if (e === 'deployifnotexists' || e === 'modify' || e === 'append') return 'remediate';
  return e === 'disabled' ? 'disabled' : 'audit';
};

export function prepare(d: PolicyAnalysis): Record<PolicyView, Row[]> {
  return {
    tree: [],
    issues: d.issues.map((i) => ({
      ...i, id: i.key, haystack: [i.title, i.detail, i.fix, i.items.join(' ')].join(' ').toLowerCase(),
    })),
    assignments: d.assignments.map((a) => ({
      ...a,
      scopeText: `${a.scopeKind}: ${a.scopeLabel}`,
      typeLabel: a.initiative ? 'Initiative' : 'Policy',
      effectsText: effectsText(a.effects),
      issuesText: (a.issues || []).join(', '),
      haystack: [a.display, a.name, a.scopeLabel, a.definition, a.category, a.source, a.identity, (a.issues || []).join(' ')]
        .join(' ').toLowerCase(),
    })),
    subscriptions: d.subscriptions.map((s) => ({
      ...s,
      remediate: s.effects?.remediate || 0,
      audit: s.effects?.audit || 0,
      issuesText: (s.issues || []).join(', '),
      haystack: [s.name, s.id, s.path, (s.issues || []).join(' ')].join(' ').toLowerCase(),
    })),
    policies: d.policies.map((p) => ({
      ...p,
      id: p.key,
      effectsText: Object.entries(p.effects || {}).map(([k, n]) => `${k} ×${n}`).join(', '),
      scopesText: (p.scopes || []).slice(0, 3).join('; ') + ((p.scopes || []).length > 3 ? ` +${p.scopes.length - 3}` : ''),
      flags: [p.deprecated ? 'deprecated' : '', p.preview ? 'preview' : '', p.notEnforced ? `${p.notEnforced}× not enforced` : '']
        .filter(Boolean).join(', '),
      haystack: [p.display, p.key, p.category, p.source, (p.scopes || []).join(' ')].join(' ').toLowerCase(),
    })),
    exemptions: d.exemptions.map((e) => ({
      ...e,
      scopeText: e.scopeKind ? `${e.scopeKind}: ${e.scopeLabel}` : '',
      policiesText: e.policies ? String(e.policies) : 'all',
      expires: e.expires || 'never',
      haystack: [e.display, e.category, e.scopeLabel, e.assignment, e.status].join(' ').toLowerCase(),
    })),
  };
}

export const searchTerms = (q: string) => (q || '').toLowerCase().split(/\s+/).filter(Boolean);

/** Search (every term must match) and the facet filters that apply to the view; `skip` leaves one out for facet counts. */
export function matches(view: PolicyView, r: Row, f: Record<string, string>, skip?: string): boolean {
  const on = (k: string) => k !== skip && !!f[k] && (APPLIES[k] || []).includes(view);
  if (skip !== 'q' && !searchTerms(f.q).every((t) => r.haystack.includes(t))) return false;
  if (on('scope') && r.scopeKind !== f.scope) return false;
  if (on('source') && r.source !== f.source) return false;
  if (on('category') && r.category !== f.category) return false;
  if (on('enforcement') && r.enforcement !== f.enforcement) return false;
  if (on('status') && r.status !== f.status) return false;
  if (on('effect') && (view === 'policies' ? r.strongest !== f.effect : !((r.effects || {})[f.effect] > 0))) return false;
  if (on('issues') && (view === 'policies' ? !r.flags : !(r.issues || []).length)) return false;
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

/** Empty values last; numbers numerically, text alphabetically; dir 1 ascending, -1 descending. */
export function sortRows(rows: Row[], key: string, dir: number): Row[] {
  if (!key) return rows;
  return rows.slice().sort((a, b) => {
    const x = a[key];
    const y = b[key];
    if (x === y) return 0;
    if (x === null || x === undefined || x === '') return 1;
    if (y === null || y === undefined || y === '') return -1;
    return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y))) * dir;
  });
}

/** Assignments made on the node's ancestors that reach it: none of the scopes in between is in their notScopes. */
export function inheritedOf(tree: Tree, byId: Map<string, Row>, nid: string): { from: TreeNode; ids: string[] }[] {
  const out: { from: TreeNode; ids: string[] }[] = [];
  const node = tree.nodes[nid];
  if (!node || node.kind === 'Group') return out;
  const between = [node.scope];
  let parent = node.parent ? tree.nodes[node.parent] : undefined;
  while (parent && parent.kind !== 'Group') {
    const ids = parent.assigned.filter((id) => {
      const notScopes: string[] = byId.get(id)?.notScopes || [];
      return !between.some((x) => notScopes.includes(x));
    });
    if (ids.length) out.push({ from: parent, ids });
    between.push(parent.scope);
    parent = parent.parent ? tree.nodes[parent.parent] : undefined;
  }
  return out;
}

export function treeRows(d: PolicyAnalysis): Row[] {
  const nodes = d.tree?.nodes || {};
  const names = new Map(d.assignments.map((a) => [a.id as string, a.display as string]));
  return Object.values(nodes).map((n) => ({
    kind: n.kind, label: n.label, parent: n.parent ? nodes[n.parent]?.label ?? '' : '', assigned: n.assigned.length,
    inherited: n.inherited, assignedBelow: n.assignedBelow, subscriptions: n.subscriptions, notEnforced: n.notEnforced,
    issues: n.issues, assignments: n.assigned.map((id) => names.get(id) ?? id).join('; '), scope: n.scope,
  }));
}

/** The policies of an assignment (its initiative's members, or its single policy) with the effect each runs with
 *  there: most non-compliant first, then strongest effect, then name. */
export function membersOf(a: Row, profiles: PolicyAnalysis['profiles'], policies: Map<string, Row>): Row[] {
  const bad: Record<string, number> = a.memberNoncompliant || {};
  return (profiles[a.profile] || []).map(([key, effect]) => {
    const p = policies.get(key) || {};
    return {
      key, effect: effect || 'default', effectClass: effectClass(effect), display: String(p.display || key),
      category: p.category || '', noncompliant: bad[key] || 0, deprecated: !!p.deprecated, preview: !!p.preview,
    };
  }).sort((x, y) => y.noncompliant - x.noncompliant
    || EFFECT_CLASSES.indexOf(x.effectClass) - EFFECT_CLASSES.indexOf(y.effectClass)
    || x.display.localeCompare(y.display));
}

const csvCell = (v: unknown) => {
  let text = v === undefined || v === null ? '' : String(v);
  if (/^[=+\-@]/.test(text)) text = `'${text}`;   // no formula injection when opened in Excel
  return /[",\n;]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
};
const csv = (columns: string[], rows: Row[]) =>
  '﻿' + [columns.join(',')].concat(rows.map((r) => columns.map((c) => csvCell(r[c])).join(','))).join('\r\n');

export function toCsv(rows: Row[], view: PolicyView): string {
  const columns = view === 'tree'
    ? ['kind', 'label', 'parent', 'assigned', 'inherited', 'assignedBelow', 'subscriptions', 'notEnforced', 'issues', 'assignments', 'scope']
    : view === 'issues'
      ? ['severity', 'title', 'count', 'detail', 'fix']
      : COLUMNS[view].map((c) => c.key).concat(view === 'assignments' ? ['definitionId', 'id'] : view === 'policies' ? ['key'] : ['id']);
  return csv(columns, rows);
}

export function membersCsv(a: Row, members: Row[]): string {
  return csv(['initiative', 'assignment', 'policy', 'category', 'effect', 'effectClass', 'noncompliant', 'deprecated', 'preview', 'definitionId'],
    members.map((m) => ({
      initiative: a.definition, assignment: a.display, policy: m.display, category: m.category, effect: m.effect,
      effectClass: m.effectClass, noncompliant: m.noncompliant, deprecated: m.deprecated ? 'yes' : '',
      preview: m.preview ? 'yes' : '', definitionId: m.key,
    })));
}

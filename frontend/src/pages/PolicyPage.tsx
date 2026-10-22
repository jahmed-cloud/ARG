/**
 * PolicyPage - Azure Policy across every connected subscription (admins), in ARG's workspace language: issues, the
 * assignment tree by scope (where an assignment is made and where it applies), every assignment with the effect each
 * of its policies runs with, the policy in effect per subscription, policies in force and exemptions.
 *
 * Data: GET /estate/policy (the estate refresh's policy collection), GET /estate/policy.md for the markdown report.
 * Filters live in the URL query string. An assignment opens as a dossier with its initiative's policies.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link as RouterLink, useSearchParams } from 'react-router-dom';
import { Drawer, Skeleton } from '@mui/material';
import { Close, Description, Download, KeyboardArrowDown, KeyboardArrowRight, Refresh } from '@mui/icons-material';
import { useSnackbar } from 'notistack';
import { useApi, ApiError } from '../hooks/useApi';
import {
  APPLIES, COLUMNS, EFFECT_CLASSES, EFFECT_SEVERITY, FILTER_KEYS, Issue, PolicyAnalysis, PolicyView, Row, Tree,
  TreeNode, VIEWS, VIEW_LABELS, countBy, effectsText, inheritedOf, matches, membersCsv, membersOf, prepare,
  searchTerms, sortRows, toCsv, treeRows,
} from '../components/policy/policyData';
import {
  SEVERITY_TONE, WsEmpty, WsFacts, WsHeading, WsList, WsMetric, WsPage, WsPanel, WsSection, WsStrip,
} from '../components/workspace/Workspace';

const PAGE_SIZE = 100;
const POLL_MS = 10000;
const fmt = (n: number | null | undefined) => (n === null || n === undefined ? '' : n.toLocaleString());

// Microsoft's Azure architecture icons, unchanged (public/azure-icons/NOTICE.md) - always shown next to the scope's name.
const SCOPE_ICONS: Record<string, string> = {
  'Management group': '/azure-icons/Management-Groups.svg',
  Subscription: '/azure-icons/Subscriptions.svg',
  'Resource group': '/azure-icons/Resource-Groups.svg',
};
const AzIcon: React.FC<{ src?: string }> = ({ src }) =>
  src ? <img className="ws-az-icon" src={src} alt="" /> : <span className="ws-az-icon" />;

const Tone: React.FC<{ tone?: string; title?: string; children: React.ReactNode }> = ({ tone, title, children }) => {
  const color = tone ? SEVERITY_TONE[tone] ?? tone : undefined;
  return <span className="ws-tag" title={title} style={color ? { color, borderColor: color } : undefined}>{children}</span>;
};

const EffectTags: React.FC<{ effects?: Record<string, number> }> = ({ effects }) => (
  <>{EFFECT_CLASSES.filter((c) => (effects || {})[c]).map((c) => <Tone key={c} tone={EFFECT_SEVERITY[c]}>{effects![c]} {c}</Tone>)}</>
);

function download(content: BlobPart, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

const IssueBlock: React.FC<{ issue: Issue }> = ({ issue }) => {
  const [all, setAll] = useState(false);
  const tone = SEVERITY_TONE[issue.severity] ?? SEVERITY_TONE.info;
  return (
    <article className="ws-issue" style={{ borderLeftColor: tone }}>
      <Tone tone={issue.severity}>{issue.severity}</Tone>
      <h3>{issue.title} <span className="ws-muted">({fmt(issue.count)})</span></h3>
      <p className="ws-text">{issue.detail}</p>
      <p className="ws-text ws-muted"><b>Fix:</b> {issue.fix}</p>
      <WsList items={all ? issue.items : issue.items.slice(0, 8)} />
      {(issue.items.length > 8 || issue.count > issue.items.length) && (
        <button type="button" className="ws-button" onClick={() => setAll(!all)}>
          {all ? 'Show fewer' : `Show all ${fmt(issue.count)}`}
        </button>
      )}
    </article>
  );
};

/** One assignment as a compact card in the tree's side panel; the name opens its dossier. */
const AssignmentCard: React.FC<{ a: Row; onOpen: (a: Row) => void }> = ({ a, onOpen }) => (
  <div className="ws-assignment">
    <div className="ws-tree-row" style={{ padding: 0 }}>
      <Tone tone={a.initiative ? '#b8d9ba' : undefined}>{a.initiative ? 'Initiative' : 'Policy'}</Tone>
      <button type="button" className="ws-link" onClick={() => onOpen(a)}>{a.definition}</button>
      {a.initiative && <span className="ws-muted" style={{ fontSize: 11 }}>{fmt(a.policies)} policies</span>}
      <EffectTags effects={a.effects} />
      {a.enforcement === 'DoNotEnforce' && <Tone tone="medium">not enforced</Tone>}
      {(a.issues || []).filter((i: string) => i !== 'not enforced').map((i: string) => <Tone key={i} tone="medium">{i}</Tone>)}
    </div>
    <p className="ws-muted" style={{ fontSize: 11, margin: '6px 0 0' }}>
      Assignment {a.display}{a.source ? ` · ${a.source}` : ''} · {a.noncompliant === null || a.noncompliant === undefined
        ? 'no compliance data' : `${fmt(a.noncompliant)} non-compliant`}
    </p>
  </div>
);

const TreeView: React.FC<{
  tree: Tree; assignments: Row[]; q: string; hideSubs: boolean; selected: string;
  onSelect: (id: string) => void; onOpen: (a: Row) => void;
}> = ({ tree, assignments, q, hideSubs, selected, onSelect, onOpen }) => {
  const byId = useMemo(() => new Map(assignments.map((a) => [a.id as string, a])), [assignments]);
  const matched = useMemo(() => {
    const terms = searchTerms(q);
    return terms.length ? new Set(assignments.filter((a) => terms.every((t) => a.haystack.includes(t))).map((a) => a.id as string)) : null;
  }, [q, assignments]);
  const [open, setOpen] = useState<Set<string>>(() => {
    const initial = new Set<string>();
    tree.roots.forEach((r) => {
      initial.add(r);
      (tree.nodes[r]?.children || []).forEach((c) => tree.nodes[c]?.kind === 'Management group' && initial.add(c));
    });
    return initial;
  });
  useEffect(() => {   // a search opens the path down to every scope a matching assignment is made on
    if (!matched) return;
    setOpen((prev) => {
      const next = new Set(prev);
      Object.values(tree.nodes).forEach((n) => {
        if (!n.assigned.some((id) => matched.has(id))) return;
        for (let p = n.parent; p; p = tree.nodes[p]?.parent ?? null) next.add(p);
      });
      return next;
    });
  }, [matched, tree]);

  const nodes = Object.values(tree.nodes);
  const bare = (n: TreeNode) => n.kind === 'Subscription' && !n.assigned.length && !n.children.length;
  const reachedBy = (n: TreeNode) => !!matched && inheritedOf(tree, byId, n.id).some((g) => g.ids.some((id) => matched.has(id)));
  const summary = matched
    ? `${fmt(matched.size)} matching assignment(s), assigned at ${fmt(nodes.filter((n) => n.assigned.some((id) => matched.has(id))).length)} scope(s), in effect on ${fmt(nodes.filter((n) => n.kind === 'Subscription' && (n.assigned.some((id) => matched.has(id)) || reachedBy(n))).length)} subscription(s).`
    : `${fmt(assignments.length)} assignments on ${fmt(nodes.length)} scopes. Search an assignment or policy to see where it is assigned and where it applies.`;

  const flip = (nid: string) => setOpen((prev) => {
    const next = new Set(prev);
    if (next.has(nid)) next.delete(nid); else next.add(nid);
    return next;
  });

  const renderNode = (nid: string): React.ReactNode => {
    const n = tree.nodes[nid];
    if (!n || (hideSubs && bare(n))) return null;
    const kids = n.children.filter((c) => !(hideSubs && tree.nodes[c] && bare(tree.nodes[c])));
    const isOpen = open.has(nid);
    const here = matched ? n.assigned.filter((id) => matched.has(id)).length : 0;
    const through = !here && reachedBy(n);
    const cls = ['ws-tree-row', selected === nid ? 'selected' : '', here ? 'here' : through ? 'through' : ''].filter(Boolean).join(' ');
    return (
      <li key={nid} role="treeitem" aria-expanded={kids.length ? isOpen : undefined} aria-selected={selected === nid}>
        <div className={cls}>
          {kids.length ? (
            <button type="button" className="ws-tree-toggle" onClick={() => flip(nid)} aria-label={`${isOpen ? 'Collapse' : 'Expand'} ${n.label}`}>
              {isOpen ? <KeyboardArrowDown fontSize="small" /> : <KeyboardArrowRight fontSize="small" />}
            </button>
          ) : <span className="ws-tree-toggle" />}
          <AzIcon src={SCOPE_ICONS[n.kind]} />
          {n.kind !== 'Group' && <span className="ws-tree-kind">{n.kind}</span>}
          <button type="button" className="ws-link" onClick={() => onSelect(nid)}>{n.label}</button>
          {here > 0 && <Tone tone="#b8d9ba">{here} assigned here</Tone>}
          {through && <Tone tone="low">in effect through a parent</Tone>}
          {n.assigned.length > 0 && <Tone tone="#b8d9ba" title="assignments made on this scope">{n.assigned.length} assigned</Tone>}
          <EffectTags effects={n.effects} />
          {n.inherited > 0 && <Tone title="assignments made above that reach this scope">{n.inherited} inherited</Tone>}
          {n.kind !== 'Subscription' && n.kind !== 'Resource group' && n.subscriptions > 0 && (
            <Tone>{n.subscriptions} subscription{n.subscriptions === 1 ? '' : 's'}</Tone>
          )}
          {n.assignedBelow > 0 && <Tone>{n.assignedBelow} assigned below</Tone>}
          {n.notEnforced > 0 && <Tone tone="medium">{n.notEnforced} not enforced</Tone>}
          {n.issues > 0 && <Tone tone="medium">{n.issues} with issues</Tone>}
        </div>
        {kids.length > 0 && isOpen && <ul role="group">{kids.map(renderNode)}</ul>}
      </li>
    );
  };

  const node = selected ? tree.nodes[selected] : undefined;
  const inherited = node ? inheritedOf(tree, byId, node.id) : [];
  const assignedHere = (node?.assigned || []).map((id) => byId.get(id)).filter((a): a is Row => !!a);
  return (
    <>
      <div className="ws-filters" style={{ alignItems: 'center' }}>
        <button type="button" className="ws-button" onClick={() => setOpen(new Set(Object.keys(tree.nodes)))}>Expand all</button>
        <button type="button" className="ws-button" onClick={() => setOpen(new Set(tree.roots))}>Collapse all</button>
        <span className="ws-muted" style={{ fontSize: 12 }}>{summary}</span>
      </div>
      <div className="ws-split">
        <div className="ws-panel" style={{ marginBottom: 0 }}>
          <ul className="ws-tree" role="tree" aria-label="Policy assignments by scope">{tree.roots.map(renderNode)}</ul>
        </div>
        <div className="ws-panel" aria-live="polite" style={{ marginBottom: 0 }}>
          {!node ? (
            <WsEmpty title="Select a scope.">
              A management group, subscription or resource group shows the assignments made on it and those it inherits.
            </WsEmpty>
          ) : (
            <>
              <p className="eyebrow">{node.kind === 'Group' ? 'Scope' : node.kind}</p>
              <div className="ws-tree-row" style={{ padding: 0 }}>
                <AzIcon src={SCOPE_ICONS[node.kind]} /><h2 style={{ margin: 0, fontSize: 18, fontWeight: 500 }}>{node.label}</h2>
              </div>
              {node.scope && <p className="ws-muted" style={{ fontSize: 11, overflowWrap: 'anywhere' }}>{node.scope}</p>}
              <WsSection number={1} title={`Assigned here (${assignedHere.length})`}>
                {assignedHere.length
                  ? assignedHere.map((a) => <AssignmentCard key={a.id} a={a} onOpen={onOpen} />)
                  : <p className="ws-text ws-muted">No assignments are made on this scope.</p>}
              </WsSection>
              <WsSection number={2} title={`Inherited (${inherited.reduce((sum, g) => sum + g.ids.length, 0)})`}>
                {inherited.length === 0 && <p className="ws-text ws-muted">Nothing reaches this scope from above.</p>}
                {inherited.map((g) => (
                  <div key={g.from.id}>
                    <p className="ws-tree-row" style={{ padding: '4px 0', margin: 0 }}>
                      <AzIcon src={SCOPE_ICONS[g.from.kind]} /><span className="ws-muted" style={{ fontSize: 12 }}>From {g.from.label}</span>
                    </p>
                    {g.ids.map((id) => byId.get(id)).filter((a): a is Row => !!a).map((a) => <AssignmentCard key={a.id} a={a} onOpen={onOpen} />)}
                  </div>
                ))}
              </WsSection>
              {node.kind !== 'Subscription' && node.subscriptions > 0 && (
                <p className="ws-muted" style={{ fontSize: 12 }}>
                  {fmt(node.subscriptions)} subscriptions and {fmt(node.assignedBelow)} further assignments below this scope.
                </p>
              )}
            </>
          )}
        </div>
      </div>
    </>
  );
};

/** The assignment dossier: what it assigns, where, how it is enforced, and every policy it brings with its effect. */
const AssignmentDossier: React.FC<{ a: Row; data: PolicyAnalysis; policies: Map<string, Row>; onClose: () => void }> = ({
  a, data, policies, onClose,
}) => {
  const [filter, setFilter] = useState('');
  const members = useMemo(() => membersOf(a, data.profiles, policies), [a, data.profiles, policies]);
  const terms = searchTerms(filter);
  const shown = members.filter((m) => terms.every((t) => [m.display, m.category, m.effect, m.effectClass, m.key].join(' ').toLowerCase().includes(t)));
  let n = 0;
  return (
    <div className="dossier" role="dialog" aria-label="Policy assignment dossier">
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
        <p className="eyebrow">{a.initiative ? 'Initiative' : 'Policy'} assignment · {a.scopeKind}</p>
        <button type="button" className="ws-button" onClick={onClose}><Close fontSize="inherit" />Close</button>
      </div>
      <h1>{a.display}</h1>
      <p className="ws-text ws-muted">{a.definition}{a.source ? ` · ${a.source}` : ''}</p>
      <WsStrip>
        <WsMetric label="Policies" value={fmt(a.policies) || '1'} note={effectsText(a.effects) || undefined} />
        <WsMetric label="Non-compliant" value={a.noncompliant === null || a.noncompliant === undefined ? '–' : fmt(a.noncompliant)} note="resources" />
        <WsMetric label="Compliance" value={a.compliance === null || a.compliance === undefined ? '–' : `${Number(a.compliance).toFixed(1)} %`} />
        <WsMetric label="Exemptions" value={fmt(a.exemptions) || '0'} />
      </WsStrip>
      {(a.issues || []).length > 0 && (
        <WsSection number={++n} title="Issues"><WsList items={a.issues} /></WsSection>
      )}
      <WsSection number={++n} title="Assignment">
        <WsFacts rows={[
          ['Scope', `${a.scopeKind}: ${a.scopeLabel}`],
          ['Enforcement', a.enforcement === 'DoNotEnforce' ? 'not enforced (DoNotEnforce)' : 'enforced'],
          ['Managed identity', a.identity || 'none'],
          ['Excluded scopes', (a.notScopes || []).join(', ')],
          ['Category', a.category],
          ['Definition ID', a.definitionId],
          ['Assignment ID', a.id],
        ]} />
      </WsSection>
      {members.length > 0 && (
        <WsSection number={++n} title={a.initiative ? `Policies in this initiative (${fmt(members.length)})` : 'Policy'}>
          <div className="ws-filters">
            {members.length > 10 && (
              <label>Filter
                <input type="search" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="name, category, effect…"
                  aria-label={`Filter the policies of ${a.definition}`} />
              </label>
            )}
            <button type="button" className="ws-button"
              onClick={() => download(membersCsv(a, members), `policies-${a.name || 'assignment'}.csv`, 'text/csv;charset=utf-8')}>
              <Download fontSize="inherit" />CSV
            </button>
          </div>
          <table className="ws-rows">
            <thead><tr><th>Policy</th><th>Category</th><th>Effect</th><th className="num">Non-compliant here</th><th>Flags</th></tr></thead>
            <tbody>
              {shown.map((m) => (
                <tr key={m.key}>
                  <td title={m.key}>{m.display}</td>
                  <td>{m.category}</td>
                  <td><Tone tone={EFFECT_SEVERITY[m.effectClass]}>{m.effectClass}</Tone><span className="ws-muted">{m.effect}</span></td>
                  <td className="num">{m.noncompliant ? fmt(m.noncompliant) : ''}</td>
                  <td>{[m.deprecated ? 'deprecated' : '', m.preview ? 'preview' : ''].filter(Boolean).join(', ')}</td>
                </tr>
              ))}
              {!shown.length && <tr><td colSpan={5} className="ws-muted">No policy matches.</td></tr>}
            </tbody>
          </table>
        </WsSection>
      )}
    </div>
  );
};

export const PolicyPage: React.FC = () => {
  const api = useApi();
  const { enqueueSnackbar } = useSnackbar();
  const [params, setParams] = useSearchParams();
  const [data, setData] = useState<PolicyAnalysis | null>(null);
  const [notReady, setNotReady] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [sort, setSort] = useState<{ key: string; dir: number }>({ key: '', dir: 1 });
  const [shown, setShown] = useState(PAGE_SIZE);
  const [openId, setOpenId] = useState<string | null>(null);

  const f = useMemo(() => Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) ?? ''])), [params]);
  const view: PolicyView = VIEWS.includes(f.view as PolicyView) ? (f.view as PolicyView) : 'issues';
  const update = useCallback((changes: Record<string, string | null>, reset = false) => {
    const next = new URLSearchParams(reset ? {} : params);
    Object.entries(changes).forEach(([k, v]) => (v ? next.set(k, v) : next.delete(k)));
    setParams(next, { replace: true });
    setShown(PAGE_SIZE);
  }, [params, setParams]);

  const load = useCallback(async () => {
    try {
      setData(await api.get('/estate/policy'));
      setNotReady(null);
      setError(null);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) setNotReady(e.message);
      else setError(e instanceof ApiError ? e.message : 'Could not load the policy analysis');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    load();
    api.get('/estate/status').then((s: { running: boolean }) => setRunning(!!s.running)).catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load]);

  useEffect(() => {
    if (!running) return undefined;
    const timer = window.setInterval(async () => {
      const s = await api.get('/estate/status');
      if (s.running) return;
      setRunning(false);
      if (s.latest?.status === 'failed') {
        enqueueSnackbar(`Refresh failed: ${s.latest.error_message ?? 'unknown error'}`, { variant: 'error' });
      } else {
        load();
      }
    }, POLL_MS);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running]);

  const refresh = async () => {
    try {
      const r = await api.post('/estate/refresh');
      setRunning(true);
      enqueueSnackbar(r.started ? 'Inventory refresh started (about 5 minutes)' : 'A refresh is already running', { variant: 'info' });
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Could not start the refresh', { variant: 'error' });
    }
  };

  const report = async () => {
    try {
      const blob: Blob = await api.get('/estate/policy.md');
      download(blob, `policy-analysis-${new Date().toISOString().slice(0, 10)}.md`, 'text/markdown');
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Could not download the report', { variant: 'error' });
    }
  };

  const rows = useMemo(() => (data ? prepare(data) : null), [data]);
  const policyByKey = useMemo(() => new Map((data?.policies || []).map((p) => [p.key as string, p])), [data]);
  const list = useMemo(() => (rows ? sortRows(rows[view].filter((r) => matches(view, r, f)), sort.key, sort.dir) : []),
    [rows, view, f, sort]);
  const facets = useMemo(() => {
    if (!rows) return { scope: [], source: [], category: [], status: [] } as Record<string, [string, number][]>;
    const base = (k: string) => rows[view].filter((r) => matches(view, r, f, k));
    return {
      scope: countBy(base('scope'), (r) => r.scopeKind),
      source: countBy(base('source'), (r) => r.source),
      category: countBy(base('category'), (r) => r.category),
      status: countBy(view === 'exemptions' ? base('status') : rows.exemptions, (r) => r.status),
    };
  }, [rows, view, f]);
  const opened = openId ? rows?.assignments.find((a) => a.id === openId) ?? null : null;

  const s = data?.summary;
  const hasFilters = FILTER_KEYS.some((k) => k !== 'view' && f[k]);
  const applies = (k: string) => (APPLIES[k] || []).includes(view);
  const notEnforced = (rows?.assignments || []).filter((a) => a.enforcement === 'DoNotEnforce').length;
  const effectBars = s ? EFFECT_CLASSES.map((c) => [c, s.byEffect[c] || 0] as [string, number]) : [];
  const shortcuts: [string, number, Record<string, string | null>, boolean][] = s ? [
    ['High and medium issues', (s.issues.high || 0) + (s.issues.medium || 0), { view: null }, view === 'issues' && !hasFilters],
    ['Subscriptions without Deny', s.subscriptionsWithoutDeny, { view: 'subscriptions', issues: '1' }, view === 'subscriptions' && !!f.issues],
    ['Assignments not enforced', notEnforced, { view: 'assignments', enforcement: 'DoNotEnforce' }, view === 'assignments' && f.enforcement === 'DoNotEnforce'],
    ['Exemptions without an end date', s.exemptionsNoExpiry, { view: 'exemptions', status: 'no end date' }, view === 'exemptions' && f.status === 'no end date'],
  ] : [];
  const barMax = (values: number[]) => Math.max(1, ...values);

  const facet = (key: string, label: string, entries: [string, number][]) => applies(key) && (
    <label>{label}
      <select value={entries.some(([v]) => v === f[key]) ? f[key] : ''} onChange={(e) => update({ [key]: e.target.value || null })}>
        <option value="">All</option>{entries.map(([v, c]) => <option key={v} value={v}>{v} ({fmt(c)})</option>)}
      </select>
    </label>
  );

  return (
    <WsPage label="Azure Policy">
      <WsHeading
        eyebrow="Assessment / Policy"
        title="What Azure Policy enforces."
        subtitle="And where it falls short."
        intro={<>
          Every assignment with the effect each of its policies runs with, the policy in effect on each subscription, policies in force,
          exemptions and issues{data?.collected_at ? `, from the inventory of ${new Date(data.collected_at).toLocaleString()}` : ''}.
          The comparison with the Azure landing zone reference is on the <RouterLink to="/architecture?view=landing">Architecture page</RouterLink>.
        </>}
        actions={<>
          <button type="button" className="ws-button solid" onClick={refresh} disabled={running}
            title="Runs the estate refresh, which collects every assignment, definition, exemption and compliance state. Also runs after every scan.">
            <Refresh fontSize="inherit" />{running ? 'Refreshing…' : 'Refresh inventory'}
          </button>
          <button type="button" className="ws-button" onClick={report} disabled={!data}><Description fontSize="inherit" />Markdown report</button>
          <button type="button" className="ws-button" disabled={!data}
            onClick={() => data && download(toCsv(view === 'tree' ? treeRows(data) : list, view), `policy-${view}.csv`, 'text/csv;charset=utf-8')}>
            <Download fontSize="inherit" />CSV
          </button>
        </>}
      />

      {error && <div className="ws-notice" role="alert"><p className="eyebrow">Error</p>{error}</div>}
      {s && !s.complianceDetail && (
        <div className="ws-notice" role="status"><p className="eyebrow">Partial data</p>Per-subscription and per-policy compliance arrive with the next inventory refresh.</div>
      )}
      {!data && !error && !notReady && <><Skeleton height={110} /><Skeleton height={320} /></>}
      {!data && notReady && (
        <WsEmpty title="No policy collection yet">
          {running ? 'The inventory is being collected; this page updates when it is ready.' : notReady}
        </WsEmpty>
      )}

      {data && rows && s && (
        <>
          <WsStrip>
            <WsMetric label="Issues (high / medium)" value={fmt((s.issues.high || 0) + (s.issues.medium || 0))} note={`${fmt(s.issues.low || 0)} low · ${fmt(s.issues.info || 0)} info`} />
            <WsMetric label="Assignments" value={fmt(s.assignments)} note={Object.entries(s.byScope).map(([k, c]) => `${c} ${k.toLowerCase()}`).join(' · ')} />
            <WsMetric label="Policies in force" value={fmt(s.policies)} note={`${fmt(s.initiatives)} initiatives`} />
            <WsMetric label="Compliance" value={s.compliance === null ? '–' : `${s.compliance.toFixed(1)} %`} note={`${fmt(s.noncompliant)} of ${fmt(s.evaluated)} resources non-compliant`} />
            <WsMetric label="Subscriptions without Deny" value={fmt(s.subscriptionsWithoutDeny)} note={`of ${fmt(s.subscriptions)}`} />
            <WsMetric label="Exemptions without an end date" value={fmt(s.exemptionsNoExpiry)} note={`of ${fmt(s.exemptions)}`} />
          </WsStrip>

          <div className="ws-grid">
            <WsPanel eyebrow="Policies in force" title="By effect">
              <div className="ws-bars">
                {effectBars.map(([c, value]) => (
                  <button key={c} type="button" className="ws-bar" aria-pressed={view === 'policies' && f.effect === c}
                    onClick={() => update({ view: 'policies', effect: f.effect === c && view === 'policies' ? null : c }, true)}>
                    <span>{c === 'remediate' ? 'Remediate (DINE / Modify / Append)' : c[0].toUpperCase() + c.slice(1)}</span>
                    <span className="track"><i style={{ width: `${Math.max(2, (value / barMax(effectBars.map(([, v]) => v))) * 100)}%`, background: SEVERITY_TONE[EFFECT_SEVERITY[c]] }} /></span>
                    <b>{fmt(value)}</b>
                  </button>
                ))}
              </div>
            </WsPanel>
            <WsPanel eyebrow="Shortcuts" title="Where to look first">
              <div className="ws-bars">
                {shortcuts.map(([label, value, set, active]) => (
                  <button key={label} type="button" className="ws-bar" aria-pressed={active} onClick={() => update(set, true)}>
                    <span>{label}</span>
                    <span className="track"><i style={{ width: `${Math.max(2, (value / barMax(shortcuts.map(([, v]) => v))) * 100)}%` }} /></span>
                    <b>{fmt(value)}</b>
                  </button>
                ))}
              </div>
            </WsPanel>
          </div>

          <WsPanel
            eyebrow="Analysis"
            title={view === 'subscriptions' ? 'Policy in effect per subscription' : view === 'tree' ? 'Assignments by scope' : VIEW_LABELS[view]}
            actions={
              <div className="ws-switch" role="group" aria-label="Policy view">
                {VIEWS.map((v) => (
                  <button key={v} type="button" aria-pressed={view === v}
                    onClick={() => { update({ view: v === 'issues' ? null : v }); setSort({ key: '', dir: 1 }); }}>
                    {VIEW_LABELS[v]}
                  </button>
                ))}
              </div>
            }
          >
            <div className="ws-filters">
              <label>Search
                <input type="search" value={f.q} onChange={(e) => update({ q: e.target.value || null })}
                  placeholder="assignment, policy, category, scope…" />
              </label>
              {facet('scope', 'Scope', facets.scope)}
              {applies('effect') && (
                <label>Effect
                  <select value={f.effect} onChange={(e) => update({ effect: e.target.value || null })}>
                    <option value="">All</option><option value="deny">Deny</option>
                    <option value="remediate">DeployIfNotExists / Modify / Append</option>
                    <option value="audit">Audit</option><option value="disabled">Disabled</option>
                  </select>
                </label>
              )}
              {facet('source', 'Source', facets.source)}
              {facet('category', 'Category', facets.category)}
              {applies('enforcement') && (
                <label>Enforcement
                  <select value={f.enforcement} onChange={(e) => update({ enforcement: e.target.value || null })}>
                    <option value="">All</option><option value="Default">Enforced</option><option value="DoNotEnforce">Not enforced</option>
                  </select>
                </label>
              )}
              {facet('status', 'Exemption status', facets.status)}
              {applies('issues') && (
                <button type="button" className={`ws-button${f.issues ? ' solid' : ''}`} aria-pressed={!!f.issues}
                  onClick={() => update({ issues: f.issues ? null : '1' })}>Only with issues</button>
              )}
              {view === 'tree' && (
                <button type="button" className={`ws-button${f.hidesubs ? ' solid' : ''}`} aria-pressed={!!f.hidesubs}
                  onClick={() => update({ hidesubs: f.hidesubs ? null : '1' })}>Hide subscriptions without assignments</button>
              )}
              <button type="button" className="ws-button" disabled={!hasFilters}
                onClick={() => update({ view: view === 'issues' ? null : view }, true)}>Clear</button>
            </div>
            {view !== 'tree' && (
              <p className="ws-muted" style={{ fontSize: 12, margin: '0 0 12px' }}>
                {fmt(list.length)} of {fmt(rows[view].length)}{view === 'assignments' ? ' · select a row for its policies' : ''}
              </p>
            )}

            {view === 'tree' ? (
              data.tree ? (
                <TreeView tree={data.tree} assignments={rows.assignments} q={f.q} hideSubs={!!f.hidesubs} selected={f.node}
                  onSelect={(id) => update({ node: id })} onOpen={(a) => setOpenId(a.id)} />
              ) : <WsEmpty title="The assignment tree arrives with the next inventory refresh." />
            ) : view === 'issues' ? (
              list.length ? list.map((i) => <IssueBlock key={i.key} issue={i as Issue} />) : <WsEmpty title="No issues match." />
            ) : list.length === 0 ? <WsEmpty title="Nothing matches these filters." /> : (
              <div style={{ overflowX: 'auto' }}>
                <table className="ws-rows" aria-label="Policy results">
                  <thead>
                    <tr>
                      {COLUMNS[view].map((c) => (
                        <th key={c.key} className={c.num ? 'num' : undefined}
                          aria-sort={sort.key === c.key ? (sort.dir < 0 ? 'descending' : 'ascending') : undefined}>
                          <button type="button" className="ws-sort"
                            onClick={() => setSort({ key: c.key, dir: sort.key === c.key ? -sort.dir : c.num ? -1 : 1 })}>
                            {c.label}{sort.key === c.key ? (sort.dir < 0 ? ' ↓' : ' ↑') : ''}
                          </button>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {list.slice(0, shown).map((r) => (
                      <tr key={r.id} className={view === 'assignments' ? 'click' : undefined}
                        onClick={view === 'assignments' ? () => setOpenId(r.id) : undefined}>
                        {COLUMNS[view].map((c) => (
                          <td key={c.key} className={c.num ? 'num' : undefined}
                            style={c.key === 'issuesText' && r[c.key] ? { color: SEVERITY_TONE.medium } : undefined}>
                            {c.num
                              ? r[c.key] === null || r[c.key] === undefined ? '–' : c.pct ? Number(r[c.key]).toFixed(1) : fmt(r[c.key])
                              : c.key === 'display' ? <b>{String(r[c.key] ?? '')}</b> : String(r[c.key] ?? '')}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {view !== 'tree' && view !== 'issues' && list.length > shown && (
              <p style={{ marginTop: 14 }}>
                <button type="button" className="ws-button" onClick={() => setShown((c) => c + PAGE_SIZE)}>
                  Show {Math.min(PAGE_SIZE, list.length - shown)} more of {fmt(list.length - shown)}
                </button>
              </p>
            )}
          </WsPanel>
        </>
      )}

      <Drawer anchor="right" open={!!opened} onClose={() => setOpenId(null)} PaperProps={{ sx: { bgcolor: '#111e19' } }}>
        {opened && data && <AssignmentDossier a={opened} data={data} policies={policyByKey} onClose={() => setOpenId(null)} />}
      </Drawer>
    </WsPage>
  );
};

export default PolicyPage;

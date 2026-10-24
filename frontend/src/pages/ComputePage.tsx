/**
 * ComputePage - operating systems and their end of support, vulnerability-scan coverage, pending security updates,
 * outdated packages, CVEs, SQL Server instances, App Service runtimes and containers across every connected
 * subscription (admins), in ARG's workspace language, plus a CVE check against that inventory.
 *
 * Data: GET /estate/compute, collected by the estate refresh. Filters live in the URL query string; the search
 * matches software, packages, hostnames and CVE IDs. The critical path is an internet-facing machine with a known
 * weakness.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Drawer, Skeleton } from '@mui/material';
import { Close, Download, Refresh } from '@mui/icons-material';
import { useSnackbar } from 'notistack';
import { useApi, ApiError } from '../hooks/useApi';
import {
  ComputeData, ComputeView, FILTER_KEYS, Row, SCAN_NOTES, SUPPORT_LABELS, SUPPORT_SEVERITY, countBy, defaultOrder,
  familyOf, matches, prepare, rowKey, statusOf, supportRank, toCsv, urlLabel,
} from '../components/compute/computeData';
import { CveCheck } from '../components/compute/CveCheck';
import {
  SEVERITY_TONE, SafeLink, WsEmpty, WsFacts, WsHeading, WsList, WsMetric, WsPage, WsPanel, WsSection, WsStrip,
} from '../components/workspace/Workspace';

const PAGE_SIZE = 100;
const POLL_MS = 10000;
const VIEWS: [ComputeView | 'cve', string][] = [
  ['machines', 'Machines'], ['sql', 'SQL Server'], ['apps', 'App Service'], ['images', 'Containers'], ['cve', 'CVE check'],
];
const NOUNS: Record<ComputeView, string> = {
  machines: 'machines', sql: 'SQL Server instances', apps: 'apps', images: 'containers',
};
const fmt = (n: number | null | undefined) => (n === null || n === undefined ? '' : n.toLocaleString());
const day = (v: string | null | undefined) => (v ? String(v).slice(0, 10) : '');

const SupportTag: React.FC<{ support: string; note?: string }> = ({ support, note }) => (
  <span className="ws-tag" title={note || ''}
    style={{ color: SEVERITY_TONE[SUPPORT_SEVERITY[support] ?? 'info'], borderColor: SEVERITY_TONE[SUPPORT_SEVERITY[support] ?? 'info'] }}>
    {SUPPORT_LABELS[support] ?? support}
  </span>
);

/** A container's Defender scan status: outdated packages are a finding, everything else is information. */
const ScanTag: React.FC<{ scan: string }> = ({ scan }) => {
  const tone = SEVERITY_TONE[scan === 'outdated packages' ? 'high' : 'info'];
  return <span className="ws-tag" title={SCAN_NOTES[scan] || ''} style={{ color: tone, borderColor: tone }}>{scan}</span>;
};

function download(content: BlobPart, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

const MachineDossier: React.FC<{ m: Row; onClose: () => void }> = ({ m, onClose }) => {
  let n = 0;
  return (
    <div className="dossier" role="dialog" aria-label="Machine dossier">
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
        <p className="eyebrow">{m.kindLabel} · {m.family || 'operating system not identified'}</p>
        <button type="button" className="ws-button" onClick={onClose}><Close fontSize="inherit" />Close</button>
      </div>
      <h1>{m.name}</h1>
      <p className="ws-text ws-muted">{m.resourceGroup} · {m.subscription} · {m.location}</p>
      <WsStrip>
        <WsMetric label="Support" value={<SupportTag support={m.support} />} note={day(m.supportEnds) || undefined} />
        <WsMetric label="Updates pending" value={m.updates ?? '—'} note={m.patches?.reboot ? 'reboot pending' : undefined} />
        <WsMetric label="CVEs" value={m.cveCount ?? '—'} note={m.cves ? `${m.cves.critical} critical · ${m.cves.high} high` : 'no scan data'} />
      </WsStrip>
      {m.reasons?.length > 0 && (
        <WsSection number={++n} title="Why it is on the critical path"><WsList items={m.reasons} /></WsSection>
      )}
      <WsSection number={++n} title="Operating system">
        <WsFacts rows={[
          ['Operating system', m.os], ['Reported version', m.osReported],
          ['Source', m.osSource === 'machine' ? 'reported by the machine' : m.osSource === 'image' ? `marketplace image ${m.image}` : 'unknown'],
          ['Support', m.supportNote], ['Extended Security Updates', m.esu],
        ]} />
      </WsSection>
      <WsSection number={++n} title="Protection and patching">
        <WsFacts rows={[
          ['Public IP', m.exposureLabel], ['Vulnerability scanner', m.scannerNote || m.scannerLabel],
          ['Defender for Servers', m.defenderPlan || 'not configured'],
          ['Agents / extensions', (m.agents || []).join(', ') || 'none visible'],
          ['Update Manager', m.patches
            ? `${m.patches.security} security, ${m.patches.critical} critical, ${m.patches.other} other${m.patches.assessed ? ` · assessed ${day(m.patches.assessed)}` : ''}`
            : `no assessment${m.patchAssessment ? ` (mode ${m.patchAssessment})` : ' - turn on periodic assessment'}`],
          ['Arc agent', m.kind === 'arc' ? `${m.state}${m.lastSeen ? ` since ${day(m.lastSeen)}` : ''}` : null],
        ]} />
      </WsSection>
      {(m.patches?.names?.length || m.packages?.names?.length || m.cves?.ids?.length) ? (
        <WsSection number={++n} title="Software findings">
          {m.patches?.names?.length ? <><p className="eyebrow">Pending security / critical updates</p><WsList items={m.patches.names.concat(m.patches.more ? [`… and ${m.patches.more} more`] : [])} /></> : null}
          {m.packages?.names?.length ? <><p className="eyebrow">Outdated packages</p><WsList items={m.packages.names.concat(m.packages.more ? [`… and ${m.packages.more} more`] : [])} /></> : null}
          {m.cves?.ids?.length ? <><p className="eyebrow">CVEs (critical and high first)</p><WsList items={m.cves.ids.slice(0, 40).concat(m.cves.count > 40 ? [`… and ${m.cves.count - 40} more`] : [])} /></> : null}
        </WsSection>
      ) : null}
      {m.sql?.length > 0 && (
        <WsSection number={++n} title="SQL Server">
          <WsList items={m.sql.map((q: Row) => `${q.name} - ${q.product}${q.edition ? ` ${q.edition}` : ''}${q.build ? ` (${q.build})` : ''}: ${q.supportNote}`)} />
        </WsSection>
      )}
      <WsSection number={++n} title="Azure">
        <WsFacts rows={[['Resource ID', m.id], ['Computer name', m.computer], ['Environment', m.env]]} />
      </WsSection>
    </div>
  );
};

const ContainerDossier: React.FC<{ i: Row; onClose: () => void }> = ({ i, onClose }) => (
  <div className="dossier" role="dialog" aria-label="Container dossier">
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
      <p className="eyebrow">{i.kind} · {i.registryLabel}</p>
      <button type="button" className="ws-button" onClick={onClose}><Close fontSize="inherit" />Close</button>
    </div>
    <h1>{i.name}</h1>
    <p className="ws-text ws-muted">{i.resourceGroup} · {i.subscription}</p>
    <WsStrip>
      <WsMetric label="Reach" value={i.exposed ? 'Internet' : 'Internal'} note={i.exposure} />
      <WsMetric label="Outdated packages" value={i.packageCount ?? 0} note={i.high ? `${i.high} high` : undefined} />
      <WsMetric label="State" value={i.state || '—'} />
    </WsStrip>
    <WsSection number={1} title="Image">
      <WsFacts rows={[
        ['Image', i.image],
        ['Pinned digest', i.digest ? String(i.digest) : null],
        ['Registry', i.registry !== i.registryLabel ? `${i.registryLabel} (${i.registry})` : i.registryLabel],
        ['Defender scan', <><ScanTag scan={i.scan} />{SCAN_NOTES[i.scan] ? <span className="ws-muted">{SCAN_NOTES[i.scan]}</span> : null}</>],
      ]} />
    </WsSection>
    <WsSection number={2} title="Network">
      <WsFacts rows={[['Exposure', i.exposure], ['URL', i.url ? <SafeLink href={i.url}>{i.url}</SafeLink> : null]]} />
    </WsSection>
    {(i.packages || []).length > 0 && (
      <WsSection number={3} title="Packages Defender reports as outdated"><WsList items={i.packages} /></WsSection>
    )}
    <WsSection number={(i.packages || []).length > 0 ? 4 : 3} title="Azure">
      <WsFacts rows={[['Workload', i.workload], ['Resource ID', i.id]]} />
    </WsSection>
  </div>
);

export const ComputePage: React.FC = () => {
  const api = useApi();
  const { enqueueSnackbar } = useSnackbar();
  const [params, setParams] = useSearchParams();
  const [data, setData] = useState<ComputeData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [shown, setShown] = useState(PAGE_SIZE);
  const [selected, setSelected] = useState<{ view: ComputeView; row: Row } | null>(null);

  const f = useMemo(() => Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) ?? ''])), [params]);
  const cveTab = f.view === 'cve';
  const view: ComputeView = f.view === 'sql' || f.view === 'apps' || f.view === 'images' ? f.view : 'machines';
  const update = useCallback((changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    Object.entries(changes).forEach(([k, v]) => (v ? next.set(k, v) : next.delete(k)));
    setParams(next, { replace: true });
    setShown(PAGE_SIZE);
  }, [params, setParams]);

  const load = useCallback(async () => {
    try {
      setData(await api.get('/estate/compute'));
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError && e.status === 404
        ? 'No compute inventory yet. Refresh the inventory - the worker also refreshes it after every completed scan.'
        : e instanceof ApiError ? e.message : 'Could not load the compute inventory');
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
      if (!s.running) { setRunning(false); load(); }
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

  const rows = useMemo(() => (data ? prepare(data) : { machines: [], sql: [], apps: [], images: [] }), [data]);
  const current = useMemo(() => defaultOrder(view, rows[view].filter((r) => matches(view, r, f))), [rows, view, f]);
  const facets = useMemo(() => {
    const base = (k: string) => rows[view].filter((r) => matches(view, r, f, k));
    const support = countBy(base('support'), (r) => statusOf(view, r));
    return {
      sub: countBy(base('sub'), (r) => r.subscription),
      family: countBy(base('family'), (r) => familyOf(view, r)),
      support: view === 'images' ? support : support.sort((a, b) => supportRank(a[0]) - supportRank(b[0])),
      env: countBy(view === 'machines' ? base('env') : [], (r) => r.env),
    };
  }, [rows, view, f]);

  const s = data?.summary;
  const hasFilters = FILTER_KEYS.some((k) => k !== 'view' && k !== 'cve' && f[k]);
  const cveSearch = /cve-\d{4}-\d+/i.test(f.q) && !rows.machines.some((m) => m.cves);
  const supportBars = s ? Object.entries(s.support).sort((a, b) => supportRank(a[0]) - supportRank(b[0])) : [];
  const maxSupport = Math.max(1, ...supportBars.map(([, n]) => n));
  const shortcuts: [string, number, Record<string, string | null>, boolean][] = s ? [
    ['Critical path', s.criticalPath, { view: null, critical: f.critical ? null : '1' }, !!f.critical],
    ['Running without a scanner', s.noScanner, { view: null, scanner: f.scanner === 'none' ? null : 'none' }, f.scanner === 'none'],
    ['Security updates pending', s.pendingSecurity, { view: null, pending: f.pending ? null : '1' }, !!f.pending],
    ['Arc agent disconnected', s.arcStale, { view: null, kind: 'arc', state: f.state === 'idle' ? null : 'idle' }, f.kind === 'arc' && f.state === 'idle'],
    ['SQL Server past support', s.sql.ended, { view: 'sql', support: 'ended' }, view === 'sql' && f.support === 'ended'],
    ['App runtimes past support', s.apps?.ended ?? 0, { view: 'apps', support: 'ended' }, view === 'apps' && f.support === 'ended'],
    ...(s.images?.total ? [
      ['Internet-facing containers', s.images.exposed, { view: 'images', exposure: 'public', support: null }, view === 'images' && f.exposure === 'public'],
      ['Containers with outdated packages', s.images.withFindings, { view: 'images', support: 'outdated packages', exposure: null }, view === 'images' && f.support === 'outdated packages'],
    ] as [string, number, Record<string, string | null>, boolean][] : []),
  ] : [];
  const shortcutMax = Math.max(1, ...shortcuts.map(([, n]) => n));
  const switchView = (v: ComputeView | 'cve') =>
    update({ view: v === 'machines' ? null : v, support: null, family: null, exposure: null, state: null });

  return (
    <WsPage label="Compute">
      <WsHeading
        eyebrow="Workspace / Compute"
        title="Every machine, every runtime."
        subtitle="Support, patching and exposure."
        intro={data?.collected_at ? `From the estate inventory of ${new Date(data.collected_at).toLocaleString()}.${running ? ' A refresh is running.' : ''}` : undefined}
        actions={<>
          <button type="button" className="ws-button solid" onClick={refresh} disabled={running}>
            <Refresh fontSize="inherit" />{running ? 'Refreshing…' : 'Refresh inventory'}
          </button>
          {!cveTab && (
            <button type="button" className="ws-button" disabled={!data}
              onClick={() => download(toCsv(current, view), `compute-${view}.csv`, 'text/csv;charset=utf-8')}>
              <Download fontSize="inherit" />CSV
            </button>
          )}
        </>}
      />

      {error && !data && <WsEmpty title="No compute inventory yet">{error}</WsEmpty>}
      {!data && !error && <><Skeleton height={110} /><Skeleton height={320} /></>}
      {data?.warnings?.length ? (
        <div className="ws-notice" role="status"><p className="eyebrow">Partial data</p><WsList items={data.warnings} /></div>
      ) : null}

      {data && s && (
        <>
          <WsStrip>
            <WsMetric label="Machines" value={fmt(s.machines)} note={`${fmt(s.vms)} VMs · ${fmt(s.arc)} Arc`} />
            <WsMetric label="Critical path" value={fmt(s.criticalPath)} note="internet-facing with a known weakness" />
            <WsMetric label="Without a scanner" value={fmt(s.noScanner)} note={`${fmt(s.noScannerExposed)} internet-facing`} />
            <WsMetric label="Security updates pending" value={fmt(s.pendingSecurity)} note="Update Manager assessment" />
            <WsMetric label="SQL Server past support" value={fmt(s.sql.ended)} note={`${fmt(s.sql.instances)} instances`} />
            {s.images?.total
              ? <WsMetric label="Containers" value={fmt(s.images.total)} note={`${fmt(s.images.exposed)} internet-facing · ${fmt(s.images.distinct)} images`} />
              : <WsMetric label="App runtimes past support" value={fmt(s.apps?.ended ?? 0)} note={`${fmt(s.apps?.total)} apps`} />}
          </WsStrip>

          <div className="ws-grid">
            <WsPanel eyebrow="Operating systems" title="End of support">
              <div className="ws-bars">
                {supportBars.map(([k, n]) => (
                  <button key={k} type="button" className="ws-bar" aria-pressed={view === 'machines' && !cveTab && f.support === k}
                    onClick={() => update({ view: null, support: f.support === k && view === 'machines' ? null : k, exposure: null, state: null })}>
                    <span>{SUPPORT_LABELS[k] ?? k}</span>
                    <span className="track"><i style={{ width: `${Math.max(2, (n / maxSupport) * 100)}%`, background: SEVERITY_TONE[SUPPORT_SEVERITY[k] ?? 'info'] }} /></span>
                    <b>{fmt(n)}</b>
                  </button>
                ))}
              </div>
            </WsPanel>
            <WsPanel eyebrow="Shortcuts" title="Where to look first">
              <div className="ws-bars">
                {shortcuts.map(([label, n, set, active]) => (
                  <button key={label} type="button" className="ws-bar" aria-pressed={active && !cveTab} onClick={() => update(set)}>
                    <span>{label}</span><span className="track"><i style={{ width: `${Math.max(2, (n / shortcutMax) * 100)}%` }} /></span><b>{fmt(n)}</b>
                  </button>
                ))}
              </div>
            </WsPanel>
          </div>

          <div className="ws-switch" role="group" aria-label="View" style={{ marginBottom: 18 }}>
            {VIEWS.map(([v, label]) => (
              <button key={v} type="button" aria-pressed={(cveTab ? 'cve' : view) === v} onClick={() => switchView(v)}>{label}</button>
            ))}
          </div>

          {cveTab ? (
            <CveCheck initial={f.cve} onChecked={(id) => update({ cve: id })}
              onDownload={(content, name) => download(content, name, 'text/csv;charset=utf-8')} />
          ) : (
            <WsPanel eyebrow="Inventory" title={`${fmt(current.length)} ${NOUNS[view]}`}>
              <div className="ws-filters">
                <label>{view === 'images' ? 'Search' : 'Software or CVE'}
                  <input type="search" value={f.q} onChange={(e) => update({ q: e.target.value || null })}
                    placeholder={view === 'images' ? 'image, tag, package, hostname…' : 'e.g. openssl, CVE-2024-…'} />
                </label>
                <label>Subscription
                  <select value={f.sub} onChange={(e) => update({ sub: e.target.value || null })}>
                    <option value="">All</option>{facets.sub.map(([k, n]) => <option key={k} value={k}>{k} ({n})</option>)}
                  </select>
                </label>
                <label>{view === 'machines' ? 'OS family' : view === 'sql' ? 'Version' : view === 'images' ? 'Registry' : 'Stack'}
                  <select value={f.family} onChange={(e) => update({ family: e.target.value || null })}>
                    <option value="">All</option>{facets.family.map(([k, n]) => <option key={k} value={k}>{k} ({n})</option>)}
                  </select>
                </label>
                <label>{view === 'images' ? 'Defender scan' : 'Support'}
                  <select value={f.support} onChange={(e) => update({ support: e.target.value || null })}>
                    <option value="">All</option>
                    {facets.support.map(([k, n]) => <option key={k} value={k}>{view === 'images' ? k : SUPPORT_LABELS[k] ?? k} ({n})</option>)}
                  </select>
                </label>
                {(view === 'machines' || view === 'images') && <>
                  <label>Exposure
                    <select value={f.exposure} onChange={(e) => update({ exposure: e.target.value || null })}>
                      <option value="">All</option>
                      <option value="public">{view === 'images' ? 'Internet-facing' : 'Public IP, running'}</option>
                      <option value="private">{view === 'images' ? 'Not internet-facing' : 'No public IP'}</option>
                    </select>
                  </label>
                  <label>State
                    <select value={f.state} onChange={(e) => update({ state: e.target.value || null })}>
                      <option value="">All</option><option value="running">Running / connected</option>
                      <option value="idle">Stopped / disconnected</option>
                    </select>
                  </label>
                </>}
                {view === 'machines' && <>
                  <label>Scanner
                    <select value={f.scanner} onChange={(e) => update({ scanner: e.target.value || null })}>
                      <option value="">All</option><option value="covered">Covered</option><option value="none">None</option><option value="unverified">Not verified</option>
                    </select>
                  </label>
                  <label>Environment
                    <select value={f.env} onChange={(e) => update({ env: e.target.value || null })}>
                      <option value="">All</option>{facets.env.map(([k, n]) => <option key={k} value={k}>{k} ({n})</option>)}
                    </select>
                  </label>
                </>}
                {f.critical && <span className="ws-tag on">critical path</span>}
                {f.pending && <span className="ws-tag on">updates pending</span>}
                <button type="button" className="ws-button" disabled={!hasFilters}
                  onClick={() => update(Object.fromEntries(FILTER_KEYS.filter((k) => k !== 'view' && k !== 'cve').map((k) => [k, null])))}>Clear</button>
              </div>
              {cveSearch && view === 'machines' && (
                <p className="ws-text ws-muted">
                  No machine reports CVE data yet: CVEs come from a vulnerability scanner (Defender for Servers or a third-party one
                  reporting to Defender). The <button type="button" className="ws-link" onClick={() => update({ view: 'cve', cve: f.q.trim().toUpperCase() })}>CVE check</button> compares
                  NVD&apos;s affected versions with what each resource runs instead.
                </p>
              )}

              {current.length === 0 ? <WsEmpty title="Nothing matches these filters." /> : (
                <div style={{ overflowX: 'auto' }}>
                  <table className="ws-rows">
                    {view === 'machines' && (
                      <>
                        <thead><tr><th className="sev" /><th>Machine</th><th>Operating system</th><th>Support</th><th>Public IP</th>
                          <th>Scanner</th><th className="num">Updates</th><th className="num">CVEs</th><th>SQL Server</th><th>Subscription</th></tr></thead>
                        <tbody>
                          {current.slice(0, shown).map((m) => (
                            <tr key={m.id} className="click" onClick={() => setSelected({ view, row: m })}>
                              <td className="sev"><i style={{ background: m.criticalPath ? SEVERITY_TONE.critical : 'transparent' }} /></td>
                              <td><b>{m.name}</b><br /><span className="ws-muted">{m.kindLabel} · {m.state}</span></td>
                              <td>{m.os || '—'}<br /><span className="ws-muted">{m.osReported}</span></td>
                              <td><SupportTag support={m.support} note={m.supportNote} /><br /><span className="ws-muted">{day(m.supportEnds)}</span></td>
                              <td>{m.exposureLabel}</td>
                              <td>{m.scannerLabel}</td>
                              <td className="num">{m.updates ?? '—'}</td>
                              <td className="num">{m.cveCount ?? '—'}</td>
                              <td>{m.sqlLabel || ''}</td>
                              <td>{m.subscription}</td>
                            </tr>
                          ))}
                        </tbody>
                      </>
                    )}
                    {view === 'sql' && (
                      <>
                        <thead><tr><th>Instance</th><th>Host</th><th>Version</th><th>Edition / build</th><th>Support</th><th>ESU</th><th>Status</th><th>Subscription</th></tr></thead>
                        <tbody>
                          {current.slice(0, shown).map((q) => (
                            <tr key={q.id}>
                              <td><b>{q.name}</b></td><td>{q.host}</td><td>{q.product}</td>
                              <td>{q.edition}<br /><span className="ws-muted">{q.build}</span></td>
                              <td><SupportTag support={q.support} note={q.supportNote} /><br /><span className="ws-muted">{day(q.supportEnds)}</span></td>
                              <td>{q.esuLabel}</td><td>{q.status}</td><td>{q.subscription}</td>
                            </tr>
                          ))}
                        </tbody>
                      </>
                    )}
                    {view === 'apps' && (
                      <>
                        <thead><tr><th>App</th><th>Runtime</th><th>Support</th><th>Network exposure</th><th>Hostname</th><th>State</th><th>Subscription</th></tr></thead>
                        <tbody>
                          {current.slice(0, shown).map((a) => (
                            <tr key={a.id}>
                              <td><b>{a.name}</b><br /><span className="ws-muted">{a.kind} · {a.resourceGroup}</span></td>
                              <td>{a.runtime}</td>
                              <td><SupportTag support={a.support} note={a.supportNote} /><br /><span className="ws-muted">{day(a.supportEnds)}</span></td>
                              <td>{a.exposure}</td>
                              <td title={(a.urls || []).join('\n')}>{(a.urls || []).length ? <SafeLink href={a.urls[0]}>{urlLabel(a.urls)}</SafeLink> : ''}</td>
                              <td>{a.state}</td><td>{a.subscription}</td>
                            </tr>
                          ))}
                        </tbody>
                      </>
                    )}
                    {view === 'images' && (
                      <>
                        <thead><tr><th className="sev" /><th>Workload / container</th><th>Image</th><th>Network exposure</th><th>Defender scan</th>
                          <th className="num">Outdated</th><th className="num">High</th><th>State</th><th>Subscription</th></tr></thead>
                        <tbody>
                          {current.slice(0, shown).map((i) => (
                            <tr key={rowKey(view, i)} className="click" onClick={() => setSelected({ view, row: i })}>
                              <td className="sev"><i style={{ background: i.exposed && i.packageCount ? SEVERITY_TONE.high : 'transparent' }} /></td>
                              <td><b>{i.name}</b><br /><span className="ws-muted">{i.kind}</span></td>
                              <td>{i.image}<br /><span className="ws-muted">{i.registryLabel}</span></td>
                              <td>{i.exposure}</td>
                              <td><ScanTag scan={i.scan} /></td>
                              <td className="num">{i.packageCount ?? ''}</td>
                              <td className="num">{i.high ?? ''}</td>
                              <td>{i.state}</td><td>{i.subscription}</td>
                            </tr>
                          ))}
                        </tbody>
                      </>
                    )}
                  </table>
                </div>
              )}
              {current.length > shown && (
                <p style={{ marginTop: 14 }}>
                  <button type="button" className="ws-button" onClick={() => setShown((n) => n + PAGE_SIZE)}>
                    Show {Math.min(PAGE_SIZE, current.length - shown)} more of {fmt(current.length - shown)}
                  </button>
                </p>
              )}
            </WsPanel>
          )}
        </>
      )}

      <Drawer anchor="right" open={!!selected} onClose={() => setSelected(null)} PaperProps={{ sx: { bgcolor: '#111e19' } }}>
        {selected?.view === 'images' && <ContainerDossier i={selected.row} onClose={() => setSelected(null)} />}
        {selected?.view === 'machines' && <MachineDossier m={selected.row} onClose={() => setSelected(null)} />}
      </Drawer>
    </WsPage>
  );
};

export default ComputePage;

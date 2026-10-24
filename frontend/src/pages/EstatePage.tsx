/**
 * EstatePage - every resource across the connected subscriptions (admins), in ARG's workspace language.
 *
 * Data: GET /estate (estate.json format 2, refreshed by the worker after every scan or with Refresh inventory),
 * GET /estate/status while a refresh runs, GET /estate/telemetry for the spend and fleet panels,
 * GET /estate/overview.md for the markdown overview. Filtering and CSV come from components/estate/estateData.ts
 * (the same rules as the local portal's Estate page); filters live in the URL query string.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Drawer, Skeleton } from '@mui/material';
import { Close, Download, Refresh, Description } from '@mui/icons-material';
import { useSnackbar } from 'notistack';
import { useApi, ApiError } from '../hooks/useApi';
import { useMoney } from '../hooks/useCurrency';
import {
  CPU_BANDS, ENDPOINT_CAVEAT, FILTER_KEYS, Estate, Filters, PAGE_SIZE, RawEstate, Resource, SnapshotMeta, Suggestion,
  View, activityBand, countBy, cpuBand, cpuProfile, expLabel, expand, exposureEntries, fmt, hasCpu, resourceMatches,
  sevRank, suggestionMatches, toCsv,
} from '../components/estate/estateData';
import { FindingDossier } from '../components/findings/FindingDossier';
import {
  SEVERITY_TONE, SafeLink, WsEmpty, WsFacts, WsHeading, WsMetric, WsPage, WsPanel, WsSection, WsStrip,
} from '../components/workspace/Workspace';

interface EstateStatus { running: boolean; latest: SnapshotMeta | null; available: SnapshotMeta | null }
interface Amount { name: string; cost: number; count?: number }
interface Telemetry {
  currency: string;
  resources: number;
  subscriptions: number;
  spend_30d: number;
  spend_by_category: Amount[];
  spend_by_environment: Amount[];
  spend_by_subscription: Amount[];
  top_services: Amount[];
  vm_power: { running: number; deallocated: number; stopped: number };
  vm_utilisation: Record<string, number>;
  network: {
    data: Record<string, number>; apps: Record<string, number>; private_endpoints: number; public_ips: number;
    vms_with_public_ip: number; vnets: number; isolated_vnets: number; collected: boolean;
  };
  tag_coverage: { resources_pct: number | null; cost_pct: number | null; most_missed: { tag: string; resources: number }[] } | null;
  suggestions: { count: number; by_severity: Record<string, number> };
}

const POLL_MS = 10000;
const when = (v: string | null | undefined) => (v ? new Date(v).toLocaleString() : '—');
const isUuid = (v: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);

function download(content: BlobPart, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/** Horizontal bars: label, share of the largest, value. Clicking one filters the table. */
const Bars: React.FC<{
  rows: { label: string; value: number; text: string; filter?: string }[]; active?: string; onPick?: (v: string) => void;
}> = ({ rows, active, onPick }) => {
  const max = Math.max(1, ...rows.map((r) => r.value));
  if (!rows.length) return <p className="ws-text ws-muted">No data in the latest inventory.</p>;
  return (
    <div className="ws-bars">
      {rows.map((r) => (
        <button key={r.label} type="button" className="ws-bar" disabled={!onPick || !r.filter}
          aria-pressed={!!active && active === r.filter} onClick={() => r.filter && onPick?.(active === r.filter ? '' : r.filter)}>
          <span title={r.label}>{r.label}</span>
          <span className="track"><i style={{ width: `${Math.max(2, (r.value / max) * 100)}%` }} /></span>
          <b>{r.text}</b>
        </button>
      ))}
    </div>
  );
};

const FilterSelect: React.FC<{
  label: string; value: string; entries: [string, number][]; all: string; onChange: (v: string) => void;
  labelFn?: (v: string) => string;
}> = ({ label, value, entries, all, onChange, labelFn }) => (
  <label>{label}
    <select value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{all}</option>
      {entries.map(([k, n]) => <option key={k} value={k}>{labelFn ? labelFn(k) : k} ({n})</option>)}
    </select>
  </label>
);

export const EstatePage: React.FC = () => {
  const api = useApi();
  const { enqueueSnackbar } = useSnackbar();
  const { format, text: moneyText } = useMoney();
  const [params, setParams] = useSearchParams();
  const [estate, setEstate] = useState<Estate | null>(null);
  const [status, setStatus] = useState<EstateStatus | null>(null);
  const [telemetry, setTelemetry] = useState<Telemetry | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [shown, setShown] = useState(PAGE_SIZE);
  const [resourceKey, setResourceKey] = useState<string | null>(null);
  const [dossierId, setDossierId] = useState<string | null>(null);

  const view: View = params.get('view') === 'suggestions' ? 'suggestions' : 'resources';
  const filters: Filters = useMemo(() => {
    const f: Filters = {};
    FILTER_KEYS.forEach((k) => { const v = params.get(k); if (v) f[k] = v; });
    return f;
  }, [params]);

  const update = useCallback((changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    Object.entries(changes).forEach(([k, v]) => (v ? next.set(k, v) : next.delete(k)));
    setParams(next, { replace: true });
    setShown(PAGE_SIZE);
  }, [params, setParams]);
  const setFilter = (k: string, v: string) => update({ [k]: v || null });

  const load = useCallback(async () => {
    try {
      const data: RawEstate = await api.get('/estate');
      setEstate(expand(data));
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError && e.status === 404
        ? 'No estate inventory yet. Refresh it - the worker also refreshes it after every completed scan.'
        : e instanceof ApiError ? e.message : 'Could not load the estate');
    }
    try { setTelemetry(await api.get('/estate/telemetry')); } catch { setTelemetry(null); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadStatus = useCallback(async () => {
    try { setStatus(await api.get('/estate/status')); } catch { /* status is informational */ }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { load(); loadStatus(); }, [load, loadStatus]);

  useEffect(() => {
    if (!status?.running) return undefined;
    const timer = window.setInterval(async () => {
      const s: EstateStatus = await api.get('/estate/status');
      setStatus(s);
      if (!s.running) {
        if (s.latest?.status === 'completed') { enqueueSnackbar('Estate inventory refreshed', { variant: 'success' }); load(); }
        else enqueueSnackbar(`Estate refresh failed: ${s.latest?.error_message ?? 'unknown error'}`, { variant: 'error' });
      }
    }, POLL_MS);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status?.running]);

  const refresh = async () => {
    try {
      const r = await api.post('/estate/refresh');
      enqueueSnackbar(r.started ? 'Estate refresh started (about 5 minutes)' : 'A refresh is already running', { variant: 'info' });
      loadStatus();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Could not start the refresh', { variant: 'error' });
    }
  };

  const overview = async () => {
    try {
      const blob: Blob = await api.get('/estate/overview.md');
      download(blob, `estate-${new Date().toISOString().slice(0, 10)}.md`, 'text/markdown');
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Could not download the overview', { variant: 'error' });
    }
  };

  const subName = useCallback((id: string) => estate?.subscriptions.find((s) => s.id === id)?.name ?? id, [estate]);

  const rows = useMemo(() => {
    if (!estate) return [] as (Resource | Suggestion)[];
    if (view === 'resources') {
      return estate.resources.filter((r) => resourceMatches(estate, r, filters))
        .sort((a, b) => sevRank(a.maxSeverity) - sevRank(b.maxSeverity) || (b.cost30 ?? -1) - (a.cost30 ?? -1));
    }
    return estate.suggestions.filter((s) => suggestionMatches(estate, s, filters))
      .sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || b.savingsUsd - a.savingsUsd);
  }, [estate, filters, view]);

  const facets = useMemo(() => {
    if (!estate) return null;
    const res = (skip: keyof Filters) => estate.resources.filter((r) => resourceMatches(estate, r, filters, skip));
    const sug = (skip: keyof Filters) => estate.suggestions.filter((s) => suggestionMatches(estate, s, filters, skip));
    const pick = view === 'resources';
    const by = (skip: keyof Filters, fn: (x: Resource | Suggestion) => string) =>
      (pick ? countBy<Resource>(res(skip), fn) : countBy<Suggestion>(sug(skip), fn));
    return {
      category: by('category', (x) => x.category),
      type: by('type', (x) => x.typeLabel),
      sub: by('sub', (x) => x.subscriptionId),
      region: countBy(res('region'), (r) => r.location || '(none)'),
      env: countBy(res('env'), (r) => r.env),
      exp: exposureEntries(res('exp')),
      stype: countBy(sug('stype'), (s) => s.type),
      sev: countBy(sug('sev'), (s) => s.severity).sort((a, b) => sevRank(a[0]) - sevRank(b[0])),
    };
  }, [estate, filters, view]);

  const cpuRows = useMemo(() => {
    if (!estate) return [];
    const machines = estate.resources.filter((r) => hasCpu(r) && !r.subResource);
    return [...CPU_BANDS.map(([, label]) => label), 'no data'].map((label) => {
      const n = machines.filter((r) => cpuBand(r.cpuAvg) === label).length;
      return { label: `CPU ${label}`, value: n, text: String(n), filter: label };
    }).filter((r) => r.value);
  }, [estate]);

  const resource = resourceKey && estate ? estate.resourceIndex.get(resourceKey) ?? null : null;
  let sectionNo = 0;   // resource dossier: numbers only the sections shown
  const hasFilters = FILTER_KEYS.some((k) => filters[k]);
  const money0 = (v: number) => format(v);
  const cost = (r: Resource) => (r.cost30 === null ? '—' : moneyText(`${fmt(r.cost30) || '0'} ${r.currency}`.trim()));

  return (
    <WsPage label="Estate">
      <WsHeading
        eyebrow="Workspace / Estate"
        title="Every resource."
        subtitle="Across every subscription."
        intro={estate
          ? `${estate.source === 'resource-graph' ? 'Live Resource Graph inventory' : 'Inventory from the subscription analyses'} of ${when(estate.inventoryAt ?? estate.generatedAt)}.${status?.running ? ' A refresh is running.' : ''}`
          : undefined}
        actions={<>
          <button type="button" className="ws-button solid" onClick={refresh} disabled={!!status?.running}>
            <Refresh fontSize="inherit" />{status?.running ? 'Refreshing…' : 'Refresh inventory'}
          </button>
          <button type="button" className="ws-button" onClick={overview} disabled={!estate}><Description fontSize="inherit" />Overview .md</button>
          <button type="button" className="ws-button" disabled={!estate}
            onClick={() => download(toCsv(rows, view), `estate-${view}.csv`, 'text/csv;charset=utf-8')}>
            <Download fontSize="inherit" />CSV
          </button>
        </>}
      />

      {status?.latest?.status === 'failed' && (
        <div className="ws-notice" role="status"><p className="eyebrow">Last refresh failed</p>
          {when(status.latest.completed_at)}: {status.latest.error_message ?? 'unknown error'}</div>
      )}
      {estate && estate.costUnavailable.length > 0 && (
        <div className="ws-notice" role="status"><p className="eyebrow">Cost not available</p>
          No Cost Management Reader on: {estate.costUnavailable.map(subName).join(', ')} - their cost shows as "—", not 0.</div>
      )}

      {error && !estate && <WsEmpty title="No estate yet">{error}</WsEmpty>}
      {!estate && !error && <><Skeleton height={110} /><Skeleton height={320} /></>}

      {estate && (
        <>
          <WsStrip>
            <WsMetric label="Resources" value={fmt(estate.resources.filter((r) => !r.subResource).length)} note={`${estate.subscriptions.length} subscriptions`} />
            <WsMetric label="Suggestions" value={fmt(estate.suggestions.filter((s) => !s.hygiene).length)}
              note={`${estate.suggestions.filter((s) => s.hygiene).length} tag / naming hygiene`} />
            <WsMetric label="Spend, last 30 days" value={telemetry ? moneyText(`${fmt(telemetry.spend_30d)} ${telemetry.currency}`) : '—'} />
            <WsMetric label="Tag coverage" value={telemetry?.tag_coverage?.resources_pct != null ? `${telemetry.tag_coverage.resources_pct.toFixed(0)} %` : '—'}
              note={telemetry?.tag_coverage?.cost_pct != null ? `${telemetry.tag_coverage.cost_pct.toFixed(0)} % of spend` : undefined} />
            <WsMetric label="Estimated saving / month" value={money0(estate.suggestions.reduce((t, s) => t + (s.savingsUsd || 0), 0))} />
          </WsStrip>

          {telemetry && (
            <div className="ws-grid">
              <WsPanel eyebrow="Where the money goes" title="Spend by category">
                <Bars active={filters.category} onPick={(v) => setFilter('category', v)}
                  rows={telemetry.spend_by_category.slice(0, 8).map((a) => ({ label: a.name, value: a.cost, text: moneyText(`${fmt(a.cost)} ${telemetry.currency}`), filter: a.name }))} />
              </WsPanel>
              <WsPanel eyebrow="By service" title="Top services">
                <Bars rows={telemetry.top_services.slice(0, 8).map((a) => ({ label: a.name, value: a.cost, text: moneyText(`${fmt(a.cost)} ${telemetry.currency}`) }))} />
              </WsPanel>
              <WsPanel eyebrow="By subscription" title="Spend per subscription">
                <Bars active={filters.sub} onPick={(v) => setFilter('sub', v)}
                  rows={telemetry.spend_by_subscription.slice(0, 8).map((a) => ({
                    label: a.name, value: a.cost, text: moneyText(`${fmt(a.cost)} ${telemetry.currency}`),
                    filter: estate.subscriptions.find((s) => s.name === a.name)?.id,
                  }))} />
              </WsPanel>
              <WsPanel eyebrow="Virtual machines" title="Fleet and CPU">
                <WsFacts rows={[
                  ['Running', fmt(telemetry.vm_power.running)],
                  ['Deallocated', fmt(telemetry.vm_power.deallocated)],
                  ['Stopped, still billed', fmt(telemetry.vm_power.stopped)],
                ]} />
                <div style={{ marginTop: 14 }}>
                  <Bars rows={cpuRows} active={filters.cpu} onPick={(v) => update({ cpu: v || null, view: null })} />
                </div>
              </WsPanel>
              {telemetry.network.collected && (
                <WsPanel eyebrow="Exposure" title="Network">
                  <WsFacts rows={[
                    ['Public IPs', fmt(telemetry.network.public_ips)],
                    ['VMs with a public IP', fmt(telemetry.network.vms_with_public_ip)],
                    ['Private endpoints', fmt(telemetry.network.private_endpoints)],
                    ['VNets', `${fmt(telemetry.network.vnets)} (${fmt(telemetry.network.isolated_vnets)} isolated)`],
                    ...Object.entries(telemetry.network.data).map(([k, v]) => [`Data services ${k}`, fmt(v)] as [string, string]),
                    ...Object.entries(telemetry.network.apps).map(([k, v]) => [`Apps ${k}`, fmt(v)] as [string, string]),
                  ]} />
                </WsPanel>
              )}
              {exposureEntries(estate.resources).length > 0 && (
                <WsPanel eyebrow="Web endpoints" title="Network exposure">
                  <Bars active={filters.exp} onPick={(v) => update({ exp: v || null, view: null })}
                    rows={exposureEntries(estate.resources).map(([k, n]) => ({ label: expLabel(k), value: n, text: fmt(n), filter: k }))} />
                  <p className="ws-muted" style={{ fontSize: 11, lineHeight: 1.6, margin: '12px 0 0' }}>{ENDPOINT_CAVEAT}</p>
                </WsPanel>
              )}
              {telemetry.tag_coverage && telemetry.tag_coverage.most_missed.length > 0 && (
                <WsPanel eyebrow="Tags" title="Most missed tags">
                  <Bars rows={telemetry.tag_coverage.most_missed.slice(0, 8).map((t) => ({ label: t.tag, value: t.resources, text: fmt(t.resources) }))} />
                </WsPanel>
              )}
            </div>
          )}

          <WsPanel
            eyebrow="Inventory"
            title={`${fmt(rows.length)} ${view === 'resources' ? 'resources' : 'suggestions'}`}
            actions={
              <div className="ws-switch" role="group" aria-label="View">
                <button type="button" aria-pressed={view === 'resources'} onClick={() => update({ view: null })}>Resources</button>
                <button type="button" aria-pressed={view === 'suggestions'} onClick={() => update({ view: 'suggestions' })}>Suggestions</button>
              </div>
            }
          >
            {facets && (
              <div className="ws-filters">
                <label>Search<input type="search" value={filters.q ?? ''} onChange={(e) => setFilter('q', e.target.value)}
                  placeholder="Name, group, tag, size, hostname…" /></label>
                <FilterSelect label="Category" value={filters.category ?? ''} entries={facets.category} all="All" onChange={(v) => setFilter('category', v)} />
                <FilterSelect label="Type" value={filters.type ?? ''} entries={facets.type} all="All" onChange={(v) => setFilter('type', v)} />
                <FilterSelect label="Subscription" value={filters.sub ?? ''} entries={facets.sub} all="All" labelFn={subName} onChange={(v) => setFilter('sub', v)} />
                {view === 'resources' && <FilterSelect label="Region" value={filters.region ?? ''} entries={facets.region} all="All" onChange={(v) => setFilter('region', v)} />}
                {view === 'resources' && <FilterSelect label="Environment" value={filters.env ?? ''} entries={facets.env} all="All" onChange={(v) => setFilter('env', v)} />}
                {view === 'resources' && facets.exp.length > 0 && (
                  <FilterSelect label="Web exposure" value={filters.exp ?? ''} entries={facets.exp} all="All" labelFn={expLabel} onChange={(v) => setFilter('exp', v)} />
                )}
                <FilterSelect label="Suggestion type" value={filters.stype ?? ''} entries={facets.stype} all="All" onChange={(v) => setFilter('stype', v)} />
                <FilterSelect label="Severity" value={filters.sev ?? ''} entries={facets.sev} all="All" onChange={(v) => setFilter('sev', v)} />
                <label>Hygiene<select value={filters.hyg ?? ''} onChange={(e) => setFilter('hyg', e.target.value)}>
                  <option value="">Hidden</option><option value="1">Shown</option></select></label>
                <label>Extensions<select value={filters.ext ?? ''} onChange={(e) => setFilter('ext', e.target.value)}>
                  <option value="">Hidden</option><option value="1">Shown</option></select></label>
                {filters.cpu && <span className="ws-tag on">CPU {filters.cpu}</span>}
                {filters.act && <span className="ws-tag on">{filters.act}</span>}
                <button type="button" className="ws-button" disabled={!hasFilters}
                  onClick={() => update(Object.fromEntries(FILTER_KEYS.map((k) => [k, null])))}>Clear</button>
              </div>
            )}

            {rows.length === 0 ? <WsEmpty title="Nothing matches these filters." /> : (
              <div style={{ overflowX: 'auto' }}>
                {view === 'resources' ? (
                  <table className="ws-rows">
                    <thead><tr><th className="sev" /><th>Resource</th><th>Size</th><th>Usage</th><th>Environment</th>
                      <th>Region</th><th>Subscription</th><th className="num">Last 30 d</th><th className="num">Suggestions</th></tr></thead>
                    <tbody>
                      {(rows as Resource[]).slice(0, shown).map((r) => (
                        <tr key={r.key} className="click" onClick={() => setResourceKey(r.key)}>
                          <td className="sev"><i style={{ background: SEVERITY_TONE[r.maxSeverity] ?? 'transparent' }} /></td>
                          <td><b>{r.name}</b><br /><span className="ws-muted">{r.typeLabel} · {r.resourceGroup}</span></td>
                          <td>{r.size || '—'}</td>
                          <td>{r.cpuAvg !== null ? `CPU ${r.cpuAvg.toFixed(1)} %` : activityBand(r) ?? '—'}</td>
                          <td>{r.env}</td>
                          <td>{r.location || '—'}</td>
                          <td>{r.subscription}</td>
                          <td className="num">{cost(r)}</td>
                          <td className="num">{r.suggestions || ''}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <table className="ws-rows">
                    <thead><tr><th className="sev" /><th>Suggestion</th><th>Resource</th><th>Subscription</th>
                      <th className="num">Saving / month</th><th className="num">Wave</th></tr></thead>
                    <tbody>
                      {(rows as Suggestion[]).slice(0, shown).map((s, i) => (
                        <tr key={`${s.findingId}-${i}`} className={isUuid(s.findingId) ? 'click' : undefined}
                          onClick={() => isUuid(s.findingId) && setDossierId(s.findingId)}>
                          <td className="sev"><i style={{ background: SEVERITY_TONE[s.severity] }} /></td>
                          <td>{moneyText(s.title)}<br /><span className="ws-muted">{s.type.replace(/_/g, ' ')}</span></td>
                          <td>{s.resourceName}<br /><span className="ws-muted">{s.typeLabel}</span></td>
                          <td>{s.subscription}</td>
                          <td className="num">{s.savingsUsd ? money0(s.savingsUsd) : ''}</td>
                          <td className="num">{s.wave ?? ''}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}
            {rows.length > shown && (
              <p style={{ marginTop: 14 }}>
                <button type="button" className="ws-button" onClick={() => setShown((n) => n + PAGE_SIZE)}>
                  Show {Math.min(PAGE_SIZE, rows.length - shown)} more of {fmt(rows.length - shown)}
                </button>
              </p>
            )}
          </WsPanel>
        </>
      )}

      <Drawer anchor="right" open={!!resource} onClose={() => setResourceKey(null)} PaperProps={{ sx: { bgcolor: '#111e19' } }}>
        {resource && (
          <div className="dossier" role="dialog" aria-label="Resource dossier">
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
              <p className="eyebrow">Resource · {resource.typeLabel}</p>
              <button type="button" className="ws-button" onClick={() => setResourceKey(null)}><Close fontSize="inherit" />Close</button>
            </div>
            <h1>{resource.name}</h1>
            <p className="ws-text ws-muted">{resource.resourceGroup} · {resource.subscription} · {resource.location}</p>
            <WsStrip>
              <WsMetric label="Last 30 days" value={cost(resource)} />
              <WsMetric label="Environment" value={resource.env} />
              <WsMetric label="Suggestions" value={String(resource.suggestions)} note={resource.hygiene ? `${resource.hygiene} hygiene` : undefined} />
            </WsStrip>
            <WsSection number={++sectionNo} title="Configuration">
              <WsFacts rows={[
                ['Size / SKU', resource.size], ['vCPU', resource.vcpu], ['RAM (GB)', resource.ramGB], ['Configuration', resource.config],
                ['OS / runtime', resource.os], ['State', resource.state], ['Kind', resource.kind], ['Managed by', resource.managedBy],
              ]} />
            </WsSection>
            {resource.endpoint && (
              <WsSection number={++sectionNo} title="Web endpoint">
                <WsFacts rows={[
                  ['Hostname', resource.endpoint.host ? <SafeLink href={`https://${resource.endpoint.host}`}>{resource.endpoint.host}</SafeLink> : 'no hostname'],
                  ['Custom domains', resource.endpoint.domains.length
                    ? <>{resource.endpoint.domains.map((d, i) => <React.Fragment key={d}>{i > 0 && ', '}<SafeLink href={`https://${d}`}>{d}</SafeLink></React.Fragment>)}</>
                    : null],
                  ['Network exposure', resource.endpoint.exposure || 'not known'],
                ]} />
                {resource.endpoint.internet && /app endpoint/i.test(resource.endpoint.exposure) && (
                  <p className="ws-text ws-muted" style={{ marginTop: 10 }}>{ENDPOINT_CAVEAT}</p>
                )}
              </WsSection>
            )}
            {(hasCpu(resource) || activityBand(resource)) && (
              <WsSection number={++sectionNo} title="Usage, last 30 days">
                <p className="ws-text">{cpuProfile(resource) || activityBand(resource) || 'No metrics.'}</p>
                {resource.memAvg !== null && <p className="ws-text">Memory average {resource.memAvg.toFixed(1)} %.</p>}
                {resource.usage && <p className="ws-text ws-muted">{resource.usage}</p>}
              </WsSection>
            )}
            <WsSection number={++sectionNo} title="Suggestions">
              {(estate?.byResource.get(resource.key) ?? []).length === 0 ? <p className="ws-text ws-muted">None.</p> : (
                <ul className="ws-list">
                  {(estate?.byResource.get(resource.key) ?? []).slice().sort((a, b) => sevRank(a.severity) - sevRank(b.severity)).map((s, i) => (
                    <li key={i}>
                      <span style={{ color: SEVERITY_TONE[s.severity] }}>{s.severity}</span> ·{' '}
                      {isUuid(s.findingId)
                        ? <a href="#finding" onClick={(e) => { e.preventDefault(); setDossierId(s.findingId); }}>{moneyText(s.title)}</a>
                        : moneyText(s.title)}
                      {s.savingsUsd ? <span className="ws-muted"> · {money0(s.savingsUsd)} / month</span> : null}
                    </li>
                  ))}
                </ul>
              )}
            </WsSection>
            {Object.keys(resource.tags).length > 0 && (
              <WsSection number={++sectionNo} title="Tags">
                <WsFacts rows={Object.entries(resource.tags).map(([k, v]) => [k, v])} />
              </WsSection>
            )}
            <WsSection number={++sectionNo} title="Azure">
              <WsFacts rows={[['Resource ID', resource.id]]} />
              <p className="ws-text" style={{ marginTop: 10 }}>
                <a href={`https://portal.azure.com/#@/resource${resource.id}`} target="_blank" rel="noopener noreferrer">Open in the Azure portal</a>
              </p>
            </WsSection>
          </div>
        )}
      </Drawer>

      <FindingDossier findingId={dossierId} onClose={() => setDossierId(null)} />
    </WsPage>
  );
};

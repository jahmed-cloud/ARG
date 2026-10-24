/**
 * CVE check (Compute page): which VM, Arc server, SQL Server instance, App Service app or container a CVE concerns.
 * GET /estate/cve/<id> matches NVD's affected versions to the inventory; GET /estate/cve/kev lists recently exploited
 * CVEs (CISA KEV) for products the estate runs. Only the CVE ID leaves the server (scripts/subscription_analysis/cve.py).
 */
import React, { useCallback, useEffect, useState } from 'react';
import { Download, Search } from '@mui/icons-material';
import { useApi, ApiError } from '../../hooks/useApi';
import { Row, urlLabel } from './computeData';
import { SEVERITY_TONE, SafeLink, WsEmpty, WsFacts, WsPanel } from '../workspace/Workspace';

const CVE_PATTERN = /^CVE-\d{4}-\d{4,7}$/i;
const VERDICTS = ['impacted', 'potentially impacted', 'not affected'];
const VERDICT_TONE: Record<string, string> = { impacted: 'critical', 'potentially impacted': 'high', 'not affected': 'low' };
const fmt = (n: number | null | undefined) => (n === null || n === undefined ? '' : n.toLocaleString());

const Tag: React.FC<{ tone: string; title?: string; children: React.ReactNode }> = ({ tone, title, children }) => (
  <span className="ws-tag" title={title} style={{ color: SEVERITY_TONE[tone], borderColor: SEVERITY_TONE[tone] }}>{children}</span>
);

function impactCsv(res: Row): string {
  const columns = ['verdict', 'name', 'kind', 'label', 'version', 'reason', 'fixed', 'exposed', 'urls', 'subscription', 'id'];
  const escape = (v: unknown) => {
    let text = v === undefined || v === null ? '' : Array.isArray(v) ? v.join(' ') : String(v);
    if (/^[=+\-@]/.test(text)) text = `'${text}`;   // no formula injection when opened in Excel
    return /[",\n;]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  return '﻿' + [columns.join(',')].concat((res.results || []).map((r: Row) => columns.map((c) => escape(r[c])).join(',')))
    .join('\r\n');
}

export const CveCheck: React.FC<{ initial: string; onChecked: (id: string) => void;
  onDownload: (content: string, filename: string) => void }> = ({ initial, onChecked, onDownload }) => {
  const api = useApi();
  const [input, setInput] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [res, setRes] = useState<Row | null>(null);
  const [days, setDays] = useState(90);
  const [kev, setKev] = useState<Row | null>(null);
  const [kevError, setKevError] = useState<string | null>(null);

  const run = useCallback(async (raw: string) => {
    const id = raw.trim().toUpperCase();
    setInput(id);
    if (!CVE_PATTERN.test(id)) {
      setError('Enter a CVE ID like CVE-2024-3094.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setRes(await api.get(`/estate/cve/${encodeURIComponent(id)}`));
      onChecked(id);
    } catch (e) {
      setRes(null);
      setError(e instanceof ApiError ? e.message : 'The CVE could not be checked.');
    } finally {
      setBusy(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (initial && CVE_PATTERN.test(initial)) run(initial);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let cancelled = false;
    setKevError(null);
    api.get(`/estate/cve/kev?days=${days}`)
      .then((d: Row) => { if (!cancelled) setKev(d); })
      .catch((e: unknown) => { if (!cancelled) setKevError(e instanceof ApiError ? e.message : 'The CISA catalog could not be loaded.'); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [days]);

  const severity = String(res?.severity || '').toLowerCase();
  return (
    <>
      <WsPanel eyebrow="CVE check" title="Which resources does a CVE concern?">
        <p className="ws-text ws-muted">
          NVD&apos;s affected versions (one CVE at a time, cached a day) and CISA&apos;s known-exploited catalog, matched to this
          inventory: operating systems and builds, appliance firmware, SQL Server, App Service runtimes, container image tags
          and packages Defender or Update Manager report. Only the CVE ID is sent.
        </p>
        <form className="ws-filters" onSubmit={(e) => { e.preventDefault(); run(input); }}>
          <label>CVE ID
            <input type="search" value={input} onChange={(e) => setInput(e.target.value)} placeholder="CVE-2024-3094" autoComplete="off" />
          </label>
          <button type="submit" className="ws-button solid" disabled={busy}><Search fontSize="inherit" />{busy ? 'Checking…' : 'Check'}</button>
          {res?.results?.length ? (
            <button type="button" className="ws-button" onClick={() => onDownload(impactCsv(res), `${res.cve}-impact.csv`)}>
              <Download fontSize="inherit" />CSV
            </button>
          ) : null}
        </form>
        {error && <div className="ws-notice" role="alert"><p className="eyebrow">CVE check</p>{error}</div>}

        {res && (
          <section aria-live="polite">
            <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8, margin: '6px 0 10px' }}>
              <h2 style={{ margin: 0, fontWeight: 500, fontSize: 20 }}>{res.cve}</h2>
              {res.severity && (
                <Tag tone={severity === 'critical' ? 'critical' : severity === 'high' ? 'high' : 'medium'}>{severity} {res.score ?? ''}</Tag>
              )}
              {res.kev && <Tag tone="critical" title={res.kev.requiredAction || ''}>exploited in the wild · KEV {res.kev.dateAdded}</Tag>}
            </div>
            {!res.found ? <p className="ws-text">{res.note}</p> : (
              <>
                <WsFacts rows={[
                  ['NVD status', res.status],
                  ['Published', String(res.published || '').slice(0, 10)],
                  ['Affects', (res.products || []).slice(0, 8).join(', ') + ((res.products || []).length > 8 ? ' …' : '')],
                  ['CISA action', res.kev ? `${res.kev.requiredAction || ''} Due ${res.kev.dueDate || ''}.` : null],
                ]} />
                <p className="ws-text" style={{ marginTop: 12 }}>{res.description}</p>
                {res.note && <p className="ws-text ws-muted">{res.note}</p>}
                <p>{VERDICTS.map((v) => <Tag key={v} tone={VERDICT_TONE[v]}>{fmt(res.counts?.[v] ?? 0)} {v}</Tag>)}</p>
                {(res.results || []).length === 0 ? <WsEmpty title="Nothing in this inventory runs an affected product." /> : (
                  <div style={{ overflowX: 'auto' }}>
                    <table className="ws-rows">
                      <thead><tr><th className="sev" /><th>Resource</th><th>Product / version</th><th>Why</th><th>Fixed in</th><th>Reach</th><th>Subscription</th></tr></thead>
                      <tbody>
                        {res.results.map((r: Row) => (
                          <tr key={`${r.id}-${r.name}-${r.label}`}>
                            <td className="sev"><i style={{ background: SEVERITY_TONE[VERDICT_TONE[r.verdict] ?? 'info'] }} /></td>
                            <td title={r.id}><b>{r.name}</b><br /><span className="ws-muted">{r.kind} · {r.verdict}</span></td>
                            <td>{r.label}{r.version && !String(r.label).includes(r.version) ? ` · ${r.version}` : ''}</td>
                            <td>{r.reason}</td>
                            <td>{r.fixed || ''}</td>
                            <td>
                              {r.exposed ? 'internet-facing' : <span className="ws-muted">internal</span>}
                              {(r.urls || []).length > 0 && <><br /><SafeLink href={r.urls[0]}>{urlLabel(r.urls)}</SafeLink></>}
                            </td>
                            <td>{r.subscription || ''}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </section>
        )}
      </WsPanel>

      <WsPanel
        eyebrow="Exploited in the wild"
        title="CISA KEV - products this estate runs"
        actions={
          <div className="ws-switch" role="group" aria-label="Added in the last">
            {[[30, '30 days'], [90, '90 days'], [365, 'Year']].map(([d, label]) => (
              <button key={d} type="button" aria-pressed={days === d} onClick={() => setDays(Number(d))}>{label}</button>
            ))}
          </div>
        }
      >
        {kevError && <div className="ws-notice" role="status"><p className="eyebrow">CISA KEV</p>{kevError}</div>}
        {kev && (
          <>
            <p className="ws-muted" style={{ fontSize: 12, margin: '0 0 12px' }}>
              {fmt(kev.rows.length)} of the {fmt(kev.total)} known-exploited CVEs (catalog {kev.catalogVersion}) were added in this
              period and name a product this estate runs. KEV names the product, not the versions - Check compares the versions.
            </p>
            {kev.rows.length === 0 ? <WsEmpty title="No known-exploited CVE of this period concerns a product this estate runs." /> : (
              <div style={{ overflowX: 'auto' }}>
                <table className="ws-rows">
                  <thead><tr><th>Added</th><th>CVE</th><th>Vendor / product</th><th>Vulnerability</th><th className="num">Resources</th>
                    <th className="num">Internet-facing</th><th>Ransomware</th><th>Due</th><th /></tr></thead>
                  <tbody>
                    {kev.rows.map((r: Row) => (
                      <tr key={r.cve}>
                        <td>{r.dateAdded}</td>
                        <td><b>{r.cve}</b></td>
                        <td>{r.vendor} / {r.product}</td>
                        <td title={r.description || ''}>{r.name}</td>
                        <td className="num" title={(r.kinds || []).join(', ')}>{fmt(r.resources)}</td>
                        <td className="num">{fmt(r.exposed)}</td>
                        <td>{r.ransomware}</td>
                        <td>{r.dueDate}</td>
                        <td><button type="button" className="ws-button" onClick={() => run(r.cve)}>Check</button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </WsPanel>
    </>
  );
};

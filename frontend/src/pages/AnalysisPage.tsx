/**
 * AnalysisPage - the 5-part subscription analysis as the local tool writes it (summary, 01 current findings,
 * 02 gap analysis, 03 cost drivers, 04 architectural critique, 05 deep dives with ARG's reasoning and the optional
 * AI review), written by the worker after each scan (backend/api/routes/analysis.py), in ARG's workspace language.
 *
 * Pages arrive as sanitised HTML; relative links between pages are resolved here, links to backlog.csv download
 * it, and mermaid charts (cost trends) are drawn with mermaid from the CDN (strict security level).
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Skeleton } from '@mui/material';
import { Download, TableChart } from '@mui/icons-material';
import { useApi, ApiError } from '../hooks/useApi';
import { useMoney } from '../hooks/useCurrency';
import { WsEmpty, WsHeading, WsMetric, WsPage, WsPanel, WsStrip } from '../components/workspace/Workspace';

interface AnalysisItem {
  subscription_id: string;
  azure_subscription_id: string;
  name: string;
  generated_at: string;
  status: string;
  error: string | null;
  findings: number | null;
  cost_30d: number | null;
  currency: string | null;
  ai_review: string | null;
}

interface Page {
  subscription: { id: string; azure_subscription_id: string; name: string };
  generated_at: string;
  status: string;
  error: string | null;
  nav: { path: string; title: string }[];
  path: string;
  html: string | null;
  thinking: { status?: string; reason?: string; model?: string; reviewed?: number; sent?: number };
}

const MERMAID_CDN = 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';

/** posix-style join of a page's directory and a relative link */
const resolve = (from: string, href: string): string => {
  const parts = from.split('/').slice(0, -1);
  for (const piece of href.split('/')) {
    if (piece === '..') parts.pop();
    else if (piece && piece !== '.') parts.push(piece);
  }
  return parts.join('/');
};

const save = (blob: Blob, name: string) => {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
};

export const AnalysisPage: React.FC = () => {
  const api = useApi();
  const money = useMoney();   // pages are in the billing currency: the currency selector converts them
  const [params, setParams] = useSearchParams();
  const subscription = params.get('subscription') ?? '';
  const path = params.get('path') ?? 'README.md';
  const [items, setItems] = useState<AnalysisItem[] | null>(null);
  const [page, setPage] = useState<Page | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const anchor = useRef<string | null>(null);

  useEffect(() => {
    api.get('/analysis')
      .then((list: AnalysisItem[]) => {
        setItems(list);
        if (!subscription && list.length) setParams({ subscription: list[0].subscription_id }, { replace: true });
      })
      .catch(() => setItems([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!subscription) return undefined;
    let cancelled = false;
    setLoading(true);
    setError(null);
    api.get(`/analysis/${subscription}?path=${encodeURIComponent(path)}`)
      .then((p: Page) => { if (!cancelled) setPage(p); })
      .catch((e: unknown) => {
        if (cancelled) return;
        setPage(null);
        setError(e instanceof ApiError ? e.message : 'The analysis could not be loaded.');
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subscription, path]);

  useEffect(() => {
    const root = contentRef.current;
    if (!root || !page?.html) return;
    if (anchor.current) {
      root.querySelector(`#${CSS.escape(anchor.current)}`)?.scrollIntoView({ block: 'start' });
      anchor.current = null;
    } else {
      window.scrollTo({ top: 0 });
    }
    const blocks = Array.from(root.querySelectorAll('pre > code.language-mermaid'));
    if (!blocks.length) return;
    (async () => {
      try {
        const mermaid = (await import(/* @vite-ignore */ MERMAID_CDN)).default;
        mermaid.initialize({ startOnLoad: false, theme: 'dark', securityLevel: 'strict' });
        for (const [i, code] of blocks.entries()) {
          const { svg } = await mermaid.render(`arg-chart-${Date.now()}-${i}`, code.textContent ?? '');
          const holder = document.createElement('div');
          holder.innerHTML = svg;   // mermaid's own SVG (securityLevel strict)
          code.parentElement?.replaceWith(holder);
        }
      } catch { /* charts stay as their source text when the CDN is not reachable */ }
    })();
  }, [page]);

  const go = (next: string, hash?: string) => {
    anchor.current = hash ?? null;
    setParams({ subscription, path: next });
  };

  const download = useCallback(async (url: string, name: string) => {
    try { save((await api.get(url)) as Blob, name); } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Download failed.');
    }
  }, [api]);

  const onClick = (e: React.MouseEvent) => {
    const a = (e.target as Element).closest('a');
    const href = a?.getAttribute('href');
    if (!a || !href) return;
    if (/^https?:\/\//i.test(href)) {
      a.setAttribute('target', '_blank');
      a.setAttribute('rel', 'noopener noreferrer');
      return;
    }
    e.preventDefault();
    const [target, hash] = href.split('#');
    if (!target) {
      contentRef.current?.querySelector(`#${CSS.escape(hash)}`)?.scrollIntoView({ block: 'start' });
      return;
    }
    const next = resolve(path, target);
    if (next.endsWith('.md')) go(next, hash);
    else if (next.endsWith('.csv')) download(`/analysis/${subscription}/file?path=${encodeURIComponent(next)}`, next.split('/').pop()!);
    else setError(`${next} is only in the local report folder (raw datasets are not stored in the cloud analysis).`);
  };

  const current = items?.find((i) => i.subscription_id === subscription) ?? null;
  const stamp = page?.generated_at ? new Date(page.generated_at).toLocaleString() : '';
  const thinking = page?.thinking?.status === 'ok'
    ? `${page.thinking.reviewed}/${page.thinking.sent} findings`
    : page?.thinking?.status === 'error' ? 'failed' : 'off';

  return (
    <WsPage label="Analysis">
      <WsHeading
        eyebrow="Assessment / Analysis"
        title="The subscription, read end to end."
        subtitle="Decisions first, evidence after."
        intro={stamp ? `Written after the scan of ${stamp}.` : 'Written by the worker after each scan.'}
        actions={subscription ? <>
          <button type="button" className="ws-button" onClick={() => download(`/analysis/${subscription}/file?path=backlog.csv`, 'backlog.csv')}>
            <TableChart fontSize="inherit" />Backlog CSV
          </button>
          <button type="button" className="ws-button" onClick={() => download(`/analysis/${subscription}/download`, `analysis-${current?.name ?? subscription}.zip`)}>
            <Download fontSize="inherit" />Zip
          </button>
        </> : undefined}
      />

      {items === null && <Skeleton height={120} />}
      {items !== null && items.length === 0 && (
        <WsEmpty title="No analysis yet.">
          The worker writes it after each scan of a subscription (ANALYSIS_REPORT_AFTER_SCAN). Start a scan to create one.
        </WsEmpty>
      )}

      {items && items.length > 0 && (
        <>
          <div className="ws-filters">
            <label>Subscription
              <select value={subscription} onChange={(e) => setParams({ subscription: e.target.value })}>
                {items.map((i) => <option key={i.subscription_id} value={i.subscription_id}>{i.name}</option>)}
              </select>
            </label>
          </div>

          {current && (
            <WsStrip>
              <WsMetric label="Findings" value={current.findings ?? '—'} />
              <WsMetric label="Cost, last 30 days" value={current.cost_30d !== null
                ? money.text(`${Math.round(current.cost_30d).toLocaleString()} ${current.currency ?? ''}`.trim()) : '—'} />
              <WsMetric label="AI review" value={thinking} note={page?.thinking?.model} />
              <WsMetric label="Status" value={current.status} note={current.error ?? undefined} />
            </WsStrip>
          )}

          {error && <div className="ws-notice" role="alert">{error}</div>}
          {page?.status === 'failed' && <div className="ws-notice" role="alert">The analysis failed: {page.error}</div>}

          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(200px, 260px) minmax(0, 1fr)', gap: 22 }} className="analysis-layout">
            <WsPanel eyebrow="Contents">
              <ol className="ws-steps">
                {(page?.nav ?? []).map((n) => (
                  <li key={n.path}>
                    <a href={`#${n.path}`} onClick={(e) => { e.preventDefault(); go(n.path); }}
                      style={{ color: n.path === path ? '#b8d9ba' : '#ebece3', textDecoration: 'none' }}>{n.title}</a>
                  </li>
                ))}
              </ol>
            </WsPanel>
            <WsPanel>
              {loading && <><Skeleton height={36} /><Skeleton height={300} /></>}
              {!loading && page?.html && (
                <div ref={contentRef} className="ws-markdown" onClick={onClick}
                  // eslint-disable-next-line react/no-danger
                  dangerouslySetInnerHTML={{ __html: money.text(page.html) }} />
              )}
            </WsPanel>
          </div>
        </>
      )}
      <style>{'@media(max-width:900px){.analysis-layout{grid-template-columns:1fr!important}}'}</style>
    </WsPage>
  );
};

/**
 * AnalysisPage — the 5-part subscription analysis, as the local tool writes it: summary (decisions), 01 current
 * findings, 02 gap analysis, 03 cost drivers, 04 architectural critique, 05 deep dives (with ARG's reasoning and
 * the optional AI review), written by the worker after each scan (backend/api/routes/analysis.py).
 *
 * Pages arrive as sanitised HTML; relative links between pages are resolved here, links to backlog.csv download it,
 * and mermaid charts (cost trends) are drawn with mermaid from the CDN, like the local portal does.
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Card,
  Chip,
  CircularProgress,
  List,
  ListItemButton,
  ListItemText,
  TextField,
  Typography,
} from '@mui/material';
import { Download, TableChart } from '@mui/icons-material';
import { useApi, ApiError } from '../hooks/useApi';
import { useMoney } from '../hooks/useCurrency';

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
  setTimeout(() => {
    URL.revokeObjectURL(a.href);
    a.remove();
  }, 1000);
};

export const AnalysisPage: React.FC = () => {
  const api = useApi();
  const money = useMoney();   // report pages are in the billing currency: the Currency dropdown converts them
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
    api
      .get('/analysis')
      .then((list: AnalysisItem[]) => {
        setItems(list);
        if (!subscription && list.length) setParams({ subscription: list[0].subscription_id }, { replace: true });
      })
      .catch(() => setItems([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!subscription) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .get(`/analysis/${subscription}?path=${encodeURIComponent(path)}`)
      .then((p: Page) => !cancelled && setPage(p))
      .catch((e: unknown) => {
        if (cancelled) return;
        setPage(null);
        setError(e instanceof ApiError ? e.message : 'The analysis could not be loaded.');
      })
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subscription, path]);

  // after a page renders: scroll to the requested anchor, draw mermaid charts
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
        mermaid.initialize({ startOnLoad: false, theme: 'neutral', securityLevel: 'strict' });
        for (const [i, code] of blocks.entries()) {
          const { svg } = await mermaid.render(`arg-chart-${Date.now()}-${i}`, code.textContent ?? '');
          const holder = document.createElement('div');
          holder.className = 'analysis-chart';
          holder.innerHTML = svg;   // mermaid's own SVG (securityLevel strict)
          code.parentElement?.replaceWith(holder);
        }
      } catch {
        /* charts stay as their source text when the CDN is not reachable */
      }
    })();
  }, [page]);

  const go = (next: string, hash?: string) => {
    anchor.current = hash ?? null;
    setParams({ subscription, path: next });
  };

  const download = useCallback(
    async (url: string, name: string) => {
      try {
        save((await api.get(url)) as Blob, name);
      } catch (e) {
        setError(e instanceof ApiError ? e.message : 'Download failed.');
      }
    },
    [api],
  );

  // links inside the analysis stay in the app
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

  return (
    <Box>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 1.5, mb: 1.5 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>
          Subscription analysis
        </Typography>
        {stamp && (
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            written after the scan of {stamp}
          </Typography>
        )}
        {page?.thinking?.status === 'ok' && (
          <Chip size="small" color="success" label={`AI review: ${page.thinking.reviewed}/${page.thinking.sent} findings`} />
        )}
        {page?.thinking?.status === 'error' && <Chip size="small" color="warning" label="AI review failed" title={page.thinking.reason} />}
        <Box sx={{ ml: 'auto', display: 'flex', gap: 1 }}>
          <Button size="small" variant="outlined" startIcon={<TableChart />} disabled={!page}
            onClick={() => download(`/analysis/${subscription}/file?path=backlog.csv`, 'backlog.csv')}>
            Backlog CSV (Azure Boards)
          </Button>
          <Button size="small" variant="contained" startIcon={<Download />} disabled={!page}
            onClick={() => download(`/analysis/${subscription}/download`, `analysis-${current?.name ?? subscription}.zip`)}>
            Download all
          </Button>
        </Box>
      </Box>

      {items && items.length === 0 && (
        <Alert severity="info">No analysis yet. It is written after each scan - start one on the Scans page.</Alert>
      )}

      {items && items.length > 0 && (
        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '280px 1fr' }, gap: 2, alignItems: 'start' }}>
          <Card sx={{ p: 1.5, position: { md: 'sticky' }, top: { md: 80 } }}>
            <Autocomplete
              size="small"
              options={items}
              value={current}
              getOptionLabel={(o) => o.name}
              isOptionEqualToValue={(a, b) => a.subscription_id === b.subscription_id}
              onChange={(_, o) => o && setParams({ subscription: o.subscription_id })}
              renderInput={(p) => <TextField {...p} label="Subscription" />}
              sx={{ mb: 1 }}
            />
            <List dense disablePadding>
              {(page?.nav ?? []).map((n) => (
                <ListItemButton key={n.path} selected={n.path === path} onClick={() => go(n.path)} sx={{ borderRadius: 1 }}>
                  <ListItemText primary={n.title} primaryTypographyProps={{ fontSize: 13 }} />
                </ListItemButton>
              ))}
            </List>
          </Card>

          <Card sx={{ p: { xs: 2, md: 3 }, minHeight: 400, position: 'relative' }}>
            {loading && <CircularProgress size={22} sx={{ position: 'absolute', right: 16, top: 16 }} />}
            {error && (
              <Alert severity="warning" sx={{ mb: 2 }} onClose={() => setError(null)}>
                {error}
              </Alert>
            )}
            {page?.status === 'failed' && <Alert severity="error">The analysis failed: {page.error}</Alert>}
            {page?.html && (
              <Box
                ref={contentRef}
                onClick={onClick}
                className="analysis-page"
                sx={{
                  fontSize: 14,
                  lineHeight: 1.6,
                  overflowWrap: 'anywhere',
                  '& h1': { fontSize: 24, mt: 0 },
                  '& h2': { fontSize: 19, mt: 3, borderBottom: 1, borderColor: 'divider', pb: 0.5 },
                  '& h3': { fontSize: 16, mt: 2.5 },
                  '& table': { borderCollapse: 'collapse', width: '100%', display: 'block', overflowX: 'auto', my: 1.5, fontSize: 13 },
                  '& th, & td': { border: 1, borderColor: 'divider', px: 1, py: 0.5, verticalAlign: 'top', textAlign: 'left' },
                  '& th': { bgcolor: 'action.hover' },
                  '& code': { fontFamily: 'monospace', fontSize: 12.5, bgcolor: 'action.hover', px: 0.5, borderRadius: 0.5 },
                  '& pre': { bgcolor: 'action.hover', p: 1.5, borderRadius: 1, overflowX: 'auto' },
                  '& pre code': { bgcolor: 'transparent', p: 0 },
                  '& blockquote': { borderLeft: 3, borderColor: 'primary.main', m: 0, pl: 2, color: 'text.secondary' },
                  '& details': { my: 1 },
                  '& summary': { cursor: 'pointer', color: 'primary.main' },
                  '& a': { color: 'primary.main' },
                  '& .analysis-chart svg': { maxWidth: '100%', height: 'auto' },
                }}
                // server-rendered by scripts/local_portal/render.py: raw HTML from Azure values is neutralised
                dangerouslySetInnerHTML={{ __html: money.text(page.html) }}
              />
            )}
          </Card>
        </Box>
      )}
    </Box>
  );
};

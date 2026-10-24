/**
 * Policy page Graph view: how Azure Policy reaches a scope (lens=scope: parent chain, the initiatives assigned on the
 * way, exclusions, what is in effect) or where an initiative is assigned (lens=initiative). Drawn server-side by
 * policy_graph.py (GET /estate/policy-graph.svg) with Microsoft's Azure icons; a click on a node with data-focus
 * refocuses the graph, one with data-expand opens the policies an assignment holds. Shown on the same light stage as
 * the Architecture diagrams.
 */
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { CircularProgress } from '@mui/material';
import { Download } from '@mui/icons-material';
import { useApi, ApiError } from '../../hooks/useApi';
import { PolicyAnalysis, Row } from './policyData';

// The SVG carries no scripts or links by design; anything that looks like one is not rendered.
const UNSAFE_SVG = /<script|<foreignObject|\son[a-z]+\s*=|javascript:/i;

export const PolicyGraph: React.FC<{
  data: PolicyAnalysis; assignments: Row[]; lens: string; focus: string; expand: string;
  onChange: (changes: Record<string, string | null>) => void;
  onDownload: (svg: string, filename: string) => void;
}> = ({ data, assignments, lens, focus, expand, onChange, onDownload }) => {
  const api = useApi();
  const host = useRef<HTMLDivElement>(null);
  const [svg, setSvg] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [zoom, setZoom] = useState(1);

  const scopes = useMemo(() => {
    const out: { id: string; label: string }[] = [];
    const nodes = data.tree?.nodes || {};
    const walk = (nid: string, depth: number) => {
      const n = nodes[nid];
      if (!n) return;
      if (n.kind !== 'Group') out.push({ id: nid, label: `${'  '.repeat(depth)}${n.label} (${n.kind.toLowerCase()})` });
      n.children.forEach((c) => walk(c, n.kind === 'Group' ? depth : depth + 1));
    };
    (data.tree?.roots || []).forEach((r) => walk(r, 0));
    return out;
  }, [data.tree]);
  const definitions = useMemo(() => {
    const byKey = new Map<string, { key: string; name: string; count: number; initiative: boolean }>();
    assignments.forEach((a) => {
      const d = byKey.get(a.definitionId) || { key: a.definitionId, name: a.definition, count: 0, initiative: !!a.initiative };
      d.count += 1;
      byKey.set(a.definitionId, d);
    });
    return Array.from(byKey.values()).sort((x, y) => y.count - x.count || x.name.localeCompare(y.name));
  }, [assignments]);

  const lensValue = lens === 'initiative' ? 'initiative' : 'scope';
  const focusValue = lensValue === 'scope'
    ? (scopes.some((o) => o.id === focus) ? focus : scopes[0]?.id || '')
    : (definitions.some((d) => d.key === focus) ? focus : definitions[0]?.key || '');
  const opened = expand.split(',').filter(Boolean);

  useEffect(() => {
    if (!focusValue) return undefined;
    let cancelled = false;
    setLoading(true);
    setError(null);
    const q = new URLSearchParams({ lens: lensValue, focus: focusValue, expand });
    api.get(`/estate/policy-graph.svg?${q.toString()}`)
      .then((blob: Blob) => blob.text())
      .then((text: string) => {
        if (cancelled) return;
        if (UNSAFE_SVG.test(text)) {
          setSvg('');
          setError('The graph was not shown: it contained active content.');
        } else {
          setSvg(text);
        }
      })
      .catch((e: unknown) => { if (!cancelled) setError(e instanceof ApiError ? e.message : 'The graph could not be loaded.'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lensValue, focusValue, expand]);

  useEffect(() => {
    const el = host.current?.querySelector('svg');
    if (!el) return;
    el.style.width = `${Math.round((Number(el.getAttribute('width')) || 1000) * zoom)}px`;
    el.style.height = 'auto';
  }, [svg, zoom]);

  const act = (target: EventTarget | null): boolean => {
    const node = (target as Element | null)?.closest?.('[data-focus], [data-expand]');
    if (!node || !host.current?.contains(node)) return false;
    if (node.hasAttribute('data-expand')) {
      const id = node.getAttribute('data-expand') || '';
      const next = new Set(opened);
      if (next.has(id)) next.delete(id); else next.add(id);
      onChange({ expand: Array.from(next).join(',') || null });
    } else {
      onChange({ lens: node.getAttribute('data-lens') === 'initiative' ? 'initiative' : 'scope',
        focus: node.getAttribute('data-focus'), expand: null });
      host.current?.scrollTo({ top: 0, left: 0 });
    }
    return true;
  };
  const fit = () => {
    const el = host.current?.querySelector('svg');
    if (el && host.current) setZoom(Math.min(1, (host.current.clientWidth - 4) / (Number(el.getAttribute('width')) || 1000)));
  };

  return (
    <>
      <div className="ws-filters">
        <label>Lens
          <select value={lensValue} onChange={(e) => onChange({ lens: e.target.value, focus: null, expand: null })}>
            <option value="scope">Scope - how policy reaches it</option>
            <option value="initiative">Initiative - where it is assigned</option>
          </select>
        </label>
        {lensValue === 'scope' ? (
          <label>Scope
            <select value={focusValue} onChange={(e) => onChange({ focus: e.target.value, expand: null })} style={{ maxWidth: 420 }}>
              {scopes.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
            </select>
          </label>
        ) : (
          <label>Initiative / policy
            <select value={focusValue} onChange={(e) => onChange({ focus: e.target.value, expand: null })} style={{ maxWidth: 420 }}>
              {definitions.map((d) => (
                <option key={d.key} value={d.key}>{d.name}{d.initiative ? ' (initiative)' : ''} · {d.count} assignment{d.count === 1 ? '' : 's'}</option>
              ))}
            </select>
          </label>
        )}
        <div className="ws-switch" role="group" aria-label="Zoom">
          <button type="button" onClick={() => setZoom((z) => Math.max(0.3, z / 1.25))} aria-label="Zoom out">−</button>
          <button type="button" onClick={fit}>Fit</button>
          <button type="button" onClick={() => setZoom((z) => Math.min(3, z * 1.25))} aria-label="Zoom in">+</button>
        </div>
        <button type="button" className="ws-button" disabled={!opened.length} onClick={() => onChange({ expand: null })}>Close all policies</button>
        <button type="button" className="ws-button" disabled={!svg} onClick={() => onDownload(svg, `policy-graph-${lensValue}.svg`)}>
          <Download fontSize="inherit" />SVG
        </button>
        {loading && <CircularProgress size={16} sx={{ color: '#b8d9ba' }} />}
      </div>
      <p className="ws-muted" style={{ fontSize: 12, margin: '0 0 10px' }}>
        {lensValue === 'scope'
          ? 'Select a scope to focus it, ▸ on an initiative or policy to open what it holds, "where else is it assigned?" for the initiative lens.'
          : 'Select an assignment to open its policies, a scope to see how policy reaches it.'}
      </p>
      {error && <div className="ws-notice" role="alert"><p className="eyebrow">Graph</p>{error}</div>}
      <div
        ref={host}
        aria-label="Policy assignment graph"
        onClick={(e) => { if (act(e.target)) e.preventDefault(); }}
        onKeyDown={(e) => { if ((e.key === 'Enter' || e.key === ' ') && act(e.target)) e.preventDefault(); }}
        className="ws-graph"
        // drawn by policy_graph.py: every Azure-sourced value is escaped server-side, and UNSAFE_SVG is checked above
        // eslint-disable-next-line react/no-danger
        dangerouslySetInnerHTML={{ __html: svg }}
      />
    </>
  );
};

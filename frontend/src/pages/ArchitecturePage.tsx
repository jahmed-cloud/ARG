/**
 * ArchitecturePage - tenant and subscription architecture diagrams (admins), in ARG's workspace language.
 *
 * Views: resources (management groups, Azure Policy, subscriptions; or one subscription's effective policy,
 * VNets, resource groups and services), network (hubs, spokes, peerings) and landing zone (management groups and
 * policy against the Azure Landing Zones reference). Drawn server-side by scripts/subscription_analysis/diagram.py
 * with the Microsoft Azure icons; every Azure-sourced value in the SVG is escaped there.
 * Wheel / buttons zoom, drag pans, search highlights, click a subscription to open it, export SVG or PNG.
 *
 * Data: GET /estate/architecture (picker), GET /estate/architecture.svg?view=&subscription=,
 * GET /estate/landing-zone, all from the newest completed estate inventory.
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Link as RouterLink, useSearchParams } from 'react-router-dom';
import { CircularProgress } from '@mui/material';
import { Add, Remove, CenterFocusStrong, Download, Image as ImageIcon } from '@mui/icons-material';
import { useApi, ApiError } from '../hooks/useApi';
import { useMoney } from '../hooks/useCurrency';
import { WsEmpty, WsHeading, WsMetric, WsPage, WsPanel, WsStrip } from '../components/workspace/Workspace';

interface SubscriptionOption { id: string; name: string; management_group?: string | null }
interface ArchitectureIndex {
  subscriptions: SubscriptionOption[];
  management_groups: number;
  policies: number;
  architecture_collected: boolean;
  snapshot?: { completed_at?: string | null } | null;
}

const MIN_SCALE = 0.03;
const MAX_SCALE = 8;
const LAYERS: [string, string][] = [['resources', 'Resources'], ['network', 'Network'], ['landing', 'Landing zone']];

export const ArchitecturePage: React.FC = () => {
  const api = useApi();
  const money = useMoney();   // cost labels are in the billing currency: the currency selector converts them
  const [params, setParams] = useSearchParams();
  const rawView = params.get('view');
  const layer = rawView === 'network' || rawView === 'landing' ? rawView : 'resources';
  const landing = layer === 'landing';
  const subscription = landing ? '' : params.get('subscription') ?? '';
  const go = (next: { subscription?: string; view?: string }) => {
    const nextLayer = next.view ?? layer;
    const sub = nextLayer === 'landing' ? '' : next.subscription ?? params.get('subscription') ?? '';
    setParams({ ...(sub ? { subscription: sub } : {}), ...(nextLayer !== 'resources' ? { view: nextLayer } : {}) });
  };

  const [index, setIndex] = useState<ArchitectureIndex | null>(null);
  const [details, setDetails] = useState<{ html: string; markdown: string } | null>(null);
  const [svgText, setSvgText] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [matches, setMatches] = useState<number | null>(null);
  const [zoom, setZoom] = useState(100);
  const stageRef = useRef<HTMLDivElement>(null);
  const hostRef = useRef<HTMLDivElement>(null);
  const view = useRef({ scale: 1, tx: 0, ty: 0 });
  const drag = useRef<{ x: number; y: number; tx: number; ty: number; moved: boolean } | null>(null);
  const suppressClick = useRef(false);

  useEffect(() => {
    api.get('/estate/architecture').then(setIndex).catch(() => setIndex(null));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setMatches(null);
    const q = `?view=${layer}` + (subscription ? `&subscription=${encodeURIComponent(subscription)}` : '');
    api.get(`/estate/architecture.svg${q}`)
      .then((blob: Blob) => blob.text())
      .then((text: string) => { if (!cancelled) setSvgText(text); })
      .catch((e: unknown) => {
        if (cancelled) return;
        setSvgText('');
        setError(e instanceof ApiError ? e.message : 'The diagram could not be loaded.');
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subscription, layer]);

  useEffect(() => {
    if (!landing) return undefined;
    let cancelled = false;
    setDetails(null);
    api.get('/estate/landing-zone')
      .then((d: { html: string; markdown: string }) => { if (!cancelled) setDetails(d); })
      .catch(() => { if (!cancelled) setDetails({ html: '<p>Landing zone details unavailable.</p>', markdown: '' }); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [landing]);

  // ---- zoom and pan (straight on the DOM: no re-render per mouse move) ----
  const svgSize = useCallback(() => {
    const el = hostRef.current?.querySelector('svg');
    return el ? { w: el.width.baseVal.value, h: el.height.baseVal.value } : { w: 1, h: 1 };
  }, []);
  const apply = useCallback(() => {
    const { scale, tx, ty } = view.current;
    if (hostRef.current) hostRef.current.style.transform = `translate(${tx}px, ${ty}px) scale(${scale})`;
    setZoom(Math.round(scale * 100));
  }, []);
  const zoomAt = useCallback((factor: number, mx: number, my: number) => {
    const v = view.current;
    const next = Math.min(MAX_SCALE, Math.max(MIN_SCALE, v.scale * factor));
    v.tx = mx - (mx - v.tx) * (next / v.scale);
    v.ty = my - (my - v.ty) * (next / v.scale);
    v.scale = next;
    apply();
  }, [apply]);
  const fit = useCallback(() => {
    const stage = stageRef.current;
    if (!stage) return;
    const { w, h } = svgSize();
    const scale = Math.min(stage.clientWidth / w, stage.clientHeight / h, 1);
    view.current = { scale, tx: (stage.clientWidth - w * scale) / 2, ty: Math.max(8, (stage.clientHeight - h * scale) / 2) };
    apply();
  }, [apply, svgSize]);
  const zoomCentre = (factor: number) => {
    const stage = stageRef.current;
    if (stage) zoomAt(factor, stage.clientWidth / 2, stage.clientHeight / 2);
  };
  useEffect(() => { if (svgText) requestAnimationFrame(fit); }, [svgText, fit]);
  useEffect(() => {
    const stage = stageRef.current;
    if (!stage) return undefined;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const r = stage.getBoundingClientRect();
      zoomAt(e.deltaY < 0 ? 1.15 : 1 / 1.15, e.clientX - r.left, e.clientY - r.top);
    };
    stage.addEventListener('wheel', onWheel, { passive: false });
    return () => stage.removeEventListener('wheel', onWheel);
  }, [zoomAt]);
  useEffect(() => {
    const onMove = (e: PointerEvent) => {
      const d = drag.current;
      if (!d) return;
      const dx = e.clientX - d.x;
      const dy = e.clientY - d.y;
      if (Math.abs(dx) + Math.abs(dy) > 4) d.moved = true;
      view.current.tx = d.tx + dx;
      view.current.ty = d.ty + dy;
      apply();
    };
    const onUp = () => {
      if (drag.current?.moved) suppressClick.current = true;
      drag.current = null;
      if (stageRef.current) stageRef.current.style.cursor = 'grab';
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    return () => { window.removeEventListener('pointermove', onMove); window.removeEventListener('pointerup', onUp); };
  }, [apply]);
  const onPointerDown = (e: React.PointerEvent) => {
    if (e.button !== 0) return;
    const { tx, ty } = view.current;
    drag.current = { x: e.clientX, y: e.clientY, tx, ty, moved: false };
    suppressClick.current = false;
    if (stageRef.current) stageRef.current.style.cursor = 'grabbing';
  };
  const onClick = (e: React.MouseEvent) => {
    if (suppressClick.current) { suppressClick.current = false; return; }
    const id = (e.target as Element).closest('[data-subscription]')?.getAttribute('data-subscription');
    if (id && id !== subscription) go({ subscription: id });
  };

  // ---- search ----
  useEffect(() => {
    const el = hostRef.current?.querySelector('svg');
    if (!el) return;
    el.querySelectorAll('.hit').forEach((n) => n.classList.remove('hit'));
    const q = query.trim().toLowerCase();
    if (q.length < 2) { setMatches(null); return; }
    const hits = Array.from(el.querySelectorAll<SVGGraphicsElement>('[data-label]'))
      .filter((n) => (n.getAttribute('data-label') ?? '').includes(q));
    hits.forEach((n) => (n.closest('.node') ?? n).classList.add('hit'));
    setMatches(hits.length);
    const stage = stageRef.current;
    if (hits.length && stage) {
      const b = hits[0].getBBox();
      const scale = Math.max(view.current.scale, 0.8);
      view.current = { scale, tx: stage.clientWidth / 2 - (b.x + b.width / 2) * scale, ty: stage.clientHeight / 2 - (b.y + b.height / 2) * scale };
      apply();
    }
  }, [query, svgText, apply]);

  // ---- export ----
  const fileName = landing ? 'landing-zone'
    : `${subscription ? `subscription-${subscription}` : 'tenant'}-${layer === 'network' ? 'network' : 'architecture'}`;
  const download = (blob: Blob, name: string) => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  };
  const exportSvg = () => download(new Blob([money.text(svgText)], { type: 'image/svg+xml' }), `${fileName}.svg`);
  const exportPng = () => {
    const { w, h } = svgSize();
    const ratio = Math.min(2, 16000 / Math.max(w, h));
    const img = new window.Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = Math.round(w * ratio);
      canvas.height = Math.round(h * ratio);
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      canvas.toBlob((blob) => blob && download(blob, `${fileName}.png`), 'image/png');
    };
    img.onerror = () => setError('PNG export failed - use SVG instead.');
    img.src = URL.createObjectURL(new Blob([money.text(svgText)], { type: 'image/svg+xml' }));
  };

  const subs = [...(index?.subscriptions ?? [])].sort((a, b) =>
    (a.management_group ?? '').localeCompare(b.management_group ?? '') || a.name.localeCompare(b.name));
  const groups = Array.from(new Set(subs.map((s) => s.management_group || 'Placement not collected')));

  return (
    <WsPage label="Architecture">
      <WsHeading
        eyebrow="Assessment / Architecture"
        title="How the estate is built."
        subtitle={landing ? 'Against the Azure Landing Zones reference.' : layer === 'network' ? 'Hubs, spokes and peerings.' : 'Groups, policy and services.'}
        intro={index?.snapshot?.completed_at
          ? `From the estate inventory of ${new Date(index.snapshot.completed_at).toLocaleString()}. Icons: Microsoft Azure architecture icons.`
          : undefined}
        actions={<>
          <button type="button" className="ws-button" onClick={exportSvg} disabled={!svgText}><Download fontSize="inherit" />SVG</button>
          <button type="button" className="ws-button solid" onClick={exportPng} disabled={!svgText}><ImageIcon fontSize="inherit" />PNG</button>
        </>}
      />

      {index && (
        <WsStrip>
          <WsMetric label="Subscriptions" value={index.subscriptions.length} />
          <WsMetric label="Management groups" value={index.management_groups} />
          <WsMetric label="Policy assignments" value={index.policies} />
          <WsMetric label="Network data" value={index.architecture_collected ? 'collected' : 'not yet'} note={index.architecture_collected ? undefined : 'refresh the estate inventory'} />
        </WsStrip>
      )}
      {index && !index.architecture_collected && (
        <div className="ws-notice" role="status">
          <p className="eyebrow">No network data yet</p>
          The newest inventory has no VNets, peerings or routes. <RouterLink to="/estate" style={{ color: '#284d3c' }}>Refresh the inventory on the Estate page</RouterLink> to draw them.
        </div>
      )}

      <div className="ws-filters">
        <div className="ws-switch" role="group" aria-label="View">
          {LAYERS.map(([key, label]) => (
            <button key={key} type="button" aria-pressed={layer === key} onClick={() => go({ view: key })}>{label}</button>
          ))}
        </div>
        {!landing && (
          <label>Scope
            <select value={subscription} onChange={(e) => go({ subscription: e.target.value })}>
              <option value="">{layer === 'network' ? 'Tenant - hubs, spokes, peerings' : 'Tenant - groups, subscriptions, policy'}</option>
              {groups.map((g) => (
                <optgroup key={g} label={g}>
                  {subs.filter((s) => (s.management_group || 'Placement not collected') === g)
                    .map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
                </optgroup>
              ))}
            </select>
          </label>
        )}
        <label>Find
          <input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Name in the diagram" />
        </label>
        {matches !== null && <span className="ws-tag on">{matches} match{matches === 1 ? '' : 'es'}</span>}
        <span style={{ flex: 1 }} />
        <button type="button" className="ws-button" onClick={() => zoomCentre(1 / 1.25)} aria-label="Zoom out"><Remove fontSize="inherit" /></button>
        <span className="ws-tag">{zoom} %</span>
        <button type="button" className="ws-button" onClick={() => zoomCentre(1.25)} aria-label="Zoom in"><Add fontSize="inherit" /></button>
        <button type="button" className="ws-button" onClick={fit}><CenterFocusStrong fontSize="inherit" />Fit</button>
      </div>

      {error && !loading && !svgText ? <WsEmpty title="No diagram.">{error}</WsEmpty> : (
        <div
          ref={stageRef}
          onPointerDown={onPointerDown}
          onClick={onClick}
          style={{ position: 'relative', overflow: 'hidden', height: 'calc(100vh - 330px)', minHeight: 420,
                   border: '1px solid #30423b', borderRadius: 4, background: '#f4f7ef', cursor: 'grab',
                   touchAction: 'none', userSelect: 'none', marginBottom: 22 }}
          aria-label="Architecture diagram - wheel to zoom, drag to move"
        >
          {loading && <div style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', zIndex: 1 }}><CircularProgress /></div>}
          <div
            ref={hostRef}
            style={{ position: 'absolute', left: 0, top: 0, transformOrigin: '0 0' }}
            // drawn by diagram.py: every Azure-sourced value is escaped server-side
            // eslint-disable-next-line react/no-danger
            dangerouslySetInnerHTML={{ __html: money.text(svgText) }}
          />
        </div>
      )}

      {landing && (
        <WsPanel
          eyebrow="Landing zone"
          title="Controls in place, missing and similar"
          actions={details?.markdown ? (
            <button type="button" className="ws-button" onClick={() => download(new Blob([details.markdown], { type: 'text/markdown' }), 'landing-zone.md')}>
              <Download fontSize="inherit" />Markdown
            </button>
          ) : undefined}
        >
          {!details ? <CircularProgress size={20} /> : (
            // server-rendered by scripts/local_portal/render.py: raw HTML from Azure values is neutralised
            // eslint-disable-next-line react/no-danger
            <div className="ws-markdown" dangerouslySetInnerHTML={{ __html: details.html }} />
          )}
        </WsPanel>
      )}
    </WsPage>
  );
};

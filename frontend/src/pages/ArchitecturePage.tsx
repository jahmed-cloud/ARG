/**
 * ArchitecturePage — tenant and subscription architecture diagrams (admins only).
 *
 * The Docker counterpart of the local portal's Architecture page (scripts/local_portal/templates/architecture.html):
 * the tenant view (management groups, their Azure Policy assignments, subscriptions) and one subscription's view
 * (effective policy - what is allowed and what is not - VNets and peerings, resource groups and services), drawn by
 * scripts/subscription_analysis/diagram.py with the official Azure icons. Wheel / buttons zoom, drag pans, search
 * highlights, click a subscription to open it, export SVG or PNG.
 *
 * Data: GET /estate/architecture (picker), GET /estate/architecture.svg[?subscription=] from the newest completed
 * estate inventory (refreshed after every scan or with Refresh inventory on the Estate page).
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Link as RouterLink, useSearchParams } from 'react-router-dom';
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  ButtonGroup,
  Card,
  CircularProgress,
  InputAdornment,
  Link,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  Typography,
} from '@mui/material';
import { AccountTree, Add, CenterFocusStrong, Download, Hub, Image, Layers, Remove, Search } from '@mui/icons-material';
import { useApi, ApiError } from '../hooks/useApi';
import { useMoney } from '../hooks/useCurrency';

interface SubscriptionOption {
  id: string;
  name: string;
  management_group?: string | null;
}

interface ArchitectureIndex {
  subscriptions: SubscriptionOption[];
  management_groups: number;
  policies: number;
  architecture_collected: boolean;
  snapshot?: { completed_at?: string | null } | null;
}

const TENANT: SubscriptionOption = { id: '', name: 'Tenant - management groups, subscriptions, Azure Policy' };
const TENANT_NETWORK: SubscriptionOption = { id: '', name: 'Tenant - hubs, spokes and peerings' };
const MIN_SCALE = 0.03;
const MAX_SCALE = 8;

export const ArchitecturePage: React.FC = () => {
  const api = useApi();
  const money = useMoney();   // cost labels are in the billing currency: the Currency dropdown converts them
  const [params, setParams] = useSearchParams();
  const rawView = params.get('view');
  const layer = rawView === 'network' || rawView === 'landing' ? rawView : 'resources';
  const landing = layer === 'landing';
  // the landing-zone view is tenant-wide
  const subscription = landing ? '' : params.get('subscription') ?? '';
  // keep the layer when the subscription changes, and the subscription when the layer changes
  const go = (next: { subscription?: string; view?: string }) => {
    const nextLayer = next.view ?? layer;
    const sub = nextLayer === 'landing' ? '' : next.subscription ?? params.get('subscription') ?? '';
    setParams({ ...(sub ? { subscription: sub } : {}), ...(nextLayer !== 'resources' ? { view: nextLayer } : {}) });
  };
  const [details, setDetails] = useState<{ html: string; markdown: string } | null>(null);

  const [index, setIndex] = useState<ArchitectureIndex | null>(null);
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

  // ---- data ----------------------------------------------------------------------------------------------------

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
    api
      .get(`/estate/architecture.svg${q}`)
      .then((blob: Blob) => blob.text())
      .then((text: string) => {
        if (!cancelled) setSvgText(text);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        setSvgText('');
        setError(e instanceof ApiError ? e.message : 'The diagram could not be loaded.');
      })
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subscription, layer]);

  useEffect(() => {
    if (!landing) return;
    let cancelled = false;
    setDetails(null);
    api
      .get('/estate/landing-zone')
      .then((d: { html: string; markdown: string }) => !cancelled && setDetails(d))
      .catch(() => !cancelled && setDetails({ html: '<p>Landing zone details unavailable.</p>', markdown: '' }));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [landing]);

  // ---- zoom and pan (applied straight to the DOM: no re-render per mouse move) --------------------------------

  const svgSize = useCallback(() => {
    const el = hostRef.current?.querySelector('svg');
    return el ? { w: el.width.baseVal.value, h: el.height.baseVal.value } : { w: 1, h: 1 };
  }, []);

  const apply = useCallback(() => {
    const { scale, tx, ty } = view.current;
    if (hostRef.current) hostRef.current.style.transform = `translate(${tx}px, ${ty}px) scale(${scale})`;
    setZoom(Math.round(scale * 100));
  }, []);

  const zoomAt = useCallback(
    (factor: number, mx: number, my: number) => {
      const v = view.current;
      const next = Math.min(MAX_SCALE, Math.max(MIN_SCALE, v.scale * factor));
      v.tx = mx - (mx - v.tx) * (next / v.scale);
      v.ty = my - (my - v.ty) * (next / v.scale);
      v.scale = next;
      apply();
    },
    [apply],
  );

  const fit = useCallback(() => {
    const stage = stageRef.current;
    if (!stage) return;
    const { w, h } = svgSize();
    const scale = Math.min(stage.clientWidth / w, stage.clientHeight / h, 1);
    view.current = {
      scale,
      tx: (stage.clientWidth - w * scale) / 2,
      ty: Math.max(8, (stage.clientHeight - h * scale) / 2),
    };
    apply();
  }, [apply, svgSize]);

  const actualSize = () => {
    view.current = { scale: 1, tx: 16, ty: 16 };
    apply();
  };

  const zoomCentre = (factor: number) => {
    const stage = stageRef.current;
    if (stage) zoomAt(factor, stage.clientWidth / 2, stage.clientHeight / 2);
  };

  useEffect(() => {
    if (svgText) requestAnimationFrame(fit);
  }, [svgText, fit]);

  useEffect(() => {
    const stage = stageRef.current;
    if (!stage) return;
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
    return () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
    };
  }, [apply]);

  const onPointerDown = (e: React.PointerEvent) => {
    if (e.button !== 0) return;
    const { tx, ty } = view.current;
    drag.current = { x: e.clientX, y: e.clientY, tx, ty, moved: false };
    suppressClick.current = false;
    if (stageRef.current) stageRef.current.style.cursor = 'grabbing';
  };

  // click a subscription (tenant view) or a peered VNet's subscription (subscription view) to open it
  const onClick = (e: React.MouseEvent) => {
    if (suppressClick.current) {
      suppressClick.current = false;
      return;
    }
    const target = (e.target as Element).closest('[data-subscription]');
    const id = target?.getAttribute('data-subscription');
    if (id && id !== subscription) go({ subscription: id });
  };

  // ---- search ----------------------------------------------------------------------------------------------------

  useEffect(() => {
    const el = hostRef.current?.querySelector('svg');
    if (!el) return;
    el.querySelectorAll('.hit').forEach((n) => n.classList.remove('hit'));
    const q = query.trim().toLowerCase();
    if (q.length < 2) {
      setMatches(null);
      return;
    }
    const hits = Array.from(el.querySelectorAll<SVGGraphicsElement>('[data-label]')).filter((n) =>
      (n.getAttribute('data-label') ?? '').includes(q),
    );
    hits.forEach((n) => (n.closest('.node') ?? n).classList.add('hit'));
    setMatches(hits.length);
    const stage = stageRef.current;
    if (hits.length && stage) {
      const b = hits[0].getBBox();
      const scale = Math.max(view.current.scale, 0.8);
      view.current = {
        scale,
        tx: stage.clientWidth / 2 - (b.x + b.width / 2) * scale,
        ty: stage.clientHeight / 2 - (b.y + b.height / 2) * scale,
      };
      apply();
    }
  }, [query, svgText, apply]);

  // ---- export ----------------------------------------------------------------------------------------------------

  const fileName = landing
    ? 'landing-zone'
    : `${subscription ? `subscription-${subscription}` : 'tenant'}-${layer === 'network' ? 'network' : 'architecture'}`;

  const download = (blob: Blob, name: string) => {
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
    img.onerror = () => setError('PNG export failed - use Export SVG instead.');
    img.src = URL.createObjectURL(new Blob([money.text(svgText)], { type: 'image/svg+xml' }));
  };

  // ---- render ----------------------------------------------------------------------------------------------------

  const groupOf = (o: SubscriptionOption) => (o.id ? o.management_group || 'Placement not collected' : 'Tenant');
  // grouped by management group (Autocomplete's groupBy needs the options sorted by group)
  const tenant = layer === 'network' ? TENANT_NETWORK : TENANT;
  const options = [
    tenant,
    ...[...(index?.subscriptions ?? [])].sort(
      (a, b) => groupOf(a).localeCompare(groupOf(b)) || a.name.localeCompare(b.name),
    ),
  ];
  const selected = options.find((o) => o.id === subscription) ?? (subscription ? { id: subscription, name: subscription } : tenant);
  const collected = index?.snapshot?.completed_at ? new Date(index.snapshot.completed_at).toLocaleString() : null;

  return (
    <Box>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 1.5, mb: 1 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>
          {landing
            ? 'Landing zone'
            : `${subscription ? 'Subscription' : 'Tenant'} ${layer === 'network' ? 'network' : 'architecture'}`}
        </Typography>
        {index && (
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            {index.management_groups} management groups · {index.subscriptions.length} subscriptions ·{' '}
            {index.policies} policy assignments{collected ? ` · inventory of ${collected}` : ''}
          </Typography>
        )}
      </Box>

      <Card sx={{ p: 1.5, mb: 1.5, display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 1 }}>
        <ToggleButtonGroup
          size="small"
          exclusive
          value={layer}
          onChange={(_, v) => v && go({ view: v })}
          aria-label="Diagram layer"
        >
          <ToggleButton value="resources" aria-label="Resources and policy">
            <AccountTree fontSize="small" sx={{ mr: 0.75 }} />
            Resources &amp; policy
          </ToggleButton>
          <ToggleButton value="network" aria-label="Network">
            <Hub fontSize="small" sx={{ mr: 0.75 }} />
            Network
          </ToggleButton>
          <ToggleButton value="landing" aria-label="Landing zone">
            <Layers fontSize="small" sx={{ mr: 0.75 }} />
            Landing zone
          </ToggleButton>
        </ToggleButtonGroup>
        {!landing && (
          <Autocomplete
            size="small"
            sx={{ minWidth: 320, flex: '1 1 320px' }}
            options={options}
            value={selected}
            disableClearable
            isOptionEqualToValue={(a, b) => a.id === b.id}
            getOptionLabel={(o) => o.name}
            groupBy={groupOf}
            onChange={(_, o) => go({ subscription: o.id })}
            renderInput={(p) => <TextField {...p} label="View" />}
          />
        )}
        <TextField
          size="small"
          sx={{ flex: '1 1 260px' }}
          placeholder="Find a subscription, group, resource group, service…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Search fontSize="small" />
              </InputAdornment>
            ),
            endAdornment:
              matches !== null ? (
                <InputAdornment position="end">
                  <Typography variant="caption" color="text.secondary">
                    {matches} match(es)
                  </Typography>
                </InputAdornment>
              ) : undefined,
          }}
        />
        <ButtonGroup size="small" variant="outlined" aria-label="Zoom">
          <Tooltip title="Zoom out">
            <Button onClick={() => zoomCentre(1 / 1.25)} aria-label="Zoom out">
              <Remove fontSize="small" />
            </Button>
          </Tooltip>
          <Button disabled sx={{ minWidth: 64 }}>
            {zoom} %
          </Button>
          <Tooltip title="Zoom in">
            <Button onClick={() => zoomCentre(1.25)} aria-label="Zoom in">
              <Add fontSize="small" />
            </Button>
          </Tooltip>
          <Tooltip title="Fit to the window">
            <Button onClick={fit} aria-label="Fit">
              <CenterFocusStrong fontSize="small" />
            </Button>
          </Tooltip>
          <Button onClick={actualSize}>100 %</Button>
        </ButtonGroup>
        {subscription && (
          <Button size="small" startIcon={<AccountTree />} onClick={() => go({ subscription: '' })}>
            Tenant view
          </Button>
        )}
        <Button size="small" variant="outlined" startIcon={<Download />} onClick={exportSvg} disabled={!svgText}>
          Export SVG
        </Button>
        <Button size="small" variant="contained" startIcon={<Image />} onClick={exportPng} disabled={!svgText}>
          Export PNG
        </Button>
      </Card>

      <Typography variant="caption" color="text.secondary" component="p" sx={{ mb: 1 }}>
        {landing ? (
          <>
            Your management groups, Azure Policy and hub network compared with Microsoft&apos;s Azure Landing Zones
            reference. Archetypes come from group names and positions - correct them under Settings &gt; Analysis
            settings &gt; Landing zone - management group archetypes. Built from the estate inventory - refresh it on
            the{' '}
          </>
        ) : (
          <>
            Wheel to zoom, drag to move
            {subscription ? '' : `, click a ${layer === 'network' ? 'VNet' : 'subscription'} to open it`}. Built from
            the estate inventory - refresh it on the{' '}
          </>
        )}
        <Link component={RouterLink} to="/estate">
          Estate
        </Link>{' '}
        page.{landing ? '' : ' Icons: Microsoft Azure architecture icons.'}
      </Typography>

      {error && (
        <Alert severity={index && !index.architecture_collected ? 'info' : 'warning'} sx={{ mb: 1.5 }}>
          {error}
        </Alert>
      )}
      {index && !index.architecture_collected && !error && (
        <Alert severity="info" sx={{ mb: 1.5 }}>
          Management-group placement and policy assignments are not in this inventory yet - refresh it on the Estate
          page to draw them.
        </Alert>
      )}

      <Box
        ref={stageRef}
        onPointerDown={onPointerDown}
        onClick={onClick}
        sx={{
          position: 'relative',
          overflow: 'hidden',
          height: 'calc(100vh - 290px)',
          minHeight: 420,
          border: 1,
          borderColor: 'divider',
          borderRadius: 1,
          bgcolor: '#F7F9FB',
          cursor: 'grab',
          touchAction: 'none',
          userSelect: 'none',
          '& svg': { display: 'block' },
        }}
      >
        {loading && (
          <Box sx={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', zIndex: 1 }}>
            <CircularProgress />
          </Box>
        )}
        {/* ARG's own diagram (diagram.py): every Azure-sourced value in it is escaped */}
        <Box
          ref={hostRef}
          sx={{ position: 'absolute', left: 0, top: 0, transformOrigin: '0 0' }}
          dangerouslySetInnerHTML={{ __html: money.text(svgText) }}
        />
      </Box>

      {landing && (
        <Card sx={{ p: 2.5, mt: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, flex: 1 }}>
              Landing zone details
            </Typography>
            <Button
              size="small"
              variant="outlined"
              startIcon={<Download />}
              disabled={!details?.markdown}
              onClick={() => details && download(new Blob([details.markdown], { type: 'text/markdown' }), 'landing-zone.md')}
            >
              Download Markdown
            </Button>
          </Box>
          {!details ? (
            <CircularProgress size={24} />
          ) : (
            <Box
              sx={{
                fontSize: 14,
                lineHeight: 1.6,
                overflowWrap: 'anywhere',
                '& h1': { display: 'none' },
                '& h2': { fontSize: 19, mt: 3, borderBottom: 1, borderColor: 'divider', pb: 0.5 },
                '& h3': { fontSize: 16, mt: 2.5 },
                '& table': { borderCollapse: 'collapse', width: '100%', display: 'block', overflowX: 'auto', my: 1.5, fontSize: 13 },
                '& th, & td': { border: 1, borderColor: 'divider', px: 1, py: 0.5, verticalAlign: 'top', textAlign: 'left' },
                '& th': { bgcolor: 'action.hover' },
                '& code': { fontFamily: 'monospace', fontSize: 12.5, bgcolor: 'action.hover', px: 0.5, borderRadius: 0.5 },
                '& a': { color: 'primary.main' },
              }}
              // server-rendered by scripts/local_portal/render.py: raw HTML from Azure values is neutralised
              dangerouslySetInnerHTML={{ __html: details.html }}
            />
          )}
        </Card>
      )}
    </Box>
  );
};

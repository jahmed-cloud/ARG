/**
 * EstatePage — every resource across every connected subscription (admins only).
 *
 * The Docker counterpart of the local portal's Estate page (scripts/local_portal/templates/estate.html):
 * category tiles, Resources / Suggestions views, faceted filters with counts, breakdowns, sortable and
 * paginated table, row drill-down (usage profile, tags, suggestions with the full finding analysis),
 * CSV export, shareable filtered links and the markdown overview.
 *
 * Data: GET /estate (estate.json format 2, refreshed by the worker after every scan or with Refresh
 * inventory), GET /estate/status while a refresh runs. Filters live in the URL query string.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Alert,
  Box,
  Button,
  ButtonGroup,
  Card,
  Checkbox,
  Chip,
  CircularProgress,
  Collapse,
  FormControl,
  FormControlLabel,
  Grid,
  IconButton,
  InputAdornment,
  InputLabel,
  Link,
  MenuItem,
  Pagination,
  Select,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  TextField,
  Tooltip,
  Typography,
  alpha,
  useTheme,
} from '@mui/material';
import {
  Download,
  FilterAltOff,
  KeyboardArrowDown,
  KeyboardArrowRight,
  Link as LinkIcon,
  OpenInNew,
  Refresh,
  Search,
  Description,
} from '@mui/icons-material';
import { useSnackbar } from 'notistack';
import { useApi, ApiError } from '../hooks/useApi';
import { useMoney } from '../hooks/useCurrency';
import { SEVERITY_COLORS, PALETTE } from '../theme/ThemeProvider';
import { FindingDetailPanel } from '../components/findings/FindingDetailPanel';
import {
  BLANK_REASON,
  CPU_BANDS,
  Column,
  Estate,
  FILTER_KEYS,
  FilterKey,
  Filters,
  PAGE_SIZE,
  RESOURCE_COLUMNS,
  RawEstate,
  Resource,
  SUGGESTION_COLUMNS,
  SnapshotMeta,
  Sort,
  Suggestion,
  View,
  activityBand,
  cellText,
  countBy,
  cpuBand,
  cpuProfile,
  expand,
  fmt,
  hasCompute,
  hasCpu,
  resourceMatches,
  sevRank,
  sortRows,
  suggestionMatches,
  toCsv,
  visibleSuggestion,
} from '../components/estate/estateData';

interface EstateStatus {
  running: boolean;
  latest: SnapshotMeta | null;
  available: SnapshotMeta | null;
}

const POLL_MS = 10000;

const when = (v: string | null | undefined) => (v ? new Date(v).toLocaleString() : '—');

const triggerLabel = (t: string | undefined) =>
  !t ? '' : t === 'manual' ? 'started manually' : t.startsWith('scan:') ? 'after a scan' : t;

function download(content: BlobPart, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(url);
    a.remove();
  }, 1000);
}

const SevChip: React.FC<{ severity: string; label?: React.ReactNode }> = ({ severity, label }) => (
  <Chip
    size="small"
    label={label ?? severity.toUpperCase()}
    sx={{
      bgcolor: alpha(SEVERITY_COLORS[severity] ?? PALETTE.grey, 0.15),
      color: SEVERITY_COLORS[severity] ?? PALETTE.grey,
      fontWeight: 700,
      fontSize: 11,
      height: 22,
    }}
  />
);

// ---- filter select with counts -------------------------------------------------------------------

const FacetSelect: React.FC<{
  label: string;
  value: string;
  entries: [string, number][];
  allLabel: string;
  onChange: (v: string) => void;
  labelFn?: (v: string) => string;
  disabled?: boolean;
}> = ({ label, value, entries, allLabel, onChange, labelFn, disabled }) => {
  const id = `estate-${label.replace(/\W+/g, '-').toLowerCase()}`;
  const options = entries.slice(0, 500);
  const missing = value && !options.some(([v]) => v === value);
  return (
    <FormControl size="small" fullWidth disabled={disabled}>
      <InputLabel id={id}>{label}</InputLabel>
      <Select labelId={id} label={label} value={value} onChange={(e) => onChange(String(e.target.value))}>
        <MenuItem value="">{allLabel}</MenuItem>
        {options.map(([v, count]) => (
          <MenuItem key={v} value={v}>
            {(labelFn ? labelFn(v) : v) + ` (${fmt(count)})`}
          </MenuItem>
        ))}
        {missing && <MenuItem value={value}>{`${labelFn ? labelFn(value) : value} (0)`}</MenuItem>}
      </Select>
    </FormControl>
  );
};

// ---- breakdown panel -------------------------------------------------------------------------------

const Breakdown: React.FC<{
  title: string;
  entries: [string, number][];
  active?: string;
  onPick: (v: string) => void;
  labelFn?: (v: string) => string;
}> = ({ title, entries, active, onPick, labelFn }) => {
  const theme = useTheme();
  if (!entries.length) return null;
  const max = entries[0][1] || 1;
  return (
    <Grid item xs={12} sm={6} lg={3}>
      <Card sx={{ p: 1.5, height: '100%' }}>
        <Typography variant="overline" sx={{ color: 'text.secondary', fontWeight: 700 }}>
          {title}
        </Typography>
        {entries.slice(0, 12).map(([value, count]) => (
          <Box
            key={value}
            component="button"
            type="button"
            title={`Filter: ${labelFn ? labelFn(value) : value}`}
            onClick={() => onPick(active === value ? '' : value)}
            sx={{
              all: 'unset',
              boxSizing: 'border-box',
              cursor: 'pointer',
              display: 'block',
              width: '100%',
              position: 'relative',
              py: 0.4,
              px: 0.75,
              borderRadius: 0.5,
              outline: active === value ? `1px solid ${theme.palette.primary.main}` : 'none',
              '&:hover': { bgcolor: alpha(theme.palette.primary.main, 0.08) },
              '&:focus-visible': { outline: `2px solid ${theme.palette.primary.main}` },
            }}
          >
            <Box
              sx={{
                position: 'absolute',
                inset: 0,
                width: `${Math.max(2, Math.round((100 * count) / max))}%`,
                bgcolor: alpha(theme.palette.primary.main, 0.12),
                borderRadius: 0.5,
              }}
            />
            <Box sx={{ position: 'relative', display: 'flex', gap: 1, fontSize: 13 }}>
              <Box component="span" sx={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {labelFn ? labelFn(value) : value}
              </Box>
              <Box component="span" sx={{ ml: 'auto', color: 'text.secondary', flexShrink: 0 }}>
                {fmt(count)}
              </Box>
            </Box>
          </Box>
        ))}
        {entries.length > 12 && (
          <Typography variant="caption" sx={{ color: 'text.secondary' }}>
            + {entries.length - 12} more - use the filter above
          </Typography>
        )}
      </Card>
    </Grid>
  );
};

// ---- resource drill-down ---------------------------------------------------------------------------

const SuggestionItem: React.FC<{ s: Suggestion }> = ({ s }) => {
  const money = useMoney();
  const [open, setOpen] = useState(false);
  return (
    <Box sx={{ py: 0.25 }}>
      <Box
        component="button"
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        sx={{ all: 'unset', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 1, '&:hover .t': { textDecoration: 'underline' } }}
      >
        {open ? <KeyboardArrowDown fontSize="small" /> : <KeyboardArrowRight fontSize="small" />}
        <SevChip severity={s.severity} />
        <Typography className="t" variant="body2">
          {money.text(s.title)}
        </Typography>
        {s.savingsUsd > 0 && (
          <Typography variant="caption" sx={{ color: 'text.secondary' }}>
            · est. {money.format(s.savingsUsd)}/month
          </Typography>
        )}
      </Box>
      <Collapse in={open} timeout="auto" unmountOnExit>
        {s.findingId && <FindingDetailPanel findingId={s.findingId} />}
      </Collapse>
    </Box>
  );
};

const ResourceDetail: React.FC<{ r: Resource; suggestions: Suggestion[] }> = ({ r, suggestions }) => {
  const [showHygiene, setShowHygiene] = useState(false);
  const sorted = suggestions.slice().sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
  const actionable = sorted.filter((s) => !s.hygiene);
  const hygiene = sorted.filter((s) => s.hygiene);
  const usage = [
    r.vcpu ? `${r.vcpu} vCPU, ${r.ramGB} GB RAM` : null,
    r.cpuAvg !== null ? `CPU ${cpuProfile(r)}` : hasCompute(r) ? 'no CPU data (not running in the last 30 days)' : null,
    r.memAvg !== null
      ? `memory used ${r.memAvg.toFixed(1)} % on average${r.memPeakHour !== null ? `, busiest hour ${r.memPeakHour.toFixed(1)} %` : ''}`
      : null,
    r.usage
      ? `usage: ${r.usage}${r.dormant ? " (idle, holds data: tier or archive it, don't delete it)" : r.idle ? ' (idle)' : ''}`
      : null,
    r.nva ? 'network virtual appliance: vendor-sized, ~100 % memory is normal' : null,
  ].filter(Boolean);
  const tags = Object.entries(r.tags || {});
  return (
    <Box sx={{ p: 2 }}>
      <Typography variant="caption" sx={{ fontFamily: 'monospace', wordBreak: 'break-all', color: 'text.secondary' }}>
        {r.id}
      </Typography>
      {(hasCpu(r) || r.usage) && usage.length > 0 && (
        <Typography variant="body2" sx={{ mt: 1 }}>
          {usage.join(' · ')} - last 30 days, Azure Monitor
        </Typography>
      )}
      <Typography variant="body2" sx={{ mt: 1, display: 'flex', flexWrap: 'wrap', gap: 1, alignItems: 'center' }}>
        <Link href={`https://portal.azure.com/#resource${r.id}`} target="_blank" rel="noopener noreferrer">
          Open in Azure portal <OpenInNew sx={{ fontSize: 13, verticalAlign: 'middle' }} />
        </Link>
        {r.kind && <span>· kind: {r.kind}</span>}
        {r.managedBy && <span>· managed by: {r.managedBy.split('/').pop()}</span>}
      </Typography>
      {tags.length > 0 && (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 1 }}>
          {tags.map(([k, v]) => (
            <Chip key={k} size="small" label={`${k}: ${v}`} sx={{ fontSize: 11 }} />
          ))}
        </Box>
      )}
      <Box sx={{ mt: 1.5 }}>
        {actionable.length ? (
          actionable.map((s) => <SuggestionItem key={s.findingId || s.title} s={s} />)
        ) : (
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            No actionable suggestions for this resource.
          </Typography>
        )}
        {hygiene.length > 0 && (
          <Box sx={{ mt: 1 }}>
            <Button size="small" onClick={() => setShowHygiene((v) => !v)}>
              {showHygiene ? 'Hide' : 'Show'} tag / naming hygiene ({hygiene.length})
            </Button>
            <Collapse in={showHygiene} unmountOnExit>
              {hygiene.map((s) => (
                <SuggestionItem key={s.findingId || s.title} s={s} />
              ))}
            </Collapse>
          </Box>
        )}
      </Box>
    </Box>
  );
};

// ---- page ------------------------------------------------------------------------------------------

export const EstatePage: React.FC = () => {
  const api = useApi();
  const money = useMoney();
  const theme = useTheme();
  const { enqueueSnackbar } = useSnackbar();
  const [params, setParams] = useSearchParams();

  const [estate, setEstate] = useState<Estate | null>(null);
  const [status, setStatus] = useState<EstateStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notReady, setNotReady] = useState(false);
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState<string | null>(null);

  const view: View = params.get('view') === 'suggestions' ? 'suggestions' : 'resources';
  const filters: Filters = useMemo(() => {
    const f: Filters = {};
    FILTER_KEYS.forEach((k) => {
      const v = params.get(k);
      if (v) f[k] = v;
    });
    return f;
  }, [params]);
  const sortParam = params.get('sort') || '';
  const sort: Sort = sortParam ? { key: sortParam.replace(/^-/, ''), dir: sortParam.startsWith('-') ? -1 : 1 } : { key: '', dir: 1 };

  const update = useCallback(
    (changes: Record<string, string | null>) => {
      const next = new URLSearchParams(params);
      Object.entries(changes).forEach(([k, v]) => (v ? next.set(k, v) : next.delete(k)));
      setParams(next, { replace: true });
      setPage(1);
      setExpanded(null);
    },
    [params, setParams]
  );

  const setFilter = (key: FilterKey, value: string) => {
    const changes: Record<string, string | null> = { [key]: value || null };
    if (key === 'category') Object.assign(changes, { type: null, size: null });
    if (key === 'type') changes.size = null;
    update(changes);
  };

  const loadEstate = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data: RawEstate = await api.get('/estate');
      setEstate(expand(data));
      setNotReady(false);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        setEstate(null);
        setNotReady(true);
      } else {
        setError(e instanceof ApiError ? e.message : 'Could not load the estate');
      }
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadStatus = useCallback(async (): Promise<EstateStatus | null> => {
    try {
      const s: EstateStatus = await api.get('/estate/status');
      setStatus(s);
      return s;
    } catch {
      return null;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    loadEstate();
    loadStatus();
  }, [loadEstate, loadStatus]);

  // While a refresh runs, poll its status; reload the data once it finishes.
  useEffect(() => {
    if (!status?.running) return undefined;
    const timer = setInterval(async () => {
      const s = await loadStatus();
      if (s && !s.running) {
        if (s.latest?.status === 'completed') {
          enqueueSnackbar('Estate inventory refreshed', { variant: 'success' });
          loadEstate();
        } else if (s.latest?.status === 'failed') {
          enqueueSnackbar(`Estate refresh failed: ${s.latest.error_message ?? 'unknown error'}`, { variant: 'error' });
        }
      }
    }, POLL_MS);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status?.running]);

  const refresh = async () => {
    try {
      const r = await api.post('/estate/refresh');
      enqueueSnackbar(r.started ? 'Estate refresh started (about 5 minutes)' : 'A refresh is already running', {
        variant: 'info',
      });
      await loadStatus();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Could not start the refresh', { variant: 'error' });
    }
  };

  const downloadOverview = async () => {
    try {
      const blob: Blob = await api.get('/estate/overview.md');
      const stamp = (estate?.snapshot?.completed_at ?? new Date().toISOString()).slice(0, 10);
      download(blob, `estate-${stamp}.md`, 'text/markdown');
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Could not download the overview', { variant: 'error' });
    }
  };

  // ---- derived data -------------------------------------------------------------------------------

  const subName = useCallback(
    (id: string) => estate?.subscriptions.find((s) => s.id === id)?.name ?? id,
    [estate]
  );

  const rowsFor = useCallback(
    (skip?: FilterKey): (Resource | Suggestion)[] => {
      if (!estate) return [];
      return view === 'resources'
        ? estate.resources.filter((r) => resourceMatches(estate, r, filters, skip))
        : estate.suggestions.filter((s) => suggestionMatches(estate, s, filters, skip));
    },
    [estate, view, filters]
  );

  const current = useMemo(() => rowsFor(), [rowsFor]);

  const facets = useMemo(() => {
    if (!estate) return null;
    const res = view === 'resources';
    const base = (k: FilterKey) => estate.resources.filter((r) => resourceMatches(estate, r, filters, k));
    const sugg = (k: FilterKey) => estate.suggestions.filter((s) => suggestionMatches(estate, s, filters, k));
    const resourceFacet = (k: FilterKey, fn: (r: Resource) => string) => countBy(base(k), fn);
    const pick = (r: Resource) => (estate.byResource.get(r.key) || []).filter((s) => visibleSuggestion(s, filters));
    return {
      category: res ? resourceFacet('category', (r) => r.category) : countBy(sugg('category'), (s) => s.category),
      type: res ? resourceFacet('type', (r) => r.typeLabel) : countBy(sugg('type'), (s) => s.typeLabel),
      size: resourceFacet('size', (r) => r.size || '(none)'),
      sub: res ? resourceFacet('sub', (r) => r.subscriptionId) : countBy(sugg('sub'), (s) => s.subscriptionId),
      region: resourceFacet('region', (r) => r.location || '(none)'),
      env: resourceFacet('env', (r) => r.env),
      state: resourceFacet('state', (r) => r.state || '(none)'),
      stype: countBy(
        res ? base('stype').flatMap((r) => estate.byResource.get(r.key) || []) : sugg('stype'),
        (s) => s.type
      ),
      sev: countBy(res ? base('sev').flatMap(pick) : sugg('sev'), (s) => s.severity).sort(
        (a, b) => sevRank(a[0]) - sevRank(b[0])
      ),
    };
  }, [estate, view, filters]);

  const tiles = useMemo(() => {
    if (!estate) return [];
    const visible = estate.resources.filter((r) => !r.subResource || !!filters.ext || filters.type === r.typeLabel);
    return [
      { key: '', label: 'All resources', count: visible.length, withSugg: 0 },
      ...countBy(visible, (r) => r.category).map(([cat, count]) => ({
        key: cat,
        label: cat,
        count,
        withSugg: visible.filter((r) => r.category === cat && r.suggestions).length,
      })),
    ];
  }, [estate, filters.ext, filters.type]);

  const columns: Column[] = useMemo(() => {
    if (view === 'suggestions') return SUGGESTION_COLUMNS;
    const res = current as Resource[];
    return RESOURCE_COLUMNS.filter(
      (c) => (!c.compute || res.some(hasCpu)) && (!c.usage || res.some((r) => r.usage))
    );
  }, [view, current]);

  const sorted = useMemo(() => sortRows(current.slice(), columns, sort, view), [current, columns, sort, view]);
  const pages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const pageRows = sorted.slice((Math.min(page, pages) - 1) * PAGE_SIZE, Math.min(page, pages) * PAGE_SIZE);

  const breakdowns = useMemo(() => {
    if (!estate) return [];
    if (view === 'resources') {
      const res = current as Resource[];
      const compute = res.filter(hasCpu);
      const active = res.filter((r) => activityBand(r));
      const bandOrder = CPU_BANDS.map(([, label]) => label).concat(['no data']);
      return [
        { title: 'By type', key: 'type' as FilterKey, entries: countBy(res, (r) => r.typeLabel) },
        {
          title: filters.type ? `Sizes / SKUs of ${filters.type}` : 'Sizes / SKUs',
          key: 'size' as FilterKey,
          entries: countBy(res, (r) => r.size || '(none)'),
        },
        ...(active.length
          ? [{ title: 'Activity, last 30 days', key: 'act' as FilterKey, entries: countBy(active, activityBand) }]
          : []),
        ...(compute.length
          ? [{
              title: 'Average CPU, last 30 days',
              key: 'cpu' as FilterKey,
              entries: countBy(compute, (r) => cpuBand(r.cpuAvg)).sort(
                (a, b) => bandOrder.indexOf(a[0]) - bandOrder.indexOf(b[0])
              ),
            }]
          : []),
        { title: 'By region', key: 'region' as FilterKey, entries: countBy(res, (r) => r.location || '(none)') },
        { title: 'By subscription', key: 'sub' as FilterKey, entries: countBy(res, (r) => r.subscriptionId), labelFn: subName },
        { title: 'By environment', key: 'env' as FilterKey, entries: countBy(res, (r) => r.env) },
        {
          title: 'Suggestions on these resources',
          key: 'stype' as FilterKey,
          entries: countBy(
            res.flatMap((r) => (estate.byResource.get(r.key) || []).filter((s) => visibleSuggestion(s, filters))),
            (s) => s.type
          ),
        },
      ];
    }
    const sugg = current as Suggestion[];
    return [
      {
        title: 'By severity',
        key: 'sev' as FilterKey,
        entries: countBy(sugg, (s) => s.severity).sort((a, b) => sevRank(a[0]) - sevRank(b[0])),
      },
      { title: 'By suggestion type', key: 'stype' as FilterKey, entries: countBy(sugg, (s) => s.type) },
      { title: 'By resource type', key: 'type' as FilterKey, entries: countBy(sugg, (s) => s.typeLabel) },
      { title: 'By subscription', key: 'sub' as FilterKey, entries: countBy(sugg, (s) => s.subscriptionId), labelFn: subName },
    ];
  }, [estate, view, current, filters, subName]);

  const hasFilters = FILTER_KEYS.some((k) => filters[k]);
  const costMissing = estate ? estate.costUnavailable.map(subName) : [];

  // ---- render -------------------------------------------------------------------------------------

  const running = !!status?.running;
  const statusLine = running
    ? `Refreshing the inventory (${triggerLabel(status?.latest?.triggered_by)}, since ${when(status?.latest?.started_at)}) - about 5 minutes.`
    : status?.latest?.status === 'failed'
      ? `The last refresh failed (${when(status.latest.completed_at)}): ${status.latest.error_message ?? 'unknown error'}`
      : null;

  return (
    <Box>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 1.5, mb: 1 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>
          Estate inventory
        </Typography>
        {estate && (
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            {fmt(estate.resources.length)} resources · {estate.subscriptions.length} subscriptions ·{' '}
            {fmt(estate.suggestions.length)} suggestions
          </Typography>
        )}
        <Box sx={{ ml: 'auto', display: 'flex', gap: 1 }}>
          <Tooltip title="Resource Graph inventory, VM sizes, 30-day usage metrics and cost for every connected subscription (about 5 minutes). Also runs automatically after every scan.">
            <span>
              <Button
                variant="contained"
                size="small"
                startIcon={running ? <CircularProgress size={14} color="inherit" /> : <Refresh />}
                onClick={refresh}
                disabled={running}
              >
                {running ? 'Refreshing…' : 'Refresh inventory'}
              </Button>
            </span>
          </Tooltip>
          <Button size="small" variant="outlined" startIcon={<Description />} onClick={downloadOverview} disabled={!estate}>
            Markdown overview
          </Button>
        </Box>
      </Box>

      {estate?.snapshot && (
        <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 1.5 }} role="status">
          Live Resource Graph inventory of {when(estate.inventoryAt)} ({triggerLabel(estate.snapshot.triggered_by)}).
          Suggestions are the open and acknowledged findings; cost is the last 30 days from Cost Management.
        </Typography>
      )}
      {statusLine && (
        <Alert severity={running ? 'info' : 'warning'} sx={{ mb: 2 }}>
          {statusLine}
        </Alert>
      )}
      {costMissing.length > 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          No cost data for {costMissing.join(', ')}: the app registration needs the Cost Management Reader role there.
        </Alert>
      )}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {loading && !estate ? (
        <Card sx={{ p: 2 }}>
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} height={40} />
          ))}
        </Card>
      ) : notReady && !estate ? (
        <Card sx={{ p: 5, textAlign: 'center' }}>
          <Typography variant="h6" sx={{ mb: 1 }}>
            No estate inventory yet
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary', mb: 2 }}>
            {running
              ? 'The first inventory is being collected; this page updates when it is ready.'
              : 'Collect it now (about 5 minutes) - it also runs automatically after every completed scan.'}
          </Typography>
          {!running && (
            <Button variant="contained" startIcon={<Refresh />} onClick={refresh}>
              Refresh inventory
            </Button>
          )}
        </Card>
      ) : estate && facets ? (
        <>
          {/* Category tiles */}
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }} aria-label="Categories - click to filter">
            {tiles.map((t) => {
              const active = (filters.category || '') === t.key;
              return (
                <Card
                  key={t.key || 'all'}
                  component="button"
                  type="button"
                  onClick={() => setFilter('category', active && t.key ? '' : t.key)}
                  title={t.withSugg ? `${t.withSugg} with suggestions` : undefined}
                  sx={{
                    all: 'unset',
                    cursor: 'pointer',
                    p: 1.25,
                    minWidth: 120,
                    borderRadius: 1,
                    bgcolor: active ? alpha(theme.palette.primary.main, 0.15) : 'background.paper',
                    border: `1px solid ${active ? theme.palette.primary.main : alpha(theme.palette.text.primary, 0.1)}`,
                    '&:focus-visible': { outline: `2px solid ${theme.palette.primary.main}` },
                  }}
                >
                  <Typography sx={{ fontWeight: 700, fontSize: 18 }}>{fmt(t.count)}</Typography>
                  <Typography variant="body2">{t.label}</Typography>
                  {t.withSugg > 0 && (
                    <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                      {fmt(t.withSugg)} with suggestions
                    </Typography>
                  )}
                </Card>
              );
            })}
          </Box>

          {/* Filters */}
          <Card sx={{ p: 2, mb: 2 }}>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1.5, alignItems: 'center', mb: 2 }}>
              <ButtonGroup size="small" aria-label="Inventory view">
                {(['resources', 'suggestions'] as View[]).map((v) => (
                  <Button
                    key={v}
                    variant={view === v ? 'contained' : 'outlined'}
                    aria-pressed={view === v}
                    onClick={() => update({ view: v === 'resources' ? null : v, sort: null })}
                  >
                    {v === 'resources' ? 'Resources' : 'Suggestions'}
                  </Button>
                ))}
              </ButtonGroup>
              <TextField
                size="small"
                sx={{ flex: 1, minWidth: 260 }}
                placeholder="name, resource group, tag, size, configuration, IP…"
                value={filters.q ?? ''}
                onChange={(e) => update({ q: e.target.value || null })}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <Search fontSize="small" />
                    </InputAdornment>
                  ),
                }}
              />
            </Box>
            <Grid container spacing={1.5}>
              <Grid item xs={12} sm={6} md={3}>
                <FacetSelect label="Category" value={filters.category ?? ''} entries={facets.category} allLabel="All categories" onChange={(v) => setFilter('category', v)} />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <FacetSelect label="Type" value={filters.type ?? ''} entries={facets.type} allLabel="All types" onChange={(v) => setFilter('type', v)} />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <FacetSelect label="Size / SKU" value={filters.size ?? ''} entries={facets.size} allLabel={view === 'resources' ? 'All sizes / SKUs' : 'Any'} onChange={(v) => setFilter('size', v)} />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <FacetSelect label="Subscription" value={filters.sub ?? ''} entries={facets.sub} allLabel="All subscriptions" labelFn={subName} onChange={(v) => setFilter('sub', v)} />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <FacetSelect label="Region" value={filters.region ?? ''} entries={facets.region} allLabel={view === 'resources' ? 'All regions' : 'Any'} onChange={(v) => setFilter('region', v)} />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <FacetSelect label="Environment" value={filters.env ?? ''} entries={facets.env} allLabel={view === 'resources' ? 'All environments' : 'Any'} onChange={(v) => setFilter('env', v)} />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <FacetSelect label="State" value={filters.state ?? ''} entries={facets.state} allLabel={view === 'resources' ? 'All states' : 'Any'} onChange={(v) => setFilter('state', v)} />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <FormControl size="small" fullWidth disabled={view !== 'resources'}>
                  <InputLabel id="estate-has">Suggestions</InputLabel>
                  <Select labelId="estate-has" label="Suggestions" value={filters.has ?? ''} onChange={(e) => setFilter('has', String(e.target.value))}>
                    <MenuItem value="">All resources</MenuItem>
                    <MenuItem value="any">With actionable suggestions</MenuItem>
                    <MenuItem value="crit-high">With critical / high</MenuItem>
                    <MenuItem value="none">Without actionable suggestions</MenuItem>
                    <MenuItem value="hygiene">Only tag / naming hygiene</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <FacetSelect label="Suggestion type" value={filters.stype ?? ''} entries={facets.stype} allLabel="All suggestion types" onChange={(v) => setFilter('stype', v)} />
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <FacetSelect label="Severity" value={filters.sev ?? ''} entries={facets.sev} allLabel="All severities" onChange={(v) => setFilter('sev', v)} />
              </Grid>
              {filters.cpu && (
                <Grid item xs={12} sm={6} md={3}>
                  <Chip label={`Average CPU: ${filters.cpu}`} onDelete={() => setFilter('cpu', '')} />
                </Grid>
              )}
              {filters.act && (
                <Grid item xs={12} sm={6} md={3}>
                  <Chip label={`Activity: ${filters.act}`} onDelete={() => setFilter('act', '')} />
                </Grid>
              )}
            </Grid>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 1, mt: 1.5 }}>
              <FormControlLabel
                control={<Checkbox size="small" checked={!!filters.hyg} onChange={(e) => setFilter('hyg', e.target.checked ? '1' : '')} />}
                label={<Typography variant="body2">Include tag / naming hygiene findings</Typography>}
              />
              <FormControlLabel
                control={<Checkbox size="small" checked={!!filters.ext} onChange={(e) => setFilter('ext', e.target.checked ? '1' : '')} />}
                label={<Typography variant="body2">Include VM / Arc extensions and license profiles</Typography>}
              />
              <Box sx={{ ml: 'auto', display: 'flex', gap: 1 }}>
                <Button size="small" startIcon={<FilterAltOff />} disabled={!hasFilters} onClick={() => update(Object.fromEntries(FILTER_KEYS.map((k) => [k, null])))}>
                  Clear filters
                </Button>
                <Button size="small" startIcon={<Download />} onClick={() => download(toCsv(sorted, view), `estate-${view}.csv`, 'text/csv;charset=utf-8')}>
                  Download CSV
                </Button>
                <Button
                  size="small"
                  startIcon={<LinkIcon />}
                  onClick={() =>
                    navigator.clipboard
                      ?.writeText(window.location.href)
                      .then(() => enqueueSnackbar('Link to this filtered view copied', { variant: 'success' }))
                  }
                >
                  Copy link
                </Button>
              </Box>
            </Box>
          </Card>

          {/* Breakdowns */}
          <Grid container spacing={1.5} sx={{ mb: 2 }} aria-label="Breakdowns - click an entry to filter">
            {breakdowns.map((b) => (
              <Breakdown
                key={b.title}
                title={b.title}
                entries={b.entries}
                active={filters[b.key]}
                labelFn={'labelFn' in b ? b.labelFn : undefined}
                onPick={(v) => setFilter(b.key, v)}
              />
            ))}
          </Grid>

          {/* Results */}
          <Card>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 1.5, px: 2, py: 1.5 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                {view === 'resources' ? 'Resources' : 'Suggestions'}
              </Typography>
              <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                {fmt(sorted.length)} match{sorted.length === 1 ? '' : 'es'} · click a row for details
              </Typography>
              {pages > 1 && (
                <Pagination
                  sx={{ ml: 'auto' }}
                  size="small"
                  count={pages}
                  page={Math.min(page, pages)}
                  onChange={(_, p) => {
                    setPage(p);
                    setExpanded(null);
                  }}
                />
              )}
            </Box>
            <TableContainer sx={{ overflowX: 'auto' }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell padding="checkbox" />
                    {columns.map((c) => (
                      <TableCell key={c.key} align={c.num ? 'right' : 'left'} sx={{ whiteSpace: 'nowrap' }}>
                        <TableSortLabel
                          active={sort.key === c.key}
                          direction={sort.key === c.key && sort.dir < 0 ? 'desc' : 'asc'}
                          onClick={() => {
                            const dir = sort.key === c.key ? -sort.dir : c.num ? -1 : 1;
                            update({ sort: `${dir < 0 ? '-' : ''}${c.key}` });
                          }}
                        >
                          {c.label}
                        </TableSortLabel>
                      </TableCell>
                    ))}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {pageRows.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={columns.length + 1} sx={{ color: 'text.secondary', py: 4, textAlign: 'center' }}>
                        Nothing matches these filters.
                      </TableCell>
                    </TableRow>
                  )}
                  {view === 'resources'
                    ? (pageRows as Resource[]).map((r) => {
                        const open = expanded === r.key;
                        return (
                          <React.Fragment key={r.key}>
                            <TableRow hover onClick={() => setExpanded(open ? null : r.key)} sx={{ cursor: 'pointer', '& > td': open ? { borderBottom: 'none' } : undefined }}>
                              <TableCell padding="checkbox">
                                <IconButton size="small" aria-label={open ? 'Collapse resource' : 'Expand resource'} aria-expanded={open}>
                                  {open ? <KeyboardArrowDown fontSize="small" /> : <KeyboardArrowRight fontSize="small" />}
                                </IconButton>
                              </TableCell>
                              {columns.map((c) => {
                                if (c.key === 'name') {
                                  return (
                                    <TableCell key={c.key} sx={{ fontWeight: 600, whiteSpace: 'nowrap' }}>
                                      {r.name}
                                    </TableCell>
                                  );
                                }
                                if (c.key === 'suggestions') {
                                  return (
                                    <TableCell key={c.key} align="right">
                                      {r.suggestions > 0 && <SevChip severity={r.maxSeverity} label={r.suggestions} />}
                                    </TableCell>
                                  );
                                }
                                const text = cellText(r, c);
                                const lowUtil =
                                  (c.key === 'cpuAvg' && r.cpuAvg !== null && r.cpuAvg < 5) ||
                                  (c.key === 'cpuPeakHour' && r.cpuPeakHour !== null && r.cpuPeakHour >= 80) ||
                                  (c.key === 'usage' && r.idle);
                                const title =
                                  text === ''
                                    ? BLANK_REASON[c.key] ?? 'Not reported for this resource'
                                    : (c.key === 'cpuAvg' || c.key === 'cpuPeakHour') && r.cpuMax !== null
                                      ? cpuProfile(r)
                                      : c.key === 'memAvg' && r.memPeakHour !== null
                                        ? `busiest hour ${r.memPeakHour.toFixed(1)} %`
                                        : undefined;
                                return (
                                  <TableCell
                                    key={c.key}
                                    align={c.num ? 'right' : 'left'}
                                    title={title}
                                    sx={{
                                      whiteSpace: 'nowrap',
                                      maxWidth: 280,
                                      overflow: 'hidden',
                                      textOverflow: 'ellipsis',
                                      color: text === '' ? 'text.disabled' : lowUtil ? PALETTE.orange : undefined,
                                      fontWeight: lowUtil ? 700 : undefined,
                                    }}
                                  >
                                    {text === '' ? '-' : text}
                                  </TableCell>
                                );
                              })}
                            </TableRow>
                            <TableRow>
                              <TableCell colSpan={columns.length + 1} sx={{ p: 0, borderBottom: open ? undefined : 'none' }}>
                                <Collapse in={open} timeout="auto" unmountOnExit>
                                  <ResourceDetail r={r} suggestions={estate.byResource.get(r.key) || []} />
                                </Collapse>
                              </TableCell>
                            </TableRow>
                          </React.Fragment>
                        );
                      })
                    : (pageRows as Suggestion[]).map((s, i) => {
                        const key = s.findingId || `${s.title}-${i}`;
                        const open = expanded === key;
                        return (
                          <React.Fragment key={key}>
                            <TableRow hover onClick={() => setExpanded(open ? null : key)} sx={{ cursor: 'pointer', '& > td': open ? { borderBottom: 'none' } : undefined }}>
                              <TableCell padding="checkbox">
                                <IconButton size="small" aria-label={open ? 'Collapse suggestion' : 'Expand suggestion'} aria-expanded={open}>
                                  {open ? <KeyboardArrowDown fontSize="small" /> : <KeyboardArrowRight fontSize="small" />}
                                </IconButton>
                              </TableCell>
                              <TableCell>
                                <SevChip severity={s.severity} />
                              </TableCell>
                              <TableCell sx={{ maxWidth: 380 }}>{money.text(s.title)}</TableCell>
                              <TableCell sx={{ fontFamily: 'monospace', fontSize: 12 }}>{s.type}</TableCell>
                              <TableCell>{s.resourceName}</TableCell>
                              <TableCell>{s.typeLabel}</TableCell>
                              <TableCell>{s.subscription}</TableCell>
                              <TableCell align="right">{s.savingsUsd ? money.format(s.savingsUsd) : ''}</TableCell>
                              <TableCell align="right">{s.wave ?? ''}</TableCell>
                            </TableRow>
                            <TableRow>
                              <TableCell colSpan={columns.length + 1} sx={{ p: 0, borderBottom: open ? undefined : 'none' }}>
                                <Collapse in={open} timeout="auto" unmountOnExit>
                                  {s.findingId && <FindingDetailPanel findingId={s.findingId} />}
                                </Collapse>
                              </TableCell>
                            </TableRow>
                          </React.Fragment>
                        );
                      })}
                </TableBody>
              </Table>
            </TableContainer>
          </Card>
        </>
      ) : null}
    </Box>
  );
};

/**
 * FindingsPage — browse, filter, and triage all scanner findings.
 *
 * Matches backend/api/routes/findings.py:
 *   GET  /findings?severity=&status=&category=&search=&page=&page_size=
 *   PATCH /findings/{id}/status
 *   POST /findings/bulk-status
 *
 * Design choice: severity and status filters are multi-select chips
 * rather than dropdowns, since analysts commonly want "critical + high"
 * or "open + acknowledged" simultaneously — a single-select dropdown
 * would force repeated round trips.
 */
import React, { useEffect, useState, useCallback } from 'react';
import {
  Box,
  Card,
  Typography,
  Chip,
  TextField,
  InputAdornment,
  Table,
  TableContainer,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  Checkbox,
  Pagination,
  Button,
  Menu,
  MenuItem,
  Alert,
  Skeleton,
  Select,
  FormControl,
  InputLabel,
  alpha,
} from '@mui/material';
import { Search, MoreVert, FilterAltOff } from '@mui/icons-material';
import { useApi, ApiError } from '../hooks/useApi';
import { useSnackbar } from 'notistack';

interface SubscriptionOption {
  id: string;
  name: string;
  tenant_id: string;
}

interface TenantOption {
  id: string;
  name: string;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['open', 'acknowledged', 'resolved', 'suppressed', 'false_positive'];

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#F44336',
  high: '#FF9800',
  medium: '#FFC107',
  low: '#2196F3',
  info: '#9E9E9E',
};

const STATUS_COLORS: Record<string, string> = {
  open: '#F44336',
  acknowledged: '#FFC107',
  resolved: '#4CAF50',
  suppressed: '#9E9E9E',
  false_positive: '#607D8B',
};

interface FindingItem {
  id: string;
  finding_type: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  resource_name: string | null;
  resource_type: string | null;
  subscription_id: string | null;
  resource_group: string | null;
  estimated_monthly_saving: number | null;
  detected_at: string;
}

export const FindingsPage: React.FC = () => {
  const api = useApi();
  const { enqueueSnackbar } = useSnackbar();

  const [items, setItems] = useState<FindingItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const pageSize = 25;
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [statusFilter, setStatusFilter] = useState<string[]>(['open']);
  const [search, setSearch] = useState('');
  const [subscriptionFilter, setSubscriptionFilter] = useState('');
  const [tenantFilter, setTenantFilter] = useState('');
  const [resourceGroupFilter, setResourceGroupFilter] = useState('');

  const [subscriptionOptions, setSubscriptionOptions] = useState<SubscriptionOption[]>([]);
  const [tenantOptions, setTenantOptions] = useState<TenantOption[]>([]);
  // Resource groups aren't a registered entity with their own endpoint —
  // derived from whatever's actually present across loaded findings,
  // so the dropdown only ever offers groups that genuinely have data.
  const [resourceGroupOptions, setResourceGroupOptions] = useState<string[]>([]);

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkAnchor, setBulkAnchor] = useState<null | HTMLElement>(null);

  const fetchFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      severityFilter.forEach((s) => params.append('severity', s));
      statusFilter.forEach((s) => params.append('status', s));
      if (search) params.set('search', search);
      if (subscriptionFilter) params.set('subscription_id', subscriptionFilter);
      if (tenantFilter) params.set('tenant_id', tenantFilter);
      if (resourceGroupFilter) params.set('resource_group', resourceGroupFilter);
      params.set('page', String(page));
      params.set('page_size', String(pageSize));

      const data = await api.get(`/findings?${params.toString()}`);
      setItems(data.items);
      setTotal(data.total);
      // Build the resource group dropdown's options from whatever's
      // actually present in the unfiltered-by-group result set — keeps
      // it from offering groups that don't exist in the current data.
      if (!resourceGroupFilter) {
        const groups = Array.from(
          new Set(data.items.map((f: FindingItem) => f.resource_group).filter(Boolean))
        ) as string[];
        setResourceGroupOptions((prev) => Array.from(new Set([...prev, ...groups])).sort());
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Failed to load findings');
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [severityFilter, statusFilter, search, subscriptionFilter, tenantFilter, resourceGroupFilter, page]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  useEffect(() => {
    // Subscription/tenant lists are small and don't change while
    // triaging findings — load once on mount rather than refetching
    // alongside every findings query.
    api.get('/subscriptions').then((data) => {
      setSubscriptionOptions(data.map((s: any) => ({ id: s.id, name: s.name, tenant_id: s.tenant_id })));
    }).catch(() => {});
    api.get('/tenants').then((data) => {
      setTenantOptions(data.map((t: any) => ({ id: t.id, name: t.name })));
    }).catch(() => {
      // Listing tenants is admin-only — a non-admin analyst will get a
      // 403 here, which is fine: the tenant filter just won't populate
      // for them, same as it would be empty if there were no tenants.
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const clearFilters = () => {
    setPage(1);
    setSeverityFilter([]);
    setStatusFilter(['open']);
    setSearch('');
    setSubscriptionFilter('');
    setTenantFilter('');
    setResourceGroupFilter('');
  };

  const hasActiveFilters =
    severityFilter.length > 0 ||
    statusFilter.length !== 1 ||
    statusFilter[0] !== 'open' ||
    !!search ||
    !!subscriptionFilter ||
    !!tenantFilter ||
    !!resourceGroupFilter;

  const toggleSeverity = (sev: string) => {
    setPage(1);
    setSeverityFilter((prev) => (prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]));
  };

  const toggleStatus = (status: string) => {
    setPage(1);
    setStatusFilter((prev) => (prev.includes(status) ? prev.filter((s) => s !== status) : [...prev, status]));
  };

  const toggleSelectAll = () => {
    if (selected.size === items.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(items.map((i) => i.id)));
    }
  };

  const toggleSelectOne = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const bulkUpdate = async (status: string) => {
    setBulkAnchor(null);
    try {
      await api.post('/findings/bulk-status', { finding_ids: Array.from(selected), status });
      enqueueSnackbar(`Updated ${selected.size} finding(s) to ${status}`, { variant: 'success' });
      setSelected(new Set());
      fetchFindings();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Bulk update failed', { variant: 'error' });
    }
  };

  const updateSingleStatus = async (id: string, status: string) => {
    try {
      await api.patch(`/findings/${id}/status`, { status });
      enqueueSnackbar('Finding updated', { variant: 'success' });
      fetchFindings();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Update failed', { variant: 'error' });
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2.5 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>
          Findings
        </Typography>
        <Typography variant="body2" sx={{ color: alpha('#fff', 0.5) }}>
          {total.toLocaleString()} total
        </Typography>
      </Box>

      {/* Filters */}
      <Card sx={{ p: 2, mb: 2.5 }}>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
          <Typography variant="caption" sx={{ color: alpha('#fff', 0.5), width: '100%', mb: 0.5 }}>
            Severity
          </Typography>
          {SEVERITIES.map((sev) => (
            <Chip
              key={sev}
              label={sev.toUpperCase()}
              size="small"
              onClick={() => toggleSeverity(sev)}
              sx={{
                fontWeight: 700,
                fontSize: 11,
                cursor: 'pointer',
                bgcolor: severityFilter.includes(sev) ? alpha(SEVERITY_COLORS[sev], 0.25) : alpha('#fff', 0.05),
                color: severityFilter.includes(sev) ? SEVERITY_COLORS[sev] : alpha('#fff', 0.5),
                border: `1px solid ${severityFilter.includes(sev) ? SEVERITY_COLORS[sev] : 'transparent'}`,
              }}
            />
          ))}
        </Box>

        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
          <Typography variant="caption" sx={{ color: alpha('#fff', 0.5), width: '100%', mb: 0.5 }}>
            Status
          </Typography>
          {STATUSES.map((status) => (
            <Chip
              key={status}
              label={status.replace('_', ' ').toUpperCase()}
              size="small"
              onClick={() => toggleStatus(status)}
              sx={{
                fontWeight: 700,
                fontSize: 11,
                cursor: 'pointer',
                bgcolor: statusFilter.includes(status) ? alpha(STATUS_COLORS[status], 0.25) : alpha('#fff', 0.05),
                color: statusFilter.includes(status) ? STATUS_COLORS[status] : alpha('#fff', 0.5),
                border: `1px solid ${statusFilter.includes(status) ? STATUS_COLORS[status] : 'transparent'}`,
              }}
            />
          ))}
        </Box>

        <TextField
          size="small"
          placeholder="Search title, description, resource name…"
          value={search}
          onChange={(e) => {
            setPage(1);
            setSearch(e.target.value);
          }}
          fullWidth
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Search fontSize="small" sx={{ color: alpha('#fff', 0.4) }} />
              </InputAdornment>
            ),
          }}
        />

        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1.5, mt: 2 }}>
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <InputLabel id="sub-filter-label">Subscription</InputLabel>
            <Select
              labelId="sub-filter-label"
              label="Subscription"
              value={subscriptionFilter}
              onChange={(e) => {
                setPage(1);
                setSubscriptionFilter(e.target.value);
              }}
            >
              <MenuItem value="">All subscriptions</MenuItem>
              {subscriptionOptions.map((s) => (
                <MenuItem key={s.id} value={s.id}>
                  {s.name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {tenantOptions.length > 0 && (
            <FormControl size="small" sx={{ minWidth: 180 }}>
              <InputLabel id="tenant-filter-label">Tenant</InputLabel>
              <Select
                labelId="tenant-filter-label"
                label="Tenant"
                value={tenantFilter}
                onChange={(e) => {
                  setPage(1);
                  setTenantFilter(e.target.value);
                }}
              >
                <MenuItem value="">All tenants</MenuItem>
                {tenantOptions.map((t) => (
                  <MenuItem key={t.id} value={t.id}>
                    {t.name}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          )}

          <FormControl size="small" sx={{ minWidth: 180 }}>
            <InputLabel id="rg-filter-label">Resource Group</InputLabel>
            <Select
              labelId="rg-filter-label"
              label="Resource Group"
              value={resourceGroupFilter}
              onChange={(e) => {
                setPage(1);
                setResourceGroupFilter(e.target.value);
              }}
            >
              <MenuItem value="">All resource groups</MenuItem>
              {resourceGroupOptions.map((rg) => (
                <MenuItem key={rg} value={rg}>
                  {rg}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {hasActiveFilters && (
            <Button size="small" startIcon={<FilterAltOff fontSize="small" />} onClick={clearFilters}>
              Clear filters
            </Button>
          )}
        </Box>
      </Card>

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <Card sx={{ p: 1.5, mb: 2, display: 'flex', alignItems: 'center', gap: 2, bgcolor: alpha('#00D4FF', 0.06) }}>
          <Typography variant="body2">{selected.size} selected</Typography>
          <Button size="small" variant="outlined" onClick={(e) => setBulkAnchor(e.currentTarget)} endIcon={<MoreVert />}>
            Bulk action
          </Button>
          <Menu anchorEl={bulkAnchor} open={Boolean(bulkAnchor)} onClose={() => setBulkAnchor(null)}>
            <MenuItem onClick={() => bulkUpdate('acknowledged')}>Acknowledge</MenuItem>
            <MenuItem onClick={() => bulkUpdate('suppressed')}>Suppress</MenuItem>
            <MenuItem onClick={() => bulkUpdate('false_positive')}>Mark false positive</MenuItem>
            <MenuItem onClick={() => bulkUpdate('open')}>Reopen</MenuItem>
          </Menu>
          <Button size="small" onClick={() => setSelected(new Set())} sx={{ ml: 'auto' }}>
            Clear selection
          </Button>
        </Card>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Card>
        {loading ? (
          <Box sx={{ p: 2 }}>
            {Array.from({ length: 8 }).map((_, i) => (
              <Skeleton key={i} height={48} sx={{ bgcolor: alpha('#fff', 0.05) }} />
            ))}
          </Box>
        ) : items.length === 0 ? (
          <Box sx={{ p: 6, textAlign: 'center' }}>
            <Typography variant="body1" sx={{ color: alpha('#fff', 0.5) }}>
              No findings match these filters.
            </Typography>
          </Box>
        ) : (
          <TableContainer sx={{ overflowX: 'auto' }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell padding="checkbox">
                  <Checkbox
                    size="small"
                    checked={selected.size === items.length && items.length > 0}
                    indeterminate={selected.size > 0 && selected.size < items.length}
                    onChange={toggleSelectAll}
                  />
                </TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Title</TableCell>
                <TableCell>Resource</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Savings/mo</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {items.map((f) => (
                <TableRow key={f.id} hover selected={selected.has(f.id)}>
                  <TableCell padding="checkbox">
                    <Checkbox size="small" checked={selected.has(f.id)} onChange={() => toggleSelectOne(f.id)} />
                  </TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      label={f.severity.toUpperCase()}
                      sx={{
                        bgcolor: alpha(SEVERITY_COLORS[f.severity] ?? '#9E9E9E', 0.15),
                        color: SEVERITY_COLORS[f.severity] ?? '#9E9E9E',
                        fontWeight: 700,
                        fontSize: 11,
                      }}
                    />
                  </TableCell>
                  <TableCell sx={{ maxWidth: 320 }}>
                    <Typography variant="body2" noWrap>
                      {f.title}
                    </Typography>
                  </TableCell>
                  <TableCell sx={{ color: alpha('#fff', 0.6) }}>{f.resource_name ?? '—'}</TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      label={f.status.replace('_', ' ')}
                      sx={{
                        bgcolor: alpha(STATUS_COLORS[f.status] ?? '#9E9E9E', 0.15),
                        color: STATUS_COLORS[f.status] ?? '#9E9E9E',
                        fontSize: 11,
                      }}
                    />
                  </TableCell>
                  <TableCell align="right">
                    {f.estimated_monthly_saving ? `$${f.estimated_monthly_saving.toFixed(2)}` : '—'}
                  </TableCell>
                  <TableCell align="right">
                    {f.status === 'open' ? (
                      <Button size="small" onClick={() => updateSingleStatus(f.id, 'acknowledged')}>
                        Acknowledge
                      </Button>
                    ) : (
                      <Button size="small" onClick={() => updateSingleStatus(f.id, 'open')}>
                        Reopen
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          </TableContainer>
        )}
      </Card>

      {totalPages > 1 && (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2.5 }}>
          <Pagination count={totalPages} page={page} onChange={(_, p) => setPage(p)} color="primary" />
        </Box>
      )}
    </Box>
  );
};

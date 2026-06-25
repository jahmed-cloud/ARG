/**
 * DriftPage — Terraform drift detection dashboard.
 *
 * Matches backend/api/routes/drift.py:
 *   GET /drift/stats    -> aggregate counts summed across imported state files
 *   GET /drift/findings -> per-resource drift findings (category='terraform'
 *                          Finding rows, persisted the same way as every
 *                          other scanner's output)
 */
import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Skeleton,
  Alert,
  Chip,
  Table,
  TableContainer,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  Pagination,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  FormHelperText,
  IconButton,
  Tooltip,
  alpha,
} from '@mui/material';
import { UploadFile, DeleteOutline } from '@mui/icons-material';
import { useApi, ApiError } from '../hooks/useApi';
import { useSnackbar } from 'notistack';

interface StateFileItem {
  id: string;
  subscription_id: string;
  workspace_name: string;
  resource_count: number;
  managed_count: number;
  unmanaged_count: number;
  missing_count: number;
  last_drift_check: string | null;
  imported_at: string;
}

interface DriftStats {
  total_resources: number;
  managed: number;
  unmanaged: number;
  missing: number;
  drifted: number;
  state_files_imported: number;
}

interface DriftFinding {
  id: string;
  finding_type: string;
  severity: string;
  status: string;
  title: string;
  resource_name: string | null;
  resource_type: string | null;
  azure_resource_id: string | null;
  recommendation: string | null;
  detected_at: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#F44336',
  high: '#FF9800',
  medium: '#FFC107',
  low: '#2196F3',
  info: '#9E9E9E',
};

const FINDING_TYPE_FILTERS = [
  { value: '', label: 'All' },
  { value: 'terraform_unmanaged_resource', label: 'Unmanaged' },
  { value: 'terraform_missing_resource', label: 'Missing' },
];

interface SubscriptionOption {
  id: string;
  name: string;
}

export const DriftPage: React.FC = () => {
  const api = useApi();
  const { enqueueSnackbar } = useSnackbar();
  const [stats, setStats] = useState<DriftStats | null>(null);
  const [findings, setFindings] = useState<DriftFinding[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [typeFilter, setTypeFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [importOpen, setImportOpen] = useState(false);
  const [subscriptions, setSubscriptions] = useState<SubscriptionOption[]>([]);
  const [selectedSubId, setSelectedSubId] = useState('');
  const [workspaceName, setWorkspaceName] = useState('default');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [importing, setImporting] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [stateFiles, setStateFiles] = useState<StateFileItem[]>([]);
  const [deleteTarget, setDeleteTarget] = useState<StateFileItem | null>(null);
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    // Don't clear a previously-successful error-free state just because
    // this refresh is starting — only set a new error if this refresh
    // itself genuinely fails. Previously setError(null) here combined
    // with `if (error || !stats) return <Alert>` below meant a single
    // transient failure in any one of the three parallel requests wiped
    // out the entire page, even right after an action (like deleting a
    // state file) had already succeeded and the page had a perfectly
    // good previous state to keep showing.
    try {
      const params = new URLSearchParams({ page: String(page), page_size: '25' });
      if (typeFilter) params.set('finding_type', typeFilter);

      // Each request can fail independently — a state-files hiccup
      // shouldn't discard stats/findings that loaded fine, and vice
      // versa. allSettled means one bad response degrades gracefully
      // instead of taking the whole page down.
      const [statsResult, findingsResult, stateFilesResult] = await Promise.allSettled([
        api.get('/drift/stats'),
        api.get(`/drift/findings?${params.toString()}`),
        api.get('/drift/state-files'),
      ]);

      if (statsResult.status === 'fulfilled') {
        setStats(statsResult.value);
        setError(null);
      } else if (!stats) {
        // Only surface a hard error if we have no stats to show at all —
        // if we already had data on screen, keep showing it rather than
        // replacing a working page with an error box over one failed
        // refresh.
        setError(statsResult.reason instanceof ApiError ? statsResult.reason.message : 'Failed to load drift data');
      }
      if (findingsResult.status === 'fulfilled') {
        setFindings(findingsResult.value.items);
        setTotal(findingsResult.value.total);
      }
      if (stateFilesResult.status === 'fulfilled') {
        setStateFiles(stateFilesResult.value.items);
      } else {
        enqueueSnackbar('Could not refresh the state files list — try Refresh again.', { variant: 'warning' });
      }
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, typeFilter]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    api.get('/subscriptions')
      .then((subs) => setSubscriptions(subs.map((s: any) => ({ id: s.id, name: s.name }))))
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleDeleteStateFile = async () => {
    if (!deleteTarget || deleting) return;
    setDeleting(true);
    try {
      await api.del(`/drift/state-files/${deleteTarget.id}`);
      enqueueSnackbar('State file removed', { variant: 'success' });
      setDeleteTarget(null);
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to remove state file', { variant: 'error' });
    } finally {
      setDeleting(false);
    }
  };

  const openImportDialog = async () => {
    setImportOpen(true);
    try {
      const subs = await api.get('/subscriptions');
      setSubscriptions(subs.map((s: any) => ({ id: s.id, name: s.name })));
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to load subscriptions', { variant: 'error' });
    }
  };

  const handleImport = async () => {
    if (!selectedSubId) {
      enqueueSnackbar('Select a subscription', { variant: 'warning' });
      return;
    }
    if (!workspaceName.trim()) {
      enqueueSnackbar('Workspace name is required', { variant: 'warning' });
      return;
    }
    if (!selectedFile) {
      enqueueSnackbar('Choose a Terraform state file (.tfstate or .json)', { variant: 'warning' });
      return;
    }

    setImporting(true);
    try {
      const formData = new FormData();
      formData.append('subscription_id', selectedSubId);
      formData.append('workspace_name', workspaceName.trim());
      formData.append('file', selectedFile);

      const res = await fetch(`${api.baseUrl}/drift/import`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${api.accessToken}` },
        body: formData,
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new ApiError(body.detail ?? `Import failed (${res.status})`, res.status);
      }

      const result = await res.json();
      enqueueSnackbar(
        `Imported ${result.resource_count} resource instance(s). Run a new scan to detect drift.`,
        { variant: 'success', autoHideDuration: 8000 }
      );
      setImportOpen(false);
      setSelectedFile(null);
      setWorkspaceName('default');
      setSelectedSubId('');
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to import state file', { variant: 'error' });
    } finally {
      setImporting(false);
    }
  };

  if (loading && !stats) {
    return (
      <Grid container spacing={2.5}>
        {Array.from({ length: 4 }).map((_, i) => (
          <Grid item xs={12} sm={6} md={3} key={i}>
            <Skeleton variant="rounded" height={110} sx={{ bgcolor: alpha('#fff', 0.05) }} />
          </Grid>
        ))}
      </Grid>
    );
  }

  if (error || !stats) {
    return <Alert severity="error">{error ?? 'No drift data available'}</Alert>;
  }

  const totalPages = Math.max(1, Math.ceil(total / 25));

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2.5 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>
          Terraform Drift
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Typography variant="caption" sx={{ color: alpha('#fff', 0.4) }}>
            {stats.state_files_imported} state file{stats.state_files_imported === 1 ? '' : 's'} imported
          </Typography>
          <Button
            variant="contained"
            size="small"
            startIcon={<UploadFile />}
            onClick={openImportDialog}
            sx={{ background: 'linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)', fontWeight: 700 }}
          >
            Import State File
          </Button>
        </Box>
      </Box>

      <Grid container spacing={2.5} sx={{ mb: 2.5 }}>
        <Grid item xs={6} sm={3}>
          <Card>
            <CardContent>
              <Typography variant="h4" sx={{ fontWeight: 800, color: '#4CAF50' }}>
                {stats.managed}
              </Typography>
              <Typography variant="caption" sx={{ color: alpha('#fff', 0.5) }}>
                Managed
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} sm={3}>
          <Card>
            <CardContent>
              <Typography variant="h4" sx={{ fontWeight: 800, color: '#FF9800' }}>
                {stats.unmanaged}
              </Typography>
              <Typography variant="caption" sx={{ color: alpha('#fff', 0.5) }}>
                Unmanaged
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} sm={3}>
          <Card>
            <CardContent>
              <Typography variant="h4" sx={{ fontWeight: 800, color: '#F44336' }}>
                {stats.missing}
              </Typography>
              <Typography variant="caption" sx={{ color: alpha('#fff', 0.5) }}>
                Missing
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} sm={3}>
          <Card>
            <CardContent>
              <Typography variant="h4" sx={{ fontWeight: 800, color: '#FFC107' }}>
                {stats.drifted}
              </Typography>
              <Typography variant="caption" sx={{ color: alpha('#fff', 0.5) }}>
                Drifted
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {stateFiles.length > 0 && (
        <Card sx={{ mb: 2.5 }}>
          <CardContent>
            <Typography variant="subtitle2" sx={{ mb: 1.5, color: alpha('#fff', 0.7) }}>
              Imported State Files
            </Typography>
            <TableContainer sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Subscription</TableCell>
                  <TableCell>Workspace</TableCell>
                  <TableCell align="right">Resources</TableCell>
                  <TableCell align="right">Managed</TableCell>
                  <TableCell align="right">Unmanaged</TableCell>
                  <TableCell align="right">Missing</TableCell>
                  <TableCell>Last Checked</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {stateFiles.map((sf) => {
                  const subName = subscriptions.find((s) => s.id === sf.subscription_id)?.name ?? sf.subscription_id;
                  return (
                    <TableRow key={sf.id} hover>
                      <TableCell>{subName}</TableCell>
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: 12, color: alpha('#fff', 0.6) }}>
                        {sf.workspace_name}
                      </TableCell>
                      <TableCell align="right">{sf.resource_count}</TableCell>
                      <TableCell align="right" sx={{ color: '#4CAF50' }}>{sf.managed_count}</TableCell>
                      <TableCell align="right" sx={{ color: '#FF9800' }}>{sf.unmanaged_count}</TableCell>
                      <TableCell align="right" sx={{ color: '#F44336' }}>{sf.missing_count}</TableCell>
                      <TableCell sx={{ color: alpha('#fff', 0.5), fontSize: 12 }}>
                        {sf.last_drift_check ? new Date(sf.last_drift_check).toLocaleString() : 'Not yet scanned'}
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title="Remove this state file">
                          <IconButton size="small" onClick={() => setDeleteTarget(sf)} sx={{ color: alpha('#F44336', 0.8) }}>
                            <DeleteOutline fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            </TableContainer>
          </CardContent>
        </Card>
      )}

      <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
        {FINDING_TYPE_FILTERS.map((f) => (
          <Chip
            key={f.value}
            label={f.label}
            size="small"
            onClick={() => {
              setPage(1);
              setTypeFilter(f.value);
            }}
            sx={{
              fontWeight: 700,
              fontSize: 11,
              cursor: 'pointer',
              bgcolor: typeFilter === f.value ? alpha('#00D4FF', 0.2) : alpha('#fff', 0.05),
              color: typeFilter === f.value ? '#00D4FF' : alpha('#fff', 0.5),
              border: `1px solid ${typeFilter === f.value ? '#00D4FF' : 'transparent'}`,
            }}
          />
        ))}
      </Box>

      <Card>
        <CardContent>
          {stats.state_files_imported === 0 ? (
            <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), py: 3, textAlign: 'center' }}>
              No Terraform state files imported yet. Upload a state file to enable drift detection.
            </Typography>
          ) : findings.length === 0 ? (
            <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), py: 3, textAlign: 'center' }}>
              No drift findings match this filter.
            </Typography>
          ) : (
            <TableContainer sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Severity</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Resource</TableCell>
                  <TableCell>Azure Resource ID</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {findings.map((f) => (
                  <TableRow key={f.id} hover>
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
                    <TableCell sx={{ color: alpha('#fff', 0.6) }}>
                      {f.finding_type === 'terraform_unmanaged_resource' ? 'Unmanaged' : 'Missing'}
                    </TableCell>
                    <TableCell>{f.resource_name ?? '—'}</TableCell>
                    <TableCell sx={{ maxWidth: 360 }}>
                      <Typography variant="body2" noWrap sx={{ fontFamily: 'monospace', fontSize: 12 }}>
                        {f.azure_resource_id ?? '—'}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

      {totalPages > 1 && (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2.5 }}>
          <Pagination count={totalPages} page={page} onChange={(_, p) => setPage(p)} color="primary" />
        </Box>
      )}

      <Dialog open={importOpen} onClose={() => setImportOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Import Terraform State</DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mb: 2 }}>
            Upload the JSON output of <code>terraform show -json</code>, or your raw{' '}
            <code>terraform.tfstate</code> file. Re-importing the same subscription and workspace
            overwrites the previous import.
          </Alert>

          <FormControl fullWidth sx={{ mb: 2 }}>
            <InputLabel id="drift-sub-label">Subscription</InputLabel>
            <Select
              labelId="drift-sub-label"
              label="Subscription"
              value={selectedSubId}
              onChange={(e) => setSelectedSubId(e.target.value)}
            >
              {subscriptions.map((s) => (
                <MenuItem key={s.id} value={s.id}>
                  {s.name}
                </MenuItem>
              ))}
            </Select>
            {subscriptions.length === 0 && (
              <FormHelperText>No subscriptions registered yet — add one under Subscriptions first.</FormHelperText>
            )}
          </FormControl>

          <TextField
            label="Workspace Name"
            fullWidth
            value={workspaceName}
            onChange={(e) => setWorkspaceName(e.target.value)}
            helperText="Matches your Terraform workspace — use 'default' if you don't use named workspaces."
            sx={{ mb: 2 }}
          />

          <Button
            variant="outlined"
            component="label"
            startIcon={<UploadFile />}
            fullWidth
            sx={{ py: 1.5 }}
          >
            {selectedFile ? selectedFile.name : 'Choose State File (.tfstate or .json)'}
            <input
              ref={fileInputRef}
              type="file"
              hidden
              accept=".json,.tfstate"
              onChange={(e) => setSelectedFile(e.target.files?.[0] ?? null)}
            />
          </Button>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setImportOpen(false)}>Cancel</Button>
          <Button onClick={handleImport} variant="contained" disabled={importing}>
            {importing ? 'Importing…' : 'Import'}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={!!deleteTarget} onClose={() => setDeleteTarget(null)} maxWidth="xs" fullWidth>
        <DialogTitle>Remove state file?</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 1.5 }}>
            This only removes the imported state from ARG — it doesn't touch your actual
            Terraform state or Azure resources.
          </Alert>
          {deleteTarget && (
            <Typography variant="body2" sx={{ color: alpha('#fff', 0.7) }}>
              Remove the <strong>{deleteTarget.workspace_name}</strong> workspace state file?
              Drift detection for this subscription will report "no state imported" until you
              upload a new one.
            </Typography>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteTarget(null)} disabled={deleting}>
            Cancel
          </Button>
          <Button onClick={handleDeleteStateFile} color="error" variant="contained" disabled={deleting}>
            {deleting ? 'Removing…' : 'Remove'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

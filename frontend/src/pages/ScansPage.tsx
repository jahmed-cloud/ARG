/**
 * ScansPage — trigger and monitor scan jobs.
 *
 * Matches backend/api/routes/scans.py:
 *   POST /scans/start { scope: { subscription_ids, resource_groups, scanners }, description }
 *   GET  /scans -> ScanListResponse
 *   GET  /scans/{id}
 *   POST /scans/{id}/cancel
 */
import React, { useEffect, useState, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Chip,
  Table,
  TableContainer,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  Alert,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Checkbox,
  FormControlLabel,
  FormGroup,
  Divider,
  alpha,
} from '@mui/material';
import { PlayArrow, Cancel, Refresh, WarningAmber } from '@mui/icons-material';
import { useApi, ApiError } from '../hooks/useApi';
import { useSnackbar } from 'notistack';

interface SubscriptionOption {
  id: string;
  name: string;
  azure_subscription_id: string;
}

interface ScanJob {
  id: string;
  status: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  total_resources_scanned: number;
  total_findings: number;
  findings_by_severity: Record<string, number>;
  scanners_requested: string[];
  error_message: string | null;
}

const STATUS_COLORS: Record<string, string> = {
  pending: '#9E9E9E',
  running: '#00D4FF',
  completed: '#4CAF50',
  failed: '#F44336',
  cancelled: '#FF9800',
};

export const ScansPage: React.FC = () => {
  const api = useApi();
  const { enqueueSnackbar } = useSnackbar();
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [scanDialogOpen, setScanDialogOpen] = useState(false);
  const [subscriptions, setSubscriptions] = useState<SubscriptionOption[]>([]);
  const [subscriptionsLoading, setSubscriptionsLoading] = useState(false);
  const [selectedSubIds, setSelectedSubIds] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.get('/scans?page=1&page_size=50');
      setScans(data.items);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Failed to load scans');
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const hasActiveScan = scans.some((s) => s.status === 'pending' || s.status === 'running');

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    // Poll faster while a scan is actually in flight, so the status
    // catches up within a couple seconds instead of a fixed 10s window —
    // a scan that completes in 5-7s (typical for this app) was
    // previously stuck showing a stale PENDING/RUNNING row for up to
    // 10s with zero visual feedback, which reasonably read as "stuck."
    // Falls back to a slower idle cadence once nothing is active.
    const intervalMs = hasActiveScan ? 2000 : 10000;
    const interval = setInterval(load, intervalMs);
    return () => clearInterval(interval);
  }, [load, hasActiveScan]);

  const openScanDialog = async () => {
    setScanDialogOpen(true);
    setSubscriptionsLoading(true);
    try {
      const data = await api.get('/subscriptions');
      const subs: SubscriptionOption[] = data.map((s: any) => ({
        id: s.id,
        name: s.name,
        azure_subscription_id: s.azure_subscription_id,
      }));
      setSubscriptions(subs);
      // Default to all selected — most people scanning with only one or
      // two subscriptions registered just want to hit "Start Scan"
      // immediately; unchecking specific ones is the exception, not
      // the common case.
      setSelectedSubIds(new Set(subs.map((s) => s.azure_subscription_id)));
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to load subscriptions', { variant: 'error' });
    } finally {
      setSubscriptionsLoading(false);
    }
  };

  const toggleSub = (azureSubId: string) => {
    setSelectedSubIds((prev) => {
      const next = new Set(prev);
      if (next.has(azureSubId)) next.delete(azureSubId);
      else next.add(azureSubId);
      return next;
    });
  };

  const handleStartScan = async () => {
    if (subscriptions.length > 0 && selectedSubIds.size === 0) {
      enqueueSnackbar('Select at least one subscription to scan', { variant: 'warning' });
      return;
    }
    setStarting(true);
    try {
      // Empty subscriptions list (no subscriptions registered at all)
      // still sends subscription_ids: [] — the backend correctly
      // interprets that as "scan all active subscriptions," which in
      // that case is zero, and will fail with a clear "no active
      // subscriptions" error rather than silently doing nothing.
      const allSelected = subscriptions.length > 0 && selectedSubIds.size === subscriptions.length;
      await api.post('/scans/start', {
        scope: {
          subscription_ids: allSelected ? [] : Array.from(selectedSubIds),
          resource_groups: [],
          scanners: ['all'],
        },
        description: 'Manual scan triggered from Scans page',
      });
      enqueueSnackbar('Scan started', { variant: 'success' });
      setScanDialogOpen(false);
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to start scan', { variant: 'error' });
    } finally {
      setStarting(false);
    }
  };

  const handleCancel = async (id: string) => {
    try {
      await api.post(`/scans/${id}/cancel`);
      enqueueSnackbar('Scan cancelled', { variant: 'success' });
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to cancel scan', { variant: 'error' });
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Scans
          </Typography>
          {hasActiveScan && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
              <Box
                sx={{
                  width: 7,
                  height: 7,
                  borderRadius: '50%',
                  bgcolor: '#00D4FF',
                  animation: 'pulse 1.4s ease-in-out infinite',
                  '@keyframes pulse': {
                    '0%, 100%': { opacity: 1, transform: 'scale(1)' },
                    '50%': { opacity: 0.4, transform: 'scale(0.7)' },
                  },
                }}
              />
              <Typography variant="caption" sx={{ color: '#00D4FF', fontWeight: 600 }}>
                Live — updating every 2s
              </Typography>
            </Box>
          )}
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button startIcon={<Refresh />} onClick={load} size="small">
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<PlayArrow />}
            onClick={openScanDialog}
            sx={{ background: 'linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)', fontWeight: 700 }}
          >
            Start a Scan
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Card>
        <CardContent>
          {!loading && scans.length === 0 ? (
            <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), py: 4, textAlign: 'center' }}>
              No scans have been run yet. Start your first scan to discover findings.
            </Typography>
          ) : (
            <TableContainer sx={{ overflowX: 'auto' }}>
              <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Status</TableCell>
                  <TableCell>Started</TableCell>
                  <TableCell>Duration</TableCell>
                  <TableCell align="right">Resources Scanned</TableCell>
                  <TableCell align="right">Findings</TableCell>
                  <TableCell>Scanners</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {scans.map((s) => (
                  <TableRow key={s.id} hover>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                        <Chip
                          size="small"
                          label={s.status.toUpperCase()}
                          sx={{
                            bgcolor: alpha(STATUS_COLORS[s.status] ?? '#9E9E9E', 0.15),
                            color: STATUS_COLORS[s.status] ?? '#9E9E9E',
                            fontWeight: 700,
                            fontSize: 11,
                          }}
                        />
                        {s.error_message && (
                          <Tooltip title={s.error_message} arrow>
                            <WarningAmber sx={{ fontSize: 16, color: '#FF9800', cursor: 'help' }} />
                          </Tooltip>
                        )}
                      </Box>
                    </TableCell>
                    <TableCell sx={{ color: alpha('#fff', 0.6) }}>
                      {s.started_at ? new Date(s.started_at).toLocaleString() : '—'}
                    </TableCell>
                    <TableCell sx={{ color: alpha('#fff', 0.6) }}>
                      {s.duration_seconds ? `${s.duration_seconds}s` : '—'}
                    </TableCell>
                    <TableCell align="right">{s.total_resources_scanned.toLocaleString()}</TableCell>
                    <TableCell align="right">{s.total_findings.toLocaleString()}</TableCell>
                    <TableCell sx={{ color: alpha('#fff', 0.6) }}>
                      {s.scanners_requested.join(', ')}
                    </TableCell>
                    <TableCell align="right">
                      {(s.status === 'pending' || s.status === 'running') && (
                        <Button
                          size="small"
                          color="error"
                          startIcon={<Cancel />}
                          onClick={() => handleCancel(s.id)}
                        >
                          Cancel
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

      <Dialog open={scanDialogOpen} onClose={() => setScanDialogOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Start a Scan</DialogTitle>
        <DialogContent>
          {subscriptionsLoading ? (
            <Typography variant="body2" sx={{ color: alpha('#fff', 0.5), py: 2 }}>
              Loading subscriptions…
            </Typography>
          ) : subscriptions.length === 0 ? (
            <Alert severity="info">
              No subscriptions registered yet. Go to{' '}
              <strong>Subscriptions</strong> to register one before scanning.
            </Alert>
          ) : (
            <>
              <Typography variant="body2" sx={{ color: alpha('#fff', 0.6), mb: 1.5 }}>
                Choose which subscription(s) to scan:
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, mb: 1 }}>
                <Button
                  size="small"
                  onClick={() => setSelectedSubIds(new Set(subscriptions.map((s) => s.azure_subscription_id)))}
                >
                  Select all
                </Button>
                <Button size="small" onClick={() => setSelectedSubIds(new Set())}>
                  Select none
                </Button>
              </Box>
              <Divider sx={{ mb: 1, borderColor: alpha('#fff', 0.08) }} />
              <FormGroup>
                {subscriptions.map((s) => (
                  <FormControlLabel
                    key={s.id}
                    control={
                      <Checkbox
                        checked={selectedSubIds.has(s.azure_subscription_id)}
                        onChange={() => toggleSub(s.azure_subscription_id)}
                        size="small"
                      />
                    }
                    label={
                      <Box>
                        <Typography variant="body2">{s.name}</Typography>
                        <Typography variant="caption" sx={{ color: alpha('#fff', 0.4), fontFamily: 'monospace' }}>
                          {s.azure_subscription_id}
                        </Typography>
                      </Box>
                    }
                  />
                ))}
              </FormGroup>
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setScanDialogOpen(false)} disabled={starting}>
            Cancel
          </Button>
          <Button
            onClick={handleStartScan}
            variant="contained"
            disabled={starting || subscriptionsLoading || subscriptions.length === 0}
            sx={{ background: 'linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)', fontWeight: 700 }}
          >
            {starting ? 'Starting…' : `Start Scan${selectedSubIds.size > 0 ? ` (${selectedSubIds.size})` : ''}`}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

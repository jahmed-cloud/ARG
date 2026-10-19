/**
 * ResetFindingsPanel - admins delete every finding and estate snapshot (POST /findings/reset) so the next scan
 * regenerates them with the current scanners and settings. Confirmation is typed inline (RESET); the API writes
 * the audit log. Subscriptions, tenants, inventory and settings are kept.
 */
import React, { useState } from 'react';
import { Box, Button, Card, CardContent, TextField, Typography, alpha } from '@mui/material';
import { useSnackbar } from 'notistack';
import { useApi, ApiError } from '../../hooks/useApi';

export const ResetFindingsPanel: React.FC = () => {
  const api = useApi();
  const { enqueueSnackbar } = useSnackbar();
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ findings_deleted: number; estate_snapshots_deleted: number } | null>(null);

  const reset = async () => {
    setBusy(true);
    try {
      const r = await api.post('/findings/reset', { confirm });
      setResult(r);
      setConfirm('');
      enqueueSnackbar(`Deleted ${r.findings_deleted} findings - start a scan to regenerate them`, { variant: 'success' });
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Reset failed', { variant: 'error' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card sx={{ mb: 3, borderLeft: '3px solid #ee8278' }}>
      <CardContent>
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5 }}>Reset findings</Typography>
        <Typography variant="body2" sx={{ color: alpha('#fff', 0.55), mb: 2, maxWidth: 760 }}>
          Deletes every finding with its recommendations and remediation tasks, and the estate snapshots, so the next
          scan regenerates them with the current scanners and settings. Subscriptions, tenants, inventory and settings
          stay. This cannot be undone.
        </Typography>
        <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'center', flexWrap: 'wrap' }}>
          <TextField size="small" value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="Type RESET"
            inputProps={{ 'aria-label': 'Type RESET to confirm' }} sx={{ width: 180 }} />
          <Button variant="outlined" color="error" disabled={confirm !== 'RESET' || busy} onClick={reset}>
            {busy ? 'Resetting…' : 'Reset findings'}
          </Button>
          {result && (
            <Typography variant="caption" sx={{ color: alpha('#fff', 0.55) }}>
              {result.findings_deleted} findings and {result.estate_snapshots_deleted} estate snapshots deleted.
            </Typography>
          )}
        </Box>
      </CardContent>
    </Card>
  );
};

/**
 * ResetFindingsCard — admins delete every finding and estate snapshot (POST /findings/reset) so the next scan
 * regenerates them with the current scanners and settings. Requires typing RESET; written to the audit log.
 */
import React, { useState } from 'react';
import {
  Alert, Box, Button, Card, CardContent, Dialog, DialogActions, DialogContent, DialogTitle, TextField,
  Typography, alpha,
} from '@mui/material';
import { DeleteForever } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useSnackbar } from 'notistack';
import { useApi, ApiError } from '../../hooks/useApi';

export const ResetFindingsCard: React.FC = () => {
  const api = useApi();
  const navigate = useNavigate();
  const { enqueueSnackbar } = useSnackbar();
  const [open, setOpen] = useState(false);
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<{ findings_deleted: number; estate_snapshots_deleted: number } | null>(null);

  const reset = async () => {
    setBusy(true);
    try {
      const result = await api.post('/findings/reset', { confirm });
      setDone(result);
      setOpen(false);
      setConfirm('');
      enqueueSnackbar(`Deleted ${result.findings_deleted} findings - start a scan to regenerate them`, { variant: 'success' });
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Reset failed', { variant: 'error' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card sx={{ mb: 3, borderColor: alpha('#f44336', 0.4) }} variant="outlined">
      <CardContent>
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5 }}>
          Reset findings
        </Typography>
        <Typography variant="body2" sx={{ color: alpha('#fff', 0.55), mb: 2 }}>
          Deletes every finding (with its recommendations and remediation tasks) and the Estate snapshots built from
          them, so the next scan regenerates everything with the current scanners and Analysis Settings.
          Subscriptions, tenants, inventory, users and settings are kept. Acknowledged, suppressed and false-positive
          states are lost.
        </Typography>
        {done && (
          <Alert severity="success" sx={{ mb: 2 }}
            action={<Button color="inherit" size="small" onClick={() => navigate('/scans', { state: { startScan: true } })}>Start a scan</Button>}>
            Deleted {done.findings_deleted} findings and {done.estate_snapshots_deleted} estate snapshots.
          </Alert>
        )}
        <Button variant="outlined" color="error" startIcon={<DeleteForever />} onClick={() => setOpen(true)}>
          Reset findings…
        </Button>
      </CardContent>
      <Dialog open={open} onClose={() => !busy && setOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Delete all findings?</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 2 }}>
            This cannot be undone. Type <b>RESET</b> to confirm.
          </Typography>
          <Box>
            <TextField autoFocus fullWidth size="small" value={confirm} onChange={(e) => setConfirm(e.target.value)}
              placeholder="RESET" inputProps={{ 'aria-label': 'Type RESET to confirm' }} />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)} disabled={busy}>Cancel</Button>
          <Button color="error" variant="contained" disabled={confirm !== 'RESET' || busy} onClick={reset}>
            {busy ? 'Deleting…' : 'Delete all findings'}
          </Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
};

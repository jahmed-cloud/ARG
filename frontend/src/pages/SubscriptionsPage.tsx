/**
 * SubscriptionsPage — manage registered Azure subscriptions and tenants.
 *
 * Matches backend/api/routes/subscriptions.py:
 *   GET  /subscriptions
 *   POST /subscriptions { name, azure_subscription_id, tenant_id }
 *   DELETE /subscriptions/{id}
 *
 * Tenant creation (backend/api/routes/tenants.py) is intentionally
 * left for the Settings page since it involves secret entry — keeping
 * credential handling in one place reduces the chance of accidental
 * exposure in browser history / autofill across multiple forms.
 */
import React, { useEffect, useState, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Table,
  TableContainer,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  Chip,
  IconButton,
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
  Alert,
  alpha,
} from '@mui/material';
import { Add, Delete, CloudQueue } from '@mui/icons-material';
import { useApi, ApiError } from '../hooks/useApi';
import { useSnackbar } from 'notistack';

interface SubscriptionItem {
  id: string;
  name: string;
  azure_subscription_id: string;
  tenant_id: string;
  state: string;
  last_scanned_at: string | null;
}

interface TenantOption {
  id: string;
  name: string;
  azure_tenant_id: string;
}

export const SubscriptionsPage: React.FC = () => {
  const api = useApi();
  const { enqueueSnackbar } = useSnackbar();
  const [subscriptions, setSubscriptions] = useState<SubscriptionItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [dialogOpen, setDialogOpen] = useState(false);
  const [name, setName] = useState('');
  const [azureSubId, setAzureSubId] = useState('');
  const [tenantId, setTenantId] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const [tenants, setTenants] = useState<TenantOption[]>([]);
  const [tenantsLoading, setTenantsLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.get('/subscriptions');
      setSubscriptions(data);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Failed to load subscriptions');
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleCreate = async () => {
    if (!name || !azureSubId || !tenantId) {
      enqueueSnackbar('All fields are required', { variant: 'warning' });
      return;
    }
    setSubmitting(true);
    try {
      await api.post('/subscriptions', {
        name,
        azure_subscription_id: azureSubId,
        tenant_id: tenantId,
      });
      enqueueSnackbar('Subscription registered', { variant: 'success' });
      setDialogOpen(false);
      setName('');
      setAzureSubId('');
      setTenantId('');
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to register subscription', { variant: 'error' });
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.del(`/subscriptions/${id}`);
      enqueueSnackbar('Subscription removed', { variant: 'success' });
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to remove subscription', { variant: 'error' });
    }
  };

  const openDialog = async () => {
    setDialogOpen(true);
    setTenantsLoading(true);
    try {
      const data = await api.get('/tenants');
      setTenants(data);
    } catch (e) {
      // Registering a subscription already requires admin, same as listing
      // tenants, so a failure here is almost always "no tenants exist yet"
      // surfacing as an empty list from the backend rather than an auth
      // error — but show something actionable either way.
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to load tenants', { variant: 'error' });
    } finally {
      setTenantsLoading(false);
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2.5 }}>
        <Typography variant="h5" sx={{ fontWeight: 700 }}>
          Subscriptions
        </Typography>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={openDialog}
          sx={{ background: 'linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)', fontWeight: 700 }}
        >
          Register Subscription
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Card>
        <CardContent>
          {!loading && subscriptions.length === 0 ? (
            <Box sx={{ py: 6, textAlign: 'center' }}>
              <CloudQueue sx={{ fontSize: 40, color: alpha('#fff', 0.2), mb: 1 }} />
              <Typography variant="body2" sx={{ color: alpha('#fff', 0.4) }}>
                No subscriptions registered yet. Register one to start scanning.
              </Typography>
            </Box>
          ) : (
            <TableContainer sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Azure Subscription ID</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Last Scanned</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {subscriptions.map((s) => (
                  <TableRow key={s.id} hover>
                    <TableCell>{s.name}</TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: 12, color: alpha('#fff', 0.6) }}>
                      {s.azure_subscription_id}
                    </TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={s.state}
                        sx={{
                          bgcolor: alpha(s.state === 'Enabled' ? '#4CAF50' : '#9E9E9E', 0.15),
                          color: s.state === 'Enabled' ? '#4CAF50' : '#9E9E9E',
                          fontSize: 11,
                        }}
                      />
                    </TableCell>
                    <TableCell sx={{ color: alpha('#fff', 0.6) }}>
                      {s.last_scanned_at ? new Date(s.last_scanned_at).toLocaleString() : 'Never'}
                    </TableCell>
                    <TableCell align="right">
                      <IconButton size="small" onClick={() => handleDelete(s.id)} sx={{ color: alpha('#F44336', 0.8) }}>
                        <Delete fontSize="small" />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Register Subscription</DialogTitle>
        <DialogContent>
          <TextField
            label="Display Name"
            fullWidth
            value={name}
            onChange={(e) => setName(e.target.value)}
            sx={{ mt: 1, mb: 2 }}
          />
          <TextField
            label="Azure Subscription ID"
            fullWidth
            value={azureSubId}
            onChange={(e) => setAzureSubId(e.target.value)}
            placeholder="00000000-0000-0000-0000-000000000000"
            sx={{ mb: 2 }}
          />
          <FormControl fullWidth error={!tenantsLoading && tenants.length === 0}>
            <InputLabel id="tenant-select-label">Azure Tenant</InputLabel>
            <Select
              labelId="tenant-select-label"
              label="Azure Tenant"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              disabled={tenantsLoading || tenants.length === 0}
            >
              {tenants.map((t) => (
                <MenuItem key={t.id} value={t.id}>
                  {t.name} ({t.azure_tenant_id})
                </MenuItem>
              ))}
            </Select>
            <FormHelperText>
              {tenantsLoading
                ? 'Loading registered tenants…'
                : tenants.length === 0
                ? 'No tenants registered yet — go to Settings and register one first, then come back here.'
                : 'Select the Azure AD tenant this subscription belongs to.'}
            </FormHelperText>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleCreate} variant="contained" disabled={submitting}>
            {submitting ? 'Registering…' : 'Register'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

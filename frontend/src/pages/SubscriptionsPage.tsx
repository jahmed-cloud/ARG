/**
 * SubscriptionsPage — manage registered Azure subscriptions and tenants.
 *
 * Matches backend/api/routes/subscriptions.py:
 *   GET  /subscriptions
 *   POST /subscriptions { name, azure_subscription_id, tenant_id }
 *   DELETE /subscriptions/{id}
 *   GET/POST /subscriptions/{id}/access, DELETE /subscriptions/{id}/access/{grantId}
 *     - reader access inside ARG, managed by the subscription's Azure owners and by admins
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
import { Add, Delete, CloudQueue, GroupAdd } from '@mui/icons-material';
import { useApi, ApiError } from '../hooks/useApi';
import { useSnackbar } from 'notistack';
import { useAppSelector } from '../store/store';

interface SubscriptionItem {
  id: string;
  name: string;
  azure_subscription_id: string;
  tenant_id: string;
  state: string;
  last_scanned_at: string | null;
  my_access?: 'all' | 'owner' | 'reader' | null;
  can_manage_access?: boolean;
}

interface AccessGrant {
  id: string;
  principal: string | null;
  kind: 'local' | 'entra';
  role: 'owner' | 'reader';
  source: 'azure' | 'manual';
  removable: boolean;
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

  const { user } = useAppSelector((s) => s.auth);
  const isAdmin = user?.role === 'admin' || user?.role === 'super_admin';
  const isViewer = user?.role === 'viewer';

  const [accessFor, setAccessFor] = useState<SubscriptionItem | null>(null);
  const [grants, setGrants] = useState<AccessGrant[]>([]);
  const [grantEmail, setGrantEmail] = useState('');
  const [granting, setGranting] = useState(false);

  const loadGrants = async (sub: SubscriptionItem) => {
    try {
      setGrants(await api.get(`/subscriptions/${sub.id}/access`));
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to load access', { variant: 'error' });
    }
  };

  const openAccess = (sub: SubscriptionItem) => {
    setAccessFor(sub);
    setGrants([]);
    setGrantEmail('');
    loadGrants(sub);
  };

  const addReader = async () => {
    if (!accessFor || !grantEmail.trim()) return;
    setGranting(true);
    try {
      await api.post(`/subscriptions/${accessFor.id}/access`, { email: grantEmail.trim() });
      enqueueSnackbar(`${grantEmail.trim()} can now see ${accessFor.name}`, { variant: 'success' });
      setGrantEmail('');
      loadGrants(accessFor);
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to add reader', { variant: 'error' });
    } finally {
      setGranting(false);
    }
  };

  const removeGrant = async (grant: AccessGrant) => {
    if (!accessFor) return;
    try {
      await api.del(`/subscriptions/${accessFor.id}/access/${grant.id}`);
      loadGrants(accessFor);
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to remove access', { variant: 'error' });
    }
  };

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
        {isAdmin && <Button
          variant="contained"
          startIcon={<Add />}
          onClick={openDialog}
          sx={{  fontWeight: 700 }}
        >
          Register Subscription
        </Button>}
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
                {isViewer
                  ? 'You do not have access to a subscription yet. You see the subscriptions you own in Azure, and the ones an owner or admin gives you access to here.'
                  : 'No subscriptions registered yet. Register one to start scanning.'}
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
                  {isViewer && <TableCell>Your access</TableCell>}
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
                    {isViewer && (
                      <TableCell sx={{ color: alpha('#fff', 0.6), textTransform: 'capitalize' }}>{s.my_access ?? '-'}</TableCell>
                    )}
                    <TableCell align="right">
                      {s.can_manage_access && (
                        <IconButton size="small" aria-label={`Manage access to ${s.name}`} title="Manage access"
                          onClick={() => openAccess(s)} sx={{ color: alpha('#b8d9ba', 0.9) }}>
                          <GroupAdd fontSize="small" />
                        </IconButton>
                      )}
                      {isAdmin && (
                        <IconButton size="small" aria-label={`Remove ${s.name}`} onClick={() => handleDelete(s.id)} sx={{ color: alpha('#F44336', 0.8) }}>
                          <Delete fontSize="small" />
                        </IconButton>
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

      <Dialog open={!!accessFor} onClose={() => setAccessFor(null)} fullWidth maxWidth="sm">
        <DialogTitle>Access to {accessFor?.name}</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ color: alpha('#fff', 0.6), mb: 2 }}>
            Readers see this subscription's findings, costs, scans and reports in ARG. Nothing changes in Azure.
            Admins, contributors and auditors already see every subscription. Owners come from Azure (Owner role)
            and are re-checked at every sign-in.
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
            <TextField
              label="Email (ARG account or Entra user)"
              size="small"
              fullWidth
              value={grantEmail}
              onChange={(e) => setGrantEmail(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') addReader(); }}
            />
            <Button variant="contained" onClick={addReader} disabled={granting || !grantEmail.trim()}
              sx={{ whiteSpace: 'nowrap', flexShrink: 0 }}>
              {granting ? 'Adding…' : 'Add reader'}
            </Button>
          </Box>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Person</TableCell>
                <TableCell>Access</TableCell>
                <TableCell>From</TableCell>
                <TableCell align="right" />
              </TableRow>
            </TableHead>
            <TableBody>
              {grants.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} sx={{ color: alpha('#fff', 0.5) }}>No owners or readers yet.</TableCell>
                </TableRow>
              )}
              {grants.map((g) => (
                <TableRow key={g.id}>
                  <TableCell>{g.principal ?? '-'}</TableCell>
                  <TableCell sx={{ textTransform: 'capitalize' }}>{g.role}</TableCell>
                  <TableCell>{g.source === 'azure' ? 'Azure Owner' : g.kind === 'local' ? 'Added in ARG' : 'Added in ARG (Entra)'}</TableCell>
                  <TableCell align="right">
                    {g.removable && (
                      <IconButton size="small" aria-label={`Remove ${g.principal}`} onClick={() => removeGrant(g)} sx={{ color: alpha('#F44336', 0.8) }}>
                        <Delete fontSize="small" />
                      </IconButton>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAccessFor(null)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

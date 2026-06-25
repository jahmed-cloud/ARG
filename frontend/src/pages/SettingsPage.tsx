/**
 * SettingsPage — tenant (Azure AD) registration and user profile.
 *
 * Matches backend/api/routes/tenants.py:
 *   GET  /tenants (admin only)
 *   POST /tenants { name, azure_tenant_id, client_id, client_secret, description }
 *   DELETE /tenants/{id}
 *
 * Credential entry lives here deliberately, separate from Subscriptions,
 * so the service principal secret is only ever typed into one form in
 * the whole app.
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
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  Divider,
  Checkbox,
  FormControlLabel,
  Switch,
  alpha,
} from '@mui/material';
import { Add, Delete, VpnKey, ContentCopy } from '@mui/icons-material';
import { useApi, ApiError } from '../hooks/useApi';
import { useAppSelector } from '../store/store';
import { useSnackbar } from 'notistack';
import { ChangePasswordCard } from '../components/settings/ChangePasswordCard';
import { IntegrationsStatusCard } from '../components/settings/IntegrationsStatusCard';
import { UserManagementSection } from '../components/settings/UserManagementSection';
import { AboutSection } from '../components/settings/AboutSection';
import { GovernanceConfigSection } from '../components/settings/GovernanceConfigSection';

interface TenantItem {
  id: string;
  name: string;
  azure_tenant_id: string;
  is_active: boolean;
  graph_permissions_granted: boolean;
}

export const SettingsPage: React.FC = () => {
  const api = useApi();
  const { user } = useAppSelector((s) => s.auth);
  const { enqueueSnackbar } = useSnackbar();

  const [tenants, setTenants] = useState<TenantItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [dialogOpen, setDialogOpen] = useState(false);
  const [form, setForm] = useState({
    name: '',
    azure_tenant_id: '',
    client_id: '',
    client_secret: '',
    graph_permissions_granted: false,
  });
  const [submitting, setSubmitting] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<TenantItem | null>(null);
  const [deleting, setDeleting] = useState(false);

  const isAdmin = user?.role === 'admin' || user?.role === 'super_admin';

  const load = useCallback(async () => {
    if (!isAdmin) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const data = await api.get('/tenants');
      setTenants(data);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Failed to load tenants');
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  useEffect(() => {
    load();
  }, [load]);

  const handleCreate = async () => {
    if (!form.name || !form.azure_tenant_id || !form.client_id || !form.client_secret) {
      enqueueSnackbar('All fields are required', { variant: 'warning' });
      return;
    }

    // Catch malformed GUIDs before submission — a mistyped tenant ID
    // doesn't fail until the first scan runs, where the actual error
    // (an Azure 400 "unable to get authority configuration") is several
    // layers removed from "I typo'd a field in a form."
    const GUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!GUID_PATTERN.test(form.azure_tenant_id.trim())) {
      enqueueSnackbar(
        'Azure Tenant ID must be a valid GUID (e.g. 00000000-0000-0000-0000-000000000000). Find yours with: az account show --query tenantId',
        { variant: 'error', autoHideDuration: 8000 }
      );
      return;
    }
    if (!GUID_PATTERN.test(form.client_id.trim())) {
      enqueueSnackbar(
        'Service Principal Client ID must be a valid GUID (the "appId" from az ad sp create-for-rbac).',
        { variant: 'error', autoHideDuration: 8000 }
      );
      return;
    }

    setSubmitting(true);
    try {
      const created = await api.post('/tenants', form);
      enqueueSnackbar(
        `Tenant registered. ARG Tenant ID: ${created.id} (copied to clipboard — use it in Subscriptions)`,
        { variant: 'success', autoHideDuration: 10000 }
      );
      try {
        await navigator.clipboard.writeText(created.id);
      } catch {
        // Clipboard access can fail (permissions, non-HTTPS context, etc.) —
        // the ID is still visible in the snackbar and in the table below.
      }
      setDialogOpen(false);
      setForm({ name: '', azure_tenant_id: '', client_id: '', client_secret: '', graph_permissions_granted: false });
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to register tenant', { variant: 'error' });
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget || deleting) return;
    setDeleting(true);
    try {
      await api.del(`/tenants/${deleteTarget.id}`);
      enqueueSnackbar('Tenant removed', { variant: 'success' });
      setDeleteTarget(null);
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to remove tenant', { variant: 'error' });
    } finally {
      setDeleting(false);
    }
  };

  const handleToggleGraph = async (id: string, current: boolean) => {
    try {
      await api.patch(`/tenants/${id}`, { graph_permissions_granted: !current });
      enqueueSnackbar(
        !current ? 'Graph access enabled — identity scanners will run on the next scan' : 'Graph access disabled',
        { variant: 'success' }
      );
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to update tenant', { variant: 'error' });
    }
  };

  const handleCopyId = async (id: string) => {
    try {
      await navigator.clipboard.writeText(id);
      enqueueSnackbar('ARG Tenant ID copied — paste it into the Subscriptions form', { variant: 'success' });
    } catch {
      enqueueSnackbar('Could not copy automatically — select and copy the ID manually', { variant: 'warning' });
    }
  };

  return (
    <Box>
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 2.5 }}>
        Settings
      </Typography>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle2" sx={{ mb: 2, color: alpha('#fff', 0.7) }}>
            Profile
          </Typography>
          <Box sx={{ display: 'flex', gap: 4 }}>
            <Box>
              <Typography variant="caption" sx={{ color: alpha('#fff', 0.5) }}>
                Username
              </Typography>
              <Typography variant="body1">{user?.username}</Typography>
            </Box>
            <Box>
              <Typography variant="caption" sx={{ color: alpha('#fff', 0.5) }}>
                Role
              </Typography>
              <Typography variant="body1" sx={{ textTransform: 'capitalize' }}>
                {user?.role?.replace('_', ' ')}
              </Typography>
            </Box>
          </Box>
        </CardContent>
      </Card>

      <ChangePasswordCard />

      <IntegrationsStatusCard />

      <Divider sx={{ my: 3, borderColor: alpha('#00D4FF', 0.1) }} />

      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2.5 }}>
        <Typography variant="h6" sx={{ fontWeight: 700 }}>
          Azure Tenants
        </Typography>
        {isAdmin && (
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setDialogOpen(true)}
            sx={{ background: 'linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)', fontWeight: 700 }}
          >
            Register Tenant
          </Button>
        )}
      </Box>

      {!isAdmin ? (
        <Alert severity="info">Tenant management requires admin privileges.</Alert>
      ) : (
        <>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}
          <Card>
            <CardContent>
              {!loading && tenants.length === 0 ? (
                <Box sx={{ py: 6, textAlign: 'center' }}>
                  <VpnKey sx={{ fontSize: 40, color: alpha('#fff', 0.2), mb: 1 }} />
                  <Typography variant="body2" sx={{ color: alpha('#fff', 0.4) }}>
                    No Azure tenants registered yet.
                  </Typography>
                </Box>
              ) : (
                <TableContainer sx={{ overflowX: 'auto' }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Name</TableCell>
                      <TableCell>Azure Tenant ID</TableCell>
                      <TableCell>ARG Tenant ID (use this in Subscriptions)</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Graph Access</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {tenants.map((t) => (
                      <TableRow key={t.id} hover>
                        <TableCell>{t.name}</TableCell>
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: 12, color: alpha('#fff', 0.6) }}>
                          {t.azure_tenant_id}
                        </TableCell>
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: 12, color: '#00D4FF' }}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                            {t.id}
                            <Tooltip title="Copy ARG Tenant ID">
                              <IconButton size="small" onClick={() => handleCopyId(t.id)}>
                                <ContentCopy sx={{ fontSize: 14 }} />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={t.is_active ? 'Active' : 'Inactive'}
                            sx={{
                              bgcolor: alpha(t.is_active ? '#4CAF50' : '#9E9E9E', 0.15),
                              color: t.is_active ? '#4CAF50' : '#9E9E9E',
                              fontSize: 11,
                            }}
                          />
                        </TableCell>
                        <TableCell>
                          <Tooltip title="Toggle after granting/revoking Microsoft Graph admin consent for this Service Principal — enables Identity scanners (stale guests, dormant users, MFA, global admins, app credentials)">
                            <Switch
                              size="small"
                              checked={t.graph_permissions_granted}
                              onChange={() => handleToggleGraph(t.id, t.graph_permissions_granted)}
                            />
                          </Tooltip>
                        </TableCell>
                        <TableCell align="right">
                          <IconButton size="small" onClick={() => setDeleteTarget(t)} sx={{ color: alpha('#F44336', 0.8) }}>
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
        </>
      )}

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Register Azure Tenant</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            The client secret is encrypted with AES-256-GCM before storage and is never returned by the API.
          </Alert>
          <TextField
            label="Display Name"
            fullWidth
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            sx={{ mb: 2 }}
          />
          <TextField
            label="Azure Tenant ID"
            fullWidth
            value={form.azure_tenant_id}
            onChange={(e) => setForm({ ...form, azure_tenant_id: e.target.value })}
            placeholder="00000000-0000-0000-0000-000000000000"
            helperText="Find yours with: az account show --query tenantId -o tsv"
            sx={{ mb: 2 }}
          />
          <TextField
            label="Service Principal Client ID"
            fullWidth
            value={form.client_id}
            onChange={(e) => setForm({ ...form, client_id: e.target.value })}
            sx={{ mb: 2 }}
          />
          <TextField
            label="Service Principal Client Secret"
            type="password"
            fullWidth
            value={form.client_secret}
            onChange={(e) => setForm({ ...form, client_secret: e.target.value })}
            autoComplete="new-password"
            sx={{ mb: 1 }}
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={form.graph_permissions_granted}
                onChange={(e) => setForm({ ...form, graph_permissions_granted: e.target.checked })}
              />
            }
            label="Microsoft Graph API permissions granted"
          />
          <Typography variant="caption" sx={{ display: 'block', color: alpha('#fff', 0.4), mt: 0.5, mb: 1 }}>
            Required for Identity scanners (stale guests, dormant users, MFA, global admins, app
            credentials). Leave unchecked if you haven't granted Graph permissions yet — those
            scanners will be skipped rather than fail.
          </Typography>
          <Typography variant="caption" sx={{ display: 'block', color: alpha('#fff', 0.5) }}>
            Add these as <strong>Application</strong> permissions (not Delegated) on the service
            principal's app registration in Azure AD, then click "Grant admin consent":
          </Typography>
          <Box
            component="ul"
            sx={{ m: '4px 0 0 0', pl: 2.5, '& li': { fontSize: 12, color: alpha('#fff', 0.6), fontFamily: 'monospace' } }}
          >
            <li>User.Read.All</li>
            <li>AuditLog.Read.All</li>
            <li>Reports.Read.All</li>
            <li>RoleManagement.Read.Directory</li>
            <li>Application.Read.All</li>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleCreate} variant="contained" disabled={submitting}>
            {submitting ? 'Registering…' : 'Register'}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={!!deleteTarget} onClose={() => setDeleteTarget(null)} maxWidth="xs" fullWidth>
        <DialogTitle>Remove tenant?</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 1.5 }}>
            This cannot be undone. The stored credentials will be permanently deleted.
          </Alert>
          <Typography variant="body2" sx={{ color: alpha('#fff', 0.7) }}>
            {deleteTarget && (
              <>
                Remove <strong>{deleteTarget.name}</strong>? If any subscriptions are still
                registered under this tenant, removal will be blocked until they're deleted
                first.
              </>
            )}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteTarget(null)} disabled={deleting}>
            Cancel
          </Button>
          <Button onClick={handleDelete} color="error" variant="contained" disabled={deleting}>
            {deleting ? 'Removing…' : 'Remove Tenant'}
          </Button>
        </DialogActions>
      </Dialog>

      <Divider sx={{ my: 3, borderColor: alpha('#00D4FF', 0.1) }} />

      <UserManagementSection />

      <Divider sx={{ my: 3, borderColor: alpha('#00D4FF', 0.1) }} />

      <GovernanceConfigSection />

      <Divider sx={{ my: 3, borderColor: alpha('#00D4FF', 0.1) }} />

      <AboutSection />
    </Box>
  );
};

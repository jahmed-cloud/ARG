/**
 * UserManagementSection — admin-only platform user management.
 *
 * Matches backend/api/routes/users.py:
 *   GET    /users
 *   POST   /users { email, username, full_name, role, password? }
 *   PATCH  /users/{id} { full_name?, role?, is_active? }
 *   POST   /users/{id}/reset-password
 *   DELETE /users/{id}  (soft delete)
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
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  FormHelperText,
  Alert,
  Switch,
  alpha,
} from '@mui/material';
import { Add, Delete, VpnKey, ContentCopy } from '@mui/icons-material';
import { useApi, ApiError } from '../../hooks/useApi';
import { useAppSelector } from '../../store/store';
import { useSnackbar } from 'notistack';

interface UserItem {
  id: string;
  email: string;
  username: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
  sso_provider: string | null;
  last_login_at: string | null;
  login_count: number;
  created_at: string;
}

const ROLES = ['viewer', 'analyst', 'auditor', 'admin', 'super_admin'];

const ROLE_COLORS: Record<string, string> = {
  super_admin: '#F44336',
  admin: '#FF9800',
  analyst: '#00D4FF',
  auditor: '#9C27B0',
  viewer: '#9E9E9E',
};

export const UserManagementSection: React.FC = () => {
  const api = useApi();
  const { user: currentUser } = useAppSelector((s) => s.auth);
  const { enqueueSnackbar } = useSnackbar();

  const [users, setUsers] = useState<UserItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [dialogOpen, setDialogOpen] = useState(false);
  const [form, setForm] = useState({
    email: '',
    username: '',
    full_name: '',
    role: 'viewer',
    password: '',
  });
  const [submitting, setSubmitting] = useState(false);
  const [createdCredential, setCreatedCredential] = useState<{ username: string; password: string } | null>(null);

  const isAdmin = currentUser?.role === 'admin' || currentUser?.role === 'super_admin';
  const isSuperAdmin = currentUser?.role === 'super_admin';

  const load = useCallback(async () => {
    if (!isAdmin) return;
    setLoading(true);
    setError(null);
    try {
      const data = await api.get('/users');
      setUsers(data);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Failed to load users');
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  useEffect(() => {
    load();
  }, [load]);

  const handleCreate = async () => {
    if (!form.email || !form.username) {
      enqueueSnackbar('Email and username are required', { variant: 'warning' });
      return;
    }
    setSubmitting(true);
    try {
      const body: any = {
        email: form.email,
        username: form.username,
        full_name: form.full_name || null,
        role: form.role,
      };
      if (form.password) body.password = form.password;

      const created = await api.post('/users', body);
      if (created.generated_password) {
        setCreatedCredential({ username: created.username, password: created.generated_password });
      } else {
        enqueueSnackbar('User created', { variant: 'success' });
        setDialogOpen(false);
      }
      setForm({ email: '', username: '', full_name: '', role: 'viewer', password: '' });
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to create user', { variant: 'error' });
    } finally {
      setSubmitting(false);
    }
  };

  const handleRoleChange = async (id: string, role: string) => {
    try {
      await api.patch(`/users/${id}`, { role });
      enqueueSnackbar('Role updated', { variant: 'success' });
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to update role', { variant: 'error' });
    }
  };

  const handleToggleActive = async (id: string, currentlyActive: boolean) => {
    try {
      await api.patch(`/users/${id}`, { is_active: !currentlyActive });
      enqueueSnackbar(!currentlyActive ? 'User activated' : 'User deactivated', { variant: 'success' });
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to update user', { variant: 'error' });
    }
  };

  const handleResetPassword = async (id: string, username: string) => {
    try {
      const result = await api.post(`/users/${id}/reset-password`);
      setCreatedCredential({ username: result.username, password: result.temporary_password });
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to reset password', { variant: 'error' });
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.del(`/users/${id}`);
      enqueueSnackbar('User removed', { variant: 'success' });
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to remove user', { variant: 'error' });
    }
  };

  const handleCopyPassword = async () => {
    if (!createdCredential) return;
    try {
      await navigator.clipboard.writeText(createdCredential.password);
      enqueueSnackbar('Password copied', { variant: 'success' });
    } catch {
      enqueueSnackbar('Could not copy — select and copy manually', { variant: 'warning' });
    }
  };

  if (!isAdmin) {
    return <Alert severity="info">User management requires admin privileges.</Alert>;
  }

  return (
    <>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2.5 }}>
        <Typography variant="h6" sx={{ fontWeight: 700 }}>
          Users
        </Typography>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => {
            setCreatedCredential(null);
            setDialogOpen(true);
          }}
          sx={{ background: 'linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)', fontWeight: 700 }}
        >
          Add User
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Card>
        <CardContent sx={{ p: 0, '&:last-child': { pb: 0 } }}>
          {loading ? (
            <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), p: 3 }}>
              Loading…
            </Typography>
          ) : users.length === 0 ? (
            <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), p: 3 }}>
              No users found.
            </Typography>
          ) : (
            <TableContainer sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>User</TableCell>
                  <TableCell>Role</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Sign-in</TableCell>
                  <TableCell>Last Login</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {users.map((u) => (
                  <TableRow key={u.id} hover>
                    <TableCell>
                      <Typography variant="body2">{u.full_name || u.username}</Typography>
                      <Typography variant="caption" sx={{ color: alpha('#fff', 0.4) }}>
                        {u.email}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ minWidth: 150 }}>
                      <FormControl size="small" fullWidth disabled={u.id === currentUser?.id}>
                        <Select
                          value={u.role}
                          onChange={(e) => handleRoleChange(u.id, e.target.value)}
                          sx={{ fontSize: 13 }}
                        >
                          {ROLES.filter((r) => r !== 'super_admin' || isSuperAdmin).map((r) => (
                            <MenuItem key={r} value={r} sx={{ fontSize: 13 }}>
                              {r.replace('_', ' ')}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    </TableCell>
                    <TableCell>
                      <Tooltip title={u.id === currentUser?.id ? "You can't deactivate yourself" : ''}>
                        <span>
                          <Switch
                            size="small"
                            checked={u.is_active}
                            disabled={u.id === currentUser?.id}
                            onChange={() => handleToggleActive(u.id, u.is_active)}
                          />
                        </span>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={u.sso_provider ? 'Microsoft' : 'Local'}
                        sx={{ fontSize: 11, bgcolor: alpha('#fff', 0.08) }}
                      />
                    </TableCell>
                    <TableCell sx={{ color: alpha('#fff', 0.5), fontSize: 12 }}>
                      {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'Never'}
                    </TableCell>
                    <TableCell align="right">
                      {!u.sso_provider && (
                        <Tooltip title="Generate a new temporary password">
                          <IconButton size="small" onClick={() => handleResetPassword(u.id, u.username)}>
                            <VpnKey fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                      {u.id !== currentUser?.id && (
                        <Tooltip title="Remove user">
                          <IconButton size="small" onClick={() => handleDelete(u.id)} sx={{ color: alpha('#F44336', 0.8) }}>
                            <Delete fontSize="small" />
                          </IconButton>
                        </Tooltip>
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
        <DialogTitle>{createdCredential ? 'User Created' : 'Add User'}</DialogTitle>
        <DialogContent>
          {createdCredential ? (
            <>
              <Alert severity="success" sx={{ mb: 2 }}>
                Account created for <strong>{createdCredential.username}</strong>. Share this
                temporary password with them securely — it won't be shown again.
              </Alert>
              <Box
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  p: 1.5,
                  borderRadius: 1,
                  bgcolor: alpha('#fff', 0.05),
                  fontFamily: 'monospace',
                }}
              >
                {createdCredential.password}
                <IconButton size="small" onClick={handleCopyPassword}>
                  <ContentCopy fontSize="small" />
                </IconButton>
              </Box>
            </>
          ) : (
            <>
              <TextField
                label="Email"
                type="email"
                fullWidth
                required
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
                sx={{ mb: 2, mt: 1 }}
              />
              <TextField
                label="Username"
                fullWidth
                required
                value={form.username}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
                sx={{ mb: 2 }}
              />
              <TextField
                label="Full name"
                fullWidth
                value={form.full_name}
                onChange={(e) => setForm({ ...form, full_name: e.target.value })}
                sx={{ mb: 2 }}
              />
              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel id="role-label">Role</InputLabel>
                <Select
                  labelId="role-label"
                  label="Role"
                  value={form.role}
                  onChange={(e) => setForm({ ...form, role: e.target.value })}
                >
                  {ROLES.filter((r) => r !== 'super_admin' || isSuperAdmin).map((r) => (
                    <MenuItem key={r} value={r}>
                      {r.replace('_', ' ')}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <TextField
                label="Password (optional)"
                type="password"
                fullWidth
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
                helperText="Leave blank to auto-generate a temporary password shown once after creation."
              />
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>{createdCredential ? 'Close' : 'Cancel'}</Button>
          {!createdCredential && (
            <Button onClick={handleCreate} variant="contained" disabled={submitting}>
              {submitting ? 'Creating…' : 'Create'}
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </>
  );
};

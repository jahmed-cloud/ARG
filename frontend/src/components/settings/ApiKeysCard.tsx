/**
 * ApiKeysCard — personal API keys for CI/CD pipelines and scripts.
 * Matches backend/api/routes/api_keys.py:
 *   GET    /api-keys            list your keys (admins: ?all_users=true)
 *   POST   /api-keys            create; the plain key is returned once
 *   DELETE /api-keys/{id}       revoke
 * A key acts as you (same role and subscriptions). Use it as `Authorization: Bearer arg_...`.
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
  alpha,
} from '@mui/material';
import { Add, ContentCopy, Delete } from '@mui/icons-material';
import { useSnackbar } from 'notistack';
import { useApi, ApiError } from '../../hooks/useApi';

interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
  active: boolean;
}

const EXPIRY_OPTIONS = [30, 90, 180, 365];

const formatDate = (value: string | null) => (value ? new Date(value).toLocaleDateString() : '-');

export const ApiKeysCard: React.FC = () => {
  const api = useApi();
  const { enqueueSnackbar } = useSnackbar();
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [name, setName] = useState('');
  const [expiry, setExpiry] = useState(90);
  const [creating, setCreating] = useState(false);
  const [createdKey, setCreatedKey] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setKeys(await api.get('/api-keys'));
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Failed to load API keys');
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const closeDialog = () => {
    setDialogOpen(false);
    setCreatedKey(null);
    setName('');
    setExpiry(90);
  };

  const create = async () => {
    setCreating(true);
    try {
      const result = await api.post('/api-keys', { name: name.trim(), expires_in_days: expiry });
      setCreatedKey(result.key);
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Could not create the API key', { variant: 'error' });
    } finally {
      setCreating(false);
    }
  };

  const revoke = async (key: ApiKey) => {
    if (!window.confirm(`Revoke "${key.name}"? Pipelines using it stop working immediately.`)) return;
    try {
      await api.del(`/api-keys/${key.id}`);
      enqueueSnackbar('API key revoked', { variant: 'success' });
      load();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Could not revoke the API key', { variant: 'error' });
    }
  };

  const copyKey = async () => {
    if (!createdKey) return;
    try {
      await navigator.clipboard.writeText(createdKey);
      enqueueSnackbar('API key copied', { variant: 'success' });
    } catch {
      enqueueSnackbar('Copy blocked by the browser - select the key and copy it manually', { variant: 'warning' });
    }
  };

  const gateUrl = `${window.location.origin}${api.baseUrl}/findings/gate?fail_on=high`;

  return (
    <Card sx={{ mb: 3 }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 2, mb: 1 }}>
          <Typography variant="subtitle2" sx={{ color: alpha('#fff', 0.7) }}>
            API keys (CI/CD)
          </Typography>
          <Button variant="contained" size="small" startIcon={<Add />} onClick={() => setDialogOpen(true)}>
            New API key
          </Button>
        </Box>
        <Typography variant="body2" sx={{ color: alpha('#fff', 0.6), mb: 2 }}>
          Use a key in pipelines and scripts as <code>Authorization: Bearer arg_…</code>. It acts as you - same role
          and subscriptions - and expires automatically. Example gate:{' '}
          <code>curl -H "Authorization: Bearer $B_ARG_API_KEY" "{gateUrl}"</code>
        </Typography>

        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

        {!loading && keys.length === 0 && !error ? (
          <Typography variant="body2" sx={{ color: alpha('#fff', 0.5) }}>No API keys yet.</Typography>
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Key</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell>Expires</TableCell>
                  <TableCell>Last used</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell align="right" />
                </TableRow>
              </TableHead>
              <TableBody>
                {keys.map((k) => (
                  <TableRow key={k.id}>
                    <TableCell>{k.name}</TableCell>
                    <TableCell sx={{ fontFamily: 'monospace' }}>{k.prefix}…</TableCell>
                    <TableCell>{formatDate(k.created_at)}</TableCell>
                    <TableCell>{formatDate(k.expires_at)}</TableCell>
                    <TableCell>{formatDate(k.last_used_at)}</TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={k.active ? 'Active' : k.revoked_at ? 'Revoked' : 'Expired'}
                        sx={{
                          bgcolor: alpha(k.active ? '#4CAF50' : '#9E9E9E', 0.15),
                          color: k.active ? '#4CAF50' : '#9E9E9E',
                        }}
                      />
                    </TableCell>
                    <TableCell align="right">
                      {k.active && (
                        <Tooltip title="Revoke">
                          <IconButton size="small" onClick={() => revoke(k)} aria-label={`Revoke ${k.name}`}>
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

      <Dialog open={dialogOpen} onClose={closeDialog} maxWidth="sm" fullWidth>
        <DialogTitle>{createdKey ? 'Copy your API key now' : 'New API key'}</DialogTitle>
        <DialogContent>
          {createdKey ? (
            <>
              <Alert severity="warning" sx={{ mb: 2 }}>
                This is the only time the key is shown. Store it as a secret in your pipeline (for example
                <code> B_ARG_API_KEY</code>); never commit it.
              </Alert>
              <TextField
                value={createdKey}
                fullWidth
                InputProps={{
                  readOnly: true,
                  sx: { fontFamily: 'monospace' },
                  endAdornment: (
                    <IconButton onClick={copyKey} aria-label="Copy API key">
                      <ContentCopy fontSize="small" />
                    </IconButton>
                  ),
                }}
                onFocus={(e) => e.target.select()}
              />
            </>
          ) : (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
              <TextField
                label="Name"
                placeholder="GitHub Actions - landing zone repo"
                value={name}
                onChange={(e) => setName(e.target.value)}
                inputProps={{ maxLength: 100 }}
                autoFocus
                required
              />
              <FormControl>
                <InputLabel id="api-key-expiry">Expires after</InputLabel>
                <Select
                  labelId="api-key-expiry"
                  label="Expires after"
                  value={expiry}
                  onChange={(e) => setExpiry(Number(e.target.value))}
                >
                  {EXPIRY_OPTIONS.map((d) => (
                    <MenuItem key={d} value={d}>{d} days</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          {createdKey ? (
            <Button variant="contained" onClick={closeDialog}>Done</Button>
          ) : (
            <>
              <Button onClick={closeDialog}>Cancel</Button>
              <Button variant="contained" onClick={create} disabled={creating || !name.trim()}>
                {creating ? 'Creating…' : 'Create key'}
              </Button>
            </>
          )}
        </DialogActions>
      </Dialog>
    </Card>
  );
};

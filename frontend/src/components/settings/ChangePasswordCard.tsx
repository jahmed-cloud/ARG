/**
 * ChangePasswordCard — self-service password change for the current
 * logged-in user. Matches POST /auth/change-password, which requires
 * the current password for verification (unlike the admin-triggered
 * reset in UserManagementSection, or the email-token-based
 * /auth/forgot-password flow used when a user can't log in at all).
 */
import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  TextField,
  Alert,
  InputAdornment,
  IconButton,
  alpha,
} from '@mui/material';
import { Visibility, VisibilityOff } from '@mui/icons-material';
import { useApi, ApiError } from '../../hooks/useApi';
import { useSnackbar } from 'notistack';

export const ChangePasswordCard: React.FC = () => {
  const api = useApi();
  const { enqueueSnackbar } = useSnackbar();

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPasswords, setShowPasswords] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (newPassword.length < 12) {
      setError('New password must be at least 12 characters.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('New passwords do not match.');
      return;
    }

    setSubmitting(true);
    try {
      await api.post('/auth/change-password', {
        current_password: currentPassword,
        new_password: newPassword,
      });
      enqueueSnackbar('Password changed. You may need to sign in again.', { variant: 'success' });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Failed to change password');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Card sx={{ mb: 3 }}>
      <CardContent>
        <Typography variant="subtitle2" sx={{ mb: 2, color: alpha('#fff', 0.7) }}>
          Change Password
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Box component="form" onSubmit={handleSubmit} sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          <TextField
            label="Current password"
            type={showPasswords ? 'text' : 'password'}
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            required
            autoComplete="current-password"
            sx={{ flex: '1 1 200px' }}
          />
          <TextField
            label="New password"
            type={showPasswords ? 'text' : 'password'}
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
            autoComplete="new-password"
            helperText="At least 12 characters"
            sx={{ flex: '1 1 200px' }}
          />
          <TextField
            label="Confirm new password"
            type={showPasswords ? 'text' : 'password'}
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            autoComplete="new-password"
            sx={{ flex: '1 1 200px' }}
            InputProps={{
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton onClick={() => setShowPasswords(!showPasswords)} edge="end" size="small">
                    {showPasswords ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
                  </IconButton>
                </InputAdornment>
              ),
            }}
          />
          <Button
            type="submit"
            variant="contained"
            disabled={submitting || !currentPassword || !newPassword || !confirmPassword}
            sx={{ background: 'linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)', fontWeight: 700, alignSelf: 'flex-start', mt: 0.5 }}
          >
            {submitting ? 'Updating…' : 'Update Password'}
          </Button>
        </Box>
      </CardContent>
    </Card>
  );
};

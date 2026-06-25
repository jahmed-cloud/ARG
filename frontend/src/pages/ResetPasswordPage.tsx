/**
 * ResetPasswordPage — consumes the token from a password reset email
 * (see LoginPage's "Forgot password?" dialog, which calls
 * POST /auth/forgot-password) and lets the user set a new password.
 *
 * Route: /reset-password?token=...
 * Contract: POST /auth/reset-password { token, new_password }
 */
import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  TextField,
  Button,
  Typography,
  Alert,
  CircularProgress,
  InputAdornment,
  IconButton,
  alpha,
} from '@mui/material';
import { Visibility, VisibilityOff } from '@mui/icons-material';
import { useNavigate, useSearchParams, Link as RouterLink } from 'react-router-dom';

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000/api/v1';

export const ResetPasswordPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token') ?? '';

  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (newPassword.length < 12) {
      setError('Password must be at least 12 characters.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch(`${API_BASE}/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, new_password: newPassword }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail ?? 'This reset link is invalid or has expired.');
        return;
      }
      setSuccess(true);
      setTimeout(() => navigate('/login'), 2500);
    } catch {
      setError('Network error — please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        bgcolor: '#0A0F1E',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <Box sx={{ width: '100%', maxWidth: 400, px: 2 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, color: '#fff', mb: 3, textAlign: 'center' }}>
          Set a new password
        </Typography>

        <Card sx={{ bgcolor: '#0D1B2A', border: `1px solid ${alpha('#00D4FF', 0.15)}` }}>
          <CardContent sx={{ p: 3 }}>
            {!token ? (
              <Alert severity="error">
                This link is missing its reset token. Please use the link from your email, or{' '}
                <RouterLink to="/login" style={{ color: '#00D4FF' }}>return to sign in</RouterLink> to
                request a new one.
              </Alert>
            ) : success ? (
              <Alert severity="success">
                Password reset successfully. Redirecting you to sign in…
              </Alert>
            ) : (
              <Box component="form" onSubmit={handleSubmit}>
                {error && (
                  <Alert severity="error" sx={{ mb: 2 }}>
                    {error}
                  </Alert>
                )}
                <TextField
                  label="New password"
                  type={showPassword ? 'text' : 'password'}
                  fullWidth
                  required
                  autoFocus
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  helperText="At least 12 characters"
                  sx={{ mb: 2 }}
                  InputProps={{
                    endAdornment: (
                      <InputAdornment position="end">
                        <IconButton onClick={() => setShowPassword(!showPassword)} edge="end" size="small">
                          {showPassword ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
                        </IconButton>
                      </InputAdornment>
                    ),
                  }}
                />
                <TextField
                  label="Confirm new password"
                  type={showPassword ? 'text' : 'password'}
                  fullWidth
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  sx={{ mb: 3 }}
                />
                <Button
                  type="submit"
                  fullWidth
                  variant="contained"
                  disabled={submitting || !newPassword || !confirmPassword}
                  sx={{
                    py: 1.25,
                    background: 'linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)',
                    fontWeight: 700,
                  }}
                >
                  {submitting ? <CircularProgress size={20} sx={{ color: '#fff' }} /> : 'Reset password'}
                </Button>
              </Box>
            )}
          </CardContent>
        </Card>
      </Box>
    </Box>
  );
};

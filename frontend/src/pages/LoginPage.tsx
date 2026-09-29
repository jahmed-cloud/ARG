/**
 * LoginPage — ARG authentication entry point.
 *
 * Design rationale:
 *   - Full-viewport dark background matches the app's midnight theme.
 *   - Single card layout — no distraction, just the form.
 *   - Subtle ambient gradient orbs give depth without being distracting.
 *   - Error messages are intentionally generic ("invalid username or
 *     password") for both bad username and bad password, to avoid
 *     leaking which field was wrong (prevents user enumeration).
 *
 * Contract with backend (see backend/api/routes/auth.py):
 *   POST /auth/login { username, password }
 *   -> { access_token, refresh_token, token_type, expires_in,
 *        user_id, username, role }
 *   Note: the login response does NOT include email/fullName/mfaEnabled,
 *   so we synthesize a minimal User object and let /auth/me (profile
 *   fetch) hydrate the rest on first authenticated page load.
 */

import React, { useState, useEffect } from 'react';
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
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Divider,
  alpha,
} from '@mui/material';
import './login.css';
import { Visibility, VisibilityOff } from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAppDispatch, loginSuccess, setLoading } from '../store/store';

const API_BASE = import.meta.env.VITE_API_URL ?? '/api/v1';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const dispatch = useAppDispatch();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [microsoftEnabled, setMicrosoftEnabled] = useState(false);
  const [forgotOpen, setForgotOpen] = useState(false);
  const [forgotEmail, setForgotEmail] = useState('');
  const [forgotSubmitting, setForgotSubmitting] = useState(false);
  const [forgotMessage, setForgotMessage] = useState<string | null>(null);

  // Only show "Sign in with Microsoft" if this deployment actually has
  // it configured — otherwise the button would lead to a dead 503.
  useEffect(() => {
    fetch(`${API_BASE}/auth/microsoft/status`)
      .then((r) => r.json())
      .then((d) => setMicrosoftEnabled(!!d.enabled))
      .catch(() => setMicrosoftEnabled(false));
  }, []);

  // Surface any error Microsoft sign-in redirected back with (e.g. no
  // matching local account) — see backend /auth/microsoft/callback.
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const oauthError = params.get('oauth_error');
    if (oauthError === 'no_matching_account') {
      const email = params.get('oauth_email');
      setError(
        `No ARG account is linked to ${email ?? 'that Microsoft account'} yet. ` +
        `Ask an admin to create an account with this email first.`
      );
    } else if (oauthError === 'account_disabled') {
      setError('This account has been disabled. Contact your administrator.');
    } else if (oauthError) {
      setError('Microsoft sign-in failed. Please try again or use your password.');
    }
  }, [location.search]);

  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setForgotSubmitting(true);
    setForgotMessage(null);
    try {
      const res = await fetch(`${API_BASE}/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: forgotEmail }),
      });
      const data = await res.json();
      setForgotMessage(data.message ?? 'If an account with that email exists, a reset link has been sent.');
    } catch {
      setForgotMessage('Network error — please try again.');
    } finally {
      setForgotSubmitting(false);
    }
  };

  // Redirect back to the page the user was trying to reach before being
  // bounced to /login by ProtectedRoute.
  const from = (location.state as any)?.from?.pathname ?? '/dashboard';

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    dispatch(setLoading(true));

    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        if (res.status === 401 || res.status === 422) {
          setError('Invalid username or password.');
        } else if (res.status === 429) {
          setError('Too many attempts. Please wait a moment and try again.');
        } else {
          setError('Unable to sign in right now. Please try again.');
        }
        return;
      }

      const data = await res.json();

      dispatch(
        loginSuccess({
          accessToken: data.access_token,
          refreshToken: data.refresh_token,
          user: {
            id: data.user_id,
            username: data.username,
            email: data.username, // hydrated properly by /auth/me on next load
            fullName: null,
            role: data.role,
            mfaEnabled: false,
          },
        })
      );

      navigate(from, { replace: true });
    } catch {
      setError('Network error — is the backend reachable?');
    } finally {
      setSubmitting(false);
      dispatch(setLoading(false));
    }
  };

  return (
    <Box className="login-workspace">
      <Box className="login-story">
        <div className="login-brand"><span>ARG</span><small>RESOURCE GUARDIAN</small></div>
        <div className="login-editorial"><p className="eyebrow">CLARITY ACROSS YOUR AZURE ESTATE</p><h1>Every resource.<br />A clearer picture.</h1><p>Understand what you run, where you spend,<br />and what deserves your attention.</p></div>
        <div className="login-capabilities"><div><span>01</span> Discover your footprint</div><div><span>02</span> Assess risk and governance</div><div><span>03</span> Make informed changes</div></div>
        <div className="login-colophon">AZURE RESOURCE GUARDIAN <span>SELF-HOSTED / OPEN SOURCE</span></div>
      </Box>
      <Box className="login-form-panel">
        <div className="login-form-heading"><p className="eyebrow">YOUR WORKSPACE</p><h2>Welcome back.</h2><p>Sign in to your Resource Guardian workspace.</p></div>
        {/* Login card */}
        <Card
          sx={{
            bgcolor: 'transparent',
            border: 0,
            boxShadow: 'none', overflow: 'visible',
          }}
        >
          <CardContent sx={{ p: 0, "&:last-child": { pb: 0 } }}>


            {error && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {error}
              </Alert>
            )}

            <Box component="form" onSubmit={handleLogin}>
              <TextField
                label="Email or username"
                fullWidth
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                autoFocus
                autoComplete="username"
                sx={{ mb: 2 }}
              />

              <TextField
                label="Password"
                type={showPassword ? 'text' : 'password'}
                fullWidth
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
                sx={{ mb: 3 }}
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton aria-label={showPassword ? "Hide password" : "Show password"} onClick={() => setShowPassword(!showPassword)} edge="end" size="small">
                        {showPassword ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
              />

              <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 3, mt: -1.5 }}>
                <Button
                  size="small"
                  onClick={() => {
                    setForgotEmail('');
                    setForgotMessage(null);
                    setForgotOpen(true);
                  }}
                  sx={{ textTransform: 'none', color: alpha('#fff', 0.5), fontSize: 13 }}
                >
                  Forgot password?
                </Button>
              </Box>

              <Button
                type="submit"
                fullWidth
                variant="contained"
                disabled={submitting || !username || !password}
                sx={{
                  py: 1.25,
                  background: '#b8d9ba', color: '#183426',
                  fontWeight: 700,
                  fontSize: 15,
                  '&:disabled': { opacity: 0.5 },
                }}
              >
                {submitting ? <CircularProgress size={20} sx={{ color: '#fff' }} /> : 'Sign in'}
              </Button>

              {microsoftEnabled && (
                <>
                  <Divider sx={{ my: 2.5, color: alpha('#fff', 0.3), fontSize: 12 }}>or</Divider>
                  <Button
                    fullWidth
                    variant="outlined"
                    onClick={() => {
                      window.location.href = `${API_BASE}/auth/microsoft/login`;
                    }}
                    sx={{
                      py: 1.1,
                      borderColor: alpha('#fff', 0.15),
                      color: '#fff',
                      textTransform: 'none',
                      fontWeight: 600,
                      display: 'flex',
                      gap: 1,
                      '&:hover': { borderColor: alpha('#fff', 0.3), bgcolor: alpha('#fff', 0.03) },
                    }}
                  >
                    <Box
                      component="svg"
                      viewBox="0 0 21 21"
                      sx={{ width: 18, height: 18 }}
                    >
                      <rect x="1" y="1" width="9" height="9" fill="#f25022" />
                      <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
                      <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
                      <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
                    </Box>
                    Sign in with Microsoft
                  </Button>
                </>
              )}
            </Box>
          </CardContent>
        </Card>

        <Typography variant="caption" sx={{ display: 'block', textAlign: 'center', mt: 3, color: alpha('#fff', 0.55) }}>
          Azure Resource Guardian • Open Source • MIT License
        </Typography>
      </Box>

      <Dialog open={forgotOpen} onClose={() => setForgotOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>Reset your password</DialogTitle>
        <Box component="form" onSubmit={handleForgotPassword}>
          <DialogContent>
            {forgotMessage ? (
              <Alert severity="success">{forgotMessage}</Alert>
            ) : (
              <>
                <Typography variant="body2" sx={{ color: alpha('#fff', 0.6), mb: 2 }}>
                  Enter your account email and we'll send a link to reset your password.
                </Typography>
                <TextField
                  label="Email"
                  type="email"
                  fullWidth
                  required
                  autoFocus
                  value={forgotEmail}
                  onChange={(e) => setForgotEmail(e.target.value)}
                />
              </>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setForgotOpen(false)}>
              {forgotMessage ? 'Close' : 'Cancel'}
            </Button>
            {!forgotMessage && (
              <Button type="submit" variant="contained" disabled={forgotSubmitting || !forgotEmail}>
                {forgotSubmitting ? 'Sending…' : 'Send reset link'}
              </Button>
            )}
          </DialogActions>
        </Box>
      </Dialog>
    </Box>
  );
};

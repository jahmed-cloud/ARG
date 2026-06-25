/**
 * OAuthCallbackPage — lands here after backend /auth/microsoft/callback
 * redirects back with tokens in the URL fragment (#access_token=...).
 *
 * Tokens are passed in the fragment rather than the query string
 * deliberately: the fragment is never sent to the server on requests
 * and isn't logged by reverse proxies/browser history in the same way
 * query params can be. We read it once here, store it via the normal
 * loginSuccess action, then immediately clear it from the address bar.
 */
import React, { useEffect, useState } from 'react';
import { Box, CircularProgress, Typography, Alert } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { useAppDispatch, loginSuccess } from '../store/store';

export const OAuthCallbackPage: React.FC = () => {
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fragment = window.location.hash.replace(/^#/, '');
    const params = new URLSearchParams(fragment);

    const accessToken = params.get('access_token');
    const refreshToken = params.get('refresh_token');
    const userId = params.get('user_id');
    const username = params.get('username');
    const role = params.get('role');

    if (!accessToken || !refreshToken || !userId || !username || !role) {
      setError('Sign-in did not complete correctly. Please try again.');
      return;
    }

    dispatch(
      loginSuccess({
        accessToken,
        refreshToken,
        user: {
          id: userId,
          username,
          email: username,
          fullName: null,
          role,
          mfaEnabled: false,
        },
      })
    );

    // Clear the fragment from the address bar immediately so the tokens
    // don't linger in browser history.
    window.history.replaceState(null, '', window.location.pathname);
    navigate('/dashboard', { replace: true });
  }, [dispatch, navigate]);

  return (
    <Box
      sx={{
        minHeight: '100vh',
        bgcolor: '#0A0F1E',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 2,
      }}
    >
      {error ? (
        <Box sx={{ maxWidth: 400, px: 2 }}>
          <Alert severity="error">{error}</Alert>
        </Box>
      ) : (
        <>
          <CircularProgress sx={{ color: '#00D4FF' }} />
          <Typography sx={{ color: 'rgba(255,255,255,0.6)' }}>Completing sign-in…</Typography>
        </>
      )}
    </Box>
  );
};

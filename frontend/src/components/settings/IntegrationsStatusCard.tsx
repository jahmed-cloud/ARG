/**
 * IntegrationsStatusCard — read-only view of optional, env-var-driven
 * integrations (SMTP for password reset emails, Microsoft OAuth for
 * "Sign in with Microsoft"). Matches GET /auth/system-status.
 *
 * Deliberately not editable here — these are configured via .env /
 * docker-compose environment variables, not stored in the database,
 * to keep credentials out of the app's own data store. This card just
 * tells an admin what's currently active and points at .env.example
 * for how to turn each one on.
 */
import React, { useEffect, useState } from 'react';
import { Box, Card, CardContent, Typography, Chip, alpha } from '@mui/material';
import { CheckCircle, Cancel } from '@mui/icons-material';
import { useApi } from '../../hooks/useApi';
import { useAppSelector } from '../../store/store';

interface SystemStatus {
  smtp_configured: boolean;
  smtp_host: string | null;
  microsoft_oauth_configured: boolean;
}

export const IntegrationsStatusCard: React.FC = () => {
  const api = useApi();
  const { user } = useAppSelector((s) => s.auth);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const isAdmin = user?.role === 'admin' || user?.role === 'super_admin';

  useEffect(() => {
    if (!isAdmin) return;
    api.get('/auth/system-status').then(setStatus).catch(() => setStatus(null));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  if (!isAdmin || !status) return null;

  const Row = ({
    label,
    enabled,
    detail,
    envHint,
  }: {
    label: string;
    enabled: boolean;
    detail?: string | null;
    envHint: string;
  }) => (
    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', py: 1.25 }}>
      <Box>
        <Typography variant="body2">{label}</Typography>
        <Typography variant="caption" sx={{ color: alpha('#fff', 0.4) }}>
          {enabled ? detail ?? 'Configured' : `Set ${envHint} in .env to enable`}
        </Typography>
      </Box>
      <Chip
        size="small"
        icon={enabled ? <CheckCircle sx={{ fontSize: '14px !important' }} /> : <Cancel sx={{ fontSize: '14px !important' }} />}
        label={enabled ? 'Enabled' : 'Not configured'}
        sx={{
          bgcolor: alpha(enabled ? '#4CAF50' : '#9E9E9E', 0.15),
          color: enabled ? '#4CAF50' : alpha('#fff', 0.5),
          fontSize: 11,
        }}
      />
    </Box>
  );

  return (
    <Card sx={{ mb: 3 }}>
      <CardContent>
        <Typography variant="subtitle2" sx={{ mb: 1, color: alpha('#fff', 0.7) }}>
          Integrations
        </Typography>
        <Row
          label="Email (SMTP)"
          enabled={status.smtp_configured}
          detail={status.smtp_host ? `Sending via ${status.smtp_host}` : undefined}
          envHint="SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM_EMAIL"
        />
        <Box sx={{ borderTop: `1px solid ${alpha('#fff', 0.06)}` }} />
        <Row
          label="Sign in with Microsoft"
          enabled={status.microsoft_oauth_configured}
          envHint="AZURE_OAUTH_CLIENT_ID, AZURE_OAUTH_CLIENT_SECRET"
        />
        {!status.smtp_configured && (
          <Typography variant="caption" sx={{ display: 'block', mt: 1.5, color: alpha('#fff', 0.35) }}>
            Without SMTP, password reset links are written to the backend container logs instead
            of emailed — run <code>docker compose logs backend | grep reset-password</code> to
            find one.
          </Typography>
        )}
      </CardContent>
    </Card>
  );
};

/**
 * SecurityPage — security posture dashboard.
 *
 * Matches backend/api/routes/security.py: GET /security/stats
 */
import React, { useEffect, useState, useCallback } from 'react';
import { Box, Grid, Card, CardContent, Typography, Skeleton, Alert, LinearProgress, alpha } from '@mui/material';
import { useApi, ApiError } from '../hooks/useApi';

interface SecurityStats {
  security_score: number;
  public_endpoints: number;
  disabled_defender_plans: number;
  missing_backups: number;
  expired_certificates: number;
  missing_diagnostics: number;
}

const STAT_LABELS: { key: keyof SecurityStats; label: string }[] = [
  { key: 'public_endpoints', label: 'Public Endpoints Exposed' },
  { key: 'disabled_defender_plans', label: 'Defender Plans Disabled' },
  { key: 'missing_backups', label: 'Missing Backup Configuration' },
  { key: 'expired_certificates', label: 'Expired Certificates' },
  { key: 'missing_diagnostics', label: 'Missing Diagnostic Settings' },
];

export const SecurityPage: React.FC = () => {
  const api = useApi();
  const [stats, setStats] = useState<SecurityStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await api.get('/security/stats');
      setStats(data);
      setError(null);
    } catch (e) {
      if (!stats) {
        setError(e instanceof ApiError ? e.message : 'Failed to load security data');
      }
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

  if (loading) {
    return (
      <Grid container spacing={2.5}>
        {Array.from({ length: 5 }).map((_, i) => (
          <Grid item xs={12} sm={6} md={4} key={i}>
            <Skeleton variant="rounded" height={100} sx={{ bgcolor: alpha('#fff', 0.05) }} />
          </Grid>
        ))}
      </Grid>
    );
  }

  if (error || !stats) {
    return <Alert severity="error">{error ?? 'No security data available'}</Alert>;
  }

  const scoreColor = stats.security_score >= 80 ? '#4CAF50' : stats.security_score >= 60 ? '#FFC107' : '#F44336';

  return (
    <Box>
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 2.5 }}>
        Security
      </Typography>

      <Grid container spacing={2.5}>
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="body2" sx={{ color: alpha('#fff', 0.6), mb: 1.5 }}>
                Security Score
              </Typography>
              <Typography variant="h3" sx={{ fontWeight: 800, color: scoreColor, mb: 1.5 }}>
                {stats.security_score}
              </Typography>
              <LinearProgress
                variant="determinate"
                value={stats.security_score}
                sx={{
                  height: 6,
                  borderRadius: 3,
                  bgcolor: alpha('#fff', 0.08),
                  '& .MuiLinearProgress-bar': { bgcolor: scoreColor, borderRadius: 3 },
                }}
              />
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={8}>
          <Grid container spacing={1.5}>
            {STAT_LABELS.map(({ key, label }) => (
              <Grid item xs={6} sm={4} key={key}>
                <Card
                  sx={{
                    border: stats[key] > 0 ? `1px solid ${alpha('#F44336', 0.3)}` : undefined,
                  }}
                >
                  <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: stats[key] > 0 ? '#F44336' : '#fff' }}>
                      {stats[key]}
                    </Typography>
                    <Typography variant="caption" sx={{ color: alpha('#fff', 0.5) }}>
                      {label}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Grid>
      </Grid>

      <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), mt: 3 }}>
        For full finding details, visit the{' '}
        <a href="/findings" style={{ color: '#00D4FF' }}>
          Findings
        </a>{' '}
        page and filter by category "security".
      </Typography>
    </Box>
  );
};

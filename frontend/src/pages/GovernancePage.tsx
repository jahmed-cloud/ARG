/**
 * GovernancePage — tag compliance, naming, and CAF alignment dashboard.
 *
 * Matches backend/api/routes/governance.py: GET /governance/stats
 * Drills into category=governance findings via the shared /findings endpoint
 * for the detail table (reuses the same filtering contract as FindingsPage).
 */
import React, { useEffect, useState, useCallback } from 'react';
import { Box, Grid, Card, CardContent, Typography, Skeleton, Alert, LinearProgress, alpha } from '@mui/material';
import { useApi, ApiError } from '../hooks/useApi';

interface GovernanceStats {
  governance_score: number;
  missing_tags: number;
  naming_violations: number;
  policy_violations: number;
  region_violations: number;
  unlocked_resources: number;
  caf_violations: number;
}

const STAT_LABELS: { key: keyof GovernanceStats; label: string }[] = [
  { key: 'missing_tags', label: 'Missing Required Tags' },
  { key: 'naming_violations', label: 'Naming Violations' },
  { key: 'policy_violations', label: 'Policy Violations' },
  { key: 'region_violations', label: 'Region Restriction Violations' },
  { key: 'unlocked_resources', label: 'Unlocked Production Resources' },
  { key: 'caf_violations', label: 'CAF Alignment Violations' },
];

export const GovernancePage: React.FC = () => {
  const api = useApi();
  const [stats, setStats] = useState<GovernanceStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await api.get('/governance/stats');
      setStats(data);
      setError(null);
    } catch (e) {
      if (!stats) {
        setError(e instanceof ApiError ? e.message : 'Failed to load governance data');
      }
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    load();
    // Refresh periodically so the score reflects newly-completed scans
    // without requiring a manual page reload — this page previously
    // fetched exactly once on mount (empty dependency array) and never
    // updated again, which is why the governance score appeared frozen
    // even after a scan that genuinely changed the underlying findings.
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

  if (loading) {
    return (
      <Grid container spacing={2.5}>
        {Array.from({ length: 6 }).map((_, i) => (
          <Grid item xs={12} sm={6} md={4} key={i}>
            <Skeleton variant="rounded" height={100} sx={{ bgcolor: alpha('#fff', 0.05) }} />
          </Grid>
        ))}
      </Grid>
    );
  }

  if (error || !stats) {
    return <Alert severity="error">{error ?? 'No governance data available'}</Alert>;
  }

  const scoreColor = stats.governance_score >= 80 ? '#4CAF50' : stats.governance_score >= 60 ? '#FFC107' : '#F44336';

  return (
    <Box>
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 2.5 }}>
        Governance
      </Typography>

      <Grid container spacing={2.5}>
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="body2" sx={{ color: alpha('#fff', 0.6), mb: 1.5 }}>
                Governance Score
              </Typography>
              <Typography variant="h3" sx={{ fontWeight: 800, color: scoreColor, mb: 1.5 }}>
                {stats.governance_score}
              </Typography>
              <LinearProgress
                variant="determinate"
                value={stats.governance_score}
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
                <Card>
                  <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
                    <Typography variant="h6" sx={{ fontWeight: 700 }}>
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
        page and filter by category "governance".
      </Typography>
    </Box>
  );
};

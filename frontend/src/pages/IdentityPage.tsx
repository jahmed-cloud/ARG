/**
 * IdentityPage — Entra ID hygiene dashboard.
 *
 * Matches backend/api/routes/identity.py:
 *   GET /identity/stats
 *   GET /identity/findings?finding_type=&status=&page=&page_size=
 */
import React, { useEffect, useState, useCallback } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Skeleton,
  Alert,
  Chip,
  Table,
  TableContainer,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  LinearProgress,
  Pagination,
  alpha,
} from '@mui/material';
import { useApi, ApiError } from '../hooks/useApi';

interface IdentityStats {
  total_findings: number;
  stale_guest_users: number;
  dormant_users: number;
  mfa_not_enabled: number;
  permanent_global_admins: number;
  expired_app_credentials: number;
  never_used_service_principals: number;
  identity_score: number | null;
  graph_scan_completed: boolean;
  last_identity_scan_at: string | null;
  coverage_message: string | null;
}

interface IdentityFinding {
  id: string;
  finding_type: string;
  severity: string;
  status: string;
  display_name: string | null;
  user_principal_name: string | null;
  title: string;
  description: string;
  detected_at: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#F44336',
  high: '#FF9800',
  medium: '#FFC107',
  low: '#2196F3',
  info: '#9E9E9E',
};

const STAT_LABELS: { key: keyof IdentityStats; label: string }[] = [
  { key: 'stale_guest_users', label: 'Stale Guest Users' },
  { key: 'dormant_users', label: 'Dormant Users' },
  { key: 'mfa_not_enabled', label: 'MFA Not Enabled' },
  { key: 'permanent_global_admins', label: 'Permanent Global Admins' },
  { key: 'expired_app_credentials', label: 'Expired App Credentials' },
  { key: 'never_used_service_principals', label: 'Unused Service Principals' },
];

export const IdentityPage: React.FC = () => {
  const api = useApi();
  const [stats, setStats] = useState<IdentityStats | null>(null);
  const [findings, setFindings] = useState<IdentityFinding[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [statsResult, findingsResult] = await Promise.allSettled([
        api.get('/identity/stats'),
        api.get(`/identity/findings?page=${page}&page_size=25`),
      ]);
      if (statsResult.status === 'fulfilled') {
        setStats(statsResult.value);
        setError(null);
      } else if (!stats) {
        setError(statsResult.reason instanceof ApiError ? statsResult.reason.message : 'Failed to load identity data');
      }
      if (findingsResult.status === 'fulfilled') {
        setFindings(findingsResult.value.items);
        setTotal(findingsResult.value.total);
      }
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page]);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

  if (loading && !stats) {
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
    return <Alert severity="error">{error ?? 'No identity data available'}</Alert>;
  }

  const hasScore = stats.identity_score !== null;
  const scoreColor = !hasScore
    ? alpha('#fff', 0.4)
    : stats.identity_score! >= 80
    ? '#4CAF50'
    : stats.identity_score! >= 60
    ? '#FFC107'
    : '#F44336';
  const totalPages = Math.max(1, Math.ceil(total / 25));

  return (
    <Box>
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 2.5 }}>
        Identity &amp; Entra ID
      </Typography>

      {stats.coverage_message && (
        <Alert severity={stats.last_identity_scan_at ? 'warning' : 'info'} sx={{ mb: 2.5 }}>
          {stats.coverage_message}
        </Alert>
      )}

      <Grid container spacing={2.5} sx={{ mb: 2.5 }}>
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="body2" sx={{ color: alpha('#fff', 0.6), mb: 1.5 }}>
                Identity Score
              </Typography>
              <Typography variant="h3" sx={{ fontWeight: 800, color: scoreColor, mb: 1.5 }}>
                {hasScore ? stats.identity_score : '—'}
              </Typography>
              <LinearProgress
                variant="determinate"
                value={hasScore ? stats.identity_score! : 0}
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

      <Card>
        <CardContent>
          <Typography variant="subtitle2" sx={{ mb: 2, color: alpha('#fff', 0.7) }}>
            Identity Findings
          </Typography>
          {findings.length === 0 ? (
            <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), py: 3, textAlign: 'center' }}>
              No identity findings to show.
            </Typography>
          ) : (
            <TableContainer sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Severity</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Principal</TableCell>
                  <TableCell>Description</TableCell>
                  <TableCell>Status</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {findings.map((f) => (
                  <TableRow key={f.id} hover>
                    <TableCell>
                      <Chip
                        size="small"
                        label={f.severity.toUpperCase()}
                        sx={{
                          bgcolor: alpha(SEVERITY_COLORS[f.severity] ?? '#9E9E9E', 0.15),
                          color: SEVERITY_COLORS[f.severity] ?? '#9E9E9E',
                          fontWeight: 700,
                          fontSize: 11,
                        }}
                      />
                    </TableCell>
                    <TableCell sx={{ color: alpha('#fff', 0.6) }}>
                      {f.finding_type.replace(/_/g, ' ')}
                    </TableCell>
                    <TableCell>{f.display_name ?? f.user_principal_name ?? '—'}</TableCell>
                    <TableCell sx={{ color: alpha('#fff', 0.6), maxWidth: 320 }}>
                      <Typography variant="body2" noWrap>
                        {f.description ?? '—'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip size="small" label={f.status} sx={{ fontSize: 11 }} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

      {totalPages > 1 && (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2.5 }}>
          <Pagination count={totalPages} page={page} onChange={(_, p) => setPage(p)} color="primary" />
        </Box>
      )}
    </Box>
  );
};

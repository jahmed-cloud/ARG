/**
 * CostsPage — cost summary and savings opportunities.
 *
 * Matches backend/api/routes/costs.py: GET /costs/summary
 */
import React, { useEffect, useState } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Skeleton,
  Alert,
  Table,
  TableContainer,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  Chip,
  Tooltip,
  alpha,
} from '@mui/material';
import { AttachMoney, TrendingUp, TrendingDown, AccountBalanceWallet } from '@mui/icons-material';
import { useApi, ApiError } from '../hooks/useApi';

interface SavingOpportunity {
  id: string;
  title: string;
  resource_name: string | null;
  resource_type: string | null;
  monthly_saving: number;
  annual_saving: number;
  severity: string;
  remediation_steps: string | null;
}

interface CostSummary {
  total_monthly_cost: number;
  total_annual_cost: number;
  potential_monthly_savings: number;
  potential_annual_savings: number;
  currency: string;
  top_savings: SavingOpportunity[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#F44336',
  high: '#FF9800',
  medium: '#FFC107',
  low: '#2196F3',
  info: '#9E9E9E',
};

function MetricCard({ icon, label, value, subtext, accent }: any) {
  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1.5 }}>
          <Box
            sx={{
              width: 36,
              height: 36,
              borderRadius: 1.5,
              bgcolor: alpha(accent ?? '#00D4FF', 0.12),
              color: accent ?? '#00D4FF',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            {icon}
          </Box>
          <Typography variant="body2" sx={{ color: alpha('#fff', 0.6) }}>
            {label}
          </Typography>
        </Box>
        <Typography variant="h4" sx={{ fontWeight: 800 }}>
          {value}
        </Typography>
        {subtext && (
          <Typography variant="caption" sx={{ color: alpha('#fff', 0.4) }}>
            {subtext}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}

export const CostsPage: React.FC = () => {
  const api = useApi();
  const [data, setData] = useState<CostSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const json = await api.get('/costs/summary');
        setData(json);
      } catch (e) {
        setError(e instanceof ApiError ? e.message : 'Failed to load cost summary');
      } finally {
        setLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (loading) {
    return (
      <Grid container spacing={2.5}>
        {Array.from({ length: 4 }).map((_, i) => (
          <Grid item xs={12} sm={6} md={3} key={i}>
            <Skeleton variant="rounded" height={130} sx={{ bgcolor: alpha('#fff', 0.05) }} />
          </Grid>
        ))}
      </Grid>
    );
  }

  if (error || !data) {
    return <Alert severity="error">{error ?? 'No cost data available'}</Alert>;
  }

  return (
    <Box>
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 2.5 }}>
        Cost Savings
      </Typography>

      <Grid container spacing={2.5} sx={{ mb: 2.5 }}>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            icon={<AttachMoney fontSize="small" />}
            label="Monthly Spend"
            value={`$${data.total_monthly_cost.toLocaleString(undefined, { maximumFractionDigits: 0 })}`}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            icon={<TrendingUp fontSize="small" />}
            label="Annual Spend"
            value={`$${data.total_annual_cost.toLocaleString(undefined, { maximumFractionDigits: 0 })}`}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            icon={<TrendingDown fontSize="small" />}
            label="Potential Monthly Savings"
            value={`$${data.potential_monthly_savings.toLocaleString(undefined, { maximumFractionDigits: 0 })}`}
            accent="#4CAF50"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            icon={<AccountBalanceWallet fontSize="small" />}
            label="Potential Annual Savings"
            value={`$${data.potential_annual_savings.toLocaleString(undefined, { maximumFractionDigits: 0 })}`}
            accent="#4CAF50"
          />
        </Grid>
      </Grid>

      <Card>
        <CardContent>
          <Typography variant="subtitle2" sx={{ mb: 2, color: alpha('#fff', 0.7) }}>
            Top Savings Opportunities
          </Typography>
          {data.top_savings.length === 0 ? (
            <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), py: 3, textAlign: 'center' }}>
              No savings opportunities identified yet. Run a scan to discover unused resources.
            </Typography>
          ) : (
            <TableContainer sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Severity</TableCell>
                  <TableCell>Resource</TableCell>
                  <TableCell>Recommendation</TableCell>
                  <TableCell align="right">Monthly</TableCell>
                  <TableCell align="right">Annual</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.top_savings.map((s) => (
                  <TableRow key={s.id} hover>
                    <TableCell>
                      <Chip
                        size="small"
                        label={s.severity.toUpperCase()}
                        sx={{
                          bgcolor: alpha(SEVERITY_COLORS[s.severity] ?? '#9E9E9E', 0.15),
                          color: SEVERITY_COLORS[s.severity] ?? '#9E9E9E',
                          fontWeight: 700,
                          fontSize: 11,
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{s.resource_name ?? s.title}</Typography>
                      <Typography variant="caption" sx={{ color: alpha('#fff', 0.4) }}>
                        {s.resource_type}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ color: alpha('#fff', 0.6), maxWidth: 360 }}>
                      <Tooltip title={s.remediation_steps ?? ''} arrow placement="top">
                        <Typography
                          variant="body2"
                          sx={{
                            display: '-webkit-box',
                            WebkitLineClamp: 2,
                            WebkitBoxOrient: 'vertical',
                            overflow: 'hidden',
                            whiteSpace: 'pre-line',
                            cursor: s.remediation_steps ? 'help' : 'default',
                          }}
                        >
                          {s.remediation_steps ?? '—'}
                        </Typography>
                      </Tooltip>
                    </TableCell>
                    <TableCell align="right" sx={{ color: '#4CAF50', fontWeight: 600 }}>
                      ${s.monthly_saving.toFixed(2)}
                    </TableCell>
                    <TableCell align="right" sx={{ color: '#4CAF50', fontWeight: 600 }}>
                      ${s.annual_saving.toFixed(2)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>
    </Box>
  );
};

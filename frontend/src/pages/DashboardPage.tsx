/**
 * DashboardPage — executive summary view.
 *
 * Fetches GET /dashboard (see backend/api/routes/dashboard.py for the
 * exact DashboardSummary contract) and renders:
 *   - KPI cards: resources, open findings, monthly/annual savings
 *   - Score gauges: governance / security / identity (0-100)
 *   - Severity breakdown donut
 *   - Top findings table
 *   - Cost trend line chart
 *
 * Loading/error states are handled inline rather than via a global
 * spinner, since different widgets can be useful even if one section
 * fails (e.g. cost trend failing shouldn't block score gauges).
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
  Chip,
  LinearProgress,
  ToggleButtonGroup,
  ToggleButton,
  alpha,
  Table,
  TableContainer,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
} from '@mui/material';
import {
  TrendingUp,
  TrendingDown,
  TrendingFlat,
  Storage,
  BugReport,
  CloudQueue,
} from '@mui/icons-material';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { useAppSelector } from '../store/store';

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000/api/v1';

interface ScoreCard {
  score: number;
  trend: 'improving' | 'declining' | 'stable';
  delta: number;
  last_updated: string | null;
}

interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

interface TopFinding {
  id: string;
  title: string;
  severity: string;
  category: string;
  resource_name: string | null;
  resource_group: string | null;
  estimated_savings: number | null;
}

interface CostTrendPoint {
  month: string;
  total_cost: number;
  savings_identified: number;
}

interface ScoreHistoryPoint {
  date: string;
  governance_score: number;
  security_score: number;
  identity_score: number | null;
}

interface DashboardSummary {
  total_resources: number;
  total_subscriptions: number;
  total_findings_open: number;
  total_orphaned: number;
  total_monthly_savings_usd: number;
  total_annual_savings_usd: number;
  top_cost_savings: any[];
  governance_score: ScoreCard;
  security_score: ScoreCard;
  identity_score: ScoreCard;
  findings_by_severity: SeverityBreakdown;
  findings_by_category: Record<string, number>;
  entra_findings_open: number;
  drift_findings: number;
  top_findings: TopFinding[];
  cost_trend: CostTrendPoint[];
  last_scan_completed_at: string | null;
  last_scan_duration_s: number | null;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#F44336',
  high: '#FF9800',
  medium: '#FFC107',
  low: '#2196F3',
  info: '#9E9E9E',
};

function ScoreGauge({ label, score, trend, delta }: { label: string; score: number; trend: string; delta: number }) {
  const color = score >= 80 ? '#4CAF50' : score >= 60 ? '#FFC107' : '#F44336';
  const TrendIcon = trend === 'improving' ? TrendingUp : trend === 'declining' ? TrendingDown : TrendingFlat;
  const trendColor = trend === 'improving' ? '#4CAF50' : trend === 'declining' ? '#F44336' : alpha('#fff', 0.5);

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Typography variant="body2" sx={{ color: alpha('#fff', 0.6), mb: 1.5 }}>
          {label}
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1, mb: 1.5 }}>
          <Typography variant="h3" sx={{ fontWeight: 800, color }}>
            {Math.round(score)}
          </Typography>
          <Typography variant="body2" sx={{ color: alpha('#fff', 0.4) }}>
            / 100
          </Typography>
        </Box>
        <LinearProgress
          variant="determinate"
          value={score}
          sx={{
            height: 6,
            borderRadius: 3,
            bgcolor: alpha('#fff', 0.08),
            mb: 1.5,
            '& .MuiLinearProgress-bar': { bgcolor: color, borderRadius: 3 },
          }}
        />
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <TrendIcon sx={{ fontSize: 16, color: trendColor }} />
          <Typography variant="caption" sx={{ color: trendColor }}>
            {delta > 0 ? '+' : ''}
            {delta.toFixed(1)} pts
          </Typography>
        </Box>
      </CardContent>
    </Card>
  );
}

function KpiCard({
  icon,
  label,
  value,
  subtext,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  subtext?: string;
}) {
  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1.5 }}>
          <Box
            sx={{
              width: 36,
              height: 36,
              borderRadius: 1.5,
              bgcolor: alpha('#00D4FF', 0.12),
              color: '#00D4FF',
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
        <Typography variant="h4" sx={{ fontWeight: 800, color: '#fff' }}>
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

export const DashboardPage: React.FC = () => {
  const { accessToken } = useAppSelector((s) => s.auth);
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [scoreHistory, setScoreHistory] = useState<ScoreHistoryPoint[]>([]);
  const [trendDays, setTrendDays] = useState(30);
  const [trendLoading, setTrendLoading] = useState(true);

  useEffect(() => {
    const fetchDashboard = async () => {
      try {
        const res = await fetch(`${API_BASE}/dashboard`, {
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        if (!res.ok) {
          throw new Error(`Dashboard request failed (${res.status})`);
        }
        const json = await res.json();
        setData(json);
        setError(null);
      } catch (e: any) {
        // Only show an error if we have nothing to display yet — a
        // transient failure on a periodic background refresh shouldn't
        // replace a dashboard that's already showing good data.
        if (!data) {
          setError(e.message ?? 'Failed to load dashboard');
        }
      } finally {
        setLoading(false);
      }
    };
    fetchDashboard();
    // Refresh periodically so governance/security/identity scores and
    // findings counts reflect newly-completed scans automatically —
    // previously this only ever fetched once per page load (dependency
    // array was just [accessToken], which doesn't change after a scan),
    // so the dashboard appeared permanently frozen until a manual reload.
    const interval = setInterval(fetchDashboard, 30000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accessToken]);

  useEffect(() => {
    const fetchScoreHistory = async () => {
      setTrendLoading(true);
      try {
        const res = await fetch(`${API_BASE}/dashboard/score-history?days=${trendDays}`, {
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        if (res.ok) {
          setScoreHistory(await res.json());
        }
      } catch {
        // Non-critical — trend chart is best-effort, main dashboard
        // already has its own error handling.
      } finally {
        setTrendLoading(false);
      }
    };
    fetchScoreHistory();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accessToken, trendDays]);

  if (loading) {
    return (
      <Grid container spacing={2.5}>
        {Array.from({ length: 8 }).map((_, i) => (
          <Grid item xs={12} sm={6} md={3} key={i}>
            <Skeleton variant="rounded" height={140} sx={{ bgcolor: alpha('#fff', 0.05) }} />
          </Grid>
        ))}
      </Grid>
    );
  }

  if (error || !data) {
    return <Alert severity="error">{error ?? 'No dashboard data available'}</Alert>;
  }

  const severityPieData = [
    { name: 'Critical', value: data.findings_by_severity.critical, color: SEVERITY_COLORS.critical },
    { name: 'High', value: data.findings_by_severity.high, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: data.findings_by_severity.medium, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: data.findings_by_severity.low, color: SEVERITY_COLORS.low },
    { name: 'Info', value: data.findings_by_severity.info, color: SEVERITY_COLORS.info },
  ].filter((d) => d.value > 0);

  return (
    <Box>
      {/* KPI row */}
      <Grid container spacing={2.5} sx={{ mb: 2.5 }}>
        <Grid item xs={12} sm={6} md={3}>
          <KpiCard
            icon={<Storage fontSize="small" />}
            label="Total Resources"
            value={data.total_resources.toLocaleString()}
            subtext={`${data.total_subscriptions} subscriptions`}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <KpiCard
            icon={<BugReport fontSize="small" />}
            label="Open Findings"
            value={data.total_findings_open.toLocaleString()}
            subtext={`${data.total_orphaned} orphaned resources`}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <KpiCard
            icon={<TrendingDown fontSize="small" />}
            label="Monthly Savings"
            value={`$${data.total_monthly_savings_usd.toLocaleString(undefined, { maximumFractionDigits: 0 })}`}
            subtext={`$${data.total_annual_savings_usd.toLocaleString(undefined, { maximumFractionDigits: 0 })}/yr potential`}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <KpiCard
            icon={<CloudQueue fontSize="small" />}
            label="Drift Findings"
            value={data.drift_findings.toLocaleString()}
            subtext={`${data.entra_findings_open} identity issues`}
          />
        </Grid>
      </Grid>

      {/* Score gauges */}
      <Grid container spacing={2.5} sx={{ mb: 2.5 }}>
        <Grid item xs={12} sm={4}>
          <ScoreGauge label="Governance Score" {...data.governance_score} />
        </Grid>
        <Grid item xs={12} sm={4}>
          <ScoreGauge label="Security Score" {...data.security_score} />
        </Grid>
        <Grid item xs={12} sm={4}>
          <ScoreGauge label="Identity Score" {...data.identity_score} />
        </Grid>
      </Grid>

      <Grid container spacing={2.5}>
        {/* Severity breakdown */}
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="subtitle2" sx={{ mb: 2, color: alpha('#fff', 0.7) }}>
                Findings by Severity
              </Typography>
              {severityPieData.length === 0 ? (
                <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), py: 4, textAlign: 'center' }}>
                  No open findings — nice work.
                </Typography>
              ) : (
                <>
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie
                        data={severityPieData}
                        dataKey="value"
                        nameKey="name"
                        innerRadius={50}
                        outerRadius={80}
                        paddingAngle={2}
                      >
                        {severityPieData.map((entry, i) => (
                          <Cell key={i} fill={entry.color} />
                        ))}
                      </Pie>
                      <RechartsTooltip
                        contentStyle={{ background: '#0D1B2A', border: '1px solid rgba(0,212,255,0.2)' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, justifyContent: 'center', mt: 1 }}>
                    {severityPieData.map((d) => (
                      <Chip
                        key={d.name}
                        size="small"
                        label={`${d.name}: ${d.value}`}
                        sx={{ bgcolor: alpha(d.color, 0.15), color: d.color, fontWeight: 600 }}
                      />
                    ))}
                  </Box>
                </>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Cost trend */}
        <Grid item xs={12} md={8}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="subtitle2" sx={{ mb: 2, color: alpha('#fff', 0.7) }}>
                Cost Trend (6 months)
              </Typography>
              {data.cost_trend.length === 0 ? (
                <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), py: 4, textAlign: 'center' }}>
                  No cost trend data yet. Run a cost sync to populate this chart.
                </Typography>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <LineChart data={data.cost_trend}>
                    <CartesianGrid strokeDasharray="3 3" stroke={alpha('#fff', 0.08)} />
                    <XAxis dataKey="month" stroke={alpha('#fff', 0.4)} fontSize={12} />
                    <YAxis stroke={alpha('#fff', 0.4)} fontSize={12} />
                    <RechartsTooltip
                      contentStyle={{ background: '#0D1B2A', border: '1px solid rgba(0,212,255,0.2)' }}
                    />
                    <Line type="monotone" dataKey="total_cost" stroke="#00D4FF" strokeWidth={2} name="Total Cost" dot={false} />
                    <Line type="monotone" dataKey="savings_identified" stroke="#4CAF50" strokeWidth={2} name="Savings Identified" dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Score trend over time */}
        <Grid item xs={12} md={8}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2, flexWrap: 'wrap', gap: 1 }}>
                <Typography variant="subtitle2" sx={{ color: alpha('#fff', 0.7) }}>
                  Score Trend
                </Typography>
                <ToggleButtonGroup
                  size="small"
                  exclusive
                  value={trendDays}
                  onChange={(_, val) => val !== null && setTrendDays(val)}
                >
                  <ToggleButton value={7} sx={{ fontSize: 11, px: 1.5 }}>7d</ToggleButton>
                  <ToggleButton value={30} sx={{ fontSize: 11, px: 1.5 }}>30d</ToggleButton>
                  <ToggleButton value={90} sx={{ fontSize: 11, px: 1.5 }}>90d</ToggleButton>
                </ToggleButtonGroup>
              </Box>
              {trendLoading ? (
                <Skeleton variant="rounded" height={220} sx={{ bgcolor: alpha('#fff', 0.05) }} />
              ) : scoreHistory.length === 0 ? (
                <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), py: 4, textAlign: 'center' }}>
                  Not enough history yet — scores are snapshotted once daily, so check back after
                  tomorrow's snapshot to see a trend.
                </Typography>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <LineChart data={scoreHistory}>
                    <CartesianGrid strokeDasharray="3 3" stroke={alpha('#fff', 0.08)} />
                    <XAxis dataKey="date" stroke={alpha('#fff', 0.4)} fontSize={12} />
                    <YAxis domain={[0, 100]} stroke={alpha('#fff', 0.4)} fontSize={12} />
                    <RechartsTooltip
                      contentStyle={{ background: '#0D1B2A', border: '1px solid rgba(0,212,255,0.2)' }}
                    />
                    <Line type="monotone" dataKey="governance_score" stroke="#00D4FF" strokeWidth={2} name="Governance" dot={false} />
                    <Line type="monotone" dataKey="security_score" stroke="#FF9800" strokeWidth={2} name="Security" dot={false} />
                    <Line type="monotone" dataKey="identity_score" stroke="#9C27B0" strokeWidth={2} name="Identity" dot={false} connectNulls />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Top findings table */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="subtitle2" sx={{ mb: 2, color: alpha('#fff', 0.7) }}>
                Top Findings
              </Typography>
              {data.top_findings.length === 0 ? (
                <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), py: 2 }}>
                  No findings to show.
                </Typography>
              ) : (
                <TableContainer sx={{ overflowX: 'auto' }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Severity</TableCell>
                      <TableCell>Title</TableCell>
                      <TableCell>Resource</TableCell>
                      <TableCell>Category</TableCell>
                      <TableCell align="right">Savings/mo</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {data.top_findings.map((f) => (
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
                        <TableCell>{f.title}</TableCell>
                        <TableCell sx={{ color: alpha('#fff', 0.6) }}>{f.resource_name ?? '—'}</TableCell>
                        <TableCell sx={{ color: alpha('#fff', 0.6) }}>{f.category}</TableCell>
                        <TableCell align="right">
                          {f.estimated_savings ? `$${f.estimated_savings.toFixed(2)}` : '—'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                </TableContainer>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

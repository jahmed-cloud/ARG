import React, { useEffect, useState } from 'react';
import { Box, Button, Alert, Skeleton, Chip, ToggleButtonGroup, ToggleButton } from '@mui/material';
import { ArrowForward, NorthEast, ShieldOutlined, CloudQueue, CheckCircleOutline, Tune } from '@mui/icons-material';
import { Link } from 'react-router-dom';
import { ResponsiveContainer, AreaChart, Area, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';
import { useAppSelector } from '../store/store';
import './dashboard.css';
const API_BASE = import.meta.env.VITE_API_URL ?? '/api/v1';
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

const money = (n: number) => n.toLocaleString('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 });
const severityColor: Record<string, string> = { critical: '#ee8278', high: '#f0b56d', medium: '#e5d48c', low: '#81c8e6', info: '#a9b4bb' };
function Posture({ title, value, path }: { title: string; value: ScoreCard; path: string }) {
  const measured = Boolean(value.last_updated);
  return <Link to={path} className="posture-row"><span>{title}<small>{measured ? 'Latest assessment' : 'Awaiting assessment'}</small></span><span className="posture-track" aria-hidden="true"><i style={{ width: measured ? `${Math.max(0, Math.min(100, value.score))}%` : 0 }} /></span><strong>{measured ? Math.round(value.score) : '—'}<small>{measured ? '/100' : 'No data'}</small></strong><NorthEast fontSize="small" /></Link>;
}
export const DashboardPage: React.FC = () => {
  const { accessToken } = useAppSelector((s) => s.auth);
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scoreHistory, setScoreHistory] = useState<ScoreHistoryPoint[]>([]);
  const [trendDays, setTrendDays] = useState(30);
  const [trendLoading, setTrendLoading] = useState(true);
  const [trendError, setTrendError] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    let fetching = false;
    const fetchDashboard = async () => {
      if (fetching) return;
      fetching = true;
      try {
        const res = await fetch(`${API_BASE}/dashboard`, {
          signal: controller.signal,
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        if (!res.ok) {
          throw new Error(`Dashboard request failed (${res.status})`);
        }
        const json = await res.json();
        setData(json);
        setError(null);
      } catch (e: any) {
        if (!controller.signal.aborted) {
          setError(e.message ?? 'Failed to load dashboard');
        }
      } finally {
        fetching = false;
        if (!controller.signal.aborted) setLoading(false);
      }
    };
    fetchDashboard();
    // Refresh periodically so governance/security/identity scores and
    // findings counts reflect newly-completed scans automatically —
    // previously this only ever fetched once per page load (dependency
    // array was just [accessToken], which doesn't change after a scan),
    // so the dashboard appeared permanently frozen until a manual reload.
    const interval = setInterval(fetchDashboard, 30000);
    return () => { clearInterval(interval); controller.abort(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accessToken]);

  useEffect(() => {
    const controller = new AbortController();
    const fetchScoreHistory = async () => {
      setTrendLoading(true);
      try {
        const res = await fetch(`${API_BASE}/dashboard/score-history?days=${trendDays}`, {
          signal: controller.signal,
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        if (!res.ok) throw new Error("History unavailable");
        setScoreHistory(await res.json());
        setTrendError(false);
      } catch {
        if (!controller.signal.aborted) { setTrendError(true); setScoreHistory([]); }
      } finally {
        if (!controller.signal.aborted) setTrendLoading(false);
      }
    };
    fetchScoreHistory();
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accessToken, trendDays]);

  if (loading) return <Box aria-label="Loading estate overview"><Skeleton height={160} /><Skeleton height={360} /></Box>;
  if (!data) return <Alert severity="error">{error ?? 'Dashboard unavailable'}</Alert>;
  const scanned = Boolean(data.last_scan_completed_at);
  const connected = data.total_subscriptions > 0;
  const urgent = data.findings_by_severity.critical + data.findings_by_severity.high;
  return <div className="estate-overview">
    {error && <Alert severity="warning" sx={{ mb: 3 }}>Showing the last available data. Refresh failed; retrying automatically.</Alert>}
    <header className="overview-heading"><div><p className="eyebrow">WORKSPACE / OVERVIEW</p><h1>Know your estate.<br /><span>Decide what comes next.</span></h1></div><div className="overview-date"><span className={`status-dot ${scanned ? 'ready' : ''}`} />{scanned ? 'Assessment available' : 'Awaiting first assessment'}<small>{scanned ? new Date(data.last_scan_completed_at!).toLocaleString() : 'Connect Azure to begin'}</small></div></header>
    <section className="estate-summary" aria-label="Estate summary">
      <div className="summary-lead"><p className="eyebrow">AZURE FOOTPRINT</p><strong>{data.total_resources.toLocaleString()}</strong><span>discovered resources</span><Link to="/subscriptions">{data.total_subscriptions} connected subscriptions <ArrowForward fontSize="small" /></Link></div>
      <div className="summary-metric"><span>Open findings</span><strong>{data.total_findings_open.toLocaleString()}</strong><small>{scanned ? `${urgent} critical or high priority` : 'No scan results yet'}</small></div>
      <div className="summary-metric"><span>Potential savings / month</span><strong>{scanned ? money(data.total_monthly_savings_usd) : '—'}</strong><small>{scanned ? `${money(data.total_annual_savings_usd)} annual opportunity` : 'Calculated after assessment'}</small></div>
      <div className="summary-metric"><span>Orphaned resources</span><strong>{scanned ? data.total_orphaned.toLocaleString() : '—'}</strong><small>{data.drift_findings} drift findings · {data.entra_findings_open} identity issues</small></div>
    </section>
    {!scanned && <section className="onboarding-panel" aria-label="Get started"><div className="onboarding-intro"><span className="section-number">01 / GET STARTED</span><h2>Your next clear step.</h2><p>Bring your subscriptions into view, then build a baseline for cost, security, and governance.</p><Button component={Link} to={connected ? '/scans' : '/settings'} variant="contained" endIcon={<ArrowForward />}>{connected ? 'Configure your first scan' : 'Connect your Azure tenant'}</Button></div><ol className="setup-steps">
      <li><span className="step-icon">{connected ? <CheckCircleOutline /> : <Tune />}</span><div><strong>Connect your tenant</strong><p>Add your Azure credentials in Settings.</p></div><span className="step-state">{connected ? 'Connected' : 'Start here'}</span></li>
      <li><span className="step-icon"><CloudQueue /></span><div><strong>Choose your scope</strong><p>Sync and select the subscriptions to assess.</p></div></li>
      <li><span className="step-icon"><ShieldOutlined /></span><div><strong>Run a baseline scan</strong><p>Review evidence and savings before taking action.</p></div></li>
    </ol></section>}
    <div className="overview-grid">
      <section className="overview-panel"><div className="panel-heading"><div><p className="eyebrow">PRIORITIES</p><h2>Needs your attention</h2></div><Link to="/findings" className="text-link">All findings <NorthEast fontSize="small" /></Link></div>
        {data.top_findings.length ? <div className="priority-list">{data.top_findings.slice(0, 5).map(f => <Link to="/findings" className="priority-item" key={f.id}><span className="severity-marker" style={{ background: severityColor[f.severity] }} /><div><strong>{f.title}</strong><small>{f.resource_name ?? 'Subscription-level finding'} · {f.category}</small></div><Chip size="small" label={f.severity} sx={{ color: severityColor[f.severity], borderColor: severityColor[f.severity] }} variant="outlined" /><span className="finding-savings">{f.estimated_savings != null ? money(f.estimated_savings) : '—'}</span></Link>)}</div>
        : <div className="empty-assessment"><ShieldOutlined /><h3>{scanned ? 'No open findings' : 'Your findings will appear here'}</h3><p>{scanned ? 'Review scan coverage to confirm which resources and checks were assessed.' : 'A completed scan turns your resource inventory into a prioritized action list.'}</p><Link className="text-link" to="/scans">{scanned ? 'Review scan coverage' : 'Explore scan options'} <ArrowForward fontSize="small" /></Link></div>}
      </section>
      <section className="overview-panel"><div className="panel-heading"><div><p className="eyebrow">POSTURE</p><h2>Assessment coverage</h2></div></div><Posture title="Governance" value={data.governance_score} path="/governance" /><Posture title="Security" value={data.security_score} path="/security" /><Posture title="Identity" value={data.identity_score} path="/identity" /><p className="panel-note">Scores appear after a successful assessment. Unchecked areas remain unscored.</p></section>
      <section className="overview-panel"><div className="panel-heading"><div><p className="eyebrow">FINANCIAL PICTURE</p><h2>Recorded Azure spend</h2></div><Link to="/costs" className="text-link">Costs <NorthEast fontSize="small" /></Link></div>
        {data.cost_trend.length ? <ResponsiveContainer width="100%" height={225}><AreaChart data={data.cost_trend} margin={{ right: 20, top: 10 }}><CartesianGrid vertical={false} stroke="#293b3b" /><XAxis dataKey="month" stroke="#94aaa5" fontSize={11} /><YAxis stroke="#94aaa5" fontSize={11} /><Tooltip contentStyle={{ background: '#172624', border: '1px solid #405450' }} /><Area dataKey="total_cost" name="Recorded cost (USD)" stroke="#a6d7bc" fill="#a6d7bc" fillOpacity={0.1} strokeWidth={2} /></AreaChart></ResponsiveContainer>
        : <div className="quiet-empty"><span className="empty-rule" /><p>No billing data recorded yet.</p><small>Recorded monthly costs will appear here when available. Missing data is never shown as zero spend.</small></div>}
      </section>
      <section className="overview-panel"><div className="panel-heading"><div><p className="eyebrow">OVER TIME</p><h2>Posture history</h2></div><ToggleButtonGroup size="small" exclusive value={trendDays} onChange={(_, v) => v !== null && setTrendDays(v)} aria-label="History window">{[7, 30, 90].map(d => <ToggleButton key={d} value={d} aria-label={`${d} days`}>{d}d</ToggleButton>)}</ToggleButtonGroup></div>
        {trendLoading ? <Skeleton height={225} /> : trendError ? <Alert severity="warning">History is unavailable. Choose another range to retry.</Alert> : scoreHistory.length ? <ResponsiveContainer width="100%" height={225}><LineChart data={scoreHistory} margin={{ right: 20, top: 10 }}><CartesianGrid vertical={false} stroke="#293b3b" /><XAxis dataKey="date" stroke="#94aaa5" fontSize={11} /><YAxis domain={[0, 100]} stroke="#94aaa5" fontSize={11} /><Tooltip contentStyle={{ background: '#172624', border: '1px solid #405450' }} /><Line dataKey="governance_score" name="Governance" stroke="#a6d7bc" dot={false} /><Line dataKey="security_score" name="Security" stroke="#e9bc79" dot={false} /><Line dataKey="identity_score" name="Identity" stroke="#98b5db" dot={false} /></LineChart></ResponsiveContainer>
        : <div className="quiet-empty"><span className="empty-rule" /><p>A baseline comes before a trend.</p><small>Daily score snapshots will build this history after your first assessment.</small></div>}
      </section>
    </div><footer className="overview-footer"><span>RESOURCE GUARDIAN</span><span>Azure estate intelligence · Refreshes every 30 seconds</span></footer>
  </div>;
};

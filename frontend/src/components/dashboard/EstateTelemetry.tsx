/**
 * EstateTelemetry — the overview's estate charts (admins): spend by category / service / subscription, VM power
 * state and CPU bands, PaaS network exposure and tag coverage, from the newest estate inventory
 * (GET /estate/telemetry, computed by scripts/subscription_analysis/telemetry.py - the local portal's overview
 * shows the same numbers).
 */
import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Alert, Skeleton } from '@mui/material';
import { NorthEast } from '@mui/icons-material';
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { useApi, ApiError } from '../../hooks/useApi';

interface Amount {
  name: string;
  cost: number;
  count?: number;
}

interface Telemetry {
  currency: string;
  resources: number;
  subscriptions: number;
  spend_30d: number;
  spend_by_category: Amount[];
  spend_by_environment: Amount[];
  spend_by_subscription: Amount[];
  top_services: Amount[];
  vm_power: { running: number; deallocated: number; stopped: number };
  vm_stopped: { name: string; subscription: string; size?: string }[];
  vm_utilisation: Record<string, number>;
  network: {
    data: Record<string, number>;
    apps: Record<string, number>;
    private_endpoints: number;
    public_ips: number;
    vms_with_public_ip: number;
    vnets: number;
    isolated_vnets: number;
    collected: boolean;
  };
  tag_coverage: { resources_pct: number | null; cost_pct: number | null; most_missed: { tag: string; resources: number }[] } | null;
  suggestions: { count: number; by_severity: Record<string, number> };
}

const TOOLTIP = { contentStyle: { background: '#172624', border: '1px solid #405450', color: '#fff' } };
const AXIS = { stroke: '#94aaa5', fontSize: 11 };

const Donut: React.FC<{ parts: { name: string; value: number; color: string }[] }> = ({ parts }) => {
  const shown = parts.filter((p) => p.value > 0);
  const total = shown.reduce((a, p) => a + p.value, 0);
  if (!total) return <p className="panel-note">No data yet.</p>;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
      <div style={{ width: 170, height: 170, position: 'relative' }}>
        <ResponsiveContainer>
          <PieChart>
            <Pie data={shown} dataKey="value" nameKey="name" innerRadius={52} outerRadius={78} stroke="none">
              {shown.map((p) => (
                <Cell key={p.name} fill={p.color} />
              ))}
            </Pie>
            <Tooltip {...TOOLTIP} />
          </PieChart>
        </ResponsiveContainer>
        <strong style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', fontSize: 20 }}>
          {total.toLocaleString()}
        </strong>
      </div>
      <ul style={{ listStyle: 'none', margin: 0, padding: 0, fontSize: 13 }}>
        {parts.map((p) => (
          <li key={p.name} style={{ display: 'flex', alignItems: 'center', gap: 8, margin: '4px 0' }}>
            <span style={{ width: 12, height: 12, borderRadius: 3, background: p.color, display: 'inline-block' }} />
            {p.name} <strong>{p.value.toLocaleString()}</strong>
          </li>
        ))}
      </ul>
    </div>
  );
};

const Bars: React.FC<{ data: Amount[]; color: string; currency: string; valueKey?: 'cost' | 'count' }> = ({
  data,
  color,
  currency,
  valueKey = 'cost',
}) => {
  if (!data.length) return <p className="panel-note">No data yet.</p>;
  return (
    <ResponsiveContainer width="100%" height={Math.max(120, data.length * 28 + 20)}>
      <BarChart data={data} layout="vertical" margin={{ left: 10, right: 30 }}>
        <XAxis type="number" {...AXIS} hide />
        <YAxis type="category" dataKey="name" width={170} {...AXIS} tickLine={false} />
        <Tooltip
          {...TOOLTIP}
          formatter={(v: number) => (valueKey === 'cost' ? `${Math.round(v).toLocaleString()} ${currency}` : v.toLocaleString())}
        />
        <Bar dataKey={valueKey} fill={color} radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
};

export const EstateTelemetry: React.FC = () => {
  const api = useApi();
  const [t, setT] = useState<Telemetry | null>(null);
  const [state, setState] = useState<'loading' | 'ready' | 'missing' | 'error'>('loading');

  useEffect(() => {
    api
      .get('/estate/telemetry')
      .then((d: Telemetry) => {
        setT(d);
        setState('ready');
      })
      .catch((e: unknown) => setState(e instanceof ApiError && e.status === 404 ? 'missing' : 'error'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (state === 'loading') return <Skeleton height={260} />;
  if (state === 'missing')
    return (
      <Alert severity="info" sx={{ mb: 3 }}>
        Estate telemetry appears after the first estate inventory - <Link to="/estate">refresh it on the Estate page</Link>.
      </Alert>
    );
  if (state === 'error' || !t) return <Alert severity="warning">Estate telemetry is unavailable.</Alert>;

  const cur = t.currency;
  const exp = t.network.data;
  const apps = t.network.apps;
  const util = t.vm_utilisation;
  const kpis: [string, string, string?][] = [
    [`${Math.round(t.spend_30d).toLocaleString()} ${cur}`, 'spend, last 30 days (analysed subscriptions)'],
    [`${t.vm_power.running} / ${t.vm_power.deallocated}`, 'VMs running / deallocated'],
    [String(t.vm_power.stopped), 'VMs stopped but still billed', t.vm_power.stopped ? '#ff6b6b' : undefined],
    [String(util.idle ?? 0), 'running VMs idle (P95 CPU under 5 %)', util.idle ? '#f2c94c' : undefined],
    [String(exp.open ?? 0), 'data services open to all networks', exp.open ? '#ff6b6b' : undefined],
    [String(t.network.vms_with_public_ip), 'VMs with a public IP', t.network.vms_with_public_ip ? '#f2c94c' : undefined],
    [String(t.network.private_endpoints), 'private endpoints'],
  ];
  if (t.tag_coverage?.resources_pct != null) kpis.push([`${Math.round(t.tag_coverage.resources_pct)} %`, 'resources with every required tag']);

  return (
    <section className="overview-panel" style={{ gridColumn: '1 / -1', marginTop: 24 }} aria-label="Estate telemetry">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">ESTATE TELEMETRY</p>
          <h2>
            {t.resources.toLocaleString()} resources in {t.subscriptions} subscriptions
          </h2>
        </div>
        <span style={{ display: 'flex', gap: 16 }}>
          <Link to="/estate" className="text-link">
            Estate <NorthEast fontSize="small" />
          </Link>
          <Link to="/architecture?view=network" className="text-link">
            Network topology <NorthEast fontSize="small" />
          </Link>
        </span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12, margin: '8px 0 20px' }}>
        {kpis.map(([v, label, color]) => (
          <div key={label} style={{ border: '1px solid #405450', borderRadius: 8, padding: '10px 12px' }}>
            <strong style={{ display: 'block', fontSize: 22, color: color ?? 'inherit' }}>{v}</strong>
            <small style={{ opacity: 0.8 }}>{label}</small>
          </div>
        ))}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: 24 }}>
        <div>
          <h3>Spend by category (30 days)</h3>
          <Bars data={t.spend_by_category} color="#b8d9ba" currency={cur} />
        </div>
        <div>
          <h3>Top services by spend</h3>
          <Bars data={t.top_services} color="#2196f3" currency={cur} />
        </div>
        <div>
          <h3>VM power state</h3>
          <Donut
            parts={[
              { name: 'Running', value: t.vm_power.running, color: '#4caf50' },
              { name: 'Deallocated - disks still billed', value: t.vm_power.deallocated, color: '#f2c94c' },
              { name: 'Stopped - compute still billed', value: t.vm_power.stopped, color: '#ff6b6b' },
            ]}
          />
          {t.vm_stopped.slice(0, 6).map((v) => (
            <p key={v.name} style={{ color: '#ff6b6b', fontSize: 13, margin: '4px 0' }}>
              Stopped, not deallocated: {v.name} ({v.subscription}{v.size ? `, ${v.size}` : ''})
            </p>
          ))}
        </div>
        <div>
          <h3>Running VMs by CPU (30-day P95)</h3>
          <Donut
            parts={[
              { name: 'Idle, under 5 %', value: util.idle ?? 0, color: '#f2c94c' },
              { name: 'Low, 5-30 %', value: util.low ?? 0, color: '#2196f3' },
              { name: 'Healthy, 30-80 %', value: util.healthy ?? 0, color: '#4caf50' },
              { name: 'Hot, over 80 %', value: util.hot ?? 0, color: '#ff6b6b' },
              { name: 'No metrics', value: util['no data'] ?? 0, color: '#94aaa5' },
            ]}
          />
        </div>
        <div>
          <h3>Data services by network exposure</h3>
          {t.network.collected ? (
            <Donut
              parts={[
                { name: 'Open to all networks', value: exp.open ?? 0, color: '#ff6b6b' },
                { name: 'Rules not in Resource Graph', value: exp.unverified ?? 0, color: '#94aaa5' },
                { name: 'Restricted (firewall / VNet)', value: exp.restricted ?? 0, color: '#f2c94c' },
                { name: 'Public access off', value: exp.closed ?? 0, color: '#b8d9ba' },
                { name: 'Private endpoint', value: exp.private ?? 0, color: '#4caf50' },
              ]}
            />
          ) : (
            <p className="panel-note">Refresh the estate inventory to collect network exposure.</p>
          )}
        </div>
        <div>
          <h3>Apps by inbound exposure</h3>
          {t.network.collected ? (
            <Donut
              parts={[
                { name: 'Public endpoint', value: apps['app-public'] ?? 0, color: '#2196f3' },
                { name: 'Restricted', value: apps.restricted ?? 0, color: '#f2c94c' },
                { name: 'Private endpoint', value: apps.private ?? 0, color: '#4caf50' },
                { name: 'Public access off', value: apps.closed ?? 0, color: '#b8d9ba' },
              ]}
            />
          ) : (
            <p className="panel-note">-</p>
          )}
        </div>
        <div>
          <h3>Top subscriptions by spend</h3>
          <Bars data={t.spend_by_subscription} color="#e9bc79" currency={cur} />
        </div>
        <div>
          <h3>Suggestions by severity</h3>
          <Bars
            data={['critical', 'high', 'medium', 'low', 'info']
              .filter((s) => t.suggestions.by_severity[s])
              .map((s) => ({ name: s[0].toUpperCase() + s.slice(1), cost: 0, count: t.suggestions.by_severity[s] }))}
            color="#e07a3f"
            currency=""
            valueKey="count"
          />
        </div>
      </div>
    </section>
  );
};

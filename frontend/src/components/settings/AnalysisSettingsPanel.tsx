/**
 * AnalysisSettingsPanel - admin editor for the analysis settings (GET/PUT /governance/config `settings`), generated
 * from the server's `setting_definitions` (scripts/subscription_analysis/settings.py): optional checks, cost basis and
 * currency, confidential-data tags, required VM extensions, AI review, landing-zone mapping. Takes effect on the next
 * scan; the .env values are the defaults until saved.
 */
import React, { useEffect, useMemo, useState } from 'react';
import {
  Box, Button, Card, CardContent, MenuItem, Switch, TextField, Typography, alpha,
} from '@mui/material';
import { RestartAlt, Save } from '@mui/icons-material';
import { useSnackbar } from 'notistack';
import { useApi, ApiError } from '../../hooks/useApi';

interface Definition {
  key: string;
  label: string;
  kind: 'bool' | 'list' | 'number' | 'choice' | 'text';
  default: unknown;
  help: string;
  choices: string[];
}

interface ConfigResponse {
  required_tags: string[];
  naming_patterns: Record<string, string>;
  settings: Record<string, unknown>;
  setting_definitions: Definition[];
}

const GROUPS: [string, string[]][] = [
  ['Findings', ['required_tags_check', 'naming_convention_enabled', 'defender_recommendations',
    'defender_plan_recommendations', 'defender_plan_coverage', 'report_unused_providers', 'blocked_resource_providers']],
  ['Cost & currency', ['amortized_cost', 'display_currency', 'engineering_hourly_rate_usd', 'ai_gateway_sku']],
  ['Security & agents', ['sensitive_data_tags', 'required_vm_extensions', 'include_arc_machines']],
  ['AI review', ['ai_reasoning', 'ai_endpoint', 'ai_deployment', 'ai_max_findings']],
  ['Architecture', ['landing_zone_mapping']],
];

const toText = (v: unknown) => (Array.isArray(v) ? v.join('\n') : v === null || v === undefined ? '' : String(v));

export const AnalysisSettingsPanel: React.FC = () => {
  const api = useApi();
  const { enqueueSnackbar } = useSnackbar();
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.get('/governance/config')
      .then((data: ConfigResponse) => { setConfig(data); setValues(data.settings ?? {}); })
      .catch(() => enqueueSnackbar('Failed to load the analysis settings', { variant: 'error' }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const groups = useMemo(() => {
    if (!config) return [];
    const known = new Set(GROUPS.flatMap(([, keys]) => keys));
    const byKey = Object.fromEntries(config.setting_definitions.map((d) => [d.key, d]));
    const out = GROUPS.map(([name, keys]) => [name, keys.map((k) => byKey[k]).filter(Boolean)] as [string, Definition[]]);
    const other = config.setting_definitions.filter((d) => !known.has(d.key));
    return other.length ? [...out, ['Other', other] as [string, Definition[]]] : out;
  }, [config]);

  const set = (key: string, value: unknown) => setValues((v) => ({ ...v, [key]: value }));

  const save = async () => {
    if (!config) return;
    setSaving(true);
    try {
      // re-read tags and patterns: the Governance Configuration card saves them through the same endpoint
      const fresh: ConfigResponse = await api.get('/governance/config');
      const body = { required_tags: fresh.required_tags, naming_patterns: fresh.naming_patterns, settings: values };
      const saved: ConfigResponse = await api.put('/governance/config', body);
      setConfig(saved);
      setValues(saved.settings ?? {});
      enqueueSnackbar('Analysis settings saved - they apply from the next scan', { variant: 'success' });
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Save failed', { variant: 'error' });
    } finally {
      setSaving(false);
    }
  };

  const reset = async () => {
    try {
      const defaults: ConfigResponse = await api.get('/governance/config/defaults');
      setValues(defaults.settings ?? Object.fromEntries((config?.setting_definitions ?? []).map((d) => [d.key, d.default])));
      enqueueSnackbar('Defaults loaded - Save to apply', { variant: 'info' });
    } catch {
      enqueueSnackbar('Failed to load the defaults', { variant: 'error' });
    }
  };

  if (!config) return null;

  const field = (d: Definition) => {
    const value = values[d.key] ?? d.default;
    if (d.kind === 'bool') {
      return (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Switch checked={!!value} onChange={(e) => set(d.key, e.target.checked)} inputProps={{ 'aria-label': d.label }} />
          <Typography variant="body2">{d.label}</Typography>
        </Box>
      );
    }
    if (d.kind === 'choice') {
      return (
        <TextField select size="small" label={d.label} value={toText(value)} onChange={(e) => set(d.key, e.target.value)}
          sx={{ minWidth: 260 }}>
          {d.choices.map((c) => <MenuItem key={c} value={c}>{c}</MenuItem>)}
        </TextField>
      );
    }
    if (d.kind === 'list') {
      return (
        <TextField multiline minRows={2} size="small" fullWidth label={d.label} value={toText(value)}
          onChange={(e) => set(d.key, e.target.value.split('\n'))} helperText="One entry per line"
          inputProps={{ style: { fontFamily: 'Consolas, monospace', fontSize: 12 } }} />
      );
    }
    return (
      <TextField size="small" fullWidth label={d.label} type={d.kind === 'number' ? 'number' : 'text'}
        value={toText(value)} onChange={(e) => set(d.key, d.kind === 'number' && e.target.value === '' ? null : e.target.value)}
        inputProps={{ maxLength: 300 }} />
    );
  };

  return (
    <Card sx={{ mb: 3 }}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.5, flexWrap: 'wrap', gap: 1 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Analysis settings</Typography>
          <Button size="small" startIcon={<RestartAlt />} onClick={reset} sx={{ color: alpha('#fff', 0.5) }}>
            Defaults
          </Button>
        </Box>
        <Typography variant="body2" sx={{ color: alpha('#fff', 0.5), mb: 2.5 }}>
          Optional checks, cost basis, currency, AI review and more. Apply from the next scan.
        </Typography>

        {groups.map(([name, defs]) => (
          <Box key={name} sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '180px 1fr' }, gap: 2,
                                py: 2, borderTop: `1px solid ${alpha('#b8d9ba', 0.1)}` }}>
            <Typography sx={{ font: "600 10px 'Consolas', monospace", letterSpacing: '0.14em', color: '#a3b5ad',
                               textTransform: 'uppercase', pt: 1 }}>
              {name}
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5, minWidth: 0 }}>
              {defs.map((d) => (
                <Box key={d.key}>
                  {field(d)}
                  <Typography variant="caption" component="p" sx={{ color: alpha('#fff', 0.45), mt: 0.5, maxWidth: 760 }}>
                    {d.help}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Box>
        ))}

        <Button variant="contained" startIcon={<Save />} onClick={save} disabled={saving} sx={{ fontWeight: 700, mt: 1 }}>
          {saving ? 'Saving…' : 'Save analysis settings'}
        </Button>
      </CardContent>
    </Card>
  );
};

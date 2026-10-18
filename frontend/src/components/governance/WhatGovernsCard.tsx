/**
 * WhatGovernsCard — "What governs this resource?"
 *
 * Paste a resource / resource group / subscription id and see every Azure Policy assignment that applies to it
 * scope by scope, the exemptions that cover it, and its compliance state per policy.
 * Backed by GET /governance/what-governs (live, read-only Resource Graph lookup).
 */
import React, { useState } from 'react';
import {
  Alert, Box, Button, Card, CardContent, Chip, CircularProgress, Stack, Table, TableBody, TableCell, TableHead,
  TableRow, TextField, Typography, alpha,
} from '@mui/material';
import { useApi, ApiError } from '../../hooks/useApi';

interface Assignment { name: string; id: string; enforced: boolean; initiative: boolean }
interface ScopeLevel { scope: string; assignments: Assignment[] }
interface Exemption {
  name: string; scope: string; category: string | null; expiresOn: string | null; refIds: string[];
  status: 'active' | 'expired' | 'never expires'; whole_assignment: boolean;
}
interface ComplianceRow { state: string; effect: string; policy: string; assignment: string; reference: string | null }
interface WhatGoverns {
  resource_id: string;
  scopes: ScopeLevel[];
  exemptions: Exemption[];
  compliance: ComplianceRow[];
  summary: { evaluations: number; non_compliant: number; exempt: number; assignments: number };
}

const STATE_COLOR: Record<string, 'error' | 'warning' | 'success' | 'default'> = {
  NonCompliant: 'error', Exempt: 'warning', Compliant: 'success',
};
const leaf = (id: string) => id.split('/').filter(Boolean).pop() ?? id;

export const WhatGovernsCard: React.FC = () => {
  const api = useApi();
  const [resourceId, setResourceId] = useState('');
  const [result, setResult] = useState<WhatGoverns | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nonCompliantOnly, setNonCompliantOnly] = useState(false);

  const lookup = async () => {
    setLoading(true);
    setError(null);
    try {
      setResult(await api.get(`/governance/what-governs?resource_id=${encodeURIComponent(resourceId.trim())}`));
    } catch (e) {
      setResult(null);
      setError(e instanceof ApiError ? e.message : 'Lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const rows = (result?.compliance ?? []).filter((r) => !nonCompliantOnly || r.state === 'NonCompliant');

  return (
    <Card sx={{ mt: 3 }}>
      <CardContent>
        <Typography variant="h6" sx={{ fontWeight: 700 }}>What governs this resource?</Typography>
        <Typography variant="body2" sx={{ color: alpha('#fff', 0.55), mb: 2 }}>
          Every policy assignment from the root management group down, the exemptions that cover it, and its
          compliance per policy. Paste the id from a "RequestDisallowedByPolicy" error or the portal.
        </Typography>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
          <TextField
            fullWidth size="small" value={resourceId} onChange={(e) => setResourceId(e.target.value)}
            placeholder="/subscriptions/<id>/resourceGroups/<rg>/providers/<type>/<name>"
            onKeyDown={(e) => { if (e.key === 'Enter' && resourceId.trim()) lookup(); }}
            inputProps={{ 'aria-label': 'Azure resource id' }}
          />
          <Button variant="contained" onClick={lookup} disabled={loading || !resourceId.trim().startsWith('/subscriptions/')}>
            {loading ? <CircularProgress size={20} /> : 'Look up'}
          </Button>
        </Stack>

        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}

        {result && (
          <Box sx={{ mt: 2.5 }}>
            <Stack direction="row" spacing={1} sx={{ mb: 2, flexWrap: 'wrap', rowGap: 1 }}>
              <Chip label={`${result.summary.assignments} assignment(s)`} size="small" />
              <Chip label={`${result.summary.non_compliant} non-compliant`} size="small"
                color={result.summary.non_compliant ? 'error' : 'default'} />
              <Chip label={`${result.summary.exempt} exempt`} size="small" />
              <Chip label={nonCompliantOnly ? 'Showing non-compliant' : 'Showing all evaluations'} size="small"
                variant="outlined" onClick={() => setNonCompliantOnly(!nonCompliantOnly)} />
            </Stack>

            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Compliance</Typography>
            {result.compliance.length === 0 ? (
              <Typography variant="body2" sx={{ color: alpha('#fff', 0.55), mb: 2 }}>
                No compliance data yet - a new assignment takes 5-30 minutes to evaluate.
              </Typography>
            ) : (
              <Box sx={{ overflowX: 'auto', mb: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow><TableCell>State</TableCell><TableCell>Effect</TableCell><TableCell>Policy</TableCell>
                      <TableCell>Assignment</TableCell></TableRow>
                  </TableHead>
                  <TableBody>
                    {rows.map((r, i) => (
                      <TableRow key={i}>
                        <TableCell><Chip label={r.state} size="small" color={STATE_COLOR[r.state] ?? 'default'} /></TableCell>
                        <TableCell>{r.effect}</TableCell>
                        <TableCell>{r.policy}{r.reference ? ` [${r.reference}]` : ''}</TableCell>
                        <TableCell>{r.assignment}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Box>
            )}

            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
              Scope chain <Typography component="span" variant="caption" sx={{ color: alpha('#fff', 0.5) }}>
                (inheritance is additive; for Deny the most restrictive result wins)</Typography>
            </Typography>
            <Box sx={{ mb: 2 }}>
              {result.scopes.map((level, depth) => (
                <Box key={level.scope} sx={{ pl: depth * 2, py: 0.5 }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }} title={level.scope}>{leaf(level.scope)}</Typography>
                  {level.assignments.map((a) => (
                    <Typography key={a.id} variant="body2" sx={{ pl: 2, color: a.enforced ? undefined : alpha('#fff', 0.5) }}>
                      → {a.name} · {a.initiative ? 'initiative' : 'policy'} · {a.enforced ? 'Enforced' : 'DoNotEnforce'}
                    </Typography>
                  ))}
                </Box>
              ))}
            </Box>

            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Exemptions covering it</Typography>
            {result.exemptions.length === 0 ? (
              <Typography variant="body2" sx={{ color: alpha('#fff', 0.55) }}>None.</Typography>
            ) : result.exemptions.map((e) => (
              <Alert key={`${e.scope}/${e.name}`} sx={{ mb: 1 }}
                severity={e.status === 'never expires' || e.whole_assignment ? 'error' : e.status === 'expired' ? 'info' : 'warning'}>
                <strong>{e.name}</strong> [{e.category ?? 'Waiver'}] at {leaf(e.scope)} — {e.status}
                {e.expiresOn ? ` (${e.expiresOn.slice(0, 10)})` : ''}.{' '}
                {e.whole_assignment ? 'Waives the ENTIRE assignment.' : `Members: ${e.refIds.join(', ')}`}
              </Alert>
            ))}
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

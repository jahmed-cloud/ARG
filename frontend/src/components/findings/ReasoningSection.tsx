/**
 * ReasoningSection — "How ARG reasoned" (built-in thinking, scripts/subscription_analysis/reasoning.py) and the
 * optional AI review (thinking.py, Azure OpenAI in the tenant) for one finding: what was observed, what changes the
 * answer, every option with its role, the recommendation, risks, how to verify and the confidence.
 */
import React from 'react';
import { Box, Chip, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material';
import { useMoney } from '../../hooks/useCurrency';

export interface ReasoningOption {
  option: string;
  role: string;
  run_cost: number | null;
  exposure_after?: string | null;
  why: string;
}

export interface Reasoning {
  observed: string[];
  context: string[];
  considered: ReasoningOption[];
  recommendation: string;
  sequence: string[];
  risks: string[];
  verify: string[];
  confidence: { level: string; why: string };
}

export interface AiReview {
  agree?: boolean;
  recommendation?: string;
  why?: string;
  sequence?: string[];
  risks?: string[];
  questions?: string[];
  model?: string;
  generated_at?: string;
}

const ROLE_COLOR: Record<string, 'success' | 'info' | 'default' | 'warning'> = {
  target: 'success',
  interim: 'info',
  alternative: 'default',
  'not suitable': 'warning',
};

const List: React.FC<{ title: string; items?: string[]; code?: boolean }> = ({ title, items, code }) =>
  items && items.length ? (
    <Box sx={{ mb: 1.25 }}>
      <Typography variant="caption" sx={{ fontWeight: 700, color: 'text.secondary' }}>
        {title}
      </Typography>
      <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
        {items.map((x) => (
          <Typography
            component="li"
            variant="body2"
            key={x}
            sx={code && x.startsWith('az ') ? { fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' } : undefined}
          >
            {x}
          </Typography>
        ))}
      </Box>
    </Box>
  ) : null;

export const ReasoningSection: React.FC<{ reasoning: Reasoning }> = ({ reasoning: r }) => {
  const money = useMoney();
  return (
  <Box>
    <List title="Observed" items={r.observed} />
    <List title="What changes the answer here" items={r.context} />
    {r.considered?.length > 0 && (
      <Box sx={{ mb: 1.25, overflowX: 'auto' }}>
        <Typography variant="caption" sx={{ fontWeight: 700, color: 'text.secondary' }}>
          Options considered
        </Typography>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Role</TableCell>
              <TableCell>Option</TableCell>
              <TableCell align="right">Run cost</TableCell>
              <TableCell>Remaining exposure / why</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {r.considered.map((c) => (
              <TableRow key={c.option} sx={{ opacity: c.role === 'not suitable' ? 0.7 : 1 }}>
                <TableCell>
                  <Chip size="small" label={c.role} color={ROLE_COLOR[c.role] ?? 'default'} variant={c.role === 'target' ? 'filled' : 'outlined'} />
                </TableCell>
                <TableCell sx={{ fontWeight: c.role === 'target' ? 700 : 400 }}>{c.option}</TableCell>
                <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                  {c.run_cost ? `${money.format(c.run_cost, { decimals: 2 })}/month` : 'free'}
                </TableCell>
                <TableCell>
                  {c.exposure_after && (
                    <Typography variant="caption" sx={{ display: 'block', color: 'text.secondary' }}>
                      {c.exposure_after}
                    </Typography>
                  )}
                  <Typography variant="caption">{c.why}</Typography>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Box>
    )}
    {r.recommendation && (
      <Box sx={{ mb: 1.25 }}>
        <Typography variant="caption" sx={{ fontWeight: 700, color: 'text.secondary' }}>
          Recommendation
        </Typography>
        <Typography variant="body2">{r.recommendation}</Typography>
      </Box>
    )}
    <List title="Risks" items={r.risks} />
    <List title="How to verify" items={r.verify} code />
    {r.confidence && (
      <Typography variant="caption" sx={{ color: 'text.secondary' }}>
        <strong>Confidence: {r.confidence.level}</strong> — {r.confidence.why}
      </Typography>
    )}
  </Box>
);
};

export const AiReviewSection: React.FC<{ review: AiReview }> = ({ review: a }) => (
  <Box>
    {a.agree !== undefined && (
      <Chip
        size="small"
        sx={{ mb: 1 }}
        color={a.agree ? 'success' : 'warning'}
        label={a.agree ? 'Agrees with the built-in recommendation' : 'Challenges the built-in recommendation'}
      />
    )}
    {a.recommendation && (
      <Typography variant="body2" sx={{ mb: 1 }}>
        {a.recommendation}
      </Typography>
    )}
    {a.why && (
      <Typography variant="body2" sx={{ mb: 1, color: 'text.secondary' }}>
        {a.why}
      </Typography>
    )}
    <List title="Sequence" items={a.sequence} />
    <List title="Risks" items={a.risks} />
    <List title="Questions for the owner" items={a.questions} />
    {a.model && (
      <Typography variant="caption" sx={{ color: 'text.secondary' }}>
        {a.model}
        {a.generated_at ? ` · ${new Date(a.generated_at).toLocaleString()}` : ''}
      </Typography>
    )}
  </Box>
);

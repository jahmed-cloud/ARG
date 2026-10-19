/**
 * FindingDetailPanel — the expanded body of a row on the Findings page.
 *
 * Loads GET /findings/{id} and shows what the local subscription report shows per finding:
 * description, why the change is needed and when it is not, the cost of implementing it
 * (Azure run cost, effort, net of the saving), remediation, Azure CLI / PowerShell scripts,
 * Microsoft Learn references, the analysis (gap area, savings wave, deep dive, architectural
 * critique), evidence and other findings on the same resource. All Azure-sourced text is
 * rendered as React text nodes (no HTML); reference links only accept https URLs.
 */
import React, { useEffect, useState } from 'react';
import {
  Box,
  Chip,
  Grid,
  IconButton,
  Link,
  Skeleton,
  Tab,
  Tabs,
  Tooltip,
  Typography,
  Alert,
  alpha,
  useTheme,
} from '@mui/material';
import { ContentCopy, OpenInNew } from '@mui/icons-material';
import { useApi, ApiError } from '../../hooks/useApi';
import { useMoney } from '../../hooks/useCurrency';
import { AiReview, AiReviewSection, Reasoning, ReasoningSection } from './ReasoningSection';
import { SEVERITY_COLORS, PALETTE } from '../../theme/ThemeProvider';

interface Critique {
  key: string;
  title: string;
  likely_rationale: string;
  why_it_falls_short: string;
  alternatives: string[];
}

interface Analysis {
  area: string;
  deep_dive: string;
  deep_dive_title: string;
  wave: number;
  wave_name: string;
  critique: Critique | null;
}

interface ResourceContext {
  sku: Record<string, unknown> | null;
  tags: Record<string, string>;
  environment_tag: string | null;
  owner_tag: string | null;
  azure_created_at: string | null;
}

interface RelatedFinding {
  id: string;
  finding_type: string;
  title: string;
  severity: string;
  status: string;
}

interface Reference {
  title: string;
  url: string;
}

interface ImplementationItem {
  label: string;
  why: string;
  skip_when: string;
  effort: string;
  hours: number[];
  monthly_usd: number | null;
  run_cost: string;
}

interface ImplementationOption {
  option: string;
  title: string;
  monthly_usd: number;
  fits: boolean;
  chosen: boolean;
  note: string;
}

interface Implementation {
  source: string;
  why: string;
  skip_when: string;
  effort: string;
  hours: number[] | null;
  monthly_usd: number | null;
  run_cost: string;
  saving_usd: number | null;
  net_monthly_usd: number | null;
  cost_included_in_saving: boolean;
  one_off_usd: number[] | null;
  prices_as_of: string;
  references: Reference[];
  items: ImplementationItem[];
  decision?: { option: string; title: string; why: string; monthly_usd: number } | null;
  options?: ImplementationOption[];
}

interface FindingSubscription {
  name: string | null;
  subscription_id: string | null;
}

export interface FindingDetail {
  id: string;
  finding_type: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  category: string;
  resource_name: string | null;
  resource_type: string | null;
  azure_resource_id: string | null;
  resource_group: string | null;
  location: string | null;
  estimated_monthly_savings_usd: number | null;
  estimated_annual_savings_usd: number | null;
  first_detected_at: string;
  last_detected_at: string;
  resolved_at: string | null;
  suppressed_until: string | null;
  suppression_reason: string | null;
  remediation_steps: string | null;
  evidence: Record<string, unknown>;
  affected_resources: string[];
  caf_control: string | null;
  nist_control: string | null;
  cis_control: string | null;
  azure_cli_script: string | null;
  powershell_script: string | null;
  analysis: Analysis | null;
  implementation: Implementation | null;
  subscription: FindingSubscription | null;
  resource_context: ResourceContext | null;
  related_findings: RelatedFinding[];
  reasoning?: Reasoning | null;
  ai_review?: AiReview | null;
}



// The team's story-point scale (scripts/subscription_analysis/guidance.py STORY_POINTS): effort is planned at the
// smallest point covering its upper hour estimate - a generic estimate of the size of the change, not measured hours.
const STORY_POINTS: [number, number, string, string][] = [
  [1, 4, '0.5 days', '0.03 sprints'], [2, 8, '1 day', '0.07 sprints'], [3, 12, '1.5 days', '0.10 sprints'],
  [5, 20, '2.5 days', '0.17 sprints'], [8, 32, '4 days', '0.27 sprints'], [13, 52, '6.5 days', '0.43 sprints'],
  [21, 84, '10.5 days', '0.70 sprints'], [55, 220, '27.5 days', '2.75 sprints'], [89, 356, '44.5 days', '4.45 sprints'],
];
const hours = (h: number[] | null | undefined) => {
  if (!h || !h.length) return '—';
  const high = h[h.length - 1];
  const row = STORY_POINTS.find(([, scale]) => high <= scale);
  const [points, scale, days, sprints] = row ?? STORY_POINTS[STORY_POINTS.length - 1];
  const more = row ? '' : '+';
  return `${points}${more} SP (${scale}h${more} / ${days} / ${sprints}) (generic estimate)`;
};

const isHttps = (url: string) => /^https:\/\//i.test(url);

/** Per-item list for multi-recommendation (Defender) findings, else the single text. */
const PerItem: React.FC<{ impl: Implementation; field: 'why' | 'skip_when' }> = ({ impl, field }) =>
  impl.items && impl.items.length > 1 ? (
    <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
      {impl.items
        .filter((i) => i[field])
        .map((i) => (
          <Typography component="li" variant="body2" key={i.label} sx={{ mb: 0.75 }}>
            <strong>{i.label.replace(/\.$/, '')}</strong> — {i[field]}
          </Typography>
        ))}
    </Box>
  ) : (
    <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
      {impl[field]}
    </Typography>
  );

const date = (v: string | null | undefined) => (v ? new Date(v).toLocaleString() : '—');

const Section: React.FC<{ title: string; children: React.ReactNode; action?: React.ReactNode }> = ({
  title,
  children,
  action,
}) => (
  <Box sx={{ mb: 2.5 }}>
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.75 }}>
      <Typography variant="overline" sx={{ color: 'text.secondary', fontWeight: 700, letterSpacing: 0.8 }}>
        {title}
      </Typography>
      {action}
    </Box>
    {children}
  </Box>
);

const Field: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
  <Box sx={{ display: 'flex', gap: 1, py: 0.25, minWidth: 0 }}>
    <Typography variant="body2" sx={{ color: 'text.secondary', minWidth: 130, flexShrink: 0 }}>
      {label}
    </Typography>
    <Typography variant="body2" sx={{ wordBreak: 'break-word', minWidth: 0 }}>
      {value ?? '—'}
    </Typography>
  </Box>
);

const CopyButton: React.FC<{ text: string; label: string }> = ({ text, label }) => {
  const [copied, setCopied] = useState(false);
  return (
    <Tooltip title={copied ? 'Copied' : `Copy ${label}`}>
      <IconButton
        size="small"
        aria-label={`Copy ${label}`}
        onClick={() => {
          navigator.clipboard?.writeText(text).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          });
        }}
      >
        <ContentCopy sx={{ fontSize: 16 }} />
      </IconButton>
    </Tooltip>
  );
};

const CodeBlock: React.FC<{ text: string; maxHeight?: number }> = ({ text, maxHeight = 320 }) => {
  const theme = useTheme();
  return (
    <Box
      component="pre"
      sx={{
        m: 0,
        p: 1.5,
        maxHeight,
        overflow: 'auto',
        borderRadius: 1,
        fontSize: 12.5,
        lineHeight: 1.5,
        fontFamily: '"Roboto Mono", Consolas, monospace',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        bgcolor: alpha(theme.palette.text.primary, 0.05),
        border: `1px solid ${alpha(theme.palette.text.primary, 0.08)}`,
      }}
    >
      {text}
    </Box>
  );
};

const SeverityChip: React.FC<{ severity: string }> = ({ severity }) => (
  <Chip
    size="small"
    label={severity.toUpperCase()}
    sx={{
      bgcolor: alpha(SEVERITY_COLORS[severity] ?? PALETTE.grey, 0.15),
      color: SEVERITY_COLORS[severity] ?? PALETTE.grey,
      fontWeight: 700,
      fontSize: 11,
    }}
  />
);

export const FindingDetailPanel: React.FC<{ findingId: string }> = ({ findingId }) => {
  const api = useApi();
  const { format, currency, converted, text: moneyText } = useMoney();
  const money = (v: number | null | undefined) => (v ? format(v, { decimals: 2 }) : '—');
  const runCost = (v: number | null | undefined) =>
    v === null || v === undefined ? 'Usage-based' : v === 0 ? 'No extra cost' : `+${money(v)} / month`;
  const theme = useTheme();
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scriptTab, setScriptTab] = useState<'cli' | 'powershell'>('cli');

  useEffect(() => {
    let cancelled = false;
    setDetail(null);
    setError(null);
    api
      .get(`/findings/${findingId}`)
      .then((data: FindingDetail) => {
        if (cancelled) return;
        setDetail(data);
        setScriptTab(data.azure_cli_script ? 'cli' : 'powershell');
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof ApiError ? e.message : 'Failed to load the finding');
      });
    return () => {
      cancelled = true;
    };
    // api is a new object every render; only the finding ID should trigger a reload
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findingId]);

  if (error) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        {error}
      </Alert>
    );
  }
  if (!detail) {
    return (
      <Box sx={{ p: 2 }}>
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} height={28} />
        ))}
      </Box>
    );
  }

  const analysis = detail.analysis;
  const context = detail.resource_context;
  const script = scriptTab === 'cli' ? detail.azure_cli_script : detail.powershell_script;
  const hasScripts = Boolean(detail.azure_cli_script || detail.powershell_script);
  const evidenceText = JSON.stringify(detail.evidence ?? {}, null, 2);
  const hasEvidence = detail.evidence && Object.keys(detail.evidence).length > 0;
  const controls = [
    detail.cis_control && `CIS ${detail.cis_control}`,
    detail.nist_control && `NIST ${detail.nist_control}`,
    detail.caf_control && `CAF ${detail.caf_control}`,
  ].filter(Boolean) as string[];
  const tags = Object.entries(context?.tags ?? {});
  const sku = context?.sku ? Object.values(context.sku).filter(Boolean).join(' / ') : null;
  const impl = detail.implementation && detail.implementation.source !== 'generic' ? detail.implementation : null;
  const references = (impl?.references ?? []).filter((r) => isHttps(r.url));
  const subscription = detail.subscription;

  return (
    <Box
      sx={{
        p: { xs: 2, md: 3 },
        bgcolor: alpha(theme.palette.primary.main, 0.03),
        borderTop: `1px solid ${alpha(theme.palette.text.primary, 0.08)}`,
      }}
    >
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
        <Chip size="small" variant="outlined" label={detail.finding_type} sx={{ fontFamily: 'monospace' }} />
        <Chip size="small" variant="outlined" label={detail.category} />
        {analysis && <Chip size="small" color="primary" variant="outlined" label={analysis.area} />}
        {analysis && <Chip size="small" color="secondary" variant="outlined" label={analysis.wave_name} />}
        {controls.map((c) => (
          <Chip key={c} size="small" variant="outlined" label={c} />
        ))}
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} lg={7}>
          <Section title="Description">
            <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
              {moneyText(detail.description) || '—'}
            </Typography>
          </Section>

          {impl?.why && (
            <Section title="Why it is needed">
              <PerItem impl={impl} field="why" />
            </Section>
          )}

          {impl?.skip_when && (
            <Section title="When it is not needed">
              <PerItem impl={impl} field="skip_when" />
            </Section>
          )}

          {detail.remediation_steps && (
            <Section title="Remediation">
              <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                {moneyText(detail.remediation_steps)}
              </Typography>
            </Section>
          )}

          {hasScripts && (
            <Section title="Script" action={script ? <CopyButton text={script} label="script" /> : undefined}>
              <Tabs
                value={scriptTab}
                onChange={(_, v) => setScriptTab(v)}
                sx={{ minHeight: 32, mb: 1, '& .MuiTab-root': { minHeight: 32, py: 0.5, fontSize: 12 } }}
              >
                <Tab value="cli" label="Azure CLI" disabled={!detail.azure_cli_script} />
                <Tab value="powershell" label="PowerShell" disabled={!detail.powershell_script} />
              </Tabs>
              {script && <CodeBlock text={script} />}
              <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mt: 0.5 }}>
                Review before running: ARG never runs scripts against Azure.
              </Typography>
            </Section>
          )}

          {references.length > 0 && (
            <Section title="References">
              <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
                {references.map((r) => (
                  <Typography component="li" variant="body2" key={r.url} sx={{ mb: 0.5 }}>
                    <Link href={r.url} target="_blank" rel="noopener noreferrer" underline="hover">
                      {r.title}
                      <OpenInNew sx={{ fontSize: 13, ml: 0.5, verticalAlign: 'text-top' }} />
                    </Link>
                  </Typography>
                ))}
              </Box>
            </Section>
          )}

          {analysis && (
            <Section title="Analysis">
              <Field label="Gap area" value={analysis.area} />
              <Field label="Savings wave" value={analysis.wave_name} />
              <Field label="Deep dive" value={analysis.deep_dive_title} />
              {analysis.critique && (
                <Box
                  sx={{
                    mt: 1.5,
                    p: 1.5,
                    borderRadius: 1,
                    borderLeft: `3px solid ${theme.palette.secondary.main}`,
                    bgcolor: alpha(theme.palette.secondary.main, 0.06),
                  }}
                >
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                    Design decision: {analysis.critique.title}
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    <strong>Likely rationale:</strong> {analysis.critique.likely_rationale}
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    <strong>Why it falls short:</strong> {analysis.critique.why_it_falls_short}
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: 700 }}>
                    What to use instead:
                  </Typography>
                  <Box component="ol" sx={{ mt: 0.5, mb: 0, pl: 2.5 }}>
                    {analysis.critique.alternatives.map((alt) => (
                      <Typography component="li" variant="body2" key={alt} sx={{ mb: 0.5 }}>
                        {alt}
                      </Typography>
                    ))}
                  </Box>
                  <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mt: 1 }}>
                    The rationale is inferred from what was found; confirm it with the workload owners.
                  </Typography>
                </Box>
              )}
            </Section>
          )}

          {hasEvidence && (
            <Section title="Evidence" action={<CopyButton text={evidenceText} label="evidence" />}>
              <CodeBlock text={evidenceText} maxHeight={280} />
            </Section>
          )}
        </Grid>

        <Grid item xs={12} lg={5}>
          {impl && (
            <Section title="Cost of implementation (estimate)">
              <Field label="Azure run cost" value={runCost(impl.monthly_usd)} />
              <Typography variant="caption" sx={{ display: 'block', color: 'text.secondary', mb: 0.75 }}>
                {impl.run_cost}
              </Typography>
              <Field
                label="Effort"
                value={
                  hours(impl.hours) +
                  (impl.one_off_usd ? ` (≈ ${money(impl.one_off_usd[0])}–${money(impl.one_off_usd[1])})` : '')
                }
              />
              {impl.items && impl.items.length > 1 ? (
                <Box component="ul" sx={{ mt: 0.5, mb: 0.75, pl: 2.5 }}>
                  {impl.items.map((i) => (
                    <Typography component="li" variant="caption" key={i.label} sx={{ color: 'text.secondary' }}>
                      {i.label.replace(/\.$/, '')}: {runCost(i.monthly_usd)}, {hours(i.hours)} — {i.effort}
                    </Typography>
                  ))}
                </Box>
              ) : (
                impl.effort && (
                  <Typography variant="caption" sx={{ display: 'block', color: 'text.secondary', mb: 0.75 }}>
                    {impl.effort}
                  </Typography>
                )
              )}
              {impl.saving_usd ? (
                <Field
                  label="Net / month"
                  value={
                    money(impl.net_monthly_usd) +
                    (impl.cost_included_in_saving ? ' (saving already net of the change)' : ' (saving − run cost)')
                  }
                />
              ) : null}
              <Typography variant="caption" sx={{ display: 'block', color: 'text.secondary', mt: 0.5 }}>
                Estimated from USD list prices of {impl.prices_as_of}{converted ? `, shown in ${currency}` : ''}; enterprise agreements and other regions differ.
              </Typography>
            </Section>
          )}

          {detail.reasoning && (
            <Section title="How ARG reasoned">
              <ReasoningSection reasoning={detail.reasoning} />
            </Section>
          )}

          {detail.ai_review && (
            <Section title="AI review (Azure OpenAI)">
              <AiReviewSection review={detail.ai_review} />
            </Section>
          )}

          <Section title="Resource">
            {subscription && (
              <Field
                label="Subscription"
                value={
                  <>
                    {subscription.name ?? '—'}
                    {subscription.subscription_id && (
                      <Box component="span" sx={{ display: 'block', fontFamily: 'monospace', fontSize: 12, color: 'text.secondary' }}>
                        {subscription.subscription_id}
                      </Box>
                    )}
                  </>
                }
              />
            )}
            <Field label="Name" value={detail.resource_name} />
            <Field label="Type" value={detail.resource_type} />
            <Field label="Resource group" value={detail.resource_group} />
            <Field label="Region" value={detail.location} />
            {sku && <Field label="Size / SKU" value={sku} />}
            {context?.environment_tag && <Field label="Environment" value={context.environment_tag} />}
            {context?.owner_tag && <Field label="Owner" value={context.owner_tag} />}
            {context?.azure_created_at && <Field label="Created" value={date(context.azure_created_at)} />}
            {detail.azure_resource_id && (
              <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 0.5, mt: 0.5 }}>
                <Typography
                  variant="caption"
                  sx={{ fontFamily: 'monospace', wordBreak: 'break-all', color: 'text.secondary', pt: 0.5 }}
                >
                  {detail.azure_resource_id}
                </Typography>
                <CopyButton text={detail.azure_resource_id} label="resource ID" />
              </Box>
            )}
            {tags.length > 0 && (
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 1 }}>
                {tags.map(([k, v]) => (
                  <Chip key={k} size="small" label={`${k}: ${v}`} sx={{ fontSize: 11, maxWidth: 260 }} />
                ))}
              </Box>
            )}
          </Section>

          <Section title="Impact & lifecycle">
            <Field label="Saving / month" value={money(detail.estimated_monthly_savings_usd)} />
            <Field label="Saving / year" value={money(detail.estimated_annual_savings_usd)} />
            <Field label="First detected" value={date(detail.first_detected_at)} />
            <Field label="Last detected" value={date(detail.last_detected_at)} />
            {detail.resolved_at && <Field label="Resolved" value={date(detail.resolved_at)} />}
            {detail.suppressed_until && <Field label="Suppressed until" value={date(detail.suppressed_until)} />}
            {detail.suppression_reason && <Field label="Suppression reason" value={detail.suppression_reason} />}
          </Section>

          {detail.affected_resources.length > 0 && (
            <Section title={`Also affected (${detail.affected_resources.length})`}>
              {detail.affected_resources.slice(0, 20).map((r) => (
                <Typography
                  key={r}
                  variant="caption"
                  sx={{ display: 'block', fontFamily: 'monospace', wordBreak: 'break-all', color: 'text.secondary' }}
                >
                  {r}
                </Typography>
              ))}
            </Section>
          )}

          {detail.related_findings.length > 0 && (
            <Section title={`Other findings on this resource (${detail.related_findings.length})`}>
              {detail.related_findings.map((r) => (
                <Box key={r.id} sx={{ display: 'flex', alignItems: 'center', gap: 1, py: 0.5 }}>
                  <SeverityChip severity={r.severity} />
                  <Typography variant="body2" sx={{ minWidth: 0 }} noWrap title={r.title}>
                    {r.title}
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'text.secondary', ml: 'auto', flexShrink: 0 }}>
                    {r.status.replace('_', ' ')}
                  </Typography>
                </Box>
              ))}
            </Section>
          )}
        </Grid>
      </Grid>
    </Box>
  );
};

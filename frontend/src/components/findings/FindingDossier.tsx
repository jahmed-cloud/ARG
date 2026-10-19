/**
 * FindingDossier - ARG's finding detail: a right-hand dossier opened from the Findings and Cost Savings tables.
 *
 * Loads GET /findings/{id} and reads like the Overview page: an eyebrow, the title, a ruled strip of the numbers
 * that matter (severity, saving, net of run cost, effort), then numbered sections - why, when not, what it costs,
 * steps, scripts, how ARG reasoned, the optional AI review, analysis, evidence, resource and related findings.
 * Azure-sourced text is rendered as text nodes only; links accept https URLs only.
 */
import React, { useEffect, useState } from 'react';
import { Drawer, Skeleton } from '@mui/material';
import { Close } from '@mui/icons-material';
import { useApi, ApiError } from '../../hooks/useApi';
import { useMoney } from '../../hooks/useCurrency';
import { SafeLink, SEVERITY_TONE, WsCode, WsFacts, WsList, WsSection, WsStrip, WsMetric } from '../workspace/Workspace';
import '../workspace/workspace.css';
import { AiReview, FindingDetail, Implementation, Reasoning, effortLabel } from './findingTypes';

const fmtDate = (v: string | null | undefined) => (v ? new Date(v).toLocaleDateString() : null);

const ImplementationBlock: React.FC<{ impl: Implementation; money: (v: number | null | undefined) => string }> = ({
  impl, money,
}) => {
  const multi = impl.items && impl.items.length > 1;
  return (
    <>
      {multi ? (
        <ul className="ws-list">
          {impl.items.map((it) => <li key={it.label}><b>{it.label}</b> - {it.why}</li>)}
        </ul>
      ) : <p className="ws-text">{impl.why}</p>}
      {impl.decision && (
        <div className="ws-quote">
          <b>{impl.decision.title}</b> - {impl.decision.why}
          {impl.decision.monthly_usd ? <span className="ws-muted"> ({money(impl.decision.monthly_usd)} / month)</span> : null}
        </div>
      )}
      {impl.options && impl.options.length > 0 && (
        <table className="ws-rows" aria-label="Options considered">
          <thead><tr><th>Option</th><th>Fits</th><th className="num">Run cost / month</th><th>Note</th></tr></thead>
          <tbody>
            {impl.options.map((o) => (
              <tr key={o.option}>
                <td>{o.chosen ? <b>{o.title}</b> : o.title}{o.chosen && <span className="ws-tag on" style={{ marginLeft: 8 }}>chosen</span>}</td>
                <td>{o.fits ? 'yes' : 'no'}</td>
                <td className="num">{money(o.monthly_usd)}</td>
                <td className="ws-muted">{o.note}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
};

const ReasoningBlock: React.FC<{ reasoning: Reasoning; money: (v: number | null | undefined) => string }> = ({
  reasoning, money,
}) => (
  <>
    {reasoning.observed?.length > 0 && <><p className="eyebrow">Observed</p><WsList items={reasoning.observed} /></>}
    {reasoning.context?.length > 0 && <><p className="eyebrow">What changes the answer</p><WsList items={reasoning.context} /></>}
    {reasoning.considered?.length > 0 && (
      <table className="ws-rows" aria-label="Options considered">
        <thead><tr><th>Option</th><th>Role</th><th className="num">Run cost</th><th>Why</th></tr></thead>
        <tbody>
          {reasoning.considered.map((o) => (
            <tr key={o.option}>
              <td>{o.option}</td>
              <td><span className={`ws-tag${o.role === 'target' ? ' on' : ''}`}>{o.role}</span></td>
              <td className="num">{o.run_cost === null ? '—' : money(o.run_cost)}</td>
              <td className="ws-muted">{o.why}{o.exposure_after ? ` Exposure after: ${o.exposure_after}.` : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    )}
    {reasoning.recommendation && <div className="ws-quote">{reasoning.recommendation}</div>}
    {reasoning.sequence?.length > 0 && <><p className="eyebrow">Sequence</p><WsList items={reasoning.sequence} ordered /></>}
    {reasoning.risks?.length > 0 && <><p className="eyebrow">Risks</p><WsList items={reasoning.risks} /></>}
    {reasoning.verify?.length > 0 && <><p className="eyebrow">How to verify</p><WsList items={reasoning.verify} /></>}
    {reasoning.confidence && (
      <p className="ws-text"><span className="ws-tag on">confidence {reasoning.confidence.level}</span>{reasoning.confidence.why}</p>
    )}
  </>
);

const AiReviewBlock: React.FC<{ review: AiReview }> = ({ review }) => (
  <>
    <p className="ws-text">
      <span className={`ws-tag${review.agree ? ' on' : ''}`}>{review.agree ? 'agrees' : 'challenges'}</span>
      {review.model && <span className="ws-muted">{review.model}{review.generated_at ? ` · ${fmtDate(review.generated_at)}` : ''}</span>}
    </p>
    {review.recommendation && <div className="ws-quote">{review.recommendation}</div>}
    {review.why && <p className="ws-text">{review.why}</p>}
    {review.sequence?.length ? <><p className="eyebrow">Sequence</p><WsList items={review.sequence} ordered /></> : null}
    {review.risks?.length ? <><p className="eyebrow">Risks</p><WsList items={review.risks} /></> : null}
    {review.questions?.length ? <><p className="eyebrow">Questions for the owner</p><WsList items={review.questions} /></> : null}
    <p className="ws-text ws-muted">Generated by an AI model from ARG's evidence (GUIDs masked) - review before acting.</p>
  </>
);

export const FindingDossier: React.FC<{ findingId: string | null; onClose: () => void }> = ({ findingId, onClose }) => {
  const api = useApi();
  const { format, text: moneyText } = useMoney();
  const money = (v: number | null | undefined) => (v || v === 0 ? format(v, { decimals: 2 }) : '—');
  const saving = (v: number | null | undefined) => (v ? format(v, { decimals: 2 }) : '—');
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!findingId) return;
    let cancelled = false;
    setDetail(null);
    setError(null);
    api.get(`/findings/${findingId}`)
      .then((d: FindingDetail) => { if (!cancelled) setDetail(d); })
      .catch((e) => { if (!cancelled) setError(e instanceof ApiError ? e.message : 'Could not load the finding'); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findingId]);

  const impl = detail?.implementation ?? null;
  let n = 0;
  const next = () => ++n;
  const evidence = detail ? Object.entries(detail.evidence ?? {}).filter(([, v]) => v !== null && v !== '' && typeof v !== 'object') : [];

  return (
    <Drawer anchor="right" open={!!findingId} onClose={onClose} PaperProps={{ sx: { bgcolor: '#111e19' } }}>
      <div className="dossier" role="dialog" aria-label="Finding dossier">
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
          <p className="eyebrow">Finding · {detail?.finding_type?.replace(/_/g, ' ') ?? '...'}</p>
          <button type="button" className="ws-button" onClick={onClose} aria-label="Close dossier"><Close fontSize="inherit" />Close</button>
        </div>
        {error && <p className="ws-text" role="alert">{error}</p>}
        {!detail && !error && <><Skeleton height={40} /><Skeleton height={90} /><Skeleton height={240} /></>}
        {detail && (
          <>
            <h1>{moneyText(detail.title)}</h1>
            <p className="ws-text ws-muted">
              {detail.resource_name ?? 'Subscription-level finding'}
              {detail.resource_group ? ` · ${detail.resource_group}` : ''}
              {detail.subscription?.name ? ` · ${detail.subscription.name}` : ''}
            </p>
            <WsStrip>
              <WsMetric label="Severity" value={<span style={{ color: SEVERITY_TONE[detail.severity] }}>{detail.severity}</span>} note={detail.status.replace(/_/g, ' ')} />
              <WsMetric label="Saving / month" value={saving(detail.estimated_monthly_savings_usd)} note={detail.estimated_annual_savings_usd ? `${saving(detail.estimated_annual_savings_usd)} / year` : undefined} />
              <WsMetric label="Net of run cost" value={saving(impl?.net_monthly_usd ?? null)} note={impl?.monthly_usd ? `run cost ${money(impl.monthly_usd)} / month` : undefined} />
              <WsMetric label="Effort" value={effortLabel(impl?.hours)} note="generic estimate" />
            </WsStrip>

            <WsSection number={next()} title="What was found">
              <p className="ws-text">{moneyText(detail.description)}</p>
            </WsSection>

            {impl && (
              <>
                <WsSection number={next()} title="Why it matters">
                  <ImplementationBlock impl={impl} money={money} />
                </WsSection>
                <WsSection number={next()} title="When not to">
                  {impl.items && impl.items.length > 1
                    ? <ul className="ws-list">{impl.items.map((it) => <li key={it.label}><b>{it.label}</b> - {it.skip_when}</li>)}</ul>
                    : <p className="ws-text">{impl.skip_when}</p>}
                </WsSection>
                <WsSection number={next()} title="What it costs">
                  <WsFacts rows={[
                    ['Effort', `${impl.effort} (${effortLabel(impl.hours)})`],
                    ['Azure run cost', impl.run_cost],
                    ['One-off', impl.one_off_usd?.length ? impl.one_off_usd.map((v) => money(v)).join(' - ') : null],
                    ['Saving already net', impl.cost_included_in_saving ? 'yes - the saving is after this cost' : null],
                    ['Prices as of', impl.prices_as_of],
                  ]} />
                  {impl.references?.length > 0 && (
                    <ul className="ws-list" style={{ marginTop: 12 }}>
                      {impl.references.map((r) => <li key={r.url}><SafeLink href={r.url}>{r.title}</SafeLink></li>)}
                    </ul>
                  )}
                </WsSection>
              </>
            )}

            {detail.remediation_steps && (
              <WsSection number={next()} title="Steps">
                <WsList items={detail.remediation_steps.split(/\n+/).map((s) => s.replace(/^\s*\d+[.)]\s*/, ''))} ordered />
              </WsSection>
            )}

            {(detail.azure_cli_script || detail.powershell_script) && (
              <WsSection number={next()} title="Scripts - review before running">
                {detail.azure_cli_script && <WsCode label="Azure CLI script" code={detail.azure_cli_script} />}
                {detail.powershell_script && <WsCode label="PowerShell script" code={detail.powershell_script} />}
              </WsSection>
            )}

            {detail.reasoning && (
              <WsSection number={next()} title="How ARG reasoned">
                <ReasoningBlock reasoning={detail.reasoning} money={money} />
              </WsSection>
            )}

            {detail.ai_review && (
              <WsSection number={next()} title="AI review">
                <AiReviewBlock review={detail.ai_review} />
              </WsSection>
            )}

            {detail.analysis && (
              <WsSection number={next()} title="Analysis">
                <WsFacts rows={[
                  ['Gap area', detail.analysis.area],
                  ['Savings wave', detail.analysis.wave_name],
                  ['Deep dive', detail.analysis.deep_dive_title],
                  ['Controls', [detail.caf_control && `CAF ${detail.caf_control}`, detail.cis_control && `CIS ${detail.cis_control}`,
                    detail.nist_control && `NIST ${detail.nist_control}`].filter(Boolean).join(' · ') || null],
                ]} />
                {detail.analysis.critique && (
                  <>
                    <p className="eyebrow" style={{ marginTop: 14 }}>{detail.analysis.critique.title}</p>
                    <p className="ws-text"><span className="ws-muted">Likely rationale. </span>{detail.analysis.critique.likely_rationale}</p>
                    <p className="ws-text"><span className="ws-muted">Why it falls short. </span>{detail.analysis.critique.why_it_falls_short}</p>
                    <WsList items={detail.analysis.critique.alternatives} />
                  </>
                )}
              </WsSection>
            )}

            {evidence.length > 0 && (
              <WsSection number={next()} title="Evidence">
                <WsFacts rows={evidence.map(([k, v]) => [k.replace(/_/g, ' '), moneyText(String(v))])} />
              </WsSection>
            )}

            <WsSection number={next()} title="Resource">
              <WsFacts rows={[
                ['Resource ID', detail.azure_resource_id],
                ['Type', detail.resource_type],
                ['Location', detail.location],
                ['Environment tag', detail.resource_context?.environment_tag ?? null],
                ['Owner tag', detail.resource_context?.owner_tag ?? null],
                ['Created', fmtDate(detail.resource_context?.azure_created_at)],
                ['First detected', fmtDate(detail.first_detected_at)],
                ['Last detected', fmtDate(detail.last_detected_at)],
                ['Suppressed until', fmtDate(detail.suppressed_until)],
                ['Affected resources', detail.affected_resources?.length ? detail.affected_resources.join(', ') : null],
              ]} />
            </WsSection>

            {detail.related_findings?.length > 0 && (
              <WsSection number={next()} title="Other findings on this resource">
                <ul className="ws-list">
                  {detail.related_findings.map((r) => (
                    <li key={r.id}>
                      <span style={{ color: SEVERITY_TONE[r.severity] }}>{r.severity}</span> · {moneyText(r.title)}
                      <span className="ws-muted"> ({r.status.replace(/_/g, ' ')})</span>
                    </li>
                  ))}
                </ul>
              </WsSection>
            )}
          </>
        )}
      </div>
    </Drawer>
  );
};

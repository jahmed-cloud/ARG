/**
 * Workspace building blocks - the ARG Overview page's design language for every analysis screen
 * (Estate, Analysis, Architecture, finding dossier, settings): eyebrow + heading, a ruled summary strip,
 * flat panels and numbered sections. Styles: workspace.css.
 */
import React, { useState } from 'react';
import { ContentCopy, Check } from '@mui/icons-material';
import './workspace.css';

export const WsPage: React.FC<{ children: React.ReactNode; label?: string }> = ({ children, label }) => (
  <div className="ws" aria-label={label}>{children}</div>
);

export const WsHeading: React.FC<{
  eyebrow: string; title: string; subtitle?: string; intro?: React.ReactNode; actions?: React.ReactNode;
}> = ({ eyebrow, title, subtitle, intro, actions }) => (
  <header className="ws-heading">
    <div>
      <p className="eyebrow">{eyebrow}</p>
      <h1>{title}{subtitle && <><br /><span>{subtitle}</span></>}</h1>
      {intro && <p>{intro}</p>}
    </div>
    {actions && <div className="ws-actions">{actions}</div>}
  </header>
);

export const WsStrip: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="ws-strip">{children}</div>
);

export const WsMetric: React.FC<{ label: string; value: React.ReactNode; note?: React.ReactNode }> = ({
  label, value, note,
}) => (
  <div className="ws-metric"><span>{label}</span><strong>{value}</strong>{note && <small>{note}</small>}</div>
);

export const WsPanel: React.FC<{
  eyebrow?: string; title?: string; actions?: React.ReactNode; children: React.ReactNode;
}> = ({ eyebrow, title, actions, children }) => (
  <section className="ws-panel">
    {(eyebrow || title || actions) && (
      <div className="ws-panel-heading">
        <div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}{title && <h2>{title}</h2>}</div>
        {actions}
      </div>
    )}
    {children}
  </section>
);

/** Numbered dossier section: "03 / WHAT IT COSTS". */
export const WsSection: React.FC<{ number: number; title: string; children: React.ReactNode }> = ({
  number, title, children,
}) => (
  <section className="ws-section">
    <h3><b>{String(number).padStart(2, '0')}</b>{title}</h3>
    {children}
  </section>
);

export const WsFacts: React.FC<{ rows: [string, React.ReactNode][] }> = ({ rows }) => {
  const shown = rows.filter(([, v]) => v !== null && v !== undefined && v !== '');
  if (!shown.length) return <p className="ws-text ws-muted">Nothing recorded.</p>;
  return (
    <dl className="ws-facts">
      {shown.map(([k, v]) => <React.Fragment key={k}><dt>{k}</dt><dd>{v}</dd></React.Fragment>)}
    </dl>
  );
};

export const WsList: React.FC<{ items?: (string | null | undefined)[] | null; ordered?: boolean }> = ({
  items, ordered,
}) => {
  const rows = (items ?? []).filter(Boolean) as string[];
  if (!rows.length) return null;
  return ordered
    ? <ol className="ws-steps">{rows.map((t, i) => <li key={i}><span>{t}</span></li>)}</ol>
    : <ul className="ws-list">{rows.map((t, i) => <li key={i}>{t}</li>)}</ul>;
};

export const WsEmpty: React.FC<{ title: string; children?: React.ReactNode }> = ({ title, children }) => (
  <div className="ws-empty"><div className="rule" /><p>{title}</p>{children && <small>{children}</small>}</div>
);

export const WsCode: React.FC<{ label: string; code: string }> = ({ label, code }) => {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch { /* clipboard blocked: the text stays selectable */ }
  };
  return (
    <div className="ws-code" aria-label={label}>
      <pre>{code}</pre>
      <button type="button" className="ws-button" onClick={copy} aria-label={`Copy ${label}`}>
        {copied ? <Check fontSize="inherit" /> : <ContentCopy fontSize="inherit" />}{copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  );
};

/** https links only - everything else is shown as plain text. */
export const SafeLink: React.FC<{ href: string; children: React.ReactNode }> = ({ href, children }) =>
  /^https:\/\//i.test(href)
    ? <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>
    : <span>{children}</span>;

export const SEVERITY_TONE: Record<string, string> = {
  critical: '#ee8278', high: '#f0b56d', medium: '#e5d48c', low: '#81c8e6', info: '#a9b4bb',
};

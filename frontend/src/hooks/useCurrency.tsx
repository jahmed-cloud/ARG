/**
 * Currency for every amount the UI shows. ARG stores savings and costs in USD; the Currency dropdown in the top
 * bar picks what they are shown in:
 * - "billing" (default): the Azure invoice's billing currency (e.g. CHF) at the rate Cost Management itself applies
 *   (billing cost / USD cost of the amortized cost over the last 30 days, recorded by each estate refresh);
 * - USD, or any other currency at the European Central Bank's reference rate (GET /dashboard/currency).
 * The choice is remembered per browser; Settings → Analysis Settings → "Currency shown" sets the default.
 */
import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { useApi } from './useApi';

export interface DisplayCurrency {
  currency: string;
  per_usd: number;
  basis?: string;
  as_of?: string;
}

export interface CurrencyOption {
  code: string;
  label: string;
}

interface CurrencyResponse extends DisplayCurrency {
  default?: string;
  billing?: { currency: string; per_usd: number } | null;
  options?: CurrencyOption[];
  reference?: { per_usd: Record<string, number>; date?: string | null; source?: string | null };
}

interface CurrencyState {
  value: DisplayCurrency;
  selected: string;
  options: CurrencyOption[];
  select: (code: string) => void;
  referenceDate?: string | null;
  /** {currency: units per USD} texts can be written in: USD and the billing currency */
  sources: Record<string, number>;
}

const STORAGE_KEY = 'arg.currency';
const USD: DisplayCurrency = { currency: 'USD', per_usd: 1, basis: 'amounts in US dollars' };
const DEFAULT_OPTIONS: CurrencyOption[] = [
  { code: 'billing', label: "Billing currency (each subscription's own)" },
  { code: 'USD', label: 'USD - US dollar' },
];
const CurrencyContext = createContext<CurrencyState>({
  value: USD,
  selected: 'billing',
  options: DEFAULT_OPTIONS,
  select: () => undefined,
  sources: { USD: 1 },
});

function stored(): string | null {
  try {
    return window.localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

export const CurrencyProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const api = useApi();
  const [server, setServer] = useState<CurrencyResponse | null>(null);
  const [selected, setSelected] = useState<string>(() => stored() ?? 'billing');

  useEffect(() => {
    if (!api.accessToken) return;
    api
      .get('/dashboard/currency')
      .then((c: CurrencyResponse) => {
        setServer(c);
        if (!stored() && c?.default) setSelected(c.default);
      })
      .catch(() => setServer(null));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api.accessToken]);

  const select = useCallback((code: string) => {
    setSelected(code);
    try {
      window.localStorage.setItem(STORAGE_KEY, code);
    } catch {
      /* private window: the choice lasts for this page only */
    }
  }, []);

  const value = useMemo<DisplayCurrency>(() => {
    if (selected === 'billing') {
      const b = server?.billing;
      return b && b.per_usd > 0
        ? { currency: b.currency, per_usd: b.per_usd, basis: server?.basis }
        : USD;
    }
    if (selected === 'USD') return USD;
    const rate = server?.reference?.per_usd?.[selected];
    return rate
      ? { currency: selected, per_usd: rate, basis: `${server?.reference?.source} of ${server?.reference?.date}` }
      : USD;
  }, [selected, server]);

  const state = useMemo<CurrencyState>(
    () => ({
      value,
      selected,
      options: server?.options?.length ? server.options : DEFAULT_OPTIONS,
      select,
      referenceDate: server?.reference?.date,
      sources: {
        USD: 1,
        ...(server?.billing && server.billing.per_usd > 0 ? { [server.billing.currency]: server.billing.per_usd } : {}),
      },
    }),
    [value, selected, server, select],
  );
  return <CurrencyContext.Provider value={state}>{children}</CurrencyContext.Provider>;
};

/** The Currency dropdown's state: what is selected, the choices, and select(code). */
export function useCurrencyChoice() {
  return useContext(CurrencyContext);
}

export interface MoneyOptions {
  decimals?: number;
  empty?: string;
}

const NUMBER = String.raw`\d[\d,]*(?:\.\d+)?`;

function reformat(number: string, factor: number): string {
  const decimals = number.includes('.') ? number.split('.')[1].length : 0;
  return (Number(number.replace(/,/g, '')) * factor).toLocaleString('en-US', {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

/**
 * format(usd) -> "CHF 1,234"; convert(usd) -> the amount in the display currency; text(s) -> the amounts written
 * inside a finding title or description ("USD 7.30/month", "CHF 1,418/30d") in the display currency.
 */
export function useMoney() {
  const { value: c, sources } = useContext(CurrencyContext);
  const convert = useCallback((usd: number) => usd * c.per_usd, [c]);
  const text = useCallback(
    (value: string | null | undefined): string => {
      if (!value) return value ?? '';
      const codes = Object.keys(sources).filter((code) => code !== c.currency);
      if (!codes.length) return value;
      const alt = codes.join('|');
      const factor = (code: string) => c.per_usd / sources[code];
      return value
        .replace(
          new RegExp(String.raw`(?<![A-Za-z])(${alt})\s?(${NUMBER})(?![\w])(?:\s?([-–])\s?(${NUMBER})(?![\w]))?`, 'g'),
          (_m, code: string, a: string, dash?: string, b?: string) =>
            `${c.currency} ${reformat(a, factor(code))}${b ? `${dash}${reformat(b, factor(code))}` : ''}`,
        )
        .replace(
          new RegExp(String.raw`(?<![\w.,])(${NUMBER}) (${alt})\b`, 'g'),
          (_m, a: string, code: string) => `${reformat(a, factor(code))} ${c.currency}`,
        );
    },
    [c, sources],
  );
  const format = useCallback(
    (usd: number | null | undefined, opts: MoneyOptions = {}) => {
      if (usd === null || usd === undefined || Number.isNaN(usd)) return opts.empty ?? '—';
      const decimals = opts.decimals ?? 0;
      try {
        return new Intl.NumberFormat(undefined, {
          style: 'currency',
          currency: c.currency,
          currencyDisplay: 'code', // "USD 1,234" / "CHF 1,234" - never a bare "$"
          minimumFractionDigits: decimals,
          maximumFractionDigits: decimals,
        }).format(usd * c.per_usd);
      } catch {
        return `${(usd * c.per_usd).toFixed(decimals)} ${c.currency}`;
      }
    },
    [c],
  );
  return useMemo(
    () => ({ format, convert, text, currency: c.currency, perUsd: c.per_usd, basis: c.basis, converted: c.currency !== 'USD' }),
    [format, convert, text, c],
  );
}

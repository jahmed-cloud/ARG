"""
The currency amounts are shown in.

Default: each subscription's billing currency (CHF, EUR, ...) at the rate Cost Management itself applies. ARG
computes savings and implementation costs in USD (Azure Retail Prices and Cost Management's CostUSD); Cost Management
returns every cost in both the billing currency and USD, so the rate the invoice uses is billing cost / USD cost over
the last 30 days of amortized cost (collector: cost["usd_to_billing"]; exchange_rate() for the Docker estate).

Any other currency the viewer picks in the Currency dropdown: USD amounts are converted with the European Central
Bank's euro reference rates (reference_rates(); public, no key, published every working day), billing-currency
amounts through USD at the subscription's own Cost Management rate - so the invoice amounts stay consistent.
"""

import re
import threading
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from xml.etree import ElementTree

USD = {"currency": "USD", "per_usd": 1.0, "basis": "amounts in US dollars"}
BILLING = "billing"   # the dropdown's default: every subscription in its own billing currency
ECB_URL = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml"
RATES_TTL_SECONDS = 12 * 3600
RATES_RETRY_SECONDS = 600   # after a failed download, offer billing / USD only for 10 minutes before trying again
CURRENCY_NAMES = {
    "USD": "US dollar", "EUR": "Euro", "CHF": "Swiss franc", "GBP": "Pound sterling", "JPY": "Japanese yen",
    "CNY": "Chinese yuan", "INR": "Indian rupee", "SEK": "Swedish krona", "NOK": "Norwegian krone",
    "DKK": "Danish krone", "PLN": "Polish zloty", "CZK": "Czech koruna", "HUF": "Hungarian forint",
    "RON": "Romanian leu", "TRY": "Turkish lira", "AUD": "Australian dollar", "CAD": "Canadian dollar",
    "NZD": "New Zealand dollar", "SGD": "Singapore dollar", "HKD": "Hong Kong dollar", "KRW": "South Korean won",
    "BRL": "Brazilian real", "MXN": "Mexican peso", "ZAR": "South African rand", "ILS": "Israeli shekel",
    "IDR": "Indonesian rupiah", "MYR": "Malaysian ringgit", "PHP": "Philippine peso", "THB": "Thai baht",
    "ISK": "Icelandic krona", "BGN": "Bulgarian lev",
}
FIRST = ("USD", "EUR", "CHF", "GBP")
_NUMBER = r"\d[\d,]*(?:\.\d+)?"
# 'USD 7.30', '+USD 7.30', 'USD 1,000-2,000' - not 'CostUSD' and not 'USD list price'
_USD_AMOUNT = re.compile(rf"(?<![A-Za-z])USD\s?({_NUMBER})(?![\w])(?:\s?([-–])\s?({_NUMBER}))?")
_RATES: Dict[str, Any] = {"at": 0.0, "value": None, "failed_at": 0.0}
_RATES_LOCK = threading.Lock()


def reference_rates(timeout: float = 10.0) -> Optional[Dict[str, Any]]:
    """{"date", "source", "per_usd": {code: units per USD}} from the ECB euro reference rates, cached 12 h. None when
    the download fails (then only the billing currency and USD can be shown)."""
    with _RATES_LOCK:
        now = time.time()
        if _RATES["value"] and now - _RATES["at"] < RATES_TTL_SECONDS:
            return _RATES["value"]
        if now - _RATES["failed_at"] < RATES_RETRY_SECONDS:
            return _RATES["value"]   # stale rates (or none) rather than another timeout per page
        try:
            request = urllib.request.Request(ECB_URL, headers={"User-Agent": "azure-resource-guardian"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                root = ElementTree.fromstring(response.read())
            per_eur = {"EUR": 1.0}
            date = ""
            for node in root.iter():
                if node.get("time"):
                    date = node.get("time")
                if node.get("currency") and node.get("rate"):
                    per_eur[node.get("currency")] = float(node.get("rate"))
            usd = per_eur["USD"]
            _RATES.update(at=now, value={"date": date, "source": "European Central Bank euro reference rates",
                                         "per_usd": {code: rate / usd for code, rate in per_eur.items()}})
        except Exception:
            _RATES["failed_at"] = now
        return _RATES["value"]


def options(rates: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
    """The Currency dropdown: billing currency (per subscription), USD, then every reference-rate currency."""
    codes = sorted(((rates or {}).get("per_usd") or {}).keys() | {"USD"},
                   key=lambda c: (FIRST.index(c) if c in FIRST else len(FIRST), c))
    return [{"code": BILLING, "label": "Billing currency (each subscription's own)"}] + [
        {"code": c, "label": f"{c} - {CURRENCY_NAMES[c]}" if c in CURRENCY_NAMES else c} for c in codes]


def _format(value: float, decimals: int) -> str:
    return f"{value:,.{decimals}f}"


class Converter:
    """
    Amounts in the currency the viewer picked. BILLING leaves each subscription in its own billing currency (pages
    are written that way); any other code converts USD amounts with the reference rate and billing-currency amounts
    through USD at the subscription's own Cost Management rate.
    """

    def __init__(self, target: Optional[str] = None, rates: Optional[Dict[str, Any]] = None):
        self.reference = (rates or {}).get("per_usd") or {}
        target = BILLING if (target or BILLING).lower() == BILLING else str(target).upper()
        if target not in (BILLING, "USD") and target not in self.reference:
            target = BILLING   # no rate for it (offline): fall back rather than show wrong numbers
        self.target = target

    @property
    def active(self) -> bool:
        return self.target != BILLING

    def per_usd(self, code: str) -> Optional[float]:
        return 1.0 if code == "USD" else self.reference.get(code)

    def from_usd(self, usd: Optional[float], billing_currency: str = "",
                 billing_per_usd: Optional[float] = None) -> Tuple[Optional[float], str]:
        if usd is None:
            return None, self.target if self.active else (billing_currency or "USD")
        if not self.active:
            if billing_per_usd and billing_currency and billing_currency != "USD":
                return usd * billing_per_usd, billing_currency
            return usd, "USD"
        return usd * (self.per_usd(self.target) or 1.0), self.target

    def from_billing(self, amount: Optional[float], currency: str,
                     per_usd: Optional[float] = None) -> Tuple[Optional[float], str]:
        """A billing-currency amount (units of `currency`, `per_usd` of them per USD) in the target currency."""
        if amount is None or not self.active or not currency or currency == self.target:
            return amount, currency
        rate = per_usd or self.per_usd(currency)
        if not rate:
            return amount, currency   # cannot convert - shown as it is, with its own currency
        return amount / rate * (self.per_usd(self.target) or 1.0), self.target

    def money(self, amount: Optional[float], currency: str, per_usd: Optional[float] = None,
              decimals: int = 0, empty: str = "-") -> str:
        value, code = self.from_billing(amount, currency, per_usd)
        return empty if value is None else f"{_format(value, decimals)} {code}".strip()

    def text(self, text: str, known: Optional[Dict[str, float]] = None) -> str:
        """
        Every amount on a page ('CHF 5.90/month', '91 CHF', 'USD 1,000-2,000', 'cost CHF 30d: 424.9') converted to
        the target. `known` = {currency: units per USD} the page was written with (its subscriptions' Cost
        Management rates); only those codes and USD are touched, so other three-letter words never are.
        """
        if not self.active or not text:
            return text
        rates = {"USD": 1.0, **{c: r for c, r in (known or {}).items() if c and r}}
        codes = "|".join(sorted((c for c in rates if c != self.target), key=len, reverse=True))
        if not codes:
            return text
        target_rate = self.per_usd(self.target) or 1.0

        def conv(number: str, code: str) -> str:
            value = float(number.replace(",", "")) / rates[code] * target_rate
            return _format(value, len(number.split(".")[1]) if "." in number else 0)

        text = re.sub(rf"\b({codes})((?: [a-z0-9]+)+): ({_NUMBER})\b",
                      lambda m: f"{self.target}{m.group(2)}: {conv(m.group(3), m.group(1))}", text)
        text = re.sub(rf"\(({codes})\): ({_NUMBER})", lambda m: f"({self.target}): {conv(m.group(2), m.group(1))}", text)
        text = re.sub(rf"(?<![A-Za-z])({codes})\s?({_NUMBER})(?![\w])(?:\s?([-–])\s?({_NUMBER})(?![\w]))?",
                      lambda m: f"{self.target} {conv(m.group(2), m.group(1))}"
                                + (f"{m.group(3)}{conv(m.group(4), m.group(1))}" if m.group(4) else ""), text)
        return re.sub(rf"(?<![\w.,])({_NUMBER}) ({codes})\b",
                      lambda m: f"{conv(m.group(1), m.group(2))} {self.target}", text)


def _convert(number: str, per_usd: float) -> str:
    value = float(number.replace(",", "")) * per_usd
    decimals = len(number.split(".")[1]) if "." in number else 0
    return f"{value:,.{decimals}f}"


def localise_amounts(text: str, per_usd: Optional[float], currency: str) -> str:
    """
    A report page in the subscription's billing currency. ARG prices in USD (Azure Retail Prices, CostUSD); the page
    shows each amount converted at the subscription's own rate (amortized billing cost / USD cost, last 30 days):
    'USD 7.30/month' -> 'CHF 5.90/month'; '91 CHF (USD 113)' -> '91 CHF'. Unchanged when the billing currency is
    USD or unknown.
    """
    if not text or not per_usd or not currency or currency.upper() == "USD":
        return text
    cur = re.escape(currency)
    # an amount already in the billing currency followed by its USD equivalent: keep the billing amount only
    text = re.sub(rf"({_NUMBER} {cur}) \((?:≈ )?USD {_NUMBER}\)", r"\1", text)
    text = _USD_AMOUNT.sub(lambda m: f"{currency} {_convert(m.group(1), per_usd)}"
                           + (f"{m.group(2)}{_convert(m.group(3), per_usd)}" if m.group(3) else ""), text)
    # '2,483 USD/yr' and evidence lines 'cost, 30 days (USD): 1,754'
    text = re.sub(rf"({_NUMBER}) USD\b", lambda m: f"{_convert(m.group(1), per_usd)} {currency}", text)
    text = re.sub(rf"\(USD\): ({_NUMBER})", lambda m: f"({currency}): {_convert(m.group(1), per_usd)}", text)
    # evidence fields 'amortized cost usd 30d: 531.1'
    text = re.sub(rf"\b((?:[a-z]+ )*)usd((?: [a-z0-9]+)*): ({_NUMBER})\b",
                  lambda m: f"{m.group(1)}{currency}{m.group(2)}: {_convert(m.group(3), per_usd)}", text)
    return re.sub(r"\bUSD list (prices?)( of [\d-]+)?(?!, shown in)", rf"USD list \1\2, shown in {currency}", text)


def exchange_rate(costs: Iterable[Optional[Dict[str, Dict[str, Any]]]]) -> Optional[Dict[str, Any]]:
    """{"currency", "per_usd", "basis", "as_of"} from per-resource cost rows ({"cost", "cost_usd", "currency"}) of
    one or more subscriptions; the currency with the most spend wins. None when no row has both amounts."""
    totals: Dict[str, list] = defaultdict(lambda: [0.0, 0.0])
    for rows in costs:
        for entry in (rows or {}).values():
            cost, usd = entry.get("cost"), entry.get("cost_usd")
            if cost and usd:
                t = totals[(entry.get("currency") or "").upper()]
                t[0] += float(cost)
                t[1] += float(usd)
    totals.pop("", None)
    if not totals:
        return None
    currency, (billing, usd) = max(totals.items(), key=lambda kv: kv[1][1])
    if usd <= 0:
        return None
    return {"currency": currency, "per_usd": round(billing / usd, 6),
            "basis": f"Cost Management, last 30 days: {billing:,.0f} {currency} = {usd:,.0f} USD",
            "as_of": datetime.now(timezone.utc).isoformat()}


def display(fx: Optional[Dict[str, Any]], preference: str = "Billing currency") -> Dict[str, Any]:
    """What the UI shows: the billing currency (when known) unless the setting asks for USD."""
    if preference == "USD" or not fx or not fx.get("per_usd"):
        return dict(USD)
    return {k: fx[k] for k in ("currency", "per_usd", "basis", "as_of") if k in fx}

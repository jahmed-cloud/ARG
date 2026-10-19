"""
Thinking mode - deep step (optional, setting `ai_reasoning`): an Azure OpenAI model in the company's own tenant
reviews the subscription's analysis like a principal cloud architect would - challenges ARG's built-in
recommendations (reasoning.py) where the evidence says otherwise, finds themes across findings and asks the owner
what the data cannot answer. Never generic: it only sees this subscription's facts and is told to cite them.

What is sent: the subscription's name, environment and management-group path, its cost by service, and the top
findings (type, title, severity, resource name and type, evidence facts, the built-in recommendation and options).
GUIDs (subscription, tenant, principal IDs) are replaced by aliases, tag values and secrets are never included.
Where: only to the configured endpoint (https://<name>.openai.azure.com or *.cognitiveservices.azure.com /
*.services.ai.azure.com), authenticated with Entra ID (the az login session locally, the service principal in
Docker - it needs the "Cognitive Services OpenAI User" role on the resource) or the ARG_AOAI_API_KEY environment
variable. Cost: one request per subscription, typically 6-15k input and 2-4k output tokens.

The result is data.thinking (README section, 05-deep-dive/thinking.md) and finding["ai_review"] (deep dives,
raw/findings.json; the Docker worker copies it to the finding's evidence so the finding detail shows it).
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from scripts.subscription_analysis import reasoning
from scripts.subscription_analysis.ai_prompt import IdMasker

logger = logging.getLogger(__name__)

API_VERSION = "2024-10-21"
SCOPE = "https://cognitiveservices.azure.com/.default"
ALLOWED_ENDPOINT = re.compile(r"^https://[a-z0-9][a-z0-9-]{1,62}\.(openai\.azure\.com|cognitiveservices\.azure\.com|"
                              r"services\.ai\.azure\.com)/?$", re.IGNORECASE)
DEPLOYMENT = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
HYGIENE = {"missing_required_tags", "naming_convention_violation", "tag_key_typo", "environment_tag_name_mismatch"}
MAX_EVIDENCE_CHARS = 700

SYSTEM_PROMPT = """You are a Principal Cloud Solution Architect reviewing one Azure subscription for the organisation that runs ARG.
You receive a case file (JSON) produced by ARG, a read-only analysis tool: subscription facts, cost by service,
and findings, each with the evidence read from Azure and ARG's built-in recommendation and the options it
considered.

Rules:
1. Never give generic advice ("follow best practices", "enable Defender", "consider monitoring", "review
   regularly"). Every sentence must name a resource, a number or a fact from the case file.
2. Recommend the target architecture (Azure Well-Architected Framework, Cloud Adoption Framework landing zones)
   first, with interim steps where the target needs prerequisites. Cost informs the order, it does not decide.
3. Challenge the built-in recommendation when the evidence points elsewhere: set "agree" to false and explain with
   the evidence. Agree briefly when it is right; do not repeat it.
4. Find themes: the same root cause behind several findings (one fix, many findings), sequencing dependencies,
   and risks the built-in rules cannot see by looking at one resource at a time.
5. Do not invent resources, numbers or configuration. When information is missing, ask the owner a precise
   question instead.
6. Answer with JSON only, exactly this shape:
{"summary": "3-6 sentences, specific to this subscription",
 "themes": [{"title": "...", "evidence": "...", "recommendation": "...", "keys": ["K1", "K4"]}],
 "findings": [{"key": "K1", "agree": true, "recommendation": "...", "why": "...",
               "sequence": ["..."], "risks": ["..."], "questions": ["..."]}],
 "questions_for_owner": ["..."]}
Include an entry in "findings" only where you add something the built-in recommendation does not say."""


def settings_ready(settings: Dict[str, Any]) -> Tuple[bool, str]:
    """(enabled and valid, reason when not)."""
    if not settings.get("ai_reasoning"):
        return False, "switched off (setting ai_reasoning)"
    endpoint = (settings.get("ai_endpoint") or "").strip()
    deployment = (settings.get("ai_deployment") or "").strip()
    if not ALLOWED_ENDPOINT.match(endpoint):
        return False, ("ai_endpoint must be an Azure OpenAI / AI Services endpoint such as "
                       "https://<name>.openai.azure.com")
    if not DEPLOYMENT.match(deployment):
        return False, "ai_deployment must be the model deployment name (letters, digits, . _ -)"
    return True, ""


def _pick(findings: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    candidates = [f for f in findings if f.get("finding_type") not in HYGIENE]
    candidates.sort(key=lambda f: (SEVERITY_RANK.get(f.get("severity") or "info", 5),
                                   -float(f.get("estimated_monthly_savings_usd") or 0)))
    return candidates[:limit]


def _evidence_text(finding: Dict[str, Any]) -> str:
    facts = reasoning.observed_facts(finding)
    text = "; ".join(facts)
    return text if len(text) <= MAX_EVIDENCE_CHARS else text[:MAX_EVIDENCE_CHARS - 1] + "…"


def build_case(subscription: Dict[str, Any], findings: List[Dict[str, Any]], *, cost: Dict[str, Any],
               limit: int = 30) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]:
    """The case file (GUIDs masked) and {key: finding} to map the answer back."""
    mask = IdMasker()
    picked = _pick(findings, limit)
    keys: Dict[str, Dict[str, Any]] = {}
    items = []
    for i, f in enumerate(picked, 1):
        key = f"K{i}"
        keys[key] = f
        r = f.get("reasoning") or reasoning.reason(f)
        items.append({
            "key": key, "type": f.get("finding_type"), "severity": f.get("severity"), "title": mask(f.get("title") or ""),
            "resource": mask(f.get("resource_name") or (f.get("resource_id") or "").split("/")[-1]),
            "resource_type": f.get("resource_type"), "saving_usd_month": f.get("estimated_monthly_savings_usd"),
            "evidence": mask(_evidence_text(f)),
            "built_in_recommendation": mask((r.get("recommendation") or "")[:600]),
            "options": [{"option": c.get("option"), "role": c.get("role"), "run_cost": c.get("run_cost")}
                        for c in (r.get("considered") or [])][:6],
            "context": [mask(c) for c in (r.get("context") or [])][:4],
        })
    services = (cost.get("last30_by_rg_service") or [])
    by_service: Dict[str, float] = {}
    for row in services:
        by_service[row.get("ServiceName") or "?"] = by_service.get(row.get("ServiceName") or "?", 0.0) + \
            float(row.get("Cost") or 0)
    case = {
        "subscription": {"name": subscription.get("name"), "environment": subscription.get("environment"),
                         "management_group_path": subscription.get("management_group_path")},
        "cost_last_30_days": {"currency": cost.get("currency"),
                              "by_service": dict(sorted(by_service.items(), key=lambda kv: -kv[1])[:10])},
        "findings_total": len(findings), "findings_shown": len(items), "findings": items,
    }
    return case, keys


async def _token(credential: Any) -> str:
    import asyncio

    token = await asyncio.to_thread(credential.get_token, SCOPE)
    return token.token


async def call_model(endpoint: str, deployment: str, case: Dict[str, Any], credential: Any,
                     timeout: float = 180.0) -> Dict[str, Any]:
    """One chat-completions request; returns {"answer": dict, "usage": dict}."""
    import httpx

    url = f"{endpoint.rstrip('/')}/openai/deployments/{deployment}/chat/completions?api-version={API_VERSION}"
    key = os.environ.get("ARG_AOAI_API_KEY")
    headers = {"Content-Type": "application/json"}
    if key:
        headers["api-key"] = key
    else:
        headers["Authorization"] = f"Bearer {await _token(credential)}"
    body = {"messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": json.dumps(case, ensure_ascii=False)}],
            "response_format": {"type": "json_object"}, "temperature": 0.2, "max_tokens": 4000}
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(url, headers=headers, json=body)
    if response.status_code >= 400:
        detail = response.text[:300]
        raise RuntimeError(f"Azure OpenAI returned {response.status_code}: {detail}")
    payload = response.json()
    content = ((payload.get("choices") or [{}])[0].get("message") or {}).get("content") or "{}"
    return {"answer": json.loads(content), "usage": payload.get("usage") or {}}


async def think(subscription: Dict[str, Any], findings: List[Dict[str, Any]], cost: Dict[str, Any],
                settings: Dict[str, Any], credential: Any) -> Dict[str, Any]:
    """Run the AI review when it is switched on; attaches finding["ai_review"]. Never raises."""
    ready, why_not = settings_ready(settings)
    if not ready:
        return {"status": "off" if not settings.get("ai_reasoning") else "error", "reason": why_not}
    limit = int(settings.get("ai_max_findings") or 30)
    case, keys = build_case(subscription, findings, cost=cost, limit=max(1, min(limit, 80)))
    if not keys:
        return {"status": "skipped", "reason": "no findings to review"}
    endpoint, deployment = settings["ai_endpoint"].strip(), settings["ai_deployment"].strip()
    try:
        result = await call_model(endpoint, deployment, case, credential)
    except Exception as exc:   # the report never depends on the AI step
        logger.warning("AI review failed: %s", exc)
        return {"status": "error", "reason": str(exc)[:400], "endpoint": endpoint, "deployment": deployment}
    answer = result["answer"] if isinstance(result.get("answer"), dict) else {}
    now = datetime.now(timezone.utc).isoformat()
    model = f"Azure OpenAI {deployment}"
    reviewed = 0
    for item in answer.get("findings") or []:
        f = keys.get(str(item.get("key")))
        if f is None:
            continue
        f["ai_review"] = {"agree": bool(item.get("agree", True)),
                          "recommendation": str(item.get("recommendation") or "")[:1500],
                          "why": str(item.get("why") or "")[:1500],
                          "sequence": [str(x)[:400] for x in item.get("sequence") or []][:8],
                          "risks": [str(x)[:400] for x in item.get("risks") or []][:6],
                          "questions": [str(x)[:400] for x in item.get("questions") or []][:5],
                          "model": model, "generated_at": now}
        reviewed += 1
    themes = []
    for t in answer.get("themes") or []:
        refs = [keys[k] for k in t.get("keys") or [] if k in keys]
        themes.append({"title": str(t.get("title") or "")[:200], "evidence": str(t.get("evidence") or "")[:1200],
                       "recommendation": str(t.get("recommendation") or "")[:1500],
                       "findings": [{"type": f.get("finding_type"), "resource_id": f.get("resource_id"),
                                     "title": f.get("title")} for f in refs]})
    return {"status": "ok", "model": model, "endpoint": endpoint, "generated_at": now,
            "summary": str(answer.get("summary") or "")[:2500], "themes": themes,
            "questions_for_owner": [str(q)[:400] for q in answer.get("questions_for_owner") or []][:10],
            "reviewed": reviewed, "sent": len(keys), "usage": result.get("usage") or {}}


def markdown(t: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    """05-deep-dive/thinking.md: the AI review of the subscription (themes, per-finding reviews, questions)."""
    by_key = {(f.get("finding_type"), (f.get("resource_id") or "").lower()): f for f in findings}
    lines = ["# Thinking mode - AI review", "", "[← Back to summary](../README.md)", ""]
    if t.get("status") != "ok":
        lines += [f"The AI review did not run: {t.get('reason') or t.get('status')}.", "",
                  "Switch it on in Settings (*AI review*): an Azure OpenAI endpoint and model deployment in the "
                  "company tenant. ARG's built-in reasoning is in every finding of the deep dives either way."]
        return "\n".join(lines) + "\n"
    usage = t.get("usage") or {}
    lines += [f"{t.get('model')} · {t.get('generated_at', '')[:16].replace('T', ' ')} UTC · "
              f"{t.get('sent')} findings sent, {t.get('reviewed')} with a review · tokens: "
              f"{usage.get('prompt_tokens', '?')} in / {usage.get('completion_tokens', '?')} out", "",
              "## Summary", "", t.get("summary") or "-", ""]
    if t.get("themes"):
        lines += ["## Themes across findings", ""]
        for th in t["themes"]:
            refs = [by_key[k] for k in ((r.get("type"), (r.get("resource_id") or "").lower())
                                         for r in th.get("findings") or []) if k in by_key]
            ref_text = ", ".join(f"[{f['ref']}](./{f['folder']}/README.md#{f['ref'].lower()})" for f in refs
                                 if f.get("ref"))
            lines += [f"### {th['title']}", "", th.get("evidence") or "", "", f"**Recommendation:** "
                      f"{th.get('recommendation') or '-'}", ""] + ([f"Findings: {ref_text}", ""] if ref_text else [])
    reviewed = [f for f in findings if f.get("ai_review")]
    if reviewed:
        lines += ["## Reviews per finding", "", "| Ref | Finding | Verdict | AI recommendation |", "|---|---|---|---|"]
        for f in reviewed:
            a = f["ai_review"]
            ref = f"[{f['ref']}](./{f['folder']}/README.md#{f['ref'].lower()})" if f.get("ref") else ""
            lines.append(f"| {ref} | {(f.get('title') or '').replace('|', '/')} | "
                         f"{'agrees' if a.get('agree') else '**challenges**'} | "
                         f"{(a.get('recommendation') or '').replace('|', '/')[:400]} |")
        lines.append("")
    if t.get("questions_for_owner"):
        lines += ["## Questions for the owner", ""] + [f"- {q}" for q in t["questions_for_owner"]] + [""]
    lines += ["> Generated by an AI model from ARG's evidence; review before acting. GUIDs were masked before "
              "sending; tag values and secrets are never sent."]
    return "\n".join(lines) + "\n"


def finding_markdown(review: Optional[Dict[str, Any]]) -> List[str]:
    """The AI review block of one finding in the deep dives."""
    if not review:
        return []
    lines = ["", f"**AI review** - {'agrees' if review.get('agree') else 'challenges the built-in recommendation'}"
             f" ({review.get('model')})", ""]
    if review.get("recommendation"):
        lines += [review["recommendation"], ""]
    if review.get("why"):
        lines += [f"*Why:* {review['why']}", ""]
    for title, key in (("Sequence", "sequence"), ("Risks", "risks"), ("Questions for the owner", "questions")):
        if review.get(key):
            lines += [f"*{title}*", ""] + [f"- {x}" for x in review[key]] + [""]
    return lines

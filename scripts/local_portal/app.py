"""
FastAPI app for the ARG local portal.

Security model (it is a single-user tool on your workstation):
- Listens on localhost only; the Host header is checked to defeat DNS rebinding.
- A simple local username/password gates every page and API call
  (in-memory sessions, HttpOnly + SameSite=Strict cookie).
- State-changing requests must come from the portal's own origin.
- Report pages are rendered with raw HTML neutralised (see render.py) and a
  strict Content-Security-Policy.
- Azure access is the user's `az login` session; the portal holds no secrets.
- Scripts and CI jobs on the same machine can call /api/* with
  `Authorization: Bearer <ARG_PORTAL_API_TOKEN>` instead of the cookie; the
  versioned API lives under /api/v1 (OpenAPI: /api/v1/openapi.json).
"""

import asyncio
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from fastapi import FastAPI, Form, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from scripts.local_portal.azure_session import AzureCliSession, friendly_error
from scripts.local_portal.jobs import JobManager
from scripts.local_portal.render import render_markdown
from scripts.subscription_analysis import ci
from scripts.subscription_analysis.ai_prompt import DEFAULT_MAX_FINDINGS, build_prompt
from scripts.subscription_analysis.report import display_names, read_summaries, write_index

HERE = Path(__file__).resolve().parent
COOKIE = "arg_portal_session"
CURRENCY_COOKIE = "arg_currency"   # the Currency dropdown: 'billing' or an ISO code
SESSION_TTL_SECONDS = 12 * 3600
SUBSCRIPTION_CACHE_SECONDS = 600
MAX_JSON_PREVIEW_BYTES = 2_000_000
MIN_API_TOKEN_LENGTH = 24
PUBLIC_PATHS = ("/login", "/static/", "/favicon.ico")
CSP = ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
       "form-action 'self'")


class PortalAuth:
    """Single local user, in-memory sessions."""

    def __init__(self, username: str, password: str):
        self.username = username
        self._password = password
        self._sessions: Dict[str, float] = {}

    def login(self, username: str, password: str) -> Optional[str]:
        user_ok = hmac.compare_digest(username.encode(), self.username.encode())
        pass_ok = hmac.compare_digest(password.encode(), self._password.encode())
        if not (user_ok and pass_ok):
            time.sleep(1)  # blunt brute-force throttle
            return None
        token = secrets.token_urlsafe(32)
        self._sessions[token] = time.time() + SESSION_TTL_SECONDS
        return token

    def valid(self, token: Optional[str]) -> bool:
        expiry = self._sessions.get(token or "")
        if not expiry:
            return False
        if expiry < time.time():
            self._sessions.pop(token, None)
            return False
        return True

    def logout(self, token: Optional[str]) -> None:
        self._sessions.pop(token or "", None)


def _safe_next(target: Optional[str]) -> str:
    return target if target and target.startswith("/") and not target.startswith("//") else "/"


def create_app(*, reports_dir: Path, username: str, password: str, azure: Optional[AzureCliSession] = None,
               jobs: Optional[JobManager] = None, allowed_hosts: Optional[List[str]] = None,
               api_token: Optional[str] = None) -> FastAPI:
    if api_token is not None and len(api_token) < MIN_API_TOKEN_LENGTH:
        raise ValueError(f"ARG_PORTAL_API_TOKEN must be at least {MIN_API_TOKEN_LENGTH} characters")
    reports_dir = reports_dir.resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)
    azure = azure or AzureCliSession()
    jobs = jobs or JobManager(reports_dir, lambda: azure.credential)
    auth = PortalAuth(username, password)
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    cache: Dict[str, Any] = {"subscriptions": None, "loaded_at": 0.0, "error": None}
    estate_job: Dict[str, Any] = {"running": False, "error": None, "started_at": None, "finished_at": None,
                                  "subscriptions": 0}
    background: set = set()
    estate_refresh_lock = asyncio.Lock()

    app = FastAPI(title="ARG Local Portal", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.auth, app.state.azure, app.state.jobs = auth, azure, jobs
    app.add_middleware(GZipMiddleware, minimum_size=2048)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts or ["127.0.0.1", "localhost"])

    def api_token_ok(request: Request) -> bool:
        """Bearer token for scripts / CI jobs; only for /api/* and only when ARG_PORTAL_API_TOKEN is set."""
        if not api_token or not request.url.path.startswith("/api/"):
            return False
        scheme, _, value = request.headers.get("authorization", "").partition(" ")
        return scheme.lower() == "bearer" and hmac.compare_digest(value.strip().encode(), api_token.encode())

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            expected = f"{request.url.scheme}://{request.headers.get('host', '')}"
            origin = request.headers.get("origin")
            referer = request.headers.get("referer")
            if (origin and origin != expected) or (not origin and referer and not referer.startswith(expected + "/")):
                return JSONResponse({"detail": "Cross-origin request rejected"}, status_code=403)
        if not path.startswith(PUBLIC_PATHS) and not auth.valid(request.cookies.get(COOKIE)) \
                and not api_token_ok(request):
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Not signed in to the portal"}, status_code=401)
            return RedirectResponse(f"/login?next={quote(path)}", status_code=303)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    # Microsoft's Azure architecture icons, unchanged (azure_icons/NOTICE.md) - the Policy page's assignment tree
    app.mount("/azure-icons", StaticFiles(directory=str(HERE.parent / "subscription_analysis" / "azure_icons")),
              name="azure-icons")

    # -- helpers ---------------------------------------------------------------

    async def subscriptions(refresh: bool = False) -> List[Dict[str, Any]]:
        from scripts.subscription_analysis.collector import list_subscriptions

        stale = time.time() - cache["loaded_at"] > SUBSCRIPTION_CACHE_SECONDS
        if cache["subscriptions"] is None or stale or refresh:
            try:
                cache["subscriptions"] = await list_subscriptions(azure.credential)
                cache["error"] = None
                cache["loaded_at"] = time.time()
            except Exception as exc:  # not cached: the next page load retries
                cache["subscriptions"], cache["error"] = [], friendly_error(exc)
        return cache["subscriptions"]

    def summaries_by_id() -> Dict[str, Dict[str, Any]]:
        result = {}
        for s in read_summaries(reports_dir):
            s["pdf"] = [d for d in ("summary", "full") if (reports_dir / s["folder"] / f"report-{d}.pdf").is_file()]
            if not s.get("per_usd"):   # reports written before summary.json carried the rate
                try:
                    s["per_usd"] = float(json.loads((reports_dir / s["folder"] / "05-deep-dive" / "raw" / "cost" /
                                                     "usd_to_billing.json").read_text(encoding="utf-8")))
                except (OSError, ValueError, TypeError):
                    s["per_usd"] = None
            result[(s.get("subscription") or {}).get("id", "").lower()] = s
        return result

    # -- currency: the Currency dropdown (cookie) over the display_currency setting ---------------------------

    def currency_choice(request: Request) -> str:
        from scripts.subscription_analysis import settings as analysis_settings
        from scripts.subscription_analysis.currency import BILLING

        chosen = (request.cookies.get(CURRENCY_COOKIE) or "").strip()
        if chosen and len(chosen) <= 10:
            return chosen
        return "USD" if analysis_settings.effective(reports_dir).get("display_currency") == "USD" else BILLING

    def converter(request: Request) -> Any:
        """Blocking (may download the reference rates once): call from a thread."""
        from scripts.subscription_analysis.currency import BILLING, Converter, reference_rates

        choice = currency_choice(request)
        return Converter(choice, reference_rates() if choice not in (BILLING, "USD") else None)

    def billing_rates(folder: Optional[str] = None) -> Dict[str, float]:
        """{billing currency: units per USD} a page was written with: its subscription's, or every analysed
        subscription's for pages across subscriptions (index, estate overview, diagrams)."""
        rates: Dict[str, float] = {}
        for s in summaries_by_id().values():
            if (folder is None or s.get("folder") == folder) and s.get("currency") and s.get("per_usd"):
                rates.setdefault(s["currency"], s["per_usd"])
        return rates

    def report_folder(folder: str) -> Optional[Path]:
        """A direct child of reports_dir that holds a generated report (summary.json)."""
        target = resolve_report_path(folder)
        if target is None or target.parent != reports_dir or not (target / "summary.json").is_file():
            return None
        return target

    async def state() -> Dict[str, Any]:
        return {"azure": await asyncio.to_thread(azure.status), "jobs": [j.to_dict() for j in jobs.list()],
                "summaries": summaries_by_id()}

    def resolve_report_path(rel: str) -> Optional[Path]:
        target = (reports_dir / rel).resolve()
        try:
            target.relative_to(reports_dir)
        except ValueError:
            return None
        return target

    def sidebar(target: Path) -> Dict[str, Any]:
        rel = target.relative_to(reports_dir)
        if not rel.parts or (len(rel.parts) == 1 and target.is_file()):
            summaries = read_summaries(reports_dir)
            labels = display_names(summaries)
            return {"title": "Subscriptions", "entries": [
                {"href": f"/reports/{s['folder']}/README.md", "label": labels[s["folder"]]} for s in summaries]}
        root = reports_dir / rel.parts[0]
        entries = [{"href": f"/reports/{p.relative_to(reports_dir).as_posix()}",
                    "label": p.relative_to(root).as_posix()}
                   for p in sorted(root.rglob("*.md"))]
        return {"title": rel.parts[0], "entries": entries}

    def folder_of(target: Path) -> Optional[str]:
        """Subscription report folder a page belongs to (drives the PDF/print toolbar)."""
        parts = target.relative_to(reports_dir).parts
        return parts[0] if len(parts) > 1 and report_folder(parts[0]) is not None else None

    def breadcrumbs(target: Path) -> List[Dict[str, str]]:
        crumbs = [{"href": "/reports/README.md", "label": "reports"}]
        parts = target.relative_to(reports_dir).parts
        for i, part in enumerate(parts):
            href = "/reports/" + "/".join(parts[: i + 1]) + ("" if i == len(parts) - 1 and target.is_file() else "/")
            crumbs.append({"href": href, "label": part})
        return crumbs

    # -- auth ------------------------------------------------------------------

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, next: str = "/", error: str = ""):
        return templates.TemplateResponse(request, "login.html", {"next": _safe_next(next), "error": error})

    @app.post("/login")
    async def login(username: str = Form(...), password: str = Form(...), next: str = Form("/")):
        token = await asyncio.to_thread(auth.login, username, password)
        if not token:
            return RedirectResponse(f"/login?error=1&next={quote(_safe_next(next))}", status_code=303)
        response = RedirectResponse(_safe_next(next), status_code=303)
        response.set_cookie(COOKIE, token, httponly=True, samesite="strict", max_age=SESSION_TTL_SECONDS)
        return response

    @app.post("/logout")
    async def logout(request: Request):
        auth.logout(request.cookies.get(COOKIE))
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(COOKIE)
        return response

    # -- dashboard & API -----------------------------------------------------------

    telemetry_cache: Dict[str, Any] = {"key": None, "html": None}

    def telemetry_section(conv: Any = None) -> Optional[str]:
        """Estate telemetry charts for the dashboard, re-computed only when estate.json, the tags or the currency
        change."""
        from scripts.subscription_analysis import settings as analysis_settings
        from scripts.subscription_analysis.estate import ESTATE_DIR, ESTATE_FILE
        from scripts.subscription_analysis.telemetry import estate_telemetry, in_currency
        from scripts.subscription_analysis.telemetry_svg import telemetry_html

        path = reports_dir / ESTATE_DIR / ESTATE_FILE
        if not path.is_file():
            return None
        tags = analysis_settings.effective(reports_dir).get("required_tags") or []
        key = (path.stat().st_mtime, tuple(tags), getattr(conv, "target", None))
        if telemetry_cache["key"] != key:
            data = estate_data()
            t = estate_telemetry(data, tags) if data else None
            if t is not None and conv is not None and conv.active:
                t = in_currency(t, conv, billing_rates())
            telemetry_cache.update(key=key, html=telemetry_html(t) if t else None)
        return telemetry_cache["html"]

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        status = await asyncio.to_thread(azure.status)
        subs = await subscriptions() if status["signed_in"] else []
        conv = await asyncio.to_thread(converter, request)
        return templates.TemplateResponse(request, "dashboard.html", {
            "azure": status, "subscriptions": subs, "subscription_error": cache["error"],
            "summaries": summaries_by_id(), "jobs": [j.to_dict() for j in jobs.list()],
            "reports_dir": str(reports_dir), "username": auth.username, "money": conv.money,
            "telemetry": await asyncio.to_thread(telemetry_section, conv),
        })

    @app.get("/api/currency")
    async def api_currency(request: Request):
        """The Currency dropdown: what is selected, the choices and the reference rates (units per USD)."""
        from scripts.subscription_analysis.currency import BILLING, options, reference_rates

        rates = await asyncio.to_thread(reference_rates)
        choice = currency_choice(request)
        per_usd = (rates or {}).get("per_usd") or {}
        selected = choice if choice in (BILLING, "USD") or choice.upper() in per_usd else BILLING
        return {"selected": selected if selected == BILLING else selected.upper(), "options": options(rates),
                "per_usd": per_usd, "date": (rates or {}).get("date"), "source": (rates or {}).get("source"),
                "billing": billing_rates()}

    @app.get("/api/state")
    async def api_state():
        return await state()

    @app.post("/api/refresh")
    async def api_refresh():
        status = await asyncio.to_thread(azure.status, True)
        subs = await subscriptions(refresh=True) if status["signed_in"] else []
        return {"azure": status, "subscriptions": subs, "error": cache["error"]}

    @app.post("/api/analyze")
    async def api_analyze(request: Request):
        body = await request.json()
        wanted = {str(s).lower() for s in body.get("subscription_ids") or []}
        if not wanted:
            return JSONResponse({"detail": "No subscriptions selected"}, status_code=400)
        known = {s["id"].lower(): s for s in await subscriptions()}
        unknown = sorted(wanted - set(known))
        if unknown:
            return JSONResponse({"detail": f"Not visible to the az login session: {', '.join(unknown)}"}, status_code=400)
        queued = [jobs.submit(known[i]["id"], known[i]["name"]).to_dict() for i in sorted(wanted)]
        return {"jobs": queued}

    # -- report browser ------------------------------------------------------------

    @app.post("/api/export-pdf")
    async def api_export_pdf(request: Request):
        from scripts.subscription_analysis.export import DETAILS, PdfExportError, export_pdf

        body = await request.json()
        detail = body.get("detail") or "summary"
        target = report_folder(str(body.get("folder") or ""))
        if target is None or detail not in DETAILS:
            return JSONResponse({"detail": "Unknown report folder or detail level"}, status_code=400)
        try:
            pdf = await asyncio.to_thread(export_pdf, target, detail)
        except PdfExportError as exc:
            return JSONResponse({"detail": str(exc), "print_url": f"/print/{target.name}?detail={detail}"},
                                status_code=500)
        return {"url": f"/reports/{target.name}/{pdf.name}"}

    @app.get("/print.css")
    async def print_css():
        from scripts.subscription_analysis.export import PRINT_CSS

        return Response(PRINT_CSS, media_type="text/css")

    # -- architecture diagrams -----------------------------------------------------------

    def estate_data() -> Optional[Dict[str, Any]]:
        """estate.json, built from the reports on first use (like /api/estate); None while nothing was analysed."""
        from scripts.subscription_analysis.estate import ESTATE_DIR, ESTATE_FILE, refresh_estate

        path = reports_dir / ESTATE_DIR / ESTATE_FILE
        if not path.is_file():
            refresh_estate(reports_dir)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if data.get("subscriptions") else None

    def diagram_view(view: str) -> str:
        return view if view in ("network", "landing") else "resources"

    @app.get("/architecture", response_class=HTMLResponse)
    async def architecture_page(request: Request, subscription: str = "", view: str = "resources"):
        data = await asyncio.to_thread(estate_data) or {}
        subs = sorted(data.get("subscriptions") or [], key=lambda s: (s.get("name") or "").lower())
        collected = str((data.get("architecture") or {}).get("collected_at") or data.get("inventory_at") or "")
        view = diagram_view(view)
        return templates.TemplateResponse(request, "architecture.html", {
            "username": auth.username, "subscriptions": subs,
            "subscription": "" if view == "landing" else subscription.lower(),
            "view": view, "collected": collected[:16].replace("T", " ")})

    def landing_inputs() -> Dict[str, Any]:
        from scripts.subscription_analysis import settings as analysis_settings
        from scripts.subscription_analysis.estate import load_policy

        return {"policy": load_policy(reports_dir),
                "mapping": analysis_settings.effective(reports_dir).get("landing_zone_mapping") or []}

    @app.get("/api/architecture.svg")
    async def architecture_svg(request: Request, subscription: str = "", view: str = "resources"):
        from scripts.subscription_analysis.network_diagram import architecture_svg as render

        data = await asyncio.to_thread(estate_data)
        if data is None:
            return PlainTextResponse("No estate inventory yet - refresh it on the Estate page.", status_code=404)
        view = diagram_view(view)
        extra = await asyncio.to_thread(landing_inputs) if view == "landing" else {}
        try:
            svg = await asyncio.to_thread(render, data, "" if view == "landing" else subscription.lower(), view,
                                          "/architecture", **extra)
        except KeyError:
            return PlainTextResponse("Unknown subscription", status_code=404)
        conv = await asyncio.to_thread(converter, request)
        if conv.active:   # cost labels are in each subscription's billing currency
            svg = conv.text(svg, billing_rates())
        return Response(svg, media_type="image/svg+xml")

    def landing_markdown() -> Optional[str]:
        from scripts.subscription_analysis.landing_zone import analyse, markdown

        data = estate_data()
        if data is None:
            return None
        inputs = landing_inputs()
        return markdown(analyse(data, inputs["policy"], inputs["mapping"]))

    @app.get("/api/landing-zone.md")
    async def landing_zone_md():
        text = await asyncio.to_thread(landing_markdown)
        if text is None:
            return PlainTextResponse("No estate inventory yet - refresh it on the Estate page.", status_code=404)
        return PlainTextResponse(text, media_type="text/markdown; charset=utf-8",
                                 headers={"Content-Disposition": 'attachment; filename="landing-zone.md"'})

    @app.get("/api/landing-zone.html", response_class=HTMLResponse)
    async def landing_zone_html():
        text = await asyncio.to_thread(landing_markdown)
        if text is None:
            return PlainTextResponse("No estate inventory yet - refresh it on the Estate page.", status_code=404)
        return HTMLResponse(render_markdown(text))

    # -- policy analyzer ---------------------------------------------------------------

    policy_cache: Dict[str, Any] = {"key": None, "result": None}

    def policy_analysis() -> Optional[Dict[str, Any]]:
        """The analyzer result for the saved estate and policy collection; reused while neither file changes."""
        from scripts.subscription_analysis.estate import ESTATE_DIR, ESTATE_FILE, POLICY_FILE, load_policy
        from scripts.subscription_analysis.policy_analyzer import analyse

        folder = reports_dir / ESTATE_DIR
        try:
            key = tuple((folder / f).stat().st_mtime_ns for f in (ESTATE_FILE, POLICY_FILE))
        except OSError:
            return None
        if policy_cache["key"] != key:
            data, policy = estate_data(), load_policy(reports_dir)
            if data is None or not policy:
                return None
            policy_cache.update(key=key, result=analyse(data, policy))
        return policy_cache["result"]

    NO_POLICY = "No policy collection yet - refresh the inventory on the Estate page (about 5 minutes)."

    @app.get("/policy", response_class=HTMLResponse)
    async def policy_page(request: Request):
        return templates.TemplateResponse(request, "policy.html", {"username": auth.username})

    @app.get("/api/policy-analysis")
    async def api_policy_analysis():
        result = await asyncio.to_thread(policy_analysis)
        if result is None:
            return JSONResponse({"detail": NO_POLICY}, status_code=404)
        return result

    @app.get("/api/policy.md")
    async def api_policy_markdown():
        from scripts.subscription_analysis.policy_analyzer import markdown

        result = await asyncio.to_thread(policy_analysis)
        if result is None:
            return PlainTextResponse(NO_POLICY, status_code=404)
        return PlainTextResponse(markdown(result), media_type="text/markdown; charset=utf-8",
                                 headers={"Content-Disposition": 'attachment; filename="policy-analysis.md"'})

    # -- settings ---------------------------------------------------------------------

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request, saved: int = 0):
        from scripts.subscription_analysis import settings as analysis_settings

        values = analysis_settings.effective(reports_dir)
        return templates.TemplateResponse(request, "settings.html", {
            "username": auth.username, "definitions": analysis_settings.SETTINGS, "values": values, "saved": saved,
            "settings_file": str(reports_dir / analysis_settings.SETTINGS_FILE)})

    @app.post("/settings")
    async def save_settings_form(request: Request):
        from scripts.subscription_analysis import settings as analysis_settings

        form = await request.form()
        values = {}
        for s in analysis_settings.SETTINGS:
            if s.kind == "bool":
                values[s.key] = s.key in form   # unchecked boxes are not submitted
            elif s.key in form:
                values[s.key] = str(form[s.key])
        await asyncio.to_thread(analysis_settings.save, reports_dir, values)
        return RedirectResponse("/settings?saved=1", status_code=303)

    @app.get("/api/settings")
    async def api_get_settings():
        from scripts.subscription_analysis import settings as analysis_settings

        return analysis_settings.effective(reports_dir)

    @app.put("/api/settings")
    async def api_put_settings(request: Request):
        from scripts.subscription_analysis import settings as analysis_settings

        body = await request.json()
        if not isinstance(body, dict):
            return JSONResponse({"detail": "Expected a JSON object"}, status_code=400)
        current = analysis_settings.load(reports_dir)
        await asyncio.to_thread(analysis_settings.save, reports_dir, {**current, **body})
        return analysis_settings.effective(reports_dir)

    # -- estate inventory ------------------------------------------------------------

    @app.get("/estate", response_class=HTMLResponse)
    async def estate_page(request: Request):
        return templates.TemplateResponse(request, "estate.html", {"username": auth.username})

    @app.get("/api/estate")
    async def api_estate():
        from scripts.subscription_analysis.estate import ESTATE_DIR, ESTATE_FILE, refresh_estate

        path = reports_dir / ESTATE_DIR / ESTATE_FILE
        if not path.is_file():
            await asyncio.to_thread(refresh_estate, reports_dir)  # first visit: build from the reports
        return FileResponse(path, media_type="application/json")

    @app.get("/compute", response_class=HTMLResponse)
    async def compute_page(request: Request):
        return templates.TemplateResponse(request, "compute.html", {"username": auth.username})

    @app.get("/api/compute")
    async def api_compute():
        from scripts.subscription_analysis.estate import COMPUTE_FILE, ESTATE_DIR

        path = reports_dir / ESTATE_DIR / COMPUTE_FILE
        if not path.is_file():
            return JSONResponse({"detail": "No Compute data yet - press Refresh inventory (about 5 minutes); the "
                                           "estate refresh collects it."}, status_code=404)
        return FileResponse(path, media_type="application/json")

    @app.get("/api/estate/status")
    async def api_estate_status():
        return estate_job

    @app.post("/api/estate/refresh")
    async def api_estate_refresh():
        # Reserve one refresh across awaits used for Azure status/subscriptions.
        # Two browser tabs must not launch duplicate metric collections.
        async with estate_refresh_lock:
            return await start_estate_refresh()

    async def start_estate_refresh():
        from scripts.subscription_analysis.estate import refresh_estate

        if estate_job["running"]:
            return estate_job
        status = await asyncio.to_thread(azure.status)
        tenant = (status.get("tenant_id") or "").lower()
        subs = [s for s in await subscriptions(refresh=True) if s.get("state") == "Enabled"
                and (not tenant or (s.get("tenant_id") or "").lower() == tenant)]
        if not subs:
            return JSONResponse({"detail": cache["error"] or "No enabled subscriptions visible to the az login session"},
                                status_code=400)
        estate_job.update(running=True, error=None, started_at=time.time(), finished_at=None, subscriptions=len(subs))

        async def run() -> None:
            try:
                await asyncio.to_thread(refresh_estate, reports_dir, azure.credential, subs)
                await asyncio.to_thread(write_index, reports_dir)
            except Exception as exc:
                estate_job["error"] = friendly_error(exc)
            finally:
                estate_job.update(running=False, finished_at=time.time())

        task = asyncio.get_running_loop().create_task(run())
        background.add(task)
        task.add_done_callback(background.discard)
        return estate_job

    @app.get("/print/{folder}", response_class=HTMLResponse)
    async def print_view(request: Request, folder: str, detail: str = "summary"):
        from scripts.subscription_analysis.export import DETAILS, build_print_body

        target = report_folder(folder)
        if target is None or detail not in DETAILS:
            return HTMLResponse("Not found", status_code=404)
        title, body = await asyncio.to_thread(build_print_body, target, detail)
        return templates.TemplateResponse(request, "print.html", {"title": title, "body": body})

    @app.get("/reports")
    async def reports_root():
        return RedirectResponse("/reports/README.md", status_code=303)

    @app.get("/reports/{rel:path}")
    async def report_page(request: Request, rel: str, raw: int = 0):
        if rel in ("", "README.md") and not (reports_dir / "README.md").exists():
            write_index(reports_dir)
        target = resolve_report_path(rel)
        if target is None or not target.exists():
            return HTMLResponse("Not found", status_code=404)
        if target.is_dir():
            if (target / "README.md").is_file():
                return RedirectResponse(f"/reports/{(target / 'README.md').relative_to(reports_dir).as_posix()}",
                                        status_code=303)
            if not request.url.path.endswith("/"):
                return RedirectResponse(request.url.path + "/", status_code=303)
            listing = [{"href": p.name + ("/" if p.is_dir() else ""), "label": p.name + ("/" if p.is_dir() else ""),
                        "size": p.stat().st_size if p.is_file() else None}
                       for p in sorted(target.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))]
            return templates.TemplateResponse(request, "page.html", {
                "title": target.name, "html": None, "listing": listing, "json": None,
                "crumbs": breadcrumbs(target), "sidebar": sidebar(target), "folder": folder_of(target)})
        suffix = target.suffix.lower()
        if suffix == ".md":
            conv = await asyncio.to_thread(converter, request)
            text = target.read_text(encoding="utf-8")
            if conv.active:   # the page is written in its subscription's billing currency
                text = conv.text(text, billing_rates(folder_of(target)) or billing_rates())
            html = render_markdown(text)
            return templates.TemplateResponse(request, "page.html", {
                "title": target.stem, "html": html, "listing": None, "json": None,
                "crumbs": breadcrumbs(target), "sidebar": sidebar(target), "folder": folder_of(target)})
        if suffix == ".pdf":
            return FileResponse(target, media_type="application/pdf", filename=f"{target.parent.name}-{target.name}",
                                content_disposition_type="inline")
        if suffix == ".csv":   # backlog.csv - Azure Boards import
            return FileResponse(target, media_type="text/csv", filename=f"{target.parent.name}-{target.name}")
        if suffix == ".json":
            if raw or target.stat().st_size > MAX_JSON_PREVIEW_BYTES:
                return FileResponse(target, media_type="application/json")
            try:
                pretty = json.dumps(json.loads(target.read_text(encoding="utf-8")), indent=2, ensure_ascii=False)
            except ValueError:
                pretty = target.read_text(encoding="utf-8", errors="replace")
            return templates.TemplateResponse(request, "page.html", {
                "title": target.name, "html": None, "listing": None, "json": pretty,
                "crumbs": breadcrumbs(target), "sidebar": sidebar(target), "folder": folder_of(target)})
        return HTMLResponse("Unsupported file type", status_code=404)

    # -- versioned API for scripts and CI/CD (cookie or Bearer ARG_PORTAL_API_TOKEN) ----------

    def find_report(key: str) -> Optional[Path]:
        """Report folder by folder name, subscription ID or display name (case-insensitive)."""
        direct = report_folder(key)
        if direct is not None:
            return direct
        wanted = key.lower()
        for s in read_summaries(reports_dir):
            sub = s.get("subscription") or {}
            if wanted in (str(sub.get("id") or "").lower(), str(sub.get("name") or "").lower()):
                return reports_dir / s["folder"]
        return None

    def not_found(key: str) -> JSONResponse:
        return JSONResponse({"detail": f"No report for '{key}' - analyse the subscription first"}, status_code=404)

    def severity_arg(value: Optional[str]) -> Optional[str]:
        if value in (None, ""):
            return None
        if value not in ci.SEVERITIES:
            raise ValueError(f"severity must be one of {', '.join(ci.SEVERITIES)}")
        return value

    @app.get("/api/v1/openapi.json", include_in_schema=False)
    async def api_v1_openapi():
        routes = [r for r in app.routes if getattr(r, "path", "").startswith("/api/v1/")]
        return get_openapi(title="ARG Local Portal API", version="1",
                           description="Authenticate with the portal cookie or `Authorization: Bearer "
                                       "<ARG_PORTAL_API_TOKEN>`. See docs/ci-cd.md.", routes=routes)

    @app.get("/api/v1/subscriptions", tags=["subscriptions"])
    async def api_v1_subscriptions(refresh: bool = False):
        status = await asyncio.to_thread(azure.status, refresh)
        subs = await subscriptions(refresh=refresh) if status["signed_in"] else []
        reports = summaries_by_id()
        return {"azure": status, "error": cache["error"], "subscriptions": [
            {**s, "report_folder": (reports.get(s["id"].lower()) or {}).get("folder")} for s in subs]}

    @app.post("/api/v1/analyses", tags=["analyses"], status_code=202)
    async def api_v1_start_analyses(request: Request):
        """Body: {"subscriptions": ["<id or display name>", ...]} - queues one analysis job per subscription."""
        body = await request.json()
        wanted = [str(s) for s in (body.get("subscriptions") or body.get("subscription_ids") or [])]
        if not wanted:
            return JSONResponse({"detail": "No subscriptions given"}, status_code=400)
        visible = await subscriptions()
        lookup = {k: s for s in visible for k in (s["id"].lower(), str(s.get("name") or "").lower()) if k}
        unknown = [w for w in wanted if w.lower() not in lookup]
        if unknown:
            return JSONResponse({"detail": f"Not visible to the az login session: {', '.join(unknown)}"},
                                status_code=400)
        chosen = {lookup[w.lower()]["id"]: lookup[w.lower()] for w in wanted}
        return {"jobs": [jobs.submit(s["id"], s["name"]).to_dict() for s in chosen.values()]}

    @app.get("/api/v1/analyses", tags=["analyses"])
    async def api_v1_list_analyses():
        return {"jobs": [j.to_dict() for j in jobs.list()]}

    @app.get("/api/v1/analyses/{job_id}", tags=["analyses"])
    async def api_v1_get_analysis(job_id: str):
        job = jobs.get(job_id)
        return job.to_dict() if job else JSONResponse({"detail": "Unknown job"}, status_code=404)

    @app.get("/api/v1/reports", tags=["reports"])
    async def api_v1_reports():
        return {"reports": list(summaries_by_id().values())}

    @app.get("/api/v1/reports/{key}", tags=["reports"])
    async def api_v1_report(key: str):
        target = find_report(key)
        if target is None:
            return not_found(key)
        return {**ci.load_report(target)["summary"], "folder": target.name}

    @app.get("/api/v1/reports/{key}/findings", tags=["reports"])
    async def api_v1_findings(key: str, min_severity: Optional[str] = None, finding_type: Optional[str] = None,
                              limit: int = 500, offset: int = 0):
        target = find_report(key)
        if target is None:
            return not_found(key)
        try:
            floor = severity_arg(min_severity)
        except ValueError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        findings = (await asyncio.to_thread(ci.load_report, target))["findings"]
        if floor:
            findings = [f for f in findings if ci.sev_rank(f.get("severity")) <= ci.sev_rank(floor)]
        if finding_type:
            types = set(ci.parse_types(finding_type))
            findings = [f for f in findings if f.get("finding_type") in types]
        limit = max(1, min(limit, 5000))
        offset = max(0, offset)
        return {"folder": target.name, "total": len(findings), "offset": offset, "limit": limit,
                "items": findings[offset:offset + limit]}

    @app.get("/api/v1/reports/{key}/gate", tags=["ci"])
    async def api_v1_gate(key: str, fail_on: str = "high", ignore: Optional[str] = None):
        """CI gate: `passed` is false when findings at or above `fail_on` remain (always HTTP 200)."""
        target = find_report(key)
        if target is None:
            return not_found(key)
        try:
            floor = severity_arg(fail_on)
        except ValueError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        report = await asyncio.to_thread(ci.load_report, target)
        return ci.ci_summary([report], floor, ci.parse_types(ignore))

    @app.get("/api/v1/reports/{key}/sarif", tags=["ci"])
    async def api_v1_sarif(key: str):
        target = find_report(key)
        if target is None:
            return not_found(key)
        report = await asyncio.to_thread(ci.load_report, target)
        return JSONResponse(ci.to_sarif([report], base=reports_dir), media_type="application/sarif+json")

    @app.get("/api/v1/reports/{key}/junit", tags=["ci"])
    async def api_v1_junit(key: str, fail_on: str = "high", ignore: Optional[str] = None):
        target = find_report(key)
        if target is None:
            return not_found(key)
        try:
            floor = severity_arg(fail_on)
        except ValueError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        report = await asyncio.to_thread(ci.load_report, target)
        return Response(ci.to_junit([report], floor, ci.parse_types(ignore)), media_type="application/xml")

    @app.get("/api/v1/reports/{key}/ai-prompt", tags=["ai"])
    async def api_v1_ai_prompt(key: str, min_severity: Optional[str] = None, max_findings: int = DEFAULT_MAX_FINDINGS,
                               mask_ids: bool = True, download: bool = False):
        """Markdown prompt for an AI assistant: instructions, subscription context and findings (GUIDs masked)."""
        target = find_report(key)
        if target is None:
            return not_found(key)
        try:
            floor = severity_arg(min_severity)
        except ValueError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        report = await asyncio.to_thread(ci.load_report, target)
        text = build_prompt(report["summary"], report["findings"], max_findings=max(1, min(max_findings, 2000)),
                            mask_ids=mask_ids, min_severity=floor)
        headers = {"Content-Disposition": f'attachment; filename="{target.name}-ai-prompt.md"'} if download else {}
        return PlainTextResponse(text, media_type="text/markdown; charset=utf-8", headers=headers)

    @app.on_event("shutdown")
    def _shutdown() -> None:
        jobs.shutdown()

    return app

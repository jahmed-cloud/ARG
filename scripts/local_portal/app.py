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
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from scripts.local_portal.azure_session import AzureCliSession, friendly_error
from scripts.local_portal.jobs import JobManager
from scripts.local_portal.render import render_markdown
from scripts.subscription_analysis.report import display_names, read_summaries, write_index

HERE = Path(__file__).resolve().parent
COOKIE = "arg_portal_session"
SESSION_TTL_SECONDS = 12 * 3600
SUBSCRIPTION_CACHE_SECONDS = 600
MAX_JSON_PREVIEW_BYTES = 2_000_000
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
               jobs: Optional[JobManager] = None, allowed_hosts: Optional[List[str]] = None) -> FastAPI:
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

    app = FastAPI(title="ARG Local Portal", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.auth, app.state.azure, app.state.jobs = auth, azure, jobs
    app.add_middleware(GZipMiddleware, minimum_size=2048)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts or ["127.0.0.1", "localhost"])

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            expected = f"{request.url.scheme}://{request.headers.get('host', '')}"
            origin = request.headers.get("origin")
            referer = request.headers.get("referer")
            if (origin and origin != expected) or (not origin and referer and not referer.startswith(expected + "/")):
                return JSONResponse({"detail": "Cross-origin request rejected"}, status_code=403)
        if not path.startswith(PUBLIC_PATHS) and not auth.valid(request.cookies.get(COOKIE)):
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
            result[(s.get("subscription") or {}).get("id", "").lower()] = s
        return result

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
        token = auth.login(username, password)
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

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        status = await asyncio.to_thread(azure.status)
        subs = await subscriptions() if status["signed_in"] else []
        return templates.TemplateResponse(request, "dashboard.html", {
            "azure": status, "subscriptions": subs, "subscription_error": cache["error"],
            "summaries": summaries_by_id(), "jobs": [j.to_dict() for j in jobs.list()],
            "reports_dir": str(reports_dir), "username": auth.username,
        })

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

    @app.get("/api/estate/status")
    async def api_estate_status():
        return estate_job

    @app.post("/api/estate/refresh")
    async def api_estate_refresh():
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
        estate_job.update(running=True, error=None, started_at=time.time(), subscriptions=len(subs))

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
            html = render_markdown(target.read_text(encoding="utf-8"))
            return templates.TemplateResponse(request, "page.html", {
                "title": target.stem, "html": html, "listing": None, "json": None,
                "crumbs": breadcrumbs(target), "sidebar": sidebar(target), "folder": folder_of(target)})
        if suffix == ".pdf":
            return FileResponse(target, media_type="application/pdf", filename=f"{target.parent.name}-{target.name}",
                                content_disposition_type="inline")
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

    @app.on_event("shutdown")
    def _shutdown() -> None:
        jobs.shutdown()

    return app

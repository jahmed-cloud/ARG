"""
Azure Resource Guardian - FastAPI Application
=============================================
Main application entry point.

Architecture decisions:
- Lifespan context manager for startup/shutdown (replaces deprecated on_event)
- Async engine for all DB operations (asyncpg driver)
- Structured logging via structlog
- OpenAPI docs with custom branding
- Security headers middleware
- Request ID middleware for tracing
"""

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from backend.core.config import settings
from backend.api.routes import (
    auth, subscriptions, tenants, scans, findings,
    costs, identity, governance, drift, security,
    reports, dashboard, remediation, webhooks, health, users,
    governance_config
)
from backend.models.models import Base

# ---------------------------------------------------------------------------
# Structured logging setup
# ---------------------------------------------------------------------------

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer() if settings.DEBUG else structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_timeout=settings.DATABASE_POOL_TIMEOUT,
    echo=settings.DATABASE_ECHO,
)

AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ---------------------------------------------------------------------------
# Application Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """
    Application startup and shutdown.
    - Creates DB tables if they don't exist (development mode)
    - In production, Alembic migrations handle schema
    - Validates critical config on startup
    """
    logger.info("Azure Resource Guardian starting", version=settings.APP_VERSION, env=settings.APP_ENV)

    # Production safety checks
    if settings.APP_ENV == "production":
        _check = settings.SECRET_KEY.get_secret_value()
        if "CHANGE-ME" in _check:
            raise ValueError("SECRET_KEY must be changed in production!")

    # Create tables in development (use Alembic in production)
    if settings.APP_ENV == "development":
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created (development mode)")

    # Store engine and session factory on app state
    app.state.engine = engine
    app.state.session_factory = AsyncSessionLocal

    logger.info("ARG started successfully")

    yield

    # Shutdown
    await engine.dispose()
    logger.info("ARG stopped")


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Azure Resource Guardian",
    description=(
        "Open-source Azure governance platform. "
        "Discover orphaned resources, detect security issues, "
        "analyze Entra ID hygiene, and optimize costs."
    ),
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.DOCS_ENABLED else None,
    redoc_url="/redoc" if settings.DOCS_ENABLED else None,
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    lifespan=lifespan,
    contact={
        "name": "ARG Open Source",
        "url": "https://github.com/your-org/azure-resource-guardian",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
)


# ---------------------------------------------------------------------------
# Middleware Stack
# ---------------------------------------------------------------------------

# CORS — configure allowed origins from settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Total-Count"],
)

# Compress responses > 1KB
app.add_middleware(GZipMiddleware, minimum_size=1024)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Attach a unique request ID to every request for distributed tracing."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    structlog.contextvars.bind_contextvars(request_id=request_id)
    response: Response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """
    Add security headers to all responses.
    OWASP Top 10 mitigation: A05 Security Misconfiguration.
    """
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if settings.APP_ENV == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.middleware("http")
async def request_timing_middleware(request: Request, call_next):
    """Log request timing for performance monitoring."""
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = int((time.perf_counter() - start) * 1000)
    response.headers["X-Response-Time"] = f"{duration_ms}ms"
    logger.debug(
        "request",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        duration_ms=duration_ms,
    )
    return response


# ---------------------------------------------------------------------------
# Exception Handlers
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch-all exception handler.
    Returns RFC 7807 Problem Details format.
    Never exposes stack traces in production.
    """
    error_id = str(uuid.uuid4())
    logger.error(
        "unhandled_exception",
        error_id=error_id,
        exc_type=type(exc).__name__,
        exc=str(exc),
        path=request.url.path,
        exc_info=True,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "type": "https://arg.dev/errors/internal-error",
            "title": "Internal Server Error",
            "status": 500,
            "detail": "An unexpected error occurred. Please contact support.",
            "error_id": error_id,
        },
    )


# ---------------------------------------------------------------------------
# Route Registration
# ---------------------------------------------------------------------------

PREFIX = settings.API_PREFIX

app.include_router(health.router,       prefix=f"{PREFIX}/health",      tags=["Health"])
app.include_router(auth.router,         prefix=f"{PREFIX}/auth",         tags=["Authentication"])
app.include_router(users.router,        prefix=f"{PREFIX}/users",        tags=["Users"])
app.include_router(subscriptions.router, prefix=f"{PREFIX}/subscriptions", tags=["Subscriptions"])
app.include_router(tenants.router,      prefix=f"{PREFIX}/tenants",      tags=["Tenants"])
app.include_router(scans.router,        prefix=f"{PREFIX}/scans",        tags=["Scans"])
app.include_router(findings.router,     prefix=f"{PREFIX}/findings",     tags=["Findings"])
app.include_router(costs.router,        prefix=f"{PREFIX}/costs",        tags=["Cost Optimization"])
app.include_router(identity.router,     prefix=f"{PREFIX}/identity",     tags=["Entra ID"])
app.include_router(governance.router,        prefix=f"{PREFIX}/governance",   tags=["Governance"])
app.include_router(governance_config.router, prefix=f"{PREFIX}/governance",   tags=["Governance"])
app.include_router(drift.router,        prefix=f"{PREFIX}/drift",        tags=["Terraform Drift"])
app.include_router(security.router,     prefix=f"{PREFIX}/security",     tags=["Security"])
app.include_router(reports.router,      prefix=f"{PREFIX}/reports",      tags=["Reports"])
app.include_router(dashboard.router,    prefix=f"{PREFIX}/dashboard",    tags=["Dashboard"])
app.include_router(remediation.router,  prefix=f"{PREFIX}/remediation",  tags=["Remediation"])
app.include_router(webhooks.router,     prefix=f"{PREFIX}/webhooks",     tags=["Webhooks"])


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": f"{settings.API_PREFIX}/docs" if settings.DOCS_ENABLED else None,
        "status": "operational",
    }

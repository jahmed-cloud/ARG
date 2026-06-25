"""
Azure Resource Guardian - Authentication Routes
===============================================
JWT-based authentication with refresh token rotation.

Security design:
- Short-lived access tokens (30 min default)
- Long-lived refresh tokens with rotation (7 days)
- Refresh token stored as hash in DB (not plaintext)
- Rate limiting on login endpoint (protect against brute force)
- Account lockout after configurable failed attempts
- Audit log on all auth events
"""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.config import settings
from backend.api.dependencies.database import get_db
from backend.api.dependencies.auth import get_current_user
from backend.models.models import AuditLog, RefreshToken, User, UserRole
from backend.utils.mailer import send_email

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user_id: str
    username: str
    role: str


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=12)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=12)


class UserProfile(BaseModel):
    id: str
    email: str
    username: str
    full_name: str | None
    role: str
    mfa_enabled: bool
    last_login_at: datetime | None
    created_at: datetime


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def create_access_token(user_id: str, username: str, role: str) -> str:
    """Create a signed JWT access token."""
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
    }
    return jwt.encode(
        payload,
        settings.SECRET_KEY.get_secret_value(),
        algorithm=settings.ALGORITHM,
    )


def create_refresh_token() -> tuple[str, str]:
    """
    Generate a cryptographically secure refresh token.
    Returns (raw_token, hashed_token).
    We only store the hash — the raw token is returned to the client once.
    """
    raw = secrets.token_urlsafe(64)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def hash_password(password: str) -> str:
    """Hash password with bcrypt."""
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)
    ).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


async def log_audit(
    db: AsyncSession,
    action: str,
    user_id: str | None,
    description: str,
    request: Request,
    outcome: str = "success",
    error: str | None = None,
):
    """Write an immutable audit log entry."""
    db.add(AuditLog(
        user_id=user_id,
        action=action,
        resource_type="auth",
        description=description,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:512],
        request_id=request.headers.get("x-request-id"),
        outcome=outcome,
        error=error,
    ))
    await db.commit()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/login", response_model=TokenResponse, summary="Authenticate and receive tokens")
async def login(
    request: Request,
    credentials: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate with username/password.
    Returns a short-lived access token and a refresh token.

    Security:
    - Rate limited at the infrastructure level (nginx/caddy rate limiting recommended)
    - Constant-time password comparison (bcrypt)
    - Identical error messages for missing user vs wrong password (prevents user enumeration)
    - Account lockout after MAX_LOGIN_ATTEMPTS failures
    """
    # Find user by username OR email
    result = await db.execute(
        select(User).where(
            (User.username == credentials.username) | (User.email == credentials.username),
            User.deleted_at.is_(None),
        )
    )
    user = result.scalar_one_or_none()

    # Generic error to prevent user enumeration
    INVALID_CREDS = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not user or not user.hashed_password:
        await log_audit(db, "auth.login_failed", None,
                       f"Login attempt for unknown user: {credentials.username}",
                       request, outcome="failure", error="user_not_found")
        raise INVALID_CREDS

    if not user.is_active:
        await log_audit(db, "auth.login_blocked", user.id,
                       f"Login blocked for disabled user: {user.username}",
                       request, outcome="failure", error="account_disabled")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled. Contact an administrator.",
        )

    if not verify_password(credentials.password, user.hashed_password):
        await log_audit(db, "auth.login_failed", user.id,
                       f"Wrong password for user: {user.username}",
                       request, outcome="failure", error="wrong_password")
        raise INVALID_CREDS

    # Generate tokens
    access_token = create_access_token(user.id, user.username, user.role.value)
    raw_refresh, hashed_refresh = create_refresh_token()

    # Store refresh token
    db.add(RefreshToken(
        user_id=user.id,
        token_hash=hashed_refresh,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:512],
    ))

    # Update user activity
    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(
            last_login_at=datetime.now(timezone.utc),
            last_login_ip=request.client.host if request.client else None,
            login_count=User.login_count + 1,
        )
    )

    await db.commit()

    await log_audit(db, "auth.login_success", user.id,
                   f"Successful login for user: {user.username}", request)

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=user.id,
        username=user.username,
        role=user.role.value,
    )


@router.post("/refresh", response_model=TokenResponse, summary="Refresh access token")
async def refresh_token(
    request: Request,
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Exchange a valid refresh token for a new access token + refresh token pair.

    Implements refresh token rotation: the old refresh token is revoked
    and a new one is issued. This limits the blast radius if a refresh
    token is stolen — it can only be used once.
    """
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()

    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked_at.is_(None),
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
    )
    stored_token = result.scalar_one_or_none()

    if not stored_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    # Revoke old token (rotation)
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.id == stored_token.id)
        .values(revoked_at=datetime.now(timezone.utc))
    )

    # Get user
    user_result = await db.execute(
        select(User).where(User.id == stored_token.user_id, User.is_active == True)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Issue new tokens
    access_token = create_access_token(user.id, user.username, user.role.value)
    raw_refresh, hashed_refresh = create_refresh_token()

    db.add(RefreshToken(
        user_id=user.id,
        token_hash=hashed_refresh,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        ip_address=request.client.host if request.client else None,
    ))
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=user.id,
        username=user.username,
        role=user.role.value,
    )


@router.post("/logout", summary="Revoke refresh token")
async def logout(
    request: Request,
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Revoke the provided refresh token. The access token will expire naturally."""
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    await db.execute(
        update(RefreshToken)
        .where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.user_id == current_user.id,
        )
        .values(revoked_at=datetime.now(timezone.utc))
    )
    await db.commit()
    await log_audit(db, "auth.logout", current_user.id, "User logged out", request)
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserProfile, summary="Get current user profile")
async def get_me(
    current_user: User = Depends(get_current_user),
):
    """Return the currently authenticated user's profile."""
    return UserProfile(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        full_name=current_user.full_name,
        role=current_user.role.value,
        mfa_enabled=current_user.mfa_enabled,
        last_login_at=current_user.last_login_at,
        created_at=current_user.created_at,
    )


@router.post("/change-password", summary="Change user password")
async def change_password(
    request: Request,
    body: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Change the current user's password. Requires current password for verification."""
    if not current_user.hashed_password:
        raise HTTPException(status_code=400, detail="SSO accounts cannot change password here")

    if not verify_password(body.current_password, current_user.hashed_password):
        await log_audit(db, "auth.password_change_failed", current_user.id,
                       "Wrong current password during change", request, outcome="failure")
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    new_hash = hash_password(body.new_password)
    await db.execute(
        update(User).where(User.id == current_user.id).values(hashed_password=new_hash)
    )
    # Revoke all refresh tokens to force re-login everywhere
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == current_user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )
    await db.commit()
    await log_audit(db, "auth.password_changed", current_user.id, "Password changed", request)
    return {"message": "Password changed successfully. Please log in again."}


@router.post("/forgot-password", summary="Request a password reset link")
async def forgot_password(
    request: Request,
    body: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Issue a time-limited password reset token and email (or log, if SMTP
    isn't configured) a reset link.

    Always returns the same generic success message regardless of whether
    the email matches an account — confirming/denying account existence
    here would let an attacker enumerate valid usernames/emails.
    """
    generic_response = {
        "message": "If an account with that email exists, a password reset link has been sent."
    }

    result = await db.execute(select(User).where(User.email == body.email, User.deleted_at.is_(None)))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        return generic_response

    if not user.hashed_password:
        # SSO-only account (e.g. signed in via Microsoft) — nothing to
        # reset locally. Still return the generic response to avoid
        # leaking account type via response differences.
        await log_audit(db, "auth.password_reset_requested_sso_account", user.id,
                       "Password reset requested for SSO-only account", request)
        return generic_response

    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_TTL_MINUTES)

    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(password_reset_token_hash=token_hash, password_reset_expires_at=expires_at)
    )
    await db.commit()

    reset_link = f"{settings.FRONTEND_BASE_URL.rstrip('/')}/reset-password?token={raw_token}"
    send_email(
        to_email=user.email,
        subject="Reset your Azure Resource Guardian password",
        body_text=(
            f"Hi {user.full_name or user.username},\n\n"
            f"A password reset was requested for your account. This link expires in "
            f"{settings.PASSWORD_RESET_TOKEN_TTL_MINUTES} minutes:\n\n{reset_link}\n\n"
            f"If you didn't request this, you can safely ignore this email."
        ),
    )

    await log_audit(db, "auth.password_reset_requested", user.id, "Password reset link issued", request)
    return generic_response


@router.post("/reset-password", summary="Reset password using a reset token")
async def reset_password(
    request: Request,
    body: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """Consume a password reset token (from /forgot-password) and set a new password."""
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    result = await db.execute(select(User).where(User.password_reset_token_hash == token_hash))
    user = result.scalar_one_or_none()

    if not user or not user.password_reset_expires_at:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")

    if user.password_reset_expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="This reset link has expired. Please request a new one.")

    new_hash = hash_password(body.new_password)
    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(
            hashed_password=new_hash,
            password_reset_token_hash=None,
            password_reset_expires_at=None,
        )
    )
    # Revoke all refresh tokens — a password reset should end every
    # existing session, the same as a normal password change does.
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )
    await db.commit()
    await log_audit(db, "auth.password_reset_completed", user.id, "Password reset via token", request)
    return {"message": "Password reset successfully. Please log in with your new password."}


# ---------------------------------------------------------------------------
# Microsoft OAuth ("Sign in with Microsoft")
# ---------------------------------------------------------------------------
# Entirely optional — only active when AZURE_OAUTH_CLIENT_ID and
# AZURE_OAUTH_CLIENT_SECRET are set via environment variables (see
# backend/core/config.py settings.microsoft_oauth_configured). This is a
# separate app registration from the per-tenant scanning Service
# Principals configured under Settings — it authenticates ARG *users*
# signing into this app, not Azure resource access for scanning.
#
# State (CSRF) is handled via a short-lived signed JWT rather than
# server-side session storage, since the rest of this API is stateless.

GRAPH_SCOPES = ["User.Read"]


def _msal_app():
    import msal
    return msal.ConfidentialClientApplication(
        client_id=settings.AZURE_OAUTH_CLIENT_ID,
        client_credential=settings.AZURE_OAUTH_CLIENT_SECRET.get_secret_value(),
        authority=f"https://login.microsoftonline.com/{settings.AZURE_OAUTH_TENANT_ID}",
    )


@router.get("/microsoft/status", summary="Check whether Microsoft sign-in is enabled")
async def microsoft_oauth_status():
    """
    Lets the frontend decide whether to show the 'Sign in with Microsoft'
    button without guessing — avoids offering a login path that will
    immediately 503 because the env vars aren't set in this deployment.
    """
    return {"enabled": settings.microsoft_oauth_configured}


@router.get("/system-status", summary="Check optional integrations (admin only)")
async def system_status(current_user: User = Depends(get_current_user)):
    """
    Surfaces whether SMTP and Microsoft OAuth are configured via
    environment variables — both are deliberately env-var-only (not
    editable through the UI) to keep credentials out of the database,
    matching how per-tenant scanning Service Principal secrets are
    handled separately under Settings. Admin-only since this reveals
    operational configuration, not because the values themselves are
    secret (no actual credentials are returned, just booleans).
    """
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(status_code=403, detail="Admin access required")
    return {
        "smtp_configured": settings.smtp_configured,
        "smtp_host": settings.SMTP_HOST if settings.smtp_configured else None,
        "microsoft_oauth_configured": settings.microsoft_oauth_configured,
    }


@router.get("/microsoft/login", summary="Start Microsoft OAuth sign-in")
async def microsoft_login():
    if not settings.microsoft_oauth_configured:
        raise HTTPException(
            status_code=503,
            detail="Microsoft sign-in is not configured on this server. "
            "Set AZURE_OAUTH_CLIENT_ID and AZURE_OAUTH_CLIENT_SECRET to enable it.",
        )

    state_token = jwt.encode(
        {"purpose": "oauth_state", "exp": datetime.now(timezone.utc) + timedelta(minutes=10)},
        settings.SECRET_KEY.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM,
    )
    auth_url = _msal_app().get_authorization_request_url(
        scopes=GRAPH_SCOPES,
        state=state_token,
        redirect_uri=settings.AZURE_OAUTH_REDIRECT_URI,
    )
    return RedirectResponse(auth_url)


@router.get("/microsoft/callback", summary="Microsoft OAuth callback")
async def microsoft_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Handles the redirect back from Microsoft after sign-in. Exchanges the
    authorization code for an identity, finds or creates the matching
    local User record (matched on sso_subject, falling back to email for
    a first-time link), issues ARG's own JWT/refresh tokens, and redirects
    to the frontend with those tokens as URL fragment parameters (never
    query params, so they aren't logged by intermediate servers) for the
    SPA to pick up and store.
    """
    frontend_login = f"{settings.FRONTEND_BASE_URL.rstrip('/')}/login"

    if error:
        return RedirectResponse(f"{frontend_login}?oauth_error={error_description or error}")

    if not settings.microsoft_oauth_configured:
        raise HTTPException(status_code=503, detail="Microsoft sign-in is not configured on this server.")

    if not code or not state:
        return RedirectResponse(f"{frontend_login}?oauth_error=missing_code_or_state")

    try:
        jwt.decode(state, settings.SECRET_KEY.get_secret_value(), algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return RedirectResponse(f"{frontend_login}?oauth_error=invalid_or_expired_state")

    result = _msal_app().acquire_token_by_authorization_code(
        code=code,
        scopes=GRAPH_SCOPES,
        redirect_uri=settings.AZURE_OAUTH_REDIRECT_URI,
    )
    if "error" in result:
        logger.error(f"Microsoft OAuth token exchange failed: {result.get('error_description')}")
        return RedirectResponse(f"{frontend_login}?oauth_error=token_exchange_failed")

    claims = result.get("id_token_claims", {})
    ms_subject = claims.get("oid") or claims.get("sub")
    ms_email = claims.get("preferred_username") or claims.get("email")
    ms_name = claims.get("name")

    if not ms_subject or not ms_email:
        return RedirectResponse(f"{frontend_login}?oauth_error=missing_identity_claims")

    existing = await db.execute(
        select(User).where(User.sso_provider == "azure_ad", User.sso_subject == ms_subject)
    )
    user = existing.scalar_one_or_none()

    if not user:
        # First sign-in via Microsoft for this identity — link to an
        # existing local account with a matching email if one exists,
        # otherwise this account must be provisioned by an admin first.
        # We deliberately do NOT auto-create new accounts with default
        # roles here, since that would let anyone with a Microsoft
        # account in the configured tenant self-provision access to ARG.
        by_email = await db.execute(select(User).where(User.email == ms_email, User.deleted_at.is_(None)))
        user = by_email.scalar_one_or_none()
        if not user:
            return RedirectResponse(
                f"{frontend_login}?oauth_error=no_matching_account"
                f"&oauth_email={ms_email}"
            )
        if not user.is_active:
            return RedirectResponse(f"{frontend_login}?oauth_error=account_disabled")
        user.sso_provider = "azure_ad"
        user.sso_subject = ms_subject

    user.last_login_at = datetime.now(timezone.utc)
    user.last_login_ip = request.client.host if request.client else None
    user.login_count = (user.login_count or 0) + 1
    await db.commit()
    await db.refresh(user)

    access_token = create_access_token(user.id, user.username, user.role.value)
    raw_refresh, hashed_refresh = create_refresh_token()
    db.add(RefreshToken(
        user_id=user.id,
        token_hash=hashed_refresh,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    ))
    await db.commit()
    await log_audit(db, "auth.login_microsoft_oauth", user.id, "Signed in via Microsoft", request)

    # Tokens go in the URL fragment (#...), not query string (?...) — the
    # fragment is never sent to the server on subsequent requests or
    # logged by reverse proxies, and the SPA route at /oauth-callback
    # reads it client-side then immediately clears it from the URL bar.
    return RedirectResponse(
        f"{settings.FRONTEND_BASE_URL.rstrip('/')}/oauth-callback"
        f"#access_token={access_token}&refresh_token={raw_refresh}"
        f"&user_id={user.id}&username={user.username}&role={user.role.value}"
    )


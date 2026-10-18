"""
Minimal SMTP email helper.

If SMTP isn't configured (settings.smtp_configured is False) or delivery
fails, send_email() logs that the email was not sent - recipient and
subject only, never the body: a password reset email carries a live reset
link, and anyone who can read the logs could use it. The caller decides
what else to do (see auth.forgot_password and LOG_PASSWORD_RESET_LINKS).
"""
import logging
import smtplib
from email.message import EmailMessage

from backend.core.config import settings

logger = logging.getLogger(__name__)


def send_email(to_email: str, subject: str, body_text: str) -> bool:
    """
    Send a plain-text email. Returns True if actually sent via SMTP,
    False if SMTP is not configured or delivery failed (the body is never logged).
    """
    if not settings.smtp_configured:
        logger.warning("SMTP not configured - email to %s not sent (subject: %s)", to_email, subject)
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM_EMAIL
    msg["To"] = to_email
    msg.set_content(body_text)

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            if settings.SMTP_USE_TLS:
                server.starttls()
            if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD.get_secret_value())
            server.send_message(msg)
        return True
    except Exception as exc:
        logger.error("Failed to send email to %s (subject: %s): %s", to_email, subject, exc.__class__.__name__)
        return False

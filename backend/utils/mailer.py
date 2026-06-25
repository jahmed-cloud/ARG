"""
Minimal SMTP email helper.

If SMTP isn't configured (settings.smtp_configured is False), send_email()
logs the message instead of raising — this keeps password reset usable
out of the box in a fresh deployment without forcing email setup, at the
cost of the link only being visible in server logs until SMTP is added.
"""
import logging
import smtplib
from email.message import EmailMessage

from backend.core.config import settings

logger = logging.getLogger(__name__)


def send_email(to_email: str, subject: str, body_text: str) -> bool:
    """
    Send a plain-text email. Returns True if actually sent via SMTP,
    False if it was only logged (SMTP not configured) or failed.
    """
    if not settings.smtp_configured:
        logger.warning(
            f"SMTP not configured — logging email instead of sending.\n"
            f"To: {to_email}\nSubject: {subject}\n\n{body_text}"
        )
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
        logger.error(f"Failed to send email to {to_email}: {exc}")
        # Fall back to logging the content so the reset link isn't lost
        # entirely if SMTP delivery fails at runtime.
        logger.warning(f"Email content (delivery failed):\nSubject: {subject}\n\n{body_text}")
        return False

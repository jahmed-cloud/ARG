"""SAST follow-up: webhook SSRF guard, no reset links in logs, no SMTP host in the API, URL and production checks."""
import asyncio
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from backend.api.routes import auth, webhooks
from backend.core import config
from backend.models.models import UserRole
from backend.utils import mailer


def resolving_to(*addresses):
    async def fake(host, port):
        return [(None, None, None, "", (address, port)) for address in addresses]
    return fake


def check(url):
    return asyncio.run(webhooks.check_webhook_url(url))


@pytest.mark.parametrize("url", ["http://hooks.example.com/x", "ftp://hooks.example.com", "https://",
                                 "https://user:pw@hooks.example.com/x", "not a url"])
def test_webhook_needs_https_without_credentials(url, monkeypatch):
    monkeypatch.setattr(webhooks, "_resolve", resolving_to("52.1.2.3"))
    with pytest.raises(webhooks.WebhookUrlError):
        check(url)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.5", "172.18.0.4", "192.168.1.10", "169.254.169.254",
                                     "100.64.0.1", "::1", "fd00::1", "::ffff:127.0.0.1"])
def test_webhook_to_an_internal_address_is_refused(address, monkeypatch):
    monkeypatch.setattr(webhooks, "_resolve", resolving_to(address))
    with pytest.raises(webhooks.WebhookUrlError):
        check("https://hooks.example.com/x")


def test_public_webhook_passes_and_private_hosts_are_opt_in_but_never_metadata(monkeypatch):
    monkeypatch.setattr(webhooks, "_resolve", resolving_to("52.1.2.3", "2603:1000::1"))
    check("https://hooks.example.com/x")
    monkeypatch.setattr(webhooks.settings, "WEBHOOK_ALLOW_PRIVATE_HOSTS", True)
    monkeypatch.setattr(webhooks, "_resolve", resolving_to("10.0.0.5"))
    check("https://siem.internal/x")
    monkeypatch.setattr(webhooks, "_resolve", resolving_to("169.254.169.254"))
    with pytest.raises(webhooks.WebhookUrlError, match="metadata"):
        check("https://metadata.internal/x")


def test_rejected_webhook_is_never_sent(monkeypatch):
    monkeypatch.setattr(webhooks, "_resolve", resolving_to("169.254.169.254"))

    class Client:
        async def post(self, *args, **kwargs):
            pytest.fail("posted to a rejected URL")

    with pytest.raises(webhooks.WebhookUrlError):
        asyncio.run(webhooks.send_webhook(Client(), "custom", "https://evil.example/x", {"a": 1}))


def test_reset_email_body_is_never_logged(monkeypatch):
    logged = []

    class Recorder:
        def __getattr__(self, level):
            return lambda msg, *args, **kwargs: logged.append(msg % args if args else msg)

    monkeypatch.setattr(mailer, "logger", Recorder())
    monkeypatch.setattr(mailer.settings, "SMTP_HOST", None)
    assert mailer.send_email("user@example.com", "Reset", "link https://arg/reset-password?token=SECRET") is False
    monkeypatch.setattr(mailer.settings, "SMTP_HOST", "smtp.invalid")
    monkeypatch.setattr(mailer.smtplib, "SMTP", lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
    assert mailer.send_email("user@example.com", "Reset", "link https://arg/reset-password?token=SECRET") is False
    text = "\n".join(logged)
    assert len(logged) == 2 and "SECRET" not in text and "user@example.com" in text


def test_system_status_returns_booleans_only(monkeypatch):
    monkeypatch.setattr(auth.settings, "SMTP_HOST", "smtp.internal.example")
    status = asyncio.run(auth.system_status(current_user=SimpleNamespace(role=UserRole.ADMIN)))
    assert "smtp_host" not in status and status["smtp_configured"] is True
    assert all(isinstance(v, bool) for v in status.values())


@pytest.mark.parametrize("url", ["javascript:alert(1)", "//evil.example", "https://", "https://a.example/?next=x",
                                 "https://a.example/#x", "https://user:pw@a.example"])
def test_frontend_base_url_must_be_a_plain_http_url(url):
    with pytest.raises(ValidationError):
        config.Settings(FRONTEND_BASE_URL=url)


def test_production_refuses_placeholder_keys_and_default_admin_password():
    weak = config.Settings(SECRET_KEY="CHANGE-ME-x", ENCRYPTION_KEY="CHANGE-ME-y", ADMIN_PASSWORD="changeme")
    assert len(config.production_config_errors(weak)) == 3
    strong = config.Settings(SECRET_KEY="a" * 64, ENCRYPTION_KEY="b" * 44, ADMIN_PASSWORD="c" * 24)
    assert config.production_config_errors(strong) == []


def test_http_frontend_url_and_logged_reset_links_are_warned_about():
    prod = config.Settings(APP_ENV="production", FRONTEND_BASE_URL="http://arg.example.com",
                           LOG_PASSWORD_RESET_LINKS=True)
    warnings = config.config_warnings(prod)
    assert any("FRONTEND_BASE_URL" in w for w in warnings) and any("LOG_PASSWORD_RESET_LINKS" in w for w in warnings)
    local = config.Settings(APP_ENV="production", FRONTEND_BASE_URL="http://localhost:3000")
    assert config.config_warnings(local) == []

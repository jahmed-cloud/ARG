"""
Docker worker: a subscription whose Azure sign-in cannot work is not scanned - no scanner falls back to its mock data
(fake findings), and no scanner waits for its own sign-in timeout.
"""

from types import SimpleNamespace

import pytest

pytest.importorskip("celery")

from workers import scan_worker  # noqa: E402


def test_undecryptable_secret_fails_instead_of_running_on_mock_data(monkeypatch):
    def broken(_):
        raise ValueError("InvalidToken")
    monkeypatch.setattr("backend.utils.encryption.decrypt", broken)
    tenant = SimpleNamespace(client_secret_encrypted="x", tenant_id="t", client_id="c", graph_permissions_granted=False)
    with pytest.raises(RuntimeError, match="cannot be decrypted"):
        scan_worker._build_scan_context("sub-1", tenant, "job-1")


@pytest.mark.parametrize("error, hint", [
    ("Failed to resolve 'login.microsoftonline.com' ([Errno -3] Temporary failure in name resolution)", "DNS"),
    ("AADSTS7000215: Invalid client secret provided.", "client ID and secret"),
])
def test_sign_in_check_names_the_cause(error, hint):
    class Credential:
        def get_token(self, *scopes):
            raise RuntimeError(error)
    with pytest.raises(RuntimeError, match="cannot sign in to Microsoft Entra ID") as info:
        scan_worker._check_sign_in(SimpleNamespace(credential=Credential()))
    assert hint in str(info.value)


def test_orphaned_running_jobs_are_failed_by_last_scanner_progress():
    from datetime import datetime, timezone
    from sqlalchemy.dialects import postgresql

    class Db:
        def execute(self, statement):
            self.sql = str(statement.compile(dialect=postgresql.dialect()))
            return SimpleNamespace(rowcount=2)

        def commit(self):
            self.committed = True

    db = Db()
    assert scan_worker.recover_orphaned_running_jobs(db, datetime.now(timezone.utc)) == 2
    assert "UPDATE scan_jobs SET status" in db.sql and "max(scan_results.started_at)" in db.sql
    assert "coalesce(" in db.sql and db.committed


def test_sign_in_check_passes_with_a_token():
    class Credential:
        def get_token(self, *scopes):
            return SimpleNamespace(token="t", expires_on=0)
    scan_worker._check_sign_in(SimpleNamespace(credential=Credential()))

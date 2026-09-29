from io import StringIO
from pathlib import Path

from alembic import command
from alembic.config import Config


def test_full_upgrade_can_be_generated_without_a_database(monkeypatch):
    root = Path(__file__).resolve().parents[2]
    monkeypatch.chdir(root)
    output = StringIO()
    config = Config(str(root / 'alembic.ini'), output_buffer=output)
    command.upgrade(config, 'head', sql=True)
    sql = output.getvalue()
    assert 'ADD COLUMN IF NOT EXISTS azure_cli_script TEXT' in sql
    assert 'ADD COLUMN IF NOT EXISTS powershell_script TEXT' in sql
    assert 'CREATE TABLE governance_configs' in sql

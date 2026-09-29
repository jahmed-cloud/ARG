import base64
import sys

import pytest

from scripts import configure_env


def test_creates_fresh_host_config_without_overwriting(tmp_path, monkeypatch):
    monkeypatch.setattr(configure_env, 'ROOT', tmp_path)
    monkeypatch.setattr(sys, 'argv', ['configure_env', '--local'])
    (tmp_path / '.env.example').write_text(
        'POSTGRES_PASSWORD=placeholder\nSECRET_KEY=placeholder\nENCRYPTION_KEY=placeholder\nADMIN_PASSWORD=placeholder\n',
        encoding='utf-8',
    )
    configure_env.main()
    text = (tmp_path / '.env').read_text()
    values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line and not line.startswith('#'))
    assert 'placeholder' not in text
    assert len(base64.b64decode(values['ENCRYPTION_KEY'])) == 32
    assert len(values['SECRET_KEY']) == 64
    assert values['POSTGRES_PASSWORD'] in values['DATABASE_URL']
    assert values['FRONTEND_BASE_URL'] == 'http://localhost:5173'
    with pytest.raises(SystemExit, match='1'):
        configure_env.main()
    assert (tmp_path / '.env').read_text() == text

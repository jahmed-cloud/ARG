"""Create a new .env with fresh credentials without overwriting existing config."""
import argparse
import base64
import re
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local', action='store_true', help='Configure the full stack for host PostgreSQL and Redis')
    args = parser.parse_args()
    values = {
        'POSTGRES_PASSWORD': secrets.token_hex(24),
        'SECRET_KEY': secrets.token_hex(32),
        'ENCRYPTION_KEY': base64.b64encode(secrets.token_bytes(32)).decode(),
        'ADMIN_PASSWORD': secrets.token_urlsafe(24),
    }
    template = (ROOT / '.env.example').read_text(encoding='utf-8')
    for key, value in values.items():
        template = re.sub(rf'^{key}=.*$', f'{key}={value}', template, flags=re.MULTILINE)
    if args.local:
        template += (
            '\n# Full-stack host development\n'
            f'DATABASE_URL=postgresql+asyncpg://arg:{values["POSTGRES_PASSWORD"]}@localhost:5432/arg\n'
            'REDIS_URL=redis://localhost:6379/0\n'
            'CELERY_BROKER_URL=redis://localhost:6379/1\n'
            'CELERY_RESULT_BACKEND=redis://localhost:6379/2\n'
            'FRONTEND_BASE_URL=http://localhost:5173\n'
            f'REPORT_STORAGE_PATH={ROOT.as_posix()}/reports\n'
        )
    try:
        with (ROOT / '.env').open('x', encoding='utf-8', newline='\n') as target:
            target.write(template)
    except FileExistsError:
        parser.exit(1, '.env already exists; edit it directly. No changes made.\n')
    print('Created .env. Read ADMIN_EMAIL and ADMIN_PASSWORD there to sign in. Keep this file private.')


if __name__ == '__main__':
    main()

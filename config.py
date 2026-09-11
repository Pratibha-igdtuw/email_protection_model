"""
Environment-based configuration. Selected via the APP_ENV env var
(development | testing | production), defaulting to development so
`python app.py` keeps working out of the box for local/manual testing.

Production deployments MUST set APP_ENV=production and provide a real
SECRET_KEY and (recommended) a non-SQLite SQLALCHEMY_DATABASE_URI via env
vars -- see README "Deploying to production".
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')


class BaseConfig:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB
    RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'true').lower() != 'false'
    # In-memory limiter storage is fine for a single dev/small deployment;
    # point RATELIMIT_STORAGE_URI at Redis (e.g. redis://localhost:6379/0)
    # for a multi-process/production deployment so limits are shared.
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')
    # Whether to auto-create tables on startup (dev/test convenience only --
    # production uses Flask-Migrate instead, see README).
    AUTO_CREATE_TABLES = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', f"sqlite:///{os.path.join(INSTANCE_DIR, 'threat_platform.db')}"
    )


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    AUTO_CREATE_TABLES = True


class TestingConfig(BaseConfig):
    TESTING = True
    DEBUG = False
    AUTO_CREATE_TABLES = True
    RATELIMIT_ENABLED = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


class ProductionConfig(BaseConfig):
    DEBUG = False
    AUTO_CREATE_TABLES = False  # use `flask db upgrade` instead -- see README

    def __init__(self):
        if os.environ.get('SECRET_KEY') in (None, '', 'dev-secret-change-me'):
            raise RuntimeError(
                'SECRET_KEY must be set to a real secret via env var in production. '
                'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
            )
        if BaseConfig.SQLALCHEMY_DATABASE_URI.startswith('sqlite') and not os.environ.get('ALLOW_SQLITE_IN_PROD'):
            import warnings
            warnings.warn(
                'Running production with SQLite. SQLite works fine for a single-process, '
                'low-concurrency deployment, but has no built-in connection pooling or '
                'concurrent-writer story -- consider PostgreSQL (set DATABASE_URL) for '
                'anything with multiple workers or meaningful write concurrency. '
                'Set ALLOW_SQLITE_IN_PROD=1 to silence this warning.'
            )


CONFIG_BY_NAME = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
}


def get_config():
    env_name = os.environ.get('APP_ENV', 'development').lower()
    config_cls = CONFIG_BY_NAME.get(env_name, DevelopmentConfig)
    return config_cls()

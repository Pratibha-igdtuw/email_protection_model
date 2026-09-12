import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault('APP_ENV', 'testing')
os.environ.setdefault('SECRET_KEY', 'test-secret')
os.environ.setdefault('RATELIMIT_ENABLED', 'false')

from app import app as flask_app, db  # noqa: E402


@pytest.fixture()
def app():
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    flask_app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{db_path}",
        WTF_CSRF_ENABLED=False,
        RATELIMIT_ENABLED=False,
        SERVER_NAME='localhost',
    )

    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def sample_dir():
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'sample_emails')


def register_and_login(client, email='analyst@example.com', password='CorrectHorse1!'):
    client.post('/signup', data={
        'full_name': 'Test Analyst',
        'email': email,
        'organization': 'Test Org',
        'password': password,
        'confirm_password': password,
    }, follow_redirects=True)
    return client
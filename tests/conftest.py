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

    # Table creation/teardown need an app context, but deliberately don't
    # keep one open for the whole test (see note below) -- each is pushed
    # and popped immediately around just the DB call.
    with flask_app.app_context():
        db.create_all()

    # No ambient `with flask_app.app_context():` wrapping the yield here.
    # Flask reuses an already-active app context instead of pushing a new
    # one (see Flask's RequestContext.push()) -- so if one were left open
    # across this whole test, every client.get()/client.post() call in the
    # test would share the same `flask.g`, and Flask-Login caches the
    # resolved user on `g._login_user` per app context, not per request.
    # A test that logs out and then expects the NEXT call to re-resolve
    # current_user from scratch (e.g. via a header-based login) would
    # silently see the previous call's cached user/anonymous state instead
    # of a fresh lookup -- a real request never has this problem, since
    # each one gets its own app context, so tests shouldn't either.
    yield flask_app

    with flask_app.app_context():
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
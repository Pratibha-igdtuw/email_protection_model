"""
WSGI entry point for production. Run with a real WSGI server instead of
Flask's built-in dev server, e.g.:

    gunicorn -c gunicorn.conf.py wsgi:application

Set APP_ENV=production (and SECRET_KEY, DATABASE_URL, etc. -- see
config.py and README "Deploying to production") before starting.
"""
from app import app as application

if __name__ == '__main__':
    application.run()

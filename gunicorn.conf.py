"""
Gunicorn config for production. Tune `workers` for your CPU count
(rule of thumb: 2 * cpu_count + 1) and `worker_class` if you later make
any route async; sync is fine for this app's current I/O pattern.

Usage:
    gunicorn -c gunicorn.conf.py wsgi:application
"""
import multiprocessing
import os

bind = os.environ.get('GUNICORN_BIND', '0.0.0.0:8000')
workers = int(os.environ.get('GUNICORN_WORKERS', multiprocessing.cpu_count() * 2 + 1))
worker_class = 'sync'
timeout = int(os.environ.get('GUNICORN_TIMEOUT', 60))  # analysis pipeline does a few network calls
graceful_timeout = 30
accesslog = '-'   # stdout
errorlog = '-'    # stderr
loglevel = os.environ.get('GUNICORN_LOG_LEVEL', 'info')

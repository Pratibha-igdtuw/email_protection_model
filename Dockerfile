# Production image. Runs behind gunicorn (see gunicorn.conf.py / wsgi.py),
# not Flask's dev server. Pair with docker-compose.yml for a working
# Redis-backed rate limiter out of the box -- see README "Rate limiting
# in production" for why that matters with multiple workers.
FROM python:3.12-slim

# Native deps for reportlab (PDF report generation) and building any
# wheels that don't ship pre-built for this platform.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p instance case_reports \
    && useradd --create-home appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Alembic migrations are a deliberate separate step (`flask db upgrade`),
# not baked into the image start command -- running migrations
# automatically on every container start is a footgun with more than one
# replica racing to migrate at once. Run it once via `docker compose run
# web flask db upgrade` (see README) before/after deploying a new image.
CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:application"]

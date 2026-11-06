"""Gunicorn settings, read automatically from the working directory.

The command line (Procfile / railway.toml) still sets --bind and --timeout.

One sync worker serves every request one at a time, so a single user opening a
large log (several seconds of analysis) stalls everyone else's page loads.
Several processes let analyses run side by side; threads let the cheap
requests (listings, polling, static) through while a worker is busy.

Each worker holds its own copy of the compiled rule buckets, so raise or lower
WEB_CONCURRENCY to fit the plan's memory. Rule edits reach every worker through
SiteConfig.rules_version (see analyzer._get_cached_rule_buckets).
"""

import os

workers = int(os.environ.get('WEB_CONCURRENCY', '2'))
threads = int(os.environ.get('GUNICORN_THREADS', '4'))
worker_class = 'gthread'

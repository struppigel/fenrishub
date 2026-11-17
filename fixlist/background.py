"""Running work off the request thread.

Every background job runs in a daemon thread that closes its database
connections when done (each thread gets its own; leaving them open would leak
one per job) and logs anything that escapes the job instead of losing it.
"""
import logging
import threading

from django.db import connections

logger = logging.getLogger(__name__)


def start(target, *args, name: str) -> threading.Thread:
    """Run ``target(*args)`` in a new daemon thread called `name`; returns at once."""

    def run():
        try:
            target(*args)
        except Exception:
            logger.exception('Background job %s failed', name)
        finally:
            connections.close_all()

    thread = threading.Thread(target=run, name=name, daemon=True)
    thread.start()
    return thread

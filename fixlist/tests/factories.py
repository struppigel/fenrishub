"""Minimal test helpers used across the fixlist test suite."""
from django.contrib.auth.models import User

from ..models import ClassificationRule, UploadedLog


def make_user(username="alice", password="password123", **extra):
    return User.objects.create_user(username=username, password=password, **extra)


def make_superuser(username="admin", password="password123"):
    return User.objects.create_superuser(username=username, password=password)


def make_uploaded_log(upload_id="test-log", **overrides):
    defaults = dict(
        upload_id=upload_id,
        reddit_username="reddit_name",
        original_filename="log.txt",
        content="payload",
    )
    defaults.update(overrides)
    return UploadedLog.objects.create(**defaults)


def make_rule(source_text, status=ClassificationRule.STATUS_MALWARE,
              match_type=ClassificationRule.MATCH_EXACT, **overrides):
    defaults = dict(
        source_text=source_text,
        status=status,
        match_type=match_type,
    )
    defaults.update(overrides)
    return ClassificationRule.objects.create(**defaults)
